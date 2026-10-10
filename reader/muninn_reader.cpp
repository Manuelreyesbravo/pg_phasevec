// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0
//
// muninn-reader: the process that reads for a watch.
//
// It loads a sealed model with llama.cpp, proves to the database that the weights it loaded are the
// ones the reader was registered with (sha256), and then reads what muninn.next() hands out: every
// row never read, read from older text, or read by another reader. Each reading is recorded with the
// hash of the exact text it read, so the database can refuse it if the row changed meanwhile.
//
// No HTTP, no service in between: the model runs in this process, and the database is the only
// authority on what to read and on whether a reading still holds.
//
//   muninn-reader --model M.gguf [--lora A.gguf] --reader NAME --register [--dims D]  register the reader
//   muninn-reader --model M.gguf [--lora A.gguf] --reader NAME --watch W [--once]     read for a watch
//   muninn-reader --model M.gguf [--lora A.gguf] --reader NAME --ask "question"       print a question's codes
//
// The database connection comes from the usual PG* environment variables (or --dsn).

#include <llama.h>
#include <libpq-fe.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <sys/select.h>
#include <vector>

namespace {

struct Options {
    std::string model, lora, reader, watch, dsn, ask, query_prefix, pooling = "last";
    int dims = 0, batch = 32, ctx = 512, gpu_layers = 99;
    bool once = false, do_register = false;
};

[[noreturn]] void die(const std::string &msg) {
    std::fprintf(stderr, "muninn-reader: %s\n", msg.c_str());
    std::exit(1);
}

Options parse(int argc, char **argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) die("missing value for " + a);
            return argv[++i];
        };
        if (a == "--model") o.model = next();
        else if (a == "--lora") o.lora = next();
        else if (a == "--reader") o.reader = next();
        else if (a == "--watch") o.watch = next();
        else if (a == "--dsn") o.dsn = next();
        else if (a == "--ask") o.ask = next();
        else if (a == "--query-prefix") o.query_prefix = next();
        else if (a == "--pooling") o.pooling = next();
        else if (a == "--dims") o.dims = std::stoi(next());
        else if (a == "--batch") o.batch = std::stoi(next());
        else if (a == "--ctx") o.ctx = std::stoi(next());
        else if (a == "--gpu-layers") o.gpu_layers = std::stoi(next());
        else if (a == "--once") o.once = true;
        else if (a == "--register") o.do_register = true;
        else die("unknown option " + a);
    }
    if (o.model.empty() || o.reader.empty()) die("--model and --reader are required");
    if (o.pooling != "last" && o.pooling != "mean") die("--pooling is last or mean");
    return o;
}

// sha256 of a file, through the system's sha256sum: the seal is computed by the same tool an operator
// would use to check it by hand.
std::string sha256_of(const std::string &path) {
    std::string cmd = "sha256sum -- '";
    for (char c : path) {
        if (c == '\'') die("refusing a path with a quote in it: " + path);
        cmd += c;
    }
    cmd += "'";
    std::unique_ptr<FILE, int (*)(FILE *)> p(popen(cmd.c_str(), "r"), pclose);
    if (!p) die("cannot run sha256sum");
    std::array<char, 65> hex{};
    if (std::fscanf(p.get(), "%64s", hex.data()) != 1) die("cannot hash " + path);
    return std::string(hex.data());
}

// ------------------------------------------------------------------- the model --

struct Reader {
    llama_model *model = nullptr;
    llama_context *ctx = nullptr;
    const llama_vocab *vocab = nullptr;
    int n_embd = 0;
    int dims = 0;
    int max_tokens = 512;

    explicit Reader(const Options &o) {
        llama_backend_init();
        auto mp = llama_model_default_params();
        mp.n_gpu_layers = o.gpu_layers;
        model = llama_model_load_from_file(o.model.c_str(), mp);
        if (!model) die("cannot load " + o.model);
        auto cp = llama_context_default_params();
        cp.embeddings = true;
        cp.pooling_type = o.pooling == "mean" ? LLAMA_POOLING_TYPE_MEAN : LLAMA_POOLING_TYPE_LAST;
        cp.n_ctx = o.ctx;
        cp.n_batch = o.ctx;
        cp.n_ubatch = o.ctx;
        cp.n_seq_max = 1;
        ctx = llama_init_from_model(model, cp);
        if (!ctx) die("cannot create a context");
        if (!o.lora.empty()) {
            llama_adapter_lora *ad = llama_adapter_lora_init(model, o.lora.c_str());
            if (!ad) die("cannot load adapter " + o.lora);
            float scale = 1.0f;
            if (llama_set_adapters_lora(ctx, &ad, 1, &scale) != 0) die("cannot apply adapter " + o.lora);
        }
        vocab = llama_model_get_vocab(model);
        n_embd = llama_model_n_embd(model);
        dims = o.dims > 0 ? o.dims : n_embd;
        if (dims > n_embd) die("--dims is larger than the model's embedding size");
        if (dims < 64) die("a reading needs at least 64 dimensions for its 64-bit code");
        max_tokens = o.ctx;
    }
    ~Reader() {
        if (ctx) llama_free(ctx);
        if (model) llama_model_free(model);
    }

    // The unit vector of a text, truncated to `dims` and renormalized (Matryoshka). Empty if the text
    // has no tokens or the model gives nothing.
    std::vector<float> read(const std::string &text) {
        std::vector<llama_token> toks(max_tokens);
        int n = llama_tokenize(vocab, text.data(), (int32_t)text.size(), toks.data(), max_tokens, true, false);
        if (n < 0) {
            // too long: keep the head, which is where a recipe puts what matters
            toks.resize(-n);
            n = llama_tokenize(vocab, text.data(), (int32_t)text.size(), toks.data(), (int32_t)toks.size(), true, false);
            if (n < 0) return {};
            toks.resize(std::min(n, max_tokens));
            n = (int)toks.size();
        } else {
            toks.resize(n);
        }
        if (n == 0) return {};

        llama_memory_clear(llama_get_memory(ctx), true);
        llama_batch b = llama_batch_init(n, 0, 1);
        for (int i = 0; i < n; i++) {
            b.token[i] = toks[i];
            b.pos[i] = i;
            b.n_seq_id[i] = 1;
            b.seq_id[i][0] = 0;
            b.logits[i] = (i == n - 1);
        }
        b.n_tokens = n;
        int rc = llama_decode(ctx, b);
        llama_batch_free(b);
        if (rc != 0) return {};

        const float *e = llama_get_embeddings_seq(ctx, 0);
        if (!e) return {};
        std::vector<float> v(e, e + dims);
        double norm = 0;
        for (float x : v) norm += (double)x * x;
        norm = std::sqrt(norm);
        if (norm == 0) return {};
        for (float &x : v) x = (float)(x / norm);
        return v;
    }
};

// The 64-bit code: the signs of the first 64 dimensions (the Matryoshka head).
int64_t code64(const std::vector<float> &v) {
    uint64_t c = 0;
    for (int i = 0; i < 64; i++)
        if (v[i] > 0) c |= (uint64_t(1) << i);
    int64_t s;
    std::memcpy(&s, &c, sizeof s);
    return s;
}

// The full code: int8 with one scale per reading (the cosine does not see the scale).
std::string code_literal(const std::vector<float> &v) {
    float m = 0;
    for (float x : v) m = std::max(m, std::fabs(x));
    std::string s = "{";
    for (size_t i = 0; i < v.size(); i++) {
        int q = m == 0 ? 0 : (int)std::lround(v[i] / m * 127.0f);
        q = std::clamp(q, -128, 127);
        if (i) s += ',';
        s += std::to_string(q);
    }
    return s + "}";
}

// ---------------------------------------------------------------- the database --

struct Db {
    PGconn *c = nullptr;
    explicit Db(const std::string &dsn) {
        c = PQconnectdb(dsn.c_str());
        if (PQstatus(c) != CONNECTION_OK) die(std::string("cannot connect: ") + PQerrorMessage(c));
    }
    ~Db() { if (c) PQfinish(c); }

    // A refused reading (the row changed meanwhile) is a normal outcome, so errors are returned.
    std::optional<std::string> exec(const char *sql, const std::vector<std::string> &params, PGresult **out = nullptr) {
        std::vector<const char *> p;
        for (auto &s : params) p.push_back(s.c_str());
        PGresult *r = PQexecParams(c, sql, (int)p.size(), nullptr, p.data(), nullptr, nullptr, 0);
        auto st = PQresultStatus(r);
        if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
            std::string err = PQresultErrorMessage(r);
            PQclear(r);
            return err;
        }
        if (out) *out = r; else PQclear(r);
        return std::nullopt;
    }
};

void check_seal(Db &db, const Options &o, const Reader &rd, const std::string &model_sha, const std::string &adapter_sha) {
    PGresult *r = nullptr;
    if (auto err = db.exec("SELECT model_sha, coalesce(adapter_sha, ''), dims FROM muninn.reader_seal($1)", {o.reader}, &r))
        die("cannot read the seal of reader " + o.reader + ": " + *err);
    if (PQntuples(r) != 1) die("no reader named " + o.reader + " (register it with --register)");
    std::string m = PQgetvalue(r, 0, 0), a = PQgetvalue(r, 0, 1);
    int dims = std::atoi(PQgetvalue(r, 0, 2));
    PQclear(r);
    if (m != model_sha || a != adapter_sha)
        die("the weights loaded are not the ones reader " + o.reader + " was registered with: refusing to read in its name");
    if (dims != rd.dims) die("reader " + o.reader + " was registered with " + std::to_string(dims) + " dimensions");
}

void wait_for_notify(Db &db, int seconds) {
    int fd = PQsocket(db.c);
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    timeval tv{seconds, 0};
    if (select(fd + 1, &set, nullptr, nullptr, &tv) < 0) return;
    PQconsumeInput(db.c);
    while (PGnotify *n = PQnotifies(db.c)) PQfreemem(n);
}

}  // namespace

int main(int argc, char **argv) {
    Options o = parse(argc, argv);
    std::string model_sha = sha256_of(o.model);
    std::string adapter_sha = o.lora.empty() ? "" : sha256_of(o.lora);
    Reader rd(o);

    if (!o.ask.empty()) {
        auto v = rd.read(o.query_prefix + o.ask);
        if (v.empty()) die("the question has no tokens");
        std::printf("%lld\t%s\n", (long long)code64(v), code_literal(v).c_str());
        return 0;
    }

    Db db(o.dsn);
    if (o.do_register) {
        PGresult *r = nullptr;
        if (auto err = db.exec("SELECT muninn.reader_register($1, $2, $3::int, nullif($4, ''), "
                               "jsonb_build_object('pooling', $5::text, 'ctx', $6::int, 'query_prefix', $7::text))",
                               {o.reader, model_sha, std::to_string(rd.dims), adapter_sha, o.pooling,
                                std::to_string(o.ctx), o.query_prefix}, &r))
            die("cannot register: " + *err);
        std::printf("registered reader %s (model %s, %d dimensions)\n", o.reader.c_str(), model_sha.substr(0, 12).c_str(), rd.dims);
        PQclear(r);
        return 0;
    }

    if (o.watch.empty()) die("--watch, --register or --ask is required");
    check_seal(db, o, rd, model_sha, adapter_sha);
    if (auto err = db.exec("LISTEN muninn", {})) die("cannot listen: " + *err);

    long read_ok = 0, refused = 0, failed = 0;
    for (;;) {
        PGresult *r = nullptr;
        if (auto err = db.exec("SELECT key, body, text_hash::text FROM muninn.next($1, $2::int)",
                               {o.watch, std::to_string(o.batch)}, &r))
            die("cannot ask what to read: " + *err);
        int rows = PQntuples(r);
        for (int i = 0; i < rows; i++) {
            std::string key = PQgetvalue(r, i, 0);
            std::string body = PQgetisnull(r, i, 1) ? "" : PQgetvalue(r, i, 1);
            std::string hash = PQgetvalue(r, i, 2);
            auto v = body.empty() ? std::vector<float>{} : rd.read(body);
            std::optional<std::string> err;
            if (v.empty()) {
                err = db.exec("SELECT muninn.record_failure($1, $2, $3, $4::bytea, $5)",
                              {o.watch, key, o.reader, hash, body.empty() ? "empty text" : "the model produced no reading"});
                if (!err) failed++;
            } else {
                err = db.exec("SELECT muninn.record($1, $2, $3, $4::bytea, $5::bigint, $6::smallint[])",
                              {o.watch, key, o.reader, hash, std::to_string(code64(v)), code_literal(v)});
                if (!err) read_ok++;
            }
            if (err) {
                refused++;
                std::fprintf(stderr, "muninn-reader: row %s not recorded: %s", key.c_str(), err->c_str());
            }
        }
        PQclear(r);
        if (rows == 0) {
            std::fprintf(stderr, "muninn-reader: %s: %ld read, %ld failed, %ld refused; queue empty\n",
                         o.watch.c_str(), read_ok, failed, refused);
            if (o.once) break;
            wait_for_notify(db, 30);
        }
    }
    return 0;
}
