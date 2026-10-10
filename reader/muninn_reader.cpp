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
// Two ways to read:
//   pooled    an off-the-shelf embedding model: llama.cpp pools the sequence (--pooling last|mean).
//   contract  a reader trained for Muninn (--heads): the text is closed by the reader's marker, the
//             state is taken at the marker's last token, and the reader's own heads turn it into the
//             vector (projection, Matryoshka prefix) and into a familiarity score. Marker and query
//             instruction come from the manifest sealed in the database, never from the command line.
//
//   muninn-reader --model M.gguf [--lora A.gguf] --reader NAME --register [--dims D]
//   muninn-reader --model M.gguf --lora A.gguf --heads H.gguf --register --manifest manifest.json
//   muninn-reader --model M.gguf [--lora A.gguf] [--heads H.gguf] --reader NAME --watch W [--once]
//   muninn-reader --model M.gguf [--lora A.gguf] [--heads H.gguf] --reader NAME --ask "question"
//   muninn-reader ... --reader NAME --ask-file questions.txt   one question per line, one code per line
//
// The database connection comes from the usual PG* environment variables (or --dsn).

#include <ggml.h>
#include <gguf.h>
#include <libpq-fe.h>
#include <llama.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <vector>

namespace {

struct Options {
    std::string model, lora, heads, manifest, reader, watch, dsn, ask, ask_file, query_prefix, pooling = "last";
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
        else if (a == "--heads") o.heads = next();
        else if (a == "--manifest") o.manifest = next();
        else if (a == "--reader") o.reader = next();
        else if (a == "--watch") o.watch = next();
        else if (a == "--dsn") o.dsn = next();
        else if (a == "--ask") o.ask = next();
        else if (a == "--ask-file") o.ask_file = next();
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
    if (o.model.empty()) die("--model is required");
    if (!o.manifest.empty() && (!o.do_register || o.heads.empty() || o.lora.empty()))
        die("--manifest is for --register, with the --lora and --heads it names");
    if (o.reader.empty() && o.manifest.empty()) die("--reader is required");
    if (o.pooling != "last" && o.pooling != "mean") die("--pooling is last or mean");
    if (!o.heads.empty() && !o.query_prefix.empty())
        die("a contract reader takes its query instruction from its manifest, not from --query-prefix");
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

// ------------------------------------------------------------------- the heads --

// The two small heads a contract reader ships next to its adapter (vec-heads.gguf): a projection whose
// prefixes are the Matryoshka dimensions, and a scalar familiarity head.
struct Heads {
    int in = 0, out = 0;
    std::vector<float> proj, bias, fam;
    float fam_bias = 0;

    explicit Heads(const std::string &path) {
        ggml_context *meta = nullptr;
        gguf_init_params gp{false, &meta};
        gguf_context *g = gguf_init_from_file(path.c_str(), gp);
        if (!g || !meta) die("cannot read heads " + path);
        auto tensor = [&](const char *name) {
            ggml_tensor *t = ggml_get_tensor(meta, name);
            if (!t) die(std::string("heads file has no tensor ") + name);
            return t;
        };
        auto floats = [&](ggml_tensor *t) {
            std::vector<float> v(ggml_nelements(t));
            if (t->type == GGML_TYPE_F32) std::memcpy(v.data(), t->data, v.size() * sizeof(float));
            else if (t->type == GGML_TYPE_F16) ggml_fp16_to_fp32_row((const ggml_fp16_t *)t->data, v.data(), (int64_t)v.size());
            else die(std::string("unsupported tensor type in heads: ") + ggml_get_name(t));
            return v;
        };
        ggml_tensor *w = tensor("vec.proj.weight");
        in = (int)w->ne[0];
        out = (int)w->ne[1];
        proj = floats(w);
        bias = floats(tensor("vec.proj.bias"));
        fam = floats(tensor("fam.weight"));
        std::vector<float> fb = floats(tensor("fam.bias"));
        if ((int)bias.size() != out || (int)fam.size() != in || fb.size() != 1) die("heads have inconsistent shapes");
        fam_bias = fb[0];
        int64_t key = gguf_find_key(g, "muninn.layer");
        if (key >= 0 && gguf_get_val_i32(g, key) != -1)
            die("these heads read an intermediate layer; this reader serves layer -1 only");
        gguf_free(g);
        ggml_free(meta);
    }

    // The first `dims` outputs of the projection: a Matryoshka prefix needs no more rows than that.
    std::vector<float> project(const float *h, int dims) const {
        std::vector<float> v(dims);
        for (int o = 0; o < dims; o++) {
            const float *row = proj.data() + (size_t)o * in;
            double acc = bias[o];
            for (int i = 0; i < in; i++) acc += (double)row[i] * h[i];
            v[o] = (float)acc;
        }
        return v;
    }

    float familiarity(const float *h) const {
        double acc = fam_bias;
        for (int i = 0; i < in; i++) acc += (double)fam[i] * h[i];
        return (float)(1.0 / (1.0 + std::exp(-acc)));
    }
};

// ------------------------------------------------------------------- the model --

struct Reading {
    std::vector<float> v;   // unit vector, `dims` long; empty if nothing could be read
    std::optional<float> familiarity;
};

struct Reader {
    llama_model *model = nullptr;
    llama_context *ctx = nullptr;
    const llama_vocab *vocab = nullptr;
    std::unique_ptr<Heads> heads;
    int n_embd = 0;
    int dims = 0;
    int max_tokens = 512;
    std::vector<llama_token> marker;   // contract readers only, set from the sealed manifest
    std::string query_instruction;

    explicit Reader(const Options &o) {
        llama_backend_init();
        llama_log_set([](ggml_log_level level, const char *text, void *) {
            if (level >= GGML_LOG_LEVEL_ERROR) std::fputs(text, stderr);
        }, nullptr);
        auto mp = llama_model_default_params();
        mp.n_gpu_layers = o.gpu_layers;
        model = llama_model_load_from_file(o.model.c_str(), mp);
        if (!model) die("cannot load " + o.model);
        auto cp = llama_context_default_params();
        cp.embeddings = true;
        cp.pooling_type = !o.heads.empty() ? LLAMA_POOLING_TYPE_NONE
                        : o.pooling == "mean" ? LLAMA_POOLING_TYPE_MEAN : LLAMA_POOLING_TYPE_LAST;
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
        int width = n_embd;
        if (!o.heads.empty()) {
            heads = std::make_unique<Heads>(o.heads);
            if (heads->in != n_embd) die("the heads expect a model of width " + std::to_string(heads->in));
            width = heads->out;
        }
        dims = o.dims > 0 ? o.dims : std::min(width, heads ? 1024 : width);
        if (dims > width) die("--dims is larger than what the reader produces");
        if (dims < 64) die("a reading needs at least 64 dimensions for its 64-bit code");
        max_tokens = o.ctx;
    }
    ~Reader() {
        if (ctx) llama_free(ctx);
        if (model) llama_model_free(model);
    }

    std::vector<llama_token> tokenize(const std::string &text, bool special) const {
        int n = -llama_tokenize(vocab, text.data(), (int32_t)text.size(), nullptr, 0, special, false);
        std::vector<llama_token> t(n > 0 ? n : 0);
        if (n > 0) llama_tokenize(vocab, text.data(), (int32_t)text.size(), t.data(), n, special, false);
        return t;
    }

    void set_contract(const std::string &marker_text, const std::string &instruction) {
        marker = tokenize(marker_text, false);
        if (marker.empty()) die("the reader's marker has no tokens");
        query_instruction = instruction;
    }

    static std::vector<float> unit(std::vector<float> v) {
        double norm = 0;
        for (float x : v) norm += (double)x * x;
        norm = std::sqrt(norm);
        if (norm == 0) return {};
        for (float &x : v) x = (float)(x / norm);
        return v;
    }

    bool decode(const std::vector<llama_token> &toks, bool output_all_last) {
        llama_memory_clear(llama_get_memory(ctx), true);
        int n = (int)toks.size();
        llama_batch b = llama_batch_init(n, 0, 1);
        for (int i = 0; i < n; i++) {
            b.token[i] = toks[i];
            b.pos[i] = i;
            b.n_seq_id[i] = 1;
            b.seq_id[i][0] = 0;
            b.logits[i] = output_all_last && i == n - 1;
        }
        b.n_tokens = n;
        int rc = llama_decode(ctx, b);
        llama_batch_free(b);
        return rc == 0;
    }

    // A document piece, or a question when `query` is set.
    Reading read(const std::string &text, bool query = false) {
        if (heads) return read_contract(query ? query_instruction + text : text);
        auto toks = tokenize(text, true);
        if (toks.empty()) return {};
        // too long: keep the head, which is where a recipe puts what matters
        if ((int)toks.size() > max_tokens) toks.resize(max_tokens);
        if (!decode(toks, true)) return {};
        const float *e = llama_get_embeddings_seq(ctx, 0);
        if (!e) return {};
        return {unit(std::vector<float>(e, e + dims)), std::nullopt};
    }

    // The contract: the piece tokenized without special tokens, closed by the marker, read at the
    // marker's last token (layer -1, the final normed state), turned into a vector by the heads.
    Reading read_contract(const std::string &text) {
        if (marker.empty()) die("internal: contract reader without its manifest");
        auto toks = tokenize(text, false);
        if (toks.empty()) return {};
        size_t room = (size_t)max_tokens - marker.size();
        if (toks.size() > room) toks.resize(room);
        toks.insert(toks.end(), marker.begin(), marker.end());
        if (!decode(toks, true)) return {};
        const float *h = llama_get_embeddings_ith(ctx, -1);
        if (!h) return {};
        return {unit(heads->project(h, dims)), heads->familiarity(h)};
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

struct Seal {
    std::string model_sha, adapter_sha, heads_sha;
};

// Proves the loaded weights are the registered ones and, for a contract reader, takes its marker and
// query instruction from the sealed manifest.
void check_seal(Db &db, const Options &o, Reader &rd, const Seal &have) {
    PGresult *r = nullptr;
    if (auto err = db.exec("SELECT model_sha, coalesce(adapter_sha, ''), dims, coalesce(heads_sha, ''), "
                           "coalesce(manifest->>'marker', ''), coalesce(manifest->>'query_instruction', '') "
                           "FROM muninn.reader_seal($1)", {o.reader}, &r))
        die("cannot read the seal of reader " + o.reader + ": " + *err);
    if (PQntuples(r) != 1) die("no reader named " + o.reader + " (register it with --register)");
    std::string m = PQgetvalue(r, 0, 0), a = PQgetvalue(r, 0, 1), h = PQgetvalue(r, 0, 3);
    int dims = std::atoi(PQgetvalue(r, 0, 2));
    std::string marker = PQgetvalue(r, 0, 4), instruction = PQgetvalue(r, 0, 5);
    PQclear(r);
    if (m != have.model_sha || a != have.adapter_sha || h != have.heads_sha)
        die("the weights loaded are not the ones reader " + o.reader + " was registered with: refusing to read in its name");
    if (dims != rd.dims) die("reader " + o.reader + " was registered with " + std::to_string(dims) + " dimensions");
    if (rd.heads) {
        if (marker.empty()) die("reader " + o.reader + " has heads but its manifest names no marker");
        rd.set_contract(marker, instruction);
    }
}

std::string read_file(const std::string &path) {
    std::ifstream f(path);
    if (!f) die("cannot read " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string familiarity_param(const Reading &r) {
    if (!r.familiarity) return "";
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.6g", *r.familiarity);
    return buf;
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
    Seal have{sha256_of(o.model), o.lora.empty() ? "" : sha256_of(o.lora),
              o.heads.empty() ? "" : sha256_of(o.heads)};
    Reader rd(o);
    Db db(o.dsn);

    if (o.do_register) {
        PGresult *r = nullptr;
        if (!o.manifest.empty()) {
            // The manifest names adapter and heads; the base is sealed here, from the file loaded.
            if (auto err = db.exec("SELECT $1::jsonb->>'adapter_sha256' = $2 AND $1::jsonb->>'heads_sha256' = $3",
                                   {read_file(o.manifest), have.adapter_sha, have.heads_sha}, &r))
                die("cannot read the manifest: " + *err);
            bool match = std::string(PQgetvalue(r, 0, 0)) == "t";
            PQclear(r);
            if (!match) die("the --lora/--heads loaded are not the ones the manifest names: refusing to register");
            if (auto err = db.exec("SELECT muninn.reader_register(jsonb_set($1::jsonb, '{base_sha256}', to_jsonb($2::text))), "
                                   "($1::jsonb->>'reader') || '-' || ($1::jsonb->>'version')",
                                   {read_file(o.manifest), have.model_sha}, &r))
                die("cannot register: " + *err);
            std::printf("registered reader %s (base %s, adapter %s, heads %s)\n", PQgetvalue(r, 0, 1),
                        have.model_sha.substr(0, 12).c_str(), have.adapter_sha.substr(0, 12).c_str(),
                        have.heads_sha.substr(0, 12).c_str());
            PQclear(r);
            return 0;
        }
        if (rd.heads) die("a reader with heads registers through its --manifest");
        if (auto err = db.exec("SELECT muninn.reader_register($1, $2, $3::int, nullif($4, ''), "
                               "jsonb_build_object('pooling', $5::text, 'ctx', $6::int, 'query_prefix', $7::text))",
                               {o.reader, have.model_sha, std::to_string(rd.dims), have.adapter_sha, o.pooling,
                                std::to_string(o.ctx), o.query_prefix}, &r))
            die("cannot register: " + *err);
        std::printf("registered reader %s (model %s, %d dimensions)\n", o.reader.c_str(),
                    have.model_sha.substr(0, 12).c_str(), rd.dims);
        PQclear(r);
        return 0;
    }

    check_seal(db, o, rd, have);

    if (!o.ask.empty()) {
        Reading q = rd.read(o.query_prefix + o.ask, true);
        if (q.v.empty()) die("the question has no tokens");
        std::printf("%lld\t%s\n", (long long)code64(q.v), code_literal(q.v).c_str());
        return 0;
    }
    if (!o.ask_file.empty()) {
        // The model loads once; each line is a question and gets its codes on the same line number.
        std::ifstream f(o.ask_file);
        if (!f) die("cannot read " + o.ask_file);
        std::string line;
        while (std::getline(f, line)) {
            Reading q = line.empty() ? Reading{} : rd.read(o.query_prefix + line, true);
            if (q.v.empty()) std::printf("\t\n");
            else std::printf("%lld\t%s\n", (long long)code64(q.v), code_literal(q.v).c_str());
        }
        return 0;
    }

    if (o.watch.empty()) die("--watch, --register or --ask is required");
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
            Reading rdg = body.empty() ? Reading{} : rd.read(body);
            std::optional<std::string> err;
            if (rdg.v.empty()) {
                err = db.exec("SELECT muninn.record_failure($1, $2, $3, $4::bytea, $5)",
                              {o.watch, key, o.reader, hash, body.empty() ? "empty text" : "the model produced no reading"});
                if (!err) failed++;
            } else {
                err = db.exec("SELECT muninn.record($1, $2, $3, $4::bytea, $5::bigint, $6::smallint[], nullif($7, '')::real)",
                              {o.watch, key, o.reader, hash, std::to_string(code64(rdg.v)), code_literal(rdg.v),
                               familiarity_param(rdg)});
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
