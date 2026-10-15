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
//   muninn-reader --backend B --model M.gguf [--lora A.gguf] --reader NAME --register [--dims D]
//   muninn-reader --backend B --model M.gguf --lora A.gguf --heads H.gguf --register --manifest manifest.json
//   muninn-reader --backend B --model M.gguf [--lora A.gguf] [--heads H.gguf] --reader NAME --watch W [--once]
//   muninn-reader --backend B --model M.gguf [--lora A.gguf] [--heads H.gguf] --reader NAME --ask "question"
//   muninn-reader ... --reader NAME --ask-file questions.txt   one question per line, one code per line
//   muninn-reader --backend B --print-compute                  the compute signature this process detects
//
// --backend cpu|cuda is always given and pins what the reader computes on: cpu hides every GPU from
// llama.cpp, cuda puts every layer on the GPU. There is no partial offload. The reader is sealed with
// that compute (pg_muninn 0.4.0) and refuses to read in a reader's name on any other.
//
// The database connection comes from the usual PG* environment variables (or --dsn).

#include <ggml-backend.h>
#include <ggml.h>
#include <gguf.h>
#include <libpq-fe.h>
#include <link.h>
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
    std::string model, lora, heads, manifest, reader, watch, dsn, ask, ask_file, ask_doc, query_prefix, pooling = "last";
    std::string backend;   // cpu | cuda: pinned by the process, never inherited from the environment
    int dims = 0, batch = 32, ctx = 512, threads = 4, audit = 0;
    bool once = false, do_register = false, print_compute = false;
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
        else if (a == "--ask-doc") o.ask_doc = next();
        else if (a == "--query-prefix") o.query_prefix = next();
        else if (a == "--pooling") o.pooling = next();
        else if (a == "--dims") o.dims = std::stoi(next());
        else if (a == "--batch") o.batch = std::stoi(next());
        else if (a == "--ctx") o.ctx = std::stoi(next());
        else if (a == "--backend") o.backend = next();
        else if (a == "--threads") o.threads = std::stoi(next());
        else if (a == "--print-compute") o.print_compute = true;
        else if (a == "--gpu-layers")
            die("--gpu-layers is gone: a partial offload has no reproducible compute; use --backend cpu|cuda");
        else if (a == "--once") o.once = true;
        else if (a == "--audit") o.audit = std::stoi(next());
        else if (a == "--register") o.do_register = true;
        else die("unknown option " + a);
    }
    if (o.backend != "cpu" && o.backend != "cuda") die("--backend cpu|cuda is required: the reader pins what it computes on");
    if (o.threads < 1) die("--threads must be at least 1");
    if (o.print_compute) return o;
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

// ------------------------------------------------------------ the compute --

// What the same weights are computed on changes the reading: CPU and GPU kernels round differently,
// and a 256-bit code can flip a few bits between them. So a reader is sealed with its compute too,
// and this is detected here, in the process, from what llama.cpp actually sees and loaded, never
// taken from a flag on trust.
//
// The number of threads is not part of it: measured (ygg mun_sello_hilos, 2026-10-15), 220 texts read
// on the CPU with 4 threads and re-read with 8 and with 16 give the same 256-bit code, every one. If
// that ever changes, the threads must enter the signature, or the signature lies.
struct Compute {
    std::string backend, device, system_info, libs;
};

// Before llama.cpp initialises anything: with --backend cpu no GPU may be visible at all, or
// llama.cpp would still send the large matrix products of a batch to it (op offload).
void pin_backend(const Options &o) {
    if (o.backend == "cpu") setenv("CUDA_VISIBLE_DEVICES", "", 1);
    llama_backend_init();
    llama_log_set([](ggml_log_level level, const char *text, void *) {
        if (level >= GGML_LOG_LEVEL_ERROR) std::fputs(text, stderr);
    }, nullptr);
}

// The libraries that compute: llama.cpp and ggml always, and for cuda also the CUDA runtime, cuBLAS
// and the driver, whose kernels the GPU runs.
std::vector<std::string> compute_libraries(const std::string &backend) {
    std::vector<std::string> prefixes = {"libllama.", "libggml.", "libggml-base.", "libggml-cpu"};
    if (backend == "cuda")
        for (const char *p : {"libggml-cuda.", "libcudart.", "libcublas.", "libcublasLt.", "libcuda."}) prefixes.push_back(p);
    std::vector<std::string> found;
    struct Ctx { const std::vector<std::string> *prefixes; std::vector<std::string> *found; } c{&prefixes, &found};
    dl_iterate_phdr([](dl_phdr_info *info, size_t, void *data) {
        auto *c = static_cast<Ctx *>(data);
        std::string path = info->dlpi_name ? info->dlpi_name : "";
        std::string base = path.substr(path.find_last_of('/') + 1);
        for (auto &p : *c->prefixes)
            if (base.rfind(p, 0) == 0) c->found->push_back(path);
        return 0;
    }, &c);
    std::sort(found.begin(), found.end(), [](const std::string &a, const std::string &b) {
        return a.substr(a.find_last_of('/') + 1) < b.substr(b.find_last_of('/') + 1);
    });
    found.erase(std::unique(found.begin(), found.end()), found.end());
    return found;
}

// One sha256 over the contents of the libraries, in a fixed order.
std::string sha256_of_all(const std::vector<std::string> &paths) {
    std::string cmd = "cat --";
    for (auto &path : paths) {
        if (path.find('\'') != std::string::npos) die("refusing a path with a quote in it: " + path);
        cmd += " '" + path + "'";
    }
    cmd += " | sha256sum";
    std::unique_ptr<FILE, int (*)(FILE *)> p(popen(cmd.c_str(), "r"), pclose);
    if (!p) die("cannot run sha256sum");
    std::array<char, 65> hex{};
    if (std::fscanf(p.get(), "%64s", hex.data()) != 1) die("cannot hash the compute libraries");
    return std::string(hex.data());
}

// The kernels a ggml backend was built with (CPU: AVX512 = 1, ...; CUDA: ARCHS = 1200, ...).
std::string backend_features(ggml_backend_reg_t reg) {
    std::string s = ggml_backend_reg_name(reg);
    auto get = (ggml_backend_get_features_t)ggml_backend_reg_get_proc_address(reg, "ggml_backend_get_features");
    if (get)
        for (ggml_backend_feature *f = get(reg); f && f->name; f++) s += std::string(" ") + f->name + "=" + f->value;
    return s;
}

Compute detect_compute(const Options &o) {
    Compute c;
    c.backend = o.backend;
    std::vector<std::string> gpus, cpus;
    for (size_t i = 0; i < ggml_backend_dev_count(); i++) {
        ggml_backend_dev_t d = ggml_backend_dev_get(i);
        auto t = ggml_backend_dev_type(d);
        std::string desc = ggml_backend_dev_description(d);
        if (t == GGML_BACKEND_DEVICE_TYPE_CPU) cpus.push_back(desc);
        else gpus.push_back(desc);
    }
    if (o.backend == "cpu" && !gpus.empty())
        die("--backend cpu, but llama.cpp still sees a device: " + gpus.front());
    if (o.backend == "cuda" && gpus.empty()) die("--backend cuda, but llama.cpp sees no GPU");
    if (cpus.empty()) die("llama.cpp sees no CPU device");
    // The CPU takes part either way (embeddings lookup, what is not offloaded); the GPU only on cuda.
    c.device = o.backend == "cuda" ? gpus.front() + " + " + cpus.front() : cpus.front();
    for (size_t i = 0; i < ggml_backend_reg_count(); i++) {
        ggml_backend_reg_t reg = ggml_backend_reg_get(i);
        std::string name = ggml_backend_reg_name(reg);
        if (name == "CPU" || (o.backend == "cuda" && name == "CUDA"))
            c.system_info += (c.system_info.empty() ? "" : " | ") + backend_features(reg);
    }
    auto libs = compute_libraries(o.backend);
    if (libs.empty()) die("cannot find the llama.cpp libraries this process loaded");
    c.libs = sha256_of_all(libs);
    return c;
}

// The signature as jsonb, built by the database so nothing is escaped by hand here.
constexpr const char *kComputeJson =
    "jsonb_build_object('backend', $%d::text, 'device', $%d::text, 'system_info', $%d::text, 'libs', $%d::text)";

std::string compute_json(int first) {
    char buf[256];
    std::snprintf(buf, sizeof buf, kComputeJson, first, first + 1, first + 2, first + 3);
    return buf;
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
    int tokens_read = 0, tokens_total = 0;   // of the text itself, marker and instruction aside
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

    // The backend was pinned before this (pin_backend), so cuda means every layer on the GPU and cpu
    // means no GPU is visible at all. Nothing is left to llama.cpp's judgement of the free VRAM.
    explicit Reader(const Options &o) {
        auto mp = llama_model_default_params();
        mp.n_gpu_layers = o.backend == "cuda" ? 999 : 0;
        model = llama_model_load_from_file(o.model.c_str(), mp);
        if (!model) die("cannot load " + o.model + (o.backend == "cuda" ? " entirely on the GPU" : ""));
        auto cp = llama_context_default_params();
        cp.op_offload = o.backend == "cuda";
        cp.n_threads = cp.n_threads_batch = o.threads;
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
        // too long: keep the head, which is where a recipe puts what matters, and say so
        int total = (int)toks.size();
        if (total > max_tokens) toks.resize(max_tokens);
        if (!decode(toks, true)) return {};
        const float *e = llama_get_embeddings_seq(ctx, 0);
        if (!e) return {};
        return {unit(std::vector<float>(e, e + dims)), std::nullopt, (int)toks.size(), total};
    }

    // The contract: the piece tokenized without special tokens, closed by the marker, read at the
    // marker's last token (layer -1, the final normed state), turned into a vector by the heads.
    Reading read_contract(const std::string &text) {
        if (marker.empty()) die("internal: contract reader without its manifest");
        auto toks = tokenize(text, false);
        if (toks.empty()) return {};
        size_t room = (size_t)max_tokens - marker.size();
        int total = (int)toks.size();
        if (toks.size() > room) toks.resize(room);
        int kept = (int)toks.size();
        toks.insert(toks.end(), marker.begin(), marker.end());
        if (!decode(toks, true)) return {};
        const float *h = llama_get_embeddings_ith(ctx, -1);
        if (!h) return {};
        return {unit(heads->project(h, dims)), heads->familiarity(h), kept, total};
    }

    // A document read in place ("late chunking"): every piece tokenized without special tokens and
    // closed by the marker, all of them in ONE forward with consecutive positions, each read at its
    // marker's last token -- so a piece's state has attended to the pieces before it. The trainer's
    // Codec.document, token for token: pieces that do not fit are dropped from the end, and the
    // caller sees how many survived. A one-piece document is exactly read_contract().
    std::vector<Reading> read_document(const std::vector<std::string> &pieces) {
        if (!heads || marker.empty()) die("--ask-doc needs a contract reader (--heads and its manifest)");
        std::vector<llama_token> toks;
        std::vector<int> at;
        for (const auto &p : pieces) {
            auto t = tokenize(p, false);
            if (toks.size() + t.size() + marker.size() > (size_t)max_tokens) break;
            toks.insert(toks.end(), t.begin(), t.end());
            toks.insert(toks.end(), marker.begin(), marker.end());
            at.push_back((int)toks.size() - 1);
        }
        if (at.empty()) return {};
        llama_memory_clear(llama_get_memory(ctx), true);
        int n = (int)toks.size();
        llama_batch b = llama_batch_init(n, 0, 1);
        size_t next_at = 0;
        for (int i = 0; i < n; i++) {
            b.token[i] = toks[i];
            b.pos[i] = i;
            b.n_seq_id[i] = 1;
            b.seq_id[i][0] = 0;
            b.logits[i] = next_at < at.size() && at[next_at] == i;
            if (b.logits[i]) next_at++;
        }
        b.n_tokens = n;
        int rc = llama_decode(ctx, b);
        llama_batch_free(b);
        if (rc != 0) return {};
        std::vector<Reading> out;
        for (int i : at) {
            const float *h = llama_get_embeddings_ith(ctx, i);
            if (!h) return {};
            out.push_back({unit(heads->project(h, dims)), heads->familiarity(h)});
        }
        return out;
    }
};

// Standard base64 (no line breaks), for --ask-doc: pieces carry newlines and tabs of their own.
std::string from_base64(const std::string &in) {
    static const std::string abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -8;
    for (char ch : in) {
        if (ch == '=') break;
        size_t p = abc.find(ch);
        if (p == std::string::npos) continue;
        val = (val << 6) + (int)p;
        bits += 6;
        if (bits >= 0) {
            out.push_back(char((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

// The 64-bit code: the signs of the first 64 dimensions (the Matryoshka head).
int64_t code64(const std::vector<float> &v) {
    uint64_t c = 0;
    for (int i = 0; i < 64; i++)
        if (v[i] > 0) c |= (uint64_t(1) << i);
    int64_t s;
    std::memcpy(&s, &c, sizeof s);
    return s;
}

// The 256-bit code (0.2.0): the signs of the first 256 dimensions, as a bit(256) literal whose
// leftmost bit is dimension 0. Taken from the float vector, like code64, never from the int8 code
// (int8 rounds small values to 0 and would lose their sign). Empty when the vector is shorter.
std::string code256(const std::vector<float> &v) {
    if (v.size() < 256) return "";
    std::string s(256, '0');
    for (int i = 0; i < 256; i++)
        if (v[i] > 0) s[i] = '1';
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

// Proves this process computes on what the reader was sealed with. Runs before the model is loaded,
// so a process on the wrong backend is turned away without touching the weights or the GPU.
void check_compute(Db &db, const Options &o, const Compute &have) {
    PGresult *r = nullptr;
    std::string sql = "SELECT muninn.reader_compute_matches($1, " + compute_json(2) + "), "
                      "coalesce(muninn.reader_compute($1)->>'backend', ''), coalesce(muninn.reader_compute($1)->>'device', ''), "
                      "EXISTS (SELECT 1 FROM muninn.reader_seal($1))";
    if (auto err = db.exec(sql.c_str(), {o.reader, have.backend, have.device, have.system_info, have.libs}, &r))
        die("cannot read the compute seal of reader " + o.reader + ": " + *err);
    bool matches = std::string(PQgetvalue(r, 0, 0)) == "t", exists = std::string(PQgetvalue(r, 0, 3)) == "t";
    std::string backend = PQgetvalue(r, 0, 1), device = PQgetvalue(r, 0, 2);
    PQclear(r);
    if (matches) return;
    if (!exists) die("no reader named " + o.reader + " (register it with --register)");
    if (backend.empty())
        die("reader " + o.reader + " was registered without its compute (before pg_muninn 0.4.0): register it again "
            "with --register --backend, and switch the watch to it with muninn.reader_switch()");
    die("this process computes on " + have.backend + " (" + have.device + "), but reader " + o.reader +
        " was sealed on " + backend + " (" + device + ") or with other kernels or libraries: refusing to read in its name");
}

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
    pin_backend(o);
    Compute compute = detect_compute(o);
    if (o.print_compute) {
        std::printf("backend\t%s\ndevice\t%s\nsystem_info\t%s\nlibs\t%s\n", compute.backend.c_str(),
                    compute.device.c_str(), compute.system_info.c_str(), compute.libs.c_str());
        for (auto &lib : compute_libraries(o.backend)) std::printf("lib\t%s\n", lib.c_str());
        return 0;
    }
    Db db(o.dsn);
    if (!o.do_register) check_compute(db, o, compute);
    Seal have{sha256_of(o.model), o.lora.empty() ? "" : sha256_of(o.lora),
              o.heads.empty() ? "" : sha256_of(o.heads)};
    Reader rd(o);

    if (o.do_register) {
        const std::vector<std::string> cv = {compute.backend, compute.device, compute.system_info, compute.libs};
        PGresult *r = nullptr;
        if (!o.manifest.empty()) {
            // The manifest names adapter and heads; the base is sealed here, from the file loaded.
            if (auto err = db.exec("SELECT $1::jsonb->>'adapter_sha256' = $2 AND $1::jsonb->>'heads_sha256' = $3",
                                   {read_file(o.manifest), have.adapter_sha, have.heads_sha}, &r))
                die("cannot read the manifest: " + *err);
            bool match = std::string(PQgetvalue(r, 0, 0)) == "t";
            PQclear(r);
            if (!match) die("the --lora/--heads loaded are not the ones the manifest names: refusing to register");
            std::vector<std::string> params = {read_file(o.manifest), have.model_sha};
            params.insert(params.end(), cv.begin(), cv.end());
            std::string sql = "SELECT muninn.reader_register(jsonb_set($1::jsonb, '{base_sha256}', to_jsonb($2::text)), " +
                              compute_json(3) + "), ($1::jsonb->>'reader') || '-' || ($1::jsonb->>'version') || '@' || $3";
            if (auto err = db.exec(sql.c_str(), params, &r)) die("cannot register: " + *err);
            std::printf("registered reader %s (base %s, adapter %s, heads %s; %s on %s)\n", PQgetvalue(r, 0, 1),
                        have.model_sha.substr(0, 12).c_str(), have.adapter_sha.substr(0, 12).c_str(),
                        have.heads_sha.substr(0, 12).c_str(), compute.backend.c_str(), compute.device.c_str());
            PQclear(r);
            return 0;
        }
        if (rd.heads) die("a reader with heads registers through its --manifest");
        std::vector<std::string> params = {o.reader, have.model_sha, std::to_string(rd.dims), have.adapter_sha,
                                           o.pooling, std::to_string(o.ctx), o.query_prefix};
        params.insert(params.end(), cv.begin(), cv.end());
        std::string sql = "SELECT muninn.reader_register($1, $2, $3::int, nullif($4, ''), "
                          "jsonb_build_object('pooling', $5::text, 'ctx', $6::int, 'query_prefix', $7::text), " +
                          compute_json(8) + ")";
        if (auto err = db.exec(sql.c_str(), params, &r)) die("cannot register: " + *err);
        std::printf("registered reader %s (model %s, %d dimensions; %s on %s)\n", o.reader.c_str(),
                    have.model_sha.substr(0, 12).c_str(), rd.dims, compute.backend.c_str(), compute.device.c_str());
        PQclear(r);
        return 0;
    }

    check_seal(db, o, rd, have);

    if (!o.ask.empty()) {
        Reading q = rd.read(o.query_prefix + o.ask, true);
        if (q.v.empty()) die("the question has no tokens");
        std::printf("%lld\t%s\t%s\n", (long long)code64(q.v), code_literal(q.v).c_str(), code256(q.v).c_str());
        return 0;
    }
    if (!o.ask_doc.empty()) {
        // Documents read in place, for measuring (F3a): "D <id>" opens a document, each "P <base64>"
        // line is one of its pieces, in order. Out: one line per piece that fit, with its document,
        // its index, both codes, the int8 code and the familiarity. A question is a one-piece
        // document whose text already carries the manifest's query instruction.
        std::ifstream f(o.ask_doc);
        if (!f) die("cannot read " + o.ask_doc);
        std::string line, doc;
        std::vector<std::string> pieces;
        auto flush = [&]() {
            if (doc.empty()) return;
            auto rs = rd.read_document(pieces);
            for (size_t i = 0; i < rs.size(); i++) {
                const Reading &q = rs[i];
                std::printf("%s\t%zu\t%lld\t%s\t%s\t%s\n", doc.c_str(), i, (long long)code64(q.v),
                            code_literal(q.v).c_str(), code256(q.v).c_str(),
                            q.familiarity ? std::to_string(*q.familiarity).c_str() : "");
            }
            std::fflush(stdout);
            pieces.clear();
        };
        while (std::getline(f, line)) {
            if (line.rfind("D ", 0) == 0) {
                flush();
                doc = line.substr(2);
            } else if (line.rfind("P ", 0) == 0) {
                pieces.push_back(from_base64(line.substr(2)));
            }
        }
        flush();
        return 0;
    }
    if (!o.ask_file.empty()) {
        // The model loads once; each line is a question and gets its codes on the same line number.
        std::ifstream f(o.ask_file);
        if (!f) die("cannot read " + o.ask_file);
        std::string line;
        while (std::getline(f, line)) {
            Reading q = line.empty() ? Reading{} : rd.read(o.query_prefix + line, true);
            if (q.v.empty()) std::printf("\t\t\n");
            else std::printf("%lld\t%s\t%s\n", (long long)code64(q.v), code_literal(q.v).c_str(),
                             code256(q.v).c_str());
        }
        return 0;
    }

    if (o.watch.empty()) die("--watch, --register or --ask is required");

    if (o.audit > 0) {
        // The self-audit (0.3.0): re-read a sample of this reader's own fresh readings, as they are
        // now, and let the database say whether each one reproduces. Nothing is recorded as a
        // reading; a reading that does not reproduce stays in muninn.audits as a broken assertion.
        PGresult *r = nullptr;
        if (auto err = db.exec("SELECT key, body, text_hash::text FROM muninn.audit_sample($1, $2::int)",
                               {o.watch, std::to_string(o.audit)}, &r))
            die("cannot ask for an audit sample: " + *err);
        long holds = 0, broken = 0, skipped = 0;
        for (int i = 0; i < PQntuples(r); i++) {
            std::string key = PQgetvalue(r, i, 0), body = PQgetvalue(r, i, 1), hash = PQgetvalue(r, i, 2);
            Reading again = rd.read(body);
            PGresult *a = nullptr;
            if (auto err = db.exec("SELECT muninn.record_audit($1, $2, $3, $4::bytea, $5::smallint[], nullif($6, '')::bit(256))",
                                   {o.watch, key, o.reader, hash, code_literal(again.v), code256(again.v)}, &a))
                die("cannot record an audit: " + *err);
            if (PQgetisnull(a, 0, 0)) skipped++;
            else if (std::string(PQgetvalue(a, 0, 0)) == "t") holds++;
            else broken++;
            PQclear(a);
        }
        PQclear(r);
        std::printf("audit %s: %ld hold, %ld broken, %ld skipped (changed meanwhile)\n",
                    o.watch.c_str(), holds, broken, skipped);
        return broken ? 2 : 0;
    }
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
                err = db.exec("SELECT muninn.record($1, $2, $3, $4::bytea, $5::bigint, $6::smallint[], "
                              "nullif($7, '')::real, nullif($8, '')::bit(256), $9::int, $10::int)",
                              {o.watch, key, o.reader, hash, std::to_string(code64(rdg.v)), code_literal(rdg.v),
                               familiarity_param(rdg), code256(rdg.v), std::to_string(rdg.tokens_read),
                               std::to_string(rdg.tokens_total)});
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
