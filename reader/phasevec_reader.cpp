// Copyright 2026 Manuel Reyes Bravo
// SPDX-License-Identifier: Apache-2.0
//
// phasevec-reader: the process that reads for a watch.
//
// It loads a sealed model with llama.cpp, proves to the database that the weights it loaded are the
// ones the reader was registered with (sha256), and then reads what phasevec.next() hands out: every
// row never read, read from older text, or read by another reader. Each reading is recorded with the
// hash of the exact text it read, so the database can refuse it if the row changed meanwhile.
//
// No HTTP, no service in between: the model runs in this process, and the database is the only
// authority on what to read and on whether a reading still holds.
//
// Two ways to read:
//   pooled    an off-the-shelf embedding model: llama.cpp pools the sequence (--pooling last|mean).
//             The text is tokenized alone, cut to fit, and closed by the model's own special tokens
//             (its BOS and EOS flags), so a long text keeps the token the model pools at. Pooling,
//             context and query instruction are sealed at --register and taken from the seal after.
//   contract  a reader trained for Phasevec (--heads): the text is closed by the reader's marker, the
//             state is taken at the marker's last token, and the reader's own heads turn it into the
//             vector (projection, Matryoshka prefix) and into a familiarity score. Marker and query
//             instruction come from the manifest sealed in the database, never from the command line.
//
//   phasevec-reader --backend B --model M.gguf [--lora A.gguf] --reader NAME --register [--dims D]
//   phasevec-reader --backend B --model M.gguf --lora A.gguf --heads H.gguf --register --manifest manifest.json
//   phasevec-reader --backend B --model M.gguf [--lora A.gguf] [--heads H.gguf] --reader NAME --watch W [--once]
//   phasevec-reader --backend B --model M.gguf [--lora A.gguf] [--heads H.gguf] --reader NAME --ask "question"
//   phasevec-reader ... --reader NAME --ask-file questions.txt   one question per line, one code per line
//   phasevec-reader ... --reader NAME --embed-file texts.txt     "Q <base64>" (a question) or "D <base64>"
//       (a document) per line; one line out each: kind, code64, int8 code, code256, tokens read, total
//   phasevec-reader --backend B --print-compute                  the compute signature this process detects
//   phasevec-reader --backend B ... --reader NAME --watch W --serve SOCKET
//       the asker: a JSON line {"q": ..., "k": 10, "m": 200, "partial": false} in, a JSON line out with
//       the hits of phasevec.find (key, score, hamming, state, familiarity, read_at, truncated), the
//       watch's coverage and the time to read the question and to find; or {"error": ...}. With
//       "hybrid": true (and "lm", default 200) it asks phasevec.find_hybrid (pg_phasevec 0.6.0), and each
//       hit also carries its rank and score in the vector and the lexical arm.
//   phasevec-reader --backend B ... --watch W1 --watch W2 ... [--serve-dir DIR]
//       one process, one model in memory, for every watch read by the same weights, compute, pooling
//       and context: each watch is read in the name of ITS reader (phasevec.watches, or --reader for
//       all), whose seal is proved against what was loaded, and keeps its own query instruction. With
//       --serve-dir each watch answers on DIR/<watch>.sock, the path phasevec._ask() connects to.
//
// --backend cpu|cuda is always given and pins what the reader computes on: cpu hides every GPU from
// llama.cpp, cuda puts every layer on the GPU. There is no partial offload. The reader is sealed with
// that compute (pg_phasevec 0.4.0) and refuses to read in a reader's name on any other.
//
// The database connection comes from the usual PG* environment variables (or --dsn).

#include <ggml-backend.h>
#include <ggml.h>
#include <gguf.h>
#include <libpq-fe.h>
#include <link.h>
#include <llama.h>

#include <algorithm>
#include <cctype>
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
#include <chrono>
#include <csignal>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

namespace {

struct Options {
    std::string model, lora, heads, manifest, reader, watch, dsn, ask, ask_file, ask_doc, embed_file, query_prefix,
        pooling = "last";
    std::string backend;   // cpu | cuda: pinned by the process, never inherited from the environment
    std::string serve;     // a unix socket: answer questions on the watch, one JSON line each way
    std::string serve_dir; // a directory: answer each watch's questions on <dir>/<watch>.sock
    std::vector<std::string> watches;   // every --watch, in order; `watch` is the first
    int dims = 0, batch = 32, ctx = 512, threads = 4, audit = 0;
    bool once = false, do_register = false, print_compute = false, no_repack = false;
};

[[noreturn]] void die(const std::string &msg) {
    std::fprintf(stderr, "phasevec-reader: %s\n", msg.c_str());
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
        else if (a == "--watch") o.watches.push_back(next());
        else if (a == "--dsn") o.dsn = next();
        else if (a == "--ask") o.ask = next();
        else if (a == "--ask-file") o.ask_file = next();
        else if (a == "--ask-doc") o.ask_doc = next();
        else if (a == "--embed-file") o.embed_file = next();
        else if (a == "--serve") o.serve = next();
        else if (a == "--serve-dir") o.serve_dir = next();
        else if (a == "--query-prefix") o.query_prefix = next();
        else if (a == "--pooling") o.pooling = next();
        else if (a == "--dims") o.dims = std::stoi(next());
        else if (a == "--batch") o.batch = std::stoi(next());
        else if (a == "--ctx") o.ctx = std::stoi(next());
        else if (a == "--backend") o.backend = next();
        else if (a == "--threads") o.threads = std::stoi(next());
        else if (a == "--print-compute") o.print_compute = true;
        else if (a == "--no-repack") o.no_repack = true;
        else if (a == "--gpu-layers")
            die("--gpu-layers is gone: a partial offload has no reproducible compute; use --backend cpu|cuda");
        else if (a == "--once") o.once = true;
        else if (a == "--audit") o.audit = std::stoi(next());
        else if (a == "--register") o.do_register = true;
        else die("unknown option " + a);
    }
    if (o.backend != "cpu" && o.backend != "cuda") die("--backend cpu|cuda is required: the reader pins what it computes on");
    if (!o.watches.empty()) o.watch = o.watches.front();
    for (size_t i = 0; i < o.watches.size(); i++)
        for (size_t j = 0; j < i; j++)
            if (o.watches[i] == o.watches[j]) die("watch " + o.watches[i] + " is given twice");
    if (o.threads < 1) die("--threads must be at least 1");
    if (o.print_compute) return o;
    if (o.model.empty()) die("--model is required");
    if (!o.manifest.empty() && (!o.do_register || o.heads.empty() || o.lora.empty()))
        die("--manifest is for --register, with the --lora and --heads it names");
    // Reading watches, each watch's reader can come from the database; everything else names it.
    const bool asking = !o.ask.empty() || !o.ask_file.empty() || !o.ask_doc.empty() || !o.embed_file.empty();
    if (o.reader.empty() && o.manifest.empty() && (o.watches.empty() || o.do_register || asking))
        die("--reader is required");
    if (o.watches.size() > 1 && (o.audit > 0 || !o.serve.empty()))
        die("with several watches: --audit takes one watch, and they are served with --serve-dir");
    if (!o.serve.empty() && !o.serve_dir.empty()) die("--serve or --serve-dir, not both");
    if (o.pooling != "last" && o.pooling != "mean") die("--pooling is last or mean");
    if (!o.heads.empty() && !o.query_prefix.empty())
        die("a contract reader takes its query instruction from its manifest, not from --query-prefix");
    if (!o.query_prefix.empty() && !o.do_register)
        die("a pooled reader's query instruction is sealed at --register and taken from the seal, not from --query-prefix");
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
    // Not repacking the weights changes the bits (measured), so it is a different compute. The
    // default (repacking) leaves the signature as it was, so readers sealed before keep matching.
    if (o.no_repack) c.system_info += " | weights not repacked";
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
        // heads written before the rename (vec-0.1.0, sealed by sha256: they cannot be rewritten) carry
        // the key under its old name; without this fallback the check below would be skipped silently
        int64_t key = gguf_find_key(g, "phasevec.layer");
        if (key < 0) key = gguf_find_key(g, "muninn.layer");
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
        // --no-repack: the weights are read from the GGUF's mmap instead of copied into anonymous
        // memory in the layout of the CPU's faster kernels: page cache the kernel can hand to other
        // processes (anonymous memory 1 GB instead of 4.9), 1.44 times slower. It CHANGES THE BITS
        // (ygg mun_norepack_bits: 28 of 220 readings reproduced), so it is part of the compute
        // signature (detect_compute) and a reader sealed with repacking refuses it.
        mp.use_extra_bufts = !o.no_repack;
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

    // A document piece, or a question when `query` is set: the reader's sealed query instruction first.
    Reading read(const std::string &text, bool query = false) {
        return read_body(query ? query_instruction + text : text);
    }

    // The text exactly as it is to be read: a question carries its watch's instruction already.
    Reading read_body(const std::string &body) {
        return heads ? read_contract(body) : read_pooled(body);
    }

    // An off-the-shelf model: the text tokenized alone (a special token written in a row is text, not
    // control), cut to what fits, then closed by the model's own special tokens. Cutting after the
    // specials were added (until 0.6.0) dropped the EOS of every long text, and a last-token reader
    // then pooled at a word instead of at the token it was trained to read. Counts are of the text.
    Reading read_pooled(const std::string &text) {
        auto toks = tokenize(text, false);
        if (toks.empty()) return {};
        const bool bos = llama_vocab_get_add_bos(vocab), eos = llama_vocab_get_add_eos(vocab);
        int total = (int)toks.size();
        size_t room = (size_t)max_tokens - (bos ? 1 : 0) - (eos ? 1 : 0);
        // too long: keep the head, which is where a recipe puts what matters, and say so
        if (toks.size() > room) toks.resize(room);
        int kept = (int)toks.size();
        if (bos) toks.insert(toks.begin(), llama_vocab_bos(vocab));
        if (eos) toks.push_back(llama_vocab_eos(vocab));
        if (!decode(toks, true)) return {};
        const float *e = llama_get_embeddings_seq(ctx, 0);
        if (!e) return {};
        return {unit(std::vector<float>(e, e + dims)), std::nullopt, kept, total};
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
void check_compute(Db &db, const std::string &reader, const Compute &have) {
    PGresult *r = nullptr;
    std::string sql = "SELECT phasevec.reader_compute_matches($1, " + compute_json(2) + "), "
                      "coalesce(phasevec.reader_compute($1)->>'backend', ''), coalesce(phasevec.reader_compute($1)->>'device', ''), "
                      "EXISTS (SELECT 1 FROM phasevec.reader_seal($1))";
    if (auto err = db.exec(sql.c_str(), {reader, have.backend, have.device, have.system_info, have.libs}, &r))
        die("cannot read the compute seal of reader " + reader + ": " + *err);
    bool matches = std::string(PQgetvalue(r, 0, 0)) == "t", exists = std::string(PQgetvalue(r, 0, 3)) == "t";
    std::string backend = PQgetvalue(r, 0, 1), device = PQgetvalue(r, 0, 2);
    PQclear(r);
    if (matches) return;
    if (!exists) die("no reader named " + reader + " (register it with --register)");
    if (backend.empty())
        die("reader " + reader + " was registered without its compute (before pg_phasevec 0.4.0): register it again "
            "with --register --backend, and switch the watch to it with phasevec.reader_switch()");
    die("this process computes on " + have.backend + " (" + have.device + "), but reader " + reader +
        " was sealed on " + backend + " (" + device + ") or with other kernels or libraries: refusing to read in its name");
}

// How a pooled reader tokenizes, as its manifest says it (0.6.0). A pooled reader registered without it
// was read by a process that dropped the closing token of every truncated text: its readings are of
// another reading, so it is registered again, as another reader, never served under the old name.
constexpr const char *kPooledTokens = "text alone, cut to fit, closed by the model's own special tokens";

// Proves the loaded weights are the registered ones. A contract reader takes its marker and query
// instruction from the sealed manifest; a pooled one, its query instruction, and it must be served
// with the pooling and the context it was sealed with, which decide what it reads.
// Returns the reader's query instruction. Several readers may share the process only if they read
// documents the same way: same weights, dimensions, pooling and context, and for contract readers the
// same marker; they may differ in the instruction a question is read with.
std::string check_seal(Db &db, const Options &o, Reader &rd, const Seal &have, const std::string &reader) {
    PGresult *r = nullptr;
    if (auto err = db.exec("SELECT model_sha, coalesce(adapter_sha, ''), dims, coalesce(heads_sha, ''), "
                           "coalesce(manifest->>'marker', ''), coalesce(manifest->>'query_instruction', ''), "
                           "coalesce(manifest->>'pooling', ''), coalesce(manifest->>'ctx', ''), "
                           "coalesce(manifest->>'query_prefix', ''), coalesce(manifest->>'tokens', '') "
                           "FROM phasevec.reader_seal($1)", {reader}, &r))
        die("cannot read the seal of reader " + reader + ": " + *err);
    if (PQntuples(r) != 1) die("no reader named " + reader + " (register it with --register)");
    std::string m = PQgetvalue(r, 0, 0), a = PQgetvalue(r, 0, 1), h = PQgetvalue(r, 0, 3);
    int dims = std::atoi(PQgetvalue(r, 0, 2));
    std::string marker = PQgetvalue(r, 0, 4), instruction = PQgetvalue(r, 0, 5);
    std::string pooling = PQgetvalue(r, 0, 6), ctx = PQgetvalue(r, 0, 7), prefix = PQgetvalue(r, 0, 8),
                tokens = PQgetvalue(r, 0, 9);
    PQclear(r);
    if (m != have.model_sha || a != have.adapter_sha || h != have.heads_sha)
        die("the weights loaded are not the ones reader " + reader + " was registered with: refusing to read in its name");
    if (dims != rd.dims) die("reader " + reader + " was registered with " + std::to_string(dims) + " dimensions");
    if (rd.heads) {
        if (marker.empty()) die("reader " + reader + " has heads but its manifest names no marker");
        if (rd.marker.empty()) rd.set_contract(marker, instruction);
        else if (rd.tokenize(marker, false) != rd.marker)
            die("reader " + reader + " closes documents with another marker than the watches already served here");
        return instruction;
    }
    if (tokens != kPooledTokens)
        die("reader " + reader + " was registered before pooled readers kept the closing token of a truncated "
            "text (pg_phasevec 0.6.0): register the model again under a new name, and reader_switch the watch to it");
    if (pooling != o.pooling) die("reader " + reader + " was sealed with --pooling " + pooling + ", not " + o.pooling);
    if (ctx != std::to_string(o.ctx)) die("reader " + reader + " was sealed with --ctx " + ctx + ", not " + std::to_string(o.ctx));
    return prefix;
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

// ------------------------------------------------------------------ serving --

// A watch this process reads, in the name of its reader, with that reader's query instruction.
struct Watch {
    std::string name, reader, instruction;
    long read_ok = 0, refused = 0, failed = 0;
    bool drained = false;   // its queue emptied and was maintained since the last wait
};

// A watch's name becomes a file name (its socket), so only names phasevec._ask() would accept.
bool safe_watch_name(const std::string &w) {
    if (w.empty() || w.size() > 63 || w[0] == '.') return false;
    for (unsigned char c : w)
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') return false;
    return true;
}

// One JSON object per line, built by the database so nothing is escaped by hand here.
std::string json_error(Db &db, const std::string &msg) {
    PGresult *r = nullptr;
    if (db.exec("SELECT jsonb_build_object('error', $1::text)::text", {msg}, &r)) return "{\"error\": \"internal\"}";
    std::string out = PQgetvalue(r, 0, 0);
    PQclear(r);
    return out;
}

// A JSON string literal (quotes, backslashes and control characters escaped).
std::string json_string(const std::string &v) {
    std::string out = "\"";
    for (unsigned char ch : v) {
        if (ch == '"' || ch == '\\') { out += '\\'; out += (char)ch; }
        else if (ch < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", ch); out += b; }
        else out += (char)ch;
    }
    return out + "\"";
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

// One question: {"q": text, "k": 10, "m": 200, "partial": false, "codes": false, "hybrid": false,
// "lm": 200, "encode": false}; with encode only the question's codes come back (nothing is searched); with codes the answer also carries the question's code64, int8 code and code256; with
// hybrid it is asked of phasevec.find_hybrid, with the question's text for the lexical arm. The question is read by this
// process, which proved its seal and compute, so it is comparable with the watch's readings; find
// refuses below the watch's declared coverage unless partial is asked for, and that refusal comes
// back as {"error": ...}: the caller fails cleanly instead of reading a half-read corpus as whole.
std::string answer(Db &db, const Watch &w, Reader &rd, const std::string &line) {
    PGresult *r = nullptr;
    if (auto err = db.exec("SELECT j->>'q', coalesce((j->>'k')::int, 10), coalesce((j->>'m')::int, 200), "
                           "coalesce((j->>'partial')::boolean, false), coalesce((j->>'codes')::boolean, false), "
                           "coalesce((j->>'hybrid')::boolean, false), coalesce((j->>'lm')::int, 200), "
                           "coalesce((j->>'encode')::boolean, false) "
                           "FROM (SELECT $1::jsonb AS j) x",
                           {line}, &r))
        return json_error(db, "a question is one JSON object per line: {\"q\": text, \"k\": 10, \"m\": 200, \"partial\": false}");
    bool no_q = PQgetisnull(r, 0, 0);
    std::string q = no_q ? "" : PQgetvalue(r, 0, 0), k = PQgetvalue(r, 0, 1), m = PQgetvalue(r, 0, 2);
    std::string partial = PQgetvalue(r, 0, 3), codes = PQgetvalue(r, 0, 4), lm = PQgetvalue(r, 0, 6);
    bool hybrid = std::string(PQgetvalue(r, 0, 5)) == "t";
    bool encode = std::string(PQgetvalue(r, 0, 7)) == "t";
    PQclear(r);
    if (q.empty()) return json_error(db, "the question (q) is empty");

    auto t0 = std::chrono::steady_clock::now();
    Reading rq = rd.read_body(w.instruction + q);
    double encode_ms = ms_since(t0);
    if (rq.v.empty()) return json_error(db, "the question has no tokens");

    // Only the codes (pg_phasevec 0.9.0): phasevec.search() asks this from inside the database and
    // runs find_ivf/find itself, in the caller's snapshot, after checking that the reader that read
    // the question is the watch's. Nothing is searched here.
    if (encode) {
        char head[64];
        std::snprintf(head, sizeof head, "{\"encode_ms\": %.1f, ", encode_ms);
        return std::string(head) + "\"watch\": " + json_string(w.name) + ", \"reader\": " + json_string(w.reader) +
               ", \"code64\": " + std::to_string(code64(rq.v)) + ", \"code\": " + json_string(code_literal(rq.v)) +
               ", \"code256\": " + json_string(code256(rq.v)) + "}";
    }

    // find(), or find_hybrid() with the question's text for the lexical arm ($10, $11); the hits of
    // the hybrid also say what each arm made of them.
    std::string source = hybrid
        ? "phasevec.find_hybrid($1, $10::text, $3::bigint, $4::smallint[], $5::int, $6::boolean, $7::int, "
          "nullif($8, '')::bit(256), $11::int)"
        : "phasevec.find($1, $3::bigint, $4::smallint[], $5::int, $6::boolean, $7::int, nullif($8, '')::bit(256))";
    std::string arms = hybrid
        ? ", 'vector_score', f.vector_score, 'vector_rank', f.vector_rank, 'lexical_score', f.lexical_score, "
          "'lexical_rank', f.lexical_rank"
        : "";
    std::vector<std::string> params = {w.name, w.reader, std::to_string(code64(rq.v)), code_literal(rq.v), k, partial,
                                       m, code256(rq.v), codes};
    if (hybrid) {
        params.push_back(q);
        params.push_back(lm);
    }
    std::string sql =
        "SELECT (jsonb_build_object('watch', $1::text, 'reader', $2::text, "
        "  'hits', coalesce((SELECT jsonb_agg(jsonb_build_object('key', f.key, 'score', f.score, 'hamming', f.hamming, "
        "      'state', f.state, 'familiarity', f.familiarity, 'read_at', f.read_at, 'truncated', f.truncated" + arms + ") "
        "      ORDER BY f.score DESC, f.key) "
        "    FROM " + source + " f), '[]'::jsonb), "
        "  'coverage', (SELECT jsonb_object_agg(c.state, c.n) FROM phasevec.coverage($1) c)) "
        // the question's own codes, on request: to audit an answer or to run find by hand
        "|| CASE WHEN $9::boolean THEN jsonb_build_object('code64', $3::bigint, 'code', to_jsonb($4::smallint[]), "
        "     'code256', nullif($8, '')) ELSE '{}'::jsonb END)::text";

    auto t1 = std::chrono::steady_clock::now();
    if (auto err = db.exec(sql.c_str(), params, &r)) {
        // The message and its hint, as the caller should read them; the PL/pgSQL context is ours.
        std::string msg = *err;
        if (msg.rfind("ERROR:  ", 0) == 0) msg.erase(0, 8);
        if (size_t at = msg.find("\nCONTEXT:"); at != std::string::npos) msg.erase(at);
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == ' ')) msg.pop_back();
        return json_error(db, msg);
    }
    double find_ms = ms_since(t1);
    std::string body = PQgetvalue(r, 0, 0);
    PQclear(r);
    char head[96];
    std::snprintf(head, sizeof head, "{\"encode_ms\": %.1f, \"find_ms\": %.1f, ", encode_ms, find_ms);
    return head + body.substr(1);
}

// The asker lives in the reading process: one model in memory (the CPU backend repacks the weights
// into anonymous memory, so a second process would cost another 5 GB). Questions arrive on a unix
// socket only its owner can open and are answered between rows, ahead of the next one; when the
// queue is empty the process waits on the database's NOTIFY and on the questions at once. A
// connection may carry many questions.
struct Asker {
    struct Listener {
        int fd;
        size_t watch;
    };
    struct Client {
        int fd;
        size_t watch;
        std::string buf;
    };
    std::vector<Listener> listeners;
    std::vector<Client> clients;

    void open(const std::string &path, size_t watch) {
        std::signal(SIGPIPE, SIG_IGN);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof addr.sun_path) die("socket path too long: " + path);
        std::strncpy(addr.sun_path, path.c_str(), sizeof addr.sun_path - 1);
        int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (ls < 0) die("cannot create a socket");
        unlink(path.c_str());
        mode_t old = umask(0177);
        if (bind(ls, (sockaddr *)&addr, sizeof addr) < 0) die("cannot bind " + path);
        umask(old);
        if (listen(ls, 16) < 0) die("cannot listen on " + path);
        listeners.push_back({ls, watch});
    }

    // Waits up to timeout_ms for questions (and for the database socket when watch_db), answering
    // every complete line that arrived, each on its watch. True when the database socket became readable.
    bool step(Db &db, const std::vector<Watch> &watches, Reader &rd, int timeout_ms, bool watch_db) {
        std::vector<pollfd> fds;
        for (auto &l : listeners) fds.push_back({l.fd, POLLIN, 0});
        const size_t first_client = fds.size();
        for (auto &c : clients) fds.push_back({c.fd, POLLIN, 0});
        if (watch_db) fds.push_back({PQsocket(db.c), POLLIN, 0});
        if (poll(fds.data(), fds.size(), timeout_ms) <= 0) return false;
        bool db_ready = watch_db && (fds.back().revents & POLLIN);
        for (size_t i = 0; i < clients.size(); i++) {
            if (!(fds[first_client + i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            Client &c = clients[i];
            char chunk[4096];
            ssize_t n = recv(c.fd, chunk, sizeof chunk, 0);
            bool keep = n > 0;
            if (keep) {
                c.buf.append(chunk, (size_t)n);
                size_t nl;
                while (keep && (nl = c.buf.find('\n')) != std::string::npos) {
                    std::string line = c.buf.substr(0, nl);
                    c.buf.erase(0, nl + 1);
                    if (line.empty()) continue;
                    std::string out = answer(db, watches[c.watch], rd, line) + "\n";
                    keep = send(c.fd, out.data(), out.size(), 0) >= 0;
                }
                keep = keep && c.buf.size() <= (1 << 20);   // a question is not a megabyte
            }
            if (!keep) {
                close(c.fd);
                c.fd = -1;
            }
        }
        clients.erase(std::remove_if(clients.begin(), clients.end(), [](const Client &c) { return c.fd < 0; }),
                      clients.end());
        for (size_t i = 0; i < listeners.size(); i++)
            if (fds[i].revents & POLLIN)
                for (int fd; (fd = accept(listeners[i].fd, nullptr, nullptr)) >= 0;)
                    clients.push_back({fd, listeners[i].watch, {}});
        return db_ready;
    }
};

// The weights of the lexical arm follow the rows when the queue empties (pg_phasevec 0.6.0). A database
// without lexical_maintain() (before 0.6.0) is said once, and the reader goes on reading.
void maintain_lexicon(Db &db, const std::string &watch) {
    static bool unavailable = false;
    if (unavailable) return;
    PGresult *r = nullptr;
    if (auto err = db.exec("SELECT phasevec.lexical_maintain($1)", {watch}, &r)) {
        std::fprintf(stderr, "phasevec-reader: the lexical weights of %s are not kept here: %s", watch.c_str(), err->c_str());
        unavailable = true;
        return;
    }
    if (std::string(PQgetvalue(r, 0, 0)) == "t")
        std::fprintf(stderr, "phasevec-reader: %s: lexical weights recounted\n", watch.c_str());
    PQclear(r);
}

// The count deltas fold into the base counts when the queue empties too (pg_phasevec 0.7.0): until
// then coverage() sums them, right but slower. A database without counts_compact() is said once.
void maintain_counts(Db &db, const std::string &watch) {
    static bool unavailable = false;
    if (unavailable) return;
    PGresult *r = nullptr;
    if (auto err = db.exec("SELECT phasevec.counts_compact($1)", {watch}, &r)) {
        std::fprintf(stderr, "phasevec-reader: the counts of %s are not folded here: %s", watch.c_str(), err->c_str());
        unavailable = true;
        return;
    }
    PQclear(r);
}

// The idle wait: until a NOTIFY says there is something to read, or 30 s pass, whichever first.
// With an asker, questions are answered meanwhile. A NOTIFY can also arrive while a question's
// query runs (libpq then queues it), so the queue is checked after each step too.
void wait_for_work(Db &db, const std::vector<Watch> &watches, Reader &rd, Asker *asker) {
    if (!asker) {
        wait_for_notify(db, 30);
        return;
    }
    auto t0 = std::chrono::steady_clock::now();
    for (;;) {
        int left = 30000 - (int)ms_since(t0);
        if (left <= 0) return;
        bool db_ready = asker->step(db, watches, rd, left, true);
        if (db_ready) PQconsumeInput(db.c);
        bool notified = false;
        while (PGnotify *n = PQnotifies(db.c)) {
            PQfreemem(n);
            notified = true;
        }
        if (notified) return;
    }
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
    // The watches and the reader each is read in the name of: --reader for all, or the watch's own.
    std::vector<Watch> watches;
    for (auto &name : o.watches) {
        Watch w;
        w.name = name;
        w.reader = o.reader;
        if (w.reader.empty()) {
            PGresult *r = nullptr;
            if (auto err = db.exec("SELECT rd.name FROM phasevec.watches w JOIN phasevec.readers rd ON rd.id = w.reader "
                                   "WHERE w.name = $1", {name}, &r))
                die("cannot find the reader of watch " + name + ": " + *err);
            if (PQntuples(r) != 1) die("no watch named " + name);
            w.reader = PQgetvalue(r, 0, 0);
            PQclear(r);
        }
        watches.push_back(w);
    }
    if (!o.do_register) {
        if (!o.reader.empty() || watches.empty()) check_compute(db, o.reader, compute);
        for (auto &w : watches)
            if (w.reader != o.reader) check_compute(db, w.reader, compute);
    }
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
            std::string sql = "SELECT phasevec.reader_register(jsonb_set($1::jsonb, '{base_sha256}', to_jsonb($2::text)), " +
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
                                           o.pooling, std::to_string(o.ctx), o.query_prefix, kPooledTokens};
        params.insert(params.end(), cv.begin(), cv.end());
        std::string sql = "SELECT phasevec.reader_register($1, $2, $3::int, nullif($4, ''), "
                          "jsonb_build_object('pooling', $5::text, 'ctx', $6::int, 'query_prefix', $7::text, "
                          "'tokens', $8::text), " + compute_json(9) + ")";
        if (auto err = db.exec(sql.c_str(), params, &r)) die("cannot register: " + *err);
        std::printf("registered reader %s (model %s, %d dimensions; %s on %s)\n", o.reader.c_str(),
                    have.model_sha.substr(0, 12).c_str(), rd.dims, compute.backend.c_str(), compute.device.c_str());
        PQclear(r);
        return 0;
    }

    if (!o.reader.empty()) rd.query_instruction = check_seal(db, o, rd, have, o.reader);
    for (auto &w : watches)
        w.instruction = w.reader == o.reader ? rd.query_instruction : check_seal(db, o, rd, have, w.reader);

    if ((!o.serve.empty() || !o.serve_dir.empty()) && (o.watch.empty() || o.once || o.audit > 0 || !o.ask.empty() || !o.ask_file.empty() ||
                             !o.ask_doc.empty() || !o.embed_file.empty()))
        die("--serve answers questions while the process reads its --watch: not with --once, --audit or --ask*");
    if (!o.serve_dir.empty())
        for (auto &w : watches)
            if (!safe_watch_name(w.name)) die("watch " + w.name + " cannot name a socket (letters, digits, _ - .)");
    if (!o.ask.empty()) {
        Reading q = rd.read(o.ask, true);
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
    if (!o.embed_file.empty()) {
        // Questions and documents, each read as find and the watch would read it: for checking a reader
        // against another implementation of the same model, and for measuring without a watch.
        std::ifstream f(o.embed_file);
        if (!f) die("cannot read " + o.embed_file);
        std::string line;
        while (std::getline(f, line)) {
            if (line.size() < 2 || (line[0] != 'Q' && line[0] != 'D') || line[1] != ' ') die("--embed-file lines are \"Q <base64>\" or \"D <base64>\"");
            Reading q = rd.read(from_base64(line.substr(2)), line[0] == 'Q');
            if (q.v.empty()) std::printf("%c\t\t\t\t\t\n", line[0]);
            else std::printf("%c\t%lld\t%s\t%s\t%d\t%d\n", line[0], (long long)code64(q.v), code_literal(q.v).c_str(),
                             code256(q.v).c_str(), q.tokens_read, q.tokens_total);
            std::fflush(stdout);
        }
        return 0;
    }
    if (!o.ask_file.empty()) {
        // The model loads once; each line is a question and gets its codes on the same line number.
        std::ifstream f(o.ask_file);
        if (!f) die("cannot read " + o.ask_file);
        std::string line;
        while (std::getline(f, line)) {
            Reading q = line.empty() ? Reading{} : rd.read(line, true);
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
        // reading; a reading that does not reproduce stays in phasevec.audits as a broken assertion.
        PGresult *r = nullptr;
        if (auto err = db.exec("SELECT key, body, text_hash::text FROM phasevec.audit_sample($1, $2::int)",
                               {o.watch, std::to_string(o.audit)}, &r))
            die("cannot ask for an audit sample: " + *err);
        long holds = 0, broken = 0, skipped = 0;
        for (int i = 0; i < PQntuples(r); i++) {
            std::string key = PQgetvalue(r, i, 0), body = PQgetvalue(r, i, 1), hash = PQgetvalue(r, i, 2);
            Reading again = rd.read(body);
            PGresult *a = nullptr;
            if (auto err = db.exec("SELECT phasevec.record_audit($1, $2, $3, $4::bytea, $5::smallint[], nullif($6, '')::bit(256))",
                                   {o.watch, key, watches.front().reader, hash, code_literal(again.v), code256(again.v)}, &a))
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
    if (auto err = db.exec("LISTEN phasevec", {})) die("cannot listen: " + *err);
    std::unique_ptr<Asker> asker;
    if (!o.serve.empty() || !o.serve_dir.empty()) {
        asker = std::make_unique<Asker>();
        for (size_t i = 0; i < watches.size(); i++) {
            std::string path = !o.serve.empty() ? o.serve : o.serve_dir + "/" + watches[i].name + ".sock";
            asker->open(path, i);
            std::fprintf(stderr, "phasevec-reader: answering on %s for watch %s (reader %s) between rows\n",
                         path.c_str(), watches[i].name.c_str(), watches[i].reader.c_str());
        }
    }

    // The watches take turns, a batch each; a waiting question goes before the next row of any of
    // them. A watch whose queue empties is maintained then (lexicon, counts), as with one watch.
    for (;;) {
        bool any = false;
        for (auto &w : watches) {
            PGresult *r = nullptr;
            if (auto err = db.exec("SELECT key, body, text_hash::text FROM phasevec.next($1, $2::int)",
                                   {w.name, std::to_string(o.batch)}, &r))
                die("cannot ask what to read of " + w.name + ": " + *err);
            int rows = PQntuples(r);
            for (int i = 0; i < rows; i++) {
                if (asker) asker->step(db, watches, rd, 0, false);   // a waiting question goes before the next row
                std::string key = PQgetvalue(r, i, 0);
                std::string body = PQgetisnull(r, i, 1) ? "" : PQgetvalue(r, i, 1);
                std::string hash = PQgetvalue(r, i, 2);
                Reading rdg = body.empty() ? Reading{} : rd.read(body);
                std::optional<std::string> err;
                if (rdg.v.empty()) {
                    err = db.exec("SELECT phasevec.record_failure($1, $2, $3, $4::bytea, $5)",
                                  {w.name, key, w.reader, hash, body.empty() ? "empty text" : "the model produced no reading"});
                    if (!err) w.failed++;
                } else {
                    err = db.exec("SELECT phasevec.record($1, $2, $3, $4::bytea, $5::bigint, $6::smallint[], "
                                  "nullif($7, '')::real, nullif($8, '')::bit(256), $9::int, $10::int)",
                                  {w.name, key, w.reader, hash, std::to_string(code64(rdg.v)), code_literal(rdg.v),
                                   familiarity_param(rdg), code256(rdg.v), std::to_string(rdg.tokens_read),
                                   std::to_string(rdg.tokens_total)});
                    if (!err) w.read_ok++;
                }
                if (err) {
                    w.refused++;
                    std::fprintf(stderr, "phasevec-reader: %s: row %s not recorded: %s", w.name.c_str(), key.c_str(),
                                 err->c_str());
                }
            }
            PQclear(r);
            if (rows > 0) {
                any = true;
                w.drained = false;
            } else if (!w.drained) {
                std::fprintf(stderr, "phasevec-reader: %s: %ld read, %ld failed, %ld refused; queue empty\n",
                             w.name.c_str(), w.read_ok, w.failed, w.refused);
                maintain_lexicon(db, w.name);
                maintain_counts(db, w.name);
                w.drained = true;
            }
        }
        if (any) continue;
        if (o.once) break;
        wait_for_work(db, watches, rd, asker.get());
        for (auto &w : watches) w.drained = false;   // maintained again after each wait, as before
    }
    return 0;
}
