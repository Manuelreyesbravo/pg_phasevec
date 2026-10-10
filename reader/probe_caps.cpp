// probe_caps.cpp -- measures, against a real GGUF, the llama.cpp capabilities the
// vec reader depends on. Every check prints the number behind its verdict; the
// thresholds are fixed here, before the probe ever runs.
//
//   probe_caps <model.gguf> [layer]
//
// 1. per_token   pooling NONE gives one hidden state per token, and a marker's
//                state depends on what was read before it (late chunking).
// 2. state_seq   a sequence's KV can be saved and restored into another sequence
//                without changing what comes after it.
// 3. shift       llama_memory_seq_add moves a chunk's KV to a new position and the
//                RoPE re-rotation matches computing it there.
// 4. transplant  a chunk computed alone, shifted and copied after a context, versus
//                read in place: the gap the KV-transplant objective has to close.
//                Reported, not judged -- it is the baseline before training.
// 5. layer       an intermediate layer's hidden states can be captured through the
//                eval callback, and what that costs.
#include <llama.h>
#include <ggml-backend.h>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

using Rows = std::vector<std::vector<float>>;

constexpr double kContextEffectMax = 0.999;   // marker after A vs after B must differ
constexpr double kStateSeqMin = 0.9999;       // restored KV must reproduce the suffix
constexpr double kShiftMin = 0.999;           // shifted KV must match in-place KV

int failures = 0;

void verdict(bool ok, const char *name, const std::string &detail) {
    std::printf("%s %-11s %s\n", ok ? "PASS" : "FAIL", name, detail.c_str());
    if (!ok) failures++;
}

[[noreturn]] void die(const char *what) {
    std::fprintf(stderr, "probe_caps: %s\n", what);
    std::exit(2);
}

struct Capture {
    std::string want;
    std::vector<float> data;
    long ne0 = 0, ne1 = 0;
};

bool on_eval(ggml_tensor *t, bool ask, void *ud) {
    auto *c = static_cast<Capture *>(ud);
    bool match = !c->want.empty() && c->want == ggml_get_name(t);
    if (ask) return match;
    if (match && t->type == GGML_TYPE_F32) {
        c->ne0 = t->ne[0];
        c->ne1 = t->ne[1];
        c->data.resize(ggml_nelements(t));
        ggml_backend_tensor_get(t, c->data.data(), 0, ggml_nbytes(t));
    }
    return true;
}

std::vector<llama_token> tokens(const llama_vocab *v, const std::string &s) {
    int n = -llama_tokenize(v, s.data(), (int)s.size(), nullptr, 0, false, false);
    std::vector<llama_token> out(n > 0 ? n : 0);
    if (n > 0) llama_tokenize(v, s.data(), (int)s.size(), out.data(), n, false, false);
    return out;
}

std::vector<llama_token> cat(std::vector<llama_token> a, const std::vector<llama_token> &b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// Decodes toks into seq starting at pos0 and returns one hidden state per token.
Rows decode(llama_context *ctx, const std::vector<llama_token> &toks, llama_seq_id seq,
            llama_pos pos0, int n_embd) {
    llama_batch b = llama_batch_init((int)toks.size(), 0, 1);
    for (size_t i = 0; i < toks.size(); i++) {
        b.token[i] = toks[i];
        b.pos[i] = pos0 + (llama_pos)i;
        b.n_seq_id[i] = 1;
        b.seq_id[i][0] = seq;
        b.logits[i] = 1;
    }
    b.n_tokens = (int)toks.size();
    if (llama_decode(ctx, b) != 0) die("llama_decode failed");
    Rows rows;
    for (size_t i = 0; i < toks.size(); i++) {
        const float *e = llama_get_embeddings_ith(ctx, (int)i);
        rows.emplace_back(e ? std::vector<float>(e, e + n_embd) : std::vector<float>());
    }
    llama_batch_free(b);
    return rows;
}

double cosine(const std::vector<float> &a, const std::vector<float> &b) {
    if (a.empty() || a.size() != b.size()) return -2;
    double ab = 0, aa = 0, bb = 0;
    for (size_t i = 0; i < a.size(); i++) {
        ab += (double)a[i] * b[i];
        aa += (double)a[i] * a[i];
        bb += (double)b[i] * b[i];
    }
    return ab / (std::sqrt(aa) * std::sqrt(bb) + 1e-30);
}

double min_cosine(const Rows &a, const Rows &b) {
    if (a.size() != b.size() || a.empty()) return -2;
    double m = 2;
    for (size_t i = 0; i < a.size(); i++) m = std::fmin(m, cosine(a[i], b[i]));
    return m;
}

Rows tail(const Rows &r, size_t n) { return Rows(r.end() - (long)n, r.end()); }

std::string fmt(const char *f, double a, double b = 0, double c = 0) {
    char buf[256];
    std::snprintf(buf, sizeof buf, f, a, b, c);
    return buf;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 2) die("usage: probe_caps <model.gguf> [layer]");
    llama_backend_init();
    llama_log_set([](ggml_log_level, const char *, void *) {}, nullptr);

    llama_model_params mp = llama_model_default_params();
    llama_model *model = llama_model_load_from_file(argv[1], mp);
    if (!model) die("cannot load model");
    const llama_vocab *vocab = llama_model_get_vocab(model);
    const int n_embd = llama_model_n_embd(model);
    const int n_layer = llama_model_n_layer(model);
    const int layer = argc > 2 ? std::atoi(argv[2]) : n_layer / 2;

    Capture cap;
    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 4096;
    cp.n_batch = cp.n_ubatch = 2048;
    cp.n_seq_max = 8;
    cp.kv_unified = true;
    cp.embeddings = true;
    cp.pooling_type = LLAMA_POOLING_TYPE_NONE;
    cp.cb_eval = on_eval;
    cp.cb_eval_user_data = &cap;
    llama_context *ctx = llama_init_from_model(model, cp);
    if (!ctx) die("cannot create context");
    llama_memory_t mem = llama_get_memory(ctx);
    std::printf("model n_embd=%d n_layer=%d pooling=%d\n", n_embd, n_layer,
                (int)llama_pooling_type(ctx));

    const std::string marker = "\xE2\x9F\xA6v\xE2\x9F\xA7";  // the vec marker, U+27E6 v U+27E7
    auto mk = tokens(vocab, marker);
    std::printf("marker tokenizes to %zu ids:", mk.size());
    for (auto t : mk) std::printf(" %d", t);
    std::printf("\n");

    // 1. per_token
    auto a = cat(tokens(vocab, "Vacuum reclaims the space held by dead tuples."), mk);
    auto b = cat(tokens(vocab, "Empanadas are baked on the eighteenth of September."), mk);
    Rows ra = decode(ctx, a, 0, 0, n_embd);
    Rows rb = decode(ctx, b, 1, 0, n_embd);
    size_t missing = 0;
    for (auto &r : ra) missing += r.empty();
    for (auto &r : rb) missing += r.empty();
    double ctx_cos = cosine(ra.back(), rb.back());
    verdict(missing == 0 && ctx_cos < kContextEffectMax, "per_token",
            fmt("rows=%.0f missing=%.0f marker_cos(A,B)=%.4f", (double)(ra.size() + rb.size()),
                (double)missing, ctx_cos));
    llama_memory_clear(mem, true);

    // 2. state_seq
    auto prefix = tokens(vocab, "The planner chooses an index scan when the predicate is selective and");
    auto suffix = tokens(vocab, " the table is large enough to make random reads worth it.");
    decode(ctx, prefix, 0, 0, n_embd);
    size_t sz = llama_state_seq_get_size(ctx, 0);
    std::vector<uint8_t> buf(sz);
    size_t got = llama_state_seq_get_data(ctx, buf.data(), buf.size(), 0);
    llama_memory_seq_rm(mem, 0, -1, -1);
    size_t put = llama_state_seq_set_data(ctx, buf.data(), got, 1);
    Rows restored = decode(ctx, suffix, 1, (llama_pos)prefix.size(), n_embd);
    Rows inplace = tail(decode(ctx, cat(prefix, suffix), 2, 0, n_embd), suffix.size());
    double st = min_cosine(restored, inplace);
    verdict(got == sz && put > 0 && st >= kStateSeqMin, "state_seq",
            fmt("bytes=%.0f restored=%.0f min_cos=%.6f", (double)sz, (double)put, st));
    llama_memory_clear(mem, true);

    // 3. shift and 4. transplant
    auto context = tokens(vocab,
        "Autovacuum runs in the background. Its thresholds depend on the table size, and "
        "a busy table with many updates accumulates dead rows quickly. ");
    auto chunk = tokens(vocab, "Each dead row keeps its space until vacuum marks it reusable.");
    auto query = cat(tokens(vocab, " So the free space returns after"), mk);
    const llama_pos P = (llama_pos)context.size(), L = (llama_pos)chunk.size();
    bool can_shift = llama_memory_can_shift(mem);

    decode(ctx, chunk, 3, 0, n_embd);
    llama_memory_seq_add(mem, 3, 0, -1, P);
    Rows shifted = decode(ctx, query, 3, P + L, n_embd);
    decode(ctx, chunk, 4, P, n_embd);
    Rows placed = decode(ctx, query, 4, P + L, n_embd);
    double sh = min_cosine(shifted, placed);
    verdict(can_shift && sh >= kShiftMin, "shift",
            fmt("can_shift=%.0f delta=%.0f min_cos=%.6f", can_shift, (double)P, sh));

    Rows reference = tail(decode(ctx, cat(cat(context, chunk), query), 5, 0, n_embd), query.size());
    decode(ctx, context, 6, 0, n_embd);
    decode(ctx, chunk, 7, 0, n_embd);
    llama_memory_seq_add(mem, 7, 0, -1, P);
    llama_memory_seq_cp(mem, 7, 6, P, P + L);
    Rows transplanted = decode(ctx, query, 6, P + L, n_embd);
    std::printf("INFO transplant  marker_cos=%.4f min_cos=%.4f (gap the KD objective closes)\n",
                cosine(transplanted.back(), reference.back()), min_cosine(transplanted, reference));
    llama_memory_clear(mem, true);

    // 5. layer
    auto longer = std::vector<llama_token>();
    while (longer.size() < 512) longer = cat(longer, cat(context, chunk));
    longer.resize(512);
    auto t0 = std::chrono::steady_clock::now();
    decode(ctx, longer, 0, 0, n_embd);
    double plain_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    llama_memory_clear(mem, true);
    cap.want = "l_out-" + std::to_string(layer);
    t0 = std::chrono::steady_clock::now();
    Rows last = decode(ctx, longer, 0, 0, n_embd);
    double cap_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    bool shape = cap.ne0 == n_embd && cap.ne1 == (long)longer.size();
    double vs_last = shape ? cosine(std::vector<float>(cap.data.end() - n_embd, cap.data.end()),
                                    last.back()) : -2;
    verdict(shape, "layer",
            fmt("captured %.0f x %.0f, cos(layer,last)=%.4f", (double)cap.ne0, (double)cap.ne1, vs_last) +
            fmt(" ms_plain=%.1f ms_capture=%.1f", plain_ms, cap_ms));

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    std::printf("%s\n", failures ? "SOME CHECKS FAILED" : "ALL CHECKS PASSED");
    return failures ? 1 : 0;
}
