// probe_parity.cpp -- prints the hidden state llama.cpp reads at the last marker
// id of one text, with an optional LoRA adapter, one float per line. The trainer's
// side of the same reading is compared against it (forja smoke_vec parity).
//
//   probe_parity <model.gguf> <lora.gguf|-> <text>
#include <llama.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 4) {
        std::fprintf(stderr, "usage: probe_parity <model.gguf> <lora.gguf|-> <text>\n");
        return 2;
    }
    llama_backend_init();
    llama_log_set([](ggml_log_level, const char *, void *) {}, nullptr);
    llama_model *model = llama_model_load_from_file(argv[1], llama_model_default_params());
    if (!model) return 2;
    llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 2048;
    cp.n_batch = cp.n_ubatch = 2048;
    cp.embeddings = true;
    cp.pooling_type = LLAMA_POOLING_TYPE_NONE;
    llama_context *ctx = llama_init_from_model(model, cp);
    if (!ctx) return 2;
    if (std::string(argv[2]) != "-") {
        llama_adapter_lora *lora = llama_adapter_lora_init(model, argv[2]);
        if (!lora) {
            std::fprintf(stderr, "cannot load adapter %s\n", argv[2]);
            return 2;
        }
        float scale = 1.0f;
        llama_set_adapters_lora(ctx, &lora, 1, &scale);
    }
    const llama_vocab *vocab = llama_model_get_vocab(model);
    auto tokenize = [&](const std::string &s) {
        int n = -llama_tokenize(vocab, s.data(), (int)s.size(), nullptr, 0, false, false);
        std::vector<llama_token> t(n);
        llama_tokenize(vocab, s.data(), (int)s.size(), t.data(), n, false, false);
        return t;
    };
    std::vector<llama_token> ids = tokenize(argv[3]);
    for (llama_token t : tokenize("\xE2\x9F\xA6v\xE2\x9F\xA7")) ids.push_back(t);
    llama_batch b = llama_batch_init((int)ids.size(), 0, 1);
    for (size_t i = 0; i < ids.size(); i++) {
        b.token[i] = ids[i];
        b.pos[i] = (llama_pos)i;
        b.n_seq_id[i] = 1;
        b.seq_id[i][0] = 0;
        b.logits[i] = i + 1 == ids.size();
    }
    b.n_tokens = (int)ids.size();
    if (llama_decode(ctx, b) != 0) return 2;
    const float *e = llama_get_embeddings_ith(ctx, -1);
    if (!e) return 2;
    for (int i = 0; i < llama_model_n_embd(model); i++) std::printf("%.7g\n", e[i]);
    llama_batch_free(b);
    llama_free(ctx);
    llama_model_free(model);
    return 0;
}
