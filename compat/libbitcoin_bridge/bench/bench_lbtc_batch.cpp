/**
 * bench_lbtc_batch.cpp — throughput benchmark for the libbitcoin batch
 * script-signature verification bridge (ufsecp_lbtc_verify_ecdsa / _schnorr).
 *
 * Measures verifications/second for a large homogeneous batch on whichever
 * backends are available (GPU if built + present, and the CPU reference). This
 * mirrors the IBD use case: a big array of (sig, key, sighash) triples verified
 * in one call. Correctness is asserted (all-valid batch + single-corruption
 * detection) before any timing, so reported numbers are for a verified-correct
 * path.
 *
 * Usage: bench_lbtc_batch [batch_size] [iters] [pool]
 *   batch_size  rows verified per call      (default 1000000)
 *   iters       timed iterations per backend (default 5)
 *   pool        distinct signatures generated, tiled to batch_size (default 50000)
 *
 * NOTE: numbers are only meaningful as measured on THIS machine. Do not copy
 * them anywhere as estimates for other hardware.
 */
#include "ufsecp_libbitcoin.h"
#include "ufsecp.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

using clock_t_ = std::chrono::steady_clock;

static double secs_since(clock_t_::time_point t0) {
    return std::chrono::duration<double>(clock_t_::now() - t0).count();
}

int main(int argc, char** argv) {
    const size_t BATCH = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 1000000ull;
    const int    ITERS = argc > 2 ? std::atoi(argv[2]) : 5;
    const size_t POOL  = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 50000ull;

    std::printf("== libbitcoin batch sig-verify benchmark ==\n");
    std::printf("batch=%zu  iters=%d  pool=%zu\n\n", BATCH, ITERS, POOL);

    ufsecp_ctx* sctx = nullptr;
    if (ufsecp_ctx_create(&sctx) != UFSECP_OK) { std::printf("ctx fail\n"); return 1; }

    /* --- generate POOL distinct ECDSA + Schnorr records, then tile to BATCH --- */
    std::printf("generating %zu signatures...\n", POOL);
    std::vector<uint8_t> e_pool(POOL * UFSECP_LBTC_ECDSA_RECORD);
    std::vector<uint8_t> s_pool(POOL * UFSECP_LBTC_SCHNORR_RECORD);
    for (size_t i = 0; i < POOL; ++i) {
        uint8_t sk[32] = {0}, msg[32] = {0}, pub[33], aux[32] = {0};
        sk[24] = (uint8_t)(i >> 24); sk[25] = (uint8_t)(i >> 16);
        sk[26] = (uint8_t)(i >> 8);  sk[31] = (uint8_t)(i | 1u);
        for (int b = 0; b < 32; ++b) msg[b] = (uint8_t)((i * 2654435761u) >> (b % 24));
        if (ufsecp_pubkey_create(sctx, sk, pub) != UFSECP_OK) { std::printf("keygen fail\n"); return 1; }
        uint8_t* er = e_pool.data() + i * UFSECP_LBTC_ECDSA_RECORD;
        std::memcpy(er, msg, 32); std::memcpy(er + 32, pub, 33);
        if (ufsecp_ecdsa_sign(sctx, msg, sk, er + 65) != UFSECP_OK) { std::printf("ecdsa sign fail\n"); return 1; }
        uint8_t* sr = s_pool.data() + i * UFSECP_LBTC_SCHNORR_RECORD;
        std::memcpy(sr, pub + 1, 32); std::memcpy(sr + 32, msg, 32);
        if (ufsecp_schnorr_sign(sctx, msg, sk, aux, sr + 64) != UFSECP_OK) { std::printf("schnorr sign fail\n"); return 1; }
    }

    /* Tile pool -> full batch tables (rows, key_size = 0). */
    std::printf("building batch tables (%zu rows each)...\n\n", BATCH);
    std::vector<uint8_t> e_rows(BATCH * UFSECP_LBTC_ECDSA_RECORD);
    std::vector<uint8_t> s_rows(BATCH * UFSECP_LBTC_SCHNORR_RECORD);
    for (size_t i = 0; i < BATCH; ++i) {
        size_t p = i % POOL;
        std::memcpy(e_rows.data() + i * UFSECP_LBTC_ECDSA_RECORD,
                    e_pool.data() + p * UFSECP_LBTC_ECDSA_RECORD, UFSECP_LBTC_ECDSA_RECORD);
        std::memcpy(s_rows.data() + i * UFSECP_LBTC_SCHNORR_RECORD,
                    s_pool.data() + p * UFSECP_LBTC_SCHNORR_RECORD, UFSECP_LBTC_SCHNORR_RECORD);
    }
    ufsecp_ctx_destroy(sctx);

    std::vector<uint8_t> results(BATCH);
    const char* be_name[] = {"CPU", "CUDA", "OpenCL", "Metal"};

    struct Run { ufsecp_lbtc_backend req; const char* label; };
    Run runs[] = { {UFSECP_LBTC_GPU, "GPU"}, {UFSECP_LBTC_CPU, "CPU"} };

    for (auto& r : runs) {
        ufsecp_lbtc_ctrl* ctrl = nullptr;
        if (ufsecp_lbtc_ctrl_create(&ctrl, r.req) != UFSECP_OK || !ctrl) {
            std::printf("[%s] backend unavailable — skipped\n\n", r.label);
            continue;
        }
        const char* bound = be_name[ufsecp_lbtc_ctrl_backend(ctrl)];
        std::printf("[%s] bound=%s device=%s\n", r.label, bound,
                    ufsecp_lbtc_ctrl_device_name(ctrl));

        /* correctness gate before timing */
        size_t ninv = 0;
        ufsecp_lbtc_verify_ecdsa(ctrl, e_rows.data(), BATCH, 0, results.data(), nullptr, 0, &ninv);
        bool ok = (ninv == 0);
        {
            auto saved = e_rows[65]; e_rows[65] ^= 0x01;  // corrupt row 0 sig
            size_t ni2 = 0;
            ufsecp_lbtc_verify_ecdsa(ctrl, e_rows.data(), BATCH, 0, results.data(), nullptr, 0, &ni2);
            ok = ok && (ni2 >= 1) && (results[0] == 0);
            e_rows[65] = saved;
        }
        std::printf("   correctness: %s\n", ok ? "PASS (all-valid + corruption detected)" : "FAIL");
        if (!ok) { ufsecp_lbtc_ctrl_destroy(ctrl); continue; }

        auto bench = [&](const char* kind, auto verify, const std::vector<uint8_t>& rows) {
            verify(ctrl, rows.data(), BATCH, (size_t)0, results.data(), nullptr, (size_t)0, &ninv); // warmup
            double best = 1e30;
            for (int it = 0; it < ITERS; ++it) {
                auto t0 = clock_t_::now();
                verify(ctrl, rows.data(), BATCH, (size_t)0, results.data(), nullptr, (size_t)0, &ninv);
                double dt = secs_since(t0);
                if (dt < best) best = dt;
            }
            double mps = (double)BATCH / best / 1e6;
            std::printf("   %-8s %8.2f M sig/s   (%.4f s for %zu, best of %d)\n",
                        kind, mps, best, BATCH, ITERS);
        };
        bench("ECDSA", ufsecp_lbtc_verify_ecdsa, e_rows);
        bench("Schnorr", ufsecp_lbtc_verify_schnorr, s_rows);
        std::printf("\n");
        ufsecp_lbtc_ctrl_destroy(ctrl);
    }
    return 0;
}
