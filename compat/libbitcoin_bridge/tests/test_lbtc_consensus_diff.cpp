/**
 * test_lbtc_consensus_diff.cpp — GPU-vs-CPU consensus differential for the
 * libbitcoin batch script-signature verification bridge.
 *
 * The GPU path is consensus-bearing: for block validation it must agree with the
 * CPU reference path BIT-FOR-BIT on the accept/reject verdict of every signature,
 * including consensus edge cases (corrupted sig, off-curve pubkey, tampered
 * message, non-canonical encodings). The CPU path is itself gated bit-for-bit
 * against libsecp256k1 (cross_libsecp256k1 + reverse bridge), so GPU==CPU here
 * means GPU==libsecp transitively.
 *
 * This test builds one mixed corpus and verifies it through a GPU controller and
 * a CPU controller; ANY per-row verdict mismatch is a consensus failure. If no
 * GPU is present it advisory-skips (exit 77) per the GPU-local-only policy.
 *
 * Standalone:
 *   g++ -std=c++17 -I ../include -I ../../../include/ufsecp \
 *       test_lbtc_consensus_diff.cpp -lufsecp -o test_lbtc_consensus_diff
 */
#include "ufsecp_libbitcoin.h"
#include "ufsecp.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, msg)                                                       \
    do { if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fail; }           \
         else         { std::printf("  ok  : %s\n", msg); } } while (0)

namespace {

constexpr int ADVISORY_SKIP_CODE = 77;

void make_sk(uint8_t sk[32], uint32_t seed) {
    std::memset(sk, 0, 32);
    sk[28]=(uint8_t)(seed>>24); sk[29]=(uint8_t)(seed>>16);
    sk[30]=(uint8_t)(seed>>8);  sk[31]=(uint8_t)(seed|1u);
}
void make_msg(uint8_t msg[32], uint32_t seed) {
    for (int i=0;i<32;++i) msg[i]=(uint8_t)((seed*2654435761u)>>(i%24));
}

/* Build a corpus that mixes valid signatures with every consensus-relevant
 * rejection class. Returns the packed rows (no opaque key). */
enum Kind { ECDSA, SCHNORR };
std::vector<uint8_t> build_corpus(ufsecp_ctx* ctx, Kind k, size_t n) {
    const size_t rec = (k==ECDSA) ? UFSECP_LBTC_ECDSA_RECORD : UFSECP_LBTC_SCHNORR_RECORD;
    std::vector<uint8_t> rows(n*rec, 0);
    for (size_t i=0;i<n;++i) {
        uint8_t* r = rows.data()+i*rec;
        uint8_t sk[32], msg[32], pub[33], aux[32]={0};
        make_sk(sk,(uint32_t)(i+1)); make_msg(msg,(uint32_t)(i+1));
        if (ufsecp_pubkey_create(ctx, sk, pub) != UFSECP_OK) ++g_fail;
        if (k==ECDSA) {
            std::memcpy(r, msg, 32); std::memcpy(r+32, pub, 33);
            if (ufsecp_ecdsa_sign(ctx, msg, sk, r+65) != UFSECP_OK) ++g_fail;
        } else {
            std::memcpy(r, pub+1, 32); std::memcpy(r+32, msg, 32);
            if (ufsecp_schnorr_sign(ctx, msg, sk, aux, r+64) != UFSECP_OK) ++g_fail;
        }
        /* Inject a rejection class every few rows (deterministic mix). */
        const size_t sig_off = (k==ECDSA) ? 65 : 64;
        switch (i % 7) {
            case 0: break;                                  /* valid                */
            case 1: r[sig_off] ^= 0x01; break;              /* corrupted sig byte   */
            case 2: r[0] ^= 0x01; break;                    /* tampered msg/xonly   */
            case 3: r[sig_off+31] ^= 0x80; break;           /* high bit of r/R.x    */
            case 4: std::memset(r+sig_off, 0, 32); break;   /* zero r/R.x           */
            case 5: std::memset(r+sig_off+32, 0xff, 32); break; /* s = 0xff..ff (>=n) */
            case 6: if (k==ECDSA) r[32] ^= 0x01;            /* flip pubkey prefix-adjacent */
                    else r[31] ^= 0x01; break;
        }
    }
    return rows;
}

bool diff_kind(ufsecp_lbtc_ctrl* gpu, ufsecp_lbtc_ctrl* cpu, Kind k, size_t n) {
    ufsecp_ctx* sctx=nullptr;
    if (ufsecp_ctx_create(&sctx)!=UFSECP_OK) return false;
    auto rows = build_corpus(sctx, k, n);
    ufsecp_ctx_destroy(sctx);

    std::vector<uint8_t> g_res(n), c_res(n);
    size_t g_ninv=0, c_ninv=0;
    int gp, cp;
    if (k==ECDSA) {
        gp = ufsecp_lbtc_verify_ecdsa(gpu, rows.data(), n, 0, g_res.data(), nullptr, 0, &g_ninv);
        cp = ufsecp_lbtc_verify_ecdsa(cpu, rows.data(), n, 0, c_res.data(), nullptr, 0, &c_ninv);
    } else {
        gp = ufsecp_lbtc_verify_schnorr(gpu, rows.data(), n, 0, g_res.data(), nullptr, 0, &g_ninv);
        cp = ufsecp_lbtc_verify_schnorr(cpu, rows.data(), n, 0, c_res.data(), nullptr, 0, &c_ninv);
    }
    if (gp != UFSECP_OK || cp != UFSECP_OK) {
        std::printf("  ERROR: verify call failed (gpu rc=%d, cpu rc=%d)\n", gp, cp);
        return false;
    }
    /* Bit-for-bit per-row agreement is the consensus property. */
    size_t mismatch = 0, first = (size_t)-1;
    for (size_t i=0;i<n;++i)
        if (g_res[i]!=c_res[i]) { if (first==(size_t)-1) first=i; ++mismatch; }
    const char* name = (k==ECDSA)?"ECDSA":"Schnorr";
    if (mismatch) {
        std::printf("  CONSENSUS DIVERGENCE [%s]: %zu/%zu rows differ (first @%zu: gpu=%d cpu=%d)\n",
                    name, mismatch, n, first, g_res[first], c_res[first]);
        return false;
    }
    std::printf("  %s: GPU==CPU bit-for-bit on %zu rows (%zu rejected); counts %zu==%zu\n",
                name, n, c_ninv, g_ninv, c_ninv);
    return (g_ninv==c_ninv);
}

} // namespace

int test_lbtc_consensus_diff_run() {
    ufsecp_lbtc_ctrl *gpu=nullptr, *cpu=nullptr;
    if (ufsecp_lbtc_ctrl_create(&gpu, UFSECP_LBTC_GPU)!=UFSECP_OK || !gpu) {
        std::printf("[lbtc_consensus_diff] no GPU backend — advisory skip\n");
        return ADVISORY_SKIP_CODE;
    }
    if (ufsecp_lbtc_ctrl_create(&cpu, UFSECP_LBTC_CPU)!=UFSECP_OK || !cpu) {
        std::printf("FATAL: CPU controller create failed\n");
        ufsecp_lbtc_ctrl_destroy(gpu); return 1;
    }
    const char* names[]={"CPU","CUDA","OpenCL","Metal"};
    std::printf("GPU-vs-CPU consensus differential (gpu=%s, cpu=%s)\n",
                names[ufsecp_lbtc_ctrl_backend(gpu)], names[ufsecp_lbtc_ctrl_backend(cpu)]);

    const size_t N = 20000;
    CHECK(diff_kind(gpu, cpu, ECDSA,   N), "ECDSA  GPU==CPU consensus (mixed corpus)");
    CHECK(diff_kind(gpu, cpu, SCHNORR, N), "Schnorr GPU==CPU consensus (mixed corpus)");

    ufsecp_lbtc_ctrl_destroy(cpu);
    ufsecp_lbtc_ctrl_destroy(gpu);
    std::printf("\n%s\n", g_fail==0 ? "CONSENSUS OK (GPU == CPU bit-for-bit)" : "CONSENSUS FAILURES");
    return g_fail==0 ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() { return test_lbtc_consensus_diff_run(); }
#endif
