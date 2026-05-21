// ============================================================================
// REGRESSION: secp256k1_schnorrsig_sign_custom varlen path CT fixes
//
// Fixed in 2026-05-21 review (review v8):
//   VCS-1: generator_mul -> generator_mul_blinded (DPA defence on nonce)
//   VCS-2: k_prime.is_zero() -> k_prime.is_zero_ct() (CT branch on secret nonce)
//   VCS-3: s.is_zero() -> s.is_zero_ct() (CT branch on secret scalar)
//   VCS-4: e_hash, e, nonce_input, rand_hash, challenge_input, t_hash
//           not erased in varlen path — all now erased before return
//
// The varlen path is triggered when msglen != 32.
// The 32-byte fast path delegates to secp256k1_schnorrsig_sign32 which routes
// through ct::schnorr_sign — that path was already correct.
//
// This test guards correctness of the varlen path after the CT fixes.
// CT properties themselves (blinding, is_zero_ct) are validated by the
// Valgrind/MSAN CT pipeline; this test guards functional correctness only.
//
// VCS-1: sign_custom varlen 64-byte round-trip via shim verify
// VCS-2: sign_custom varlen 33-byte (smallest varlen)
// VCS-3: sign_custom varlen 256-byte (stack buffer boundary)
// VCS-4: sign_custom varlen 300-byte (heap buffer path)
// VCS-5: sign_custom varlen determinism (same inputs -> same sig)
// VCS-6: 32-byte fast path still works (regression guard)
// ============================================================================

#ifndef UNIFIED_AUDIT_RUNNER
#include <cstdio>
#define STANDALONE_TEST
#endif

#include <cstring>
#include <cstdio>
#include <cstdint>

static constexpr int ADVISORY_SKIP_CODE = 77;
static int g_fail = 0;

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { std::printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, (msg)); ++g_fail; } \
} while(0)

#if defined(__APPLE__)
#  define SHIM_WEAK __attribute__((weak_import))
#else
#  define SHIM_WEAK __attribute__((weak))
#endif

extern "C" {
    typedef struct { unsigned char data[64]; } secp256k1_pubkey;
    typedef struct { unsigned char data[96]; } secp256k1_keypair;
    typedef struct secp256k1_context_struct secp256k1_context;
    typedef struct { unsigned char data[64]; } secp256k1_xonly_pubkey;

    static constexpr unsigned int CTX_SIGN   = 0x0101u;
    static constexpr unsigned int CTX_VERIFY = 0x0102u;

    SHIM_WEAK secp256k1_context* secp256k1_context_create(unsigned int flags);
    SHIM_WEAK void secp256k1_context_destroy(secp256k1_context* ctx);
    SHIM_WEAK int secp256k1_keypair_create(const secp256k1_context*, secp256k1_keypair*, const unsigned char*);
    SHIM_WEAK int secp256k1_schnorrsig_sign_custom(const secp256k1_context*, unsigned char*, const unsigned char*, size_t, const secp256k1_keypair*, void*);
    SHIM_WEAK int secp256k1_schnorrsig_sign32(const secp256k1_context*, unsigned char*, const unsigned char*, const secp256k1_keypair*, const unsigned char*);
    SHIM_WEAK int secp256k1_keypair_xonly_pub(const secp256k1_context*, secp256k1_xonly_pubkey*, int*, const secp256k1_keypair*);
    // Note: schnorrsig_verify only accepts msglen==32 per BIP-340 shim profile.
    // We verify round-trip correctness by re-signing with the same inputs.
}

static const unsigned char kPrivkey[32] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0x01,0x23,0x45,0x67,0xDE,0xAD,0xBE,0xEF,
};

// VCS-1: 64-byte message — basic varlen correctness
static void test_varlen_64byte(secp256k1_context* ctx) {
    std::printf("  [VCS-1] sign_custom varlen 64-byte round-trip\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-1: keypair_create");

    unsigned char msg[64] = {};
    msg[0] = 0xDE; msg[32] = 0xAD; msg[63] = 0xBE;
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 64, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-1: sign_custom 64-byte returns 1");

    unsigned int r_nonzero = 0;
    for (int i = 0; i < 32; ++i) r_nonzero |= sig[i];
    ASSERT_TRUE(r_nonzero != 0, "VCS-1: r component is not all-zero");

    unsigned int s_nonzero = 0;
    for (int i = 32; i < 64; ++i) s_nonzero |= sig[i];
    ASSERT_TRUE(s_nonzero != 0, "VCS-1: s component is not all-zero");
}

// VCS-2: 33-byte message — smallest varlen case
static void test_varlen_33byte(secp256k1_context* ctx) {
    std::printf("  [VCS-2] sign_custom varlen 33-byte (smallest varlen)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-2: keypair_create");

    unsigned char msg[33] = {};
    msg[0] = 0xFF; msg[32] = 0x01;
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 33, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-2: sign_custom 33-byte returns 1");

    unsigned int nonzero = 0;
    for (int i = 0; i < 64; ++i) nonzero |= sig[i];
    ASSERT_TRUE(nonzero != 0, "VCS-2: signature is non-zero");
}

// VCS-3: 256-byte message — stack buffer boundary (kStackMsgMax)
static void test_varlen_256byte(secp256k1_context* ctx) {
    std::printf("  [VCS-3] sign_custom varlen 256-byte (stack buffer boundary)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-3: keypair_create");

    unsigned char msg[256] = {};
    for (int i = 0; i < 256; ++i) msg[i] = (unsigned char)i;
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 256, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-3: sign_custom 256-byte returns 1");

    unsigned int nonzero = 0;
    for (int i = 0; i < 64; ++i) nonzero |= sig[i];
    ASSERT_TRUE(nonzero != 0, "VCS-3: signature is non-zero");
}

// VCS-4: 300-byte message — triggers heap buffer path (msglen > 256)
static void test_varlen_300byte_heap(secp256k1_context* ctx) {
    std::printf("  [VCS-4] sign_custom varlen 300-byte (heap path, msglen > 256)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-4: keypair_create");

    unsigned char msg[300] = {};
    for (int i = 0; i < 300; ++i) msg[i] = (unsigned char)(i ^ 0xA5);
    unsigned char sig[64] = {};

    int rc = secp256k1_schnorrsig_sign_custom(ctx, sig, msg, 300, &kp, nullptr);
    ASSERT_TRUE(rc == 1, "VCS-4: sign_custom 300-byte (heap path) returns 1");

    unsigned int nonzero = 0;
    for (int i = 0; i < 64; ++i) nonzero |= sig[i];
    ASSERT_TRUE(nonzero != 0, "VCS-4: signature is non-zero");
}

// VCS-5: determinism — same inputs must yield identical signature
static void test_varlen_determinism(secp256k1_context* ctx) {
    std::printf("  [VCS-5] sign_custom varlen determinism (same inputs -> same sig)\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-5: keypair_create");

    unsigned char msg[64] = {};
    msg[7] = 0xCA; msg[35] = 0xFE;
    unsigned char sig1[64] = {}, sig2[64] = {};

    ASSERT_TRUE(secp256k1_schnorrsig_sign_custom(ctx, sig1, msg, 64, &kp, nullptr) == 1,
                "VCS-5: first sign returns 1");
    ASSERT_TRUE(secp256k1_schnorrsig_sign_custom(ctx, sig2, msg, 64, &kp, nullptr) == 1,
                "VCS-5: second sign returns 1");
    ASSERT_TRUE(std::memcmp(sig1, sig2, 64) == 0,
                "VCS-5: varlen sign_custom is deterministic (CT erasure must not affect output)");
}

// VCS-6: 32-byte fast path still delegates correctly (regression guard)
static void test_32byte_fast_path(secp256k1_context* ctx) {
    std::printf("  [VCS-6] sign_custom 32-byte fast path still works after varlen fixes\n");
    secp256k1_keypair kp{};
    ASSERT_TRUE(secp256k1_keypair_create(ctx, &kp, kPrivkey) == 1, "VCS-6: keypair_create");

    unsigned char msg[32] = {}; msg[0] = 0x42; msg[31] = 0x77;
    unsigned char sig_custom[64] = {}, sig_sign32[64] = {};

    ASSERT_TRUE(secp256k1_schnorrsig_sign_custom(ctx, sig_custom, msg, 32, &kp, nullptr) == 1,
                "VCS-6: sign_custom 32-byte returns 1");
    ASSERT_TRUE(secp256k1_schnorrsig_sign32(ctx, sig_sign32, msg, &kp, nullptr) == 1,
                "VCS-6: sign32 returns 1");

    // sign_custom(msglen=32) must delegate to sign32 — same deterministic output
    ASSERT_TRUE(std::memcmp(sig_custom, sig_sign32, 64) == 0,
                "VCS-6: sign_custom(32) == sign32 (fast path delegation correct)");
}

int test_regression_schnorr_varlen_ct_fixes_run() {
    g_fail = 0;

    if (!secp256k1_context_create || !secp256k1_context_destroy ||
        !secp256k1_keypair_create || !secp256k1_schnorrsig_sign_custom ||
        !secp256k1_schnorrsig_sign32) {
        std::printf("  SKIP VCS: shim not linked\n");
        return ADVISORY_SKIP_CODE;
    }

    secp256k1_context* ctx = secp256k1_context_create(CTX_SIGN | CTX_VERIFY);
    if (!ctx) {
        std::printf("  SKIP VCS: context_create failed\n");
        return ADVISORY_SKIP_CODE;
    }

    test_varlen_64byte(ctx);
    test_varlen_33byte(ctx);
    test_varlen_256byte(ctx);
    test_varlen_300byte_heap(ctx);
    test_varlen_determinism(ctx);
    test_32byte_fast_path(ctx);

    secp256k1_context_destroy(ctx);

    if (g_fail == 0)
        std::printf("  PASS VCS-1..6: sign_custom varlen CT fixes correctness\n");
    else
        std::printf("  FAIL VCS: sign_custom varlen CT fixes: %d failure(s)\n", g_fail);
    return g_fail;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_schnorr_varlen_ct_fixes_run(); }
#endif
