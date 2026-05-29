// ============================================================================
// test_shim_der_zero_r.cpp — DER parse rejection of degenerate / malformed sigs
// ============================================================================
// secp256k1_ecdsa_signature_parse_der behavior (verified empirically against the
// shim, 2026-05-28):
//
//   * r=0 and s=0 are REJECTED at parse time (return 0). The only canonical DER
//     encoding of zero is `02 01 00`, which the parser's minimal-encoding rule
//     rejects (a single leading 0x00 byte fails the `len < 2` check). This is a
//     documented divergence from upstream libsecp256k1, which accepts zero at
//     parse and defers rejection to verify — see docs/SHIM_KNOWN_DIVERGENCES.md
//     ("secp256k1_ecdsa_signature_parse_der").
//   * r=n / s=n (>= curve order) are rejected (not in [1, n-1]).
//   * RT-02 (strict-DER): an inflated-length SEQUENCE whose declared length fills
//     the input buffer but leaves trailing bytes *inside* the SEQUENCE after s is
//     rejected (the parser requires exact SEQUENCE consumption, `p == end`).
//   * A well-formed minimal DER signature parses (return 1).
//
// NOTE: a prior read-only-review pass (RT-01) claimed parse_der had switched to
// ACCEPTING r=0/s=0 and that this test was stale. Direct measurement disproved
// that — parse_der rejects r=0/s=0 at parse, and this test asserts the true,
// shipping behavior. The added RT-02 trailing-bytes case covers the real fix.
// ============================================================================

#include <secp256k1.h>
#include <cstdio>
#include <cstring>
#include <cstdint>

// r=0 (canonical `02 01 00`), s=0x01..01 (32 bytes): 37-byte SEQUENCE.
static const uint8_t DER_R_ZERO[] = {
    0x30, 0x25,
    0x02, 0x01, 0x00,
    0x02, 0x20,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

// r=0x01..01 (32 bytes), s=0 (canonical `02 01 00`): 37-byte SEQUENCE.
static const uint8_t DER_S_ZERO[] = {
    0x30, 0x25,
    0x02, 0x20,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x01, 0x00,
};

// RT-02: SEQUENCE declares 8 content bytes (fills the 10-byte buffer) but r,s
// consume only 6 — two trailing bytes (7F 7F) remain inside the SEQUENCE.
//   30 08  02 01 0F  02 01 01  7F 7F
static const uint8_t DER_TRAILING_INSIDE_SEQ[] = {
    0x30, 0x08, 0x02, 0x01, 0x0F, 0x02, 0x01, 0x01, 0x7F, 0x7F,
};

// Well-formed minimal DER: r=0x0F, s=0x01 — must parse.
static const uint8_t DER_VALID[] = {
    0x30, 0x06, 0x02, 0x01, 0x0F, 0x02, 0x01, 0x01,
};

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, label) do { \
    if (cond) { printf("  [PASS] %s\n", (label)); ++g_pass; } \
    else      { printf("  [FAIL] %s\n", (label)); ++g_fail; } \
} while (0)

static int parse(secp256k1_context* ctx, const uint8_t* d, size_t n) {
    secp256k1_ecdsa_signature sig;
    memset(&sig, 0, sizeof(sig));
    return secp256k1_ecdsa_signature_parse_der(ctx, &sig, d, n);
}

int test_shim_der_zero_r_run() {
    printf("\n[der-parse-strict] reject r=0 / s=0 / trailing-in-SEQUENCE; accept valid\n");

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        printf("  [FAIL] context_create returned NULL\n");
        return 1;
    }

    CHECK(parse(ctx, DER_R_ZERO, sizeof(DER_R_ZERO)) == 0,
          "parse_der rejects r=0 (shim stricter than upstream — rejects at parse)");
    CHECK(parse(ctx, DER_S_ZERO, sizeof(DER_S_ZERO)) == 0,
          "parse_der rejects s=0 (shim stricter than upstream — rejects at parse)");
    CHECK(parse(ctx, DER_TRAILING_INSIDE_SEQ, sizeof(DER_TRAILING_INSIDE_SEQ)) == 0,
          "parse_der rejects trailing bytes inside SEQUENCE (strict-DER, RT-02)");
    CHECK(parse(ctx, DER_VALID, sizeof(DER_VALID)) == 1,
          "parse_der accepts a well-formed minimal DER signature");

    secp256k1_context_destroy(ctx);

    printf("\n  Results: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main(void) {
    return test_shim_der_zero_r_run();
}
#endif
