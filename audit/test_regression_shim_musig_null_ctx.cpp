// ============================================================================
// test_regression_shim_musig_null_ctx.cpp
// Regression: secp256k1_musig_pubnonce_serialize, pubnonce_parse, nonce_agg,
// nonce_process must reject NULL ctx and return 0 (SHIM-NEW-004).
//
// Prior behavior: these four functions used `const secp256k1_context* /*ctx*/`
// (parameter suppressed), so NULL ctx was silently accepted and the functions
// proceeded without firing the illegal callback. This violated libsecp256k1
// ABI contracts, which require NULL ctx to trigger the illegal callback.
//
// Fix: SHIM_REQUIRE_CTX(ctx) added to all four functions.
//
// Tests:
//   MNC-1: pubnonce_serialize(NULL ctx) returns 0
//   MNC-2: pubnonce_parse(NULL ctx) returns 0
//   MNC-3: nonce_agg(NULL ctx) returns 0
//   MNC-4: nonce_process(NULL ctx) returns 0
// ============================================================================

#include "audit_check.hpp"
static int g_pass = 0, g_fail = 0;
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "secp256k1.h"
#include "secp256k1_musig.h"
#include "secp256k1_extrakeys.h"

static const unsigned char kSk1[32] = {
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01
};
static const unsigned char kSid[32] = {
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
    0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89
};

// Build a valid pubnonce by running nonce_gen with a real context
static secp256k1_musig_pubnonce make_pubnonce(secp256k1_context* ctx) {
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, kSk1);

    secp256k1_musig_keyagg_cache kagg;
    const secp256k1_pubkey* pks[1] = { &pubkey };
    secp256k1_musig_pubkey_agg(ctx, nullptr, &kagg, pks, 1);

    secp256k1_musig_secnonce secnonce;
    secp256k1_musig_pubnonce pubnonce;
    secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce,
                               kSid, kSk1, &pubkey, nullptr, nullptr, nullptr);
    return pubnonce;
}

// ── MNC-1: pubnonce_serialize with NULL ctx returns 0 ────────────────────
static void test_pubnonce_serialize_null_ctx() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_musig_pubnonce pn = make_pubnonce(ctx);
    unsigned char out66[66] = {};
    int r = secp256k1_musig_pubnonce_serialize(nullptr, out66, &pn);
    CHECK(r == 0, "[MNC-1] pubnonce_serialize(NULL ctx) must return 0");
    secp256k1_context_destroy(ctx);
}

// ── MNC-2: pubnonce_parse with NULL ctx returns 0 ────────────────────────
static void test_pubnonce_parse_null_ctx() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_musig_pubnonce pn = make_pubnonce(ctx);

    // First serialize to get a valid 66-byte encoding
    unsigned char enc66[66] = {};
    secp256k1_musig_pubnonce_serialize(ctx, enc66, &pn);

    secp256k1_musig_pubnonce out_pn;
    int r = secp256k1_musig_pubnonce_parse(nullptr, &out_pn, enc66);
    CHECK(r == 0, "[MNC-2] pubnonce_parse(NULL ctx) must return 0");
    secp256k1_context_destroy(ctx);
}

// ── MNC-3: nonce_agg with NULL ctx returns 0 ─────────────────────────────
static void test_nonce_agg_null_ctx() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_musig_pubnonce pn = make_pubnonce(ctx);
    const secp256k1_musig_pubnonce* pns[1] = { &pn };
    secp256k1_musig_aggnonce aggnonce;
    int r = secp256k1_musig_nonce_agg(nullptr, &aggnonce, pns, 1);
    CHECK(r == 0, "[MNC-3] nonce_agg(NULL ctx) must return 0");
    secp256k1_context_destroy(ctx);
}

// ── MNC-4: nonce_process with NULL ctx returns 0 ─────────────────────────
static void test_nonce_process_null_ctx() {
    secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // Build a valid aggnonce to pass non-NULL aggnonce arg (only ctx is NULL)
    secp256k1_musig_pubnonce pn = make_pubnonce(ctx);
    const secp256k1_musig_pubnonce* pns[1] = { &pn };
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_nonce_agg(ctx, &aggnonce, pns, 1);

    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, kSk1);
    secp256k1_musig_keyagg_cache kagg;
    const secp256k1_pubkey* pks[1] = { &pubkey };
    secp256k1_musig_pubkey_agg(ctx, nullptr, &kagg, pks, 1);

    static const unsigned char msg32[32] = { 0x11 };
    secp256k1_musig_session session;
    int r = secp256k1_musig_nonce_process(nullptr, &session, &aggnonce, msg32, &kagg);
    CHECK(r == 0, "[MNC-4] nonce_process(NULL ctx) must return 0");
    secp256k1_context_destroy(ctx);
}

// ── _run() ────────────────────────────────────────────────────────────────
int test_regression_shim_musig_null_ctx_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_shim_musig_null_ctx] SHIM-NEW-004: NULL ctx rejected by 4 MuSig shim functions\n");

    test_pubnonce_serialize_null_ctx();
    test_pubnonce_parse_null_ctx();
    test_nonce_agg_null_ctx();
    test_nonce_process_null_ctx();

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_shim_musig_null_ctx_run(); }
#endif
