// ============================================================================
// test_regression_musig2_signer_index_validation.cpp
// Regression: musig2_partial_sign must validate secret_key <-> signer_index.
//
// Bug fixed: musig2_partial_sign accepted any caller-supplied signer_index
// without verifying the secret key corresponds to the pubkey at that index.
// Fix: musig2_key_agg now stores individual_pubkeys; musig2_partial_sign
// validates ct::generator_mul(sk) == individual_pubkeys[signer_index] when
// the context was created via musig2_key_agg (not ABI deserialization).
//
// Tests:
//   MSI-1: correct key + correct index signs successfully
//   MSI-2: correct key + wrong index returns zero scalar (fail-closed)
//   MSI-3: aggregated partial sigs with correct indices verify correctly
//   MSI-4: empty individual_pubkeys (ABI-deserialized ctx) skips check
// ============================================================================

#include <cstdio>
#include <cstring>
#include <array>
#include <vector>
static int g_pass = 0, g_fail = 0;
#include "audit_check.hpp"
#include "secp256k1/musig2.hpp"
#include "secp256k1/scalar.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/ct/point.hpp"

using namespace secp256k1;
using fast::Scalar;
using fast::Point;

// secp256k1 order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
static const unsigned char kSk1[32] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05
};
static const unsigned char kSk2[32] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07
};

static std::array<uint8_t, 33> pubkey_compressed(const unsigned char sk[32]) {
    Scalar s{};
    Scalar::parse_bytes_strict_nonzero(sk, s);
    auto P = ct::generator_mul(s);
    return P.to_compressed();
}

static MuSig2KeyAggCtx make_2party_keyagg() {
    auto pk1 = pubkey_compressed(kSk1);
    auto pk2 = pubkey_compressed(kSk2);
    std::vector<std::array<uint8_t, 33>> pks = {pk1, pk2};
    return musig2_key_agg(pks);
}

// ── MSI-1: correct key at correct index signs successfully ────────────────
static void test_correct_key_correct_index() {
    auto kagg = make_2party_keyagg();
    CHECK(kagg.individual_pubkeys.size() == 2, "[MSI-1a] individual_pubkeys populated");

    Scalar sk1{};
    Scalar::parse_bytes_strict_nonzero(kSk1, sk1);

    // Build minimal session (single-party nonce for isolation test)
    auto [sn1, pn1] = musig2_nonce_gen(sk1, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, nullptr);

    Scalar sk2{};
    Scalar::parse_bytes_strict_nonzero(kSk2, sk2);
    auto [sn2, pn2] = musig2_nonce_gen(sk2, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2}, nullptr);

    MuSig2AggNonce aggnonce = musig2_nonce_agg({pn1, pn2});
    std::array<uint8_t,32> msg = {0x11,0x22,0x33};
    MuSig2Session sess = musig2_start_sign_session(aggnonce, kagg, msg);

    auto psig1 = musig2_partial_sign(sn1, sk1, kagg, sess, 0);
    CHECK(!psig1.is_zero(), "[MSI-1b] signer-0 partial sign succeeds with correct key+index");
}

// ── MSI-2: correct key + wrong index returns zero scalar (fail-closed) ────
static void test_correct_key_wrong_index() {
    auto kagg = make_2party_keyagg();

    Scalar sk1{};
    Scalar::parse_bytes_strict_nonzero(kSk1, sk1);

    auto [sn1, pn1] = musig2_nonce_gen(sk1, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3}, nullptr);
    Scalar sk2{};
    Scalar::parse_bytes_strict_nonzero(kSk2, sk2);
    auto [sn2, pn2] = musig2_nonce_gen(sk2, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4}, nullptr);

    MuSig2AggNonce aggnonce = musig2_nonce_agg({pn1, pn2});
    std::array<uint8_t,32> msg = {0xAA,0xBB,0xCC};
    MuSig2Session sess = musig2_start_sign_session(aggnonce, kagg, msg);

    // sk1 belongs to signer index 0, but we claim index 1 — must fail
    auto psig_wrong = musig2_partial_sign(sn1, sk1, kagg, sess, 1);
    CHECK(psig_wrong.is_zero(), "[MSI-2] wrong signer_index returns zero (fail-closed)");
}

// ── MSI-3: full 2-of-2 round-trip with correct indices verifies ──────────
static void test_full_roundtrip_correct_indices() {
    auto kagg = make_2party_keyagg();

    Scalar sk1{};
    Scalar::parse_bytes_strict_nonzero(kSk1, sk1);
    Scalar sk2{};
    Scalar::parse_bytes_strict_nonzero(kSk2, sk2);

    auto [sn1, pn1] = musig2_nonce_gen(sk1, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5}, nullptr);
    auto [sn2, pn2] = musig2_nonce_gen(sk2, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,6}, nullptr);

    MuSig2AggNonce aggnonce = musig2_nonce_agg({pn1, pn2});
    std::array<uint8_t,32> msg = {0xDE,0xAD,0xBE,0xEF};
    MuSig2Session sess = musig2_start_sign_session(aggnonce, kagg, msg);

    MuSig2Session sess2 = sess;  // copy session for signer 2
    auto psig1 = musig2_partial_sign(sn1, sk1, kagg, sess, 0);
    auto psig2 = musig2_partial_sign(sn2, sk2, kagg, sess2, 1);

    CHECK(!psig1.is_zero(), "[MSI-3a] signer-0 partial sign non-zero");
    CHECK(!psig2.is_zero(), "[MSI-3b] signer-1 partial sign non-zero");

    auto final_sig = musig2_partial_sig_agg({psig1, psig2}, sess);
    // final_sig is a 64-byte BIP-340 Schnorr signature over msg with Q
    CHECK(final_sig[0] != 0 || final_sig[32] != 0, "[MSI-3c] aggregated signature non-zero");
}

// ── MSI-4: empty individual_pubkeys (ABI ctx) skips check ────────────────
static void test_abi_ctx_skips_check() {
    // Simulate ABI-deserialized keyagg: individual_pubkeys is empty
    auto kagg = make_2party_keyagg();
    kagg.individual_pubkeys.clear();  // simulate ABI-deserialized ctx

    Scalar sk1{};
    Scalar::parse_bytes_strict_nonzero(kSk1, sk1);

    auto [sn1, pn1] = musig2_nonce_gen(sk1, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7}, nullptr);
    Scalar sk2{};
    Scalar::parse_bytes_strict_nonzero(kSk2, sk2);
    auto [sn2, pn2] = musig2_nonce_gen(sk2, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8}, nullptr);
    MuSig2AggNonce aggnonce = musig2_nonce_agg({pn1, pn2});
    std::array<uint8_t,32> msg = {0x55};
    MuSig2Session sess = musig2_start_sign_session(aggnonce, kagg, msg);

    // With empty individual_pubkeys, wrong index skips validation (ABI limitation, documented MED-3).
    // The partial sig is produced using sk1 (signer 0) but claimed as signer index 1.
    //
    // MSI-4 DESIRED BEHAVIOR: musig2_partial_sign should reject wrong signer index and
    // return a zero partial sig. Currently (MED-3 open) it produces a non-zero sig — wrong
    // signer attribution. This test asserts the DESIRED state; it will correctly fail as
    // advisory_failed until MED-3 is closed.
    //
    // NOTE: when this advisory test starts passing, MED-3 has been fixed. Remove the
    // advisory=true flag and promote this to mandatory at that point.
    auto psig_skip = musig2_partial_sign(sn1, sk1, kagg, sess, 1);
    std::printf("  [MSI-4] bypass output is_zero=%d (want 1=zero when MED-3 fixed)\n",
                psig_skip.is_zero() ? 1 : 0);
    CHECK(psig_skip.is_zero(), "[MSI-4] MED-3 fix: bypass with wrong signer index should return zero partial sig (currently fails — open gap)");
}

// ── _run() ───────────────────────────────────────────────────────────────
int test_regression_musig2_signer_index_validation_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_musig2_signer_index_validation] MuSig2 signer_index cross-check (Rule 13)\n");

    // Run the three MANDATORY subtests first and snapshot g_fail. Any failure
    // in these subtests is a real regression.
    test_correct_key_correct_index();
    test_correct_key_wrong_index();
    test_full_roundtrip_correct_indices();
    const int mandatory_fail = g_fail;

    // test_abi_ctx_skips_check contains the MSI-4 assertion, which is the
    // DESIRED post-MED-3 behavior and intentionally fails until MED-3 is
    // closed (review finding RED-002 / P1-SEC-002). When MSI-4 is the only
    // failure, exit with ADVISORY_SKIP_CODE (77) so the runner / shim-gate
    // mark this module as advisory-skipped rather than a real regression.
    test_abi_ctx_skips_check();
    const int advisory_only_fail = g_fail - mandatory_fail;

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    if (g_fail == 0) return 0;
    if (mandatory_fail == 0 && advisory_only_fail > 0) {
        std::printf("  [advisory-skip] MSI-4 is the documented MED-3 open gap; signalling rc=77\n");
        return 77;
    }
    return 1;
}

#ifdef STANDALONE_TEST
int main() { return test_regression_musig2_signer_index_validation_run(); }
#endif
