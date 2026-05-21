// ============================================================================
// test_regression_musig2_infinity_nonce.cpp
// Regression: musig2_start_sign_session and musig2_nonce_agg must handle
// infinity nonce components safely (SEC-005, SEC-009).
//
// SEC-005: BIP-327 §GetSessionValues step 2 requires aborting if R1 or R2
//          in the aggregated nonce is the point at infinity. Previously,
//          musig2_start_sign_session would call to_compressed() on an infinity
//          point (undefined/UB path) and proceed to produce a corrupt session.
//
// SEC-009: musig2_nonce_agg with an empty pub_nonces vector initialises R1 and
//          R2 to Point::infinity() and returns without error, silently passing
//          an invalid aggregated nonce to the caller.  The fix adds an early
//          return for the empty-vector case.  Non-empty but cancelling nonces
//          (R1+…+Rn = infinity) are caught at start_sign_session (SEC-005).
//
// Tests:
//   MIN-1: musig2_nonce_agg with empty vector returns all-infinity struct
//   MIN-2: musig2_start_sign_session rejects R1=infinity → invalid session
//          (session.e.is_zero() and session.R.is_infinity())
//   MIN-3: musig2_start_sign_session rejects R2=infinity → invalid session
//   MIN-4: musig2_start_sign_session with empty-agg-nonce (from nonce_agg({}))
//          returns invalid session — end-to-end path
//   MIN-5: Valid 2-of-2 nonce round-trip still works correctly after the fix
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

static const unsigned char kSk1[32] = {
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0A
};
static const unsigned char kSk2[32] = {
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0B
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

// Returns a session that is considered invalid: R is infinity AND e is zero.
static bool session_is_invalid(const MuSig2Session& sess) {
    return sess.R.is_infinity() && sess.e.is_zero();
}

// ── MIN-1: nonce_agg empty vector returns infinity struct ─────────────────
static void test_nonce_agg_empty_vector() {
    MuSig2AggNonce agg = musig2_nonce_agg({});
    CHECK(agg.R1.is_infinity(), "[MIN-1a] musig2_nonce_agg({}) → R1 is infinity");
    CHECK(agg.R2.is_infinity(), "[MIN-1b] musig2_nonce_agg({}) → R2 is infinity");
}

// ── MIN-2: start_sign_session rejects R1=infinity ─────────────────────────
static void test_start_sign_session_r1_infinity() {
    auto kagg = make_2party_keyagg();
    std::array<uint8_t, 32> msg = {0x11, 0x22, 0x33};

    MuSig2AggNonce bad_nonce{};
    bad_nonce.R1 = Point::infinity();   // R1 is infinity
    bad_nonce.R2 = Point::generator();  // R2 is a valid point

    MuSig2Session sess = musig2_start_sign_session(bad_nonce, kagg, msg);
    CHECK(session_is_invalid(sess),
          "[MIN-2] start_sign_session with R1=infinity returns invalid session");
}

// ── MIN-3: start_sign_session rejects R2=infinity ─────────────────────────
static void test_start_sign_session_r2_infinity() {
    auto kagg = make_2party_keyagg();
    std::array<uint8_t, 32> msg = {0x44, 0x55, 0x66};

    MuSig2AggNonce bad_nonce{};
    bad_nonce.R1 = Point::generator();  // R1 is a valid point
    bad_nonce.R2 = Point::infinity();   // R2 is infinity

    MuSig2Session sess = musig2_start_sign_session(bad_nonce, kagg, msg);
    CHECK(session_is_invalid(sess),
          "[MIN-3] start_sign_session with R2=infinity returns invalid session");
}

// ── MIN-4: start_sign_session rejects agg_nonce from nonce_agg({}) ────────
static void test_start_sign_session_from_empty_agg() {
    auto kagg = make_2party_keyagg();
    std::array<uint8_t, 32> msg = {0x77, 0x88, 0x99};

    // SEC-009 + SEC-005 end-to-end: empty vector → infinity → rejected
    MuSig2AggNonce agg = musig2_nonce_agg({});
    MuSig2Session sess = musig2_start_sign_session(agg, kagg, msg);
    CHECK(session_is_invalid(sess),
          "[MIN-4] start_sign_session with musig2_nonce_agg({}) returns invalid session");
}

// ── MIN-5: valid 2-of-2 round-trip still works after the fix ─────────────
static void test_valid_2of2_round_trip() {
    auto kagg = make_2party_keyagg();

    Scalar sk1{};
    Scalar::parse_bytes_strict_nonzero(kSk1, sk1);
    Scalar sk2{};
    Scalar::parse_bytes_strict_nonzero(kSk2, sk2);

    auto [sn1, pn1] = musig2_nonce_gen(sk1, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, nullptr);
    auto [sn2, pn2] = musig2_nonce_gen(sk2, kagg.Q_x, kagg.Q_x,
                                        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2}, nullptr);

    MuSig2AggNonce aggnonce = musig2_nonce_agg({pn1, pn2});
    // Valid aggregated nonce must NOT be infinity
    CHECK(!aggnonce.R1.is_infinity(), "[MIN-5a] valid nonce agg: R1 not infinity");
    CHECK(!aggnonce.R2.is_infinity(), "[MIN-5b] valid nonce agg: R2 not infinity");

    std::array<uint8_t, 32> msg = {0xAB, 0xCD, 0xEF};
    MuSig2Session sess = musig2_start_sign_session(aggnonce, kagg, msg);
    CHECK(!session_is_invalid(sess), "[MIN-5c] valid session: not flagged as invalid");
    CHECK(!sess.e.is_zero(),         "[MIN-5d] valid session: challenge e is non-zero");
    CHECK(!sess.R.is_infinity(),     "[MIN-5e] valid session: nonce R is not infinity");

    MuSig2Session sess2 = sess;
    auto psig1 = musig2_partial_sign(sn1, sk1, kagg, sess, 0);
    auto psig2 = musig2_partial_sign(sn2, sk2, kagg, sess2, 1);
    CHECK(!psig1.is_zero(), "[MIN-5f] signer-0 partial sign succeeds");
    CHECK(!psig2.is_zero(), "[MIN-5g] signer-1 partial sign succeeds");

    auto final_sig = musig2_partial_sig_agg({psig1, psig2}, sess2);
    CHECK(final_sig[0] != 0 || final_sig[32] != 0,
          "[MIN-5h] aggregated signature non-zero");
}

// ── _run() ───────────────────────────────────────────────────────────────
int test_regression_musig2_infinity_nonce_run() {
    g_pass = 0; g_fail = 0;
    std::printf("[regression_musig2_infinity_nonce] MuSig2 infinity nonce rejection (SEC-005, SEC-009)\n");

    test_nonce_agg_empty_vector();
    test_start_sign_session_r1_infinity();
    test_start_sign_session_r2_infinity();
    test_start_sign_session_from_empty_agg();
    test_valid_2of2_round_trip();

    std::printf("  pass=%d  fail=%d\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}

#ifdef STANDALONE_TEST
int main() {
    return test_regression_musig2_infinity_nonce_run();
}
#endif
