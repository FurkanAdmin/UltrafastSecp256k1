/**
 * ufsecp_libbitcoin.h — UltrafastSecp256k1 ⇄ libbitcoin acceleration bridge.
 *
 * A single "shim controller" entry point that gives a Bitcoin full node (or any
 * consumer) two GPU-accelerated batch capabilities with a MANDATORY CPU
 * fallback, behind one tiny C ABI. Pure C / C++ — no FFI, no language bindings
 * required.
 *
 *   1. Script-signature batch verification  (ECDSA + Schnorr / BIP-340)
 *        - The signature/key/sighash triples extracted from Bitcoin scripts
 *          (CHECKSIG / CHECKMULTISIG / Taproot CHECKSIG / CHECKSIGADD).
 *        - Signatures are ~95% of script validation cost; this is the big win
 *          for IBD / historical block validation. NOT a mempool-latency path.
 *        - GPU verifies each signature on its own thread, so PER-ROW pass/fail
 *          is produced naturally — exactly what a node needs to locate the bad
 *          signature and map it back to a block/tx.
 *
 *   2. BIP-352 Silent Payments scan batch
 *        - GPU-accelerated ECDH scan for silent-payment indexing (Electrum /
 *          server use case). Reuses the existing engine SP scan pipeline.
 *
 * Design contract (agreed with the libbitcoin maintainer):
 *   - ECDSA and Schnorr are SEPARATE calls. The data stays homogeneous and
 *     uniform-sized, and the two kinds stack independently (one GPU stream
 *     each, or one card each).
 *   - The caller passes ONE unified table per call. Each row is:
 *         [ signature record ][ optional opaque correlation key ]
 *     The bridge verifies only the signature record and never interprets the
 *     opaque key bytes. The key is the caller's own tag (e.g. 3-byte block id,
 *     4-byte tx id). It is carried purely so an invalid row can be mapped back
 *     to its block/tx without a second side table.
 *   - The opaque key column is VARIABLE-sized: pass `key_size` on the call.
 *     `key_size == 0` disables it entirely (fastest; row stride == record size).
 *   - Results are returned directly: a per-row pass/fail array AND, optionally,
 *     a compact list of the failing row indices.
 *
 * Consensus note:
 *   For block validation the GPU path is used as a consensus-bearing
 *   accelerator. Correctness is anchored on the CPU/libsecp256k1-equivalent
 *   reference: the GPU result MUST match the CPU result bit-for-bit, which is
 *   enforced by a differential test gate. The CPU fallback is always available
 *   and is never optional.
 */
#ifndef UFSECP_LIBBITCOIN_H
#define UFSECP_LIBBITCOIN_H

#include <stddef.h>
#include <stdint.h>
#include "ufsecp_error.h" /* ufsecp_error_t, UFSECP_OK, UFSECP_ERR_* */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Record layouts (signature payload only — excludes any opaque key column).  */
/* ------------------------------------------------------------------------- */

/* ECDSA row:   32-byte msghash | 33-byte compressed pubkey | 64-byte sig. */
#define UFSECP_LBTC_ECDSA_RECORD   129u
/* Schnorr row: 32-byte x-only pubkey | 32-byte msg | 64-byte sig (R.x|s). */
#define UFSECP_LBTC_SCHNORR_RECORD 128u

/* ------------------------------------------------------------------------- */
/* Controller lifecycle.                                                      */
/* ------------------------------------------------------------------------- */

/* Opaque controller. Create once, reuse across many batches. It owns the GPU
 * backend (if any) and the CPU fallback. Not internally synchronized: use one
 * controller per worker thread, or serialize calls externally. */
typedef struct ufsecp_lbtc_ctrl ufsecp_lbtc_ctrl;

/* Backend selection at creation time. */
typedef enum {
    UFSECP_LBTC_AUTO = 0, /* GPU if usable, else CPU (recommended).            */
    UFSECP_LBTC_GPU  = 1, /* Require a GPU; create fails with no usable GPU.   */
    UFSECP_LBTC_CPU  = 2  /* Force the CPU fallback only.                      */
} ufsecp_lbtc_backend;

/* The backend the controller actually bound (query after create). */
typedef enum {
    UFSECP_LBTC_BOUND_CPU    = 0,
    UFSECP_LBTC_BOUND_CUDA   = 1,
    UFSECP_LBTC_BOUND_OPENCL = 2,
    UFSECP_LBTC_BOUND_METAL  = 3
} ufsecp_lbtc_bound;

/* Create / destroy the controller. On success *out receives a non-NULL handle.
 * UFSECP_LBTC_AUTO never fails for lack of a GPU — it silently binds CPU. */
ufsecp_error_t ufsecp_lbtc_ctrl_create(ufsecp_lbtc_ctrl** out,
                                       ufsecp_lbtc_backend backend);
void           ufsecp_lbtc_ctrl_destroy(ufsecp_lbtc_ctrl* ctrl);

/* Which backend is bound, and a human-readable device name (may be NULL). */
ufsecp_lbtc_bound ufsecp_lbtc_ctrl_backend(const ufsecp_lbtc_ctrl* ctrl);
const char*       ufsecp_lbtc_ctrl_device_name(const ufsecp_lbtc_ctrl* ctrl);

/* ------------------------------------------------------------------------- */
/* 1. Script-signature batch verification.                                    */
/* ------------------------------------------------------------------------- */

/*
 * Verify a homogeneous batch of ECDSA (resp. Schnorr) signatures.
 *
 *   rows          n rows, each (RECORD + key_size) bytes, tightly packed.
 *                 The signature record occupies the first RECORD bytes; the
 *                 trailing key_size bytes are the caller's opaque tag.
 *   n             number of rows.
 *   key_size      opaque trailing bytes per row; 0 to disable.
 *   results       OUT, optional. If non-NULL, must be n bytes: results[i] is
 *                 1 if row i is valid, 0 if invalid.
 *   invalid_idx   OUT, optional. If non-NULL, receives the indices of failing
 *                 rows, up to invalid_cap entries.
 *   invalid_cap   capacity of invalid_idx (entries); ignored if invalid_idx is
 *                 NULL.
 *   invalid_count OUT, optional. Set to the TOTAL number of failing rows (which
 *                 may exceed invalid_cap — the caller can detect truncation).
 *
 * Return value:
 *   UFSECP_OK              the batch was processed (inspect results / counts);
 *                          all rows valid iff *invalid_count == 0.
 *   UFSECP_ERR_BAD_INPUT   n overflow, malformed stride, etc.
 *   UFSECP_ERR_BAD_PUBKEY  a row's pubkey is not a valid curve point.
 *   UFSECP_ERR_BAD_SIG     a row's signature is structurally invalid (e.g.
 *                          s >= n, R.x >= p). Such a row counts as invalid.
 *   UFSECP_ERR_NULL_ARG    ctrl or rows is NULL with n > 0.
 *
 * A NULL `rows` with n == 0 is the empty batch: vacuously valid, returns
 * UFSECP_OK with *invalid_count == 0.
 */
ufsecp_error_t ufsecp_lbtc_verify_ecdsa(ufsecp_lbtc_ctrl* ctrl,
                                        const uint8_t* rows, size_t n,
                                        size_t key_size,
                                        uint8_t* results,
                                        size_t* invalid_idx, size_t invalid_cap,
                                        size_t* invalid_count);

ufsecp_error_t ufsecp_lbtc_verify_schnorr(ufsecp_lbtc_ctrl* ctrl,
                                          const uint8_t* rows, size_t n,
                                          size_t key_size,
                                          uint8_t* results,
                                          size_t* invalid_idx, size_t invalid_cap,
                                          size_t* invalid_count);

/* ------------------------------------------------------------------------- */
/* 2. BIP-352 Silent Payments scan batch.                                     */
/* ------------------------------------------------------------------------- */

/*
 * Scan a batch of input-tweak public keys for a single recipient (scan key +
 * spend pubkey), producing one 64-bit output prefix per tweak for fast wallet
 * matching. Mirrors the engine GPU scan pipeline (ufsecp_gpu_bip352_scan_batch)
 * with a CPU fallback.
 *
 *   scan_privkey32  the recipient scan private key (secret — CT path on CPU,
 *                   branchless on GPU; erased after use).
 *   spend_pubkey33  the recipient spend public key (compressed).
 *   tweak_pubkeys33 n * 33 bytes, one compressed input-tweak pubkey per entry.
 *   n               number of tweaks.
 *   prefix64_out    OUT, n * uint64_t output prefixes for matching.
 */
ufsecp_error_t ufsecp_lbtc_sp_scan(ufsecp_lbtc_ctrl* ctrl,
                                   const uint8_t scan_privkey32[32],
                                   const uint8_t spend_pubkey33[33],
                                   const uint8_t* tweak_pubkeys33, size_t n,
                                   uint64_t* prefix64_out);

#ifdef __cplusplus
} /* extern "C" */

/* ------------------------------------------------------------------------- */
/* Optional thin C++ RAII convenience wrapper (header-only, zero overhead).   */
/* ------------------------------------------------------------------------- */
namespace ufsecp {
namespace lbtc {

class Controller {
public:
    explicit Controller(ufsecp_lbtc_backend backend = UFSECP_LBTC_AUTO) {
        (void)ufsecp_lbtc_ctrl_create(&ctrl_, backend);
    }
    ~Controller() { ufsecp_lbtc_ctrl_destroy(ctrl_); }
    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;

    bool ok() const { return ctrl_ != nullptr; }
    ufsecp_lbtc_ctrl* get() const { return ctrl_; }
    ufsecp_lbtc_bound backend() const { return ufsecp_lbtc_ctrl_backend(ctrl_); }

private:
    ufsecp_lbtc_ctrl* ctrl_ = nullptr;
};

} // namespace lbtc
} // namespace ufsecp
#endif /* __cplusplus */

#endif /* UFSECP_LIBBITCOIN_H */
