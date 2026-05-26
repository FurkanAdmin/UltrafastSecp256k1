# Libsecp256k1 Shim — Known Behavioral Divergences

This document lists every intentional behavioral difference between the
UltrafastSecp256k1 libsecp256k1 shim and upstream libsecp256k1.

**An unlisted divergence is a bug.** If you discover shim behavior that differs
from libsecp256k1 and it is not documented here, it must either be fixed or added
to this file before any PR.

For the complete compatibility test matrix see `compat/libsecp256k1_shim/tests/`.

---

## Security improvements (shim is stricter than upstream)

These divergences are intentional hardening beyond upstream libsecp256k1. They
are stricter but never less safe. Callers using well-formed inputs are unaffected.

---

### secp256k1_ecdh — private key >= curve order rejected

- **Upstream behavior:** `secp256k1_ecdh` with a private key value `>= n` (curve order)
  reduces the key silently mod n and proceeds. A key equal to `n` reduces to 0 and is
  rejected (returns 0); `n+1` reduces to 1 and succeeds.
- **Shim behavior:** Any private key value `>= n` returns 0 immediately.
  `parse_bytes_strict_nonzero` is used instead of `from_bytes` (CLAUDE.md Rule 11).
- **Reason:** Rule 11 requires strict private key parsing for all functions accepting a
  secret key byte array. Silent mod-n reduction can mask caller errors (e.g., passing
  `n+1` believing it is invalid). Strict rejection is the safer default.
- **Impact:** Any caller passing a private key value `>= n` to `secp256k1_ecdh`.
  In practice, well-formed private keys from `secp256k1_ec_seckey_verify` or
  `secp256k1_keypair_create` are always `< n` and are unaffected.
- **Test:** `test_ecdh_privkey_out_of_range` in
  `audit/test_regression_shim_security_v8.cpp` (checks ORDER, ORDER+1, 0xff..ff).

---

### secp256k1_ecdh — off-curve pubkey rejected

- **Upstream behavior:** libsecp256k1 trusts the `secp256k1_pubkey` opaque struct to
  contain a valid on-curve point (invariant: always populated via `ec_pubkey_parse`).
  No runtime on-curve check is performed in `secp256k1_ecdh` itself.
- **Shim behavior:** The shim performs a `y²=x³+7` check before the scalar
  multiplication. If the point is off-curve, returns 0.
- **Reason:** An invalid-curve attack using a small-order subgroup point can recover
  private key bits modulo the subgroup order. While normal use routes through
  `ec_pubkey_parse` (which validates), the C ABI struct can be written directly by
  hostile callers. The check cost is negligible vs the ECDH scalar multiplication.
- **Impact:** None for normal callers. Only affects callers who bypass `ec_pubkey_parse`.
- **Test:** `test_ecdh_pubkey_off_curve` in `audit/test_regression_shim_security_v8.cpp`.

---

### secp256k1_context_randomize — seed >= n

- **Upstream behavior:** Seeds are treated as opaque bytes for blinding; no range check.
  Upstream libsecp256k1 applies the seed directly as a blinding scalar (with mod-n reduction
  internally), so seeds >= n are accepted and result in a reduced blinding value.
- **Shim behavior:** Uses `Scalar::parse_bytes_strict_nonzero` on the seed. Seeds >= n or == 0
  disable blinding (the blinding scalar is left at its current value) rather than silently
  reducing mod-n. No conditional subtraction of n is applied to the seed.
- **Reason:** Rule 11 (CLAUDE.md) requires `parse_bytes_strict_nonzero` for any private-key
  or secret-scalar input. Seeds >= n are astronomically rare with fresh OS randomness;
  disabling blinding on such seeds is safe (the call is advisory in libsecp256k1 too — a
  failed randomization leaves the context operational, just without blinding).
- **Impact:** A caller passing a seed value in [n, 2^256) will not get a blinding scalar
  derived from that seed — blinding is left disabled. Callers using the recommended 32 bytes
  of fresh randomness from the OS are effectively never affected (probability ~2^-128).
- **Test:** `audit/test_regression_p2_ct_shim_fixes.cpp` covers the `parse_bytes_strict_nonzero`
  path in `secp256k1_context_randomize` (CT-003).

---

### secp256k1_musig_partial_sig_agg — all-zero check uses CT accumulator (SHIM-MUSIG-CT)

- **Upstream behavior:** No all-zero check — returns the aggregated value unconditionally.
- **Shim behavior:** Checks whether the 64-byte aggregated signature is all-zero (degenerate
  aggregation result) and returns 0 if so. The check uses a branchless OR-accumulator
  (`uint32_t nonzero = 0; for(i) nonzero |= sig[i]`) running all 64 bytes unconditionally.
- **Reason:** The early-exit pattern would leak information about the signature bytes via
  branch-predictor and cache timing — the loop would terminate faster when a non-zero byte
  appeared early, revealing the index of the first non-zero byte. The OR-accumulator
  eliminates this side-channel. The all-zero check itself is an additional fail-closed guard
  not present in upstream.
- **Impact:** No behavioral change for callers — the return value is the same. Timing
  behavior is now data-independent for the all-zero check.
- **Test:** `test_regression_shim_security_v7_run` (musig2 aggregate round-trips).

---

### secp256k1_ecdsa_sign / secp256k1_ecdsa_sign_recoverable / secp256k1_schnorrsig_sign_custom — custom nonce function rejected

- **Upstream behavior:** Any `noncefp` / `extraparams->noncefp` is dispatched (called with the
  message, key, and counter to produce a nonce).
- **Shim behavior:** Only the standard nonce functions are accepted (NULL, `rfc6979`, `default`
  for ECDSA; NULL, `bip340` for Schnorr). Any other non-NULL `noncefp` fires the illegal callback
  with a descriptive message before returning 0. Previously returned 0 silently (fixed 2026-05-21,
  PASS3-001).
- **Reason:** The shim uses RFC 6979 / BIP-340 nonce generation internally and cannot forward
  an arbitrary nonce function. Fail-closed so callers relying on a specific nonce function see
  an error rather than silently receiving RFC 6979 output.
- **Impact:** Callers with custom nonce functions. Bitcoin Core uses NULL (RFC 6979 default) —
  unaffected. Callers with callbacks installed now receive the callback notification.
- **Test:** `compat/libsecp256k1_shim/tests/test_shim_recovery_and_noncefp.cpp` NFP-1..3.

---

### secp256k1_nonce_function_rfc6979 / secp256k1_nonce_function_default

- **Upstream behavior:** These function pointers generate RFC 6979 nonce bytes when
  called directly.
- **Shim behavior:** Both pointers are stubs that return 0 (failure) and write nothing.
  They are exported for ABI symbol compatibility only. The shim never calls them.
- **Reason:** The shim's signing path uses its own RFC 6979 implementation. Returning 0
  from a stub that writes nothing is correct: a caller that invokes these pointers
  directly gets explicit failure rather than empty output with a success code (SC-08).
- **Impact:** Any caller using these pointers as standalone hash primitives (rare).

---

### secp256k1_nonce_function_bip340

- **Upstream behavior:** Generates BIP-340 aux-entropy-mixed nonce bytes when called.
- **Shim behavior:** Returns 0 (failure) and writes nothing. Exported for ABI compatibility.
- **Reason:** Same as rfc6979 stubs above. The shim handles BIP-340 nonce internally
  via the `aux_rand32` parameter of `secp256k1_schnorrsig_sign32`.
- **Impact:** Any caller using this pointer as a standalone hash primitive.

---

## Performance improvements (shim is faster; correctness identical to upstream)

These divergences are intentional optimizations. The observable results (pubkeys,
signatures, verification outcomes) are identical to upstream; only latency differs.

---

### secp256k1_context_preallocated_* — placement-new semantics

- **Upstream behavior:** `secp256k1_context_preallocated_size(flags)` returns a
  flags-dependent byte count. The preallocated buffer holds ALL context state
  inline; the context is entirely self-contained in that buffer.
- **Shim behavior:** `secp256k1_context_preallocated_size` always returns
  `sizeof(secp256k1_context)` regardless of flags (our context struct size is
  flags-independent). `secp256k1_context_preallocated_create` places a
  `secp256k1_context` object into the caller's buffer via placement-new.
  The struct contains non-trivially-destructible members (Point, Scalar),
  so `secp256k1_context_preallocated_destroy` calls the destructor explicitly
  but does NOT free the buffer — caller owns it. This matches upstream semantics.
- **Reason:** Our internal context state fits in a fixed-size struct. Placement-new
  is used so member initializers (Point default ctor, Scalar default ctor) run
  correctly in the caller's buffer without requiring heap allocation. Precomputed
  tables are globally shared (not per-context), so the size is flags-independent.
- **Impact:** None for correct callers. The size returned by `preallocated_size` may
  differ from upstream (upstream may include precomputed table space in certain
  configurations). Callers must use the shim's own `preallocated_size` return value,
  not a size hard-coded from upstream libsecp256k1.
- **Test:** `audit/test_regression_shim_preallocated_ctx.cpp` PAC-1..6.

---

### secp256k1_schnorrsig_verify — thread-local xonly-pubkey cache (NEW-SHIM-004)

- **Upstream behavior:** No caching. Every `secp256k1_schnorrsig_verify` call
  re-runs `lift_x` (sqrt) and rebuilds GLV precomputation tables for the supplied
  x-only pubkey.
- **Shim behavior:** A 256-slot, thread-local, FNV-1a-fingerprinted cache stores
  the lifted point + precomputed tables. Warm cache hits skip `lift_x` and the
  GLV rebuild (~1,954 ns saved per hit on the ConnectBlock workload).
- **Reason:** ConnectBlock-style hot paths (Bitcoin Core block validation) re-verify
  the same set of x-only pubkeys many times within a small window. Caching the
  lifted point is a strict perf optimisation; correctness is identical to upstream.
- **Impact / divergence shape:**
  1. **Memory:** ~256 × ~1.5 KB ≈ 384 KB of additional thread-local memory per
     thread that ever calls `secp256k1_schnorrsig_verify` in the shim.
  2. **Hash collisions are silent:** the cache uses a 32-bit FNV-1a fingerprint
     to index into 256 slots; on collision (~2^-32 per slot ≈ 0.1% per million
     unique pubkeys) the previously cached entry is overwritten without warning.
     The next verify of the evicted key re-runs `lift_x` + table build (~2 µs penalty).
     This is a perf footprint, not a correctness issue — verification is still sound.
  3. **Thread isolation:** cache is `thread_local`, so multi-threaded callers
     each pay the cold-cache cost on the first verify per thread.
  4. **msglen != 32:** for variable-length messages, the function bypasses the cache
     and calls the varlen verify overload directly — identical latency to upstream.
     The cache speedup applies to msglen == 32 only (standard BIP-340 / ConnectBlock
     use case).
- **Note on the `verify_precomp` API:** callers that need deterministic warm-cache
  behaviour (no eviction) should use `secp256k1_xonly_pubkey_parse_precomp` +
  `secp256k1_schnorrsig_verify_precomp` from `secp256k1_schnorrsig.h`, which
  exposes the prebuilt object explicitly and bypasses the global cache.
- **Test:** Planned — `audit/test_regression_shim_schnorr_cache_collision.cpp`
  will exercise the eviction-and-rebuild path: verify key A, fill the cache by
  verifying ≥256 distinct keys (forcing at least one slot collision), re-verify
  key A and assert it still returns 1. Current coverage is indirect via the
  unique-pubkey ConnectBlock workload exercised in `bench_unified` and the
  high-diversity verify path in `audit/test_exploit_schnorr_verify_*`.

---

## Capability gaps and structural divergences

These divergences reflect architectural constraints or unimplemented features.
They are not security issues; callers are affected only if they use the specific
unsupported API.

---

### secp256k1_ecdsa_sign — ndata/extra_entropy nonce divergence (SHIM-P3-006)

- **Upstream behavior:** When `ndata` is non-NULL, `secp256k1_ecdsa_sign` passes it
  to `secp256k1_nonce_function_rfc6979` as the `extra_entropy` argument. Upstream
  mixes it using the `secp256k1_rfc6979_hmac_sha256` keydata-based structure:
  `keydata = key32 || msg32 || algo16("ECDSA") || extra32` (112 bytes), which is
  hashed into the HMAC-DRBG state as a key material block.
- **Shim behavior:** When `ndata` is non-NULL, the shim calls
  `ct::ecdsa_sign_hedged(msg, key, ndata)`. Our hedged nonce uses RFC6979 Section 3.2
  with extra data in the HMAC **message** (not the key material):
  `K = HMAC(K0, V || 0x00 || x || h1 || extra)` (129 bytes). This produces valid
  signatures but different nonce values than upstream libsecp256k1 for the same inputs.
- **Reason:** The hedged signing path was designed for forward-secrecy/DPA resistance
  and uses a cryptographically equivalent (but not byte-identical) structure.
- **Impact:** Bitcoin Core's R-grinding loop (`CKey::Sign()`) calls `secp256k1_ecdsa_sign`
  with increasing `extra_entropy` counter bytes. Our shim produces **valid** signatures
  on each iteration (verify passes), but the specific `(r, s)` values differ from
  upstream. The final (low-S) signature accepted by the loop is cryptographically correct;
  only the byte representation differs. No consensus impact: script validation accepts
  any valid (r,s) that satisfies `r,s ∈ [1,n-1]` and DER encoding.
- **Fix available:** Build the shim with `-DSECP256K1_SHIM_RFC6979_COMPAT=ON` to enable
  `rfc6979_nonce_libsecp_compat`, which appends the 16-byte `ECDSA` algo16 tag and passes
  `ndata` directly — producing byte-identical nonces to upstream libsecp256k1. Trade-off:
  the hedged nonce's OS-CSPRNG fault-attack resistance is not available in compat mode.
- **Tracking:** SHIM-P3-006. Functional test:
  `audit/test_regression_shim_rgrind_functional.cpp` RGF-1..4 (valid sig across 32 iterations).
  `audit/test_regression_shim_rfc6979_compat.cpp` — rfc6979_nonce_libsecp_compat determinism
  and signing correctness.

---

### secp256k1_musig_pubkey_agg — session map cap

- **Upstream behavior:** Unlimited concurrent MuSig2 sessions; all state stored inline in opaque structs.
- **Shim behavior:** Hard cap at 1024 concurrent sessions (`kMaxKaEntries`). The 1025th
  call returns 0. (Fixed 2026-05-11: previously returned 1 even when cap was hit.)
- **Reason:** The shim uses a global `unordered_map` to associate opaque `secp256k1_musig_keyagg_cache`
  pointers with internal session state (because the opaque struct is too small for variable-length
  data). Unbounded growth is a DoS risk.
- **Impact:** Applications that open >1024 simultaneous unfinished MuSig2 sessions.
  Sessions that complete normally free their slot.
- **Leak risk:** If a caller errors out before completing a session, the map entry persists
  until the cache address is reused. Callers must ensure sessions are completed or abandoned
  cleanly. A future `secp256k1_musig_keyagg_cache_destroy` API could address this.
- **Test:** `audit/test_exploit_shim_musig_ka_cap.cpp` KAC-1..4.
  KAC-4 fills kMaxKaEntries+1 sessions and asserts at least one pubkey_agg returns 0.

---

### secp256k1_musig_session — internal raw pointer (process-local-only)

- **Upstream behavior:** `secp256k1_musig_session` is a 133-byte self-contained opaque
  struct. All data needed to reconstruct the session is encoded in those bytes. The struct
  can be copied, memcpy'd, or checkpointed safely within a process.
- **Shim behavior:** The shim's `secp256k1_musig_session` (133 bytes) stores an 8-byte
  raw pointer to the associated `secp256k1_musig_keyagg_cache` at byte offset 98.
  This pointer is written by `secp256k1_musig_session_init` and read by `partial_sig_agg`.
- **Reason:** The shim uses a global token-keyed map to associate opaque cache pointers
  with internal state. The raw pointer allows O(1) map removal in `partial_sig_agg`.
- **Impact:** **The session struct is process-local-only.**
  - Safe: `memcpy` within the same process (pointer remains valid).
  - Unsafe: serializing the session to disk/network and deserializing in a new process
    — the pointer becomes dangling. Do not checkpoint or persist sessions.
  - The pointer at offset 98–105 also leaks a heap address (ASLR bypass) in any
    inter-process context (hypothetical only — MuSig2 sessions should never cross
    process boundaries).
- **Planned fix:** Store a token/index instead of a raw pointer (v2 scope, MED-3).
- **Test:** Any attempt to serialize + deserialize a session across process restart
  will produce a dangling-pointer UB. No differential test is feasible; the divergence
  is structural.

---

### secp256k1_musig_nonce_gen — extra_input32 silently ignored (SHIM-NONCEGEN-001)

- **Upstream behavior:** `secp256k1_musig_nonce_gen` accepts an `extra_input32` parameter
  that is mixed into the nonce derivation as additional entropy (defense-in-depth).
- **Shim behavior:** The `extra_input32` parameter is accepted in the function signature but
  not forwarded to the internal `frost_sign_nonce_gen` / `musig2_nonce_gen` primitives.
  The parameter is silently ignored.
- **Reason:** The shim's internal nonce generation API does not expose an `extra_input32`
  parameter. Adding support requires a non-trivial API change to the nonce derivation path.
- **Impact:** Callers relying on `extra_input32` for additional entropy get correct nonces
  (RFC 6979 / BIP-340 hedged) but without the extra input mixed in. For production Bitcoin
  Core usage (extra_input32 = NULL or ignored), there is no difference.
- **Test:** `audit/test_regression_musig_noncegen_extra_input.cpp` — behavioral freeze test:
  verifies that `extra_input32` is silently ignored (pubnonces are identical with NULL vs non-NULL
  extra_input32, and identical for two distinct non-NULL extra_input32 values). Sub-tests NCI-1..3
  also scan `shim_musig.cpp` for the `SHIM-NONCEGEN-001` marker. The test is `advisory=true` in
  the unified runner (requires shim) and is designed to **fail** when SHIM-NONCEGEN-001 is fixed
  (diverging pubnonces = correct signal to remove the advisory flag and promote to mandatory).

---

### secp256k1_schnorrsig_verify_batch — msglen != 32 returns 0 silently (SHIM-006)

- **Upstream behavior:** `secp256k1_schnorrsig_verify_batch` in libsecp256k1 supports
  variable-length messages (`msglen` need not be 32). The BIP-340 challenge hash accepts
  any message length; batch verify is defined for arbitrary `msglen`.
- **Shim behavior:** The shim's batch verify does not implement the varlen code path — it
  only supports `msglen == 32`. When `msglen != 32`, the function returns `0` (fail-closed)
  without firing the illegal callback. Callers needing varlen must use the singular
  `secp256k1_schnorrsig_verify` which handles any `msglen` correctly.
- **Reason:** Varlen batch verify requires a generalized tagged-hash path through the MSM
  accumulator. The shim's current batch MSM uses 32-byte message slots. This is a shim
  capability limitation, not an illegal API call — firing `abort()` via the illegal callback
  for an unsupported-but-valid input was itself a divergence from upstream (corrected 2026-05-26).
- **Impact:** Callers using `msglen == 32` (standard BIP-340 use) are unaffected. Callers
  using varlen batch verify receive `0` (verification failed) instead of aborting. They
  should fall back to singular verify for varlen messages.
- **Test:** `test_shim006_verify_batch_nonstandard_msglen_returns_zero()` in
  `compat/libsecp256k1_shim/tests/test_shim_security_edge_cases.cpp` — verifies that
  `secp256k1_schnorrsig_verify_batch` with `msglen=64` returns 0 without firing the
  illegal callback.

---

### secp256k1_context_randomize — blinding is per-thread, not per-context (SHIM-THREAD-BLIND)

- **Upstream behavior:** `secp256k1_context_randomize` stores the blinding scalar inside the
  `secp256k1_context` struct. The blinding is strictly per-context: two contexts on the same
  thread each maintain independent blinding scalars. Signing with context A always uses A's
  blinding; signing with context B always uses B's blinding. Multiple threads signing
  concurrently with different contexts do not interfere with each other's blinding state
  (each context's blinding is local to that struct).
- **Shim behavior:** The shim stores the blinding scalar in a `static thread_local BlindingState
  g_blinding` variable (`src/cpu/src/ct_point.cpp:3417`). The per-context blinding seed IS
  stored in `secp256k1_context::blind[]` and `cached_r` / `cached_r_G`, but the _active_
  blinding applied during signing is a thread-local singleton — not the context's own stored
  seed. `ContextBlindingScope` (entered at sign time via `shim_context.cpp:230`) loads the
  context's cached seed into `g_blinding`, uses it for the signing operation, then clears it
  via `clear_blinding()` on scope exit.
  **Consequence:** Two contexts on the same thread used in an interleaved pattern will
  overwrite each other's active blinding. This cannot happen via the shim's synchronous API
  but could happen via callbacks or coroutines. The source contains a comment
  `// DEVIATION FROM LIBSECP CONTRACT` acknowledging this limitation.
- **Reason:** The CT blinding API (`ct::set_blinding` / `ct::clear_blinding` /
  `ct::generator_mul_blinded`) is a global singleton by design — it operates on a thread-local
  scalar pair that applies to all CT operations on that thread. Plumbing per-context blinding
  through the CT layer would require a significant internal API refactor (passing the blinding
  state through every CT call as an explicit parameter). The current design is safe for the
  dominant use pattern: one context per thread, or multiple contexts used sequentially
  (not interleaved within a single call frame).
- **Impact:**
  1. **Single-context-per-thread callers:** No divergence — identical to upstream.
  2. **Multiple-contexts-same-thread, sequential callers:** No divergence. As long as signing
     operations from different contexts do not interleave, each `ContextBlindingScope` loads
     its own context's seed and clears it correctly.
  3. **Interleaved contexts (callbacks, coroutines, C++ co_await):** Potential mismatch.
     If context A's signing path is suspended after entering its `ContextBlindingScope` and
     context B's signing is invoked on the same thread, B will overwrite `g_blinding`; when
     A resumes, it will operate under B's (or no) blinding. This scenario does not arise in
     Bitcoin Core's synchronous signing paths.
- **Tracking:** SHIM-THREAD-BLIND. The source acknowledgement `// DEVIATION FROM LIBSECP
  CONTRACT` is at `src/cpu/src/ct_point.cpp` near the `thread_local BlindingState` definition.
  This divergence is not a security vulnerability for the targeted Bitcoin Core use case
  (one-context-per-thread, synchronous signing), but is a correctness gap for advanced
  multi-context patterns.
- **Planned fix:** Refactor CT blinding to accept an explicit `BlindingState*` parameter,
  thread-local as a fallback only. Deferred — requires changes throughout the CT layer.
- **Test:** `audit/test_regression_shim_thread_blinding.cpp` (to be added) — TBL-1: sign with
  ctx_a then sign with ctx_b on same thread, both must verify. TBL-2: randomize then sign 1000
  times with alternating contexts, all must verify.
