/**
 * ufsecp_libbitcoin.cpp — implementation of the libbitcoin acceleration bridge.
 *
 * The controller is dispatch + marshalling only. It owns a CPU context (always)
 * and, when built with GPU support and a device is available, a GPU context.
 * It reuses the engine's existing, tested public primitives:
 *
 *   CPU:  ufsecp_ecdsa_batch_verify / ufsecp_schnorr_batch_verify
 *           (packed records — exactly the row layout this bridge documents)
 *   GPU:  ufsecp_gpu_ecdsa_verify_batch / ufsecp_gpu_schnorr_verify_batch
 *           (per-item results — one signature per thread)
 *   SP :  ufsecp_gpu_bip352_scan_batch
 *
 * GPU dispatch is compile-time optional: define UFSECP_LBTC_WITH_GPU to link the
 * engine GPU ABI. Without it the bridge is a CPU-only build (the consensus
 * reference path) that links a CPU-only engine library. The C ABI is identical
 * in both configurations.
 *
 * Per-row semantics: every row gets a 1/0 result. A structurally-malformed
 * record (off-curve pubkey, s>=n, R.x>=p) is reported as invalid (0); it never
 * aborts the batch. This is obtained on CPU by interpreting the return code of a
 * single-entry verify, and on GPU by the kernel's per-item out_results.
 *
 * Mandatory CPU fallback: if a GPU chunk fails at the device level, that chunk
 * is transparently re-run on the CPU. The CPU path is the consensus reference.
 */
#include "ufsecp_libbitcoin.h"

#include "ufsecp.h"     /* ufsecp_ctx, ufsecp_ctx_create/destroy,
                           ufsecp_ecdsa_batch_verify, ufsecp_schnorr_batch_verify */
#ifdef UFSECP_LBTC_WITH_GPU
#include "ufsecp_gpu.h" /* GPU C ABI + UFSECP_GPU_BACKEND_*, UFSECP_ERR_GPU_* */
#endif

#include <cstring>
#include <new>
#include <vector>

/* UFSECP_ERR_GPU_UNAVAILABLE lives in ufsecp_gpu.h; provide it for CPU-only builds. */
#ifndef UFSECP_ERR_GPU_UNAVAILABLE
#define UFSECP_ERR_GPU_UNAVAILABLE 100
#endif

/* ------------------------------------------------------------------------- */
/* Controller state                                                           */
/* ------------------------------------------------------------------------- */

struct ufsecp_lbtc_ctrl {
    ufsecp_ctx*       cpu  = nullptr;                 /* always present        */
#ifdef UFSECP_LBTC_WITH_GPU
    ufsecp_gpu_ctx*   gpu  = nullptr;                 /* null when CPU-bound   */
#endif
    ufsecp_lbtc_bound bound = UFSECP_LBTC_BOUND_CPU;
    char              device_name[128] = {'C', 'P', 'U', '\0'};
};

namespace {

/* Per-call chunk size. Well below kMaxGpuBatchN (64 M) and any CPU limit, large
 * enough to amortize device transfer for IBD-scale batches. Tunable. */
constexpr std::size_t kChunk = std::size_t{1} << 18; /* 262144 */

enum class Kind { Ecdsa, Schnorr };

inline std::size_t record_size(Kind k) {
    return k == Kind::Ecdsa ? UFSECP_LBTC_ECDSA_RECORD : UFSECP_LBTC_SCHNORR_RECORD;
}

inline ufsecp_error_t cpu_verify_one(ufsecp_ctx* ctx, Kind k, const uint8_t* rec) {
    /* For n == 1 the packed verify reads exactly record_size() bytes, so the
     * row's opaque key tail (if any) is never touched. */
    return k == Kind::Ecdsa ? ufsecp_ecdsa_batch_verify(ctx, rec, 1)
                            : ufsecp_schnorr_batch_verify(ctx, rec, 1);
}

inline ufsecp_error_t cpu_verify_run(ufsecp_ctx* ctx, Kind k,
                                     const uint8_t* recs, std::size_t cnt) {
    return k == Kind::Ecdsa ? ufsecp_ecdsa_batch_verify(ctx, recs, cnt)
                            : ufsecp_schnorr_batch_verify(ctx, recs, cnt);
}

/* Accumulates per-row results + the compact invalid-index list. */
struct Sink {
    uint8_t* results;
    std::size_t* invalid_idx;
    std::size_t  invalid_cap;
    std::size_t  total_invalid;

    inline void mark(std::size_t global, bool valid) {
        if (results) results[global] = valid ? 1u : 0u;
        if (!valid) {
            if (invalid_idx && total_invalid < invalid_cap)
                invalid_idx[total_invalid] = global;
            ++total_invalid;
        }
    }
    inline void mark_all_valid(std::size_t base, std::size_t cnt) {
        if (results) std::memset(results + base, 1, cnt);
    }
};

/* CPU path for one chunk [base, base+cnt). Never aborts: malformed → invalid. */
void cpu_chunk(ufsecp_ctx* ctx, Kind k, const uint8_t* rows,
               std::size_t base, std::size_t cnt, std::size_t stride,
               Sink& sink) {
    const std::size_t rec = record_size(k);
    /* Fast all-valid path is only directly applicable when rows are contiguous
     * records (no opaque key column splitting the stride). */
    if (stride == rec) {
        if (cpu_verify_run(ctx, k, rows + base * stride, cnt) == UFSECP_OK) {
            sink.mark_all_valid(base, cnt);
            return;
        }
    }
    for (std::size_t i = 0; i < cnt; ++i) {
        const uint8_t* recp = rows + (base + i) * stride;
        sink.mark(base + i, cpu_verify_one(ctx, k, recp) == UFSECP_OK);
    }
}

#ifdef UFSECP_LBTC_WITH_GPU
/* GPU path for one chunk. Returns false on device-level failure (caller then
 * falls back to CPU for this chunk). Per-row validity comes from out_results. */
bool gpu_chunk(ufsecp_gpu_ctx* gpu, Kind k, const uint8_t* rows,
               std::size_t base, std::size_t cnt, std::size_t stride,
               Sink& sink) {
    std::vector<uint8_t> msg(cnt * 32), sig(cnt * 64), res(cnt);
    std::vector<uint8_t> pub(cnt * (k == Kind::Ecdsa ? 33u : 32u));

    for (std::size_t i = 0; i < cnt; ++i) {
        const uint8_t* r = rows + (base + i) * stride;
        if (k == Kind::Ecdsa) {
            /* record: 32 msg | 33 pubkey | 64 sig */
            std::memcpy(msg.data() + i * 32, r, 32);
            std::memcpy(pub.data() + i * 33, r + 32, 33);
            std::memcpy(sig.data() + i * 64, r + 65, 64);
        } else {
            /* record: 32 xonly | 32 msg | 64 sig */
            std::memcpy(pub.data() + i * 32, r, 32);
            std::memcpy(msg.data() + i * 32, r + 32, 32);
            std::memcpy(sig.data() + i * 64, r + 64, 64);
        }
    }

    const ufsecp_error_t rc =
        k == Kind::Ecdsa
            ? ufsecp_gpu_ecdsa_verify_batch(gpu, msg.data(), pub.data(),
                                            sig.data(), cnt, res.data())
            : ufsecp_gpu_schnorr_verify_batch(gpu, msg.data(), pub.data(),
                                              sig.data(), cnt, res.data());
    if (rc != UFSECP_OK) return false; /* fall back to CPU */

    for (std::size_t i = 0; i < cnt; ++i)
        sink.mark(base + i, res[i] != 0);
    return true;
}
#endif /* UFSECP_LBTC_WITH_GPU */

ufsecp_error_t verify_impl(ufsecp_lbtc_ctrl* ctrl, Kind k,
                           const uint8_t* rows, std::size_t n, std::size_t key_size,
                           uint8_t* results,
                           std::size_t* invalid_idx, std::size_t invalid_cap,
                           std::size_t* invalid_count) {
    if (!ctrl) return UFSECP_ERR_NULL_ARG;
    if (invalid_count) *invalid_count = 0;
    if (n == 0) return UFSECP_OK; /* empty batch is vacuously valid */
    if (!rows) return UFSECP_ERR_NULL_ARG;

    const std::size_t stride = record_size(k) + key_size;
    Sink sink{results, invalid_idx, invalid_cap, 0};

    for (std::size_t base = 0; base < n; base += kChunk) {
        const std::size_t cnt = (n - base) < kChunk ? (n - base) : kChunk;
#ifdef UFSECP_LBTC_WITH_GPU
        if (ctrl->gpu) {
            if (gpu_chunk(ctrl->gpu, k, rows, base, cnt, stride, sink)) continue;
            /* device-level failure → mandatory CPU fallback for this chunk */
        }
#endif
        cpu_chunk(ctrl->cpu, k, rows, base, cnt, stride, sink);
    }

    if (invalid_count) *invalid_count = sink.total_invalid;
    return UFSECP_OK;
}

} // namespace

/* ------------------------------------------------------------------------- */
/* Public API                                                                 */
/* ------------------------------------------------------------------------- */

extern "C" {

ufsecp_error_t ufsecp_lbtc_ctrl_create(ufsecp_lbtc_ctrl** out,
                                       ufsecp_lbtc_backend backend) {
    if (!out) return UFSECP_ERR_NULL_ARG;
    *out = nullptr;

    auto* c = new (std::nothrow) ufsecp_lbtc_ctrl{};
    if (!c) return UFSECP_ERR_INTERNAL;

    if (ufsecp_ctx_create(&c->cpu) != UFSECP_OK || !c->cpu) {
        delete c;
        return UFSECP_ERR_INTERNAL;
    }

#ifdef UFSECP_LBTC_WITH_GPU
    if (backend != UFSECP_LBTC_CPU) {
        const uint32_t order[3] = {UFSECP_GPU_BACKEND_CUDA,
                                   UFSECP_GPU_BACKEND_OPENCL,
                                   UFSECP_GPU_BACKEND_METAL};
        for (uint32_t b : order) {
            if (!ufsecp_gpu_is_available(b)) continue;
            if (ufsecp_gpu_ctx_create(&c->gpu, b, 0) == UFSECP_OK &&
                ufsecp_gpu_is_ready(c->gpu)) {
                c->bound = (b == UFSECP_GPU_BACKEND_CUDA)   ? UFSECP_LBTC_BOUND_CUDA
                         : (b == UFSECP_GPU_BACKEND_OPENCL) ? UFSECP_LBTC_BOUND_OPENCL
                                                            : UFSECP_LBTC_BOUND_METAL;
                ufsecp_gpu_device_info_t info;
                if (ufsecp_gpu_device_info(b, 0, &info) == UFSECP_OK) {
                    std::strncpy(c->device_name, info.name,
                                 sizeof(c->device_name) - 1);
                    c->device_name[sizeof(c->device_name) - 1] = '\0';
                }
                break;
            }
            if (c->gpu) {
                ufsecp_gpu_ctx_destroy(c->gpu);
                c->gpu = nullptr;
            }
        }
        if (!c->gpu && backend == UFSECP_LBTC_GPU) {
            ufsecp_ctx_destroy(c->cpu);
            delete c;
            return UFSECP_ERR_GPU_UNAVAILABLE;
        }
    }
#else
    if (backend == UFSECP_LBTC_GPU) { /* GPU support not compiled in */
        ufsecp_ctx_destroy(c->cpu);
        delete c;
        return UFSECP_ERR_GPU_UNAVAILABLE;
    }
#endif

    *out = c;
    return UFSECP_OK;
}

void ufsecp_lbtc_ctrl_destroy(ufsecp_lbtc_ctrl* ctrl) {
    if (!ctrl) return;
#ifdef UFSECP_LBTC_WITH_GPU
    if (ctrl->gpu) ufsecp_gpu_ctx_destroy(ctrl->gpu);
#endif
    if (ctrl->cpu) ufsecp_ctx_destroy(ctrl->cpu);
    delete ctrl;
}

ufsecp_lbtc_bound ufsecp_lbtc_ctrl_backend(const ufsecp_lbtc_ctrl* ctrl) {
    return ctrl ? ctrl->bound : UFSECP_LBTC_BOUND_CPU;
}

const char* ufsecp_lbtc_ctrl_device_name(const ufsecp_lbtc_ctrl* ctrl) {
    return ctrl ? ctrl->device_name : "";
}

ufsecp_error_t ufsecp_lbtc_verify_ecdsa(ufsecp_lbtc_ctrl* ctrl,
                                        const uint8_t* rows, size_t n,
                                        size_t key_size, uint8_t* results,
                                        size_t* invalid_idx, size_t invalid_cap,
                                        size_t* invalid_count) {
    return verify_impl(ctrl, Kind::Ecdsa, rows, n, key_size, results,
                       invalid_idx, invalid_cap, invalid_count);
}

ufsecp_error_t ufsecp_lbtc_verify_schnorr(ufsecp_lbtc_ctrl* ctrl,
                                          const uint8_t* rows, size_t n,
                                          size_t key_size, uint8_t* results,
                                          size_t* invalid_idx, size_t invalid_cap,
                                          size_t* invalid_count) {
    return verify_impl(ctrl, Kind::Schnorr, rows, n, key_size, results,
                       invalid_idx, invalid_cap, invalid_count);
}

ufsecp_error_t ufsecp_lbtc_sp_scan(ufsecp_lbtc_ctrl* ctrl,
                                   const uint8_t scan_privkey32[32],
                                   const uint8_t spend_pubkey33[33],
                                   const uint8_t* tweak_pubkeys33, size_t n,
                                   uint64_t* prefix64_out) {
    if (!ctrl) return UFSECP_ERR_NULL_ARG;
    if (n == 0) return UFSECP_OK;
    if (!scan_privkey32 || !spend_pubkey33 || !tweak_pubkeys33 || !prefix64_out)
        return UFSECP_ERR_NULL_ARG;

#ifdef UFSECP_LBTC_WITH_GPU
    /* v1: SP scan is GPU-only (CUDA/OpenCL). CPU SP-scan fallback is a follow-up. */
    if (!ctrl->gpu) return UFSECP_ERR_GPU_UNAVAILABLE;

    for (size_t base = 0; base < n; base += kChunk) {
        const size_t cnt = (n - base) < kChunk ? (n - base) : kChunk;
        const ufsecp_error_t rc = ufsecp_gpu_bip352_scan_batch(
            ctrl->gpu, scan_privkey32, spend_pubkey33,
            tweak_pubkeys33 + base * 33, cnt, prefix64_out + base);
        if (rc != UFSECP_OK) return rc;
    }
    return UFSECP_OK;
#else
    (void)spend_pubkey33; (void)tweak_pubkeys33; (void)prefix64_out;
    return UFSECP_ERR_GPU_UNAVAILABLE; /* GPU support not compiled in */
#endif
}

} // extern "C"
