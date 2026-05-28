// ============================================================================
// shim_pubkey_helpers.hpp — Shared inline helpers for shim_*.cpp files
// ============================================================================
// `#pragma once` ensures Unity build compiles each helper exactly once even
// when all shim_*.cpp files are merged into a single translation unit.
// All functions are `inline` in the secp256k1_shim_internal namespace to avoid
// duplicate-symbol errors when multiple shim files are compiled together.
// ============================================================================
#pragma once
#include <array>
#include <cstring>
#include "secp256k1/field.hpp"
#include "secp256k1/point.hpp"

namespace secp256k1_shim_internal {

using secp256k1::fast::Point;
using secp256k1::fast::FieldElement;

// Write X[0..31] || Y[32..63] from a Point into a 64-byte opaque buffer.
// Fast path (Z=1): extract X and Y field elements directly — no allocation.
// Fallback (Jacobian): copy the point and normalize (one field inversion) then
// extract, avoiding the 65-byte to_uncompressed() heap allocation + memcpy.
inline void point_to_pubkey_data(const Point& pt, unsigned char data[64]) noexcept {
    if (pt.is_normalized()) {
        pt.x_raw().to_bytes_into(reinterpret_cast<uint8_t*>(data));
        pt.y_raw().to_bytes_into(reinterpret_cast<uint8_t*>(data) + 32);
    } else {
        Point n = pt;
        n.normalize();
        n.x_raw().to_bytes_into(reinterpret_cast<uint8_t*>(data));
        n.y_raw().to_bytes_into(reinterpret_cast<uint8_t*>(data) + 32);
    }
}

// Reconstruct a Point from a 64-byte opaque pubkey buffer (X || Y).
// Trust contract (matches libsecp256k1): secp256k1_pubkey is populated only
// by secp256k1_ec_pubkey_parse / secp256k1_ec_pubkey_create, both of which
// validate y²=x³+7. We do NOT re-check curve membership here — the parse
// already did it. A caller writing arbitrary bytes into the struct violates
// the API contract; behaviour is undefined (same as libsecp256k1).
// PERF-003: uses reinterpret_cast to avoid 64-byte stack copy overhead.
[[nodiscard]] inline Point pubkey_data_to_point(const unsigned char data[64]) noexcept {
    const auto& xb = *reinterpret_cast<const std::array<uint8_t, 32>*>(data);
    const auto& yb = *reinterpret_cast<const std::array<uint8_t, 32>*>(data + 32);
    auto x = FieldElement::from_bytes(xb);
    auto y = FieldElement::from_bytes(yb);
    return Point::from_affine(x, y);
}

} // namespace secp256k1_shim_internal
