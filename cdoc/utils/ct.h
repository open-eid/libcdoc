/*
 * libcdoc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <cstddef>
#include <cstdint>

// Branch-free, data-independent helpers used by the constant-time PKCS#1 v1.5
// unpadding implementation.
//
// The compiler is allowed - in principle - to "optimise" any of these into
// branches; in practice, on GCC/Clang/MSVC at any reasonable optimisation
// level, none of them produce conditional jumps because the inputs are
// integer expressions without short-circuit operators. We rely on this
// observation, periodically verify it via dudect-style timing tests, and
// avoid further hardening (assembly, OPENSSL_cleanse-style barriers) to keep
// the code portable across the platforms libcdoc targets.

namespace libcdoc::ct {

// Returns 0xFF when a == b, otherwise 0x00. Branch-free for 8-bit inputs.
constexpr uint8_t eq8(uint8_t a, uint8_t b) noexcept {
    // x is 0 iff a == b; otherwise 1..255. Subtracting 1 underflows to a
    // very large value when x == 0, so the high byte of (x - 1) is 0xFF
    // exactly when a == b.
    uint16_t x = uint16_t(a ^ b);
    return uint8_t(((uint32_t(x) - 1u) >> 8) & 0xFFu);
}

// Returns 0xFF when a >= b, otherwise 0x00. Branch-free for size_t inputs.
constexpr uint8_t ge_size(size_t a, size_t b) noexcept {
    // (b - a - 1) wraps to a huge value when a >= b, putting 1 in the top bit
    constexpr size_t shift = sizeof(size_t) * 8u - 1u;
    size_t top_bit = (b - a - 1u) >> shift;     // 1 if a < b, 0 if a >= b
    return uint8_t(top_bit * 0xFFu);
}

// Returns 0xFF when a == b, otherwise 0x00 (32-bit operands).
constexpr uint8_t eq32(uint32_t a, uint32_t b) noexcept {
    uint32_t x = a ^ b;
    // (x - 1) >> 31 is 1 iff x == 0
    return uint8_t(((x - 1u) >> 31) & 1u) * 0xFFu;
}

// Constant-time conditional-copy: out[i] = mask ? a[i] : b[i] for n bytes.
// `mask` must be 0x00 or 0xFF.
inline void cmov(uint8_t *out, const uint8_t *a, const uint8_t *b,
                 size_t n, uint8_t mask) noexcept {
    const uint8_t inv = uint8_t(~mask);
    for (size_t i = 0; i < n; ++i) {
        out[i] = uint8_t((a[i] & mask) | (b[i] & inv));
    }
}

} // namespace libcdoc::ct
