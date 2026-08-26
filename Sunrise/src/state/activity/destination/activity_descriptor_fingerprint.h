#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sunrise::state::activity::destination {

/**
 * Computes a non-reversible identity for a captured selection descriptor.
 * The bit length is included so equal byte prefixes with different meaningful tails remain
 * distinguishable in diagnostics.
 * @param bits Left-aligned descriptor bytes.
 * @param bitLength Number of meaningful bits in bits.
 * @param omitSource Clear the leading twelve-bit source activity before hashing.
 * @return Stable 32-bit fingerprint, or zero when the descriptor bounds are invalid.
 */
[[nodiscard]] inline std::uint32_t descriptor_fingerprint(
    std::span<const std::byte> bits, std::size_t bitLength, bool omitSource = false) noexcept {
    constexpr std::uint32_t kOffsetBasis = 2166136261U;
    constexpr std::uint32_t kPrime = 16777619U;
    constexpr std::size_t kBitsPerByte = 8;
    if (bitLength == 0) {
        return 0;
    }
    const std::size_t byteLength = (bitLength - 1) / kBitsPerByte + 1;
    if (byteLength > bits.size()) {
        return 0;
    }
    std::uint32_t hash = kOffsetBasis;
    for (std::size_t index = 0; index < byteLength; ++index) {
        std::uint8_t value = static_cast<std::uint8_t>(bits[index]);
        // The MSB-first descriptor starts with a four-bit reason and a twelve-bit source. Keep the
        // reason nibble and clear the source bytes so A/B logs can distinguish source-only changes
        // from changes in the opaque destination descriptor without retaining any game payload.
        if (omitSource) {
            if (index == 0) {
                value = static_cast<std::uint8_t>(value & 0xF0U);
            } else if (index == 1) {
                value = 0;
            }
        }
        // Ignore padding bits in the final byte; they are outside the captured descriptor and may
        // contain unrelated data in the request buffer.
        const std::size_t remainder = bitLength % kBitsPerByte;
        if (index + 1 == byteLength && remainder != 0) {
            value = static_cast<std::uint8_t>(value & (0xFFU << (kBitsPerByte - remainder)));
        }
        hash ^= value;
        hash *= kPrime;
    }
    for (std::size_t shift = 0; shift < sizeof(bitLength); ++shift) {
        hash ^= static_cast<std::uint8_t>(bitLength >> (shift * 8));
        hash *= kPrime;
    }
    return hash;
}

} // namespace sunrise::state::activity::destination
