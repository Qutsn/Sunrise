#include "activity_destination_validation.h"

#include <climits>

#include "../../../middleware/encoding/bit_reader.h"
#include "../../../middleware/encoding/bit_writer.h"

namespace sunrise::state::activity::destination {
namespace {

/** Selection reason precedes the source index in a captured descriptor. */
constexpr std::uint8_t kReasonWidth = 4;
/** Source activity indices use 12 bits and bias 1. */
constexpr std::uint8_t kActivityIndexWidth = 12;
/** The bit writer accepts at most 64 bits in one field. */
constexpr std::uint8_t kMaximumCopyWidth = 64;

} // namespace

/** Bounds one destination selection against its fixed package-name storage. */
bool valid(const DestinationSelection& selection) noexcept {
    return selection.packageNameLength <= selection.packageName.size();
}

/** Replaces only the source-activity field in a captured descriptor. */
bool rewrite_previous_activity_index(DestinationSelection& selection,
                                     std::int16_t previousActivityIndex) noexcept {
    if (previousActivityIndex < kAbsentActivityIndex
        || previousActivityIndex > kMaximumActivityIndex) {
        return false;
    }
    if (selection.descriptorBitLength == 0) {
        selection.previousActivityIndex = previousActivityIndex;
        return true;
    }
    constexpr std::size_t prefixBits = kReasonWidth + kActivityIndexWidth;
    if (selection.descriptorBitLength < prefixBits
        || selection.descriptorBitLength > selection.descriptorBits.size() * CHAR_BIT) {
        return false;
    }

    std::array<std::byte, kDescriptorCapacity> rewritten{};
    middleware::encoding::bits::Reader reader(selection.descriptorBits);
    middleware::encoding::bits::Writer writer(rewritten);
    std::uint64_t reason = 0;
    std::uint64_t discardedSource = 0;
    if (!reader.read(kReasonWidth, reason) || !reader.read(kActivityIndexWidth, discardedSource)
        || !writer.write(reason, kReasonWidth)
        || !writer.write(static_cast<std::uint16_t>(previousActivityIndex + 1),
                         kActivityIndexWidth)) {
        return false;
    }

    std::size_t remaining = selection.descriptorBitLength - prefixBits;
    while (remaining != 0) {
        const auto width = static_cast<std::uint8_t>(
            remaining > kMaximumCopyWidth ? kMaximumCopyWidth : remaining);
        std::uint64_t value = 0;
        if (!reader.read(width, value) || !writer.write(value, width)) {
            return false;
        }
        remaining -= width;
    }
    std::size_t written = 0;
    if (!writer.finish(written)
        || written != (selection.descriptorBitLength + CHAR_BIT - 1) / CHAR_BIT) {
        return false;
    }

    selection.descriptorBits = rewritten;
    selection.previousActivityIndex = previousActivityIndex;
    return true;
}

} // namespace sunrise::state::activity::destination
