#pragma once

#include <cstddef>
#include <cstdint>

namespace sunrise::client::hooks::retail_log::activity_egress_probe {

/**
 * Arms one bounded BAP-egress observation window for a native activity selection.
 *
 * The probe records only sizes and executable-relative call sites. It does not read or retain
 * packet contents and does not change the selected activity.
 * @param selectionToken Native selection generation.
 * @param activityIndex Selected activity index.
 * @param destination Selected destination hash.
 * @param hasCache Whether the native face-to-face cache still names the old destination.
 * @param cachedDestination Old cached destination, when present.
 */
void arm(std::uint32_t selectionToken,
         std::uint32_t activityIndex,
         std::uint32_t destination,
         bool hasCache,
         std::uint32_t cachedDestination) noexcept;

/**
 * Records one send to the configured BAP peer while an observation window is active.
 * @param api Stable Winsock entry-point name.
 * @param socketValue Process-local socket value used only to distinguish concurrent BAP links.
 * @param bytes Total bytes submitted by this call, or zero when the caller buffers were invalid.
 * @param bufferCount Number of submitted buffers.
 */
void observe(const char* api,
             std::uintptr_t socketValue,
             std::size_t bytes,
             std::uint32_t bufferCount) noexcept;

/** @return True while a bounded selection observation window can still accept records. */
[[nodiscard]] bool active() noexcept;

/** Clears the current observation window and counters. */
void reset() noexcept;

} // namespace sunrise::client::hooks::retail_log::activity_egress_probe
