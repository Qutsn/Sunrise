#pragma once

#include <cstdint>
#include <string_view>

namespace sunrise::client::hooks::retail_log::activity_probe {

/**
 * Observes one already-sanitized native retail-log line.
 *
 * The probe only records a structured diagnostic event; it never changes the line or any game
 * state.
 * @param siteId Native retail-log site id.
 * @param text Sanitized, bounded native line.
 */
void observe(std::int32_t siteId, std::string_view text) noexcept;

/** Clears the in-process transition context. */
void reset() noexcept;

} // namespace sunrise::client::hooks::retail_log::activity_probe
