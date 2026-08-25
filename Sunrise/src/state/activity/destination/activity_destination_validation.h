#pragma once

#include "definition.h"

namespace sunrise::state::activity::destination {

/** Bounds one destination selection. @return True when the name length fits the fixed array. */
[[nodiscard]] bool valid(const DestinationSelection& selection) noexcept;

/**
 * Replaces the source activity in a captured client descriptor without changing any other bits.
 * A selection with no captured descriptor needs no rewrite and succeeds unchanged.
 * @param selection Destination holding the descriptor and structured source field.
 * @param previousActivityIndex Server-owned logical source activity.
 * @return True when the source fits and any captured descriptor was rewritten completely.
 */
[[nodiscard]] bool rewrite_previous_activity_index(DestinationSelection& selection,
                                                   std::int16_t previousActivityIndex) noexcept;

} // namespace sunrise::state::activity::destination
