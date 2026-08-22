#include "activity_transition_probe.h"

#include <Windows.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>

#include "../../../core/logging/log.h"
#include "../../../state/activity/runtime.h"

namespace sunrise::client::hooks::retail_log::activity_probe {
namespace {

constexpr std::size_t kTokenCapacity = 48;
constexpr std::size_t kDetailCapacity = 192;

struct Context {
    bool hasCache{};
    std::uint32_t cachedDestination{};
    bool hasSelection{};
    std::uint32_t selectionToken{};
    std::uint32_t activityIndex{};
    std::uint32_t activityHash{};
    std::uint32_t selectionDestination{};
    char activityName[kTokenCapacity]{};
};

enum class EventKind : std::uint8_t {
    selection,
    cacheSet,
    cacheClear,
    transitionStart,
    transitionStop,
    stateEnter,
    stateLeave,
    prologue,
    arrival,
    clientCreate,
    clientConnect,
    clientJoin,
    clientReady,
    clientSession,
    clientSubstate,
    clientSwap,
    clientShutdown,
    clientDispose,
};

struct Event {
    EventKind kind{};
    std::uint32_t first{};
    std::uint32_t second{};
    std::int32_t signedFirst{};
    std::int32_t signedSecond{};
    char firstText[kTokenCapacity]{};
    char secondText[kTokenCapacity]{};
};

SRWLOCK g_lock{SRWLOCK_INIT};
Context g_context{};

/** @return A stable name for the current Sunrise world phase. */
[[nodiscard]] const char* phase_name(state::activity::WorldPhase phase) noexcept {
    switch (phase) {
    case state::activity::WorldPhase::idle:
        return "idle";
    case state::activity::WorldPhase::transitioning:
        return "transitioning";
    case state::activity::WorldPhase::arrived:
        return "arrived";
    }
    return "unknown";
}

/** Copies a bounded token while making it safe for key=value log fields. */
void copy_token(std::string_view source, std::span<char> output) noexcept {
    if (output.empty()) {
        return;
    }
    const std::size_t limit = output.size() - 1;
    const std::size_t count = source.size() < limit ? source.size() : limit;
    for (std::size_t index = 0; index < count; ++index) {
        const char value = source[index];
        const bool safe = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
                          || (value >= '0' && value <= '9') || value == '_' || value == '-';
        output[index] = safe ? value : '_';
    }
    output[count] = '\0';
}

/** Copies the text between two markers, or clears the output when either marker is absent. */
void copy_between(std::string_view text,
                  std::string_view begin,
                  std::string_view end,
                  std::span<char> output) noexcept {
    const std::size_t start = text.find(begin);
    if (start == std::string_view::npos) {
        if (!output.empty()) {
            output[0] = '\0';
        }
        return;
    }
    const std::size_t valueStart = start + begin.size();
    const std::size_t valueEnd = text.find(end, valueStart);
    if (valueEnd == std::string_view::npos) {
        if (!output.empty()) {
            output[0] = '\0';
        }
        return;
    }
    copy_token(text.substr(valueStart, valueEnd - valueStart), output);
}

/** Copies a bounded suffix, trimming the punctuation used by native log sentences. */
void copy_suffix(std::string_view text, std::string_view marker, std::span<char> output) noexcept {
    const std::size_t start = text.find(marker);
    if (start == std::string_view::npos) {
        if (!output.empty()) {
            output[0] = '\0';
        }
        return;
    }
    std::string_view value = text.substr(start + marker.size());
    while (!value.empty() && (value.back() == '.' || value.back() == ' ')) {
        value.remove_suffix(1);
    }
    copy_token(value, output);
}

/** Copies a token after a marker, stopping at native punctuation or whitespace. */
void copy_token_after(std::string_view text,
                      std::string_view marker,
                      std::span<char> output) noexcept {
    const std::size_t start = text.find(marker);
    if (start == std::string_view::npos) {
        if (!output.empty()) {
            output[0] = '\0';
        }
        return;
    }
    const std::size_t valueStart = start + marker.size();
    const std::size_t valueEnd = text.find_first_of("'.,;] \r\n", valueStart);
    copy_token(text.substr(valueStart,
                            valueEnd == std::string_view::npos ? std::string_view::npos
                                                               : valueEnd - valueStart),
               output);
}

/** Parses an unsigned integer immediately following a textual marker. */
[[nodiscard]] bool parse_integer(std::string_view text,
                                 std::string_view marker,
                                 int base,
                                 std::uint32_t& output) noexcept {
    const std::size_t start = text.find(marker);
    if (start == std::string_view::npos) {
        return false;
    }
    const char* first = text.data() + start + marker.size();
    const char* last = text.data() + text.size();
    const auto result = std::from_chars(first, last, output, base);
    return result.ec == std::errc{} && result.ptr != first;
}

/** Parses a signed state number from a native activity-manager sentence. */
[[nodiscard]] bool parse_signed_integer(std::string_view text,
                                        std::string_view marker,
                                        std::int32_t& output) noexcept {
    const std::size_t start = text.find(marker);
    if (start == std::string_view::npos) {
        return false;
    }
    const char* first = text.data() + start + marker.size();
    const char* last = text.data() + text.size();
    const auto result = std::from_chars(first, last, output, 10);
    return result.ec == std::errc{} && result.ptr != first;
}

/** Parses one selection line and updates the current selection snapshot. */
[[nodiscard]] bool parse_selection(std::string_view text, Event& event, Context& context) noexcept {
    if (text.find("activity_selection_manager: Launching activity-selection")
        == std::string_view::npos) {
        return false;
    }
    std::uint32_t index = 0;
    std::uint32_t activityHash = 0;
    std::uint32_t destination = 0;
    std::uint32_t token = 0;
    if (!parse_integer(text, "]: 0x", 16, index)
        || !parse_integer(text, "(HASH(0x", 16, activityHash)
        || !parse_integer(text, "destination: HASH(0x", 16, destination)
        || !parse_integer(text, "selection_token: ", 10, token)) {
        return false;
    }
    context.hasSelection = true;
    context.selectionToken = token;
    context.activityIndex = index;
    context.activityHash = activityHash;
    context.selectionDestination = destination;
    copy_between(text, "grognok: ", ")(destination: ", context.activityName);

    event = {};
    event.kind = EventKind::selection;
    return true;
}

/** Parses one in-world line and refreshes the activity fields from the arrival itself. */
[[nodiscard]] bool parse_arrival(std::string_view text, Event& event, Context& context) noexcept {
    if (text.find("state:in_world: Starting activity '") == std::string_view::npos) {
        return false;
    }
    std::uint32_t index = 0;
    std::uint32_t activityHash = 0;
    std::uint32_t destination = 0;
    if (!parse_integer(text, "activity '0x", 16, index)
        || !parse_integer(text, "(HASH(0x", 16, activityHash)
        || !parse_integer(text, "destination: HASH(0x", 16, destination)) {
        return false;
    }
    context.hasSelection = true;
    context.activityIndex = index;
    context.activityHash = activityHash;
    context.selectionDestination = destination;
    copy_between(text, "grognok: ", ")(destination: ", context.activityName);

    event = {};
    event.kind = EventKind::arrival;
    return true;
}

/** Parses a cache assignment or clear. */
[[nodiscard]] bool parse_cache(std::string_view text, Event& event, Context& context) noexcept {
    if (text.find("face_to_face_join: Clearing cached destination") != std::string_view::npos) {
        context.hasCache = false;
        context.cachedDestination = 0;
        event = {};
        event.kind = EventKind::cacheClear;
        return true;
    }
    if (text.find("face_to_face_join: Caching destination") == std::string_view::npos) {
        return false;
    }
    std::uint32_t destination = 0;
    if (!parse_integer(text, "Caching destination 'HASH(0x", 16, destination)) {
        return false;
    }
    context.hasCache = true;
    context.cachedDestination = destination;
    event = {};
    event.kind = EventKind::cacheSet;
    event.first = destination;
    return true;
}

/** Parses a transition start or stop and preserves the native reason text. */
[[nodiscard]] bool parse_transition(std::string_view text, Event& event) noexcept {
    if (text.find("slice_set_transition_manager: Starting a new transition")
        != std::string_view::npos) {
        event = {};
        event.kind = EventKind::transitionStart;
        copy_between(text, "type '", "' to", event.firstText);
        (void)parse_integer(text, "HASH: 0x", 16, event.first);
        return true;
    }
    if (text.find("slice_set_transition_manager: Stopping transition")
        != std::string_view::npos) {
        event = {};
        event.kind = EventKind::transitionStop;
        copy_between(text, "type '", "' due to", event.firstText);
        copy_suffix(text, " due to ", event.secondText);
        return true;
    }
    return false;
}

/** Parses state-manager edges. */
[[nodiscard]] bool parse_state(std::string_view text, Event& event) noexcept {
    if (text.find("state_manager: Entering state '") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::stateEnter;
        copy_between(text, "Entering state '", "' for", event.firstText);
        return true;
    }
    if (text.find("state_manager: Leaving state '") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::stateLeave;
        copy_between(text, "Leaving state '", "' for", event.firstText);
        return true;
    }
    return false;
}

/** Parses prologue-filler loading and the ActivityClient lifecycle markers. */
[[nodiscard]] bool parse_lifecycle(std::string_view text, Event& event) noexcept {
    if (text.find("prologue_intro_loading: batch requesting load") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::prologue;
        const std::size_t start = text.find("activity=");
        if (start == std::string_view::npos) {
            return false;
        }
        copy_token(text.substr(start + 9), event.firstText);
        return true;
    }
    if (text.find("activity_manager: [") != std::string_view::npos
        && text.find("] Timed sub-state changed from '") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientSubstate;
        copy_between(text, "activity_manager: [", "] Timed", event.firstText);
        std::int32_t from = 0;
        std::int32_t to = 0;
        if (!parse_signed_integer(text, "Timed sub-state changed from '", from)
            || !parse_signed_integer(text, "' to '", to)) {
            return false;
        }
        event.signedFirst = from;
        event.signedSecond = to;
        return true;
    }
    if (text.find("activity_manager: Pumping creation for '") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientCreate;
        copy_between(text, "Pumping creation for '", "' activity", event.firstText);
        return true;
    }
    if (text.find("activity_manager: '") != std::string_view::npos
        && text.find("' connecting to AH ID '") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientConnect;
        copy_between(text, "activity_manager: '", "' connecting", event.firstText);
        copy_between(text, "connecting to AH ID '", "'", event.secondText);
        return true;
    }
    if (text.find("activity_manager: '") != std::string_view::npos
        && text.find("' activity client sent join request to AH ") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientJoin;
        copy_between(text, "activity_manager: '", "' activity client", event.firstText);
        copy_token_after(text, "sent join request to AH ", event.secondText);
        return true;
    }
    if (text.find("activity client '[AC ") != std::string_view::npos
        && text.find("ready for instantiation") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientReady;
        copy_between(text, "activity client '[AC ", " CON-", event.firstText);
        copy_between(text, "AH->", " ", event.secondText);
        return true;
    }
    if (text.find("PRIVATE activity instance is ready for instantiation")
        != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientSession;
        copy_token("PRIVATE CURRENT", event.firstText);
        copy_token_after(text, "session=", event.secondText);
        return true;
    }
    if (text.find("activity_manager: '") != std::string_view::npos
        && text.find("' shutting down, waiting") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientShutdown;
        copy_between(text, "activity_manager: '", "' shutting down", event.firstText);
        return true;
    }
    if (text.find("Swapping '") != std::string_view::npos
        && text.find("' activity instances") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientSwap;
        copy_between(text, "Swapping '", "' activity", event.firstText);
        return true;
    }
    if (text.find("shut down delay complete, disposing") != std::string_view::npos) {
        event = {};
        event.kind = EventKind::clientDispose;
        copy_between(text, "activity_manager: '", "' shut down", event.firstText);
        return true;
    }
    return false;
}

/** Names one structured event. */
[[nodiscard]] const char* event_name(EventKind kind) noexcept {
    switch (kind) {
    case EventKind::selection:
        return "selection";
    case EventKind::cacheSet:
        return "cache_set";
    case EventKind::cacheClear:
        return "cache_clear";
    case EventKind::transitionStart:
        return "transition_start";
    case EventKind::transitionStop:
        return "transition_stop";
    case EventKind::stateEnter:
        return "state_enter";
    case EventKind::stateLeave:
        return "state_leave";
    case EventKind::prologue:
        return "prologue";
    case EventKind::arrival:
        return "arrival";
    case EventKind::clientCreate:
        return "client_create";
    case EventKind::clientConnect:
        return "client_connect";
    case EventKind::clientJoin:
        return "client_join";
    case EventKind::clientReady:
        return "client_ready";
    case EventKind::clientSession:
        return "client_session";
    case EventKind::clientSubstate:
        return "client_substate";
    case EventKind::clientSwap:
        return "client_swap";
    case EventKind::clientShutdown:
        return "client_shutdown";
    case EventKind::clientDispose:
        return "client_dispose";
    }
    return "unknown";
}

/** Formats one event with the context that existed at that native log line. */
[[nodiscard]] std::size_t format_event(const Event& event,
                                       std::int32_t siteId,
                                       const Context& context,
                                       std::span<char> output) noexcept {
    if (output.empty()) {
        return 0;
    }
    std::array<char, kDetailCapacity> detail{};
    int detailLength = 0;
    switch (event.kind) {
    case EventKind::selection:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "token=%u activity_index=%u activity_hash=0x%08X "
                                     "destination=0x%08X name=%s",
                                     context.selectionToken,
                                     context.activityIndex,
                                     context.activityHash,
                                     context.selectionDestination,
                                     context.activityName);
        break;
    case EventKind::cacheSet:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "destination=0x%08X",
                                     event.first);
        break;
    case EventKind::cacheClear:
        detailLength = std::snprintf(detail.data(), detail.size(), "destination=none");
        break;
    case EventKind::transitionStart:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "type=%s target=0x%08X",
                                     event.firstText,
                                     event.first);
        break;
    case EventKind::transitionStop:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "type=%s reason=%s",
                                     event.firstText,
                                     event.secondText);
        break;
    case EventKind::stateEnter:
    case EventKind::stateLeave:
        detailLength = std::snprintf(detail.data(), detail.size(), "name=%s", event.firstText);
        break;
    case EventKind::prologue:
        detailLength = std::snprintf(detail.data(), detail.size(), "activity=%s", event.firstText);
        break;
    case EventKind::arrival:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "activity_index=%u destination=0x%08X name=%s",
                                     context.activityIndex,
                                     context.selectionDestination,
                                     context.activityName);
        break;
    case EventKind::clientCreate:
    case EventKind::clientDispose:
    case EventKind::clientShutdown:
    case EventKind::clientSwap:
        detailLength = std::snprintf(detail.data(), detail.size(), "role=%s", event.firstText);
        break;
    case EventKind::clientConnect:
    case EventKind::clientJoin:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "role=%s ah=%s",
                                     event.firstText,
                                     event.secondText);
        break;
    case EventKind::clientReady:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "role=%s ah=%s",
                                     event.firstText,
                                     event.secondText);
        break;
    case EventKind::clientSession:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "role=%s session=%s",
                                     event.firstText,
                                     event.secondText);
        break;
    case EventKind::clientSubstate:
        detailLength = std::snprintf(detail.data(),
                                     detail.size(),
                                     "role=%s from=%d to=%d",
                                     event.firstText,
                                     event.signedFirst,
                                     event.signedSecond);
        break;
    }
    if (detailLength <= 0) {
        return 0;
    }
    detailLength = detailLength < static_cast<int>(detail.size())
                       ? detailLength
                       : static_cast<int>(detail.size() - 1);

    char cache[20]{};
    if (context.hasCache) {
        (void)std::snprintf(cache, sizeof(cache), "0x%08X", context.cachedDestination);
    } else {
        (void)std::snprintf(cache, sizeof(cache), "none");
    }
    const auto phase = state::activity::world_phase();
    const int written = std::snprintf(
        output.data(),
        output.size(),
        "ev=diag stage=activity_context site=%d event=%s %.*s cache=%s "
        "sel_token=%u sel_activity=%u sel_dest=0x%08X phase=%s age_ms=%llu",
        siteId,
        event_name(event.kind),
        detailLength,
        detail.data(),
        cache,
        context.hasSelection ? context.selectionToken : 0U,
        context.hasSelection ? context.activityIndex : 0U,
        context.hasSelection ? context.selectionDestination : 0U,
        phase_name(phase),
        static_cast<unsigned long long>(state::activity::world_transition_age()));
    if (written <= 0) {
        return 0;
    }
    return static_cast<std::size_t>(written) < output.size()
               ? static_cast<std::size_t>(written)
               : output.size() - 1;
}

/** Tries the parsers in the order of the most specific lifecycle markers. */
[[nodiscard]] bool parse(std::string_view text, Event& event, Context& context) noexcept {
    return parse_selection(text, event, context) || parse_arrival(text, event, context)
           || parse_cache(text, event, context) || parse_transition(text, event)
           || parse_lifecycle(text, event) || parse_state(text, event);
}

} // namespace

void observe(std::int32_t siteId, std::string_view text) noexcept {
    if (!core::log::accepts(core::log::Channel::client, core::log::Level::debug)) {
        return;
    }
    Event event{};
    std::array<char, core::log::kLineCapacity> line{};
    std::size_t length = 0;
    AcquireSRWLockExclusive(&g_lock);
    if (parse(text, event, g_context)) {
        length = format_event(event, siteId, g_context, line);
    }
    ReleaseSRWLockExclusive(&g_lock);
    if (length != 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), length});
    }
}

void reset() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    g_context = {};
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace sunrise::client::hooks::retail_log::activity_probe
