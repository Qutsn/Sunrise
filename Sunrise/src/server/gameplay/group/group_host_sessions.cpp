#include "group_host_sessions.h"

#include <Windows.h>

#include <array>
#include <limits>

#include "../../../state/activity/runtime.h"
#include "../gameplay_log.h"

namespace sunrise::server::gameplay::group {

namespace {

/** One source-bound activity-host row owned by the fixed table. */
struct HostSession {
    HostSessionBinding binding{};
    HostSessionState state{HostSessionState::absent};
    std::uint64_t lastUse{};
    std::uint32_t references{};
    bool occupied{};
};

/** Regions that may hold an activity-host session at once. */
constexpr std::size_t kHostSessionCapacity = 8;
/** Guards host rows and their deferred-retirement queue. Never held across a State call. */
SRWLOCK g_hostSessionLock{SRWLOCK_INIT};
std::array<HostSession, kHostSessionCapacity> g_hostSessions{};
std::array<HostSessionBinding, kHostSessionCapacity> g_retired{};
std::size_t g_retiredCount = 0;
std::uint64_t g_useStamp = 0;
std::uint64_t g_generation = 0;

/** Copies the deferred-retirement count without exposing the host lock to callers. */
[[nodiscard]] std::size_t retired_count_snapshot() noexcept {
    AcquireSRWLockShared(&g_hostSessionLock);
    const std::size_t count = g_retiredCount;
    ReleaseSRWLockShared(&g_hostSessionLock);
    return count;
}

/** @return A stable name for one host-row lifecycle state. */
[[nodiscard]] const char* state_name(HostSessionState state) noexcept {
    switch (state) {
    case HostSessionState::absent:
        return "absent";
    case HostSessionState::pending:
        return "pending";
    case HostSessionState::ready:
        return "ready";
    case HostSessionState::conflict:
        return "conflict";
    case HostSessionState::full:
        return "full";
    }
    return "unknown";
}

/** Writes one bounded snapshot of a host row and both State bindings. */
void report_row(core::log::Level level,
                const char* event,
                const char* result,
                const HostSessionBinding& binding,
                HostSessionState state,
                std::uint32_t references,
                std::size_t retiredCount,
                const char* reason = "none") noexcept {
    report(level,
           "ev=gameplay stage=activityhost event=%s result=%s reason=%s "
           "group=0x%016llX generation=%llu state=%s refs=%u region=%d "
           "source=0x%016llX/%llu target=0x%016llX/%llu retired=%zu",
           event,
           result,
           reason,
           static_cast<unsigned long long>(binding.groupSessionId),
           static_cast<unsigned long long>(binding.generation),
           state_name(state),
           static_cast<unsigned>(references),
           binding.regionIndex,
           static_cast<unsigned long long>(binding.source.sessionId),
           static_cast<unsigned long long>(binding.source.createdRevision),
           static_cast<unsigned long long>(binding.target.sessionId),
           static_cast<unsigned long long>(binding.target.createdRevision),
           retiredCount);
}

/** @return True when two bindings name the same immutable State record generation. */
[[nodiscard]] bool same_generation(const state::activity::SessionBinding& left,
                                   const state::activity::SessionBinding& right) noexcept {
    return left.sessionId == right.sessionId && left.createdRevision == right.createdRevision;
}

/** @return Next nonzero row generation, or zero after monotonic generation exhaustion. */
[[nodiscard]] std::uint64_t next_generation_locked() noexcept {
    if (g_generation == (std::numeric_limits<std::uint64_t>::max)()) {
        return 0;
    }
    ++g_generation;
    return g_generation;
}

/** Moves one unreferenced occupied row to deferred retirement. The caller holds the lock. */
[[nodiscard]] bool retire_locked(HostSession& row) noexcept {
    if (!row.occupied) {
        return true;
    }
    if (row.references != 0 || g_retiredCount == g_retired.size()) {
        return false;
    }
    g_retired[g_retiredCount] = row.binding;
    ++g_retiredCount;
    row = {};
    return true;
}

/** Releases both State retains and the allocated target of one retired row. */
void release_retired(const HostSessionBinding& binding) noexcept {
    report_row(core::log::Level::debug,
               "retire_release",
               "begin",
               binding,
               HostSessionState::absent,
               0,
               0);
    if (binding.target.sessionId != state::activity::kAbsentSessionId) {
        state::activity::release_binding(binding.target);
        const bool released = state::activity::release_session(binding.target.sessionId);
        report(core::log::Level::info,
               "ev=gameplay stage=activityhost result=retired session=0x%llX generation=%llu "
               "state=%s",
               static_cast<unsigned long long>(binding.target.sessionId),
               static_cast<unsigned long long>(binding.generation),
               released ? "freed" : "retained");
        report_row(core::log::Level::debug,
                   "retire_release",
                   released ? "target_freed" : "target_retained",
                   binding,
                   HostSessionState::absent,
                   0,
                   0);
    }
    state::activity::release_binding(binding.source);
}

/** Releases every deferred row. Callers hold no lock. */
void free_retired_host_sessions() noexcept {
    std::array<HostSessionBinding, kHostSessionCapacity> retired{};
    std::size_t count = 0;
    AcquireSRWLockExclusive(&g_hostSessionLock);
    retired = g_retired;
    count = g_retiredCount;
    g_retired = {};
    g_retiredCount = 0;
    ReleaseSRWLockExclusive(&g_hostSessionLock);
    if (count != 0) {
        report(core::log::Level::debug,
               "ev=gameplay stage=activityhost event=retire_drain result=begin count=%zu",
               count);
    }
    for (std::size_t index = 0; index < count; ++index) {
        release_retired(retired[index]);
    }
}

/** Copies one ready row selected by a predicate, then validates both retained State bindings. */
template <typename Predicate>
[[nodiscard]] bool find_ready(Predicate predicate, HostSessionBinding& output) noexcept {
    output = {};
    AcquireSRWLockShared(&g_hostSessionLock);
    for (const HostSession& row : g_hostSessions) {
        if (row.occupied && row.state == HostSessionState::ready && predicate(row.binding)) {
            output = row.binding;
            break;
        }
    }
    ReleaseSRWLockShared(&g_hostSessionLock);
    bool sourceMatches = false;
    bool targetMatches = false;
    bool valid = output.generation != 0;
    if (valid) {
        sourceMatches = state::activity::binding_matches(output.source);
        if (sourceMatches) {
            targetMatches = state::activity::binding_matches(output.target);
        }
        valid = sourceMatches && targetMatches;
    }
    if (!valid) {
        report_row(core::log::Level::debug,
                   "lookup",
                   "stale",
                   output,
                   HostSessionState::ready,
                   0,
                   0,
                   output.generation == 0 ? "generation" : !sourceMatches ? "source" : "target");
        output = {};
        return false;
    }
    return true;
}

} // namespace

/** Claims or finds one source-bound activity-host row. */
HostSessionState request_host_session(std::uint64_t groupSessionId,
                                      const state::activity::SessionBinding& source,
                                      std::int32_t regionIndex,
                                      HostSessionBinding& output) noexcept {
    output = {};
    const bool validInput = groupSessionId != 0 && regionIndex >= 0;
    const bool sourceRetained = validInput && state::activity::retain_binding(source);
    if (!sourceRetained) {
        HostSessionBinding requested{};
        requested.groupSessionId = groupSessionId;
        requested.regionIndex = regionIndex;
        requested.source = source;
        report_row(core::log::Level::debug,
                   "request",
                   "absent",
                   requested,
                   HostSessionState::absent,
                   0,
                   0,
                   !validInput ? "input" : "source_binding");
        return HostSessionState::absent;
    }

    HostSessionState result = HostSessionState::full;
    bool sourceTransferred = false;
    HostSessionBinding observed{};
    HostSessionState observedState = HostSessionState::absent;
    std::uint32_t observedReferences = 0;
    AcquireSRWLockExclusive(&g_hostSessionLock);

    HostSession* matching = nullptr;
    for (HostSession& row : g_hostSessions) {
        if (row.occupied && row.binding.groupSessionId == groupSessionId) {
            matching = &row;
            break;
        }
    }
    if (matching != nullptr && same_generation(matching->binding.source, source)
        && matching->binding.regionIndex == regionIndex) {
        matching->lastUse = ++g_useStamp;
        output = matching->binding;
        result = matching->state;
        observed = matching->binding;
        observedState = matching->state;
        observedReferences = matching->references;
    } else if (matching != nullptr && matching->references != 0) {
        result = HostSessionState::conflict;
        observed = matching->binding;
        observedState = matching->state;
        observedReferences = matching->references;
    } else {
        HostSession* target = matching;
        if (target == nullptr) {
            for (HostSession& row : g_hostSessions) {
                if (!row.occupied) {
                    target = &row;
                    break;
                }
            }
        }
        if (target == nullptr) {
            for (HostSession& row : g_hostSessions) {
                if (row.references == 0 && (target == nullptr || row.lastUse < target->lastUse)) {
                    target = &row;
                }
            }
        }

        const std::uint64_t generation = target == nullptr ? 0 : next_generation_locked();
        if (target != nullptr && generation != 0 && retire_locked(*target)) {
            target->binding.source = source;
            target->binding.groupSessionId = groupSessionId;
            target->binding.generation = generation;
            target->binding.regionIndex = regionIndex;
            target->state = HostSessionState::pending;
            target->lastUse = ++g_useStamp;
            target->occupied = true;
            output = target->binding;
            sourceTransferred = true;
            result = HostSessionState::pending;
            observed = target->binding;
            observedState = target->state;
            observedReferences = target->references;
        }
    }
    const std::size_t retiredCount = g_retiredCount;
    ReleaseSRWLockExclusive(&g_hostSessionLock);

    if (!sourceTransferred) {
        state::activity::release_binding(source);
    }
    if (result == HostSessionState::full) {
        report(core::log::Level::warn, "ev=gameplay stage=activityhost result=full");
    }
    const HostSessionBinding& logged = output.generation != 0 ? output : observed;
    report_row(core::log::Level::debug,
               "request",
               state_name(result),
               logged,
               output.generation != 0 ? result : observedState,
               observedReferences,
               retiredCount,
               result == HostSessionState::conflict ? "referenced" : "none");
    return result;
}

/** Copies a ready row by its exact group-session key. */
bool host_session_for_group(std::uint64_t groupSessionId, HostSessionBinding& output) noexcept {
    output = {};
    return groupSessionId != 0
           && find_ready(
               [groupSessionId](const HostSessionBinding& binding) {
                   return binding.groupSessionId == groupSessionId;
               },
               output);
}

/** Copies a ready row by its allocated target activity-session id. */
bool host_session_for_activity(std::uint64_t hostSessionId, HostSessionBinding& output) noexcept {
    output = {};
    return hostSessionId != state::activity::kAbsentSessionId
           && find_ready(
               [hostSessionId](const HostSessionBinding& binding) {
                   return binding.target.sessionId == hostSessionId;
               },
               output);
}

/** Retains one ready host-row generation against replacement or eviction. */
bool retain_host_session(std::uint64_t generation) noexcept {
    if (generation == 0) {
        return false;
    }
    bool retained = false;
    HostSessionBinding binding{};
    HostSessionState state = HostSessionState::absent;
    std::uint32_t before = 0;
    std::uint32_t after = 0;
    std::size_t retiredCount = 0;
    AcquireSRWLockExclusive(&g_hostSessionLock);
    for (HostSession& row : g_hostSessions) {
        if (row.occupied && row.binding.generation == generation) {
            binding = row.binding;
            state = row.state;
            before = row.references;
        }
        if (row.occupied && row.state == HostSessionState::ready
            && row.binding.generation == generation
            && row.references != (std::numeric_limits<decltype(row.references)>::max)()) {
            ++row.references;
            row.lastUse = ++g_useStamp;
            retained = true;
            after = row.references;
            break;
        }
    }
    retiredCount = g_retiredCount;
    ReleaseSRWLockExclusive(&g_hostSessionLock);
    report_row(retained ? core::log::Level::debug : core::log::Level::warn,
               "retain",
               retained ? "ok" : "fail",
               binding,
               state,
               retained ? after : before,
               retiredCount,
               retained ? "none" : state == HostSessionState::absent ? "missing" : "not_ready");
    return retained;
}

/** Releases one external retain on the exact host-row generation. */
void release_host_session(std::uint64_t generation) noexcept {
    if (generation == 0) {
        return;
    }
    HostSessionBinding binding{};
    HostSessionState state = HostSessionState::absent;
    std::uint32_t before = 0;
    std::uint32_t after = 0;
    bool found = false;
    AcquireSRWLockExclusive(&g_hostSessionLock);
    for (HostSession& row : g_hostSessions) {
        if (row.occupied && row.binding.generation == generation) {
            found = true;
            binding = row.binding;
            state = row.state;
            before = row.references;
            if (row.references != 0) {
                --row.references;
            }
            after = row.references;
            break;
        }
    }
    const std::size_t retiredCount = g_retiredCount;
    ReleaseSRWLockExclusive(&g_hostSessionLock);
    report_row(core::log::Level::debug,
               "release_retain",
               found && before != 0 ? "ok" : "ignored",
               binding,
               state,
               after,
               retiredCount,
               !found ? "missing" : before == 0 ? "zero" : "none");
}

/** Copies every occupied host-session row. */
void snapshot_host_sessions(std::span<HostSessionRow> output, std::size_t& count) noexcept {
    count = 0;
    AcquireSRWLockShared(&g_hostSessionLock);
    for (const HostSession& row : g_hostSessions) {
        if (!row.occupied || count >= output.size()) {
            continue;
        }
        output[count] = {row.binding.groupSessionId,
                         row.binding.target.sessionId,
                         row.binding.regionIndex,
                         row.binding.generation};
        ++count;
    }
    ReleaseSRWLockShared(&g_hostSessionLock);
}

/** Fills every pending host-session row with a source-bound target. */
void allocate_claimed_host_sessions() noexcept {
    free_retired_host_sessions();
    for (;;) {
        HostSessionBinding pending{};
        AcquireSRWLockShared(&g_hostSessionLock);
        for (const HostSession& row : g_hostSessions) {
            if (row.occupied && row.state == HostSessionState::pending) {
                pending = row.binding;
                break;
            }
        }
        ReleaseSRWLockShared(&g_hostSessionLock);
        if (pending.generation == 0) {
            return;
        }

        report_row(core::log::Level::debug,
                   "allocate",
                   "pending",
                   pending,
                   HostSessionState::pending,
                   0,
                   retired_count_snapshot());

        std::uint64_t sessionId = state::activity::kAbsentSessionId;
        state::activity::PendingAllocation allocation{};
        const bool prepared =
            state::activity::prepare_session(pending.source.destination, sessionId, allocation);
        const bool committed = prepared && state::activity::commit(allocation);
        if (!prepared || !committed) {
            report_row(core::log::Level::warn,
                       "allocate",
                       "fail",
                       pending,
                       HostSessionState::pending,
                       0,
                       retired_count_snapshot(),
                       !prepared ? "prepare" : "commit");
            return;
        }

        state::activity::SessionBinding target{};
        const bool snapshotted = state::activity::snapshot_binding(sessionId, target);
        const bool targetRetained = snapshotted && state::activity::retain_binding(target);
        if (!snapshotted || !targetRetained) {
            HostSessionBinding committedBinding = pending;
            committedBinding.target = target;
            committedBinding.target.sessionId = sessionId;
            report_row(core::log::Level::warn,
                       "allocate",
                       "leak_risk",
                       committedBinding,
                       HostSessionState::pending,
                       0,
                       retired_count_snapshot(),
                       !snapshotted ? "snapshot" : "target_binding");
            return;
        }

        bool stored = false;
        std::size_t occupied = 0;
        AcquireSRWLockExclusive(&g_hostSessionLock);
        for (HostSession& row : g_hostSessions) {
            if (!row.occupied) {
                continue;
            }
            ++occupied;
            if (row.state == HostSessionState::pending
                && row.binding.generation == pending.generation) {
                row.binding.target = target;
                row.state = HostSessionState::ready;
                row.lastUse = ++g_useStamp;
                stored = true;
                break;
            }
        }
        ReleaseSRWLockExclusive(&g_hostSessionLock);

        if (!stored) {
            HostSessionBinding lost = pending;
            lost.target = target;
            report_row(core::log::Level::warn,
                       "allocate",
                       "not_stored",
                       lost,
                       HostSessionState::pending,
                       0,
                       retired_count_snapshot(),
                       "generation_replaced");
            state::activity::release_binding(target);
            static_cast<void>(state::activity::release_session(target.sessionId));
            return;
        }
        HostSessionBinding ready = pending;
        ready.target = target;
        report_row(core::log::Level::debug,
                   "allocate",
                   "ready",
                   ready,
                   HostSessionState::ready,
                   0,
                   retired_count_snapshot());
        report(core::log::Level::info,
               "ev=gameplay stage=activityhost result=allocated session=0x%llX group=0x%016llX "
               "generation=%llu held=%zu",
               static_cast<unsigned long long>(target.sessionId),
               static_cast<unsigned long long>(pending.groupSessionId),
               static_cast<unsigned long long>(pending.generation),
               occupied);
    }
}

/** Returns every retained binding and allocated target to State, then clears the table. */
void reset_host_sessions() noexcept {
    std::array<HostSessionBinding, kHostSessionCapacity * 2> released{};
    std::size_t count = 0;
    AcquireSRWLockExclusive(&g_hostSessionLock);
    for (const HostSession& row : g_hostSessions) {
        if (row.occupied) {
            released[count] = row.binding;
            ++count;
        }
    }
    for (std::size_t index = 0; index < g_retiredCount; ++index) {
        released[count] = g_retired[index];
        ++count;
    }
    g_hostSessions = {};
    g_retired = {};
    g_retiredCount = 0;
    ReleaseSRWLockExclusive(&g_hostSessionLock);

    if (count != 0) {
        report(core::log::Level::info,
               "ev=gameplay stage=activityhost event=reset result=release count=%zu",
               count);
    }

    for (std::size_t index = 0; index < count; ++index) {
        release_retired(released[index]);
    }
}

} // namespace sunrise::server::gameplay::group
