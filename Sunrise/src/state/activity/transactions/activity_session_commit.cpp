#include "../../runtime/storage/internal.h"
#include "../destination/activity_destination_validation.h"
#include "../runtime.h"
#include "internal.h"

namespace sunrise::state::activity {

/** Commits one prepared activity-session allocation when its revisions still match. */
bool commit(PendingAllocation& allocation) noexcept {
    // Take the plan first so no transaction can replay, pass or fail.
    const PendingAllocation prepared = allocation;
    allocation = {};
    // A fresh plan must name the id the allocator is about to publish. A re-created plan names one
    // it published before, and its prepare has already proved the counter is behind the allocator.
    const bool namesNextId =
        prepared.sessionId
        == transactions::compose_session_soid(prepared.soidBase, prepared.expectedNextSessionId);
    if (!prepared.prepared || prepared.sessionId == kAbsentSessionId
        || prepared.expectedStateRevision == kInvalidRevision
        || prepared.expectedAllocatorRevision == kInvalidRevision
        || (!prepared.recreated && !namesNextId) || prepared.targetSlot >= kSessionCapacity
        || !destination::valid(prepared.destination)
        || (prepared.advancesCurrentActivity
            && prepared.destination.activityIndex == destination::kAbsentActivityIndex)) {
        return false;
    }

    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_state.activity;
    if (!transactions::allocation_available(state)
        || state.stateRevision != prepared.expectedStateRevision
        || state.allocatorRevision != prepared.expectedAllocatorRevision
        || state.nextSessionId != prepared.expectedNextSessionId) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }

    // Pick again under the write lock so stale plan data cannot redirect State.
    const std::size_t target = transactions::select_target(state);
    if (target != prepared.targetSlot) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }

    SessionRecord& record = state.sessions[target];
    // A full reset clears the evicted record and restores each field's own unset value.
    record = {};
    ++state.stateRevision;
    record.destination = prepared.destination;
    record.sessionId = prepared.sessionId;
    record.createdRevision = state.stateRevision;
    record.recordRevision = state.stateRevision;
    record.occupied = true;
    if (!prepared.recreated) {
        // The counter a re-created id fills was spent when it was first published, so the
        // allocator stays where it is and no later allocation can collide with it.
        transactions::advance_allocator(state);
    }
    if (prepared.advancesCurrentActivity) {
        state.currentActivityIndex = prepared.destination.activityIndex;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

/** Commits one prepared logical activity-location change. */
bool commit(PendingLocationMutation& mutation) noexcept {
    const PendingLocationMutation prepared = mutation;
    mutation = {};
    if (!prepared.prepared || prepared.expectedStateRevision == kInvalidRevision
        || prepared.activityIndex < kOrbitActivityIndex
        || prepared.activityIndex > destination::kMaximumActivityIndex) {
        return false;
    }

    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_state.activity;
    if (state.stateRevision != prepared.expectedStateRevision) {
        ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
        return false;
    }
    if (state.currentActivityIndex != prepared.activityIndex) {
        if (state.stateRevision == kMaximumRevision) {
            ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
            return false;
        }
        state.currentActivityIndex = prepared.activityIndex;
        ++state.stateRevision;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return true;
}

} // namespace sunrise::state::activity
