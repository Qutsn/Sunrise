#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../state/activity/runtime.h"
#include "../../hooking/detour.h"
#include "internal.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * The destination-hold predicate of the orbit setup step. Its prologue repeats across the image,
 * so the pattern runs on through the call and the flag test that follow. Every displacement is
 * wildcarded.
 */
constexpr std::string_view kHoldSignatureText =
    "48 89 5C 24 ? 57 48 83 EC ? 48 8B D9 E8 ? ? ? ? 80 3D ? ? ? ? 00 48 8B F8 75 ?";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kHoldSignature = signature<signature_length(kHoldSignatureText)>(kHoldSignatureText);

/**
 * Answer that lets the handoff test pass. The native predicate holds for an armed pending
 * destination, or for a cinematic under a 5,000 ms timer. This answer skips that wait. It has one
 * call site, the step's own update, so nothing else sees the change.
 */
constexpr bool kReleased = false;
/** Do not let a polled handoff predicate turn the diagnostic sink into a frame-rate log. */
constexpr std::uint64_t kReportIntervalMs = 500;

hooking::detour::Handle g_handle{};
std::atomic_uint64_t g_callCount{};
std::atomic_uint64_t g_lastReportTick{};

/** @return A stable name for the activity phase in diagnostic records. */
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

/** Reports the handoff call at the first call and at a bounded interval thereafter. */
void report_handoff() noexcept {
    const std::uint64_t now = GetTickCount64();
    const std::uint64_t call = g_callCount.fetch_add(1, std::memory_order_relaxed) + 1;
    bool report = call == 1;
    if (call == 1) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         "ev=bootflow stage=orbit_handoff result=released");
    }
    if (report) {
        g_lastReportTick.store(now, std::memory_order_relaxed);
    } else {
        std::uint64_t previous = g_lastReportTick.load(std::memory_order_relaxed);
        while (now - previous >= kReportIntervalMs
               && !g_lastReportTick.compare_exchange_weak(
                   previous, now, std::memory_order_relaxed, std::memory_order_relaxed)) {
        }
        report = now - previous >= kReportIntervalMs;
    }
    if (!report || !core::log::accepts(core::log::Channel::client, core::log::Level::debug)) {
        return;
    }

    const state::activity::WorldPhase phase = state::activity::world_phase();
    std::array<char, 192> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=diag stage=orbit_handoff call=%llu phase=%s age_ms=%llu",
                                      static_cast<unsigned long long>(call),
                                      phase_name(phase),
                                      static_cast<unsigned long long>(
                                          state::activity::world_transition_age()));
    if (written > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

/**
 * Releases the destination hold. The original is never called: blocking is the only answer it
 * gives here, so answering directly gives the same result with no call.
 * @param stepCtx Borrowed step context; the answer does not depend on it.
 * @return The released answer, always.
 */
__declspec(noinline) bool __fastcall destination_hold(void* stepCtx) noexcept {
    (void)stepCtx;
    report_handoff();
    return kReleased;
}

} // namespace

/**
 * Attaches the orbit handoff release.
 * @return True when the target is found and the detour attaches.
 */
bool install_orbit_handoff() noexcept {
    if (g_handle.attached) {
        return true;
    }
    std::byte* const target = scan_main_image_unique(kHoldSignature, "orbit_destination_hold");
    if (target == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=orbit_handoff result=fail reason=target");
        return false;
    }
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&destination_hold)};
    if (!hooking::detour::install(spec, g_handle)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=orbit_handoff result=fail reason=attach");
        return false;
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=bootflow stage=orbit_handoff result=ok");
    return true;
}

/** Detaches the orbit handoff release. */
void uninstall_orbit_handoff() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_callCount.store(0, std::memory_order_release);
    g_lastReportTick.store(0, std::memory_order_release);
}

} // namespace sunrise::client::hooks::bootflow
