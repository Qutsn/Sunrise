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

/** Fallback used only when the Detours trampoline is unavailable. */
constexpr bool kFallbackReleased = false;
/** Do not let a polled handoff predicate turn the diagnostic sink into a frame-rate log. */
constexpr std::uint64_t kReportIntervalMs = 500;

using DestinationHold = bool(__fastcall*)(void*) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<DestinationHold> g_original{nullptr};
std::atomic_uint64_t g_callCount{};
std::atomic_uint64_t g_lastReportTick{};
std::atomic_bool g_nativeSeen{false};
std::atomic_bool g_lastNative{false};

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

/** Reports the native answer when it changes and at a bounded interval thereafter. */
void report_handoff(bool native, bool originalAvailable) noexcept {
    const std::uint64_t now = GetTickCount64();
    const std::uint64_t call = g_callCount.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool first = !g_nativeSeen.exchange(true, std::memory_order_relaxed);
    const bool previousNative = g_lastNative.exchange(native, std::memory_order_relaxed);
    const bool changed = first || previousNative != native;
    bool report = changed;
    if (first) {
        std::array<char, 128> line{};
        const int written = std::snprintf(line.data(),
                                          line.size(),
                                          "ev=bootflow stage=orbit_handoff result=native native=%s "
                                          "available=%s",
                                          native ? "true" : "false",
                                          originalAvailable ? "true" : "false");
        if (written > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(written)});
        }
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
    std::array<char, 224> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=diag stage=orbit_handoff call=%llu native=%s "
                                      "available=%s phase=%s age_ms=%llu",
                                      static_cast<unsigned long long>(call),
                                      native ? "true" : "false",
                                      originalAvailable ? "true" : "false",
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
 * Runs the native destination-hold predicate for this experiment.
 * @param stepCtx Borrowed step context passed to the native predicate.
 * @return The native answer, or the released fallback when the trampoline is unavailable.
 */
__declspec(noinline) bool __fastcall destination_hold(void* stepCtx) noexcept {
    const DestinationHold original = g_original.load(std::memory_order_acquire);
    if (original == nullptr) {
        report_handoff(kFallbackReleased, false);
        return kFallbackReleased;
    }
    const bool native = original(stepCtx);
    report_handoff(native, true);
    return native;
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
    g_original.store(reinterpret_cast<DestinationHold>(g_handle.original),
                     std::memory_order_release);
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
    g_original.store(nullptr, std::memory_order_release);
    g_callCount.store(0, std::memory_order_release);
    g_lastReportTick.store(0, std::memory_order_release);
    g_nativeSeen.store(false, std::memory_order_release);
    g_lastNative.store(false, std::memory_order_release);
}

} // namespace sunrise::client::hooks::bootflow
