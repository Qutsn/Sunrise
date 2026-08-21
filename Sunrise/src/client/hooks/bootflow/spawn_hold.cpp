#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../core/settings/settings.h"
#include "../../../state/activity/runtime.h"
#include "../../hooking/detour.h"
#include "internal.h"
#include "spawn/probe.h"

namespace sunrise::client::hooks::bootflow {
namespace {

/**
 * The player spawn gate. Anchored on the load of the encrypted manager global, then run on
 * through the stack-cookie store because the wildcarded frame size leaves the head too short.
 */
constexpr std::string_view kSpawnGateSignatureText =
    "40 53 57 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 8B D9 "
    "40 B7 01";
/** Compiled pattern bytes of the signature text above. */
constexpr auto kSpawnGateSignature =
    signature<signature_length(kSpawnGateSignatureText)>(kSpawnGateSignatureText);

/** Answer that holds the spawn for this tick. The gate is polled, so a refusal only delays it. */
constexpr bool kHeld = false;
/** Bound the diagnostic work performed by the polled spawn gate. */
constexpr std::uint64_t kReportIntervalMs = 500;

using SpawnGate = bool(__fastcall*)(std::int32_t) noexcept;

hooking::detour::Handle g_handle{};
std::atomic<SpawnGate> g_original{nullptr};
std::atomic_bool g_probeReady{false};
std::atomic_bool g_haveReport{false};
std::atomic_bool g_lastNative{};
std::atomic_uint8_t g_lastPhase{};
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

/** Runs the reverse-engineered probe behind an SEH boundary so a stale target only loses data. */
[[nodiscard]] bool try_examine(std::int32_t datum, spawn::Reading& reading) noexcept {
    __try {
        reading = spawn::examine(datum);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

/** Emits native gate state and, when available, the bounded read-only predicate snapshot. */
void report_spawn_gate(std::int32_t datum,
                       bool nativeAllowed,
                       state::activity::WorldPhase phase,
                       std::uint64_t age,
                       bool loading,
                       bool holdSpawn) noexcept {
    const std::uint64_t now = GetTickCount64();
    const auto phaseValue = static_cast<std::uint8_t>(phase);
    const bool changed = !g_haveReport.load(std::memory_order_relaxed)
                         || g_lastNative.load(std::memory_order_relaxed) != nativeAllowed
                         || g_lastPhase.load(std::memory_order_relaxed) != phaseValue;
    const std::uint64_t previous = g_lastReportTick.load(std::memory_order_relaxed);
    if (!changed && now - previous < kReportIntervalMs) {
        return;
    }
    g_haveReport.store(true, std::memory_order_relaxed);
    g_lastNative.store(nativeAllowed, std::memory_order_relaxed);
    g_lastPhase.store(phaseValue, std::memory_order_relaxed);
    g_lastReportTick.store(now, std::memory_order_relaxed);
    if (!core::log::accepts(core::log::Channel::client, core::log::Level::debug)) {
        return;
    }

    std::array<char, 384> line{};
    int written = 0;
    if (!g_probeReady.load(std::memory_order_acquire)) {
        written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=spawn_gate datum=%d native=%u phase=%s "
                                "age_ms=%llu loading=%u hold=%u probe=unavailable",
                                datum,
                                nativeAllowed ? 1U : 0U,
                                phase_name(phase),
                                static_cast<unsigned long long>(age),
                                loading ? 1U : 0U,
                                holdSpawn ? 1U : 0U);
    } else {
        spawn::Reading reading{};
        std::array<char, 256> probeText{};
        const bool examined = try_examine(datum, reading);
        std::size_t probeLength = 0;
        if (examined) {
            probeLength = std::min(spawn::describe(reading, probeText), probeText.size() - 1);
        }
        written = std::snprintf(line.data(),
                                line.size(),
                                "ev=diag stage=spawn_gate datum=%d native=%u phase=%s "
                                "age_ms=%llu loading=%u hold=%u probe=%s%s%.*s",
                                datum,
                                nativeAllowed ? 1U : 0U,
                                phase_name(phase),
                                static_cast<unsigned long long>(age),
                                loading ? 1U : 0U,
                                holdSpawn ? 1U : 0U,
                                examined ? "ok" : "seh",
                                examined ? " " : "",
                                static_cast<int>(probeLength),
                                probeText.data());
    }
    if (written > 0) {
        const std::size_t length = std::min(static_cast<std::size_t>(written), line.size() - 1);
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), length});
    }
}

/**
 * Puts the spawn after the world-transition fade is armed.
 * A release on a channel that is not up does nothing, so a spawn during the load leaves the
 * screen black. The client's own predicate reads a host field this destination never fills.
 * @param datum Borrowed player datum handle; the answer does not depend on it.
 * @return The native answer, or held while a destination load is still running.
 */
__declspec(noinline) bool __fastcall spawn_gate(std::int32_t datum) noexcept {
    const SpawnGate original = g_original.load(std::memory_order_acquire);
    const bool allowed = original != nullptr && original(datum);
    observe_world_step();
    const state::activity::WorldPhase phase = state::activity::world_phase();
    const bool transitioning = phase == state::activity::WorldPhase::transitioning;
    // Zero unless a load is running.
    const std::uint64_t age = state::activity::world_transition_age();
    const core::settings::client::Settings& client = core::settings::get().client;
    const bool gaveUp = age >= client.spawnHoldMs;
    const bool loading = transitioning && !gaveUp && client.holdSpawn;
    // Release only on arrival. The step-37 exit re-arms the fade unless one is already up, and
    // nothing polls this gate after the spawn, so an early release leaves a fade nobody clears.
    if (phase == state::activity::WorldPhase::arrived) {
        release_world_fade();
    }
    report_spawn_gate(datum, allowed, phase, age, loading, client.holdSpawn);
    return allowed && loading ? kHeld : allowed;
}

} // namespace

/** Attaches the spawn hold. */
bool install_spawn_hold() noexcept {
    if (g_handle.attached) {
        return true;
    }
    spawn::forget();
    g_probeReady.store(false, std::memory_order_release);
    std::byte* const target = scan_main_image_unique(kSpawnGateSignature, "player_spawn_gate");
    if (target == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=spawn_hold result=fail reason=target");
        return false;
    }
    const bool probeReady = spawn::resolve(target);
    g_probeReady.store(probeReady, std::memory_order_release);
    if (!probeReady) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=diag stage=spawn_probe result=unavailable reason=resolve");
    } else {
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         "ev=diag stage=spawn_probe result=ready");
    }
    const hooking::detour::Spec spec{target, reinterpret_cast<void*>(&spawn_gate)};
    if (!hooking::detour::install(spec, g_handle)) {
        spawn::forget();
        g_probeReady.store(false, std::memory_order_release);
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=spawn_hold result=fail reason=attach");
        return false;
    }
    g_original.store(reinterpret_cast<SpawnGate>(g_handle.original), std::memory_order_release);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=bootflow stage=spawn_hold result=ok");
    return true;
}

/** Detaches the spawn hold. */
void uninstall_spawn_hold() noexcept {
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_original.store(nullptr, std::memory_order_release);
    if (!g_handle.attached) {
        spawn::forget();
        g_probeReady.store(false, std::memory_order_release);
    }
    g_haveReport.store(false, std::memory_order_release);
    g_lastReportTick.store(0, std::memory_order_release);
}

} // namespace sunrise::client::hooks::bootflow
