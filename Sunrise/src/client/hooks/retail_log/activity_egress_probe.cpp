#include "activity_egress_probe.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>

#include "../../../core/logging/log.h"

namespace sunrise::client::hooks::retail_log::activity_egress_probe {
namespace {

/** Long enough to cover the observed selection-to-orbit-request interval with margin. */
constexpr std::uint64_t kWindowMs = 12'000;
/** A broken or unexpectedly busy route must not turn this diagnostic into an unbounded logger. */
constexpr std::uint32_t kRecordLimit = 128;
/** Native stack depth retained before non-game frames are discarded. */
constexpr USHORT kCapturedFrameCount = 20;
/** Game-relative call sites kept in one record. */
constexpr std::size_t kGameFrameCount = 8;
/** Distinct native callers retained so their function bytes are read only once per process. */
constexpr std::size_t kFunctionCacheCapacity = 64;
/** Function-prefix bytes hashed to bind a runtime address to the sampled executable. */
constexpr std::size_t kFunctionHashBytes = 32;
/** FNV-1a offset basis used only for a non-reversible code identity. */
constexpr std::uint64_t kFnvOffsetBasis = 14'695'981'039'346'656'037ULL;
/** FNV-1a prime used only for a non-reversible code identity. */
constexpr std::uint64_t kFnvPrime = 1'099'511'628'211ULL;

struct ImageIdentity final {
    std::uintptr_t base{};
    std::uint32_t size{};
    std::uint32_t timestamp{};
};

struct GameFrame final {
    std::uintptr_t returnRva{};
    std::uint32_t functionRva{};
    std::uint64_t functionHash{};
};

struct FunctionIdentity final {
    std::uint32_t functionRva{};
    std::uint64_t functionHash{};
};

struct Window final {
    std::uint64_t started{};
    std::uint32_t generation{};
    std::uint32_t selectionToken{};
    std::uint32_t activityIndex{};
    std::uint32_t destination{};
    std::uint32_t cachedDestination{};
    std::uint32_t records{};
    bool hasCache{};
    bool active{};
};

struct Snapshot final {
    std::uint64_t started{};
    std::uint32_t generation{};
    std::uint32_t selectionToken{};
    std::uint32_t activityIndex{};
    std::uint32_t destination{};
    std::uint32_t cachedDestination{};
    std::uint32_t record{};
    bool hasCache{};
};

SRWLOCK g_lock{SRWLOCK_INIT};
SRWLOCK g_functionLock{SRWLOCK_INIT};
Window g_window{};
std::array<FunctionIdentity, kFunctionCacheCapacity> g_functions{};
std::size_t g_functionCount{};
std::atomic_uint32_t g_generation{};
std::atomic_uint64_t g_deadline{};
std::atomic_bool g_active{};
thread_local bool g_reporting{};

/** Reads the mapped main-image identity needed to interpret all recorded RVAs. */
[[nodiscard]] bool inspect_image(ImageIdentity& output) noexcept {
    output = {};
    const HMODULE game = GetModuleHandleW(nullptr);
    if (game == nullptr) {
        return false;
    }
    const auto* const base = reinterpret_cast<const std::byte*>(game);
    IMAGE_DOS_HEADER dos{};
    SIZE_T copied = 0;
    if (ReadProcessMemory(GetCurrentProcess(), base, &dos, sizeof(dos), &copied) == FALSE
        || copied != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    copied = 0;
    if (ReadProcessMemory(
            GetCurrentProcess(), base + dos.e_lfanew, &nt, sizeof(nt), &copied)
            == FALSE
        || copied != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE
        || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || nt.OptionalHeader.SizeOfImage == 0) {
        return false;
    }
    output.base = reinterpret_cast<std::uintptr_t>(game);
    output.size = nt.OptionalHeader.SizeOfImage;
    output.timestamp = nt.FileHeader.TimeDateStamp;
    return true;
}

/** Hashes a bounded function prefix without retaining or logging executable bytes. */
[[nodiscard]] std::uint64_t function_hash(const ImageIdentity& image,
                                          std::uint32_t begin,
                                          std::uint32_t end) noexcept {
    if (begin >= end || end > image.size) {
        return 0;
    }
    const std::size_t available = static_cast<std::size_t>(end - begin);
    const std::size_t length = available < kFunctionHashBytes ? available : kFunctionHashBytes;
    std::array<std::byte, kFunctionHashBytes> bytes{};
    SIZE_T copied = 0;
    if (ReadProcessMemory(GetCurrentProcess(),
                          reinterpret_cast<const void*>(image.base + begin),
                          bytes.data(),
                          length,
                          &copied)
            == FALSE
        || copied != length) {
        return 0;
    }
    std::uint64_t hash = kFnvOffsetBasis;
    for (std::size_t index = 0; index < length; ++index) {
        hash ^= std::to_integer<std::uint8_t>(bytes[index]);
        hash *= kFnvPrime;
    }
    return hash;
}

/** Returns a cached function identity, reading its bytes only on the first observation. */
[[nodiscard]] std::uint64_t cached_function_hash(const ImageIdentity& image,
                                                 std::uint32_t begin,
                                                 std::uint32_t end) noexcept {
    AcquireSRWLockShared(&g_functionLock);
    for (std::size_t index = 0; index < g_functionCount; ++index) {
        if (g_functions[index].functionRva == begin) {
            const std::uint64_t hash = g_functions[index].functionHash;
            ReleaseSRWLockShared(&g_functionLock);
            return hash;
        }
    }
    ReleaseSRWLockShared(&g_functionLock);

    const std::uint64_t hash = function_hash(image, begin, end);
    AcquireSRWLockExclusive(&g_functionLock);
    for (std::size_t index = 0; index < g_functionCount; ++index) {
        if (g_functions[index].functionRva == begin) {
            const std::uint64_t existing = g_functions[index].functionHash;
            ReleaseSRWLockExclusive(&g_functionLock);
            return existing;
        }
    }
    if (g_functionCount < g_functions.size()) {
        g_functions[g_functionCount++] = {begin, hash};
    }
    ReleaseSRWLockExclusive(&g_functionLock);
    return hash;
}

/** @return The active window snapshot for one record, or false outside its bounds. */
[[nodiscard]] bool acquire_snapshot(std::uint64_t now, Snapshot& output) noexcept {
    output = {};
    AcquireSRWLockExclusive(&g_lock);
    const bool expired = g_window.active && now - g_window.started > kWindowMs;
    if (expired || g_window.records >= kRecordLimit) {
        g_window.active = false;
        g_active.store(false, std::memory_order_release);
    }
    if (g_window.active) {
        ++g_window.records;
        output.started = g_window.started;
        output.generation = g_window.generation;
        output.selectionToken = g_window.selectionToken;
        output.activityIndex = g_window.activityIndex;
        output.destination = g_window.destination;
        output.cachedDestination = g_window.cachedDestination;
        output.record = g_window.records;
        output.hasCache = g_window.hasCache;
    }
    const bool active = g_window.active;
    ReleaseSRWLockExclusive(&g_lock);
    return active;
}

/** Collects main-executable-relative stack sites, discarding Sunrise and system frames. */
[[nodiscard]] std::size_t capture_game_frames(
    std::span<GameFrame, kGameFrameCount> output) noexcept {
    std::array<void*, kCapturedFrameCount> frames{};
    const USHORT captured =
        RtlCaptureStackBackTrace(0, kCapturedFrameCount, frames.data(), nullptr);
    ImageIdentity image{};
    if (!inspect_image(image)) {
        return 0;
    }
    std::size_t count = 0;
    for (USHORT index = 0; index < captured && count < output.size(); ++index) {
        const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(frames[index]);
        if (address < image.base || address - image.base >= image.size) {
            continue;
        }
        DWORD64 functionBase = 0;
        const RUNTIME_FUNCTION* function = RtlLookupFunctionEntry(address, &functionBase, nullptr);
        GameFrame frame{};
        frame.returnRva = address - image.base;
        if (function != nullptr && functionBase == image.base) {
            frame.functionRva = function->BeginAddress;
            frame.functionHash =
                cached_function_hash(image, function->BeginAddress, function->EndAddress);
        }
        output[count++] = frame;
    }
    return count;
}

/** Appends one comma-separated game-relative stack to a bounded event line. */
void append_frames(std::array<char, core::log::kLineCapacity>& line,
                   std::size_t& length,
                   std::span<const GameFrame> frames) noexcept {
    for (std::size_t index = 0; index < frames.size() && length < line.size(); ++index) {
        const int written = std::snprintf(line.data() + length,
                                          line.size() - length,
                                          "%s0x%llX@0x%X#0x%llX",
                                          index == 0 ? "" : ",",
                                          static_cast<unsigned long long>(frames[index].returnRva),
                                          frames[index].functionRva,
                                          static_cast<unsigned long long>(
                                              frames[index].functionHash));
        if (written <= 0) {
            return;
        }
        const std::size_t appended = static_cast<std::size_t>(written);
        length += appended < line.size() - length ? appended : line.size() - length - 1;
    }
}

} // namespace

/** Arms one bounded BAP-egress observation window for a native activity selection. */
void arm(std::uint32_t selectionToken,
         std::uint32_t activityIndex,
         std::uint32_t destination,
         bool hasCache,
         std::uint32_t cachedDestination) noexcept {
    const std::uint64_t now = GetTickCount64();
    const std::uint32_t generation = g_generation.fetch_add(1, std::memory_order_relaxed) + 1;
    AcquireSRWLockExclusive(&g_lock);
    g_window = {now,
                generation,
                selectionToken,
                activityIndex,
                destination,
                cachedDestination,
                0,
                hasCache,
                true};
    g_deadline.store(now + kWindowMs, std::memory_order_relaxed);
    g_active.store(true, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lock);

    ImageIdentity image{};
    (void)inspect_image(image);
    std::array<char, 256> line{};
    const int written = std::snprintf(line.data(),
                                      line.size(),
                                      "ev=diag stage=transition_egress event=armed generation=%u "
                                      "selection=%u activity=%u destination=0x%08X cache=%s:0x%08X "
                                      "window_ms=%llu image_timestamp=0x%08X image_size=0x%X",
                                      generation,
                                      selectionToken,
                                      activityIndex,
                                      destination,
                                      hasCache ? "set" : "none",
                                      hasCache ? cachedDestination : 0U,
                                      static_cast<unsigned long long>(kWindowMs),
                                      image.timestamp,
                                      image.size);
    if (written > 0) {
        const std::size_t length = static_cast<std::size_t>(written) < line.size()
                                       ? static_cast<std::size_t>(written)
                                       : line.size() - 1;
        core::log::write(core::log::Channel::client,
                         core::log::Level::debug,
                         {line.data(), length});
    }
}

/** Records one BAP send without reading or retaining packet contents. */
void observe(const char* api,
             std::uintptr_t socketValue,
             std::size_t bytes,
             std::uint32_t bufferCount) noexcept {
    if (g_reporting
        || !core::log::accepts(core::log::Channel::client, core::log::Level::debug)) {
        return;
    }
    Snapshot snapshot{};
    const std::uint64_t now = GetTickCount64();
    if (!acquire_snapshot(now, snapshot)) {
        return;
    }

    g_reporting = true;
    std::array<GameFrame, kGameFrameCount> frames{};
    const std::size_t frameCount = capture_game_frames(frames);
    std::array<char, core::log::kLineCapacity> line{};
    const int prefix = std::snprintf(
        line.data(),
        line.size(),
        "ev=diag stage=transition_egress event=send generation=%u record=%u age_ms=%llu "
        "selection=%u activity=%u destination=0x%08X cache=%s:0x%08X api=%s "
        "socket=0x%llX bytes=%zu buffers=%u stack=",
        snapshot.generation,
        snapshot.record,
        static_cast<unsigned long long>(now - snapshot.started),
        snapshot.selectionToken,
        snapshot.activityIndex,
        snapshot.destination,
        snapshot.hasCache ? "set" : "none",
        snapshot.hasCache ? snapshot.cachedDestination : 0U,
        api != nullptr ? api : "unknown",
        static_cast<unsigned long long>(socketValue),
        bytes,
        bufferCount);
    if (prefix > 0) {
        std::size_t length = static_cast<std::size_t>(prefix) < line.size()
                                 ? static_cast<std::size_t>(prefix)
                                 : line.size() - 1;
        if (frameCount == 0) {
            constexpr char kNone[] = "none";
            const std::size_t remaining = line.size() - length - 1;
            const std::size_t copied =
                remaining < sizeof(kNone) - 1 ? remaining : sizeof(kNone) - 1;
            std::memcpy(line.data() + length, kNone, copied);
            length += copied;
        } else {
            append_frames(line, length, std::span(frames).first(frameCount));
        }
        core::log::write(
            core::log::Channel::client, core::log::Level::debug, {line.data(), length});
    }
    g_reporting = false;
}

/** @return True while a bounded selection observation window can still accept records. */
bool active() noexcept {
    if (!g_active.load(std::memory_order_acquire)) {
        return false;
    }
    std::uint64_t deadline = g_deadline.load(std::memory_order_acquire);
    if (GetTickCount64() <= deadline) {
        return true;
    }
    if (g_deadline.compare_exchange_strong(
            deadline, 0, std::memory_order_acq_rel, std::memory_order_acquire)) {
        g_active.store(false, std::memory_order_release);
    }
    return false;
}

/** Clears the current observation window and counters. */
void reset() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    g_window = {};
    g_deadline.store(0, std::memory_order_relaxed);
    g_active.store(false, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace sunrise::client::hooks::retail_log::activity_egress_probe
