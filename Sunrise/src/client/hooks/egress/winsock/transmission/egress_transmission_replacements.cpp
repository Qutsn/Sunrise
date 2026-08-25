#include <array>
#include <limits>

#include "../../../../../core/settings/settings.h"
#include "../../../retail_log/activity_egress_probe.h"
#include "../../internal.h"
#include "../../policy/policy.h"
#include "replacements.h"

namespace sunrise::client::hooks::egress::winsock::transmission {
namespace {

/** @return True when the connected peer is the configured BAP listener. */
[[nodiscard]] bool is_bap_peer(SOCKET socket) noexcept {
    sockaddr_in peer{};
    int peerLength = static_cast<int>(sizeof(peer));
    return ::getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peerLength) != SOCKET_ERROR
           && peer.sin_family == AF_INET
           && ntohs(peer.sin_port) == core::settings::get().server.bapPort;
}

/** Totals a bounded caller-owned buffer list without reading any payload bytes. */
[[nodiscard]] std::size_t buffer_bytes(LPWSABUF buffers, DWORD bufferCount) noexcept {
    constexpr DWORD kMaximumBufferCount = 64;
    if (bufferCount > kMaximumBufferCount) {
        return 0;
    }
    std::array<WSABUF, kMaximumBufferCount> snapshot{};
    const SIZE_T expected = static_cast<SIZE_T>(bufferCount) * sizeof(WSABUF);
    SIZE_T copied = 0;
    if (expected != 0
        && (buffers == nullptr
            || ReadProcessMemory(
                   GetCurrentProcess(), buffers, snapshot.data(), expected, &copied)
                   == FALSE
            || copied != expected)) {
        return 0;
    }
    std::size_t total = 0;
    for (DWORD index = 0; index < bufferCount; ++index) {
        if (snapshot[index].len > (std::numeric_limits<std::size_t>::max)() - total) {
            return 0;
        }
        total += snapshot[index].len;
    }
    return total;
}

/**
 * Sets a fixed byte count before a blocked overlapped send returns.
 * @param bytes Optional caller-owned byte count.
 */
void clear_bytes(LPDWORD bytes) noexcept {
    if (bytes != nullptr) {
        *bytes = 0;
    }
}

} // namespace

/** Sends contiguous bytes to a connected exact IPv4 redirect target. */
int WSAAPI send_bytes(SOCKET socket, const char* buffer, int length, int flags) noexcept {
    const auto call = original<decltype(&::send)>(HookSlot::send);
    const bool targetsRedirect = policy::has_redirect_target_peer(socket);
    if (call == nullptr
        || !policy::allow_socket_call(policy::SocketOperation::send, targetsRedirect, true)) {
        return policy::deny_socket_call();
    }
    const int result = call(socket, buffer, length, flags);
    const int error = WSAGetLastError();
    if (retail_log::activity_egress_probe::active()) {
        if (is_bap_peer(socket)) {
            retail_log::activity_egress_probe::observe(
                "send",
                static_cast<std::uintptr_t>(socket),
                length >= 0 ? static_cast<std::size_t>(length) : 0,
                1);
        }
        WSASetLastError(error);
    }
    return result;
}

/** Sends buffers to a connected exact IPv4 redirect target. */
int WSAAPI send_buffers(SOCKET socket,
                        LPWSABUF buffers,
                        DWORD bufferCount,
                        LPDWORD bytesSent,
                        DWORD flags,
                        LPWSAOVERLAPPED overlapped,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) noexcept {
    const auto call = original<decltype(&::WSASend)>(HookSlot::wsaSend);
    const bool targetsRedirect = policy::has_redirect_target_peer(socket);
    if (call == nullptr
        || !policy::allow_socket_call(policy::SocketOperation::send, targetsRedirect, true)) {
        clear_bytes(bytesSent);
        return policy::deny_socket_call();
    }
    const int result = call(socket, buffers, bufferCount, bytesSent, flags, overlapped, completion);
    const int error = WSAGetLastError();
    if (retail_log::activity_egress_probe::active()) {
        if (is_bap_peer(socket)) {
            retail_log::activity_egress_probe::observe("WSASend",
                                                       static_cast<std::uintptr_t>(socket),
                                                       buffer_bytes(buffers, bufferCount),
                                                       bufferCount);
        }
        WSASetLastError(error);
    }
    return result;
}

/** Sends disconnect data to a connected exact IPv4 redirect target. */
int WSAAPI send_disconnect(SOCKET socket, LPWSABUF outboundData) noexcept {
    const auto call = original<decltype(&::WSASendDisconnect)>(HookSlot::wsaSendDisconnect);
    const bool targetsRedirect = policy::has_redirect_target_peer(socket);
    if (call == nullptr
        || !policy::allow_socket_call(policy::SocketOperation::send, targetsRedirect, true)) {
        return policy::deny_socket_call();
    }
    return call(socket, outboundData);
}

} // namespace sunrise::client::hooks::egress::winsock::transmission
