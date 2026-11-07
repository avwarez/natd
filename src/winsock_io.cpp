// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/winsock_io.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include <algorithm>
#include <vector>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace natd {
namespace {

sockaddr_in toSockaddr(uint32_t ip, uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(ip);
    a.sin_port = htons(port);
    return a;
}

SOCKET sock(uintptr_t v) { return static_cast<SOCKET>(v); }

} // namespace

WinsockDatagramIo::WinsockDatagramIo(uint32_t bindIp) : bindIp_(bindIp) {
    WSADATA wd;
    started_ = WSAStartup(MAKEWORD(2, 2), &wd) == 0;
}

WinsockDatagramIo::~WinsockDatagramIo() {
    for (auto& [id, s] : socks_) closesocket(sock(s));
    if (started_) WSACleanup();
}

std::optional<SocketId> WinsockDatagramIo::openSocket(uint16_t port) {
    if (!started_) return std::nullopt;
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return std::nullopt;
    // Exclusive bind: without it another process could bind the same port
    // with SO_REUSEADDR and steal our datagrams.
    BOOL excl = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&excl), sizeof excl);
    sockaddr_in a = toSockaddr(bindIp_, port);
    if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) == SOCKET_ERROR) {
        closesocket(s);
        return std::nullopt;
    }
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    BOOL noReset = FALSE;
    DWORD ret = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &noReset, sizeof noReset, nullptr, 0, &ret, nullptr, nullptr);
    SocketId id = next_++;
    socks_[id] = static_cast<uintptr_t>(s);
    return id;
}

void WinsockDatagramIo::closeSocket(SocketId id) {
    auto it = socks_.find(id);
    if (it == socks_.end()) return;
    closesocket(sock(it->second));
    socks_.erase(it);
}

Endpoint WinsockDatagramIo::localEndpoint(SocketId id) const {
    auto it = socks_.find(id);
    if (it == socks_.end()) return {};
    sockaddr_in a{};
    int len = sizeof a;
    if (getsockname(sock(it->second), reinterpret_cast<sockaddr*>(&a), &len) != 0) return {};
    return {ntohl(a.sin_addr.s_addr), ntohs(a.sin_port)};
}

bool WinsockDatagramIo::send(SocketId id, const Endpoint& to, const uint8_t* data, size_t len) {
    auto it = socks_.find(id);
    if (it == socks_.end() || len > 65507) return false;
    sockaddr_in a = toSockaddr(to.ip, to.port);
    int n = ::sendto(sock(it->second), reinterpret_cast<const char*>(data), int(len), 0,
                     reinterpret_cast<sockaddr*>(&a), sizeof a);
    return n == int(len);
}

int WinsockDatagramIo::wait(TimePoint deadline, const RxFn& onRx) {
    std::vector<WSAPOLLFD> pfds;
    std::vector<SocketId> ids;
    for (auto& [id, s] : socks_) {
        WSAPOLLFD p{};
        p.fd = sock(s);
        p.events = POLLRDNORM;
        pfds.push_back(p);
        ids.push_back(id);
    }
    auto now = Clock::now();
    int timeoutMs = 0;
    if (deadline == TimePoint::max()) timeoutMs = 1000;
    else if (deadline > now)
        timeoutMs = int(std::min<int64_t>(1000, std::chrono::duration_cast<Duration>(deadline - now).count() + 1));
    if (pfds.empty()) { Sleep(DWORD(timeoutMs)); return 0; }   // WSAPoll rejects an empty set
    int r = WSAPoll(pfds.data(), ULONG(pfds.size()), timeoutMs);
    if (r <= 0) return 0;
    int delivered = 0;
    char buf[2048];
    for (size_t i = 0; i < pfds.size(); ++i) {
        if (!(pfds[i].revents & (POLLRDNORM | POLLERR | POLLHUP))) continue;
        if (!socks_.count(ids[i])) continue;   // closed by an earlier callback
        for (;;) {
            sockaddr_in a{};
            int alen = sizeof a;
            int n = ::recvfrom(pfds[i].fd, buf, sizeof buf, 0, reinterpret_cast<sockaddr*>(&a), &alen);
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAECONNRESET || e == WSAEMSGSIZE) continue;   // ICMP report / oversized: skip
                break;                                                   // WSAEWOULDBLOCK: drained
            }
            SocketId id = ids[i];
            onRx(id, Endpoint{ntohl(a.sin_addr.s_addr), ntohs(a.sin_port)}, reinterpret_cast<uint8_t*>(buf),
                 size_t(n));
            ++delivered;
            if (!socks_.count(id)) break;
        }
    }
    return delivered;
}

uint32_t WinsockDatagramIo::localIpToward(uint32_t destIp) {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return 0;
    uint32_t ip = 0;
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
        sockaddr_in a = toSockaddr(destIp, 9);
        if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0) {
            sockaddr_in l{};
            int len = sizeof l;
            if (getsockname(s, reinterpret_cast<sockaddr*>(&l), &len) == 0) ip = ntohl(l.sin_addr.s_addr);
        }
        closesocket(s);
    }
    WSACleanup();
    return ip;
}

} // namespace natd
