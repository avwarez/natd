// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/posix_io.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

namespace natd {
namespace {

sockaddr_in toSockaddr(uint32_t ip, uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(ip);
    a.sin_port = htons(port);
    return a;
}

} // namespace

PosixDatagramIo::PosixDatagramIo(uint32_t bindIp) : bindIp_(bindIp) {}

PosixDatagramIo::~PosixDatagramIo() {
    for (auto& [id, fd] : fds_) ::close(fd);
}

std::optional<SocketId> PosixDatagramIo::openSocket(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return std::nullopt;
    sockaddr_in a = toSockaddr(bindIp_, port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
        ::close(fd);
        return std::nullopt;
    }
    SocketId id = next_++;
    fds_[id] = fd;
    return id;
}

void PosixDatagramIo::closeSocket(SocketId s) {
    auto it = fds_.find(s);
    if (it == fds_.end()) return;
    ::close(it->second);
    fds_.erase(it);
}

Endpoint PosixDatagramIo::localEndpoint(SocketId s) const {
    auto it = fds_.find(s);
    if (it == fds_.end()) return {};
    sockaddr_in a{};
    socklen_t len = sizeof a;
    if (::getsockname(it->second, reinterpret_cast<sockaddr*>(&a), &len) != 0) return {};
    return {ntohl(a.sin_addr.s_addr), ntohs(a.sin_port)};
}

bool PosixDatagramIo::send(SocketId s, const Endpoint& to, const uint8_t* data, size_t len) {
    auto it = fds_.find(s);
    if (it == fds_.end()) return false;
    sockaddr_in a = toSockaddr(to.ip, to.port);
    ssize_t n;
    do {
        n = ::sendto(it->second, data, len, 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
    } while (n < 0 && errno == EINTR);
    return n == ssize_t(len);
}

int PosixDatagramIo::wait(TimePoint deadline, const RxFn& onRx) {
    std::vector<pollfd> pfds;
    std::vector<SocketId> ids;
    for (auto& [id, fd] : fds_) {
        pfds.push_back({fd, POLLIN, 0});
        ids.push_back(id);
    }
    auto now = Clock::now();
    int timeoutMs = 0;
    if (deadline == TimePoint::max()) timeoutMs = 1000;
    else if (deadline > now)
        timeoutMs = int(std::min<int64_t>(
            1000, std::chrono::duration_cast<Duration>(deadline - now).count() + 1));
    int r = ::poll(pfds.data(), pfds.size(), timeoutMs);
    if (r <= 0) return 0;
    int delivered = 0;
    uint8_t buf[2048];
    for (size_t i = 0; i < pfds.size(); ++i) {
        if (!(pfds[i].revents & POLLIN)) continue;
        if (!fds_.count(ids[i])) continue;   // closed by an earlier callback
        for (;;) {
            sockaddr_in a{};
            socklen_t alen = sizeof a;
            ssize_t n = ::recvfrom(pfds[i].fd, buf, sizeof buf, 0, reinterpret_cast<sockaddr*>(&a), &alen);
            if (n < 0) break;   // EAGAIN: drained (or a transient error)
            SocketId id = ids[i];
            // The callback may close sockets: stop if this one is gone.
            onRx(id, Endpoint{ntohl(a.sin_addr.s_addr), ntohs(a.sin_port)}, buf, size_t(n));
            ++delivered;
            if (!fds_.count(id)) break;
        }
    }
    return delivered;
}

uint32_t PosixDatagramIo::localIpToward(uint32_t destIp) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(destIp);
    a.sin_port = htons(9);
    uint32_t ip = 0;
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0) {
        sockaddr_in l{};
        socklen_t len = sizeof l;
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&l), &len) == 0) ip = ntohl(l.sin_addr.s_addr);
    }
    ::close(fd);
    return ip;
}

} // namespace natd
