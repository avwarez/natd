// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/resolve.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <mutex>
#include <thread>

namespace natd {

uint32_t resolveIpv4(const std::string& host) {
    if (auto ip = parseIp(host)) return *ip;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return 0;
    uint32_t ip = 0;
    for (addrinfo* a = res; a && !ip; a = a->ai_next)
        if (a->ai_family == AF_INET) ip = ntohl(reinterpret_cast<sockaddr_in*>(a->ai_addr)->sin_addr.s_addr);
    freeaddrinfo(res);
    return ip;
}

std::vector<StunEndpoint> resolveStunServers(const std::vector<stun::ServerEntry>& list, size_t max) {
    std::vector<StunEndpoint> out;
    for (const auto& e : list) {
        if (max && out.size() >= max) break;
        const uint32_t ip = resolveIpv4(e.host);
        if (!ip) continue;
        const Endpoint ep{ip, e.port};
        if (std::none_of(out.begin(), out.end(), [&](const StunEndpoint& s) { return s.ep == ep; }))
            out.push_back({ep, e.altPort});
    }
    return out;
}

struct StunResolver::State {
    mutable std::mutex m;
    bool done = false;
    std::vector<StunEndpoint> servers;
};

StunResolver::StunResolver(std::vector<stun::ServerEntry> list, size_t max) : st_(std::make_shared<State>()) {
    std::thread([st = st_, list = std::move(list), max] {
        std::vector<StunEndpoint> found = resolveStunServers(list, max);
        std::lock_guard<std::mutex> lock(st->m);
        st->servers = std::move(found);
        st->done = true;
    }).detach();
}

StunResolver::~StunResolver() = default;

bool StunResolver::ready() const {
    std::lock_guard<std::mutex> lock(st_->m);
    return st_->done;
}

std::vector<StunEndpoint> StunResolver::servers() const {
    std::lock_guard<std::mutex> lock(st_->m);
    return st_->servers;
}

} // namespace natd
