// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// Name resolution for the example tools (the library itself does no I/O).
// On Windows, Winsock must be started first (PlatformDatagramIo does it).
#pragma once

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

#include "natd/stun.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace natd::examples {

// First IPv4 address of host (dotted or name); 0 if none.
inline uint32_t resolveIpv4(const std::string& host) {
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

struct Resolved {
    stun::ServerEntry entry;
    Endpoint ep;
};

// Resolves entries in order, one address per host, skipping duplicates and
// failures, until max endpoints are collected (0 = all).
inline std::vector<Resolved> resolveServers(const std::vector<stun::ServerEntry>& list, size_t max = 0) {
    std::vector<Resolved> out;
    for (auto& e : list) {
        if (max && out.size() >= max) break;
        uint32_t ip = resolveIpv4(e.host);
        if (!ip) continue;
        Endpoint ep{ip, e.port};
        bool dup = false;
        for (auto& r : out) dup |= r.ep == ep;
        if (!dup) out.push_back({e, ep});
    }
    return out;
}

inline bool readFile(const std::string& path, std::string& text) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    text = ss.str();
    return true;
}

} // namespace natd::examples
