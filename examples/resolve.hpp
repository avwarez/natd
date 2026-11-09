// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// Name resolution for the example tools, over natd::resolveIpv4 (natd/resolve.hpp).
// On Windows, Winsock must be started first (PlatformDatagramIo does it).
#pragma once

#include "natd/resolve.hpp"
#include "natd/stun.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace natd::examples {

using natd::resolveIpv4;

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
