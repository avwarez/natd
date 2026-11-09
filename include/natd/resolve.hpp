// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/resolve.hpp — name resolution of STUN servers, for applications that
// do not bring their own. Like the socket adapters (posix_io, winsock_io) it
// is a platform helper outside the sans-I/O core: getaddrinfo, which blocks.
// On Windows, Winsock must be started first (WinsockDatagramIo does it).
#pragma once

#include "natd/discovery.hpp"
#include "natd/stun.hpp"

#include <memory>
#include <string>
#include <vector>

namespace natd {

// First IPv4 address of host (dotted or name), host order; 0 if none.
uint32_t resolveIpv4(const std::string& host);

// The servers of list in order, one address per host, without duplicates
// or names that do not resolve, until max endpoints (0 = all). Blocks.
std::vector<StunEndpoint> resolveStunServers(const std::vector<stun::ServerEntry>& list = stun::builtinServers(),
                                             size_t max = 0);

// resolveStunServers() on a thread of its own, started by the constructor,
// so that the caller's thread never waits for DNS: ready() once done, then
// servers() (Agent::start). The thread keeps what it needs, so destroying
// the resolver never waits either.
class StunResolver {
public:
    explicit StunResolver(std::vector<stun::ServerEntry> list = stun::builtinServers(), size_t max = 0);
    ~StunResolver();
    StunResolver(const StunResolver&) = delete;
    StunResolver& operator=(const StunResolver&) = delete;

    bool ready() const;
    std::vector<StunEndpoint> servers() const;   // empty until ready()

private:
    struct State;
    std::shared_ptr<State> st_;
};

} // namespace natd
