// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/reflector.hpp — reflector role (sans-I/O).
//
// A reflector answers PROBE_REQ messages telling the sender which external
// endpoint it observed. Any node with a reachable public endpoint can run it.
//
// Safety rules enforced here:
//   - replies only ever go to the observed source of a request;
//   - FORWARD_REQ is accepted only from configured partner IPs, and its target
//     is the observed source chosen by the partner, never client data;
//   - the replies to one request total fewer bytes than the request
//     (at most 4 x 28 bytes against 128);
//   - every reply declares what the reflector can do (PROBE_RESP caps):
//     whether its partner answered a recent check and whether another local
//     port can send, so that a client never reads a missing reply caused by
//     the reflector as filtering by its NAT;
//   - per-source-IP token bucket and caps on pending delayed replies per
//     endpoint, per IP and in total. A delayed reply that cannot be queued is
//     answered at once with kind Refused, so the client does not mistake it
//     for an expired binding.
//
// Many subscribers share one public IP behind a CGNAT: the per-IP limits are
// sized for several concurrent discoveries from the same address, the
// per-endpoint cap stops one socket from filling the IP quota.
#pragma once

#include "natd/types.hpp"

#include <memory>
#include <vector>

namespace natd {

class IReflectorIo {
public:
    virtual ~IReflectorIo() = default;
    // Send from the reflector's local socket number portIndex.
    virtual void send(uint32_t portIndex, const Endpoint& to, const uint8_t* data, size_t len) = 0;
};

struct ReflectorConfig {
    uint32_t portCount = 1;                 // local sockets 0..portCount-1
    std::vector<Endpoint> partners;         // partner reflectors (FORWARD target and allowlist)
    double   ratePerIp = 500.0;             // requests per second per source IP
    double   burstPerIp = 2000.0;           // ~10 full discoveries at once
    uint32_t maxPendingPerEndpoint = 4;     // per IP:port; >= 1 + client retries
    uint32_t maxPendingPerIp = 1024;        // ~50 lifetime measurements at once
    uint32_t maxPendingTotal = 100000;
    uint32_t maxDelayMs = 300000;
    size_t   maxTrackedIps = 100000;
    // Partner check: a PROBE_REQ to the first partner every interval; the
    // partner counts as reachable while its last answer is younger than
    // partnerTimeout. 0 disables the check (caps then leave it undeclared).
    Duration partnerCheckInterval{5000};
    Duration partnerTimeout{16000};
};

struct ReflectorStats {
    uint64_t requests = 0, replies = 0, forwardsSent = 0, forwardsServed = 0;
    uint64_t droppedRate = 0, droppedInvalid = 0, droppedNotPartner = 0, droppedPending = 0;
    uint64_t refused = 0;   // Refused replies sent (pending caps reached)
    uint64_t partnerChecks = 0, partnerAnswers = 0;
};

class Reflector {
public:
    Reflector(ReflectorConfig cfg, IReflectorIo& io);
    ~Reflector();

    // Returns true if the datagram was a natd message.
    bool onDatagram(uint32_t portIndex, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);
    TimePoint poll(TimePoint now);

    const ReflectorStats& stats() const;
    bool partnerAlive(TimePoint now) const;   // last partner check answered recently

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace natd
