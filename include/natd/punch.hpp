// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/punch.hpp — profile exchange, port prediction, punch planning and
// a sans-I/O punch session.
//
// Flow between two peers A and B (signalling channel provided by the caller):
//   1. each runs NatDiscovery and obtains a NatProfile;
//   2. just before punching, each refreshes its observation of the primary
//      socket mapping (QuickCheck::observed()) and sends PeerInfo to the other
//      together with an agreed session token and start time;
//   3. each calls planPunch(local, remote) — the function is symmetric, so the
//      two plans are complementary — and runs a PunchSession.
#pragma once

#include "natd/discovery.hpp"

#include <memory>
#include <vector>

namespace natd {

// ---------------------------------------------------------------------------
// Exchange format (versioned binary)
// ---------------------------------------------------------------------------
struct PeerInfo {
    NatProfile profile;
    Endpoint   observed;   // fresh mapping of the primary socket
    // Inside addresses of the primary socket (LAN or CGNAT side), at most
    // kMaxLocalEndpoints, filled by the caller (see localIpToward() in the
    // socket adapters). Used only when both peers have the same public IP.
    std::vector<Endpoint> localEndpoints;
};
constexpr size_t kMaxLocalEndpoints = 4;

std::vector<uint8_t>    encodePeerInfo(const PeerInfo&);
std::optional<PeerInfo> decodePeerInfo(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Prediction
// ---------------------------------------------------------------------------
struct PortCandidate {
    uint16_t port;
    double   probability;
};

// Candidates for the external port the NAT will assign to the *next* mapping
// of the primary socket (towards a new destination), in allocation order.
// sinceObserved: upper bound on the time elapsed since lastObserved was taken
// (age assumed uniform in [0, bound]); with a measured allocationRate the
// window widens accordingly. Probabilities are absolute:
// their sum is the chance that the next port is among the candidates (capped
// at 0.8 for sequential allocators when the rate is unknown).
std::vector<PortCandidate> predictNextPorts(const NatProfile&, const Endpoint& lastObserved,
                                            int maxCandidates, RandomBytesFn rnd = {},
                                            Duration sinceObserved = Duration(0));

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------
enum class PunchStrategy : uint8_t {
    Direct,          // both stable: send to the observed endpoint
    Predict,         // spray predicted ports of the remote side
    BirthdaySpray,   // we are the stable side: spray M ports of the remote block/range
    BirthdayListen,  // we are the hard side: open K sockets towards the remote endpoint
    Local,           // same public IP, no public path: inside addresses only
    Infeasible
};

struct PunchLimits {
    int      maxSockets = 64;      // K
    int      maxTargets = 256;     // M
    Duration budget{20000};        // total time spent punching
    double   minSuccess = 0.05;    // below this, return Infeasible
    // Hard cap on PUNCH packets one session may send, whatever the plan
    // (ACKs excluded: each answers a packet received from the peer's IP).
    int      maxPackets = 2000;
    // Upper bound on the time between the fresh observation in PeerInfo and
    // the agreed start (age assumed uniform in [0, bound]): other subscribers
    // keep taking ports meanwhile (allocationRate).
    Duration observationAge{1000};
    // Upper bound on the NAT mappings this side creates in one session (each
    // takes a port of the subscriber's CGN quota, RFC 6888 REQ-4): limits K,
    // and M when our mapping is address+port dependent (one mapping per
    // target). The estimate follows the reduced plan. 0 = no cap.
    int      maxMappings = 128;
    // planUnknownPeer: the block a peer of unknown NAT may take its ports
    // from (an aligned block around the endpoint seen). Mobile CGNs give each
    // subscriber blocks of ports (RFC 6888 port block allocation): 128 ports
    // measured on one; at most maxTargets.
    uint16_t unknownBlock = 128;
    // planUnknownPeer: the ports past the endpoint seen that are sprayed too,
    // beyond the end of the block: a sequential allocator's next mapping.
    uint16_t unknownAhead = 64;
};

struct PunchPlan {
    PunchStrategy         strategy = PunchStrategy::Infeasible;
    int                   localSockets = 1;     // including the primary socket
    std::vector<Endpoint> targets;              // all on the remote observed IP
    // BirthdaySpray: every round sprays all the targets (planUnknownPeer),
    // else each round sprays a new slice. A hard side that opens its mapping
    // after our first round is still met by the next one.
    bool                  wholeRange = false;
    // wholeRange: the rounds before this one send to targets[0] alone.
    int                   sprayFromRound = 0;
    Duration              sendInterval{4000};   // retransmit period (>= 3 s, RFC 8085 §3.1.3, see planPunch)
    Duration              packetSpacing{2};     // pacing inside a round
    Duration              budget{20000};
    Duration              keepalive{15000};     // once established (>= 15 s, RFC 8085 §3.5)
    int                   maxPackets = 2000;    // hard cap, see PunchLimits
    // Public path only. Local: 0 (unknown, depends on the LAN/carrier).
    double                estimatedSuccess = 0;
    // Same public IP on both sides (same NAT). The public path then needs
    // hairpinning; the remote inside addresses are tried in parallel from
    // the primary socket, and packets from private/CGNAT sources are accepted.
    bool                  sameNat = false;
    std::vector<Endpoint> localTargets;         // remote inside addresses (private/CGNAT only)
};

const char* toString(PunchStrategy);

PunchPlan planPunch(const PeerInfo& local, const PeerInfo& remote, const PunchLimits& = {});

// Plan when the signalling channel carries only the remote endpoint, not a
// PeerInfo (for instance a relay that forwards an address and a port). Both
// sides must have endpoint-independent mapping (Predictability::Stable): the
// remote endpoint, observed by a third party, is then the one the peer's NAT
// uses towards us. Infeasible when our own mapping is not Stable. The peer is
// assumed Stable too; when it is not, the session fails within the budget.
//   punch every punchInterval of our profile for 15 s, keepalive from our
//   profile. Both follow RFC 8085 (at least 3 s and 15 s) unless the
//   profile measured a shorter binding lifetime (a NAT below RFC 4787 REQ-5).
PunchPlan planDirect(const NatProfile& local, const Endpoint& remote, const PunchLimits& = {});

// Plan when the signalling channel carries only the remote endpoint and
// nothing tells whether the peer's mapping is endpoint-independent,
// sequential (Predictable) or random inside a block (Bounded, as on mobile
// CGNs). The peer's port then is the one the channel saw (Stable), a port a
// little past it (Predictable) or a new port of the block around it
// (Bounded). The endpoint the channel saw should be a fresh mapping of the
// peer's primary socket, as the one of a request it has just sent.
//   We are Stable: BirthdaySpray. The first round goes to the endpoint alone
//   (a Stable peer answers as with planDirect); every later round goes to it,
//   to the whole aligned block of PunchLimits::unknownBlock ports around it
//   and to the PunchLimits::unknownAhead ports past it (sprayFromRound 1,
//   wholeRange).
//   We are Predictable or Bounded: BirthdayListen, the endpoint from the
//   primary socket alone; the peer needs no port of ours.
//   Otherwise Infeasible: two sides that both open a new port each cannot
//   find each other without sockets or ports beyond these.
// With a port block per subscriber the spray reaches only the peer's own
// mappings; behind a NAT without blocks it can reach other subscribers of the
// same public IP, who drop it (the token is unknown to them).
PunchPlan planUnknownPeer(const NatProfile& local, const Endpoint& remote, const PunchLimits& = {});

// 96-bit session token from data both peers already hold (for instance
// fields of the relayed request): SHA-256 of the data, truncated. It tells
// sessions apart and keeps out packets from anyone who did not see the data:
// with a random nonce in it that only the signalling channel carries, an
// off-path sender has to guess 96 bits (a TCP connection: 32). It is no
// authentication: whoever sees the signalling can derive it, so what an
// application runs over the path with it is as safe as an unencrypted TCP
// connection, no more.
TxId sessionTokenFrom(const uint8_t* data, size_t len);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
enum class PunchState : uint8_t { Waiting, Punching, Established, Failed };

struct PunchSessionConfig {
    PunchPlan plan;
    TxId      token{};             // agreed through signalling
    TimePoint startAt{};           // agreed start time (local clock)
    uint32_t  remoteIp = 0;        // packets from other IPs are ignored
    SocketId  primarySocket = 0;
    // Optional: transform of every datagram of the session (null: plain natd
    // format).
    std::shared_ptr<IDatagramObfuscator> obfuscator;
};

class PunchSession {
public:
    PunchSession(PunchSessionConfig cfg, IDatagramIo& io);
    ~PunchSession();

    bool onDatagram(SocketId, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);
    TimePoint poll(TimePoint now);

    PunchState state() const;
    SocketId   establishedSocket() const;   // valid when Established
    Endpoint   remoteEndpoint() const;      // valid when Established
    Duration   keepalive() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace natd
