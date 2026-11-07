// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/discovery.hpp — NAT behavior discovery (sans-I/O).
//
// Input : two partnered natd reflectors with distinct IPs, of which only the
//         first is contacted by clients, on one public UDP port; a list of
//         public STUN servers used as mirrors; the caller's primary socket.
//         See DiscoveryConfig.
// Output: a NatProfile whose essential fields are
//           - predictability   (return code)
//           - publicEndpoint   (external IP:port of the primary socket)
//           - punchInterval    (retransmit period while punching)
//           - keepaliveInterval(refresh period once the path is up)
//
// Result is delivered in two stages:
//   Provisional : mapping/filtering/allocation known, conservative timers
//                 (punch 4 s, keepalive 15 s). Usable immediately.
//   Final       : binding lifetime measured in background (up to minutes),
//                 timers relaxed accordingly. resultVersion() increments.
#pragma once

#include "natd/types.hpp"

#include <memory>
#include <vector>

namespace natd {

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------
struct ReflectorInfo {
    uint32_t              ip = 0;
    std::vector<uint16_t> ports;   // ports clients send to (see DiscoveryConfig::reflectors)
};

// A public STUN server, resolved. altPort: a second port on the same IP that
// answers too (0 = none), see stun::ServerEntry.
struct StunEndpoint {
    Endpoint ep;
    uint16_t altPort = 0;
};

struct AdvancedConfig {
    // Retransmission (RFC 8489 §6.2.1, RFC 8085 §3.1.3): the first resend
    // after RTO, then doubling. RTO starts at `rto` (>= 500 ms) and follows
    // the measured round-trip time of each server (RFC 6298, Karn), cached
    // for 10 minutes. A STUN transaction makes stunRc requests and fails
    // stunRm x RTO after the last one; a probe to the natd reflector makes
    // 1 + probeRetries requests and fails one doubled RTO after the last.
    Duration rto{500};
    int      stunRc = 7;
    int      stunRm = 16;
    int      probeRetries = 2;
    // At most this many transactions outstanding towards one server IP
    // (RFC 8489 §6.2); the delayed lifetime replies are not counted.
    int      maxOutstanding = 10;
    // A phase stops waiting for STUN transactions it no longer needs (the
    // mapping is decided, the samples are enough) once each of them has
    // made this many requests without an answer; with an undecided mapping
    // the next STUN servers are asked meanwhile, in parallel.
    int      stunStaleAfter = 4;
    Duration probeTimeout{800};        // extra wait after a lifetime test delay
    Duration probeSpacing{5};          // pacing between outgoing probes
    Duration forwardGrace{1500};       // extra wait for partner replies

    // Adaptive sample sizes (each step runs only if the previous was ambiguous)
    std::vector<int> allocNewSocketSteps{16, 32, 64};
    std::vector<int> allocSameSocketSteps{8};   // round 0 includes the mapping samples
    // STUN servers in the mapping test: this many two-port servers (both
    // ports) when R0 has a single port, otherwise this many servers as the
    // second IP. One answer is enough, the others are extra same-socket
    // samples and cover servers that do not answer.
    int      mappingStunProbes = 2;
    // Extra fresh destinations per same-socket round, so that a server that
    // does not answer costs no sample.
    int      allocSameSpare = 2;
    double   confidenceTarget = 0.8;
    Duration roundGap{1000};
    // Sequential allocators: one more mapping after driftGap measures how
    // many ports other subscribers take per second (allocationRate).
    Duration driftGap{2000};

    bool     sequentialLocalPorts = true;   // bind base, base+1, ... when possible
    uint16_t localPortBase = 0;              // 0 -> OS-assigned

    uint32_t maxBlockSize = 4096;            // larger span => full range
    uint32_t blockAlignment = 64;

    // Binding lifetime grid (seconds). All values are tested in parallel on
    // fresh sockets, so the measurement lasts max(grid) + timeout.
    std::vector<int> lifetimeGridSec{5, 10, 15, 20, 30, 45, 60, 90, 120, 180};

    // Timers
    Duration defaultPunchInterval{4000};     // < 10 s worst case observed
    Duration defaultKeepalive{15000};        // RFC 8085 §3.5: >= 15 s
    Duration minInterval{1000};
    Duration maxKeepalive{120000};

    // Upper bound on the NAT mappings one discovery may create (each takes
    // a port of the subscriber's CGN quota, RFC 6888 REQ-4). Counted as
    // (socket, destination) pairs, an upper bound whatever the mapping
    // behaviour. The extra sampling rounds are shortened or skipped to stay
    // within it, keeping room for the lifetime test. Typical use is 38 (EIM)
    // to 50 (APDM); the worst case without a cap is 145. 0 = no cap.
    int maxMappings = 100;

    RandomBytesFn randomBytes;               // empty -> defaultRandomBytes()
};

struct DiscoveryConfig {
    // Reflector pairs: entries 0-1 are the first pair (R0, R1), 2-3 the
    // second, and so on. The discovery uses the first usable pair and moves
    // to the next when its R0 does not answer the mapping test. Without any
    // pair answering, a partial profile comes from the STUN servers
    // (NatDetails::reflectorReached false); UdpBlocked only when nothing
    // answers at all.
    // Empty (no reflector at all) with at least 2 STUN servers: the same
    // partial profile from the start, without waiting for reflectors.
    // In each pair, two natd reflectors with distinct public IPs, partners
    // of each other.
    //   reflectors[0] (R0): >= 1 port, the only ones clients send to.
    //     Filtering (request to R0:p0, replies from R0's other socket and from
    //     R1 through the partner link), allocation from new sockets, drift and
    //     lifetime use R0:p0. The reflector itself must run 2 sockets (the
    //     reply "from another port" of the filtering test), but the second
    //     one only sends: its port can stay closed to inbound traffic. With
    //     a second listed port, R0:p0 vs R0:p1 is the mapping test's "same
    //     IP, other port" pair; with one port, two-port STUN servers are.
    //   reflectors[1] (R1): its IP is needed (partner replies come from it);
    //     ports may be empty, so that R1 only accepts traffic from R0 (its
    //     firewall can drop everything else). If ports are given, R1:p0 is
    //     the mapping probe towards a second IP and the remaining ports are
    //     same-socket destinations, as in the reflector-only deployment.
    // Minimum with no loss of function: 1 public port on R0 plus STUN servers
    // of which at least one answers on two ports of its IP (or 2 public
    // ports on R0 plus any STUN servers, or 8 reflector ports and no STUN).
    std::vector<ReflectorInfo> reflectors;
    // Public STUN servers, resolved, in preference order (see natd/stun.hpp).
    // Used as mirrors only, in the mapping test (second IP when R1 has no
    // ports; same IP and other port, from servers with altPort, when R0 has
    // one port) and as fresh destinations for the same-socket sample
    // (allocSameSocketSteps[0] minus the mapping samples, plus
    // allocSameSpare). About 10 are enough, 2 of them with altPort; servers
    // that do not answer, or answer with an IP other than the reflector's,
    // are ignored. Without any answering two-port server (and with one R0
    // port) address- and address+port-dependent mapping cannot be told apart:
    // a dependent mapping is then reported as AddressPortDependent, the
    // conservative choice (same-socket sampling, one mapping per target).
    std::vector<StunEndpoint> stunServers;
    SocketId primarySocket = 0;              // caller's socket, never closed
    bool     measureLifetime = true;
    AdvancedConfig advanced;
};

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
enum class Predictability : uint8_t {
    Stable = 0,      // endpoint-independent mapping: reuse publicEndpoint
    Predictable = 1, // dependent mapping, next port computable
    Bounded = 2,     // dependent mapping, random inside a known port block
    Unpredictable = 3, // dependent mapping, random over the whole range
    UdpBlocked = 4,  // neither a reflector nor a STUN server answered
    Inconclusive = 5 // not enough consistent data
};

enum class MappingBehavior : uint8_t { Unknown, EndpointIndependent, AddressDependent, AddressPortDependent };
enum class FilteringBehavior : uint8_t { Unknown, EndpointIndependent, AddressDependent, AddressPortDependent };
enum class AllocationPattern : uint8_t { Unknown, PortPreserving, Sequential, SequentialNoisy, RandomInBlock, RandomFull };
// Hairpinning: a packet sent to our own public IP comes back in through the
// NAT. Needed when two peers sit behind the same NAT (same public IP).
//   External: the receiver sees the sender's public endpoint (RFC 4787 REQ-9)
//   Internal: the receiver sees the sender's inside address
// A negative result is conclusive only with endpoint-independent mapping;
// otherwise it stays Unknown.
enum class HairpinBehavior : uint8_t { Unknown, None, External, Internal };

struct PortBlock {
    uint16_t base = 0;
    uint16_t size = 0;
    bool contains(uint16_t p) const { return size && p >= base && uint32_t(p) < uint32_t(base) + size; }
};

struct AllocationInfo {
    AllocationPattern pattern = AllocationPattern::Unknown;
    int32_t  delta = 0;          // Sequential*: typical step
    double   jitter = 0;         // stddev of steps
    PortBlock block;             // RandomInBlock
    int      samples = 0;
    double   confidence = 0;
};

struct NatDetails {
    MappingBehavior   mapping = MappingBehavior::Unknown;
    // A same-IP, other-port pair was answered: port dependence measured. When
    // false, a dependent mapping is reported as AddressPortDependent without
    // proof (conservative; see DiscoveryConfig::stunServers).
    bool mappingPortTested = false;       // local only, not in PeerInfo
    // A natd reflector answered. False: no reflector pair reachable, but
    // STUN servers agreed on the public address; mapping and allocation come
    // from STUN, filtering, hairpinning and lifetime stay unknown (local only).
    bool reflectorReached = false;
    int  restarts = 0;   // runs started over after a network change (local only)
    FilteringBehavior filtering = FilteringBehavior::Unknown;
    // The reflector declared it could send the partner reply (other IP) /
    // the other-port reply. When false, AddressDependent means "address
    // dependent or more permissive" and AddressPortDependent "address or
    // address+port dependent": the stricter level, never a wrong one.
    bool filteringPartnerTested = false;
    bool filteringPortTested = false;     // local only, not in PeerInfo
    AllocationInfo sameSocket;   // same socket -> new destinations (punch path)
    AllocationInfo newSocket;    // new sockets -> same destination (birthday)
    bool sameSocketFromNewSocket = false;  // fallback used (ADM, too few dests)
    bool parityPreserved = false;
    bool behindNat = true;
    bool multiplePublicIps = false;
    HairpinBehavior hairpin = HairpinBehavior::Unknown;
    std::optional<Duration> singlePacketLifetime;  // lower bound, outbound-only binding
    std::optional<Duration> bidirectionalLifetime; // lower bound, after inbound
    bool lifetimeAtLeast = false;   // every grid value succeeded
    // Ports per second taken by other subscribers of a sequential allocator,
    // measured over driftGap. Assumes one allocator shared by all sockets.
    std::optional<double> allocationRate;
};

struct NatProfile {
    Predictability predictability = Predictability::Inconclusive;
    Endpoint publicEndpoint;
    Duration punchInterval{4000};
    Duration keepaliveInterval{15000};
    bool     lifetimeMeasured = false;
    double   confidence = 0;
    NatDetails details;
};

enum class DiscoveryState : uint8_t { Idle, Running, Provisional, Final, Cancelled };

const char* toString(Predictability);
const char* toString(MappingBehavior);
const char* toString(FilteringBehavior);
const char* toString(AllocationPattern);
const char* toString(HairpinBehavior);

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------
class NatDiscovery {
public:
    NatDiscovery(DiscoveryConfig cfg, IDatagramIo& io);
    ~NatDiscovery();
    NatDiscovery(const NatDiscovery&) = delete;
    NatDiscovery& operator=(const NatDiscovery&) = delete;

    void start(TimePoint now);
    void cancel();

    // Deliver every inbound datagram received on the primary socket or on a
    // socket opened by this object. Returns true if the datagram was consumed.
    bool onDatagram(SocketId, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);

    // Drive timers and sending. Returns the next time it wants to be called.
    TimePoint poll(TimePoint now);

    DiscoveryState state() const;
    const NatProfile& result() const;     // meaningful in Provisional/Final
    uint32_t resultVersion() const;       // increments on each update

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Quick re-validation of a profile (network change, IP change, block rotation)
// ---------------------------------------------------------------------------
enum class QuickCheckResult : uint8_t { Pending, Valid, Changed, Unreachable };
const char* toString(QuickCheckResult);

class QuickCheck {
public:
    QuickCheck(const DiscoveryConfig& cfg, const NatProfile& expected, IDatagramIo& io);
    ~QuickCheck();
    void start(TimePoint now);
    bool onDatagram(SocketId, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);
    TimePoint poll(TimePoint now);
    QuickCheckResult result() const;
    Endpoint observed() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Classifier exposed for testing and offline analysis.
// ports: external ports in allocation order; localPorts optional (same size).
AllocationInfo classifyAllocation(const std::vector<uint16_t>& ports,
                                  const std::vector<uint16_t>& localPorts,
                                  const AdvancedConfig& cfg);

} // namespace natd
