// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/agent.hpp — one object for an application: discovery, endpoint
// checks and punch sessions (sans-I/O).
//
// The Agent puts together what every application otherwise writes around
// NatDiscovery, QuickCheck and PunchSession: the life of the profile, a
// queue and caps for the punch sessions, and the events the application
// reacts to. It owns no socket, thread or timer, like the rest of natd.
//
// natd ends where the hole is open. A punch that gets through hands the
// application a PunchResult: the socket, both endpoints, how often the path
// must carry something to stay open, and how long our mapping lives. What
// goes over the path, how it is kept open and when it ends are the
// application's: natd never sees its datagrams again (but for answering the
// peer's last PUNCH packets for a moment, see takeResult()).
//
// Split of responsibilities. natd knows how; the application decides
// whether, when and with whom:
//   - the application owns the sockets (IDatagramIo), resolves the STUN
//     server names, chooses when to start discovery, and passes every
//     datagram of its primary socket and of the sockets natd opened to
//     onDatagram() before its own parsing;
//   - it decides when a punch is worth it, carries the offer (encodeOffer)
//     over its own signalling channel, and chooses the key the session token
//     is derived from (tokenFrom); natd never reads the channel;
//   - it says when the public endpoint may have changed (checkEndpoint: a
//     lost connection, a path of its own that died) and what to do once it
//     did (EndpointChanged);
//   - it runs whatever it likes over the punched path, and the obfuscation
//     of the punch, if any (IDatagramObfuscator).
//
// Events are queued and read with nextEvent(): the Agent never calls back
// into the application, so nothing re-enters it from inside onDatagram() or
// poll(). The Agent is not thread-safe: an application that calls it from
// several threads holds one lock around every call.
#pragma once

#include "natd/discovery.hpp"
#include "natd/punch.hpp"

#include <array>
#include <memory>
#include <optional>
#include <vector>

namespace natd {

struct AgentConfig {
    // primarySocket is the application's socket; stunServers and reflectors
    // as for NatDiscovery. The STUN list may also be given later, to start().
    DiscoveryConfig discovery;
    // Each client its own order of the STUN servers, so that no public server
    // takes everybody's first request.
    bool     shuffleStunServers = true;
    // Random bytes for that order; empty -> defaultRandomBytes(). Not the
    // discovery's own source: the two would draw the same sequence.
    RandomBytesFn randomBytes;

    size_t   maxPunches = 4;            // punch sessions at once
    size_t   maxWaiting = 16;           // requests waiting for a free punch session
    Duration punchWait{10000};          // how long one may wait (the other side punches for 15 s)
    Duration checkReuse{60000};         // an endpoint check stands this long
    PunchLimits limits;
};

using SessionId = uint32_t;             // 0 = none

enum class AgentEventType : uint8_t {
    ProfileReady,       // discovery has a first result: profile(), directPunchable()
    EndpointChanged,    // a check found another public endpoint: publicEndpoint()
    EndpointChecked,    // an endpoint check ended: lastCheckResult() (Valid, Changed:
                        // EndpointChanged follows, Unreachable)
    Punched,            // a session from connect() or accept() got through: takeResult()
    PunchFailed,        // it did not, `error` says why; the session is gone
};

enum class PunchError : uint8_t {
    None,
    Refused,            // no punch possible, or the caps were full
    TimedOut,           // the punch did not get through, or waited too long
};

struct AgentEvent {
    AgentEventType type;
    SessionId      session = 0;
    PunchError     error = PunchError::None;
};

// Counters, for the application's diagnostics.
struct AgentStats {
    uint64_t punchesStarted = 0, punchesQueued = 0, punchesEstablished = 0, punchesFailed = 0;
    uint64_t punchesRefused = 0;        // at once, or given up in the queue
    uint64_t endpointChecks = 0, endpointChecksReused = 0, endpointChanges = 0;
};

const char* toString(AgentEventType);
const char* toString(PunchError);

// What a punch hands over: from here the path is the application's.
struct PunchResult {
    // The punched socket: the primary one, or one natd opened for the punch,
    // which is now the application's (it closes it with IDatagramIo::closeSocket).
    SocketId  socket = 0;
    Endpoint  local;               // that socket's local endpoint
    // The peer's endpoint the punch got through to: send there, and take on
    // that socket only what comes from there.
    Endpoint  remote;
    // Send something on the path at least this often while it is idle, so
    // that both NATs keep its mappings and filters (RFC 4787 REQ-6, RFC 8085
    // §3.5: at least 15 s, shorter when our profile measured a shorter
    // binding lifetime).
    Duration  keepalive{15000};
    // How long our mapping survives with nothing sent (mappingLifetime() of
    // our profile); none when not known.
    std::optional<Duration> mappingLifetime;
    PunchStrategy strategy = PunchStrategy::Direct;
    bool      incoming = false;    // from accept()
    TxId      token{};             // the session's
};

enum class SessionPhase : uint8_t { None, Waiting, Punching, Punched };

// The offer an application carries over its signalling channel to ask for a
// punch: "NATD", a version, an application-defined kind and a random nonce
// (little-endian). The token of the session is tokenFrom(key, nonce), with a
// key both peers know.
constexpr size_t  kOfferSize = 14;
constexpr uint8_t kOfferVersion = 1;
struct Offer {
    uint8_t  kind = 0;
    uint64_t nonce = 0;
};
std::array<uint8_t, kOfferSize> encodeOffer(const Offer&);
std::optional<Offer> decodeOffer(const uint8_t* data, size_t len);
TxId tokenFrom(const uint8_t* key, size_t keyLen, uint64_t nonce);


// What the application knows of a peer's NAT, for connect()/accept() with an
// Endpoint. Stable: its mapping is endpoint-independent, the endpoint the
// channel saw is the one to punch (planDirect). Unknown: the channel says
// nothing (planUnknownPeer: a Stable side also sprays the ports around the
// endpoint after a first direct round; a Predictable or Bounded side punches
// the endpoint from its primary socket).
enum class PeerNat : uint8_t { Stable, Unknown };

class Agent {
public:
    Agent(AgentConfig cfg, IDatagramIo& io);
    ~Agent();
    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    // Discovery on the primary socket. With servers, they replace the
    // configured STUN list (resolved by the application, off its main thread
    // if DNS blocks). Once only.
    void start(TimePoint now, std::optional<std::vector<StunEndpoint>> stunServers = std::nullopt);
    bool started() const;

    // Cheap test for a socket shared with the application's own protocol:
    // false means the datagram is surely not natd's (STUN, natd format, or an
    // obfuscated punch is on).
    bool mayBeOurs(const uint8_t* data, size_t len) const;
    // Every datagram of the primary socket and of the sockets natd opened.
    // True when it is natd's: consumed, or in natd's or STUN's format (a late
    // answer, or a packet of a session already over), which the application
    // should then drop as well.
    bool onDatagram(SocketId, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);
    // Drive timers; returns the next time it wants to be called.
    TimePoint poll(TimePoint now);
    // When poll() is wanted next, also after the other calls: a datagram
    // (onDatagram) or a start, connect, accept, cancel or endpoint check may
    // want it earlier than the last poll() said (then: their now).
    TimePoint nextPoll() const;
    bool nextEvent(AgentEvent& out);

    // Profile
    bool profileReady() const;
    const NatProfile& profile() const;
    Endpoint publicEndpoint() const;          // invalid until ready
    // A direct punch (planDirect) can work: endpoint-independent mapping.
    bool directPunchable() const;
    // A punch with a peer of unknown NAT (PeerNat::Unknown) can work: our
    // mapping is endpoint-independent, sequential (Predictable) or random
    // inside a block (Bounded).
    bool punchable() const;
    // What a peer needs for planPunch, when the channel can carry it
    // (localEndpoints left to the application, see PeerInfo).
    PeerInfo localPeerInfo() const;

    // The public endpoint may have changed (the application lost a
    // connection that shows it, a punched path of its went silent, a network
    // change). One check at a time, none within checkReuse of the last.
    void checkEndpoint(TimePoint now);
    // The result of the last check that ended (Pending: none yet), and
    // whether one is running now.
    QuickCheckResult lastCheckResult() const;
    bool checking() const;

    // Sessions. connect() punches towards a peer that was sent an offer;
    // accept() answers an offer that came in. Both return 0 when refused at
    // once; otherwise the session ends with Punched or PunchFailed. A remote
    // Endpoint means planDirect (both sides endpoint-independent); a
    // PeerInfo means planPunch. accept() of a token already in progress, or
    // punched a moment ago, returns 0.
    SessionId connect(const Endpoint& remote, const TxId& token, TimePoint now,
                      std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId connect(const PeerInfo& remote, const TxId& token, TimePoint now,
                      std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId accept(const Endpoint& remote, const TxId& token, TimePoint now,
                     std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId accept(const PeerInfo& remote, const TxId& token, TimePoint now,
                     std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    // With what the application knows of the peer's NAT: PeerNat::Stable as
    // the calls above, PeerNat::Unknown with planUnknownPeer (refused unless
    // punchable()). A Predictable or Bounded side punches from the primary
    // socket alone.
    SessionId connect(const Endpoint& remote, PeerNat nat, const TxId& token, TimePoint now,
                      std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId accept(const Endpoint& remote, PeerNat nat, const TxId& token, TimePoint now,
                     std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);

    SessionPhase phase(SessionId) const;
    Endpoint remote(SessionId) const;
    // After Punched: the path, once. natd then keeps only the punch, to
    // answer the peer's PUNCH packets on that path until the punch budget
    // ends (its last ACK may have been lost); the session is no longer
    // listed (phase None).
    std::optional<PunchResult> takeResult(SessionId, TimePoint now);
    // The application gives up on a session (waiting, punching, or punched
    // and not taken): no more events, and the sockets natd opened for it are
    // closed.
    void cancel(SessionId, TimePoint now);

    size_t sessionCount() const;              // waiting, punching, or punched and not taken
    const AgentStats& stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace natd
