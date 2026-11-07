// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/agent.hpp — one object for an application: discovery, endpoint
// checks, punch sessions and the streams over them (sans-I/O).
//
// The Agent puts together what every application otherwise writes around
// NatDiscovery, QuickCheck, PunchSession and Stream: the life of the profile,
// a queue and caps for the punch sessions, the move from punch to stream,
// keepalives, a graceful close that lingers, and the events the application
// reacts to. It owns no socket, thread or timer, like the rest of natd.
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
//   - it says when the public endpoint may have changed (checkEndpoint) and
//     what to do once it did (EndpointChanged); natd closes only the streams
//     whose path is gone;
//   - it supplies the stream transport (IStreamTransport: reliability, flow
//     and congestion control), which natd carries but never reads, and the
//     obfuscation of a session, if any (IDatagramObfuscator);
//   - it runs its own protocol over the stream bytes.
//
// Events are queued and read with nextEvent(): the Agent never calls back
// into the application, so nothing re-enters it from inside onDatagram() or
// poll(). The Agent is not thread-safe: an application that calls it from
// several threads holds one lock around every call.
#pragma once

#include "natd/discovery.hpp"
#include "natd/punch.hpp"
#include "natd/stream.hpp"

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
    size_t   maxSessions = 64;          // punches and streams together
    Duration linger{10000};             // a closed stream, until its FIN is through
    Duration checkReuse{60000};         // an endpoint check stands this long
    Duration keepalive{20000};          // stream keepalive (>= 15 s, RFC 8085 §3.5; jittered)
    PunchLimits limits;
    StreamConfig stream;                // deadAfter, maxPayload (socket, remote, token: per session)
};

using SessionId = uint32_t;             // 0 = none

enum class AgentEventType : uint8_t {
    ProfileReady,       // discovery has a first result: profile(), directPunchable()
    EndpointChanged,    // a check found another public endpoint: publicEndpoint()
    Incoming,           // a session from accept() is through: its stream is open
    Connected,          // a session from connect() is through: its stream is open
    Readable,           // read() has bytes (once, until a read())
    Writable,           // write() takes bytes again, after it returned 0
    Closed,             // the session is over, `error` says why; it comes after the
                        // bytes that arrived before the end were read. Then release().
};

enum class SessionError : uint8_t {
    None,               // the peer closed the stream gracefully
    Refused,            // no punch possible, or the caps were full
    TimedOut,           // the punch did not get through, or waited too long
    Reset,              // the stream died (no datagram for keepalive x deadAfter)
    AddressChanged,     // a check found our public endpoint changed (checkEndpoint)
};

struct AgentEvent {
    AgentEventType type;
    SessionId      session = 0;
    SessionError   error = SessionError::None;
};

// Counters, for the application's diagnostics.
struct AgentStats {
    uint64_t punchesStarted = 0, punchesQueued = 0, punchesEstablished = 0, punchesFailed = 0;
    uint64_t punchesRefused = 0;        // at once, or given up in the queue
    uint64_t streamsDead = 0, streamsAddressChanged = 0;
    uint64_t endpointChecks = 0, endpointChecksReused = 0, endpointChanges = 0;
};

const char* toString(AgentEventType);
const char* toString(SessionError);

enum class SessionPhase : uint8_t { None, Waiting, Punching, Open, Closing, Over };

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

class Agent {
public:
    // transport: the application's stream transport, one per session (see
    // stream.hpp). Required: without it connect() and accept() refuse.
    Agent(AgentConfig cfg, IDatagramIo& io, StreamTransportFactory transport);
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
    // obfuscated session is open).
    bool mayBeOurs(const uint8_t* data, size_t len) const;
    // Every datagram of the primary socket and of the sockets natd opened.
    // True when it is natd's: consumed, or in natd's or STUN's format (a late
    // answer, or a packet of a session already over), which the application
    // should then drop as well.
    bool onDatagram(SocketId, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);
    // Drive timers; returns the next time it wants to be called.
    TimePoint poll(TimePoint now);
    // When poll() is wanted next, also after the other calls: a datagram
    // (onDatagram) or a start, connect, accept, write, release or endpoint
    // check may want it earlier than the last poll() said (then: their now).
    TimePoint nextPoll() const;
    bool nextEvent(AgentEvent& out);

    // Profile
    bool profileReady() const;
    const NatProfile& profile() const;
    Endpoint publicEndpoint() const;          // invalid until ready
    // A direct punch (planDirect) can work: endpoint-independent mapping.
    bool directPunchable() const;
    // What a peer needs for planPunch, when the channel can carry it
    // (localEndpoints left to the application, see PeerInfo).
    PeerInfo localPeerInfo() const;

    // The public endpoint may have changed (the application lost a
    // connection that shows it, or a network change). One check at a time,
    // none within checkReuse of the last. closeIfChanged: the open streams
    // end (AddressChanged) if it did change. A dead stream checks by itself.
    void checkEndpoint(TimePoint now, bool closeIfChanged);

    // Sessions. connect() punches towards a peer that was sent an offer;
    // accept() answers an offer that came in. Both return 0 when refused at
    // once; otherwise the session is the application's until release(), and
    // ends with Connected or Incoming, or with Closed. A remote Endpoint
    // means planDirect (both sides endpoint-independent); a PeerInfo means
    // planPunch. accept() of a token already in progress returns 0.
    SessionId connect(const Endpoint& remote, const TxId& token, TimePoint now,
                      std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId connect(const PeerInfo& remote, const TxId& token, TimePoint now,
                      std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId accept(const Endpoint& remote, const TxId& token, TimePoint now,
                     std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);
    SessionId accept(const PeerInfo& remote, const TxId& token, TimePoint now,
                     std::shared_ptr<IDatagramObfuscator> obfuscator = nullptr);

    SessionPhase phase(SessionId) const;
    Endpoint remote(SessionId) const;
    // Stream I/O. write() takes what fits (0 = full: Writable follows);
    // read() returns 0 when nothing is there (Readable follows when there is).
    size_t write(SessionId, const uint8_t* data, size_t len, TimePoint now);
    size_t read(SessionId, uint8_t* out, size_t max);
    size_t readable(SessionId) const;
    // The application is done with the session: no more events for it. An
    // open stream closes gracefully (FIN once what was written is through,
    // at most `linger`); a punch in progress stops.
    void release(SessionId, TimePoint now);

    size_t sessionCount() const;
    const AgentStats& stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace natd
