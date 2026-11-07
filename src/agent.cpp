// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/agent.hpp"

#include "natd/protocol.hpp"
#include "natd/stun.hpp"

#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <random>

namespace natd {

const char* toString(AgentEventType t) {
    switch (t) {
        case AgentEventType::ProfileReady:    return "ProfileReady";
        case AgentEventType::EndpointChanged: return "EndpointChanged";
        case AgentEventType::Incoming:        return "Incoming";
        case AgentEventType::Connected:       return "Connected";
        case AgentEventType::Readable:        return "Readable";
        case AgentEventType::Writable:        return "Writable";
        case AgentEventType::Closed:          return "Closed";
        case AgentEventType::EndpointChecked: return "EndpointChecked";
    }
    return "?";
}

const char* toString(SessionError e) {
    switch (e) {
        case SessionError::None:     return "None";
        case SessionError::Refused:  return "Refused";
        case SessionError::TimedOut: return "TimedOut";
        case SessionError::Reset:    return "Reset";
        case SessionError::AddressChanged: return "AddressChanged";
    }
    return "?";
}

static const uint8_t kOfferMagic[4] = {'N', 'A', 'T', 'D'};

std::array<uint8_t, kOfferSize> encodeOffer(const Offer& o) {
    std::array<uint8_t, kOfferSize> b{};
    std::memcpy(b.data(), kOfferMagic, 4);
    b[4] = kOfferVersion;
    b[5] = o.kind;
    for (int i = 0; i < 8; ++i) b[size_t(6 + i)] = uint8_t(o.nonce >> (8 * i));
    return b;
}

std::optional<Offer> decodeOffer(const uint8_t* d, size_t len) {
    if (len < kOfferSize || std::memcmp(d, kOfferMagic, 4) != 0 || d[4] != kOfferVersion)
        return std::nullopt;
    Offer o;
    o.kind = d[5];
    for (int i = 0; i < 8; ++i) o.nonce |= uint64_t(d[6 + i]) << (8 * i);
    return o;
}

TxId tokenFrom(const uint8_t* key, size_t keyLen, uint64_t nonce) {
    std::vector<uint8_t> in(key, key + keyLen);
    for (int i = 0; i < 8; ++i) in.push_back(uint8_t(nonce >> (8 * i)));
    return sessionTokenFrom(in.data(), in.size());
}

namespace {

struct Session {
    SessionId id = 0;
    bool incoming = false;
    Endpoint remote;
    std::optional<PeerInfo> remoteInfo;     // planPunch; else planDirect
    TxId token{};
    std::shared_ptr<IDatagramObfuscator> obfuscator;
    TimePoint queuedAt{};
    std::unique_ptr<PunchSession> punch;
    std::unique_ptr<Stream> stream;
    bool released = false;
    TimePoint releasedAt{};
    bool over = false;                      // nothing more will happen on it
    SessionError error = SessionError::None;
    bool open = false;                      // Connected/Incoming was queued
    bool wantWrite = false;                 // a write() found the window full
    bool readSignalled = false;             // a Readable is out, no read() since
    bool closeSignalled = false;
};

} // namespace

struct Agent::Impl {
    AgentConfig cfg;
    IDatagramIo& io;
    std::unique_ptr<NatDiscovery> discovery;
    uint32_t seenVersion = 0;
    bool ready = false;
    NatProfile profile;
    std::unique_ptr<QuickCheck> check;
    bool checkedOnce = false;
    TimePoint lastCheck{};
    bool closeIfChanged = false;
    QuickCheckResult lastCheckResult = QuickCheckResult::Pending;
    std::map<SessionId, std::unique_ptr<Session>> sessions;
    // Open streams by (socket, remote endpoint): a datagram finds its stream
    // in one lookup. A stream accepts only that pair, so nothing is missed.
    std::map<std::pair<SocketId, uint64_t>, SessionId> streamIndex;
    static uint64_t epKey(const Endpoint& e) { return uint64_t(e.ip) << 16 | e.port; }
    TimePoint nextAt = TimePoint::max();   // see Agent::nextPoll()
    void touch(TimePoint now) { nextAt = std::min(nextAt, now); }
    // Every removal of a session goes through here (index and counters).
    void erase(SessionId id) {
        auto it = sessions.find(id);
        if (it == sessions.end()) return;
        Session& s = *it->second;
        if (s.obfuscator) --obfuscated;
        if (s.stream) streamIndex.erase({s.stream->config().socket, epKey(s.stream->config().remote)});
        sessions.erase(it);
    }
    std::deque<SessionId> waiting;
    SessionId nextId = 1;
    std::deque<AgentEvent> events;
    size_t obfuscated = 0;                  // sessions with an obfuscator, not freed
    AgentStats stats;

    StreamTransportFactory transport;
    Impl(AgentConfig c, IDatagramIo& i, StreamTransportFactory t) : cfg(std::move(c)), io(i), transport(std::move(t)) {}

    Session* find(SessionId id) const {
        auto it = sessions.find(id);
        return it == sessions.end() ? nullptr : it->second.get();
    }
    void emit(AgentEventType t, SessionId id = 0, SessionError e = SessionError::None) {
        events.push_back(AgentEvent{t, id, e});
    }
    size_t punching() const {
        size_t n = 0;
        for (auto& [id, s] : sessions) n += s->punch && !s->stream && !s->over;
        return n;
    }
    void fail(Session& s, SessionError e) {
        if (s.over) return;
        if (e == SessionError::Refused) ++stats.punchesRefused;
        s.over = true;
        s.error = e;
        s.punch.reset();
    }

    SessionId open(bool incoming, const Endpoint& remote, std::optional<PeerInfo> info, const TxId& token,
                   std::shared_ptr<IDatagramObfuscator> obf, TimePoint now) {
        if (!transport || !directOk(info) || sessions.size() >= cfg.maxSessions) return 0;
        if (incoming)
            for (auto& [id, s] : sessions)
                if (s->token == token && !s->over) return 0;   // a request repeated while its punch is on
        auto p = std::make_unique<Session>();
        p->id = nextId++;
        if (nextId == 0) nextId = 1;
        p->incoming = incoming;
        p->remote = remote;
        p->remoteInfo = std::move(info);
        p->token = token;
        p->obfuscator = std::move(obf);
        if (p->obfuscator) ++obfuscated;
        Session& s = *p;
        sessions[s.id] = std::move(p);
        startPunch(s, now);
        if (s.over && s.error == SessionError::Refused && !s.punch) {
            // refused at once: the caller hears it from the return value
            erase(s.id);
            return 0;
        }
        return s.id;
    }
    bool directOk(const std::optional<PeerInfo>& info) const {
        if (!ready) return false;
        return info ? true : directPunchable();
    }
    bool directPunchable() const {
        return ready && profile.predictability == Predictability::Stable && profile.publicEndpoint.valid();
    }

    void startPunch(Session& s, TimePoint now) {
        if (punching() >= cfg.maxPunches) {
            if (waiting.size() >= cfg.maxWaiting) { fail(s, SessionError::Refused); return; }
            ++stats.punchesQueued;
            s.queuedAt = now;
            waiting.push_back(s.id);
            return;
        }
        PunchSessionConfig pc;
        if (s.remoteInfo) {
            PeerInfo local = localPeerInfo();
            pc.plan = planPunch(local, *s.remoteInfo, cfg.limits);
            pc.remoteIp = s.remoteInfo->observed.ip;
        } else {
            pc.plan = planDirect(profile, s.remote, cfg.limits);
            pc.remoteIp = s.remote.ip;
        }
        if (pc.plan.strategy == PunchStrategy::Infeasible) { fail(s, SessionError::Refused); return; }
        pc.token = s.token;
        pc.startAt = now;
        pc.primarySocket = cfg.discovery.primarySocket;
        pc.obfuscator = s.obfuscator;
        s.punch = std::make_unique<PunchSession>(pc, io);
        ++stats.punchesStarted;
    }

    PeerInfo localPeerInfo() const {
        PeerInfo pi;
        pi.profile = profile;
        pi.observed = profile.publicEndpoint;
        return pi;
    }

    void established(Session& s, TimePoint now) {
        StreamConfig sc = cfg.stream;
        sc.socket = s.punch->establishedSocket();
        sc.remote = s.punch->remoteEndpoint();
        sc.token = s.token;
        sc.keepalive = cfg.keepalive;
        sc.randomBytes = cfg.randomBytes;
        sc.obfuscator = s.obfuscator;
        s.remote = sc.remote;
        s.stream = std::make_unique<Stream>(sc, transport, io, now);
        streamIndex[{sc.socket, epKey(sc.remote)}] = s.id;
        s.punch.reset();
        ++stats.punchesEstablished;
        if (s.released) { s.stream->close(now); return; }
        s.open = true;
        emit(s.incoming ? AgentEventType::Incoming : AgentEventType::Connected, s.id);
    }

    void startCheck(bool closeStreams, TimePoint now) {
        if (!ready) return;
        closeIfChanged = closeIfChanged || closeStreams;
        if (check || (checkedOnce && now - lastCheck < cfg.checkReuse)) {
            if (!check) {
                closeIfChanged = false;   // found the same, or updated, a moment ago
                ++stats.endpointChecksReused;
            }
            return;
        }
        ++stats.endpointChecks;
        check = std::make_unique<QuickCheck>(cfg.discovery, profile, io);
        check->start(now);
    }

    TimePoint step(TimePoint now) {
        TimePoint next = TimePoint::max();
        if (discovery) {
            next = std::min(next, discovery->poll(now));
            const DiscoveryState st = discovery->state();
            if ((st == DiscoveryState::Provisional || st == DiscoveryState::Final) &&
                discovery->resultVersion() != seenVersion) {
                seenVersion = discovery->resultVersion();
                const Endpoint kept = profile.publicEndpoint;
                profile = discovery->result();
                if (ready && checkedOnce && kept.valid()) profile.publicEndpoint = kept;   // a check is newer
                if (!ready) { ready = true; emit(AgentEventType::ProfileReady); }
            }
        }
        if (check) {
            next = std::min(next, check->poll(now));
            const QuickCheckResult r = check->result();
            if (r != QuickCheckResult::Pending) {
                lastCheckResult = r;
                emit(AgentEventType::EndpointChecked);
                if (r == QuickCheckResult::Changed) {
                    profile.publicEndpoint = check->observed();
                    ++stats.endpointChanges;
                    emit(AgentEventType::EndpointChanged);
                    if (closeIfChanged)
                        for (auto& [id, s] : sessions)
                            if (s->stream && !s->over) {
                                fail(*s, SessionError::AddressChanged);
                                ++stats.streamsAddressChanged;
                            }
                }
                check.reset();
                lastCheck = now;
                checkedOnce = true;
                closeIfChanged = false;
            }
        }
        // requests that waited for a free punch session
        while (!waiting.empty() && punching() < cfg.maxPunches) {
            Session* s = find(waiting.front());
            waiting.pop_front();
            if (!s || s->over || s->released) continue;
            if (now - s->queuedAt >= cfg.punchWait) {
                fail(*s, SessionError::TimedOut);
                ++stats.punchesRefused;
            }
            else startPunch(*s, now);
        }
        for (SessionId id : waiting)
            if (Session* s = find(id)) next = std::min(next, s->queuedAt + cfg.punchWait);

        bool dead = false;
        for (auto it = sessions.begin(); it != sessions.end();) {
            Session& s = *it->second;
            if (!s.over) {
                if (s.stream) {
                    next = std::min(next, s.stream->poll(now));
                    const StreamState st = s.stream->state();
                    if (st == StreamState::Dead) {
                        // a lost connection; our own endpoint may have changed (the NAT lost
                        // its mappings, a new address): checked, so that the next punch is right
                        fail(s, SessionError::Reset);
                        ++stats.streamsDead;
                        dead = true;
                    } else if (st == StreamState::Closed) {
                        s.over = true;
                    }
                    if (s.released && !s.over) {
                        if (now - s.releasedAt >= cfg.linger) s.over = true;
                        else next = std::min(next, s.releasedAt + cfg.linger);
                    }
                } else if (s.punch) {
                    next = std::min(next, s.punch->poll(now));
                    const PunchState st = s.punch->state();
                    if (st == PunchState::Established) {
                        established(s, now);
                        next = now;   // the new stream wants a poll
                    } else if (st == PunchState::Failed) {
                        fail(s, SessionError::TimedOut);
                        ++stats.punchesFailed;
                    }
                }
            }
            if (!s.released) signal(s);
            if (s.released && s.over) {
                const SessionId gone = s.id;
                ++it;
                erase(gone);
            } else {
                ++it;
            }
        }
        if (dead) startCheck(false, now);
        return next;
    }

    void signal(Session& s) {
        if (s.stream && s.open) {
            if (!s.readSignalled && s.stream->readable() > 0) {
                s.readSignalled = true;
                emit(AgentEventType::Readable, s.id);
            }
            if (s.wantWrite && !s.over && s.stream->writable()) {
                s.wantWrite = false;
                emit(AgentEventType::Writable, s.id);
            }
        }
        if (s.closeSignalled) return;
        const bool peerDone = s.stream && (s.stream->peerClosed() || s.stream->state() == StreamState::Closed);
        if (!s.over && !peerDone) return;
        if (s.stream && s.stream->readable() > 0) return;   // what arrived before the end is read first
        s.closeSignalled = true;
        emit(AgentEventType::Closed, s.id, s.over ? s.error : SessionError::None);
    }
};

Agent::Agent(AgentConfig cfg, IDatagramIo& io, StreamTransportFactory transport)
    : impl_(std::make_unique<Impl>(std::move(cfg), io, std::move(transport))) {}
Agent::~Agent() = default;

void Agent::start(TimePoint now, std::optional<std::vector<StunEndpoint>> servers) {
    Impl& m = *impl_;
    if (m.discovery) return;
    if (servers) m.cfg.discovery.stunServers = std::move(*servers);
    if (m.cfg.shuffleStunServers && m.cfg.discovery.stunServers.size() > 1) {
        RandomBytesFn rnd = m.cfg.randomBytes ? m.cfg.randomBytes : defaultRandomBytes();
        uint32_t seed = 0;
        rnd(reinterpret_cast<uint8_t*>(&seed), sizeof seed);
        std::shuffle(m.cfg.discovery.stunServers.begin(), m.cfg.discovery.stunServers.end(), std::mt19937(seed));
    }
    m.discovery = std::make_unique<NatDiscovery>(m.cfg.discovery, m.io);
    m.discovery->start(now);
    m.touch(now);
}

bool Agent::started() const { return impl_->discovery != nullptr; }

bool Agent::mayBeOurs(const uint8_t* d, size_t len) const {
    return impl_->obfuscated > 0 || stun::isStunPacket(d, len) || proto::isNatdPacket(d, len);
}

bool Agent::onDatagram(SocketId sock, const Endpoint& from, const uint8_t* d, size_t len, TimePoint now) {
    Impl& m = *impl_;
    bool used = false;
    if (m.discovery && m.discovery->onDatagram(sock, from, d, len, now)) used = true;
    if (!used && m.check && m.check->onDatagram(sock, from, d, len, now)) used = true;
    if (!used) {
        auto ix = m.streamIndex.find({sock, Impl::epKey(from)});
        if (ix != m.streamIndex.end())
            if (Session* s = m.find(ix->second)) used = s->stream->onDatagram(sock, from, d, len, now);
    }
    // Punches in progress (at most maxPunches): a punch may hear from more
    // than one endpoint, so they are asked in turn.
    for (auto it = m.sessions.begin(); !used && it != m.sessions.end(); ++it) {
        Session& s = *it->second;
        if (s.punch && !s.stream) used = s.punch->onDatagram(sock, from, d, len, now);
    }
    if (used) m.nextAt = m.step(now);
    return used || stun::isStunPacket(d, len) || proto::isNatdPacket(d, len);
}

TimePoint Agent::poll(TimePoint now) { return impl_->nextAt = impl_->step(now); }
TimePoint Agent::nextPoll() const { return impl_->nextAt; }

bool Agent::nextEvent(AgentEvent& out) {
    if (impl_->events.empty()) return false;
    out = impl_->events.front();
    impl_->events.pop_front();
    return true;
}

bool Agent::profileReady() const { return impl_->ready; }
const NatProfile& Agent::profile() const { return impl_->profile; }
Endpoint Agent::publicEndpoint() const { return impl_->ready ? impl_->profile.publicEndpoint : Endpoint{}; }
bool Agent::directPunchable() const { return impl_->directPunchable(); }
PeerInfo Agent::localPeerInfo() const { return impl_->localPeerInfo(); }

QuickCheckResult Agent::lastCheckResult() const { return impl_->lastCheckResult; }
bool Agent::checking() const { return impl_->check != nullptr; }

void Agent::checkEndpoint(TimePoint now, bool closeIfChanged) {
    impl_->startCheck(closeIfChanged, now);
    impl_->touch(now);
}

SessionId Agent::connect(const Endpoint& remote, const TxId& token, TimePoint now,
                         std::shared_ptr<IDatagramObfuscator> obf) {
    if (!remote.valid()) return 0;
    impl_->touch(now);
    return impl_->open(false, remote, std::nullopt, token, std::move(obf), now);
}
SessionId Agent::connect(const PeerInfo& remote, const TxId& token, TimePoint now,
                         std::shared_ptr<IDatagramObfuscator> obf) {
    if (!remote.observed.valid()) return 0;
    impl_->touch(now);
    return impl_->open(false, remote.observed, remote, token, std::move(obf), now);
}
SessionId Agent::accept(const Endpoint& remote, const TxId& token, TimePoint now,
                        std::shared_ptr<IDatagramObfuscator> obf) {
    if (!remote.valid()) return 0;
    impl_->touch(now);
    return impl_->open(true, remote, std::nullopt, token, std::move(obf), now);
}
SessionId Agent::accept(const PeerInfo& remote, const TxId& token, TimePoint now,
                        std::shared_ptr<IDatagramObfuscator> obf) {
    if (!remote.observed.valid()) return 0;
    impl_->touch(now);
    return impl_->open(true, remote.observed, remote, token, std::move(obf), now);
}

SessionPhase Agent::phase(SessionId id) const {
    const Session* s = impl_->find(id);
    if (!s) return SessionPhase::None;
    if (s->over) return SessionPhase::Over;
    if (s->stream) return s->released || s->stream->state() == StreamState::Closing ? SessionPhase::Closing
                                                                                     : SessionPhase::Open;
    return s->punch ? SessionPhase::Punching : SessionPhase::Waiting;
}

Endpoint Agent::remote(SessionId id) const {
    const Session* s = impl_->find(id);
    return s ? s->remote : Endpoint{};
}

size_t Agent::write(SessionId id, const uint8_t* d, size_t len, TimePoint now) {
    Session* s = impl_->find(id);
    if (!s || !s->stream || s->over || s->released) return 0;
    const size_t n = s->stream->write(d, len, now);
    if (n == 0 && len > 0) s->wantWrite = true;
    impl_->touch(now);
    return n;
}

size_t Agent::read(SessionId id, uint8_t* out, size_t max) {
    Session* s = impl_->find(id);
    if (!s || !s->stream || s->released) return 0;
    s->readSignalled = false;
    const size_t n = s->stream->read(out, max);
    impl_->signal(*s);   // more left: Readable again; the end once it is all read
    return n;
}

size_t Agent::readable(SessionId id) const {
    const Session* s = impl_->find(id);
    return s && s->stream ? s->stream->readable() : 0;
}

void Agent::release(SessionId id, TimePoint now) {
    Impl& m = *impl_;
    Session* s = m.find(id);
    if (!s || s->released) return;
    s->released = true;
    s->releasedAt = now;
    if (s->stream && !s->over && s->stream->state() == StreamState::Open) s->stream->close(now);
    else if (!s->stream) s->over = true;
    if (s->over) m.erase(id);
    m.touch(now);
}

size_t Agent::sessionCount() const { return impl_->sessions.size(); }
const AgentStats& Agent::stats() const { return impl_->stats; }

} // namespace natd
