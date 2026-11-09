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
        case AgentEventType::EndpointChecked: return "EndpointChecked";
        case AgentEventType::Punched:         return "Punched";
        case AgentEventType::PunchFailed:     return "PunchFailed";
    }
    return "?";
}

const char* toString(PunchError e) {
    switch (e) {
        case PunchError::None:     return "None";
        case PunchError::Refused:  return "Refused";
        case PunchError::TimedOut: return "TimedOut";
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
    PunchStrategy strategy = PunchStrategy::Infeasible;
    bool punched = false;                   // Punched was queued
    bool taken = false;                     // the result went to the application
    TimePoint lingerUntil{};                // taken: the punch answers late PUNCHes until then
    bool over = false;                      // failed: PunchFailed was queued
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
    QuickCheckResult lastCheckResult = QuickCheckResult::Pending;
    std::map<SessionId, std::unique_ptr<Session>> sessions;
    TimePoint nextAt = TimePoint::max();   // see Agent::nextPoll()
    void touch(TimePoint now) { nextAt = std::min(nextAt, now); }
    void erase(SessionId id) {
        auto it = sessions.find(id);
        if (it == sessions.end()) return;
        if (it->second->obfuscator) --obfuscated;
        sessions.erase(it);
    }
    std::deque<SessionId> waiting;
    SessionId nextId = 1;
    std::deque<AgentEvent> events;
    size_t obfuscated = 0;                  // sessions with an obfuscator, not freed
    AgentStats stats;

    Impl(AgentConfig c, IDatagramIo& i) : cfg(std::move(c)), io(i) {}

    Session* find(SessionId id) const {
        auto it = sessions.find(id);
        return it == sessions.end() ? nullptr : it->second.get();
    }
    void emit(AgentEventType t, SessionId id = 0, PunchError e = PunchError::None) {
        events.push_back(AgentEvent{t, id, e});
    }
    size_t punching() const {
        size_t n = 0;
        for (auto& [id, s] : sessions) n += s->punch && !s->punched && !s->over;
        return n;
    }
    void fail(Session& s, PunchError e) {
        if (s.over) return;
        if (e == PunchError::Refused) ++stats.punchesRefused;
        s.over = true;
        s.punch.reset();
        emit(AgentEventType::PunchFailed, s.id, e);
    }

    SessionId open(bool incoming, const Endpoint& remote, std::optional<PeerInfo> info, const TxId& token,
                   std::shared_ptr<IDatagramObfuscator> obf, TimePoint now) {
        if (!directOk(info)) return 0;
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
        if (!startPunch(s, now)) {
            // refused at once: the caller hears it from the return value
            ++stats.punchesRefused;
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

    // False: no punch possible, or no room to wait for one.
    bool startPunch(Session& s, TimePoint now) {
        if (punching() >= cfg.maxPunches) {
            if (waiting.size() >= cfg.maxWaiting) return false;
            ++stats.punchesQueued;
            s.queuedAt = now;
            waiting.push_back(s.id);
            return true;
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
        if (pc.plan.strategy == PunchStrategy::Infeasible) return false;
        pc.token = s.token;
        pc.startAt = now;
        pc.primarySocket = cfg.discovery.primarySocket;
        pc.obfuscator = s.obfuscator;
        s.strategy = pc.plan.strategy;
        s.punch = std::make_unique<PunchSession>(pc, io);
        ++stats.punchesStarted;
        return true;
    }

    PeerInfo localPeerInfo() const {
        PeerInfo pi;
        pi.profile = profile;
        pi.observed = profile.publicEndpoint;
        return pi;
    }

    void startCheck(TimePoint now) {
        if (!ready) return;
        if (check) return;
        if (checkedOnce && now - lastCheck < cfg.checkReuse) {
            ++stats.endpointChecksReused;   // found the same, or updated, a moment ago
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
                }
                check.reset();
                lastCheck = now;
                checkedOnce = true;
            }
        }
        // requests that waited for a free punch session
        while (!waiting.empty() && punching() < cfg.maxPunches) {
            Session* s = find(waiting.front());
            waiting.pop_front();
            if (!s || s->over) continue;
            if (now - s->queuedAt >= cfg.punchWait) {
                fail(*s, PunchError::TimedOut);
                ++stats.punchesRefused;
            } else if (!startPunch(*s, now)) {
                fail(*s, PunchError::Refused);
            }
        }
        for (SessionId id : waiting)
            if (Session* s = find(id)) next = std::min(next, s->queuedAt + cfg.punchWait);
        for (auto it = sessions.begin(); it != sessions.end();) {
            Session& s = *it->second;
            if (s.punch && !s.punched && !s.over) {
                next = std::min(next, s.punch->poll(now));
                const PunchState st = s.punch->state();
                if (st == PunchState::Established) {
                    s.punched = true;
                    s.remote = s.punch->remoteEndpoint();
                    ++stats.punchesEstablished;
                    emit(AgentEventType::Punched, s.id);
                } else if (st == PunchState::Failed) {
                    fail(s, PunchError::TimedOut);
                    ++stats.punchesFailed;
                }
            }
            if (s.taken && now < s.lingerUntil) next = std::min(next, s.lingerUntil);
            const SessionId id = s.id;
            ++it;
            if (sessions.at(id)->over || (sessions.at(id)->taken && now >= sessions.at(id)->lingerUntil)) erase(id);
        }
        return next;
    }
};

Agent::Agent(AgentConfig cfg, IDatagramIo& io) : impl_(std::make_unique<Impl>(std::move(cfg), io)) {}
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
    // Punches in progress (at most maxPunches), and those handed over a moment
    // ago: a punch may hear from more than one endpoint, so they are asked in turn.
    for (auto it = m.sessions.begin(); !used && it != m.sessions.end(); ++it) {
        Session& s = *it->second;
        if (s.punch) used = s.punch->onDatagram(sock, from, d, len, now);
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

void Agent::checkEndpoint(TimePoint now) {
    impl_->startCheck(now);
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
    if (!s || s->over || s->taken) return SessionPhase::None;
    if (s->punched) return SessionPhase::Punched;
    return s->punch ? SessionPhase::Punching : SessionPhase::Waiting;
}

Endpoint Agent::remote(SessionId id) const {
    const Session* s = impl_->find(id);
    return s && !s->taken ? s->remote : Endpoint{};
}

std::optional<PunchResult> Agent::takeResult(SessionId id, TimePoint now) {
    Impl& m = *impl_;
    Session* s = m.find(id);
    if (!s || !s->punched || s->taken) return std::nullopt;
    PunchResult r;
    r.socket = s->punch->establishedSocket();
    r.local = m.io.localEndpoint(r.socket);
    r.remote = s->punch->remoteEndpoint();
    r.keepalive = s->punch->keepalive();
    r.mappingLifetime = mappingLifetime(m.profile);
    r.strategy = s->strategy;
    r.incoming = s->incoming;
    r.token = s->token;
    s->taken = true;
    s->lingerUntil = now + m.cfg.limits.budget;
    m.touch(now);
    return r;
}

void Agent::cancel(SessionId id, TimePoint now) {
    Impl& m = *impl_;
    Session* s = m.find(id);
    if (!s || s->taken) return;
    // a punched path nobody took: its socket, if natd opened it, is still natd's
    if (s->punched && s->punch->establishedSocket() != m.cfg.discovery.primarySocket)
        m.io.closeSocket(s->punch->establishedSocket());
    m.erase(id);
    m.touch(now);
}

size_t Agent::sessionCount() const {
    size_t n = 0;
    for (auto& [id, s] : impl_->sessions) n += !s->taken && !s->over;
    return n;
}
const AgentStats& Agent::stats() const { return impl_->stats; }

} // namespace natd
