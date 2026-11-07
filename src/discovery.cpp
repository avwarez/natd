// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// NAT behavior discovery engine (sans-I/O).
//
// Phases, each a batch of probes driven by poll():
//   Mapping    primary socket -> R0:p0, a same-IP/other-port pair (R0:p1 or
//              both ports of a STUN server), a second IP (R1:p0 or STUN)
//   AllocSame  primary socket -> fresh destinations (STUN servers or extra
//              reflector ports), adaptive rounds (APD mapping only)
//   Filtering  fresh socket   -> R0:p0 asking replies from R0:p1 and partner R1
//   Hairpin    primary and filtering socket punch each other's public endpoint
//   AllocNew   fresh sockets  -> R0:p0, adaptive rounds
//   -> Provisional result
//   Lifetime   fresh sockets, one per grid value and variant, delayed replies
//   -> Final result
//
// Adaptive sampling: each allocation round is classified on its own (a gap of
// roundGap between rounds would otherwise appear as an outlier step); the next,
// larger round runs only while the confidence stays below confidenceTarget.
#include "natd/discovery.hpp"
#include "natd/protocol.hpp"
#include "natd/stun.hpp"
#include "probe_engine.hpp"

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <map>
#include <set>

namespace natd {
namespace detail {

std::vector<uint32_t> reflectorIps(const DiscoveryConfig& c) {
    std::vector<uint32_t> ips;
    for (auto& r : c.reflectors) ips.push_back(r.ip);
    return ips;
}

// Reflector pair starting at index base: R0 with a port, R1 with a distinct
// IP, and a second IP for the mapping test (R1:p0 or a STUN server).
bool pairUsable(const DiscoveryConfig& c, size_t base) {
    if (base + 1 >= c.reflectors.size()) return false;
    const auto &r0 = c.reflectors[base], &r1 = c.reflectors[base + 1];
    if (r0.ip == 0 || r1.ip == 0 || r0.ip == r1.ip || r0.ports.empty()) return false;
    return !r1.ports.empty() || !c.stunServers.empty();
}

// First usable pair at or after base (pairs at even indexes); npos if none.
size_t nextPair(const DiscoveryConfig& c, size_t base) {
    for (size_t b = base; b + 1 < c.reflectors.size(); b += 2)
        if (pairUsable(c, b)) return b;
    return size_t(-1);
}

Duration clampDur(double ms, Duration lo, Duration hi) {
    auto v = Duration(int64_t(ms));
    return std::max(lo, std::min(hi, v));
}

} // namespace detail

using detail::ProbeKind;

// ===========================================================================
// NatDiscovery
// ===========================================================================
struct NatDiscovery::Impl {
    enum class Phase { Idle, Mapping, Filtering, Hairpin, AllocSame, AllocNew, Drift, Lifetime, Done };

    DiscoveryConfig cfg;
    IDatagramIo& io;
    detail::ProbeEngine eng;
    Phase phase = Phase::Idle;
    DiscoveryState st = DiscoveryState::Idle;
    NatProfile prof;
    uint32_t version = 0;
    std::vector<SocketId> opened;
    TimePoint waitUntil{};
    size_t round = 0;
    std::vector<std::pair<Endpoint, bool>> freshDests;   // (destination, is STUN) not yet used by the primary socket
    size_t freshNext = 0;
    uint16_t nextLocalPort = 0;
    bool haveSame = false;
    std::vector<uint16_t> mapSamples;   // mapping-phase ports of the primary socket, in send order
    std::vector<bool> mapSampleStun;    // ... and whether each came from a STUN server
    std::vector<uint32_t> seenIps;

    // Hairpin test state
    struct HairpinLeg { SocketId sock = 0; Endpoint to; };
    HairpinLeg hpLeg[2];
    TxId hpToken{};
    int hpSendsLeft = 0, hpSent = 0;
    TimePoint hpNextSend{}, hpEnd{};
    HairpinBehavior hpSeen = HairpinBehavior::Unknown;

    Impl(DiscoveryConfig c, IDatagramIo& i)
        : cfg(std::move(c)), io(i), eng(i, cfg.advanced, detail::reflectorIps(cfg)) {
        prof.punchInterval = cfg.advanced.defaultPunchInterval;
        prof.keepaliveInterval = cfg.advanced.defaultKeepalive;
        randomBytes = cfg.advanced.randomBytes ? cfg.advanced.randomBytes : defaultRandomBytes();
    }
    ~Impl() { closeAll(); }
    RandomBytesFn randomBytes;

    size_t pairBase = 0;   // index of the R0 in use (reflector pairs, failover)
    bool noReflector = false;   // no pair answered: STUN-only partial profile
    bool ipChanged = false;     // the reflector saw another public IP mid-run
    int restarts = 0;
    const ReflectorInfo& R(size_t i) const { return cfg.reflectors[pairBase + i]; }
    Endpoint ep(size_t r, size_t port) const { return {R(r).ip, R(r).ports[port]}; }

    int used = 0;   // (socket, destination) pairs so far: upper bound on NAT mappings

    int lifetimeCost() const {
        if (!cfg.measureLifetime) return 0;
        int n = 0;
        for (int g : cfg.advanced.lifetimeGridSec)
            if (g > 0 && uint32_t(g) * 1000u <= proto::kMaxDelayMs) n += 2;
        return n;
    }
    // Mappings still available to the sampling rounds.
    int room() const {
        if (cfg.advanced.maxMappings <= 0) return 1 << 30;
        return std::max(0, cfg.advanced.maxMappings - used - lifetimeCost());
    }

    void closeAll() {
        for (SocketId s : opened) io.closeSocket(s);
        opened.clear();
    }

    std::optional<SocketId> openSock(bool sequential) {
        uint16_t pref = sequential ? nextLocalPort : 0;
        auto s = io.openSocket(pref);
        if (!s && pref) s = io.openSocket(0);
        if (!s) return std::nullopt;
        opened.push_back(*s);
        if (sequential) {
            uint16_t lp = io.localEndpoint(*s).port;
            nextLocalPort = lp && lp < 65535 ? uint16_t(lp + 1) : 0;
        }
        return s;
    }

    void noteIp(uint32_t ip) {
        // Paired pooling (RFC 4787 REQ-2, RFC 6888 REQ-2): one public IP per
        // host. Another one from the reflector means the network changed.
        if (prof.publicEndpoint.valid() && ip != prof.publicEndpoint.ip) ipChanged = true;
        if (std::find(seenIps.begin(), seenIps.end(), ip) == seenIps.end()) seenIps.push_back(ip);
    }

    void publish(DiscoveryState s) {
        prof.details.multiplePublicIps = seenIps.size() > 1;
        st = s;
        ++version;
    }

    // ---------------------------------------------------------------- start
    void start(TimePoint now) {
        if (st != DiscoveryState::Idle) return;
        st = DiscoveryState::Running;
        pairBase = detail::nextPair(cfg, 0);
        if (pairBase == size_t(-1) && cfg.stunServers.size() >= 2) {
            // No reflector configured (or none usable): STUN servers only,
            // the same partial profile as when no reflector answers.
            pairBase = cfg.reflectors.size();
        } else if (pairBase == size_t(-1)) {
            pairBase = 0;
            prof.predictability = Predictability::Inconclusive;
            phase = Phase::Done;
            publish(DiscoveryState::Final);
            return;
        }
        nextLocalPort = cfg.advanced.localPortBase;
        stunUsed.assign(cfg.stunServers.size(), false);
        startMapping(now);
    }

    void startMapping(TimePoint now) {
        // Mapping test destinations, besides R0:p0:
        //   same IP, other port: R0:p1, or both ports of two-port STUN servers;
        //   second IP: R1:p0 when clients may reach R1, otherwise STUN servers
        //   (the first port of a two-port server already is one).
        phase = Phase::Mapping;
        mapTag = 0;
        mapBatches = 0;
        if (havePair()) {
            eng.add(cfg.primarySocket, ep(0, 0), proto::ReplySame, 0, ProbeKind::Basic, mapTag++);
            ++used;
        }
        if (r0Pair()) eng.add(cfg.primarySocket, ep(0, 1), proto::ReplySame, 0, ProbeKind::Basic, mapTag++);
        if (r1Open()) eng.add(cfg.primarySocket, ep(1, 0), proto::ReplySame, 0, ProbeKind::Basic, mapTag++);
        used += int(r0Pair()) + int(r1Open());
        addMappingBatch(!r0Pair(), !r1Open());
        waitUntil = now;
    }

    bool havePair() const { return pairBase + 1 < cfg.reflectors.size(); }
    bool r0Pair() const { return havePair() && R(0).ports.size() >= 2; }
    bool r1Open() const { return havePair() && !R(1).ports.empty(); }
    std::vector<bool> stunUsed;   // STUN servers already used by the mapping test
    int mapTag = 0, mapBatches = 0;
    size_t sameNeed = 0;   // samples the current same-socket round wants (spares excluded)

    // STUN probes of the mapping test: up to mappingStunProbes two-port
    // servers (both ports) when a same-IP pair is wanted, otherwise up to
    // mappingStunProbes servers as the second IP. Returns the probes added.
    size_t addMappingBatch(bool wantPair, bool wantIp) {
        const size_t k = size_t(std::max(1, cfg.advanced.mappingStunProbes));
        size_t added = 0, pairs = 0, plain = 0;
        if (wantPair)
            for (size_t i = 0; i < cfg.stunServers.size() && pairs < k; ++i) {
                const auto& sv = cfg.stunServers[i];
                if (stunUsed[i] || !sv.altPort || sv.altPort == sv.ep.port) continue;
                eng.addStun(cfg.primarySocket, sv.ep, mapTag++);
                eng.addStun(cfg.primarySocket, {sv.ep.ip, sv.altPort}, mapTag++);
                stunUsed[i] = true;
                ++pairs;
                added += 2;
            }
        if (wantIp && pairs == 0)
            for (size_t i = 0; i < cfg.stunServers.size() && plain < k; ++i) {
                if (stunUsed[i]) continue;
                eng.addStun(cfg.primarySocket, cfg.stunServers[i].ep, mapTag++);
                stunUsed[i] = true;
                ++plain;
                ++added;
            }
        used += int(added);
        return added;
    }

    // Destinations the primary socket has not used yet: reflector ports
    // (interleaved), then the STUN servers the mapping test left.
    void buildFreshDests() {
        freshDests.clear();
        freshNext = 0;
        if (!noReflector) {   // ports of the pair in use
            const size_t maxPorts = std::max(R(0).ports.size(), R(1).ports.size());
            for (size_t p = 0; p < maxPorts; ++p)
                for (size_t r = 0; r < 2; ++r) {
                    if (p >= R(r).ports.size()) continue;
                    if ((r == 0 && p <= 1) || (r == 1 && p == 0)) continue;   // used by Mapping
                    freshDests.push_back({ep(r, p), false});
                }
        }
        for (size_t i = 0; i < cfg.stunServers.size(); ++i)
            if (!stunUsed[i]) freshDests.push_back({cfg.stunServers[i].ep, true});
    }

    // -------------------------------------------------------------- phases
    // A STUN answer counts only with the reflector's public IP: with paired
    // pooling (RFC 4787 REQ-2, RFC 6888 REQ-2) every mapping of this host
    // has it, so another address is a wrong answer.
    bool usable(const detail::Probe& p) const { return usableWith(p, prof.publicEndpoint.ip); }
    static bool usableWith(const detail::Probe& p, uint32_t pubIp) {
        return p.same && (!p.stun || p.same->ip == pubIp);
    }

    struct MapEval {
        MappingBehavior mapping = MappingBehavior::Unknown;
        bool portTested = false, decided = false, pairTested = false, ipTested = false;
    };
    // The mapping evidence in the answers so far, given the public IP.
    MapEval evalMapping(uint32_t pubIp, bool stunOnly) const {
        // RFC 4787 §4.1 on every pair of answered probes:
        //   same destination IP, other port, other mapping -> address+port dependent;
        //   other destination IP, same mapping              -> endpoint independent
        //     (address and address+port dependent mappings both make a new one);
        //   other destination IP, other mapping             -> dependent: address
        //     dependent if a same-IP pair kept its mapping, otherwise assumed
        //     address+port dependent (untested, conservative).
        std::vector<const detail::Probe*> ok;
        for (auto& p : eng.probes()) if (usableWith(p, pubIp)) ok.push_back(&p);
        // Evidence between two reflector probes is trusted on its own; from
        // STUN servers, "different mapping" needs two servers agreeing (three
        // without a reflector), since one server may answer a wrong port.
        std::set<uint32_t> pairSameSrv, pairDiffSrv, ipDiffSrv;
        bool pairSameT = false, pairDiffT = false, ipDiffT = false, ipSame = false;
        for (size_t i = 0; i < ok.size(); ++i)
            for (size_t j = i + 1; j < ok.size(); ++j) {
                const auto &a = *ok[i], &b = *ok[j];
                const bool sameMap = *a.same == *b.same;
                const bool trusted = !a.stun && !b.stun;
                auto note = [&](std::set<uint32_t>& set, bool& t) {
                    if (trusted) t = true;
                    if (a.stun) set.insert(a.dest.ip);
                    if (b.stun) set.insert(b.dest.ip);
                };
                if (a.dest.ip == b.dest.ip) {
                    if (a.dest.port != b.dest.port) sameMap ? note(pairSameSrv, pairSameT) : note(pairDiffSrv, pairDiffT);
                } else if (sameMap) {
                    ipSame = true;
                } else {
                    note(ipDiffSrv, ipDiffT);
                }
            }
        const size_t need = stunOnly ? 3 : 2;
        const bool pairSame = pairSameT || pairSameSrv.size() >= 2;
        const bool pairDiff = pairDiffT || pairDiffSrv.size() >= 2;
        const bool ipDiff = ipDiffT || ipDiffSrv.size() >= need;
        // Equal endpoints first: a server cannot make up the port another
        // destination saw (1 in 64k), so "same mapping" cannot be faked.
        MapEval e;
        if (ipSame) e.mapping = MappingBehavior::EndpointIndependent;
        else if (pairDiff) e.mapping = MappingBehavior::AddressPortDependent;
        else if (ipDiff) e.mapping = pairSame ? MappingBehavior::AddressDependent : MappingBehavior::AddressPortDependent;
        else e.mapping = MappingBehavior::Unknown;
        e.portTested = (pairSame || pairDiff) && !(pairSame && pairDiff);
        e.decided = pairDiff || ipSame || (ipDiff && pairSame);
        e.pairTested = pairSame || pairDiff;
        e.ipTested = ipDiff;
        return e;
    }

    // Undecided mapping: ask the next STUN servers (at most twice; nothing is
    // sent when all asked servers answered and nothing is left). With no
    // public address yet from STUN alone, every server may be asked in turn:
    // a silent server says nothing about UDP.
    bool moreMappingServers(const MapEval& ev, bool noAnswerYet = false) {
        if (mapBatches >= 2 && !noAnswerYet) return false;
        if (addMappingBatch(!r0Pair() && !ev.pairTested, !r1Open() && !ev.ipTested) == 0) return false;
        ++mapBatches;
        return true;
    }

    // Public IP the mapping test can already rely on: the reflector's answer
    // (first by tag), or, without reflectors, two STUN servers agreeing.
    std::optional<uint32_t> provisionalPublicIp() const {
        std::vector<const detail::Probe*> byTag;
        for (auto& p : eng.probes()) byTag.push_back(&p);
        std::sort(byTag.begin(), byTag.end(), [](auto a, auto b) { return a->tag < b->tag; });
        if (havePair()) {
            for (auto* p : byTag) if (p->same && !p->stun) return p->same->ip;
            return std::nullopt;
        }
        std::map<uint32_t, int> n;
        for (auto* p : byTag) if (p->same && p->stun) ++n[p->same->ip];
        for (auto& [ip, c] : n) if (c >= 2) return ip;
        return std::nullopt;
    }

    // Called while only stale STUN probes are open (see stunStaleAfter): true
    // when the phase may end without them.
    bool mappingDoneWithoutStale() {
        auto ip = provisionalPublicIp();
        if (!ip) {
            // Nobody answered yet: with STUN alone, ask the next servers in
            // parallel; with a reflector, its own probes decide.
            if (!havePair()) moreMappingServers(MapEval{}, true);
            return false;
        }
        const MapEval ev = evalMapping(*ip, !havePair());
        if (ev.decided) return true;
        moreMappingServers(ev);   // in parallel with the stale ones
        return false;
    }

    bool doneWithoutStale() {
        switch (phase) {
        case Phase::Mapping: return mappingDoneWithoutStale();
        case Phase::AllocSame: {
            size_t n = round == 0 ? mapSamples.size() : 0;
            for (auto& p : eng.probes()) n += usable(p);
            return n >= sameNeed;
        }
        default: return false;
        }
    }

    void endMapping(TimePoint now) {
        std::vector<const detail::Probe*> byTag;
        for (auto& p : eng.probes()) byTag.push_back(&p);
        std::sort(byTag.begin(), byTag.end(), [](auto a, auto b) { return a->tag < b->tag; });
        // Public endpoint: the first reflector answer (R0:p0 normally).
        for (auto* p : byTag)
            if (p->same && !p->stun) {
                noteIp(p->same->ip);
                if (!prof.publicEndpoint.valid()) prof.publicEndpoint = *p->same;
            }
        auto& d = prof.details;
        if (!prof.publicEndpoint.valid() && !noReflector) {   // no reflector of this pair answered
            // Next reflector pair, if any. The STUN servers already used stay
            // used: probing them again would show old mappings, not new ones.
            size_t next = detail::nextPair(cfg, pairBase + 2);
            if (next != size_t(-1)) {
                pairBase = next;
                eng.clear();
                startMapping(now);
                return;
            }
            // No reflector at all. If STUN servers agree on a public address
            // (two answers at least), UDP works: partial profile from STUN
            // (mapping, allocation), no filtering, hairpinning or lifetime.
            std::map<uint32_t, std::vector<const detail::Probe*>> byIp;
            for (auto* p : byTag) if (p->same && p->stun) byIp[p->same->ip].push_back(p);
            const std::vector<const detail::Probe*>* best = nullptr;
            for (auto& [ip, v] : byIp) if (!best || v.size() > best->size()) best = &v;
            if (best && best->size() >= 2) {
                noReflector = true;
                prof.publicEndpoint = *best->front()->same;
                nsDest = best->front()->dest;
            }
        }
        // STUN alone and no two answers agreeing yet: ask the servers not
        // asked so far before UDP is declared blocked.
        if (!prof.publicEndpoint.valid() && !havePair() && moreMappingServers(MapEval{}, true)) return;
        if (!prof.publicEndpoint.valid()) {   // nobody answered
            prof.predictability = Predictability::UdpBlocked;
            prof.confidence = 1.0;
            phase = Phase::Done;
            publish(DiscoveryState::Final);
            return;
        }
        d.reflectorReached = !noReflector;
        Endpoint local = io.localEndpoint(cfg.primarySocket);
        d.behindNat = !(local.ip != 0 && local == prof.publicEndpoint);

        const MapEval ev = evalMapping(prof.publicEndpoint.ip, noReflector);
        d.mapping = ev.mapping;
        d.mappingPortTested = ev.portTested;

        // Undecided because the chosen STUN servers did not answer: try the
        // next ones at once (at most twice; nothing is sent when all answered).
        if (!noReflector) nsDest = ep(0, 0);
        if (!ev.decided && moreMappingServers(ev)) {
            d.mapping = MappingBehavior::Unknown;
            return;
        }
        buildFreshDests();

        // The mapping probes are the first same-socket samples (one new
        // mapping each with address+port dependent mapping, in send order).
        mapSamples.clear();
        mapSampleStun.clear();
        for (auto* p : byTag)
            if (usable(*p)) { mapSamples.push_back(p->same->port); mapSampleStun.push_back(p->stun); }
        eng.clear();
        // Same-socket sampling right after, before the filtering socket and
        // the hairpin probes take ports from the allocator in between.
        if (d.mapping == MappingBehavior::AddressPortDependent) {
            round = 0;
            phase = Phase::AllocSame;
            if (startSameRound()) return;
        }
        startFiltering(now);
    }

    void startFiltering(TimePoint now) {
        round = 0;
        if (noReflector) {   // needs the reflector: filtering and hairpinning stay Unknown
            startAllocation(now);
            return;
        }
        phase = Phase::Filtering;
        auto s = openSock(false);
        if (!s) { prof.details.filtering = FilteringBehavior::Unknown; startAllocation(now); return; }
        eng.add(*s, ep(0, 0), proto::ReplySame | proto::ReplyOtherPort | proto::ReplyPartner, 0,
                ProbeKind::Filter, 0);
        used += 1;
    }

    void endFiltering(TimePoint now) {
        auto& d = prof.details;
        const auto& p = eng.probes().front();
        // A missing reply proves filtering only if the reflector could send
        // it: its caps tell (older reflectors declare nothing and are
        // trusted, as before). Untested levels are reported as the stricter
        // one, flagged: AddressDependent without partner test = "address
        // dependent or more permissive"; AddressPortDependent without port
        // test = "address or address+port dependent".
        const uint8_t c = p.caps;
        const bool declared = c & proto::CapValid;
        d.filteringPartnerTested =
            !declared || ((c & proto::CapPartnerChecked) && (c & proto::CapPartnerAlive));
        d.filteringPortTested = !declared || (c & proto::CapOtherPort);
        if (!p.same) d.filtering = FilteringBehavior::Unknown;
        else if (p.partner) { d.filtering = FilteringBehavior::EndpointIndependent; d.filteringPartnerTested = d.filteringPortTested = true; }
        else if (p.other) { d.filtering = FilteringBehavior::AddressDependent; d.filteringPortTested = true; }
        else d.filtering = FilteringBehavior::AddressPortDependent;
        if (p.same) noteIp(p.same->ip);
        // Hairpin: the primary socket and the filtering socket send to each
        // other's public endpoint. Each opened its own mapping towards R0 only,
        // so the punch in both directions also opens address-dependent filters.
        const bool canHairpin = d.behindNat && p.same && prof.publicEndpoint.valid() &&
                                p.same->ip == prof.publicEndpoint.ip && *p.same != prof.publicEndpoint;
        SocketId fs = p.sock;
        eng.clear();
        if (!canHairpin) {
            closeAll();
            startAllocation(now);
            return;
        }
        phase = Phase::Hairpin;
        hpLeg[0] = {cfg.primarySocket, *p.same};
        hpLeg[1] = {fs, prof.publicEndpoint};
        randomBytes(hpToken.data(), hpToken.size());
        // Three sends with a doubling interval, as for a request without an
        // answer yet (RFC 8085 §3.1.3): at 0, RTO and 3 RTO; then one more
        // doubling for the last one to come back.
        hpSendsLeft = 3;
        hpSent = 0;
        hpNextSend = now;
        hpEnd = now + cfg.advanced.rto * 7;
        hpSeen = HairpinBehavior::Unknown;
        used += 2;
    }

    TimePoint pollHairpin(TimePoint now) {
        if (hpSendsLeft > 0 && now >= hpNextSend) {
            auto b = proto::encode(proto::Punch{hpToken, false});
            for (auto& l : hpLeg) io.send(l.sock, l.to, b.data(), b.size());
            --hpSendsLeft;
            hpNextSend = now + cfg.advanced.rto * (int64_t(1) << hpSent);
            ++hpSent;
        }
        if (now < hpEnd && hpSeen == HairpinBehavior::Unknown)
            return hpSendsLeft > 0 ? std::min(hpNextSend, hpEnd) : hpEnd;
        auto& d = prof.details;
        if (hpSeen != HairpinBehavior::Unknown) d.hairpin = hpSeen;
        else d.hairpin = d.mapping == MappingBehavior::EndpointIndependent ? HairpinBehavior::None
                                                                          : HairpinBehavior::Unknown;
        closeAll();
        startAllocation(now);
        return now;
    }

    bool onHairpin(SocketId s, const Endpoint& from, const uint8_t* d, size_t len) {
        if (proto::peekType(d, len) != proto::MsgType::Punch) return false;
        auto p = proto::decodePunch(d, len);
        if (!p || p->token != hpToken) return false;
        int leg = s == hpLeg[0].sock ? 0 : s == hpLeg[1].sock ? 1 : -1;
        if (leg < 0) return false;
        // Received on leg i: sent by the other leg, whose public endpoint is
        // the target of leg i.
        if (from.ip == prof.publicEndpoint.ip) hpSeen = HairpinBehavior::External;
        else if (hpSeen == HairpinBehavior::Unknown) hpSeen = HairpinBehavior::Internal;
        return true;
    }

    void startAllocation(TimePoint now) {
        round = 0;
        phase = Phase::AllocNew;
        if (!startNewRound()) finishAllocation(now);
    }

    bool startSameRound() {
        const auto& steps = cfg.advanced.allocSameSocketSteps;
        if (round >= steps.size()) return false;
        // Round 0 counts the mapping samples: only the rest needs fresh
        // destinations (reflector ports).
        const size_t prefix = round == 0 ? mapSamples.size() : 0;
        size_t want = size_t(std::max(0, steps[round]));
        want = want > prefix ? want - prefix : 0;
        if (want == 0) return false;
        sameNeed = prefix + want;
        want += size_t(std::max(0, cfg.advanced.allocSameSpare));
        size_t avail = freshDests.size() - freshNext;
        size_t n = std::min<size_t>({want, avail, size_t(room())});
        if (n == 0 || prefix + n < 4) return false;
        for (size_t i = 0; i < n; ++i) {
            auto& [dest, isStun] = freshDests[freshNext++];
            if (isStun) eng.addStun(cfg.primarySocket, dest, int(i));
            else eng.add(cfg.primarySocket, dest, proto::ReplySame, 0, ProbeKind::Basic, int(i));
        }
        used += int(n);
        return true;
    }

    // New-socket sample destination: R0:p0, or a STUN server without reflector.
    Endpoint nsDest;
    void addNsProbe(SocketId s, int tag) {
        const uint16_t lp = io.localEndpoint(s).port;
        if (noReflector) eng.addStun(s, nsDest, tag, lp);
        else eng.add(s, nsDest, proto::ReplySame, 0, ProbeKind::Basic, tag, lp);
    }

    bool startNewRound() {
        const auto& steps = cfg.advanced.allocNewSocketSteps;
        if (round >= steps.size()) return false;
        int n = std::min(std::max(0, steps[round]), room());
        if (n < 2) return false;
        int added = 0;
        for (int i = 0; i < n; ++i) {
            auto s = openSock(cfg.advanced.sequentialLocalPorts);
            if (!s) break;
            addNsProbe(*s, i);
            ++added;
        }
        used += added;
        return added >= 2;
    }

    AllocationInfo classifyRound(bool withLocal, const std::vector<uint16_t>& prefix = {},
                                 const std::vector<bool>& prefixStun = {}) {
        std::vector<std::pair<int, const detail::Probe*>> got;
        for (auto& p : eng.probes()) if (usable(p)) got.push_back({p.tag, &p});
        std::sort(got.begin(), got.end(), [](auto& a, auto& b) { return a.first < b.first; });
        std::vector<uint16_t> ports = prefix, locals;
        std::vector<bool> fromStun = prefixStun;
        fromStun.resize(prefix.size(), false);
        for (auto& [tag, p] : got) {
            ports.push_back(p->same->port);
            locals.push_back(p->localPort);
            fromStun.push_back(p->stun);
            if (!p->stun) noteIp(p->same->ip);
        }
        if (!withLocal) locals.clear();
        return robustClassify(ports, locals, fromStun);
    }

    // A STUN server may answer a wrong port consistently (the double query
    // does not catch it). One such sample breaks a sequence. When the sample
    // does not read as sequential, try leaving out one or two STUN samples:
    // a clean sequence in what remains (>= 6 samples, confidence at target)
    // is taken. Random allocation does not turn sequential by dropping two
    // points; the reflector's samples are never dropped.
    AllocationInfo robustClassify(const std::vector<uint16_t>& ports, const std::vector<uint16_t>& locals,
                                  const std::vector<bool>& fromStun) {
        AllocationInfo base = classifyAllocation(ports, locals, cfg.advanced);
        auto sequential = [](const AllocationInfo& a) {
            return a.pattern == AllocationPattern::Sequential || a.pattern == AllocationPattern::SequentialNoisy ||
                   a.pattern == AllocationPattern::PortPreserving;
        };
        const double target = cfg.advanced.confidenceTarget;
        if ((sequential(base) && base.confidence >= target) || !locals.empty()) return base;
        std::vector<size_t> cand;
        for (size_t i = 0; i < ports.size(); ++i) if (fromStun[i]) cand.push_back(i);
        auto without = [&](size_t a, size_t b) {
            std::vector<uint16_t> v;
            for (size_t i = 0; i < ports.size(); ++i) if (i != a && i != b) v.push_back(ports[i]);
            return v;
        };
        std::optional<AllocationInfo> best;
        auto consider = [&](const std::vector<uint16_t>& v) {
            if (v.size() < 6) return;
            AllocationInfo a = classifyAllocation(v, {}, cfg.advanced);
            if (a.pattern != AllocationPattern::Sequential || a.confidence < target) return;
            if (!best || a.confidence > best->confidence) best = a;
        };
        const size_t none = size_t(-1);
        for (size_t i : cand) consider(without(i, none));
        if (!best)
            for (size_t x = 0; x < cand.size(); ++x)
                for (size_t y = x + 1; y < cand.size(); ++y) consider(without(cand[x], cand[y]));
        return best ? *best : base;
    }

    void parity() {
        int ok = 0, n = 0;
        for (auto& p : eng.probes())
            if (p.same && p.localPort) { ++n; ok += (p.same->port & 1) == (p.localPort & 1); }
        prof.details.parityPreserved = n >= 8 && ok >= n * 9 / 10;
    }

    void endSameRound(TimePoint now) {
        auto info = round == 0 ? classifyRound(false, mapSamples, mapSampleStun) : classifyRound(false);
        eng.clear();
        auto& d = prof.details;
        if (!haveSame || info.confidence >= d.sameSocket.confidence) d.sameSocket = info;
        haveSame = true;
        ++round;
        if (info.confidence >= cfg.advanced.confidenceTarget || !startSameRoundAfterGap(now)) startFiltering(now);
    }

    bool pendingSameStart = false, pendingNewStart = false, pendingDriftStart = false;
    std::optional<std::pair<uint16_t, TimePoint>> lastAlloc;   // latest mapping seen (port, creation time)

    bool startSameRoundAfterGap(TimePoint now) {
        const auto& steps = cfg.advanced.allocSameSocketSteps;
        if (round >= steps.size() || freshDests.size() - freshNext < 4) return false;
        waitUntil = now + cfg.advanced.roundGap;
        pendingSameStart = true;
        return true;
    }

    void endNewRound(TimePoint now) {
        auto info = classifyRound(true);
        parity();
        for (auto& p : eng.probes())
            if (p.same && (!lastAlloc || p.firstSent >= lastAlloc->second)) lastAlloc = {{p.same->port, p.firstSent}};
        eng.clear();
        closeAll();
        auto& d = prof.details;
        if (d.newSocket.pattern == AllocationPattern::Unknown || info.confidence >= d.newSocket.confidence)
            d.newSocket = info;
        ++round;
        // With endpoint-independent mapping the allocation is diagnostic only:
        // one round is enough.
        bool more = d.mapping != MappingBehavior::EndpointIndependent &&
                    info.confidence < cfg.advanced.confidenceTarget &&
                    round < cfg.advanced.allocNewSocketSteps.size();
        if (more) {
            waitUntil = now + cfg.advanced.roundGap;
            pendingNewStart = true;
            return;
        }
        // Sequential allocator: measure how fast other subscribers move it.
        const auto& a = d.newSocket;
        if (d.mapping != MappingBehavior::EndpointIndependent && d.behindNat && lastAlloc && a.delta != 0 &&
            (a.pattern == AllocationPattern::Sequential || a.pattern == AllocationPattern::SequentialNoisy)) {
            phase = Phase::Drift;
            waitUntil = std::max(now, lastAlloc->second + cfg.advanced.driftGap);
            pendingDriftStart = true;
            return;
        }
        finishAllocation(now);
    }

    void endDrift(TimePoint now) {
        auto& d = prof.details;
        const auto& p = eng.probes().front();
        if (p.same && lastAlloc) {
            const int32_t delta = d.newSocket.delta;
            const int dir = delta > 0 ? 1 : -1;
            int32_t step = int32_t(int16_t(uint16_t(p.same->port - lastAlloc->first)));
            double secs = std::chrono::duration<double>(p.firstSent - lastAlloc->second).count();
            // Ports beyond our own step, in the allocator's direction. A step
            // the wrong way (wrap of a port block, reset) gives no estimate.
            // +1 port (add-one estimate): seeing nobody in a 2 s window does not
            // mean nobody allocates, and a zero rate would make the prediction
            // bet everything on a single port.
            if (secs > 0 && step * dir > 0)
                d.allocationRate = (std::max(0, step * dir - std::abs(delta)) + 1) / secs;
            noteIp(p.same->ip);
        }
        eng.clear();
        closeAll();
        finishAllocation(now);
    }

    void finishAllocation(TimePoint now) {
        auto& d = prof.details;
        if (d.mapping == MappingBehavior::AddressDependent ||
            (d.mapping == MappingBehavior::AddressPortDependent && !haveSame)) {
            d.sameSocket = d.newSocket;
            d.sameSocketFromNewSocket = true;
        }
        computeProfile();
        if (cfg.measureLifetime && !noReflector && prof.predictability != Predictability::UdpBlocked) {
            publish(DiscoveryState::Provisional);
            startLifetime(now);
        } else {
            phase = Phase::Done;
            publish(DiscoveryState::Final);
        }
    }

    void computeProfile() {
        auto& d = prof.details;
        const double target = cfg.advanced.confidenceTarget;
        if (!d.behindNat || d.mapping == MappingBehavior::EndpointIndependent) {
            prof.predictability = Predictability::Stable;
            prof.confidence = 1.0;
            return;
        }
        if (d.mapping == MappingBehavior::Unknown) {
            prof.predictability = Predictability::Inconclusive;
            prof.confidence = 0;
            return;
        }
        // Random allocators: the hard side punches from new sockets
        // (BirthdayListen), so the new-socket sample, taken on one reflector
        // port and grown to 64 when needed, is the stronger evidence when both
        // samples agree that allocation is random.
        auto isRandom = [](AllocationPattern p) {
            return p == AllocationPattern::RandomInBlock || p == AllocationPattern::RandomFull;
        };
        const AllocationInfo& a = isRandom(d.sameSocket.pattern) && isRandom(d.newSocket.pattern) &&
                                          d.newSocket.confidence > d.sameSocket.confidence
                                      ? d.newSocket
                                      : d.sameSocket;
        prof.confidence = a.confidence;
        if (a.confidence < target / 2) { prof.predictability = Predictability::Inconclusive; return; }
        switch (a.pattern) {
        case AllocationPattern::PortPreserving:
        case AllocationPattern::Sequential:
        case AllocationPattern::SequentialNoisy: prof.predictability = Predictability::Predictable; break;
        case AllocationPattern::RandomInBlock: prof.predictability = Predictability::Bounded; break;
        case AllocationPattern::RandomFull: prof.predictability = Predictability::Unpredictable; break;
        case AllocationPattern::Unknown: prof.predictability = Predictability::Inconclusive; break;
        }
    }

    void startLifetime(TimePoint) {
        phase = Phase::Lifetime;
        const auto& grid = cfg.advanced.lifetimeGridSec;
        int tag = 0;
        for (int g : grid) {
            if (g <= 0) { ++tag; continue; }
            uint32_t ms = uint32_t(g) * 1000u;
            if (ms > proto::kMaxDelayMs) { ++tag; continue; }
            // Both variants or none, within the cap (normally reserved by room()).
            if (cfg.advanced.maxMappings > 0 && used + 2 > cfg.advanced.maxMappings) { ++tag; continue; }
            if (auto s = openSock(false)) { eng.add(*s, ep(0, 0), 0, ms, ProbeKind::LifeSingle, tag); ++used; }
            if (auto s = openSock(false)) {
                eng.add(*s, ep(0, 0), proto::ReplySame, ms, ProbeKind::LifeBidir, tag);
                ++used;
            }
            ++tag;
        }
    }

    void endLifetime() {
        const auto& grid = cfg.advanced.lifetimeGridSec;
        const size_t G = grid.size();
        // Per grid value: -1 unknown, 0 binding expired, 1 binding alive.
        // Unknown = not run, refused by the reflector (pending caps), or, for
        // the bidirectional variant, request never acknowledged (lost or
        // rate-limited). Only known results count.
        std::vector<int> single(G, -1), bidir(G, -1);
        for (auto& p : eng.probes()) {
            int v = p.delayed ? 1 : 0;
            if (p.refused) v = -1;
            if (p.kind == ProbeKind::LifeBidir && !p.same && !p.delayed) v = -1;
            (p.kind == ProbeKind::LifeSingle ? single : bidir)[p.tag] = v;
        }
        struct Summary { std::optional<Duration> bound; bool known = false; bool allAlive = true; };
        // Longest run of successes from the smallest known value: an expiry
        // further up ends the run (conservative), unknown values are skipped.
        auto summarize = [&](const std::vector<int>& r) {
            Summary sm;
            bool ended = false;
            for (size_t i = 0; i < G; ++i) {
                if (r[i] < 0) { sm.allAlive = false; continue; }
                sm.known = true;
                if (r[i] == 0) { sm.allAlive = false; ended = true; }
                if (!ended) sm.bound = Duration(int64_t(grid[i]) * 1000);
            }
            if (!sm.known) sm.allAlive = false;
            return sm;
        };
        const Summary S = summarize(single), B = summarize(bidir);
        auto& d = prof.details;
        d.singlePacketLifetime = S.bound;
        d.bidirectionalLifetime = B.bound;
        d.lifetimeAtLeast = B.allAlive;
        prof.lifetimeMeasured = S.known || B.known;
        const auto& a = cfg.advanced;
        // A variant with no known result keeps its default timer; a known
        // variant whose smallest value already expired gets minInterval.
        if (S.known)
            prof.punchInterval = S.bound ? detail::clampDur(0.4 * double(S.bound->count()), a.minInterval,
                                                            a.defaultPunchInterval)
                                         : a.minInterval;
        if (B.known)
            prof.keepaliveInterval = B.bound ? detail::clampDur(0.5 * double(B.bound->count()), a.minInterval,
                                                                a.maxKeepalive)
                                             : a.minInterval;
    }

    // ----------------------------------------------------------------- loop
    TimePoint poll(TimePoint now) {
        for (int guard = 0; guard < 16; ++guard) {
            if (st == DiscoveryState::Idle || st == DiscoveryState::Cancelled || phase == Phase::Done)
                return TimePoint::max();
            if (now < waitUntil) return waitUntil;
            if (phase == Phase::Hairpin) {
                TimePoint w = pollHairpin(now);
                if (phase == Phase::Hairpin) return w;
                continue;
            }
            if (pendingSameStart) {
                pendingSameStart = false;
                if (!startSameRound()) { startFiltering(now); continue; }
            }
            if (pendingDriftStart) {
                pendingDriftStart = false;
                auto sock = room() >= 1 ? openSock(cfg.advanced.sequentialLocalPorts) : std::nullopt;
                if (!sock) { finishAllocation(now); continue; }
                addNsProbe(*sock, 0);
                used += 1;
            }
            if (pendingNewStart) {
                pendingNewStart = false;
                if (!startNewRound()) { finishAllocation(now); continue; }
            }
            TimePoint next = eng.poll(now);
            // STUN transactions still open that the phase no longer needs
            // (stunStaleAfter): it ends without them, abandoning them.
            if (!eng.idle() && !(eng.onlyStale() && doneWithoutStale())) return next;
            switch (phase) {
            case Phase::Mapping: endMapping(now); break;
            case Phase::Filtering: endFiltering(now); break;
            case Phase::AllocSame: endSameRound(now); break;
            case Phase::AllocNew: endNewRound(now); break;
            case Phase::Drift: endDrift(now); break;
            case Phase::Lifetime:
                endLifetime();
                eng.clear();
                closeAll();
                phase = Phase::Done;
                publish(DiscoveryState::Final);
                break;
            default: return TimePoint::max();
            }
        }
        return now;
    }

    bool onDatagram(SocketId s, const Endpoint& from, const uint8_t* d, size_t len, TimePoint now) {
        if (st == DiscoveryState::Idle || st == DiscoveryState::Cancelled) return false;
        if (phase == Phase::Hairpin && onHairpin(s, from, d, len)) return true;
        return eng.onDatagram(s, from, d, len, now);
    }

    void cancel() {
        if (st == DiscoveryState::Final) return;
        eng.clear();
        closeAll();
        phase = Phase::Done;
        st = DiscoveryState::Cancelled;
    }
};

NatDiscovery::NatDiscovery(DiscoveryConfig cfg, IDatagramIo& io)
    : impl_(std::make_unique<Impl>(std::move(cfg), io)) {}
NatDiscovery::~NatDiscovery() = default;
void NatDiscovery::start(TimePoint now) { impl_->start(now); }
void NatDiscovery::cancel() { impl_->cancel(); }
bool NatDiscovery::onDatagram(SocketId s, const Endpoint& f, const uint8_t* d, size_t l, TimePoint n) {
    return impl_->onDatagram(s, f, d, l, n);
}
TimePoint NatDiscovery::poll(TimePoint now) {
    // Network change mid-run (another public IP seen by the reflector): the
    // data mixes two NATs, start over once.
    if (impl_->ipChanged && impl_->restarts < 1 && impl_->st != DiscoveryState::Cancelled) {
        DiscoveryConfig cfg = impl_->cfg;
        IDatagramIo& io = impl_->io;
        const uint32_t v = impl_->version;
        const int r = impl_->restarts + 1;
        impl_ = std::make_unique<Impl>(std::move(cfg), io);
        impl_->restarts = r;
        impl_->version = v;
        impl_->prof.details.restarts = r;
        impl_->start(now);
    }
    return impl_->poll(now);
}
DiscoveryState NatDiscovery::state() const { return impl_->st; }
const NatProfile& NatDiscovery::result() const { return impl_->prof; }
uint32_t NatDiscovery::resultVersion() const { return impl_->version; }

// ===========================================================================
// QuickCheck: one probe from the primary socket to R0:p0; if R0 does not
// answer, R1:p0 when clients may reach R1, otherwise up to two STUN servers.
// ===========================================================================
struct QuickCheck::Impl {
    DiscoveryConfig cfg;
    NatProfile expected;
    IDatagramIo& io;
    detail::ProbeEngine eng;
    QuickCheckResult res = QuickCheckResult::Pending;
    Endpoint obs;
    int stage = -1;
    std::vector<std::pair<Endpoint, bool>> targets;   // (destination, is STUN), tried in order

    Impl(const DiscoveryConfig& c, const NatProfile& e, IDatagramIo& i)
        : cfg(c), expected(e), io(i), eng(i, cfg.advanced, detail::reflectorIps(cfg)) {
        for (size_t b = 0; b < cfg.reflectors.size(); b += 2)   // R0 of every pair
            if (!cfg.reflectors[b].ports.empty())
                targets.push_back({{cfg.reflectors[b].ip, cfg.reflectors[b].ports[0]}, false});
        if (cfg.reflectors.size() > 1 && !cfg.reflectors[1].ports.empty())
            targets.push_back({{cfg.reflectors[1].ip, cfg.reflectors[1].ports[0]}, false});
        else
            for (size_t k = 0; k < cfg.stunServers.size() && k < 2; ++k) targets.push_back({cfg.stunServers[k].ep, true});
    }

    void send(int i) {
        stage = i;
        if (targets[i].second) eng.addStun(cfg.primarySocket, targets[i].first, 0);
        else eng.add(cfg.primarySocket, targets[i].first, proto::ReplySame, 0, ProbeKind::Basic, 0);
    }

    void start(TimePoint) {
        if (stage >= 0) return;
        if (targets.empty()) { res = QuickCheckResult::Unreachable; return; }
        send(0);
    }

    void judge() {
        const auto& d = expected.details;
        bool ok;
        switch (expected.predictability) {
        case Predictability::Stable: ok = obs == expected.publicEndpoint; break;
        case Predictability::Bounded:
            ok = obs.ip == expected.publicEndpoint.ip &&
                 (!d.sameSocket.block.size || d.sameSocket.block.contains(obs.port));
            break;
        default: ok = obs.ip == expected.publicEndpoint.ip; break;
        }
        res = ok ? QuickCheckResult::Valid : QuickCheckResult::Changed;
    }

    // Targets in order: the next one is asked when the current one failed,
    // or, for a STUN server, while it is still running but stale (its
    // transaction goes on in parallel, RFC 8489 §6.2.1). The first answer counts.
    TimePoint poll(TimePoint now) {
        if (res != QuickCheckResult::Pending || stage < 0) return TimePoint::max();
        for (int guard = 0; guard < 8; ++guard) {
            TimePoint next = eng.poll(now);
            for (const auto& p : eng.probes())
                if (p.same) { obs = *p.same; judge(); eng.clear(); return TimePoint::max(); }
            const bool more = stage + 1 < int(targets.size());
            if (eng.idle()) {
                if (!more) { res = QuickCheckResult::Unreachable; return TimePoint::max(); }
                send(stage + 1);
                continue;
            }
            if (more && eng.onlyStale()) { send(stage + 1); continue; }
            return next;
        }
        return now;
    }
};

QuickCheck::QuickCheck(const DiscoveryConfig& cfg, const NatProfile& expected, IDatagramIo& io)
    : impl_(std::make_unique<Impl>(cfg, expected, io)) {}
QuickCheck::~QuickCheck() = default;
void QuickCheck::start(TimePoint now) { impl_->start(now); }
bool QuickCheck::onDatagram(SocketId s, const Endpoint& f, const uint8_t* d, size_t l, TimePoint n) {
    return impl_->eng.onDatagram(s, f, d, l, n);
}
TimePoint QuickCheck::poll(TimePoint now) { return impl_->poll(now); }
QuickCheckResult QuickCheck::result() const { return impl_->res; }
Endpoint QuickCheck::observed() const { return impl_->obs; }

} // namespace natd
