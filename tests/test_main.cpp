// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd unit and simulation tests. Exit code 0 = all passed.
#include "natd/natd.hpp"
#include "simnet.hpp"
#include "../src/sha256.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>

using namespace natd;
using namespace sim;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond)                                                                  \
    do {                                                                             \
        ++g_checks;                                                                  \
        if (!(cond)) { ++g_fail; std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)
#define CHECK_EQ(a, b)                                                               \
    do {                                                                             \
        ++g_checks;                                                                  \
        auto va = (a); auto vb = (b);                                                \
        if (!(va == vb)) { ++g_fail; std::printf("  FAIL %s:%d  %s == %s\n", __FILE__, __LINE__, #a, #b); } \
    } while (0)

// ---------------------------------------------------------------- classifier
static std::vector<uint16_t> seq(uint16_t start, int n, int step) {
    std::vector<uint16_t> v;
    for (int i = 0; i < n; ++i) v.push_back(uint16_t(start + i * step));
    return v;
}

static void testClassifier() {
    std::puts("classifier");
    AdvancedConfig cfg;
    std::mt19937 rng(7);

    auto a = classifyAllocation(seq(40000, 16, 1), {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::Sequential);
    CHECK_EQ(a.delta, 1);
    CHECK(a.confidence >= 0.99);

    a = classifyAllocation(seq(40000, 16, -2), {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::Sequential);
    CHECK_EQ(a.delta, -2);

    // Wrap-around 65535 -> 0 keeps a +1 step
    a = classifyAllocation(seq(65530, 12, 1), {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::Sequential);

    // One outlier in 16 still a clean sequence (15/16 >= 0.8 is not required: 14/15 steps)
    auto v = seq(40000, 16, 1);
    v[8] = 41000;
    a = classifyAllocation(v, {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::Sequential);   // 13 of 15 steps are +1

    // Noisy: +1..+7
    v.clear();
    uint16_t p = 30000;
    for (int i = 0; i < 16; ++i) { v.push_back(p); p = uint16_t(p + 1 + rng() % 7); }
    a = classifyAllocation(v, {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::SequentialNoisy);
    CHECK(a.delta >= 1 && a.delta <= 7);

    // Port preserving
    auto loc = seq(50000, 16, 1);
    a = classifyAllocation(loc, loc, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::PortPreserving);

    // Random in an aligned 2048 block
    v.clear();
    for (int i = 0; i < 32; ++i) v.push_back(uint16_t(20480 + rng() % 2048));
    a = classifyAllocation(v, {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::RandomInBlock);
    CHECK(a.block.size >= 1024 && a.block.size <= 4096);
    for (auto x : v) CHECK(a.block.contains(x));
    CHECK(a.confidence >= cfg.confidenceTarget);

    // Random over the whole range
    v.clear();
    for (int i = 0; i < 16; ++i) v.push_back(uint16_t(1024 + rng() % 64512));
    a = classifyAllocation(v, {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::RandomFull);
    CHECK(a.confidence >= cfg.confidenceTarget);

    // Few random samples -> below target, discovery will sample more
    v.resize(6);
    a = classifyAllocation(v, {}, cfg);
    CHECK(a.confidence < cfg.confidenceTarget);

    // Degenerate input
    a = classifyAllocation({1234}, {}, cfg);
    CHECK_EQ(a.pattern, AllocationPattern::Unknown);
    CHECK_EQ(a.confidence, 0.0);
}

// ---------------------------------------------------------------- protocol / reflector
struct CaptureIo : IReflectorIo {
    struct Out { uint32_t pi; Endpoint to; std::vector<uint8_t> d; };
    std::vector<Out> out;
    void send(uint32_t pi, const Endpoint& to, const uint8_t* d, size_t len) override {
        out.push_back({pi, to, std::vector<uint8_t>(d, d + len)});
    }
};

static void testReflector() {
    std::puts("reflector");
    CaptureIo io;
    ReflectorConfig rc;
    rc.portCount = 4;
    rc.partners = {{kR1, 3478}};
    rc.ratePerIp = 10;
    rc.burstPerIp = 5;
    rc.maxPendingPerEndpoint = 2;
    rc.maxPendingPerIp = 3;
    rc.partnerCheckInterval = Duration(0);   // partner checks tested below
    Reflector r(rc, io);
    TimePoint t{std::chrono::hours(1)};
    Endpoint client{0x0A000001, 5000};

    proto::ProbeReq req;
    req.mask = proto::ReplySame | proto::ReplyOtherPort | proto::ReplyPartner;
    auto b = proto::encode(req);
    CHECK(r.onDatagram(0, client, b.data(), b.size(), t));
    CHECK_EQ(io.out.size(), size_t(3));
    CHECK_EQ(b.size(), proto::kProbeReqSize);
    CHECK(io.out[0].to == client);
    CHECK_EQ(io.out[1].pi, 1u);
    CHECK(io.out[2].to == (Endpoint{kR1, 3478}));         // forward goes to the partner only
    auto fw = proto::decodeForwardReq(io.out[2].d.data(), io.out[2].d.size());
    CHECK(fw && fw->target == client);

    // Truncated request rejected (anti-amplification)
    io.out.clear();
    r.onDatagram(0, client, b.data(), 40, t);
    CHECK(io.out.empty());

    // FORWARD_REQ from a non-partner is dropped
    proto::ForwardReq f{{}, Endpoint{0x08080808, 53}};
    auto fb = proto::encode(f);
    r.onDatagram(0, Endpoint{0x01020304, 3478}, fb.data(), fb.size(), t);
    CHECK(io.out.empty());
    CHECK_EQ(r.stats().droppedNotPartner, 1u);

    // Rate limit: burst 5, one already used
    proto::ProbeReq one;
    auto ob = proto::encode(one);
    for (int i = 0; i < 10; ++i) r.onDatagram(0, client, ob.data(), ob.size(), t);
    CHECK_EQ(io.out.size(), size_t(4));
    CHECK_EQ(r.stats().droppedRate, 6u);

    // Delayed replies: capped per endpoint (2) and per IP (3); excess answered
    // at once with Refused instead of being dropped silently.
    io.out.clear();
    Endpoint c2{0x0A000002, 6000}, c3{0x0A000002, 6001};
    proto::ProbeReq d;
    d.mask = 0;
    d.delayMs = 1000;
    auto db = proto::encode(d);
    auto kindOf = [](const CaptureIo::Out& o) {
        auto x = proto::decodeProbeResp(o.d.data(), o.d.size());
        return x ? int(x->kind) : -1;
    };
    for (int i = 0; i < 3; ++i) r.onDatagram(0, c2, db.data(), db.size(), t);   // 3rd: endpoint cap
    CHECK_EQ(io.out.size(), size_t(1));
    CHECK_EQ(kindOf(io.out[0]), int(proto::ReplyKind::Refused));
    CHECK(io.out[0].to == c2);
    r.onDatagram(0, c3, db.data(), db.size(), t);                               // same IP, 3rd pending
    r.onDatagram(0, c3, db.data(), db.size(), t);                               // IP cap
    CHECK_EQ(io.out.size(), size_t(2));
    CHECK_EQ(kindOf(io.out[1]), int(proto::ReplyKind::Refused));
    CHECK_EQ(r.stats().refused, 2u);
    io.out.clear();
    r.poll(t + Duration(1000));
    CHECK_EQ(io.out.size(), size_t(3));
    for (auto& o : io.out) CHECK_EQ(kindOf(o), int(proto::ReplyKind::Delayed));
    // Quotas released: the same endpoint can queue again
    io.out.clear();
    r.onDatagram(0, c2, db.data(), db.size(), t + Duration(1000));
    CHECK(io.out.empty());

    // Amplification: the worst request (all reply kinds + a refused delay)
    // sends back fewer bytes towards its source than it carried.
    CaptureIo io2;
    ReflectorConfig rc2;
    rc2.portCount = 2;
    rc2.partners = {{kR1, 3478}};
    rc2.maxPendingPerEndpoint = 0;   // force Refused
    rc2.partnerCheckInterval = Duration(0);
    Reflector r2(rc2, io2);
    proto::ProbeReq worst;
    worst.mask = proto::ReplySame | proto::ReplyOtherPort | proto::ReplyPartner;
    worst.delayMs = 1000;
    auto wb = proto::encode(worst);
    r2.onDatagram(0, client, wb.data(), wb.size(), t);
    size_t toClient = 0;
    for (auto& o : io2.out) if (o.to.ip == client.ip) toClient += o.d.size();
    toClient += proto::kProbeRespSize;   // the partner's reply, triggered by the FORWARD_REQ
    CHECK_EQ(toClient, size_t(4 * proto::kProbeRespSize));
    CHECK(toClient <= wb.size());
    // Truncated (old 64-byte) requests are rejected
    r2.onDatagram(0, Endpoint{0x0A000009, 1}, wb.data(), 64, t);
    CHECK_EQ(r2.stats().droppedInvalid, 1u);
}

// ---------------------------------------------------------------- end-to-end discovery
struct RunResult {
    NatProfile provisional, final;
    DiscoveryState state;
    bool sawProvisional = false;
    double provisionalAtSec = 0, finalAtSec = 0;
    int openedSockets = 0, leaked = 0;
    uint64_t sent = 0;
    size_t mappings = 0, peakMappings = 0, refused = 0;
    uint64_t r1Requests = 0, r1Forwards = 0, stunRequests = 0, r0FirewallDrops = 0;
};

static RunResult runDiscovery(NatModel m, bool lifetime = true, uint32_t seed = 1,
                              std::function<void(ReflectorConfig&)> tweak = {},
                              std::function<void(DiscoveryConfig&)> cfgTweak = {},
                              std::function<void(Net&)> netTweak = {}) {
    Net net(m, seed, tweak);
    if (netTweak) netTweak(net);
    auto primary = *net.openSocket(4662);
    auto cfg = discoveryConfig(net, primary);
    cfg.measureLifetime = lifetime;
    if (cfgTweak) cfgTweak(cfg);
    net.r0FirstPortOnly = cfg.reflectors.size() > 0 && cfg.reflectors[0].ports.size() <= 1;
    NatDiscovery disc(cfg, net);
    net.onClientRx = [&](const Net::Rx& rx) {
        disc.onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), net.now);
    };
    RunResult rr;
    TimePoint t0 = net.now;
    disc.start(net.now);
    net.run([&](TimePoint now) {
        TimePoint w = disc.poll(now);
        if (disc.state() == DiscoveryState::Provisional && !rr.sawProvisional) {
            rr.sawProvisional = true;
            rr.provisional = disc.result();
            rr.provisionalAtSec = std::chrono::duration<double>(now - t0).count();
        }
        return w;
    }, t0 + std::chrono::minutes(10));
    rr.state = disc.state();
    rr.final = disc.result();
    rr.finalAtSec = std::chrono::duration<double>(net.now - t0).count();
    rr.openedSockets = net.opened - 1;
    rr.leaked = net.opened - net.closed - 1;   // primary stays open
    rr.sent = net.clientSent;
    rr.mappings = net.host.box.mappingsCreated;
    rr.peakMappings = net.host.box.peakLive;
    rr.refused = net.host.box.mappingsRefused;
    rr.r1Requests = net.reflStats(1).requests - net.reflStats(0).partnerChecks;   // minus R0's partner checks
    rr.r1Forwards = net.reflStats(1).forwardsServed;
    rr.r0FirewallDrops = net.r0FirewallDrops;
    for (auto& sv : net.stun) rr.stunRequests += sv.requests;
    return rr;
}

static void show(const char* name, const RunResult& r) {
    const auto& p = r.final;
    const auto& d = p.details;
    std::printf("  %-28s %-13s map=%-20s filt=%-20s same=%s/%d(%.2f,n=%d%s) new=%s(%.2f,n=%d) "
                "life=%llds/%llds punch=%llds ka=%llds prov@%.1fs final@%.0fs socks=%d pkts=%llu\n",
                name, toString(p.predictability), toString(d.mapping), toString(d.filtering),
                toString(d.sameSocket.pattern), d.sameSocket.delta, d.sameSocket.confidence, d.sameSocket.samples,
                d.sameSocketFromNewSocket ? ",fallback" : "", toString(d.newSocket.pattern), d.newSocket.confidence,
                d.newSocket.samples,
                (long long)(d.singlePacketLifetime ? d.singlePacketLifetime->count() / 1000 : -1),
                (long long)(d.bidirectionalLifetime ? d.bidirectionalLifetime->count() / 1000 : -1),
                (long long)(p.punchInterval.count() / 1000), (long long)(p.keepaliveInterval.count() / 1000),
                r.provisionalAtSec, r.finalAtSec, r.openedSockets, (unsigned long long)r.sent);
}

// Mappings each discovery creates on the NAT (CGN port quota, RFC 6888 REQ-4).
static void testMappingBudget() {
    std::puts("mapping budget (discovery, mappings created / peak alive)");
    struct Case { const char* name; Map m; Filt f; Alloc a; double busy; };
    const Case cases[] = {
        {"EIM, APDF, preserving", Map::EI, Filt::APD, Alloc::Preserve, 0},
        {"EIM, APDF, random", Map::EI, Filt::APD, Alloc::RandomFull, 0},
        {"ADM, sequential", Map::AD, Filt::APD, Alloc::Sequential, 0},
        {"APDM, sequential", Map::APD, Filt::APD, Alloc::Sequential, 0},
        {"APDM, sequential busy 50/s", Map::APD, Filt::APD, Alloc::Sequential, 50},
        {"APDM, noisy", Map::APD, Filt::APD, Alloc::Noisy, 0},
        {"APDM, random in block", Map::APD, Filt::APD, Alloc::RandomBlock, 0},
        {"APDM, random full", Map::APD, Filt::APD, Alloc::RandomFull, 0},
    };
    for (const auto& c : cases) {
        size_t mx[2] = {0, 0}, pk[2] = {0, 0}, sum[2] = {0, 0};
        for (int life = 0; life < 2; ++life)
            for (uint32_t seed = 1; seed <= 20; ++seed) {
                NatModel m; m.mapping = c.m; m.filtering = c.f; m.alloc = c.a; m.othersPerSec = c.busy;
                auto r = runDiscovery(m, life == 1, seed);
                mx[life] = std::max(mx[life], r.mappings);
                pk[life] = std::max(pk[life], r.peakMappings);
                sum[life] += r.mappings;
            }
        std::printf("  %-28s no lifetime: mean %5.1f max %3zu peak %3zu | lifetime: mean %5.1f max %3zu peak %3zu\n",
                    c.name, sum[0] / 20.0, mx[0], pk[0], sum[1] / 20.0, mx[1], pk[1]);
        CHECK(mx[0] <= 4 + 6 + 1 + 2 + 112 + 1);    // worst case without lifetime
        CHECK_EQ(mx[1], mx[0] + 20);                 // lifetime: 2 sockets per grid value
    }
}

// CGN limits (RFC 6888 REQ-4 port quota, REQ-4c mapping rate): what the
// discovery reports when the NAT refuses mappings.
static void testFilterTimeout() {
    std::puts("NAT filter state per remote (filterTimeout)");
    for (const Filt f : {Filt::APD, Filt::AD}) {
        NatModel m; m.mapping = Map::EI; m.filtering = f; m.filterTimeout = Duration(60000);
        NatBox box(m, 1);
        const Endpoint a{0x0A000001, 5000}, b{0x0A000002, 5000};
        TimePoint t{};
        const uint16_t ext = box.outbound(1, 4672, a, t);
        CHECK(box.inbound(ext, a, t + Duration(20000)).has_value());     // answered in time
        // Traffic to b keeps the binding, not a's permission.
        for (int i = 1; i <= 6; ++i) CHECK_EQ(box.outbound(1, 4672, b, t + Duration(i * 20000)), ext);
        CHECK(!box.inbound(ext, a, t + Duration(85000)).has_value());   // 65 s after the last packet with a
        CHECK(box.inbound(ext, b, t + Duration(130000)).has_value());
        box.outbound(1, 4672, a, t + Duration(140000));                  // a datagram to a opens it again
        CHECK(box.inbound(ext, a, t + Duration(141000)).has_value());
        // filterTimeout 0: a remote stays allowed as long as the binding lives.
        NatModel m0 = m; m0.filterTimeout = Duration(0);
        NatBox box0(m0, 1);
        const uint16_t e0 = box0.outbound(1, 4672, a, t);
        for (int i = 1; i <= 6; ++i) box0.outbound(1, 4672, b, t + Duration(i * 20000));
        CHECK(box0.inbound(e0, a, t + Duration(130000)).has_value());
    }
}

static void testCgnLimits() {
    std::puts("CGN limits (discovery under port quota / mapping rate)");
    struct M { const char* name; Map m; Alloc a; };
    const M models[] = {{"EIM", Map::EI, Alloc::Preserve},
                        {"APDM seq", Map::APD, Alloc::Sequential},
                        {"APDM rand", Map::APD, Alloc::RandomFull}};
    struct L { size_t quota; double rate; };
    const L limits[] = {{0, 0}, {64, 0}, {52, 0}, {48, 0}, {32, 0}, {24, 0}, {16, 0}, {8, 0},
                        {0, 50}, {0, 20}, {0, 10}, {0, 5}};
    for (const auto& mo : models)
        for (const auto& li : limits) {
            NatModel m; m.mapping = mo.m; m.filtering = Filt::APD; m.alloc = mo.a;
            m.portQuota = li.quota; m.mappingRate = li.rate;
            auto r = runDiscovery(m, true, 1);
            const auto& d = r.final.details;
            std::printf("  %-9s quota %3zu rate %4.0f  %-13s map=%-20s filt=%-20s same=%s(%.2f,n=%d) new=%s(%.2f,n=%d) "
                        "life=%llds/%llds refused=%zu created=%zu\n",
                        mo.name, li.quota, li.rate, toString(r.final.predictability), toString(d.mapping),
                        toString(d.filtering), toString(d.sameSocket.pattern), d.sameSocket.confidence,
                        d.sameSocket.samples, toString(d.newSocket.pattern), d.newSocket.confidence,
                        d.newSocket.samples,
                        (long long)(d.singlePacketLifetime ? d.singlePacketLifetime->count() / 1000 : -1),
                        (long long)(d.bidirectionalLifetime ? d.bidirectionalLifetime->count() / 1000 : -1),
                        r.refused, r.mappings);
            // A refused mapping looks like a lost packet: the result may get
            // less precise, never wrong. Predictability stays right or turns
            // Inconclusive; with room for the whole discovery nothing changes.
            Predictability want = mo.m == Map::EI ? Predictability::Stable
                                : mo.a == Alloc::Sequential ? Predictability::Predictable
                                                            : Predictability::Unpredictable;
            CHECK(r.final.predictability == want || r.final.predictability == Predictability::Inconclusive);
            if (li.quota == 0 || li.quota >= 52) CHECK(li.rate > 0 || r.refused == 0);
        }
    // Worst case: every sampling round ambiguous (target never reached).
    for (int cap : {0, 100, 64}) {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
        auto r = runDiscovery(m, true, 1, {}, [&](DiscoveryConfig& c) {
            c.advanced.confidenceTarget = 1.01;
            c.advanced.maxMappings = cap;
        });
        const auto& d = r.final.details;
        std::printf("  worst case, cap %3d: created %zu, %s same n=%d new n=%d life=%llds/%llds\n", cap, r.mappings,
                    toString(r.final.predictability), d.sameSocket.samples, d.newSocket.samples,
                    (long long)(d.singlePacketLifetime ? d.singlePacketLifetime->count() / 1000 : -1),
                    (long long)(d.bidirectionalLifetime ? d.bidirectionalLifetime->count() / 1000 : -1));
        if (cap == 0) CHECK_EQ(r.mappings, size_t(4 + 6 + 1 + 2 + 112 + 20));
        else CHECK(r.mappings <= size_t(cap));
        CHECK(r.final.lifetimeMeasured);   // the lifetime test keeps its room
    }
    // A block guessed from a couple of samples is not trusted by the planner.
    {
        PeerInfo a, b;
        a.observed = {0xCB007105, 4662}; b.observed = {0xCB007106, 4662};
        a.profile.predictability = Predictability::Stable;
        a.profile.details.mapping = MappingBehavior::EndpointIndependent;
        a.profile.details.filtering = FilteringBehavior::AddressPortDependent;
        b.profile.predictability = Predictability::Bounded;
        b.profile.details.mapping = MappingBehavior::AddressPortDependent;
        b.profile.details.newSocket.pattern = AllocationPattern::RandomInBlock;
        b.profile.details.newSocket.block = {20000, 64};
        b.profile.details.newSocket.samples = 2;
        b.profile.details.newSocket.confidence = 0.29;
        auto p = planPunch(a, b, PunchLimits{});
        CHECK_EQ(p.strategy, PunchStrategy::BirthdaySpray);
        bool outside = false;
        for (auto& t : p.targets) outside |= t.port < 20000 || t.port >= 20064;
        CHECK(outside);                       // full range, not the 64-port guess
        CHECK(p.estimatedSuccess < 0.9);
        b.profile.details.newSocket.confidence = 0.9;
        auto q = planPunch(a, b, PunchLimits{});
        bool inside = !q.targets.empty();
        for (auto& t : q.targets) inside &= t.port >= 20000 && t.port < 20064;
        CHECK(inside);                        // a confident block is used
    }
    // Punch mapping cap: K sockets and, with per-target mapping, M targets.
    {
        PeerInfo s, h;
        s.observed = {0xCB007105, 4662}; h.observed = {0xCB007106, 4662};
        s.profile.predictability = Predictability::Stable;
        s.profile.details.mapping = MappingBehavior::EndpointIndependent;
        s.profile.details.filtering = FilteringBehavior::AddressPortDependent;
        h.profile.predictability = Predictability::Unpredictable;
        h.profile.details.mapping = MappingBehavior::AddressPortDependent;
        h.profile.details.newSocket = {AllocationPattern::RandomFull, 0, 0, {}, 16, 0.94};
        for (int cap : {0, 128, 32}) {
            PunchLimits lim; lim.maxMappings = cap;
            auto ps = planPunch(s, h, lim), ph = planPunch(h, s, lim);
            CHECK_EQ(ps.strategy, PunchStrategy::BirthdaySpray);
            CHECK_EQ(ph.strategy, PunchStrategy::BirthdayListen);
            CHECK(ph.localSockets <= (cap ? std::min(cap, lim.maxSockets) : lim.maxSockets));
            CHECK(std::abs(ps.estimatedSuccess - ph.estimatedSuccess) < 1e-9);   // same number on both sides
            if (cap == 32) CHECK(ph.estimatedSuccess < planPunch(h, s, PunchLimits{}).estimatedSuccess);
        }
        // Both sequential: each side's targets are new mappings of its own.
        PeerInfo a = h, b = h;
        b.observed = {0xCB007107, 5000};
        a.profile.predictability = b.profile.predictability = Predictability::Predictable;
        AllocationInfo seq{AllocationPattern::Sequential, 1, 0.5, {}, 16, 1.0};
        a.profile.details.sameSocket = a.profile.details.newSocket = seq;
        b.profile.details.sameSocket = b.profile.details.newSocket = seq;
        a.profile.details.allocationRate = b.profile.details.allocationRate = 2.0;
        PunchLimits lim; lim.maxMappings = 4;
        auto pa = planPunch(a, b, lim), pb = planPunch(b, a, lim);
        CHECK_EQ(pa.strategy, PunchStrategy::Predict);
        CHECK(pa.targets.size() <= 4 && pb.targets.size() <= 4);
        auto pu = planPunch(a, b, PunchLimits{});
        std::printf("  both sequential: %zu targets uncapped (est %.2f), %zu with cap 4 (est %.2f)\n",
                    pu.targets.size(), pu.estimatedSuccess, pa.targets.size(), pa.estimatedSuccess);
    }
}

static void testDiscovery() {
    std::puts("discovery (simulated NAT)");
    {
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::EI; m.alloc = Alloc::Preserve;
        auto r = runDiscovery(m); show("full cone, preserving", r);
        CHECK_EQ(r.state, DiscoveryState::Final);
        CHECK(r.sawProvisional);
        CHECK_EQ(r.final.predictability, Predictability::Stable);
        CHECK_EQ(r.final.details.mapping, MappingBehavior::EndpointIndependent);
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::EndpointIndependent);
        CHECK_EQ(r.final.details.newSocket.pattern, AllocationPattern::PortPreserving);
        CHECK_EQ(r.final.publicEndpoint, (Endpoint{m.publicIp, 4662}));
        CHECK(r.final.details.parityPreserved);
        CHECK_EQ(r.leaked, 0);
    }
    {
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
        auto r = runDiscovery(m); show("port-restricted cone", r);
        CHECK_EQ(r.final.predictability, Predictability::Stable);
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::AddressPortDependent);
    }
    {
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::AD; m.alloc = Alloc::Sequential;
        auto r = runDiscovery(m, false); show("restricted cone", r);
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::AddressDependent);
        CHECK(!r.sawProvisional);   // no lifetime -> straight to Final
    }
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential; m.delta = 1;
        auto r = runDiscovery(m); show("symmetric, sequential +1", r);
        CHECK_EQ(r.final.predictability, Predictability::Predictable);
        CHECK_EQ(r.final.details.mapping, MappingBehavior::AddressPortDependent);
        CHECK_EQ(r.final.details.sameSocket.pattern, AllocationPattern::Sequential);
        CHECK_EQ(r.final.details.sameSocket.delta, 1);
        CHECK(!r.final.details.sameSocketFromNewSocket);
        CHECK_EQ(r.leaked, 0);
    }
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential; m.delta = 2;
        auto r = runDiscovery(m, false); show("symmetric, sequential +2", r);
        CHECK_EQ(r.final.details.sameSocket.delta, 2);
        // Nobody else allocates: add-one estimate over the 2 s drift gap
        CHECK(r.final.details.allocationRate && *r.final.details.allocationRate < 1.0);
    }
    // Allocation rate (point 6): busy CGNAT, 50 allocations/s by others
    {
        double sum = 0; int n = 0, okSeq = 0;
        for (uint32_t s = 1; s <= 20; ++s) {
            NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential;
            m.othersPerSec = 50;
            auto r = runDiscovery(m, false, s);
            okSeq += r.final.predictability == Predictability::Predictable;
            if (r.final.details.allocationRate) { sum += *r.final.details.allocationRate; ++n; }
        }
        std::printf("  busy sequential (50/s), 20 seeds: Predictable %d/20, mean measured rate %.1f/s over %d\n",
                    okSeq, n ? sum / n : -1.0, n);
        CHECK(okSeq >= 18);
        CHECK(n >= 18);
        CHECK(n && sum / n > 35 && sum / n < 65);
    }
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Noisy;
        auto r = runDiscovery(m, false); show("symmetric, noisy", r);
        CHECK_EQ(r.final.predictability, Predictability::Predictable);
        CHECK_EQ(r.final.details.sameSocket.pattern, AllocationPattern::SequentialNoisy);
    }
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomBlock;
        auto r = runDiscovery(m, false); show("CGNAT, random in 2048 block", r);
        CHECK_EQ(r.final.predictability, Predictability::Bounded);
        const auto& b = r.final.details.sameSocket.block;
        CHECK(b.base <= m.blockBase + 64 && uint32_t(b.base) + b.size >= uint32_t(m.blockBase) + m.blockSize - 128);
        CHECK_EQ(r.final.details.newSocket.pattern, AllocationPattern::RandomInBlock);
    }
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
        auto r = runDiscovery(m, false); show("symmetric, random full", r);
        CHECK_EQ(r.final.predictability, Predictability::Unpredictable);
    }
    // Hairpinning
    {
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::APD;
        m.hairpin = Hairpin::External;
        auto r = runDiscovery(m, false);
        CHECK_EQ(r.final.details.hairpin, HairpinBehavior::External);
        CHECK_EQ(r.leaked, 0);
        m.hairpin = Hairpin::Internal;
        CHECK_EQ(runDiscovery(m, false).final.details.hairpin, HairpinBehavior::Internal);
        m.hairpin = Hairpin::None;
        CHECK_EQ(runDiscovery(m, false).final.details.hairpin, HairpinBehavior::None);
        // Dependent mapping + port-dependent filter: a negative is not conclusive
        NatModel s; s.mapping = Map::APD; s.filtering = Filt::APD; s.alloc = Alloc::Sequential;
        s.hairpin = Hairpin::None;
        CHECK_EQ(runDiscovery(s, false).final.details.hairpin, HairpinBehavior::Unknown);
        s.filtering = Filt::EI; s.hairpin = Hairpin::External;
        CHECK_EQ(runDiscovery(s, false).final.details.hairpin, HairpinBehavior::External);
        NatModel open; open.present = false;
        CHECK_EQ(runDiscovery(open, false).final.details.hairpin, HairpinBehavior::Unknown);
    }
    // Minimum reflector ports with no loss: 3 used by Mapping, which are also
    // the first same-socket samples, + 5 fresh destinations = 8 in total.
    {
        auto ports = [](int a, int b, std::vector<int> steps = {8}) {
            return [a, b, steps](DiscoveryConfig& c) {   // reflector-only deployment, no STUN
                c.reflectors[0].ports = seq(3478, a, 1);
                c.reflectors[1].ports = seq(3478, b, 1);
                c.stunServers.clear();
                c.advanced.allocSameSocketSteps = steps;
            };
        };
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
        auto full = runDiscovery(m, true, 1, {}, ports(4, 4));
        show("symmetric random, 4+4 reflector ports", full);
        CHECK_EQ(full.final.details.sameSocket.samples, 8);
        CHECK_EQ(full.final.predictability, Predictability::Unpredictable);
        CHECK(full.final.confidence >= 0.8);   // from the new-socket sample
        CHECK_EQ(full.final.details.filtering, FilteringBehavior::AddressPortDependent);
        CHECK(full.final.lifetimeMeasured);
        auto shortOne = runDiscovery(m, false, 1, {}, ports(4, 3));
        CHECK_EQ(shortOne.final.details.sameSocket.samples, 7);
        auto twoEach = runDiscovery(m, false, 1, {}, ports(2, 2));   // 3 mapping samples + 1 fresh
        CHECK_EQ(twoEach.final.details.sameSocket.samples, 4);
        CHECK(!twoEach.final.details.sameSocketFromNewSocket);
        auto none = runDiscovery(m, false, 1, {}, ports(2, 2, {}));
        CHECK(none.final.details.sameSocketFromNewSocket);   // fallback: same-socket pattern not measured

        // No loss against the former 27-port setup (8 + 16 same-socket
        // samples), on every allocator model and 10 seeds each.
        struct Mo { Alloc a; int delta; double busy; };
        const Mo mo[] = {{Alloc::Sequential, 1, 0}, {Alloc::Sequential, 2, 0}, {Alloc::Sequential, 1, 50},
                         {Alloc::Noisy, 1, 0}, {Alloc::RandomBlock, 1, 0}, {Alloc::RandomFull, 1, 0},
                         {Alloc::Preserve, 1, 0}};
        int same = 0, total = 0;
        for (auto& x : mo)
            for (uint32_t seed = 1; seed <= 10; ++seed) {
                NatModel mm; mm.mapping = Map::APD; mm.filtering = Filt::APD; mm.alloc = x.a; mm.delta = x.delta;
                mm.othersPerSec = x.busy;
                auto big = runDiscovery(mm, false, seed, {}, [](DiscoveryConfig& c) {
                    for (auto& r : c.reflectors) {
                        r.ports.clear();
                        for (int i = 0; i < 14; ++i) r.ports.push_back(uint16_t(3478 + i));
                    }
                    c.reflectors[1].ports.pop_back();
                    c.stunServers.clear();
                    c.advanced.allocSameSocketSteps = {8, 16};
                });
                auto small = runDiscovery(mm, false, seed, {}, ports(4, 4));
                ++total;
                same += big.final.predictability == small.final.predictability &&
                        big.final.details.sameSocket.pattern == small.final.details.sameSocket.pattern &&
                        big.final.details.sameSocket.delta == small.final.details.sameSocket.delta;
            }
        std::printf("  8 ports vs 27: %d/%d identical classifications\n", same, total);
        CHECK_EQ(same, total);
        // Why the same-socket sample is needed at all: new sockets keep their
        // port, the same socket towards new destinations gets random ports.
        NatModel pm; pm.mapping = Map::APD; pm.filtering = Filt::APD; pm.alloc = Alloc::Preserve;
        CHECK_EQ(runDiscovery(pm, false, 1, {}, ports(4, 4)).final.predictability, Predictability::Unpredictable);
        CHECK_EQ(runDiscovery(pm, false, 1, {}, ports(4, 4, {})).final.predictability, Predictability::Predictable);
    }
    {
        NatModel m; m.mapping = Map::AD; m.filtering = Filt::AD; m.alloc = Alloc::Sequential;
        auto r = runDiscovery(m, false); show("address-dependent, seq", r);
        CHECK_EQ(r.final.details.mapping, MappingBehavior::AddressDependent);
        CHECK(r.final.details.sameSocketFromNewSocket);
        CHECK_EQ(r.final.predictability, Predictability::Predictable);
    }
    {
        NatModel m; m.blocked = true;
        auto r = runDiscovery(m); show("UDP blocked", r);
        CHECK_EQ(r.final.predictability, Predictability::UdpBlocked);
        CHECK_EQ(r.leaked, 0);
    }
    {
        NatModel m; m.present = false;
        auto r = runDiscovery(m, false); show("no NAT", r);
        CHECK_EQ(r.final.predictability, Predictability::Stable);
        CHECK(!r.final.details.behindNat);
        CHECK(!mappingLifetime(r.final));   // no mapping to keep
    }
    // Lifetime: Nokia-like 15 s first-packet timer, 65 s once bidirectional
    {
        NatModel m; m.singleTimeout = Duration(17000); m.bidirTimeout = Duration(65000);
        auto r = runDiscovery(m); show("lifetime 17s / 65s", r);
        CHECK(r.final.lifetimeMeasured);
        CHECK(r.final.details.singlePacketLifetime == Duration(15000));
        CHECK(r.final.details.bidirectionalLifetime == Duration(60000));
        CHECK_EQ(r.final.punchInterval, Duration(4000));     // 40% of 15 s = 6 s, capped at 4 s
        CHECK_EQ(r.final.keepaliveInterval, Duration(30000)); // 50% of 60 s
        CHECK(mappingLifetime(r.final) == Duration(60000));   // measured, after inbound
        CHECK(r.provisional.keepaliveInterval == Duration(15000));   // RFC 8085 §3.5 until measured
        CHECK(r.provisionalAtSec < 15);
        CHECK(r.finalAtSec < 190);
        CHECK_EQ(r.leaked, 0);
    }
    {
        NatModel m; m.singleTimeout = Duration(7000); m.bidirTimeout = Duration(12000);
        auto r = runDiscovery(m); show("lifetime 7s / 12s", r);
        CHECK(r.final.details.singlePacketLifetime == Duration(5000));
        CHECK_EQ(r.final.punchInterval, Duration(2000));
        CHECK_EQ(r.final.keepaliveInterval, Duration(5000));
        CHECK(mappingLifetime(r.final) == Duration(10000));   // measured, below RFC 4787 REQ-5
    }
    {
        NatModel m; m.singleTimeout = Duration(3000); m.bidirTimeout = Duration(4000);
        auto r = runDiscovery(m); show("lifetime < 5s", r);
        CHECK(r.final.lifetimeMeasured);            // replies acknowledged, none refused: real expiry
        CHECK_EQ(r.final.punchInterval, Duration(1000));
        CHECK_EQ(r.final.keepaliveInterval, Duration(1000));
        CHECK(!mappingLifetime(r.final));   // below the smallest value: nothing to rely on
    }
    // Not measured: the RFC 4787 REQ-5 minimum, only for a mapping that
    // conforms to REQ-1 (endpoint independent).
    {
        NatModel m; m.singleTimeout = Duration(17000); m.bidirTimeout = Duration(65000);
        auto r = runDiscovery(m, false); show("EIM, lifetime not measured", r);
        CHECK(!r.final.lifetimeMeasured);
        CHECK(mappingLifetime(r.final) == Duration(120000));
        NatProfile p = r.final;
        p.details.mapping = MappingBehavior::AddressPortDependent;
        CHECK(!mappingLifetime(p));
        p.details.mapping = MappingBehavior::AddressDependent;
        CHECK(!mappingLifetime(p));
        p.details.mapping = MappingBehavior::Unknown;
        CHECK(!mappingLifetime(p));
        p = r.final;
        p.predictability = Predictability::UdpBlocked;
        CHECK(!mappingLifetime(p));
        p = r.final;   // only the outbound-only variant known
        p.lifetimeMeasured = true;
        p.details.singlePacketLifetime = Duration(30000);
        CHECK(mappingLifetime(p) == Duration(30000));
    }
    // Reflector quota exhausted (many subscribers behind the same CGNAT IP):
    // refused probes are unknown, not expired; timers stay at defaults.
    {
        NatModel m; m.singleTimeout = Duration(17000); m.bidirTimeout = Duration(65000);
        auto r = runDiscovery(m, true, 1, [](ReflectorConfig& rc) { rc.maxPendingPerIp = 0; });
        show("quota exhausted", r);
        CHECK(!r.final.lifetimeMeasured);
        CHECK_EQ(r.final.punchInterval, Duration(4000));
        CHECK_EQ(r.final.keepaliveInterval, Duration(15000));
        CHECK(r.finalAtSec < 10);   // Refused answers end the measurement early
    }
    // Partial quota: the values that got through still give a bound
    {
        NatModel m; m.singleTimeout = Duration(17000); m.bidirTimeout = Duration(65000);
        auto r = runDiscovery(m, true, 1, [](ReflectorConfig& rc) { rc.maxPendingPerIp = 12; });
        show("quota 12 of 20", r);
        CHECK(r.final.lifetimeMeasured);
        CHECK(r.final.details.singlePacketLifetime == Duration(15000));
        CHECK(!r.final.details.lifetimeAtLeast);
    }
    {
        NatModel m; m.singleTimeout = Duration(600000); m.bidirTimeout = Duration(600000);
        auto r = runDiscovery(m); show("lifetime > 180s", r);
        CHECK(r.final.details.lifetimeAtLeast);
        CHECK_EQ(r.final.keepaliveInterval, Duration(90000));
    }
    // Robustness across random seeds for the hard cases
    int okBlock = 0, okNoisy = 0;
    for (uint32_t s = 1; s <= 50; ++s) {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomBlock;
        okBlock += runDiscovery(m, false, s).final.predictability == Predictability::Bounded;
        m.alloc = Alloc::Noisy;
        okNoisy += runDiscovery(m, false, s).final.predictability == Predictability::Predictable;
    }
    std::printf("  50 seeds: Bounded %d/50, Predictable(noisy) %d/50\n", okBlock, okNoisy);
    CHECK(okBlock >= 48);
    CHECK(okNoisy >= 48);
}

// ---------------------------------------------------------------- STUN
static void testStun() {
    std::puts("stun");
    // Codec: RFC 8489 Binding request / success response.
    TxId tx{};
    for (int i = 0; i < 12; ++i) tx[i] = uint8_t(0xA0 + i);
    auto q = stun::encodeBindingRequest(tx);
    // SOFTWARE attribute (RFC 8489 §6.1): "natd <version>", padded to 4.
    const std::string sw = std::string("natd ") + versionString();
    CHECK_EQ(q.size(), size_t(24) + ((sw.size() + 3) & ~size_t(3)));
    CHECK(q[20] == 0x80 && q[21] == 0x22 && q[23] == sw.size());
    CHECK(std::string(q.begin() + 24, q.begin() + 24 + long(sw.size())) == sw);
    CHECK(stun::isStunPacket(q.data(), q.size()));
    CHECK(!proto::isNatdPacket(q.data(), q.size()));
    std::vector<uint8_t> qv(q.begin(), q.end());
    StunServer sv{{kStunBase + 1, 3478}};
    auto a = sv.answer({0xCB007105, 40001}, qv);
    CHECK(a.has_value());
    auto r = stun::decodeBindingResponse(a->data(), a->size());
    CHECK(r && r->txId == tx && r->mapped == (Endpoint{0xCB007105, 40001}));
    sv.rfc3489 = true;
    a = sv.answer({0xCB007105, 40002}, qv);
    r = stun::decodeBindingResponse(a->data(), a->size());
    CHECK(r && r->mapped == (Endpoint{0xCB007105, 40002}));   // MAPPED-ADDRESS fallback
    // Malformed: truncated, wrong cookie, attribute overrunning the message,
    // error response, natd packet.
    CHECK(!stun::decodeBindingResponse(a->data(), a->size() - 4));
    auto bad = *a; bad[5] ^= 1;
    CHECK(!stun::decodeBindingResponse(bad.data(), bad.size()));
    bad = *a; bad[23] = 40;
    CHECK(!stun::decodeBindingResponse(bad.data(), bad.size()));
    bad = *a; bad[0] = 0x01; bad[1] = 0x11;
    CHECK(!stun::decodeBindingResponse(bad.data(), bad.size()));
    auto np = proto::encode(proto::ProbeResp{});
    CHECK(!stun::isStunPacket(np.data(), np.size()));
    // List parsing: comments, default port, stun: URI, IPv6 and junk skipped, duplicates removed.
    auto list = stun::parseServerList("# list\n stun.example.org:3478 \nstun:a.example\n1.2.3.4:19302\n"
                                      "[2001:db8::1]:3478\n2001:db8::1\nbad host\nx.example:0\nx.example:99999\n"
                                      "stun.example.org:3478\r\n");
    CHECK_EQ(list.size(), size_t(3));
    if (list.size() == 3) {
        CHECK(list[0].host == "stun.example.org" && list[0].port == 3478);
        CHECK(list[1].host == "a.example" && list[1].port == 3478);
        CHECK(list[2].host == "1.2.3.4" && list[2].port == 19302);
    }
    CHECK_EQ(stun::parseServerList(stun::formatServerList(list)), list);
    // Second port: " alt=PORT"; junk after the host invalidates the line.
    auto alt = stun::parseServerList("a.example:3478 alt=3479\nb.example alt=3478\nc.example:3478 alt=x\n"
                                     "d.example:3478 port=3479\ne.example:19302\talt=19303\n");
    CHECK_EQ(alt.size(), size_t(3));
    if (alt.size() == 3) {
        CHECK(alt[0].host == "a.example" && alt[0].altPort == 3479);
        CHECK(alt[1].host == "b.example" && alt[1].altPort == 0);   // same as the main port
        CHECK(alt[2].host == "e.example" && alt[2].port == 19302 && alt[2].altPort == 19303);
    }
    CHECK_EQ(stun::parseServerList(stun::formatServerList(alt)), alt);
    size_t builtinPairs = 0;
    for (auto& e : stun::builtinServers()) builtinPairs += e.altPort != 0;
    CHECK(builtinPairs >= 4);
    // OTHER-ADDRESS read as a hint.
    {
        std::vector<uint8_t> m = {0x01, 0x01, 0x00, 24, 0x21, 0x12, 0xA4, 0x42};
        m.insert(m.end(), tx.begin(), tx.end());
        uint8_t xa[12] = {0x00, 0x20, 0, 8, 0, 1, uint8_t((40001 ^ 0x2112) >> 8), uint8_t((40001 ^ 0x2112) & 0xFF),
                          0xCB ^ 0x21, 0x00 ^ 0x12, 0x71 ^ 0xA4, 0x05 ^ 0x42};
        uint8_t oa[12] = {0x80, 0x2C, 0, 8, 0, 1, 0x0D, 0x97, 192, 0, 10, 10};
        m.insert(m.end(), xa, xa + 12);
        m.insert(m.end(), oa, oa + 12);
        auto rr = stun::decodeBindingResponse(m.data(), m.size());
        CHECK(rr && rr->mapped == (Endpoint{0xCB007105, 40001}) && rr->other && *rr->other == (Endpoint{kStunBase + 10, 3479}));
    }
    CHECK(stun::builtinServers().size() >= 10);

    // RFC 8489 response processing (§6.3.3, §6.3.4, §9).
    {
        auto msg = [&](uint16_t type, std::vector<std::vector<uint8_t>> attrs) {
            std::vector<uint8_t> m = {uint8_t(type >> 8), uint8_t(type), 0, 0, 0x21, 0x12, 0xA4, 0x42};
            m.insert(m.end(), tx.begin(), tx.end());
            for (auto& a : attrs) m.insert(m.end(), a.begin(), a.end());
            m[2] = uint8_t((m.size() - 20) >> 8); m[3] = uint8_t(m.size() - 20);
            return m;
        };
        const std::vector<uint8_t> xma = {0x00, 0x20, 0, 8, 0, 1, uint8_t((40001 ^ 0x2112) >> 8),
                                          uint8_t((40001 ^ 0x2112) & 0xFF), 0xCB ^ 0x21, 0x00 ^ 0x12, 0x71 ^ 0xA4, 0x05 ^ 0x42};
        const std::vector<uint8_t> xmb = {0x00, 0x20, 0, 8, 0, 1, uint8_t((50001 ^ 0x2112) >> 8),
                                          uint8_t((50001 ^ 0x2112) & 0xFF), 0xCB ^ 0x21, 0x00 ^ 0x12, 0x71 ^ 0xA4, 0x05 ^ 0x42};
        const std::vector<uint8_t> unkReq = {0x7F, 0x00, 0, 4, 1, 2, 3, 4};
        const std::vector<uint8_t> unkOpt = {0xC0, 0x01, 0, 4, 1, 2, 3, 4};
        const std::vector<uint8_t> mi(24, 0), soft = {0x80, 0x22, 0, 4, 't', 'e', 's', 't'};
        auto miAttr = mi; miAttr[0] = 0x00; miAttr[1] = 0x08; miAttr[2] = 0; miAttr[3] = 20;
        auto ok = msg(0x0101, {xma, unkOpt, soft});
        auto r1 = stun::decodeBinding(ok.data(), ok.size());
        CHECK(r1 && r1->success && r1->mapped == (Endpoint{0xCB007105, 40001}));   // optional unknowns ignored
        auto req = msg(0x0101, {xma, unkReq});
        auto r2 = stun::decodeBinding(req.data(), req.size());
        CHECK(r2 && !r2->success && r2->txId == tx);                             // unknown required: failed
        CHECK(!stun::decodeBindingResponse(req.data(), req.size()));
        auto err = msg(0x0111, {{0x00, 0x09, 0, 4, 0, 0, 4, 0}});
        auto r3 = stun::decodeBinding(err.data(), err.size());
        CHECK(r3 && !r3->success && r3->txId == tx);                             // error response: failed
        auto errNoCode = msg(0x0111, {});
        auto r4 = stun::decodeBinding(errNoCode.data(), errNoCode.size());
        CHECK(r4 && !r4->success);
        // After MESSAGE-INTEGRITY: an address or an unknown required attribute does not count.
        auto afterMi = msg(0x0101, {xma, miAttr, xmb, unkReq});
        auto r5 = stun::decodeBinding(afterMi.data(), afterMi.size());
        CHECK(r5 && r5->success && r5->mapped == (Endpoint{0xCB007105, 40001}));
        auto onlyAfterMi = msg(0x0101, {miAttr, xmb});
        auto r6 = stun::decodeBinding(onlyAfterMi.data(), onlyAfterMi.size());
        CHECK(r6 && !r6->success);
        // An IPv6 address only: ignored, so no usable mapping.
        auto v6 = msg(0x0101, {{0x00, 0x20, 0, 20, 0, 2, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}});
        auto r7 = stun::decodeBinding(v6.data(), v6.size());
        CHECK(r7 && !r7->success);
    }

    // Retransmission (RFC 8489 §6.2.1): RTO 500 ms doubling, 7 requests,
    // failure 16 RTO after the last. QuickCheck towards two dead STUN
    // servers: the second one is asked once the first is stale (4 requests),
    // in parallel; the result comes when both transactions failed.
    {
        struct DeadIo : IDatagramIo {
            TimePoint now{};
            std::map<uint32_t, std::vector<double>> sends;   // server IP -> request times (s)
            std::map<uint32_t, std::set<TxId>> txs;
            std::optional<SocketId> openSocket(uint16_t) override { return SocketId(9); }
            void closeSocket(SocketId) override {}
            Endpoint localEndpoint(SocketId) const override { return {0x0A000002, 4662}; }
            bool send(SocketId, const Endpoint& to, const uint8_t* d, size_t l) override {
                if (stun::isStunPacket(d, l)) {
                    TxId t; std::copy(d + 8, d + 20, t.begin());
                    if (txs[to.ip].insert(t).second || true) sends[to.ip].push_back(std::chrono::duration<double>(now.time_since_epoch()).count());
                }
                return true;
            }
        } io;
        DiscoveryConfig dc;
        dc.primarySocket = 9;
        dc.stunServers = {{{0xC6336401, 3478}, 0}, {{0xC6336402, 3478}, 0}};
        NatProfile ex; ex.predictability = Predictability::Stable; ex.publicEndpoint = {0xCB007105, 4662};
        QuickCheck q(dc, ex, io);
        q.start(io.now);
        double doneAt = -1;
        for (int i = 0; i < 1000 && q.result() == QuickCheckResult::Pending; ++i) {
            TimePoint w = q.poll(io.now);
            if (q.result() != QuickCheckResult::Pending) break;
            if (w == TimePoint::max()) break;
            io.now = std::max(io.now, w);
        }
        doneAt = std::chrono::duration<double>(io.now.time_since_epoch()).count();
        CHECK_EQ(q.result(), QuickCheckResult::Unreachable);
        auto& a = io.sends[0xC6336401];
        // Two transactions per probe (liar check): each time both requests go.
        const double want[] = {0, 0.5, 1.5, 3.5, 7.5, 15.5, 31.5};
        CHECK_EQ(a.size(), size_t(14));
        bool sched = a.size() == 14;
        for (size_t k = 0; sched && k < 7; ++k) sched = std::abs(a[2 * k] - want[k]) < 0.01 && std::abs(a[2 * k + 1] - want[k]) < 0.01;
        CHECK(sched);
        auto& b = io.sends[0xC6336402];
        CHECK(b.size() == 14 && std::abs(b.front() - 3.5) < 0.01);   // stale after 4 requests
        CHECK(std::abs(doneAt - (3.5 + 39.5)) < 0.01);
        std::printf("  dead STUN servers: requests at 0 .. %.1f s, second server from %.1f s, unreachable at %.1f s\n",
                    a.back(), b.empty() ? -1.0 : b.front(), doneAt);
    }

    // At most 10 transactions outstanding towards one STUN server (§6.2):
    // STUN-only discovery behind a symmetric NAT (16 new-socket samples on
    // one server).
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential;
        Net net(m, 1);
        auto primary = *net.openSocket(4662);
        auto cfg = discoveryConfig(net, primary);
        cfg.reflectors.clear();
        cfg.measureLifetime = false;
        cfg.advanced.probeSpacing = Duration(0);   // no pacing: only the limit holds the burst
        NatDiscovery disc(cfg, net);
        std::map<uint32_t, std::set<TxId>> open;
        size_t peak = 0;
        net.onStunRequest = [&](const Endpoint& to, const std::vector<uint8_t>& d) {
            if (!stun::isStunPacket(d.data(), d.size())) return;
            TxId t; std::copy(d.begin() + 8, d.begin() + 20, t.begin());
            open[to.ip].insert(t);
            peak = std::max(peak, open[to.ip].size());
        };
        net.onClientRx = [&](const Net::Rx& rx) {
            if (stun::isStunPacket(rx.data.data(), rx.data.size())) {
                TxId t; std::copy(rx.data.begin() + 8, rx.data.begin() + 20, t.begin());
                open[rx.from.ip].erase(t);
            }
            disc.onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), net.now);
        };
        disc.start(net.now);
        net.run([&](TimePoint now) { return disc.poll(now); }, net.now + std::chrono::minutes(5));
        CHECK_EQ(disc.state(), DiscoveryState::Final);
        CHECK(disc.result().details.newSocket.samples >= 16);
        CHECK(peak <= 10 && peak >= 8);
        std::printf("  STUN only: new-socket samples %d, peak outstanding per server %zu\n",
                    disc.result().details.newSocket.samples, peak);
    }

    // Error responses and unknown required attributes fail the transaction
    // at once: the discovery does not wait for those servers.
    {
        NatModel m; m.mapping = Map::EI;
        auto t0 = runDiscovery(m, false, 1);
        auto te = runDiscovery(m, false, 1, {}, {}, [](Net& n) {
            for (size_t i = 0; i < 4; ++i) (i % 2 ? n.stun[i].extraRequired : n.stun[i].errorReply) = true;
        });
        CHECK_EQ(te.final.details.mapping, MappingBehavior::EndpointIndependent);
        CHECK(te.finalAtSec < t0.finalAtSec + 2);
        std::printf("  4 servers failing (error / unknown attribute): final at %.1f s (all answering: %.1f s)\n",
                    te.finalAtSec, t0.finalAtSec);
    }

    // Option 1 deployment (default here: R0 one public port, R1 closed to
    // clients, STUN mirrors with two-port servers) and option C (R0 two
    // ports) against the reflector-only 8-port deployment: same
    // classification on every allocator model, 10 seeds each.
    auto legacy = [](DiscoveryConfig& c) {
        c.reflectors[0].ports = seq(3478, 4, 1);
        c.reflectors[1].ports = seq(3478, 4, 1);
        c.stunServers.clear();
    };
    struct Mo { Map m; Alloc a; int delta; double busy; };
    const Mo mo[] = {{Map::EI, Alloc::Preserve, 1, 0},     {Map::AD, Alloc::Sequential, 1, 0},
                     {Map::APD, Alloc::Sequential, 1, 0},  {Map::APD, Alloc::Sequential, 2, 0},
                     {Map::APD, Alloc::Sequential, 1, 50}, {Map::APD, Alloc::Noisy, 1, 0},
                     {Map::APD, Alloc::RandomBlock, 1, 0}, {Map::APD, Alloc::RandomFull, 1, 0},
                     {Map::APD, Alloc::Preserve, 1, 0}};
    // Allocator family: a sequential allocator may read as Sequential or
    // SequentialNoisy depending on how many ports other subscribers took
    // during the sample (10 samples here, 8 there).
    auto family = [](AllocationPattern p) {
        return p == AllocationPattern::SequentialNoisy ? AllocationPattern::Sequential : p;
    };
    auto optionC = [](DiscoveryConfig& c) { c.reflectors[0].ports = {3478, 3479}; };
    int same = 0, exact = 0, total = 0, sameC = 0, portTested = 0;
    uint64_t r1Req = 0, r1Fwd = 0, r0Drops = 0;
    for (auto& x : mo)
        for (uint32_t seed = 1; seed <= 10; ++seed) {
            NatModel m; m.mapping = x.m; m.filtering = Filt::APD; m.alloc = x.a; m.delta = x.delta;
            m.othersPerSec = x.busy;
            auto c = runDiscovery(m, false, seed);
            auto l = runDiscovery(m, false, seed, {}, legacy);
            auto oc = runDiscovery(m, false, seed, {}, optionC);
            ++total;
            const auto &cd = c.final.details, &ld = l.final.details;
            const bool eq = c.final.predictability == l.final.predictability && cd.mapping == ld.mapping &&
                            cd.filtering == ld.filtering &&
                            family(cd.sameSocket.pattern) == family(ld.sameSocket.pattern);
            same += eq;
            exact += eq && cd.sameSocket.pattern == ld.sameSocket.pattern && cd.sameSocket.delta == ld.sameSocket.delta;
            const auto& od = oc.final.details;
            sameC += oc.final.predictability == l.final.predictability && od.mapping == ld.mapping &&
                     od.filtering == ld.filtering && family(od.sameSocket.pattern) == family(ld.sameSocket.pattern);
            portTested += cd.mappingPortTested;
            r0Drops += c.r0FirewallDrops;
            if (!eq) { show("option 1", c); show("8 ports", l); }
            r1Req += c.r1Requests;
            r1Fwd += c.r1Forwards;
        }
    std::printf("  1 port + STUN vs 8 ports: %d/%d same class (%d also same pattern and step), port dependence "
                "measured %d/%d; 2 ports + STUN: %d/%d; R1 got %llu client requests, %llu forwards; R0 firewall "
                "dropped %llu\n",
                same, total, exact, portTested, total, sameC, total, (unsigned long long)r1Req,
                (unsigned long long)r1Fwd, (unsigned long long)r0Drops);
    CHECK_EQ(same, total);
    CHECK_EQ(sameC, total);
    CHECK_EQ(portTested, total);
    CHECK_EQ(r0Drops, 0u);  // clients never try R0's second port: it can stay closed
    CHECK_EQ(r1Req, 0u);    // clients never contact R1: its firewall may admit R0 only
    CHECK(r1Fwd > 0);       // R1 still serves the filtering test through the partner link
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
        auto r = runDiscovery(m, true);
        show("symmetric random, 1 port + STUN", r);
        CHECK_EQ(r.final.predictability, Predictability::Unpredictable);
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::AddressPortDependent);
        CHECK(r.final.details.sameSocket.samples >= 8);
        CHECK(r.final.lifetimeMeasured);
        CHECK_EQ(r.leaked, 0);
    }
    // Servers that do not answer: the spare destinations absorb them.
    for (int dead = 0; dead <= 6; ++dead) {
        int okPred = 0, minSamples = 99;
        for (uint32_t seed = 1; seed <= 10; ++seed)
            for (Alloc al : {Alloc::Preserve, Alloc::Sequential, Alloc::RandomFull}) {
                NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = al;
                auto r = runDiscovery(m, false, seed, {}, {}, [&](Net& n) {
                    for (int i = 0; i < dead; ++i) n.stun[size_t(i * 5 % 12)].alive = false;
                });
                Predictability want = al == Alloc::Sequential ? Predictability::Predictable : Predictability::Unpredictable;
                okPred += r.final.predictability == want;
                minSamples = std::min(minSamples, r.final.details.sameSocket.samples);
            }
        std::printf("  %d of 12 STUN servers dead: %d/30 right, min same-socket samples %d\n", dead, okPred, minSamples);
        if (dead <= 2) CHECK(minSamples >= 8);
        CHECK_EQ(okPred, 30);
    }
    // Lying servers (wrong mapped address): their answers are ignored.
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential;
        auto r = runDiscovery(m, false, 1, {}, {}, [](Net& n) { n.stun[0].lies = n.stun[3].lies = true; });
        CHECK_EQ(r.final.predictability, Predictability::Predictable);
        // The ignored answers leave holes in the sequence (the mapping was
        // made anyway): still sequential, possibly noisy.
        CHECK_EQ(family(r.final.details.sameSocket.pattern), AllocationPattern::Sequential);
        CHECK_EQ(r.final.details.mapping, MappingBehavior::AddressPortDependent);
        CHECK(!r.final.details.multiplePublicIps);
        NatModel e; e.mapping = Map::EI;
        auto re = runDiscovery(e, false, 1, {}, {}, [](Net& n) { n.stun[0].lies = true; });
        CHECK_EQ(re.final.details.mapping, MappingBehavior::EndpointIndependent);   // second STUN probe used
        NatModel a; a.mapping = Map::AD; a.alloc = Alloc::Sequential;
        auto ra = runDiscovery(a, false, 1, {}, {}, [](Net& n) { n.stun[0].rfc3489 = true; });
        CHECK_EQ(ra.final.details.mapping, MappingBehavior::AddressDependent);
    }
    // No two-port server answering, one R0 port: port dependence cannot be
    // measured; a dependent mapping is reported as address+port dependent
    // (conservative), the rest is unchanged.
    {
        auto pairsDead = [](Net& n) { for (auto& sv : n.stun) if (sv.altPort) sv.alive = false; };
        NatModel a; a.mapping = Map::AD; a.filtering = Filt::AD; a.alloc = Alloc::Sequential;
        auto ra = runDiscovery(a, false, 1, {}, {}, pairsDead);
        CHECK_EQ(ra.final.details.mapping, MappingBehavior::AddressPortDependent);
        CHECK(!ra.final.details.mappingPortTested);
        CHECK_EQ(ra.final.predictability, Predictability::Predictable);
        CHECK_EQ(ra.final.details.filtering, FilteringBehavior::AddressDependent);
        NatModel e; e.mapping = Map::EI;
        CHECK_EQ(runDiscovery(e, false, 1, {}, {}, pairsDead).final.details.mapping, MappingBehavior::EndpointIndependent);
        NatModel p; p.mapping = Map::APD; p.filtering = Filt::APD; p.alloc = Alloc::RandomBlock;
        auto rp = runDiscovery(p, false, 1, {}, {}, pairsDead);
        CHECK_EQ(rp.final.details.mapping, MappingBehavior::AddressPortDependent);
        CHECK_EQ(rp.final.predictability, Predictability::Bounded);
        // With a list without any two-port server, same outcome.
        auto rn = runDiscovery(a, false, 1, {}, [](DiscoveryConfig& c) { for (auto& sv : c.stunServers) sv.altPort = 0; });
        CHECK_EQ(rn.final.details.mapping, MappingBehavior::AddressPortDependent);
        CHECK_EQ(rn.final.predictability, Predictability::Predictable);
    }
    // No STUN server reachable and R1 closed: what needs a second IP becomes
    // unknown, nothing turns wrong.
    {
        auto allDead = [](Net& n) { for (auto& sv : n.stun) sv.alive = false; };
        NatModel e; e.mapping = Map::EI;
        auto re = runDiscovery(e, false, 1, {}, {}, allDead);
        CHECK_EQ(re.final.details.mapping, MappingBehavior::Unknown);
        CHECK_EQ(re.final.predictability, Predictability::Inconclusive);
        NatModel p; p.mapping = Map::APD; p.filtering = Filt::APD; p.alloc = Alloc::RandomFull;
        auto rp = runDiscovery(p, false, 1, {}, {}, allDead);
        CHECK_EQ(rp.final.details.mapping, MappingBehavior::Unknown);   // only R0:p0 answered
        CHECK(rp.final.predictability == Predictability::Unpredictable ||
              rp.final.predictability == Predictability::Inconclusive);
        // Unusable configurations: R1 closed and no STUN list; R1 sharing R0's IP.
        auto r = runDiscovery(e, false, 1, {}, [](DiscoveryConfig& c) { c.stunServers.clear(); });
        CHECK_EQ(r.final.predictability, Predictability::Inconclusive);
        CHECK_EQ(r.sent, 0u);
    }
    // A STUN answer from another address than the one probed is ignored.
    {
        EventLoop loop;
        NatModel pub; pub.present = false;
        Host h(loop, pub, 1);
        h.egress = [](const Endpoint&, const Endpoint&, std::vector<uint8_t>, const Endpoint*) {};
        auto prim = *h.openSocket(4662);
        DiscoveryConfig c;
        c.reflectors = {{kR0, {3478, 3479}}, {kR1, {}}};
        c.stunServers = {{kStunBase + 10, 3478}};
        c.primarySocket = prim;
        std::vector<std::vector<uint8_t>> out;
        h.egress = [&](const Endpoint&, const Endpoint& to, std::vector<uint8_t> d, const Endpoint*) {
            if (to.ip == kStunBase + 10) out.push_back(d);
        };
        NatDiscovery disc(c, h);
        disc.start(loop.now);
        disc.poll(loop.now);
        for (int i = 0; i < 5 && out.empty(); ++i) { loop.now += Duration(5); loop.runDue(); disc.poll(loop.now); }
        CHECK(!out.empty());
        if (!out.empty()) {
            StunServer s2{{kStunBase + 10, 3478}};
            auto ans = *s2.answer({pub.publicIp, 4662}, out[0]);
            CHECK(!disc.onDatagram(prim, {kStunBase + 11, 3478}, ans.data(), ans.size(), loop.now));   // other IP
            CHECK(!disc.onDatagram(prim, {kStunBase + 10, 3479}, ans.data(), ans.size(), loop.now));   // other port
            CHECK(disc.onDatagram(prim, {kStunBase + 10, 3478}, ans.data(), ans.size(), loop.now));
        }
    }
}

// ---------------------------------------------------------------- resilience
// Infrastructure faults must make results less precise, never wrong.
static void testResilience() {
    std::puts("resilience");
    // Reflector caps: other port, partner checked and alive.
    {
        CaptureIo io;
        ReflectorConfig rc;
        rc.portCount = 2;
        rc.partners = {{kR1, 3478}};
        Reflector r(rc, io);
        TimePoint t{std::chrono::hours(1)};
        r.poll(t);   // first partner check goes out
        CHECK_EQ(io.out.size(), size_t(1));
        CHECK(io.out.size() == 1 && io.out[0].to == (Endpoint{kR1, 3478}));
        CHECK_EQ(r.stats().partnerChecks, 1u);
        auto chk = proto::decodeProbeReq(io.out[0].d.data(), io.out[0].d.size());
        auto capsOf = [&](Endpoint client) {
            io.out.clear();
            auto b = proto::encode(proto::ProbeReq{});
            r.onDatagram(0, client, b.data(), b.size(), t);
            auto x = proto::decodeProbeResp(io.out.back().d.data(), io.out.back().d.size());
            return x ? x->caps : uint8_t(0);
        };
        uint8_t c = capsOf({0x0A000001, 5000});
        CHECK_EQ(c, uint8_t(proto::CapValid | proto::CapOtherPort | proto::CapPartnerChecked));   // not answered yet
        CHECK(chk.has_value());
        if (chk) {
            auto ans = proto::encode(proto::ProbeResp{chk->txId, {kR0, 3478}, proto::ReplyKind::Same, 0});
            r.onDatagram(0, {0x01020304, 3478}, ans.data(), ans.size(), t);   // not the partner: ignored
            CHECK(!r.partnerAlive(t));
            r.onDatagram(0, {kR1, 3478}, ans.data(), ans.size(), t);
            CHECK(r.partnerAlive(t));
            c = capsOf({0x0A000001, 5001});
            CHECK(c & proto::CapPartnerAlive);
            CHECK(!r.partnerAlive(t + Duration(17000)));   // timed out without new answers
        }
        // Older clients ignore the byte; older reflectors send 0 (nothing declared).
        auto z = proto::encode(proto::ProbeResp{});
        CHECK_EQ(z[27], uint8_t(0));
    }
    // R1 down: an EIF NAT reads as AddressDependent, flagged as untested
    // (stricter, not wrong); before, it was plain AddressDependent.
    {
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::EI;
        auto r = runDiscovery(m, false, 1, {}, {}, [](Net& n) { n.reflDown[1] = true; });
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::AddressDependent);
        CHECK(!r.final.details.filteringPartnerTested);
        auto ok = runDiscovery(m, false);
        CHECK_EQ(ok.final.details.filtering, FilteringBehavior::EndpointIndependent);
        CHECK(ok.final.details.filteringPartnerTested && ok.final.details.filteringPortTested);
        NatModel a; a.mapping = Map::EI; a.filtering = Filt::AD;
        auto ra = runDiscovery(a, false, 1, {}, {}, [](Net& n) { n.reflDown[1] = true; });
        CHECK_EQ(ra.final.details.filtering, FilteringBehavior::AddressDependent);   // other-port reply still proves it
        CHECK(ra.final.details.filteringPortTested);
    }
    // R0 without its second socket: an ADF NAT reads as AddressPortDependent,
    // flagged as port-untested.
    {
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::AD;
        auto r = runDiscovery(m, false, 1, [](ReflectorConfig& rc) { rc.portCount = 1; });
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::AddressPortDependent);
        CHECK(!r.final.details.filteringPortTested);
        NatModel e; e.mapping = Map::EI; e.filtering = Filt::EI;
        auto re = runDiscovery(e, false, 1, [](ReflectorConfig& rc) { rc.portCount = 1; });
        CHECK_EQ(re.final.details.filtering, FilteringBehavior::EndpointIndependent);   // partner reply proves it
    }
    // Reflector pairs: the first pair is down, the second takes over.
    {
        auto twoPairs = [](DiscoveryConfig& c) {
            auto real = c.reflectors;
            c.reflectors = {{kR0 + 100, {3478}}, {kR1 + 100, {}}, real[0], real[1]};
        };
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential;
        m.singleTimeout = Duration(17000); m.bidirTimeout = Duration(65000);
        auto r = runDiscovery(m, true, 1, {}, twoPairs);
        CHECK_EQ(r.final.predictability, Predictability::Predictable);
        CHECK_EQ(r.final.details.filtering, FilteringBehavior::AddressPortDependent);
        CHECK(r.final.details.reflectorReached);
        CHECK(r.final.details.singlePacketLifetime == Duration(15000));
        CHECK_EQ(r.leaked, 0);
    }
    // No reflector at all, STUN servers answering: partial profile, not UdpBlocked.
    {
        auto down = [](Net& n) { n.reflDown[0] = n.reflDown[1] = true; };
        struct C { Map m; Alloc a; Predictability want; };
        const C cs[] = {{Map::EI, Alloc::Preserve, Predictability::Stable},
                        {Map::APD, Alloc::Sequential, Predictability::Predictable},
                        {Map::APD, Alloc::RandomFull, Predictability::Unpredictable},
                        {Map::APD, Alloc::RandomBlock, Predictability::Bounded}};
        for (auto& x : cs) {
            NatModel m; m.mapping = x.m; m.filtering = Filt::APD; m.alloc = x.a;
            auto r = runDiscovery(m, true, 1, {}, {}, down);
            CHECK_EQ(r.final.predictability, x.want);
            CHECK(!r.final.details.reflectorReached);
            CHECK_EQ(r.final.details.filtering, FilteringBehavior::Unknown);
            CHECK(!r.final.lifetimeMeasured);
            CHECK_EQ(r.final.publicEndpoint.ip, m.publicIp);
            CHECK_EQ(r.leaked, 0);
        }
        NatModel b; b.blocked = true;
        CHECK_EQ(runDiscovery(b, false).final.predictability, Predictability::UdpBlocked);
        // No reflector configured at all (STUN-only deployment): same results,
        // without waiting for reflectors that are not there.
        auto none = [](DiscoveryConfig& c) { c.reflectors.clear(); };
        for (auto& x : cs) {
            NatModel m; m.mapping = x.m; m.filtering = Filt::APD; m.alloc = x.a;
            auto r = runDiscovery(m, true, 1, {}, none);
            CHECK_EQ(r.final.predictability, x.want);
            CHECK(!r.final.details.reflectorReached);
            CHECK_EQ(r.final.publicEndpoint.ip, m.publicIp);
            CHECK_EQ(r.leaked, 0);
        }
        {
            NatModel m; m.mapping = Map::AD; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
            auto r = runDiscovery(m, true, 1, {}, none);
            CHECK_EQ(r.final.details.mapping, MappingBehavior::AddressDependent);
        }
        // STUN only, and the first servers in the list never answer (an
        // application's IP filter dropping them, as eMule's did with 13 of 16):
        // the next ones are asked before UDP is declared blocked.
        {
            NatModel m; m.mapping = Map::EI; m.filtering = Filt::APD; m.alloc = Alloc::Preserve;
            auto lastThree = [](Net& n) { for (size_t i = 0; i + 3 < n.stun.size(); ++i) n.stun[i].alive = false; };
            auto r = runDiscovery(m, false, 1, {}, none, lastThree);
            CHECK_EQ(r.final.predictability, Predictability::Stable);
            CHECK_EQ(r.final.details.mapping, MappingBehavior::EndpointIndependent);
            CHECK_EQ(r.final.publicEndpoint.ip, m.publicIp);
            std::printf("  STUN only, 9 of 12 servers silent: %s, final at %.1f s\n", toString(r.final.predictability), r.finalAtSec);
            auto allSilent = [](Net& n) { for (auto& sv : n.stun) sv.alive = false; };
            auto b = runDiscovery(m, false, 1, {}, none, allSilent);
            CHECK_EQ(b.final.predictability, Predictability::UdpBlocked);
            uint64_t asked = 0;
            for (size_t i = 0; i < 12; ++i) asked += 1;   // every server is asked before giving up
            CHECK(b.stunRequests >= 2 * asked);
            std::printf("  STUN only, all silent: %s at %.1f s, %llu requests\n", toString(b.final.predictability), b.finalAtSec,
                        (unsigned long long)b.stunRequests);
        }
    }
    // Network change mid-run (new public IP): started over once, result for
    // the new network.
    {
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::Sequential;
        auto r = runDiscovery(m, false, 1, {}, {}, [](Net& n) {
            n.loop.schedule(n.loop.now + Duration(1500), [&n] { n.host.box.nat.publicIp = 0xCB007199; });
        });
        CHECK_EQ(r.final.details.restarts, 1);
        CHECK_EQ(r.final.publicEndpoint.ip, 0xCB007199u);
        CHECK_EQ(r.final.predictability, Predictability::Predictable);
        CHECK(!r.final.details.multiplePublicIps);
        CHECK_EQ(r.leaked, 0);
        auto still = runDiscovery(m, false);
        CHECK_EQ(still.final.details.restarts, 0);
    }
    // STUN servers answering the right IP and a wrong port, at random or
    // always the same: dropped by the double query, outvoted by equal
    // endpoints, or left out of a sequence. Never a wrong class.
    {
        int ok = 0, total = 0, falseSeq = 0, randTotal = 0;
        for (int fixed = 0; fixed < 2; ++fixed)
            for (int liars = 1; liars <= 3; ++liars)
                for (Alloc al : {Alloc::Sequential, Alloc::Noisy, Alloc::Preserve, Alloc::RandomFull, Alloc::RandomBlock})
                    for (uint32_t seed = 1; seed <= 6; ++seed) {
                        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = al;
                        auto r = runDiscovery(m, false, seed, {}, {}, [&](Net& n) {
                            for (int i = 0; i < liars; ++i) (fixed ? n.stun[size_t(4 + i * 2)].liesPortFixed
                                                                   : n.stun[size_t(4 + i * 2)].liesPort) = true;
                        });
                        const bool seqAlloc = al == Alloc::Sequential || al == Alloc::Noisy;
                        Predictability want = seqAlloc ? Predictability::Predictable
                                            : al == Alloc::RandomBlock ? Predictability::Bounded
                                                                       : Predictability::Unpredictable;
                        ++total;
                        ok += r.final.predictability == want || r.final.predictability == Predictability::Inconclusive;
                        if (!seqAlloc) { ++randTotal; falseSeq += r.final.predictability == Predictability::Predictable; }
                    }
        std::printf("  STUN port liars: %d/%d right or Inconclusive, random allocators read as sequential %d/%d\n",
                    ok, total, falseSeq, randTotal);
        CHECK_EQ(ok, total);
        CHECK_EQ(falseSeq, 0);
        NatModel e; e.mapping = Map::EI;
        auto re = runDiscovery(e, false, 1, {}, {}, [](Net& n) { n.stun[0].liesPortFixed = n.stun[1].liesPort = true; });
        CHECK_EQ(re.final.details.mapping, MappingBehavior::EndpointIndependent);
    }
}

static void testQuickCheck() {
    std::puts("quickcheck");
    NatModel m; m.mapping = Map::EI;
    Net net(m);
    auto primary = *net.openSocket(4662);
    auto cfg = discoveryConfig(net, primary);
    NatProfile expected;
    expected.predictability = Predictability::Stable;
    expected.publicEndpoint = {m.publicIp, 4662};
    for (int variant = 0; variant < 2; ++variant) {
        if (variant == 1) expected.publicEndpoint.port = 9999;
        QuickCheck qc(cfg, expected, net);
        net.onClientRx = [&](const Net::Rx& rx) { qc.onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), net.now); };
        qc.start(net.now);
        net.run([&](TimePoint now) { return qc.poll(now); }, net.now + std::chrono::seconds(10));
        CHECK_EQ(qc.result(), variant == 0 ? QuickCheckResult::Valid : QuickCheckResult::Changed);
        CHECK_EQ(qc.observed(), (Endpoint{m.publicIp, 4662}));
    }
    NatModel b; b.blocked = true;
    Net nb(b);
    auto pb = *nb.openSocket(4662);
    QuickCheck qc(discoveryConfig(nb, pb), expected, nb);
    qc.start(nb.now);
    // The STUN fallback gives up only when its transactions fail (RFC 8489
    // §6.2.1: 7 requests, 39.5 s), the second server asked in parallel.
    nb.run([&](TimePoint now) { return qc.poll(now); }, nb.now + std::chrono::seconds(30));
    CHECK_EQ(qc.result(), QuickCheckResult::Pending);
    nb.run([&](TimePoint now) { return qc.poll(now); }, nb.now + std::chrono::seconds(30));
    CHECK_EQ(qc.result(), QuickCheckResult::Unreachable);
    // R0 unreachable, R1 closed: falls back to a STUN server.
    {
        Net n2(m);
        auto p2 = *n2.openSocket(4662);
        auto c2 = discoveryConfig(n2, p2);
        c2.reflectors[0].ip = kR0 + 100;   // nobody there
        expected.publicEndpoint.port = 4662;
        QuickCheck q2(c2, expected, n2);
        n2.onClientRx = [&](const Net::Rx& rx) { q2.onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), n2.now); };
        q2.start(n2.now);
        n2.run([&](TimePoint now) { return q2.poll(now); }, n2.now + std::chrono::seconds(10));
        CHECK_EQ(q2.result(), QuickCheckResult::Valid);
        CHECK_EQ(q2.observed(), (Endpoint{m.publicIp, 4662}));
    }
    // No reflector at all (public STUN servers only), after the NAT lost its
    // mappings and moved the port: Changed, with the new endpoint.
    {
        NatModel r = m;
        r.alloc = Alloc::RandomFull;
        Net n3(r);
        auto p3 = *n3.openSocket(4662);
        auto c3 = discoveryConfig(n3, p3);
        c3.reflectors.clear();
        NatProfile e3 = expected;
        for (int round = 0; round < 2; ++round) {
            QuickCheck q3(c3, e3, n3);
            n3.onClientRx = [&](const Net::Rx& rx) { q3.onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), n3.now); };
            q3.start(n3.now);
            n3.run([&](TimePoint now) { return q3.poll(now); }, n3.now + std::chrono::seconds(10));
            CHECK(q3.observed().ip == r.publicIp);
            if (round == 0) {
                e3.publicEndpoint = q3.observed();
                n3.host.box.flush();
            } else {
                CHECK_EQ(q3.result(), QuickCheckResult::Changed);
                CHECK(q3.observed().port != e3.publicEndpoint.port);
            }
        }
    }
}

// ---------------------------------------------------------------- punch
static void testPeerInfo() {
    std::puts("peerinfo");
    NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomBlock;
    auto r = runDiscovery(m, true);
    PeerInfo pi{r.final, Endpoint{0xCB007105, 20555}};
    auto b = encodePeerInfo(pi);
    auto d = decodePeerInfo(b.data(), b.size());
    CHECK(d.has_value());
    if (d) {
        CHECK_EQ(d->observed, pi.observed);
        CHECK_EQ(d->profile.predictability, pi.profile.predictability);
        CHECK_EQ(d->profile.publicEndpoint, pi.profile.publicEndpoint);
        CHECK_EQ(d->profile.keepaliveInterval, pi.profile.keepaliveInterval);
        CHECK_EQ(d->profile.details.sameSocket.block.base, pi.profile.details.sameSocket.block.base);
        CHECK_EQ(d->profile.details.sameSocket.block.size, pi.profile.details.sameSocket.block.size);
        CHECK_EQ(d->profile.details.filtering, pi.profile.details.filtering);
        CHECK(d->profile.details.bidirectionalLifetime == pi.profile.details.bidirectionalLifetime);
        CHECK_EQ(encodePeerInfo(*d), b);   // stable re-encoding
    }
    CHECK(!decodePeerInfo(b.data(), b.size() - 1));
    auto bad = b; bad[5] = 99;   // predictability out of range
    CHECK(!decodePeerInfo(bad.data(), bad.size()));
    bad = b; bad[4] = 9;         // unknown version
    CHECK(!decodePeerInfo(bad.data(), bad.size()));

    // v3: hairpin and inside endpoints
    PeerInfo v3 = pi;
    v3.profile.details.hairpin = HairpinBehavior::External;
    v3.localEndpoints = {{0xC0A80105, 4662}, {0x64400203, 4662}};
    auto b3 = encodePeerInfo(v3);
    CHECK_EQ(b3.size(), b.size() - 2 - 6 * pi.localEndpoints.size() + 2 + 12);
    if (auto d = decodePeerInfo(b3.data(), b3.size())) {
        CHECK_EQ(d->profile.details.hairpin, HairpinBehavior::External);
        CHECK(d->localEndpoints == v3.localEndpoints);
    } else CHECK(false);
    auto tooMany = b3; tooMany[b3.size() - 13] = 5;   // count field
    CHECK(!decodePeerInfo(tooMany.data(), tooMany.size()));
    // A v2 record (no trailing fields) still decodes
    auto b2 = encodePeerInfo(pi);
    b2.resize(b2.size() - 2 - 6 * pi.localEndpoints.size());
    b2[4] = 2;
    if (auto d = decodePeerInfo(b2.data(), b2.size())) {
        CHECK_EQ(d->profile.details.hairpin, HairpinBehavior::Unknown);
        CHECK(d->localEndpoints.empty());
    } else CHECK(false);
}

constexpr uint32_t kSig = 0xC6336409;   // signalling server, sees the fresh mapping

struct PunchOutcome {
    PunchPlan plan[2];
    PunchState state[2];
    double seconds = 0;
    uint64_t packets[2] = {0, 0};
};

struct SameNat { uint32_t ipA, ipB; bool lan; };

static PunchOutcome runPunch(NatModel ma, NatModel mb, uint32_t seed = 1, const SameNat* same = nullptr) {
    NatProfile prof[2] = {runDiscovery(ma, false, seed).final, runDiscovery(mb, false, seed + 1).final};
    auto wp = same ? std::make_unique<Peers>(ma, seed, same->ipA, same->ipB, same->lan)
                   : std::make_unique<Peers>(ma, mb, seed);
    Peers& w = *wp;
    SocketId prim[2] = {*w[0].openSocket(4662), *w[1].openSocket(4672)};
    Endpoint seen[2];
    // Signalling: each peer contacts the server from its primary socket.
    for (int i = 0; i < 2; ++i) {
        auto old = w[i].egress;
        w[i].egress = [&, i, old](const Endpoint& src, const Endpoint& to, std::vector<uint8_t> d, const Endpoint* fa) {
            if (to.ip == kSig) { seen[i] = src; return; }
            old(src, to, std::move(d), fa);
        };
        uint8_t hello[4] = {1, 2, 3, 4};
        w[i].send(prim[i], Endpoint{kSig, 8000}, hello, 4);
    }
    w.run([](TimePoint) { return TimePoint::max(); }, w.loop.now + Duration(50));
    PeerInfo info[2] = {{prof[0], seen[0], {}}, {prof[1], seen[1], {}}};
    for (int i = 0; i < 2; ++i) info[i].localEndpoints = {w[i].localEndpoint(prim[i])};
    PunchOutcome out;
    TxId token{};
    token[0] = 0x5A;
    std::unique_ptr<PunchSession> s[2];
    TimePoint t0 = w.loop.now + Duration(100);
    for (int i = 0; i < 2; ++i) {
        out.plan[i] = planPunch(info[i], info[1 - i]);
        PunchSessionConfig c;
        c.plan = out.plan[i];
        c.token = token;
        c.startAt = t0;
        c.remoteIp = seen[1 - i].ip;   // from the signalling channel
        c.primarySocket = prim[i];
        s[i] = std::make_unique<PunchSession>(c, w[i]);
        w[i].onRx = [&, i](const Host::Rx& rx) { s[i]->onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), w.loop.now); };
    }
    uint64_t base[2] = {w[0].sent, w[1].sent};
    TimePoint done = TimePoint::max();
    w.run([&](TimePoint now) {
        TimePoint a = s[0]->poll(now), b = s[1]->poll(now);
        if (done == TimePoint::max() && s[0]->state() == PunchState::Established &&
            s[1]->state() == PunchState::Established)
            done = now;
        return std::min(a, b);
    }, t0 + Duration(30000));
    for (int i = 0; i < 2; ++i) {
        out.state[i] = s[i]->state();
        out.packets[i] = w[i].sent - base[i];
    }
    if (done != TimePoint::max()) out.seconds = std::chrono::duration<double>(done - t0).count();
    // Established socket really carries traffic both ways
    if (out.state[0] == PunchState::Established && out.state[1] == PunchState::Established) {
        int got = 0;
        for (int i = 0; i < 2; ++i)
            w[i].onRx = [&](const Host::Rx& rx) { if (rx.data.size() == 3) ++got; };
        uint8_t ping[3] = {9, 9, 9};
        for (int i = 0; i < 2; ++i) w[i].send(s[i]->establishedSocket(), s[i]->remoteEndpoint(), ping, 3);
        w.run([](TimePoint) { return TimePoint::max(); }, w.loop.now + Duration(100));
        if (got != 2) out.state[0] = PunchState::Failed;
    }
    return out;
}

static const char* st(PunchState s) {
    switch (s) {
    case PunchState::Waiting: return "Waiting";
    case PunchState::Punching: return "Punching";
    case PunchState::Established: return "Established";
    case PunchState::Failed: return "Failed";
    }
    return "?";
}

static void testPunch() {
    std::puts("punch (two simulated NATs)");
    NatModel fullCone; fullCone.mapping = Map::EI; fullCone.filtering = Filt::EI;
    NatModel restricted; restricted.mapping = Map::EI; restricted.filtering = Filt::AD;
    NatModel portRestricted; portRestricted.mapping = Map::EI; portRestricted.filtering = Filt::APD;
    portRestricted.alloc = Alloc::RandomFull;
    NatModel symSeq; symSeq.mapping = Map::APD; symSeq.filtering = Filt::APD; symSeq.alloc = Alloc::Sequential;
    NatModel symNoisy = symSeq; symNoisy.alloc = Alloc::Noisy; symNoisy.noiseMax = 3;
    NatModel cgnBlock = symSeq; cgnBlock.alloc = Alloc::RandomBlock;
    NatModel symRand = symSeq; symRand.alloc = Alloc::RandomFull;
    NatModel symBusy = symSeq; symBusy.othersPerSec = 50;

    struct Case { const char* name; NatModel a, b; bool expectOk; bool mayFail; };
    Case cases[] = {
        {"full cone   + full cone", fullCone, fullCone, true, false},
        {"port-restr  + port-restr", portRestricted, portRestricted, true, false},
        {"restricted  + sym random", restricted, symRand, true, false},
        {"port-restr  + sym seq", portRestricted, symSeq, true, false},
        {"port-restr  + sym noisy", portRestricted, symNoisy, true, true},
        {"port-restr  + CGNAT block", portRestricted, cgnBlock, true, false},
        {"port-restr  + sym random", portRestricted, symRand, false, true},
        {"sym seq     + sym seq", symSeq, symSeq, true, false},
        {"port-restr  + sym busy", portRestricted, symBusy, true, true},
        {"sym busy    + sym busy", symBusy, symBusy, false, true},
        {"sym random  + sym random", symRand, symRand, false, false},
        {"CGNAT block + CGNAT block", cgnBlock, cgnBlock, false, false},
    };
    for (auto& c : cases) {
        auto o = runPunch(c.a, c.b);
        bool ok = o.state[0] == PunchState::Established && o.state[1] == PunchState::Established;
        std::printf("  %-26s A=%-14s B=%-14s est=%.2f/%.2f  %s/%s  %.2fs  pkts=%llu/%llu\n", c.name,
                    toString(o.plan[0].strategy), toString(o.plan[1].strategy), o.plan[0].estimatedSuccess,
                    o.plan[1].estimatedSuccess, st(o.state[0]), st(o.state[1]), o.seconds,
                    (unsigned long long)o.packets[0], (unsigned long long)o.packets[1]);
        if (!c.mayFail) CHECK_EQ(ok, c.expectOk);
        // Complementary plans: both infeasible or both feasible
        CHECK_EQ(o.plan[0].strategy == PunchStrategy::Infeasible, o.plan[1].strategy == PunchStrategy::Infeasible);
        // Packet budget: never more than budget/interval rounds of (sockets x targets)
        for (int i = 0; i < 2; ++i) {
            const auto& p = o.plan[i];
            uint64_t rounds = uint64_t(p.budget / p.sendInterval) + 1;
            CHECK(o.packets[i] <= rounds * uint64_t(p.localSockets) * p.targets.size() + 64);
        }
    }
    // Busy sequential CGNAT (point 6): honest estimate, real success rate close to it
    {
        int okN = 0; double est = 0;
        for (uint32_t s = 1; s <= 40; ++s) {
            auto o = runPunch(portRestricted, symBusy, s);
            okN += o.state[0] == PunchState::Established && o.state[1] == PunchState::Established;
            est += o.plan[0].estimatedSuccess / 40;
        }
        std::printf("  port-restr + sym busy, 40 seeds: %d/40 established (mean estimate %.2f)\n", okN, est);
        CHECK(est < 1.0);
        CHECK(okN >= 30);
    }
    // Birthday against a full random range over many seeds: success rate near the estimate
    int okN = 0; double est = 0;
    for (uint32_t s = 1; s <= 40; ++s) {
        auto o = runPunch(portRestricted, symRand, s);
        okN += o.state[0] == PunchState::Established && o.state[1] == PunchState::Established;
        est = o.plan[0].estimatedSuccess;
    }
    std::printf("  birthday vs random full, 40 seeds: %d/40 established (estimate %.2f over the whole budget)\n", okN, est);
    CHECK(okN >= 20);   // estimate 0.72: 40 Bernoulli trials, 4 sigma below the mean

    // Both peers behind the same NAT (same public IP)
    auto both = [](const PunchOutcome& o) {
        return o.state[0] == PunchState::Established && o.state[1] == PunchState::Established;
    };
    {
        // Same home network, symmetric random NAT without hairpinning: only
        // the inside addresses work.
        NatModel m; m.mapping = Map::APD; m.filtering = Filt::APD; m.alloc = Alloc::RandomFull;
        SameNat sn{0xC0A80102, 0xC0A80103, true};
        auto o = runPunch(m, m, 1, &sn);
        std::printf("  same home, symmetric random, no hairpin: %s/%s %s\n", toString(o.plan[0].strategy),
                    toString(o.plan[1].strategy), st(o.state[0]));
        CHECK(o.plan[0].sameNat && o.plan[1].sameNat);
        CHECK_EQ(o.plan[0].strategy, PunchStrategy::Local);
        CHECK(both(o));
    }
    {
        // Same CGNAT, subscribers isolated, hairpinning with public source:
        // the public path works.
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::APD; m.hairpin = Hairpin::External;
        SameNat sn{0x64400102, 0x64400907, false};
        auto o = runPunch(m, m, 1, &sn);
        std::printf("  same CGNAT, hairpin External: %s %s\n", toString(o.plan[0].strategy), st(o.state[0]));
        CHECK_EQ(o.plan[0].strategy, PunchStrategy::Direct);
        CHECK(o.plan[0].estimatedSuccess > 0.5);
        CHECK(both(o));
        // Same, without hairpinning: no public path, inside addresses unreachable
        m.hairpin = Hairpin::None;
        o = runPunch(m, m, 1, &sn);
        CHECK_EQ(o.plan[0].strategy, PunchStrategy::Local);
        CHECK(!both(o));
        // Hairpinning with inside source, carrier routes between subscribers
        m.hairpin = Hairpin::Internal;
        SameNat routed{0x64400102, 0x64400907, true};
        o = runPunch(m, m, 1, &routed);
        CHECK_EQ(o.plan[0].strategy, PunchStrategy::Local);
        CHECK(both(o));
    }
    {
        // Inside addresses are ignored unless the public IPs match, and only
        // private/CGNAT addresses are accepted.
        NatModel m; m.mapping = Map::EI; m.filtering = Filt::APD;
        NatProfile p = runDiscovery(m, false).final;
        PeerInfo a{p, {0xCB007105, 4662}, {{0xC0A80102, 4662}}};
        PeerInfo b{p, {0xC6120A07, 4672}, {{0xC0A80103, 4672}}};
        CHECK(planPunch(a, b).localTargets.empty());
        b.observed.ip = a.observed.ip;
        b.localEndpoints = {{0x08080808, 53}, {0xC0A80103, 4672}};
        auto plan = planPunch(a, b);
        CHECK(plan.localTargets.size() == 1 && (plan.localTargets[0] == Endpoint{0xC0A80103, 4672}));
    }

    // Hard packet cap (point 8): the plan honours it and the session enforces it
    {
        NatModel prA = portRestricted, rnd = symRand;
        NatProfile pa = runDiscovery(prA, false).final, pb = runDiscovery(rnd, false).final;
        PunchLimits lim;
        lim.maxPackets = 100;
        PeerInfo ia{pa, {0xCB007105, 4662}}, ib{pb, {0xC6120A07, 31000}};
        auto plan = planPunch(ia, ib, lim);
        CHECK_EQ(plan.strategy, PunchStrategy::BirthdaySpray);
        CHECK(plan.targets.size() <= 100);
        CHECK(plan.estimatedSuccess < 0.15);   // 100 sprayed ports: much lower chance, said honestly
        EventLoop loop;
        NatModel pub; pub.present = false;
        Host h(loop, pub, 3);
        int sent = 0;
        h.egress = [&](const Endpoint&, const Endpoint&, std::vector<uint8_t>, const Endpoint*) { ++sent; };
        auto prim = *h.openSocket(4662);
        plan.targets.assign(500, Endpoint{0xC6120A07, 31000});   // a plan that ignores the cap
        for (int i = 0; i < 500; ++i) plan.targets[i].port = uint16_t(20000 + i);
        PunchSessionConfig c;
        c.plan = plan;
        c.plan.strategy = PunchStrategy::Predict;
        c.remoteIp = 0xC6120A07;
        c.primarySocket = prim;
        c.startAt = loop.now;
        PunchSession ps(c, h);
        for (int i = 0; i < 100000 && ps.state() != PunchState::Failed; ++i) {
            TimePoint t = ps.poll(loop.now);
            loop.now = std::max(std::min(t, loop.now + Duration(1000)), loop.now + Duration(1));
            loop.runDue();
        }
        loop.now += Duration(10);
        loop.runDue();
        CHECK_EQ(sent, 100);
    }
    // Session refuses targets on any IP but the signalled one
    {
        EventLoop loop;
        NatModel pub; pub.present = false;
        Host h(loop, pub, 1);
        std::vector<Endpoint> dst;
        h.egress = [&](const Endpoint&, const Endpoint& to, std::vector<uint8_t>, const Endpoint*) { dst.push_back(to); };
        auto prim = *h.openSocket(4662);
        PunchSessionConfig c;
        c.plan.strategy = PunchStrategy::Predict;
        c.plan.targets = {{0x01010101, 1000}, {0x08080808, 53}, {0x01010101, 1001}};
        c.plan.budget = Duration(1000);
        c.remoteIp = 0x01010101;
        c.primarySocket = prim;
        c.startAt = loop.now;
        PunchSession ps(c, h);
        TimePoint t = loop.now;
        for (int i = 0; i < 2000 && ps.state() != PunchState::Failed; ++i) {
            t = std::min(ps.poll(loop.now), loop.now + Duration(1000));
            loop.now = std::max(t, loop.now + Duration(1));
            loop.runDue();
        }
        loop.now += Duration(10);
        loop.runDue();
        CHECK(!dst.empty());
        bool onlyRemote = true;
        for (auto& e : dst) onlyRemote &= e.ip == 0x01010101;
        CHECK(onlyRemote);
        CHECK_EQ(ps.state(), PunchState::Failed);   // nobody answered within the budget
    }
}


// Obfuscated punch: the application's transform on every datagram of the
// punch. On the wire no natd header; mismatched keys, or one side only
// obfuscating, never establish.
namespace {
struct TestObfuscator : IDatagramObfuscator {
    uint8_t key;
    explicit TestObfuscator(uint8_t k) : key(k) {}
    std::vector<uint8_t> wrap(const uint8_t* d, size_t n) override {
        std::vector<uint8_t> o(n + 1);
        o[0] = uint8_t(0x5A ^ key);
        for (size_t i = 0; i < n; ++i) o[i + 1] = uint8_t(d[i] ^ uint8_t(key + i * 7));
        return o;
    }
    bool unwrap(const uint8_t* d, size_t n, std::vector<uint8_t>& out) override {
        if (n < 1 || d[0] != uint8_t(0x5A ^ key)) return false;
        out.resize(n - 1);
        for (size_t i = 0; i + 1 < n; ++i) out[i] = uint8_t(d[i + 1] ^ uint8_t(key + i * 7));
        return true;
    }
};

struct ObfResult { bool established = false; uint64_t plainOnWire = 0, onWire = 0; };

ObfResult runObfuscated(int keyA, int keyB) {   // key < 0: no obfuscation on that side
    NatProfile stable;
    stable.predictability = Predictability::Stable;
    stable.keepaliveInterval = Duration(20000);
    NatModel cg; cg.mapping = Map::EI; cg.filtering = Filt::APD; cg.alloc = Alloc::RandomFull;
    Peers w(cg, cg, 91);
    SocketId prim[2] = {*w[0].openSocket(4672), *w[1].openSocket(4672)};
    Endpoint seen[2];
    const uint32_t kThird = 0xC6336409;
    ObfResult r;
    for (int i = 0; i < 2; ++i) {
        auto old = w[i].egress;
        w[i].egress = [&, i, old](const Endpoint& src, const Endpoint& to, std::vector<uint8_t> d, const Endpoint* fa) {
            if (to.ip == kThird) { seen[i] = src; return; }
            ++r.onWire;
            if (d.size() >= 4 && std::memcmp(d.data(), "NATD", 4) == 0) ++r.plainOnWire;
            old(src, to, std::move(d), fa);
        };
        uint8_t hi = 1;
        w[i].send(prim[i], Endpoint{kThird, 9}, &hi, 1);
    }
    w.run([](TimePoint) { return TimePoint::max(); }, w.loop.now + Duration(50));
    const TxId tok = sessionTokenFrom(reinterpret_cast<const uint8_t*>("obf"), 3);
    std::shared_ptr<IDatagramObfuscator> obf[2];
    const int keys[2] = {keyA, keyB};
    for (int i = 0; i < 2; ++i)
        if (keys[i] >= 0) obf[i] = std::make_shared<TestObfuscator>(uint8_t(keys[i]));
    std::unique_ptr<PunchSession> ps[2];
    for (int i = 0; i < 2; ++i) {
        PunchSessionConfig c;
        c.plan = planDirect(stable, seen[1 - i]);
        c.token = tok;
        c.startAt = w.loop.now + Duration(i * 80);
        c.remoteIp = seen[1 - i].ip;
        c.primarySocket = prim[i];
        c.obfuscator = obf[i];
        ps[i] = std::make_unique<PunchSession>(c, w[i]);
    }
    for (int i = 0; i < 2; ++i)
        w[i].onRx = [&, i](const Host::Rx& rx) { ps[i]->onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), w.loop.now); };
    auto tick = [&](TimePoint now) {
        TimePoint next = TimePoint::max();
        for (int i = 0; i < 2; ++i) next = std::min(next, ps[i]->poll(now));
        return std::max(next, now + Duration(1));
    };
    w.run(tick, w.loop.now + Duration(20000));
    r.established = ps[0]->state() == PunchState::Established && ps[1]->state() == PunchState::Established;
    return r;
}
} // namespace

// Dispatch costs: a punch looks at the source before it unwraps anything;
// the Agent tells when it wants poll() also after other calls.
static void testDispatch() {
    std::puts("dispatch");
    struct NullIo : IDatagramIo {
        std::optional<SocketId> openSocket(uint16_t) override { return SocketId(1); }
        void closeSocket(SocketId) override {}
        Endpoint localEndpoint(SocketId) const override { return {0x0A000002, 4662}; }
        bool send(SocketId, const Endpoint&, const uint8_t*, size_t) override { return true; }
    } io;
    struct Counting : IDatagramObfuscator {
        int unwraps = 0;
        std::vector<uint8_t> wrap(const uint8_t* d, size_t l) override { return {d, d + l}; }
        bool unwrap(const uint8_t* d, size_t l, std::vector<uint8_t>& out) override { ++unwraps; out.assign(d, d + l); return true; }
    };
    auto obf = std::make_shared<Counting>();
    NatProfile stable;
    stable.predictability = Predictability::Stable;
    PunchSessionConfig pc;
    pc.plan = planDirect(stable, Endpoint{0x5B000001, 5000});
    pc.remoteIp = 0x5B000001;
    pc.obfuscator = obf;
    const TimePoint t0 = TimePoint{} + std::chrono::hours(1);
    pc.startAt = t0;
    PunchSession ps(pc, io);
    ps.poll(t0);
    const uint8_t junk[40] = {1, 2, 3};
    for (int i = 0; i < 100; ++i) ps.onDatagram(0, Endpoint{0x5C000001, uint16_t(4000 + i)}, junk, sizeof junk, t0);
    CHECK_EQ(obf->unwraps, 0);                          // other IPs: not even unwrapped
    ps.onDatagram(0, Endpoint{0x5B000001, 5000}, junk, sizeof junk, t0);
    CHECK_EQ(obf->unwraps, 1);

    // nextPoll(): what poll() said, or earlier after another call.
    AgentConfig ac;
    ac.discovery.primarySocket = 0;
    ac.discovery.stunServers = {{{0xC6336401, 3478}, 0}, {{0xC6336402, 3478}, 0}};
    Agent agent(ac, io);
    CHECK(agent.nextPoll() == TimePoint::max());
    agent.start(t0);
    CHECK(agent.nextPoll() <= t0);
    const TimePoint w = agent.poll(t0);
    CHECK(agent.nextPoll() == w && w > t0);
    agent.checkEndpoint(t0 + Duration(10));
    CHECK(agent.nextPoll() <= t0 + Duration(10));
}

static void testObfuscation() {
    std::puts("obfuscated punch (application transform)");
    const ObfResult same = runObfuscated(7, 7);
    CHECK(same.established);
    CHECK(same.onWire > 0 && same.plainOnWire == 0);   // no natd header on the path
    const ObfResult plain = runObfuscated(-1, -1);
    CHECK(plain.established && plain.plainOnWire == plain.onWire);
    CHECK(!runObfuscated(7, 8).established);
    CHECK(!runObfuscated(7, -1).established);
    std::printf("  obfuscated: %llu datagrams, none with the natd header; plain: all %llu with it\n",
                (unsigned long long)same.onWire, (unsigned long long)plain.onWire);
}

// ---------------------------------------------------------------- agent
// Two applications, each with an Agent on its primary socket, behind CGNATs
// with endpoint-independent mapping; public STUN servers only. The
// signalling channel is the test itself: each side learns the other's
// public endpoint and the offer.
namespace {
struct AgentRig {
    Peers w;
    std::vector<StunServer> stun;
    SocketId prim[2];
    std::unique_ptr<Agent> a[2];
    std::vector<AgentEvent> ev[2];
    std::vector<std::vector<uint8_t>> appRx[2];   // datagrams natd said are not its own
    uint64_t out[2] = {0, 0};                      // datagrams sent to anything but the STUN servers
    bool deaf[2] = {false, false};

    AgentRig(NatModel m0, NatModel m1, uint32_t seed, std::function<void(AgentConfig&, int)> tweak = {}) : w(m0, m1, seed) {
        for (uint32_t i = 0; i < 6; ++i) stun.push_back(StunServer{{kStunBase + 20 + i, 3478}, 3479});
        for (int i = 0; i < 2; ++i) {
            prim[i] = *w[i].openSocket(4672);
            auto old = w[i].egress;
            w[i].egress = [this, i, old](const Endpoint& src, const Endpoint& to, std::vector<uint8_t> d, const Endpoint* fa) {
                for (auto& sv : stun)
                    if (sv.ep.ip == to.ip && (to.port == sv.ep.port || to.port == sv.altPort)) {
                        if (auto r = sv.answer(src, d)) {
                            Host* h = &w[i];
                            w.loop.schedule(w.loop.now + kLatency, [h, to, src, r] { h->ingress(to, src, *r); });
                        }
                        return;
                    }
                ++out[i];
                old(src, to, std::move(d), fa);
            };
            AgentConfig c;
            c.discovery.primarySocket = prim[i];
            c.discovery.measureLifetime = false;
            for (auto& sv : stun) c.discovery.stunServers.push_back({sv.ep, sv.altPort});
            if (tweak) tweak(c, i);
            a[i] = std::make_unique<Agent>(c, w[i]);
            w[i].onRx = [this, i](const Host::Rx& rx) {
                if (!deaf[i] && !a[i]->onDatagram(rx.sock, rx.from, rx.data.data(), rx.data.size(), w.loop.now))
                    appRx[i].push_back(rx.data);
            };
        }
    }
    // Runs both agents, collecting their events; app(now) is the applications' turn.
    void run(Duration d, std::function<void(TimePoint)> app = {}) {
        w.run([&](TimePoint now) {
            TimePoint next = TimePoint::max();
            for (int i = 0; i < 2; ++i) {
                if (deaf[i]) continue;
                next = std::min(next, a[i]->poll(now));
                AgentEvent e;
                while (a[i]->nextEvent(e)) ev[i].push_back(e);
            }
            if (app) app(now);
            return std::max(next, now + Duration(1));
        }, w.loop.now + d);
    }
    bool saw(int i, AgentEventType t, SessionId id = 0, PunchError* err = nullptr) const {
        for (auto& e : ev[i])
            if (e.type == t && (id == 0 || e.session == id)) { if (err) *err = e.error; return true; }
        return false;
    }
};
} // namespace

static void testAgent() {
    std::puts("agent");
    // Offer and token: the wire format eMule's marker already used.
    {
        Offer o{1, 0x0102030405060708ull};
        auto b = encodeOffer(o);
        CHECK(std::memcmp(b.data(), "NATD", 4) == 0 && b[4] == kOfferVersion && b[5] == 1 && b[6] == 0x08 && b[13] == 0x01);
        auto d = decodeOffer(b.data(), b.size());
        CHECK(d && d->kind == 1 && d->nonce == o.nonce);
        CHECK(!decodeOffer(b.data(), b.size() - 1));
        b[4] = 2;
        CHECK(!decodeOffer(b.data(), b.size()));
        uint8_t key[16];
        for (int i = 0; i < 16; ++i) key[i] = uint8_t(i * 3);
        uint8_t in[24];
        std::memcpy(in, key, 16);
        for (int i = 0; i < 8; ++i) in[16 + i] = uint8_t(o.nonce >> (8 * i));
        CHECK(tokenFrom(key, 16, o.nonce) == sessionTokenFrom(in, 24));
        CHECK(tokenFrom(key, 16, o.nonce) != tokenFrom(key, 16, o.nonce + 1));
    }
    NatModel cg; cg.mapping = Map::EI; cg.filtering = Filt::APD; cg.alloc = Alloc::RandomFull;
    const uint8_t key[16] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
    const TxId tok = tokenFrom(key, 16, 42);
    // Cost of an obfuscated session for the rest of the application's
    // traffic: while one punches, and later while its stream is open, the
    // Agent gets the application's own datagrams from many other peers
    // (mayBeOurs() lets them all through), and unwraps none of them.
    {
        struct Counting : IDatagramObfuscator {
            int unwraps = 0;
            std::vector<uint8_t> wrap(const uint8_t* d, size_t l) override { return {d, d + l}; }
            bool unwrap(const uint8_t* d, size_t l, std::vector<uint8_t>& out) override {
                ++unwraps;
                out.assign(d, d + l);
                return true;
            }
        };
        AgentRig r(cg, cg, 5);
        for (int i = 0; i < 2; ++i) r.a[i]->start(r.w.loop.now);
        r.run(Duration(20000));
        CHECK(r.a[0]->profileReady() && r.a[1]->profileReady());
        auto o0 = std::make_shared<Counting>(), o1 = std::make_shared<Counting>();
        const SessionId c = r.a[0]->connect(r.a[1]->publicEndpoint(), tok, r.w.loop.now, o0);
        const SessionId in = r.a[1]->accept(r.a[0]->publicEndpoint(), tok, r.w.loop.now, o1);
        CHECK(c != 0 && in != 0);
        const uint8_t own[40] = {0xE3, 5, 0, 0, 0, 0x4C};   // eD2K-like: not natd's
        auto flood = [&](int n) {
            const int before = o0->unwraps;
            for (int k = 0; k < n; ++k)
                r.a[0]->onDatagram(r.prim[0], Endpoint{0x5C000000u + uint32_t(k), uint16_t(4662 + k % 7)}, own, sizeof own,
                                   r.w.loop.now);
            return o0->unwraps - before;
        };
        CHECK(r.a[0]->mayBeOurs(own, sizeof own));                       // an obfuscated session is open
        CHECK_EQ(r.a[0]->phase(c), SessionPhase::Punching);
        const int whilePunching = flood(500);
        CHECK_EQ(whilePunching, 0);
        r.run(Duration(10000));
        CHECK(r.saw(0, AgentEventType::Punched, c) && r.saw(1, AgentEventType::Punched, in));
        CHECK(o0->unwraps > 0);                                            // its own datagrams were unwrapped
        CHECK(r.a[0]->takeResult(c, r.w.loop.now) && r.a[1]->takeResult(in, r.w.loop.now));
        const int whileHandedOver = flood(500);                            // the punch still answers late PUNCHes
        CHECK_EQ(whileHandedOver, 0);
        std::printf("  obfuscated punch: 500 foreign datagrams while punching, 500 after the hand-over: %d and %d unwrap() calls\n",
                    whilePunching, whileHandedOver);
    }
    // Discovery, punch, hand-over: the path is the application's.
    {
        AgentRig r(cg, cg, 5);
        uint8_t junk[3] = {0xE3, 1, 2};   // the application's own protocol
        CHECK(!r.a[0]->mayBeOurs(junk, 3));
        CHECK(!r.a[0]->onDatagram(r.prim[0], {0x01020304, 4662}, junk, 3, r.w.loop.now));
        CHECK_EQ(r.a[0]->connect(Endpoint{0x01020304, 4672}, tok, r.w.loop.now), SessionId(0));   // no profile yet
        for (int i = 0; i < 2; ++i) r.a[i]->start(r.w.loop.now);
        r.run(Duration(30000));
        CHECK(r.saw(0, AgentEventType::ProfileReady) && r.saw(1, AgentEventType::ProfileReady));
        CHECK(r.a[0]->directPunchable() && r.a[1]->directPunchable());
        CHECK_EQ(r.a[0]->publicEndpoint().ip, r.w[0].publicIp());
        SessionId s0 = r.a[0]->connect(r.a[1]->publicEndpoint(), tok, r.w.loop.now);
        SessionId s1 = r.a[1]->accept(r.a[0]->publicEndpoint(), tok, r.w.loop.now);
        CHECK(s0 != 0 && s1 != 0);
        CHECK_EQ(r.a[1]->accept(r.a[0]->publicEndpoint(), tok, r.w.loop.now), SessionId(0));   // repeated
        CHECK_EQ(r.a[0]->phase(s0), SessionPhase::Punching);
        r.run(Duration(20000));
        CHECK(r.saw(0, AgentEventType::Punched, s0) && r.saw(1, AgentEventType::Punched, s1));
        CHECK_EQ(r.a[0]->phase(s0), SessionPhase::Punched);
        CHECK_EQ(r.a[0]->sessionCount(), size_t(1));
        const std::optional<PunchResult> r0 = r.a[0]->takeResult(s0, r.w.loop.now);
        const std::optional<PunchResult> r1 = r.a[1]->takeResult(s1, r.w.loop.now);
        CHECK(r0 && r1);
        if (r0 && r1) {
            CHECK_EQ(r0->socket, r.prim[0]);
            CHECK(r0->remote == r.a[1]->publicEndpoint() && r1->remote == r.a[0]->publicEndpoint());
            CHECK(r0->local == r.w[0].localEndpoint(r.prim[0]));
            CHECK(r0->keepalive >= Duration(15000));
            CHECK(r0->mappingLifetime == mappingLifetime(r.a[0]->profile()) && r0->mappingLifetime);
            CHECK(r0->strategy == PunchStrategy::Direct && !r0->incoming && r1->incoming);
            CHECK(r0->token == tok && r1->token == tok);
        }
        CHECK(!r.a[0]->takeResult(s0, r.w.loop.now));            // once
        CHECK_EQ(r.a[0]->phase(s0), SessionPhase::None);
        CHECK_EQ(r.a[0]->sessionCount(), size_t(0));
        CHECK_EQ(r.a[1]->accept(r.a[0]->publicEndpoint(), tok, r.w.loop.now), SessionId(0));   // the request again, late
        // The application's own datagrams over the path, both ways.
        if (r0 && r1) {
            const uint8_t hello[5] = {0xA9, 'h', 'e', 'l', 'o'};
            r.w[0].send(r0->socket, r0->remote, hello, sizeof hello);
            r.w[1].send(r1->socket, r1->remote, hello, sizeof hello);
            r.run(Duration(1000));
            CHECK(!r.appRx[0].empty() && !r.appRx[1].empty() && r.appRx[1].back().size() == sizeof hello);
            // A late PUNCH of the peer (our last ACK lost) is answered while the
            // punch budget lasts, and no longer after it.
            const std::vector<uint8_t> late = proto::encode(proto::Punch{tok, false});
            uint64_t before = r.out[0];
            r.w[1].send(r1->socket, r1->remote, late.data(), late.size());
            r.run(Duration(1000));
            CHECK_EQ(r.out[0], before + 1);
            r.run(Duration(25000));
            before = r.out[0];
            r.w[1].send(r1->socket, r1->remote, late.data(), late.size());
            r.run(Duration(1000));
            CHECK_EQ(r.out[0], before);
        }
        CHECK_EQ(r.a[0]->stats().punchesEstablished, 1u);
    }
    // Our NAT loses its mappings (a new address, a renumbered block): the
    // application asks a check, the endpoint changed.
    {
        AgentRig r(cg, cg, 8);
        for (int i = 0; i < 2; ++i) r.a[i]->start(r.w.loop.now);
        r.run(Duration(30000));
        const Endpoint before = r.a[0]->publicEndpoint();
        r.w[0].box.flush();
        CHECK_EQ(r.a[0]->lastCheckResult(), QuickCheckResult::Pending);   // none yet
        r.a[0]->checkEndpoint(r.w.loop.now);
        CHECK(r.a[0]->checking());
        r.a[0]->checkEndpoint(r.w.loop.now);   // one check at a time
        r.run(Duration(10000));
        CHECK(r.saw(0, AgentEventType::EndpointChecked));
        CHECK_EQ(r.a[0]->lastCheckResult(), QuickCheckResult::Changed);
        CHECK(r.saw(0, AgentEventType::EndpointChanged));
        CHECK(r.a[0]->publicEndpoint() != before);
        CHECK_EQ(r.a[0]->stats().endpointChecks, 1u);
        r.a[0]->checkEndpoint(r.w.loop.now);   // within checkReuse: the result stands
        CHECK_EQ(r.a[0]->stats().endpointChecksReused, 1u);
        CHECK(!r.a[0]->checking());
    }
    // Caps: one punch at a time, one waiting; the waiting one gives up after
    // punchWait, the next is refused at once. A cancelled punch ends quietly.
    {
        AgentRig r(cg, cg, 6, [](AgentConfig& c, int) { c.maxPunches = 1; c.maxWaiting = 1; c.punchWait = Duration(5000); });
        for (int i = 0; i < 2; ++i) r.a[i]->start(r.w.loop.now);
        r.run(Duration(30000));
        const Endpoint nobody{0xCB0071FE, 4672};   // nobody punches back
        SessionId p = r.a[0]->connect(nobody, tokenFrom(key, 16, 1), r.w.loop.now);
        SessionId q = r.a[0]->connect(nobody, tokenFrom(key, 16, 2), r.w.loop.now);
        CHECK(p != 0 && q != 0);
        CHECK_EQ(r.a[0]->phase(p), SessionPhase::Punching);
        CHECK_EQ(r.a[0]->phase(q), SessionPhase::Waiting);
        CHECK_EQ(r.a[0]->connect(nobody, tokenFrom(key, 16, 3), r.w.loop.now), SessionId(0));
        r.run(Duration(30000));
        PunchError e1 = PunchError::None, e2 = PunchError::None;
        CHECK(r.saw(0, AgentEventType::PunchFailed, p, &e1) && e1 == PunchError::TimedOut);
        CHECK(r.saw(0, AgentEventType::PunchFailed, q, &e2) && e2 == PunchError::TimedOut);
        CHECK_EQ(r.a[0]->stats().punchesStarted, 1u);   // q never got a session
        CHECK_EQ(r.a[0]->stats().punchesQueued, 1u);
        CHECK_EQ(r.a[0]->stats().punchesFailed, 1u);
        CHECK_EQ(r.a[0]->stats().punchesRefused, 2u);   // the third at once, q after waiting
        CHECK_EQ(r.a[0]->sessionCount(), size_t(0));
        CHECK_EQ(r.a[0]->phase(p), SessionPhase::None);
        SessionId c = r.a[0]->connect(nobody, tokenFrom(key, 16, 4), r.w.loop.now);
        CHECK_EQ(r.a[0]->phase(c), SessionPhase::Punching);
        r.a[0]->cancel(c, r.w.loop.now);
        CHECK_EQ(r.a[0]->phase(c), SessionPhase::None);
        r.run(Duration(30000));
        CHECK(!r.saw(0, AgentEventType::PunchFailed, c));
        CHECK_EQ(r.a[0]->sessionCount(), size_t(0));
    }
    // A NAT with address+port dependent mapping: no direct punch.
    {
        NatModel hard; hard.mapping = Map::APD; hard.filtering = Filt::APD; hard.alloc = Alloc::RandomFull;
        AgentRig r(hard, cg, 7);
        for (int i = 0; i < 2; ++i) r.a[i]->start(r.w.loop.now);
        r.run(Duration(30000));
        CHECK(r.a[0]->profileReady());
        CHECK(!r.a[0]->directPunchable());
        CHECK(r.a[1]->directPunchable());
        CHECK_EQ(r.a[0]->connect(r.a[1]->publicEndpoint(), tok, r.w.loop.now), SessionId(0));
    }
}

static void testVersion() {
    std::puts("version");
    CHECK(std::strcmp(versionString(), NATD_VERSION_STRING) == 0);
    char v[32];
    std::snprintf(v, sizeof v, "%d.%d.%d", kVersionMajor, kVersionMinor, kVersionPatch);
    CHECK(std::strcmp(v, NATD_VERSION_STRING) == 0);
    CHECK_EQ(NATD_VERSION, kVersionMajor * 10000 + kVersionMinor * 100 + kVersionPatch);
    PeerInfo pi;
    pi.observed = {0x01020304, 5000};
    const auto b = encodePeerInfo(pi);
    CHECK(b.size() > 4 && b[4] == kPeerInfoVersion);
}

int main() {
    testVersion();
    testClassifier();
    testReflector();
    testDiscovery();
    testMappingBudget();
    testFilterTimeout();
    testCgnLimits();
    testStun();
    testResilience();
    testQuickCheck();
    testPeerInfo();
    testPunch();
    testObfuscation();
    testDispatch();
    testAgent();
    std::printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
