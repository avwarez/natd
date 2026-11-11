// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// Profile exchange, port prediction, punch planning and punch session.
//
// planPunch() is deterministic and symmetric: A computes planPunch(a, b) and B
// computes planPunch(b, a) and the two plans fit together, provided both
// sides use the same PunchLimits.
//
// Roles (S = Stable side, X = other side):
//   S,S                      both Direct
//   S (filtering EI/AD), X   both Direct: X's packet reaches S, S learns X's
//                            port from the source address
//   S (filtering APD), X predictable      S Predict, X Direct
//   S (filtering APD), X bounded/random   S BirthdaySpray, X BirthdayListen
//   X predictable, Y predictable          both Predict
//   anything harder                       Infeasible
//
// Safety: every target is on the remote observed IP; PunchSession drops
// targets on any other IP and ignores packets from other IPs. The caller must
// set remote.observed.ip / PunchSessionConfig::remoteIp from the address seen
// on its signalling channel, never from the peer's own claim.
#include "natd/punch.hpp"
#include "sha256.hpp"
#include "natd/version.hpp"
#include "natd/protocol.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <set>

namespace natd {

// ===========================================================================
// PeerInfo encoding (big-endian)
// ===========================================================================
namespace {

constexpr uint8_t kPeerMagic[4] = {'N', 'P', 'I', 'F'};
// v1: fields up to newSocket. v2 appends allocationRate (u32, milli-ports/s,
// 0xFFFFFFFF = unknown). v3 appends hairpin (u8), the count of inside
// endpoints (u8, <= kMaxLocalEndpoints) and the endpoints (6 bytes each).
// Decoders accept all three; encoders write v3.
constexpr uint8_t kPeerVersion = kPeerInfoVersion;   // natd/version.hpp
constexpr size_t kAllocSize = 1 + 4 + 4 + 2 + 2 + 2 + 2;   // 17
constexpr size_t kPeerSizeV1 = 4 + 1 + 1 + 1 + 1 + 1 + 6 + 6 + 4 + 4 + 4 + 4 + 2 + kAllocSize * 2;
constexpr size_t kPeerSizeV2 = kPeerSizeV1 + 4;
constexpr uint32_t kRateUnknown = 0xFFFFFFFF;

struct W {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void u16(uint16_t v) { u8(uint8_t(v >> 8)); u8(uint8_t(v)); }
    void u32(uint32_t v) { u16(uint16_t(v >> 16)); u16(uint16_t(v)); }
    void ep(const Endpoint& e) { u32(e.ip); u16(e.port); }
};
struct Rd {
    const uint8_t* p; size_t n; size_t i = 0;
    uint8_t u8() { return p[i++]; }
    uint16_t u16() { uint16_t v = uint16_t((p[i] << 8) | p[i + 1]); i += 2; return v; }
    uint32_t u32() { uint32_t v = uint32_t(u16()) << 16; return v | u16(); }
    Endpoint ep() { Endpoint e; e.ip = u32(); e.port = u16(); return e; }
};

uint32_t msOrZero(const std::optional<Duration>& d) {
    return d ? uint32_t(std::clamp<int64_t>(d->count(), 1, 0xFFFFFFFF)) : 0;
}
uint16_t permille(double x) { return uint16_t(std::lround(std::clamp(x, 0.0, 1.0) * 1000)); }

void putAlloc(W& w, const AllocationInfo& a) {
    w.u8(uint8_t(a.pattern));
    w.u32(uint32_t(a.delta));
    w.u32(uint32_t(std::lround(std::clamp(a.jitter, 0.0, 1e6) * 1000)));
    w.u16(a.block.base);
    w.u16(a.block.size);
    w.u16(uint16_t(std::clamp(a.samples, 0, 65535)));
    w.u16(permille(a.confidence));
}
bool getAlloc(Rd& r, AllocationInfo& a) {
    uint8_t pat = r.u8();
    if (pat > uint8_t(AllocationPattern::RandomFull)) return false;
    a.pattern = AllocationPattern(pat);
    a.delta = int32_t(r.u32());
    a.jitter = r.u32() / 1000.0;
    a.block.base = r.u16();
    a.block.size = r.u16();
    a.samples = r.u16();
    uint16_t c = r.u16();
    if (c > 1000) return false;
    a.confidence = c / 1000.0;
    return a.delta >= -65535 && a.delta <= 65535;
}

} // namespace

std::vector<uint8_t> encodePeerInfo(const PeerInfo& pi) {
    const NatProfile& p = pi.profile;
    const NatDetails& d = p.details;
    W w;
    for (uint8_t c : kPeerMagic) w.u8(c);
    w.u8(kPeerVersion);
    w.u8(uint8_t(p.predictability));
    w.u8(uint8_t(d.mapping));
    w.u8(uint8_t(d.filtering));
    w.u8(uint8_t((d.filteringPartnerTested << 0) | (d.sameSocketFromNewSocket << 1) | (d.parityPreserved << 2) |
                 (d.behindNat << 3) | (d.multiplePublicIps << 4) | (d.lifetimeAtLeast << 5) |
                 (p.lifetimeMeasured << 6)));
    w.ep(p.publicEndpoint);
    w.ep(pi.observed);
    w.u32(uint32_t(std::clamp<int64_t>(p.punchInterval.count(), 0, 0xFFFFFFFF)));
    w.u32(uint32_t(std::clamp<int64_t>(p.keepaliveInterval.count(), 0, 0xFFFFFFFF)));
    w.u32(msOrZero(d.singlePacketLifetime));
    w.u32(msOrZero(d.bidirectionalLifetime));
    w.u16(permille(p.confidence));
    putAlloc(w, d.sameSocket);
    putAlloc(w, d.newSocket);
    // Rounded, not truncated: rate / 1000.0 * 1000 may fall just below the
    // integer it came from, and each decode-encode would lose one.
    w.u32(d.allocationRate ? uint32_t(std::llround(std::clamp(*d.allocationRate * 1000.0, 0.0, double(kRateUnknown - 1))))
                           : kRateUnknown);
    w.u8(uint8_t(d.hairpin));
    size_t n = std::min(pi.localEndpoints.size(), kMaxLocalEndpoints);
    w.u8(uint8_t(n));
    for (size_t i = 0; i < n; ++i) w.ep(pi.localEndpoints[i]);
    return w.b;
}

std::optional<PeerInfo> decodePeerInfo(const uint8_t* data, size_t len) {
    // Exact size per version: no optional fields inside a version.
    if (!data || len < 5 || std::memcmp(data, kPeerMagic, 4) != 0) return std::nullopt;
    const uint8_t ver = data[4];
    bool sizeOk = (ver == 1 && len == kPeerSizeV1) || (ver == 2 && len == kPeerSizeV2);
    if (ver == 3 && len >= kPeerSizeV2 + 2) {
        size_t n = data[kPeerSizeV2 + 1];
        sizeOk = n <= kMaxLocalEndpoints && len == kPeerSizeV2 + 2 + 6 * n;
    }
    if (!sizeOk) return std::nullopt;
    Rd r{data, len, 5};
    PeerInfo pi;
    NatProfile& p = pi.profile;
    NatDetails& d = p.details;
    uint8_t pr = r.u8(), mp = r.u8(), fl = r.u8(), flags = r.u8();
    if (pr > uint8_t(Predictability::Inconclusive) || mp > uint8_t(MappingBehavior::AddressPortDependent) ||
        fl > uint8_t(FilteringBehavior::AddressPortDependent))
        return std::nullopt;
    p.predictability = Predictability(pr);
    d.mapping = MappingBehavior(mp);
    d.filtering = FilteringBehavior(fl);
    d.filteringPartnerTested = flags & 1;
    d.sameSocketFromNewSocket = flags & 2;
    d.parityPreserved = flags & 4;
    d.behindNat = flags & 8;
    d.multiplePublicIps = flags & 16;
    d.lifetimeAtLeast = flags & 32;
    p.lifetimeMeasured = flags & 64;
    p.publicEndpoint = r.ep();
    pi.observed = r.ep();
    p.punchInterval = Duration(r.u32());
    p.keepaliveInterval = Duration(r.u32());
    if (uint32_t v = r.u32()) d.singlePacketLifetime = Duration(v);
    if (uint32_t v = r.u32()) d.bidirectionalLifetime = Duration(v);
    uint16_t c = r.u16();
    if (c > 1000) return std::nullopt;
    p.confidence = c / 1000.0;
    if (!getAlloc(r, d.sameSocket) || !getAlloc(r, d.newSocket)) return std::nullopt;
    if (ver >= 2) {
        uint32_t rate = r.u32();
        if (rate != kRateUnknown) d.allocationRate = rate / 1000.0;
    }
    if (ver >= 3) {
        uint8_t hp = r.u8();
        if (hp > uint8_t(HairpinBehavior::Internal)) return std::nullopt;
        d.hairpin = HairpinBehavior(hp);
        size_t n = r.u8();
        for (size_t i = 0; i < n; ++i) pi.localEndpoints.push_back(r.ep());
    }
    return pi;
}

// ===========================================================================
// Prediction
// ===========================================================================
namespace {

constexpr uint32_t kFullLo = 1024, kFullSize = 65536 - 1024;

// Ports of a range picked evenly (deterministic, as good as random against a
// random allocator). offset in [0,1) shifts the comb.
std::vector<uint16_t> comb(uint32_t lo, uint32_t size, int count, double offset) {
    std::vector<uint16_t> v;
    if (size == 0 || count <= 0) return v;
    count = int(std::min<uint32_t>(uint32_t(count), size));
    double stepLen = double(size) / count;
    for (int i = 0; i < count; ++i) v.push_back(uint16_t(lo + uint32_t((i + offset) * stepLen) % size));
    return v;
}

int hardness(const NatProfile& p) {
    switch (p.predictability) {
    case Predictability::Stable: return 0;
    case Predictability::Predictable: return 1;
    case Predictability::Bounded: return 2;
    default: return 3;   // Unpredictable, Inconclusive, UdpBlocked
    }
}

} // namespace

std::vector<PortCandidate> predictNextPorts(const NatProfile& prof, const Endpoint& last, int maxCandidates,
                                            RandomBytesFn rnd, Duration sinceObserved) {
    std::vector<PortCandidate> out;
    if (maxCandidates <= 0 || !last.valid()) return out;
    if (prof.predictability == Predictability::Stable) return {{last.port, 1.0}};

    const AllocationInfo& a = prof.details.sameSocket;
    const auto& rate = prof.details.allocationRate;
    // Ports other subscribers take before our next mapping. The age of the
    // observation is only bounded: average over ages spread in [0, bound].
    const double maxSecs = std::max(0.0, std::chrono::duration<double>(sinceObserved).count());
    constexpr int kAges = 8;
    double drifts[kAges];
    for (int j = 0; j < kAges; ++j) drifts[j] = rate ? *rate * maxSecs * (j + 0.5) / kAges : 0.0;
    // Without a measured rate the drift is unknown: never claim certainty.
    const double scale = rate ? 1.0 : 0.8;
    auto addStep = [&](int64_t off, double w) {
        int64_t p = int64_t(last.port) + off;
        p = ((p % 65536) + 65536) % 65536;
        if (p == 0) return;
        for (auto& c : out) if (c.port == p) { c.probability += w; return; }
        out.push_back({uint16_t(p), w});
    };

    switch (a.pattern) {
    case AllocationPattern::Sequential:
    case AllocationPattern::PortPreserving: {
        // Next port = last + d * (1 + N), N = allocations by others in the
        // meantime, Poisson with mean drift / |d|.
        int32_t d = a.delta ? a.delta : 1;
        for (int k = 1; k <= maxCandidates; ++k) {
            int n = k - 1;
            double pk = 0;
            for (double dr : drifts) {
                double lambda = dr / std::abs(d);
                pk += lambda > 0 ? std::exp(n * std::log(lambda) - lambda - std::lgamma(n + 1.0)) : (n == 0 ? 1 : 0);
            }
            pk /= kAges;
            if (pk > 1e-9) addStep(int64_t(k) * d, pk * scale);
        }
        break;
    }
    case AllocationPattern::SequentialNoisy: {
        // Offset in ports ~ Normal(|delta| + drift, jitter^2 + drift):
        // Poisson variance of the others' allocations, unit step assumed.
        int dir = a.delta >= 0 ? 1 : -1;
        double base = a.delta ? std::abs(a.delta) : 1;
        for (int k = 1; k <= maxCandidates; ++k) {
            double pk = 0;
            for (double dr : drifts) {
                double mu = base + dr;
                double sigma = std::max(1.0, std::sqrt(a.jitter * a.jitter + dr));
                auto cdf = [&](double x) { return 0.5 * std::erfc(-(x - mu) / (sigma * std::sqrt(2.0))); };
                pk += cdf(k + 0.5) - cdf(k - 0.5);
            }
            pk /= kAges;
            if (pk > 1e-9) addStep(int64_t(k) * dir, pk * scale);
        }
        break;
    }
    case AllocationPattern::RandomInBlock:
    case AllocationPattern::RandomFull: {
        uint32_t lo = kFullLo, size = kFullSize;
        if (a.pattern == AllocationPattern::RandomInBlock && a.block.size) { lo = a.block.base; size = a.block.size; }
        if (!rnd) rnd = defaultRandomBytes();
        uint8_t b[4];
        rnd(b, 4);
        double off = (uint32_t(b[0]) | (uint32_t(b[1]) << 8)) / 65536.0;
        for (uint16_t p : comb(lo, size, maxCandidates, off)) out.push_back({p, 1.0 / size});
        return out;
    }
    case AllocationPattern::Unknown: return out;
    }
    // Kept in allocation order (k = 1, 2, ...), not sorted by probability:
    // when both sides are Predictable, the k-th packet of each side creates
    // the k-th new mapping, so both must walk the candidates in the same order.
    return out;
}

// ===========================================================================
// Planning
// ===========================================================================
const char* toString(PunchStrategy s) {
    switch (s) {
    case PunchStrategy::Direct: return "Direct";
    case PunchStrategy::Predict: return "Predict";
    case PunchStrategy::BirthdaySpray: return "BirthdaySpray";
    case PunchStrategy::BirthdayListen: return "BirthdayListen";
    case PunchStrategy::Local: return "Local";
    case PunchStrategy::Infeasible: return "Infeasible";
    }
    return "?";
}

namespace {

// Range the remote side's next mappings fall into (birthday attack).
// Range the hard side's new mappings fall in. A block is trusted only from a
// confident sample (the same threshold computeProfile uses with the default
// target): a few samples, e.g. when the CGN refused mappings, can look like a
// small block and would aim the whole spray at it. Otherwise the full range.
void remoteRange(const NatProfile& p, uint32_t& lo, uint32_t& size) {
    const AllocationInfo& n = p.details.newSocket;
    const AllocationInfo& s = p.details.sameSocket;
    const AllocationInfo& a = n.pattern != AllocationPattern::Unknown && n.confidence >= s.confidence ? n : s;
    lo = kFullLo; size = kFullSize;
    if (a.pattern == AllocationPattern::RandomInBlock && a.block.size && a.confidence >= 0.4) {
        lo = a.block.base;
        size = a.block.size;
    }
}

double birthday(int k, int m, uint32_t n) {
    if (n == 0) return 0;
    double q = std::max(0.0, 1.0 - double(k) / n);
    return 1.0 - std::pow(q, m);
}

// Packets one side can afford per round within the budget, at packetSpacing.
int perRound(const PunchPlan& p) {
    auto spacing = std::max<int64_t>(1, p.packetSpacing.count());
    return int(std::max<int64_t>(1, p.sendInterval.count() / spacing));
}

// Inside addresses a peer may point us to: private (RFC 1918) or CGNAT shared
// space (RFC 6598). Anything else could aim our packets at third parties.
bool isInsideAddress(uint32_t ip) { return isPrivate(ip) || isCgnatSpace(ip); }

// Rounds that fit in the budget. Shared by planPunch and PunchSession.
int roundsIn(const PunchPlan& p) {
    auto iv = std::max<int64_t>(1, p.sendInterval.count());
    return int(std::max<int64_t>(1, p.budget.count() / iv));
}

// Until the peer answers, a punch gets no return traffic: at most one
// datagram per destination every 3 s (RFC 8085 §3.1.3), and keepalives at
// least 15 s apart (§3.5). Shorter periods only when the profile measured the
// binding lifetime (NatDiscovery derives them from it): a NAT that drops
// bindings that early is below RFC 4787 REQ-5 and needs them.
constexpr Duration kMinPunchInterval{3000};
constexpr Duration kMinKeepalive{15000};
Duration punchIntervalOf(const NatProfile& p) {
    if (p.lifetimeMeasured && p.punchInterval.count() > 0) return p.punchInterval;
    return std::max(p.punchInterval, kMinPunchInterval);
}
Duration keepaliveOf(const NatProfile& p) {
    if (p.lifetimeMeasured && p.keepaliveInterval.count() > 0) return p.keepaliveInterval;
    return std::max(p.keepaliveInterval, kMinKeepalive);
}

} // namespace

PunchPlan planPunch(const PeerInfo& local, const PeerInfo& remote, const PunchLimits& lim) {
    PunchPlan plan;
    const NatProfile& L = local.profile;
    const NatProfile& R = remote.profile;
    plan.sendInterval = punchIntervalOf(L);
    plan.keepalive = keepaliveOf(L);
    plan.budget = lim.budget;
    plan.maxPackets = std::max(0, lim.maxPackets);
    plan.strategy = PunchStrategy::Infeasible;
    if (!remote.observed.valid() || L.predictability == Predictability::UdpBlocked ||
        R.predictability == Predictability::UdpBlocked)
        return plan;

    const int hl = hardness(L), hr = hardness(R);
    const uint32_t rip = remote.observed.ip;
    // Mapping cap: one mapping per socket, and with address+port dependent
    // (or unknown) mapping one per distinct target as well.
    const int cap = lim.maxMappings > 0 ? lim.maxMappings : 1 << 30;
    const bool perTarget = L.details.mapping == MappingBehavior::AddressPortDependent ||
                           (L.details.mapping == MappingBehavior::Unknown && L.details.behindNat);
    const int maxTargets = std::max(1, std::min({lim.maxTargets, perRound(plan), perTarget ? cap : 1 << 30}));
    const int maxSockets = std::max(1, std::min(lim.maxSockets, cap));
    // Targets the stable side sprays (its mapping is not per target, so the
    // cap does not shrink it): used for estimates made by the hard side too,
    // so both sides compute the same number.
    const int sprayTargets = std::max(1, std::min(lim.maxTargets, perRound(plan)));
    auto direct = [&](double p) {
        plan.strategy = PunchStrategy::Direct;
        plan.targets = {remote.observed};
        plan.estimatedSuccess = p;
    };
    auto predict = [&](double partnerCoverage) {
        auto c = predictNextPorts(R, remote.observed, maxTargets, {}, lim.observationAge);
        double cov = 0;
        for (auto& x : c) { plan.targets.push_back({rip, x.port}); cov += x.probability; }
        plan.strategy = PunchStrategy::Predict;
        plan.estimatedSuccess = std::min(1.0, cov) * partnerCoverage;
    };
    auto predictCoverage = [&](const NatProfile& p, const Endpoint& obs) {
        double cov = 0;
        for (auto& x : predictNextPorts(p, obs, sprayTargets, {}, lim.observationAge)) cov += x.probability;
        return std::min(1.0, cov);
    };
    // Birthday: the stable side sprays M ports of the hard side's range, the
    // hard side opens K sockets towards the stable endpoint.
    // The hard side keeps its K mappings alive across rounds while the spray
    // moves to new ports each round, so the M*R sprayed ports add up.
    const int rounds = roundsIn(plan);
    auto bdayP = [&](const NatProfile& hard) {
        uint32_t lo, n;
        remoteRange(hard, lo, n);
        int total = int(std::min<int64_t>({int64_t(sprayTargets) * rounds, int64_t(n), int64_t(plan.maxPackets)}));
        return std::make_pair(birthday(maxSockets, total, n), std::make_pair(lo, n));
    };

    if (hl == 0 && hr == 0) { direct(0.95); }
    else if (hl == 0 || hr == 0) {
        const NatProfile& S = hl == 0 ? L : R;
        const NatProfile& X = hl == 0 ? R : L;
        const PeerInfo& xInfo = hl == 0 ? remote : local;
        if (S.details.filtering != FilteringBehavior::AddressPortDependent &&
            S.details.filtering != FilteringBehavior::Unknown) {
            direct(0.9);
        } else if (hardness(X) == 1) {
            double cov = predictCoverage(X, xInfo.observed);
            if (hl == 0) predict(1.0);          // we are S: spray X's predicted ports
            else direct(cov);                   // we are X: open one mapping towards S
            plan.estimatedSuccess = cov;
        } else {
            auto [p, range] = bdayP(X);
            plan.estimatedSuccess = p;
            if (hl == 0) {
                plan.strategy = PunchStrategy::BirthdaySpray;
                // One even comb over the range, dealt into R interleaved slices:
                // round r sprays slice r, itself an even comb of ~M ports.
                int total = int(std::min<int64_t>({int64_t(sprayTargets) * rounds, int64_t(range.second),
                                                   int64_t(plan.maxPackets)}));
                auto ports = comb(range.first, range.second, total, 0.5);
                for (int r = 0; r < rounds; ++r)
                    for (size_t i = size_t(r); i < ports.size(); i += size_t(rounds))
                        plan.targets.push_back({rip, ports[i]});
            } else {
                plan.strategy = PunchStrategy::BirthdayListen;
                plan.localSockets = maxSockets;
                plan.targets = {remote.observed};
            }
        }
    } else if (hl == 1 && hr == 1) {
        // Both sides spray in allocation order: A's j-th packet creates A's
        // j-th new mapping and targets B's j-th predicted port, and vice versa.
        // The pairs line up only if no other subscriber took a port on either
        // side before the punch, so the chance is P(no drift on A) x P(no drift
        // on B): the probability of each side's first candidate.
        auto noDrift = [&](const NatProfile& p, const Endpoint& obs) {
            auto c = predictNextPorts(p, obs, 1, {}, lim.observationAge);
            return c.empty() ? 0.0 : c.front().probability;
        };
        predict(1.0);
        plan.estimatedSuccess = noDrift(L, local.observed) * noDrift(R, remote.observed);
    } else {
        plan.estimatedSuccess = 0;
    }

    // Same public IP: both peers sit behind the same NAT. The public path
    // needs hairpinning as RFC 4787 REQ-9/9a define it (external source);
    // the inside addresses are tried as well. No handling is added for
    // behaviours the RFCs do not recommend.
    plan.sameNat = local.observed.valid() && local.observed.ip == rip;
    if (plan.sameNat) {
        // None violates REQ-9, Internal violates REQ-9a: either way the
        // public path is not usable as specified.
        auto noPublic = [](HairpinBehavior h) {
            return h == HairpinBehavior::None || h == HairpinBehavior::Internal;
        };
        if (noPublic(L.details.hairpin) || noPublic(R.details.hairpin)) plan.estimatedSuccess = 0;
        for (const Endpoint& e : remote.localEndpoints) {
            if (plan.localTargets.size() >= kMaxLocalEndpoints) break;
            if (e.valid() && isInsideAddress(e.ip) &&
                std::find(plan.localTargets.begin(), plan.localTargets.end(), e) == plan.localTargets.end())
                plan.localTargets.push_back(e);
        }
    }

    if (plan.strategy != PunchStrategy::Infeasible && plan.estimatedSuccess < lim.minSuccess) {
        plan.strategy = PunchStrategy::Infeasible;
        plan.targets.clear();
        plan.localSockets = 1;
    }
    if (plan.strategy == PunchStrategy::Infeasible && !plan.localTargets.empty()) {
        plan.strategy = PunchStrategy::Local;
        plan.estimatedSuccess = 0;
    }
    return plan;
}

// ===========================================================================
// Session
// ===========================================================================
PunchPlan planDirect(const NatProfile& local, const Endpoint& remote, const PunchLimits& lim) {
    PunchPlan p;
    if (local.predictability != Predictability::Stable || !remote.valid()) return p;
    p.strategy = PunchStrategy::Direct;
    p.localSockets = 1;
    p.targets = {remote};
    p.sendInterval = punchIntervalOf(local);
    p.packetSpacing = Duration(0);
    p.budget = std::min(lim.budget, Duration(15000));
    p.keepalive = keepaliveOf(local);
    p.maxPackets = std::min(lim.maxPackets, 64);
    p.estimatedSuccess = 0.9;
    return p;
}

PunchPlan planUnknownPeer(const NatProfile& local, const Endpoint& remote, const PunchLimits& lim) {
    PunchPlan p;
    if (!remote.valid()) return p;
    p.sendInterval = punchIntervalOf(local);
    p.budget = lim.budget;
    p.keepalive = keepaliveOf(local);
    p.maxPackets = std::max(0, lim.maxPackets);
    if (local.predictability == Predictability::Stable) {
        // The endpoint first, alone, as planDirect: a Stable peer answers
        // there. From the second round on the ports around it too, more each
        // round, the nearest first: a Predictable peer's mapping towards us
        // is a port a little past the endpoint, a Bounded one's a port of the
        // block that holds it, wherever the block starts.
        p.strategy = PunchStrategy::BirthdaySpray;
        p.wholeRange = true;
        p.sprayFromRound = 1;
        p.roundTargets = std::max(1, lim.unknownSpray);
        p.targets = {remote};
        // a port `a` past the endpoint ranks as one 2a before it
        uint32_t a = 1, b = 1;
        while (p.targets.size() < size_t(p.maxPackets)) {
            const bool ahead = uint32_t(remote.port) + a <= 65535;
            const bool behind = uint32_t(remote.port) >= kFullLo + b;
            if (!ahead && !behind) break;
            if (ahead && (!behind || a <= 2 * b)) p.targets.push_back({remote.ip, uint16_t(remote.port + a++)});
            else p.targets.push_back({remote.ip, uint16_t(remote.port - b++)});
        }
        p.estimatedSuccess = 0.9;
    } else if (local.predictability == Predictability::Predictable ||
               local.predictability == Predictability::Bounded) {
        // Our mapping towards the peer is a new port, a little past the
        // endpoint the channel saw or in its block, which a Stable peer
        // sprays: one mapping is enough, the primary socket's.
        p.strategy = PunchStrategy::BirthdayListen;
        p.localSockets = 1;
        p.targets = {remote};
        p.estimatedSuccess = 0.9;
    }
    return p;
}

TxId sessionTokenFrom(const uint8_t* data, size_t len) {
    // SHA-256 truncated to 96 bits: without the input, the token cannot be
    // told from random (and the input cannot be worked back from the token).
    static const char kDomain[] = "natd session token";
    std::vector<uint8_t> in(kDomain, kDomain + sizeof kDomain - 1);
    in.insert(in.end(), data, data + len);
    const auto h = detail::sha256(in.data(), in.size());
    TxId t;
    std::copy(h.begin(), h.begin() + long(t.size()), t.begin());
    return t;
}

struct PunchSession::Impl {
    PunchSessionConfig cfg;
    IDatagramIo& io;
    PunchState st = PunchState::Waiting;
    std::vector<SocketId> socks;      // [0] = primary
    std::vector<Endpoint> targets;    // from the plan, remote IP only
    std::vector<Endpoint> localTargets;   // same NAT: remote inside addresses
    std::vector<Endpoint> learned;    // endpoints that punched us
    std::vector<Endpoint> cur;        // this round's targets
    int round = 0;
    SocketId estSock = 0;
    Endpoint estEp;
    TimePoint roundAt{}, nextSend{}, deadline{};
    size_t cursor = 0;                // position inside the current round
    int punchesSent = 0;              // PUNCH (non-ACK) packets, capped by plan.maxPackets
    std::set<std::pair<SocketId, uint64_t>> heard;   // (socket, endpoint) that sent us a punch

    Impl(PunchSessionConfig c, IDatagramIo& i) : cfg(std::move(c)), io(i) {
        for (auto& t : cfg.plan.targets)
            if (t.ip == cfg.remoteIp && t.valid()) targets.push_back(t);   // never anyone else
        if (cfg.plan.sameNat)
            for (auto& t : cfg.plan.localTargets)
                if (t.valid() && isInsideAddress(t.ip) && localTargets.size() < kMaxLocalEndpoints)
                    localTargets.push_back(t);
        if (cfg.plan.strategy == PunchStrategy::Infeasible || (targets.empty() && localTargets.empty()) ||
            cfg.remoteIp == 0)
            st = PunchState::Failed;
        socks.push_back(cfg.primarySocket);
    }
    ~Impl() { closeExtras(); }

    void closeExtras() {
        for (size_t i = 1; i < socks.size(); ++i)
            if (socks[i] != estSock) io.closeSocket(socks[i]);
        socks.resize(1);
    }

    static uint64_t key(const Endpoint& e) { return (uint64_t(e.ip) << 16) | e.port; }

    void sendPunch(SocketId s, const Endpoint& to, bool ack) {
        proto::Punch p{cfg.token, ack};
        auto b = proto::encode(p);
        if (cfg.obfuscator) b = cfg.obfuscator->wrap(b.data(), b.size());
        io.send(s, to, b.data(), b.size());
    }

    size_t roundSize() const { return socks.size() * cur.size(); }

    // BirthdaySpray walks a new slice of its targets every round; the other
    // strategies repeat all targets. Endpoints that punched us are always added.
    void buildRound() {
        cur.clear();
        if (cfg.plan.strategy == PunchStrategy::BirthdaySpray && cfg.plan.wholeRange &&
            round < cfg.plan.sprayFromRound && !targets.empty()) {
            cur.push_back(targets.front());
        } else if (cfg.plan.strategy == PunchStrategy::BirthdaySpray && !cfg.plan.wholeRange) {
            size_t R = size_t(roundsIn(cfg.plan));
            size_t per = (targets.size() + R - 1) / R;
            size_t from = (size_t(round) % R) * per;
            for (size_t i = from; i < std::min(targets.size(), from + per); ++i) cur.push_back(targets[i]);
        } else if (cfg.plan.strategy == PunchStrategy::BirthdaySpray && cfg.plan.roundTargets > 0) {
            // the nearest targets, twice as many each round
            const int grow = std::min(round - cfg.plan.sprayFromRound, 20);
            const uint64_t n = 1 + (uint64_t(cfg.plan.roundTargets) << std::max(0, grow));
            cur.assign(targets.begin(), targets.begin() + ptrdiff_t(std::min<uint64_t>(n, targets.size())));
        } else {
            cur = targets;
        }
        for (auto& e : localTargets)
            if (std::find(cur.begin(), cur.end(), e) == cur.end()) cur.push_back(e);
        for (auto& e : learned)
            if (std::find(cur.begin(), cur.end(), e) == cur.end()) cur.push_back(e);
        ++round;
    }

    TimePoint poll(TimePoint now) {
        if (st == PunchState::Failed || st == PunchState::Established) return TimePoint::max();
        if (st == PunchState::Waiting) {
            if (now < cfg.startAt) return cfg.startAt;
            st = PunchState::Punching;
            deadline = now + cfg.plan.budget;
            for (int i = 1; i < cfg.plan.localSockets; ++i)
                if (auto s = io.openSocket(0)) socks.push_back(*s);
            roundAt = nextSend = now;
            cursor = 0;
            buildRound();
        }
        if (now >= deadline) { st = PunchState::Failed; closeExtras(); return TimePoint::max(); }
        // Socket-major order: in BirthdayListen every socket sends early.
        while (cursor < roundSize() && now >= nextSend && punchesSent < cfg.plan.maxPackets) {
            size_t si = cursor % socks.size(), ti = cursor / socks.size();
            sendPunch(socks[si], cur[ti], false);
            ++punchesSent;
            ++cursor;
            nextSend = now + cfg.plan.packetSpacing;
            if (cfg.plan.packetSpacing.count() > 0) break;
        }
        // Cap reached: stop sending, keep listening until the deadline.
        if (punchesSent >= cfg.plan.maxPackets) return deadline;
        if (cursor >= roundSize()) {
            if (now >= roundAt + cfg.plan.sendInterval) {
                roundAt = now; cursor = 0; nextSend = now; buildRound(); return now;
            }
            return std::min(deadline, roundAt + cfg.plan.sendInterval);
        }
        return std::min(deadline, nextSend);
    }

    bool onDatagram(SocketId s, const Endpoint& from, const uint8_t* d, size_t len, TimePoint) {
        // Only the signalled public IP or one of the inside addresses the
        // peer announced (same NAT), on one of our sockets: checked before
        // anything is decoded, so that other traffic costs no unwrap().
        if (from.ip != cfg.remoteIp &&
            std::none_of(localTargets.begin(), localTargets.end(),
                         [&](const Endpoint& t) { return t.ip == from.ip; }))
            return false;
        if (std::find(socks.begin(), socks.end(), s) == socks.end() && s != estSock) return false;
        std::vector<uint8_t> plain;
        if (cfg.obfuscator) {
            if (!cfg.obfuscator->unwrap(d, len, plain)) return false;
            d = plain.data();
            len = plain.size();
        }
        if (proto::peekType(d, len) != proto::MsgType::Punch) return false;
        auto p = proto::decodePunch(d, len);
        if (!p || p->token != cfg.token) return false;
        if (st == PunchState::Established) {
            if (!p->ack && s == estSock) sendPunch(s, from, true);   // the peer may still wait for our ACK
            return true;
        }
        if (st != PunchState::Punching) return true;
        if (!p->ack) {
            // Inbound works on this socket; answer and keep punching there.
            sendPunch(s, from, true);
            if (heard.insert({s, key(from)}).second &&
                std::find(learned.begin(), learned.end(), from) == learned.end())
                learned.push_back(from);
            return true;
        }
        // ACK: the peer received our packet and we received theirs. Answer
        // with one ACK so that the peer, too, knows both directions work
        // (punch -> ACK -> ACK); an established side never answers an ACK.
        st = PunchState::Established;
        estSock = s;
        estEp = from;
        sendPunch(s, from, true);
        closeExtras();
        return true;
    }
};

PunchSession::PunchSession(PunchSessionConfig cfg, IDatagramIo& io)
    : impl_(std::make_unique<Impl>(std::move(cfg), io)) {}
PunchSession::~PunchSession() = default;
bool PunchSession::onDatagram(SocketId s, const Endpoint& f, const uint8_t* d, size_t l, TimePoint n) {
    return impl_->onDatagram(s, f, d, l, n);
}
TimePoint PunchSession::poll(TimePoint now) { return impl_->poll(now); }
PunchState PunchSession::state() const { return impl_->st; }
SocketId PunchSession::establishedSocket() const { return impl_->estSock; }
Endpoint PunchSession::remoteEndpoint() const { return impl_->estEp; }
Duration PunchSession::keepalive() const { return impl_->cfg.plan.keepalive; }

} // namespace natd
