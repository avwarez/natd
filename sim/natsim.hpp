// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/sim/natsim.hpp — NAT and network building blocks for simulations
// with virtual time, shared by natd's tests and by downstream simulators.
// Header-only, not part of the library.
//   NatModel / NatBox — one NAT: mapping / filtering / allocation / binding
//                       timeouts / hairpin / port quota (RFC 4787, 6888)
//   StunServer        — RFC 8489 Binding responder (honest or faulty)
//   EventLoop         — virtual clock and event queue
#pragma once

#include "natd/natd.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <tuple>
#include <vector>

namespace sim {

using namespace natd;
enum class Map { EI, AD, APD };
enum class Filt { EI, AD, APD };
enum class Alloc { Preserve, Sequential, Noisy, RandomBlock, RandomFull };
enum class Hairpin { None, External, Internal };

struct NatModel {
    bool     present = true;        // false: client has a public address
    bool     blocked = false;       // drop all UDP
    Map      mapping = Map::EI;
    Filt     filtering = Filt::EI;
    Alloc    alloc = Alloc::Preserve;
    int      delta = 1;             // Sequential / Noisy
    int      noiseMax = 6;          // Noisy: extra ports taken by others per allocation
    uint16_t blockBase = 20480, blockSize = 2048;   // RandomBlock
    double   othersPerSec = 0;      // Sequential / Noisy: allocations by other subscribers
    Duration singleTimeout{30000};  // binding with outbound traffic only
    Duration bidirTimeout{120000};  // binding that has seen inbound traffic
    // Filtering state per remote (ADF: address, APDF: address and port).
    // 0: a remote once contacted stays allowed as long as the binding lives.
    // Otherwise each remote expires this long after the last packet
    // exchanged with it, like a per-session timer (Linux conntrack: 30 s
    // unreplied, 120-180 s replied), while the binding itself can be kept
    // alive by traffic to other remotes.
    Duration filterTimeout{0};
    uint32_t publicIp = 0xCB007105; // 203.0.113.5
    Hairpin  hairpin = Hairpin::None;
    // RFC 6888 REQ-4: limit on the subscriber's external ports (live
    // mappings; 0 = none). REQ-4c: limit on the rate of new mappings per
    // second (token bucket, burst of one second; 0 = none). A packet that
    // would need a refused mapping is dropped.
    size_t   portQuota = 0;
    double   mappingRate = 0;
};

// Simulated STUN server (RFC 8489 Binding), written independently of the
// library's encoder so that the two check each other.
struct StunServer {
    Endpoint ep;
    uint16_t altPort = 0;       // second port on the same IP (0 = none)
    bool alive = true;
    bool lies = false;          // answers with a wrong mapped address
    bool liesPort = false;      // right IP, made-up port (different on every request)
    bool liesPortFixed = false; // right IP, wrong port, always the same for a mapping
    bool rfc3489 = false;       // MAPPED-ADDRESS instead of XOR-MAPPED-ADDRESS
    bool errorReply = false;    // Binding error response (400) instead of success
    bool extraRequired = false; // success with an unknown comprehension-required attribute
    uint64_t requests = 0;

    std::optional<std::vector<uint8_t>> answer(const Endpoint& src, const std::vector<uint8_t>& q) {
        if (q.size() < 20 || q[0] != 0x00 || q[1] != 0x01 || q[4] != 0x21 || q[5] != 0x12 || q[6] != 0xA4 ||
            q[7] != 0x42)
            return std::nullopt;
        ++requests;
        if (!alive) return std::nullopt;
        Endpoint m = lies ? Endpoint{0x0A000001, uint16_t(src.port + 1)} : src;
        if (liesPort) m.port = uint16_t(1024 + (requests * 7919u + src.port * 31u) % 64000u);
        if (liesPortFixed) m.port = uint16_t(1024 + (src.port * 7919u) % 64000u);
        if (errorReply) {   // ERROR-CODE 400 "Bad"
            std::vector<uint8_t> e = {0x01, 0x11, 0x00, 12, 0x21, 0x12, 0xA4, 0x42};
            e.insert(e.end(), q.begin() + 8, q.begin() + 20);
            const uint8_t ec[12] = {0x00, 0x09, 0, 7, 0, 0, 4, 0, 'B', 'a', 'd', 0};
            e.insert(e.end(), ec, ec + 12);
            return e;
        }
        std::vector<uint8_t> r = {0x01, 0x01, 0x00, uint8_t(extraRequired ? 20 : 12), 0x21, 0x12, 0xA4, 0x42};
        r.insert(r.end(), q.begin() + 8, q.begin() + 20);
        if (extraRequired) {
            const uint8_t x[8] = {0x7F, 0x00, 0, 4, 1, 2, 3, 4};
            r.insert(r.end(), x, x + 8);
        }
        uint16_t port = m.port;
        uint32_t ip = m.ip;
        if (!rfc3489) { port ^= 0x2112; ip ^= 0x2112A442; }
        uint16_t type = rfc3489 ? 0x0001 : 0x0020;
        uint8_t a[12] = {uint8_t(type >> 8), uint8_t(type), 0, 8, 0, 1, uint8_t(port >> 8), uint8_t(port),
                         uint8_t(ip >> 24), uint8_t(ip >> 16), uint8_t(ip >> 8), uint8_t(ip)};
        r.insert(r.end(), a, a + 12);
        return r;
    }
};

// --------------------------------------------------------------------------
class NatBox {
public:
    NatBox(NatModel m, uint32_t seed) : nat(m), rng(seed) {
        nextAlloc = nat.alloc == Alloc::RandomBlock ? nat.blockBase : 40000;
    }

    // Outbound packet from local endpoint (lip, lp) to `to`: returns the
    // external port, 0 if the mapping is refused (quota or rate limit).
    uint16_t outbound(uint32_t lip, uint16_t lp, const Endpoint& to, TimePoint now) {
        gc(now);
        Key k = keyFor(lip, lp, to);
        auto it = bindings.find(k);
        if (it == bindings.end()) {
            if (nat.portQuota && bindings.size() >= nat.portQuota) { ++mappingsRefused; return 0; }
            if (nat.mappingRate > 0) {
                if (bucketAt != TimePoint{})
                    tokens = std::min(nat.mappingRate,
                                      tokens + nat.mappingRate * std::chrono::duration<double>(now - bucketAt).count());
                else tokens = nat.mappingRate;
                bucketAt = now;
                if (tokens < 1) { ++mappingsRefused; return 0; }
                tokens -= 1;
            }
            Binding b;
            b.ext = allocate(lp, now);
            it = bindings.emplace(k, b).first;
            extToKey[b.ext] = k;
            ++mappingsCreated;
            peakLive = std::max(peakLive, bindings.size());
        }
        Binding& b = it->second;
        b.lastOut = now;
        b.ips[to.ip] = now;
        b.eps[{to.ip, to.port}] = now;
        return b.ext;
    }

    // Inbound packet to external port: local endpoint if the filter lets it in.
    std::optional<Endpoint> inbound(uint16_t ext, const Endpoint& from, TimePoint now) {
        gc(now);
        auto kit = extToKey.find(ext);
        if (kit == extToKey.end()) return std::nullopt;
        auto bit = bindings.find(kit->second);
        if (bit == bindings.end() || bit->second.ext != ext) return std::nullopt;
        Binding& b = bit->second;
        auto live = [&](auto& m, const auto& key) {
            auto e = m.find(key);
            if (e == m.end() || (nat.filterTimeout.count() > 0 && now - e->second >= nat.filterTimeout)) return false;
            e->second = now;   // the session's timer runs on traffic both ways
            return true;
        };
        bool ok = nat.filtering == Filt::EI || (nat.filtering == Filt::AD && live(b.ips, from.ip)) ||
                  (nat.filtering == Filt::APD && live(b.eps, std::make_pair(from.ip, from.port)));
        if (!ok) return std::nullopt;
        b.inbound = true;
        return Endpoint{std::get<0>(kit->second), std::get<1>(kit->second)};
    }

    // Simulate other subscribers taking n ports (moves sequential allocators).
    void consume(int n) { for (int i = 0; i < n; ++i) allocate(0, lastAllocAt); }

    // Every mapping lost at once (CGN restart, session table reset, new
    // public address): the next outbound packet allocates afresh.
    void flush() {
        bindings.clear();
        extToKey.clear();
        extUsed.clear();
    }

    NatModel nat;
    size_t mappingsCreated = 0;   // every mapping ever created (CGN port quota)
    size_t peakLive = 0;          // most mappings alive at once
    size_t mappingsRefused = 0;   // refused by portQuota / mappingRate

private:
    double tokens = 0;
    TimePoint bucketAt{};
    struct Binding {
        uint16_t ext = 0;
        TimePoint lastOut{};
        bool inbound = false;
        std::map<uint32_t, TimePoint> ips;                     // remote address -> last packet
        std::map<std::pair<uint32_t, uint16_t>, TimePoint> eps; // remote endpoint -> last packet
    };
    using Key = std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>;   // local ip, port, dst ip, dst port (masked)

    Key keyFor(uint32_t lip, uint16_t lp, const Endpoint& to) const {
        switch (nat.mapping) {
        case Map::EI: return {lip, lp, 0, 0};
        case Map::AD: return {lip, lp, to.ip, 0};
        case Map::APD: return {lip, lp, to.ip, to.port};
        }
        return {lip, lp, 0, 0};
    }

    bool expired(const Binding& b, TimePoint now) const {
        return now - b.lastOut >= (b.inbound ? nat.bidirTimeout : nat.singleTimeout);
    }

    void gc(TimePoint now) {
        for (auto it = bindings.begin(); it != bindings.end();)
            if (expired(it->second, now)) { extUsed.erase(it->second.ext); it = bindings.erase(it); } else ++it;
    }

    uint16_t allocate(uint16_t lp, TimePoint now) {
        // Other subscribers allocated meanwhile (Poisson process).
        if ((nat.alloc == Alloc::Sequential || nat.alloc == Alloc::Noisy) && nat.othersPerSec > 0 &&
            lastAllocAt != TimePoint{} && now > lastAllocAt) {
            double mean = nat.othersPerSec * std::chrono::duration<double>(now - lastAllocAt).count();
            int n = std::poisson_distribution<int>(mean)(rng);
            int64_t off = (int64_t(nextAlloc) - 1024 + int64_t(n) * nat.delta) % 64512;
            nextAlloc = uint32_t(1024 + (off + 64512) % 64512);
        }
        lastAllocAt = now;
        auto freePort = [&](uint32_t p) { return p >= 1024 && p <= 65535 && !extUsed.count(uint16_t(p)); };
        uint32_t p = 0;
        switch (nat.alloc) {
        case Alloc::Preserve:
            p = lp;
            while (!freePort(p)) p = 1024 + rng() % 64512;
            break;
        case Alloc::Sequential:
        case Alloc::Noisy:
            p = nextAlloc;
            if (nat.alloc == Alloc::Noisy) p += rng() % (nat.noiseMax + 1);
            if (p > 65535) p = 1024;
            while (!freePort(p)) { p += nat.delta; if (p > 65535) p = 1024; }
            nextAlloc = p + nat.delta;
            if (nextAlloc > 65535) nextAlloc = 1024;
            break;
        case Alloc::RandomBlock:
        {
            // A full block: the CGN gives the subscriber another one (RFC 7422).
            auto full = [&] {
                for (uint32_t q = nat.blockBase; q < uint32_t(nat.blockBase) + nat.blockSize; ++q)
                    if (freePort(q)) return false;
                return true;
            };
            while (full())
                nat.blockBase = uint16_t(uint32_t(nat.blockBase) + nat.blockSize + nat.blockSize > 65536
                                             ? 1024 : nat.blockBase + nat.blockSize);
            do { p = nat.blockBase + rng() % nat.blockSize; } while (!freePort(p));
        }
            break;
        case Alloc::RandomFull:
            do { p = 1024 + rng() % 64512; } while (!freePort(p));
            break;
        }
        if (lp) extUsed.insert(uint16_t(p));   // consume(): other subscribers, port reused later
        return uint16_t(p);
    }

    std::mt19937 rng;
    std::map<Key, Binding> bindings;
    std::map<uint16_t, Key> extToKey;
    std::set<uint16_t> extUsed;
    uint32_t nextAlloc;
    TimePoint lastAllocAt{};
};

// --------------------------------------------------------------------------
class EventLoop {
public:
    TimePoint now{std::chrono::hours(1)};
    void schedule(TimePoint t, std::function<void()> f) { evq.push({t, seq++, std::move(f)}); }
    TimePoint nextEvent() const { return evq.empty() ? TimePoint::max() : evq.top().t; }
    void runDue() {
        while (!evq.empty() && evq.top().t <= now) {
            auto e = evq.top();
            evq.pop();
            e.f();
        }
    }
    bool empty() const { return evq.empty(); }

private:
    struct Ev {
        TimePoint t; uint64_t seq; std::function<void()> f;
        bool operator>(const Ev& o) const { return std::tie(t, seq) > std::tie(o.t, o.seq); }
    };
    std::priority_queue<Ev, std::vector<Ev>, std::greater<Ev>> evq;
    uint64_t seq = 0;
};

} // namespace sim
