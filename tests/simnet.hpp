// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// In-process network simulator with virtual time, built on sim/natsim.hpp:
//   Net     — one client behind a NatBox, two partnered reflectors and a
//             set of public STUN servers (some may be dead or lie)
//   Peers   — two clients, each behind its own NatBox (hole punching)
#pragma once

#include "../sim/natsim.hpp"

namespace sim {

constexpr uint32_t kClientIp = 0xC0A80102;   // 192.168.1.2
constexpr uint32_t kR0 = 0xC6336401;          // 198.51.100.1
constexpr uint32_t kR1 = 0xC6336402;          // 198.51.100.2
constexpr Duration kLatency{5};
constexpr uint32_t kStunBase = 0xC0000A00;    // 192.0.10.x: simulated public STUN servers


// A host with sockets, optionally behind a NAT. Delivery to the outside world
// goes through `egress`.
class Host : public IDatagramIo {
public:
    struct Rx { SocketId sock; Endpoint from; std::vector<uint8_t> data; };
    using Egress = std::function<void(const Endpoint& src, const Endpoint& to, std::vector<uint8_t>,
                                      const Endpoint* filterAs)>;
    // Returns true if `to` is on the host's LAN and the packet was delivered.
    using Lan = std::function<bool(const Endpoint& src, const Endpoint& to, const std::vector<uint8_t>&)>;

    Host(EventLoop& l, NatModel m, uint32_t seed, std::shared_ptr<NatBox> shared = {}, uint32_t localIp = kClientIp)
        : loop(l), boxp(shared ? shared : std::make_shared<NatBox>(m, seed)), box(*boxp), rng(seed * 7919u + 1) {
        ip = box.nat.present ? localIp : box.nat.publicIp;
    }

    std::optional<SocketId> openSocket(uint16_t pref) override {
        uint16_t port = pref;
        if (port == 0 || localUsed.count(port)) {
            if (pref) return std::nullopt;
            do { port = uint16_t(32768 + rng() % 28000); } while (localUsed.count(port));
        }
        SocketId id = nextSock++;
        socks[id] = port;
        localUsed.insert(port);
        ++opened;
        return id;
    }
    void closeSocket(SocketId s) override {
        auto it = socks.find(s);
        if (it == socks.end()) return;
        localUsed.erase(it->second);
        socks.erase(it);
        ++closed;
    }
    Endpoint localEndpoint(SocketId s) const override {
        auto it = socks.find(s);
        return it == socks.end() ? Endpoint{} : Endpoint{ip, it->second};
    }
    bool send(SocketId s, const Endpoint& to, const uint8_t* d, size_t len) override {
        auto it = socks.find(s);
        if (it == socks.end()) return false;
        ++sent;
        Endpoint src{ip, it->second};
        std::vector<uint8_t> data(d, d + len);
        // Same LAN: delivered directly, without the NAT.
        if (box.nat.present && lan && lan(src, to, data)) return true;
        if (box.nat.present) {
            if (box.nat.blocked) return true;
            Endpoint inside = src;
            uint16_t ext = box.outbound(ip, it->second, to, loop.now);
            if (!ext) return true;   // mapping refused: the NAT drops the packet
            src = {box.nat.publicIp, ext};
            if (to.ip == box.nat.publicIp) {
                // Hairpin: back in through the NAT. The filter sees the public
                // source; with Internal the receiver sees the inside address.
                if (box.nat.hairpin == Hairpin::None) return true;
                Endpoint shown = box.nat.hairpin == Hairpin::External ? src : inside;
                loop.schedule(loop.now + kLatency, [this, src, shown, to, data] { egress(shown, to, data, &src); });
                return true;
            }
        }
        loop.schedule(loop.now + kLatency, [this, src, to, data] { egress(src, to, data, nullptr); });
        return true;
    }

    // Packet arriving at this host's public address. filterAs: source the
    // NAT filter checks, when it differs from the one shown (hairpin).
    void ingress(const Endpoint& from, const Endpoint& to, const std::vector<uint8_t>& d,
                 const Endpoint* filterAs = nullptr) {
        uint16_t lp = to.port;
        if (box.nat.present) {
            if (box.nat.blocked) return;
            auto l = box.inbound(to.port, filterAs ? *filterAs : from, loop.now);
            if (!l || l->ip != ip) return;   // shared NAT: another host's mapping
            lp = l->port;
        }
        deliverLocal(from, lp, d);
    }
    // Packet on the LAN for local port lp.
    void deliverLocal(const Endpoint& from, uint16_t lp, const std::vector<uint8_t>& d) {
        for (auto& [id, port] : socks)
            if (port == lp) { if (onRx) onRx({id, from, d}); return; }
    }
    uint32_t localIp() const { return ip; }

    uint32_t publicIp() const { return box.nat.present ? box.nat.publicIp : ip; }

    EventLoop& loop;
    std::shared_ptr<NatBox> boxp;
    NatBox& box;
    Egress egress;
    Lan lan;
    std::function<void(const Rx&)> onRx;
    int opened = 0, closed = 0;
    uint64_t sent = 0;

private:
    std::mt19937 rng;
    uint32_t ip;
    SocketId nextSock = 1;
    std::map<SocketId, uint16_t> socks;
    std::set<uint16_t> localUsed;
};

// --------------------------------------------------------------------------
// One client + two partnered reflectors.
class Net : public IDatagramIo {
public:
    using Rx = Host::Rx;

    explicit Net(NatModel m, uint32_t seed = 1, std::function<void(ReflectorConfig&)> tweak = {})
        : host(loop, m, seed), nat(m) {
        for (int r = 0; r < 2; ++r) {
            for (int i = 0; i < 4; ++i) reflPorts[r].push_back(uint16_t(3478 + i));   // minimum 4 + 4
            refl[r].io.net = this;
            refl[r].io.r = r;
            ReflectorConfig rc;
            rc.portCount = 4;
            rc.partners = {Endpoint{r == 0 ? kR1 : kR0, 3478}};
            if (tweak) tweak(rc);
            refl[r].obj = std::make_unique<Reflector>(rc, refl[r].io);
        }
        // 12 servers, the first 4 answering on two ports (like ~half of the
        // public ones), one on 19302 every three.
        for (uint32_t i = 0; i < 12; ++i)
            stun.push_back({{kStunBase + 10 + i, uint16_t(i % 3 == 1 ? 19302 : 3478)}, uint16_t(i < 4 ? 3479 : 0)});
        host.egress = [this](const Endpoint& src, const Endpoint& to, std::vector<uint8_t> d, const Endpoint* fa) {
            if (to.ip == host.publicIp()) host.ingress(src, to, d, fa);
            else toReflector(src, to, d);
        };
        host.onRx = [this](const Rx& rx) { if (onClientRx) onClientRx(rx); };
    }

    std::optional<SocketId> openSocket(uint16_t p) override { return host.openSocket(p); }
    void closeSocket(SocketId s) override { host.closeSocket(s); }
    Endpoint localEndpoint(SocketId s) const override { return host.localEndpoint(s); }
    bool send(SocketId s, const Endpoint& to, const uint8_t* d, size_t l) override { return host.send(s, to, d, l); }

    std::function<void(const Rx&)> onClientRx;
    // Every datagram towards a STUN server address, before the server sees it.
    std::function<void(const Endpoint& to, const std::vector<uint8_t>&)> onStunRequest;

    void run(std::function<TimePoint(TimePoint)> tick, TimePoint until) {
        TimePoint wake = tick(loop.now);
        while (loop.now < until) {
            TimePoint rp = std::min(refl[0].obj->poll(loop.now), refl[1].obj->poll(loop.now));
            TimePoint next = std::min({wake, rp, loop.nextEvent(), until});
            if (next < loop.now) next = loop.now;
            loop.now = next;
            loop.runDue();
            refl[0].obj->poll(loop.now);
            refl[1].obj->poll(loop.now);
            wake = tick(loop.now);
            // The client is done and nothing is in flight. (The reflectors
            // always have a next partner check, so their timers do not count.)
            if (wake == TimePoint::max() && loop.empty()) break;
        }
    }

    EventLoop loop;
    Host host;
    NatModel nat;
    TimePoint& now = loop.now;
    std::vector<uint16_t> reflPorts[2];
    std::vector<StunServer> stun;
    bool r0FirstPortOnly = true;
    bool reflDown[2] = {false, false};
    uint64_t r0FirewallDrops = 0;
    const ReflectorStats& reflStats(int r) const { return refl[r].obj->stats(); }
    int& opened = host.opened;
    int& closed = host.closed;
    uint64_t& clientSent = host.sent;

private:
    struct RIo : IReflectorIo {
        Net* net = nullptr; int r = 0;
        void send(uint32_t pi, const Endpoint& to, const uint8_t* d, size_t len) override {
            Endpoint from{r == 0 ? kR0 : kR1, net->reflPorts[r][pi]};
            std::vector<uint8_t> data(d, d + len);
            net->loop.schedule(net->loop.now + kLatency, [n = net, from, to, data] { n->fromReflector(from, to, data); });
        }
    };
    struct R { RIo io; std::unique_ptr<Reflector> obj; };

    void toReflector(const Endpoint& src, const Endpoint& to, const std::vector<uint8_t>& d) {
        int r = to.ip == kR0 ? 0 : to.ip == kR1 ? 1 : -1;
        if (r < 0) {
            if (onStunRequest) onStunRequest(to, d);
            for (auto& sv : stun)
                if (sv.ep == to || (sv.altPort && to == Endpoint{sv.ep.ip, sv.altPort}))
                    if (auto a = sv.answer(src, d))
                        loop.schedule(loop.now + kLatency * 3, [this, from = to, src, data = *a] {
                            if (src.ip == host.publicIp()) host.ingress(from, src, data);
                        });
            return;
        }
        if (reflDown[r]) return;   // reflector switched off
        // Firewall of the deployment: R0 accepts clients on its first port only.
        if (r == 0 && r0FirstPortOnly && to.port != reflPorts[0][0] && src.ip != kR1) { ++r0FirewallDrops; return; }
        for (size_t i = 0; i < reflPorts[r].size(); ++i)
            if (reflPorts[r][i] == to.port) { refl[r].obj->onDatagram(uint32_t(i), src, d.data(), d.size(), loop.now); return; }
    }
    void fromReflector(const Endpoint& from, const Endpoint& to, const std::vector<uint8_t>& d) {
        if (to.ip == kR0 || to.ip == kR1) { toReflector(from, to, d); return; }
        if (to.ip == host.publicIp()) host.ingress(from, to, d);
    }

    R refl[2];
};

// Default deployment (option 1): clients reach R0 on one port only (the
// reflector still sends from its other sockets), R1 is the partner (no
// client traffic), the mapping pairs and the same-socket destinations are
// STUN servers.
inline DiscoveryConfig discoveryConfig(Net& net, SocketId primary) {
    DiscoveryConfig c;
    c.reflectors = {{kR0, {net.reflPorts[0][0]}}, {kR1, {}}};
    for (auto& sv : net.stun) c.stunServers.push_back({sv.ep, sv.altPort});
    c.primarySocket = primary;
    uint64_t s = 42;
    c.advanced.randomBytes = [s](uint8_t* out, size_t n) mutable {
        for (size_t i = 0; i < n; ++i) { s = s * 6364136223846793005ULL + 1442695040888963407ULL; out[i] = uint8_t(s >> 56); }
    };
    return c;
}

// --------------------------------------------------------------------------
// Two peers, each behind its own NAT, talking directly.
class Peers {
public:
    Peers(NatModel a, NatModel b, uint32_t seed) {
        a.publicIp = 0xCB007105;   // 203.0.113.5
        b.publicIp = 0xC6120A07;   // 198.18.10.7 (distinct operator)
        h[0] = std::make_unique<Host>(loop, a, seed);
        h[1] = std::make_unique<Host>(loop, b, seed + 1000);
        wire();
    }
    // Both peers behind the same NAT `m`, with inside addresses ipA and ipB.
    // sameLan: the inside addresses reach each other directly (same home
    // network, or a carrier that routes between its subscribers).
    Peers(NatModel m, uint32_t seed, uint32_t ipA, uint32_t ipB, bool sameLan) {
        auto box = std::make_shared<NatBox>(m, seed);
        h[0] = std::make_unique<Host>(loop, m, seed, box, ipA);
        h[1] = std::make_unique<Host>(loop, m, seed + 1000, box, ipB);
        wire();
        if (sameLan)
            for (auto& x : h)
                x->lan = [this](const Endpoint& src, const Endpoint& to, const std::vector<uint8_t>& d) {
                    for (auto& y : h)
                        if (y->localIp() == to.ip) {
                            Host* t = y.get();
                            loop.schedule(loop.now + kLatency, [t, src, to, d] { t->deliverLocal(src, to.port, d); });
                            return true;
                        }
                    return false;
                };
    }
    void wire() {
        for (int i = 0; i < 2; ++i)
            h[i]->egress = [this](const Endpoint& src, const Endpoint& to, std::vector<uint8_t> d, const Endpoint* fa) {
                for (auto& x : h) if (x->publicIp() == to.ip) x->ingress(src, to, d, fa);
            };
    }
    Host& operator[](int i) { return *h[i]; }

    void run(std::function<TimePoint(TimePoint)> tick, TimePoint until) {
        TimePoint wake = tick(loop.now);
        while (loop.now < until) {
            TimePoint next = std::min({wake, loop.nextEvent(), until});
            if (next < loop.now) next = loop.now;
            loop.now = next;
            loop.runDue();
            wake = tick(loop.now);
            if (wake == TimePoint::max() && loop.empty()) break;
        }
    }

    EventLoop loop;

private:
    std::unique_ptr<Host> h[2];
};

} // namespace sim
