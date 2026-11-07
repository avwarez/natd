// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd_probe — runs NatDiscovery and prints the profile.
//
//   natd_probe --bind 10.0.0.2 --port 4662
//              --reflector 198.51.100.10:3478 --reflector 198.51.100.11
//              --stun-list stun-servers.txt
//              [--stun host[:port]]... [--builtin-stun] [--stun-max 12]
//              [--grid 5,10,20] [--no-lifetime] [--timeout 300]
//
// --reflector options come in pairs (R0, R1), tried in order: the next pair
// is used when the previous R0 does not answer.
// The first --reflector of a pair is R0 (the ports clients send to: one is enough
// when the STUN list has two-port servers, entries with " alt=PORT"); the
// second is its partner R1, given by IP alone when clients must not contact
// it (option C) or with ports for the reflector-only deployment. STUN
// servers come from --stun, --stun-list files (one host[:port] per line,
// see natd_stunlist) and --builtin-stun, in that order; the first --stun-max
// that resolve are used.
//
// Output: one "key=value" line per stage (provisional, final). Exit 0 when a
// Final result was reached, 1 on timeout.
#include "natd/discovery.hpp"
#include "natd/platform_io.hpp"
#include "natd/stun.hpp"
#include "resolve.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace natd;

static void print(const char* stage, const NatProfile& p) {
    const auto& d = p.details;
    auto lt = [](const std::optional<Duration>& x) { return x ? long(x->count() / 1000) : -1L; };
    std::printf("%s predictability=%s public=%s mapping=%s filtering=%s behindNat=%d "
                "same=%s same.delta=%d same.conf=%.2f same.block=%u+%u same.fallback=%d "
                "new=%s new.delta=%d new.conf=%.2f new.block=%u+%u parity=%d multiIp=%d "
                "rate=%.1f lifetimeMeasured=%d single=%ld bidir=%ld atLeast=%d punch=%ld keepalive=%ld conf=%.2f "
                "hairpin=%s reflector=%d restarts=%d mapPortTested=%d partnerTested=%d portTested=%d\n",
                stage, toString(p.predictability), toString(p.publicEndpoint).c_str(), toString(d.mapping),
                toString(d.filtering), d.behindNat, toString(d.sameSocket.pattern), d.sameSocket.delta,
                d.sameSocket.confidence, d.sameSocket.block.base, d.sameSocket.block.size,
                d.sameSocketFromNewSocket, toString(d.newSocket.pattern), d.newSocket.delta, d.newSocket.confidence,
                d.newSocket.block.base, d.newSocket.block.size, d.parityPreserved, d.multiplePublicIps,
                d.allocationRate ? *d.allocationRate : -1.0, p.lifetimeMeasured, lt(d.singlePacketLifetime),
                lt(d.bidirectionalLifetime), d.lifetimeAtLeast, long(p.punchInterval.count() / 1000),
                long(p.keepaliveInterval.count() / 1000), p.confidence, toString(d.hairpin), d.reflectorReached,
                d.restarts, d.mappingPortTested, d.filteringPartnerTested, d.filteringPortTested);
    std::fflush(stdout);
}

int main(int argc, char** argv) {
    uint32_t bind = 0;
    uint16_t port = 0;
    int timeoutSec = 300;
    DiscoveryConfig cfg;
    std::vector<stun::ServerEntry> stunList;
    size_t stunMax = 12;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", k.c_str()); std::exit(2); }
            return argv[++i];
        };
        if (k == "--bind") { auto x = parseIp(val()); if (!x) return 2; bind = *x; }
        else if (k == "--port") port = uint16_t(std::strtoul(val().c_str(), nullptr, 10));
        else if (k == "--timeout") timeoutSec = std::atoi(val().c_str());
        else if (k == "--no-lifetime") cfg.measureLifetime = false;
        else if (k == "--grid") {
            cfg.advanced.lifetimeGridSec.clear();
            std::string g = val();
            for (size_t p = 0; p < g.size();) {
                size_t c = g.find(',', p);
                cfg.advanced.lifetimeGridSec.push_back(std::atoi(g.substr(p, c - p).c_str()));
                if (c == std::string::npos) break;
                p = c + 1;
            }
        } else if (k == "--reflector") {
            std::string v = val();
            auto colon = v.rfind(':');
            auto ip = parseIp(v.substr(0, colon));
            if (!ip) { std::fprintf(stderr, "bad --reflector %s\n", v.c_str()); return 2; }
            ReflectorInfo ri;
            ri.ip = *ip;
            if (colon != std::string::npos) {
                std::string r = v.substr(colon + 1);
                auto dash = r.find('-');
                unsigned long lo = std::strtoul(r.c_str(), nullptr, 10);
                unsigned long hi = dash == std::string::npos ? lo : std::strtoul(r.c_str() + dash + 1, nullptr, 10);
                for (unsigned long p = lo; p <= hi && p <= 65535; ++p) ri.ports.push_back(uint16_t(p));
            }
            cfg.reflectors.push_back(ri);
        } else if (k == "--stun") {
            auto l = stun::parseServerList(val());
            stunList.insert(stunList.end(), l.begin(), l.end());
        } else if (k == "--stun-list") {
            std::string path = val(), text;
            if (!examples::readFile(path, text)) { std::fprintf(stderr, "cannot read %s\n", path.c_str()); return 2; }
            auto l = stun::parseServerList(text);
            stunList.insert(stunList.end(), l.begin(), l.end());
        } else if (k == "--builtin-stun") {
            auto& l = stun::builtinServers();
            stunList.insert(stunList.end(), l.begin(), l.end());
        } else if (k == "--stun-max") {
            stunMax = size_t(std::strtoul(val().c_str(), nullptr, 10));
        } else { std::fprintf(stderr, "unknown option %s\n", k.c_str()); return 2; }
    }

    PlatformDatagramIo io(bind);
    {
        // A few two-port servers first (the mapping test's same-IP pair when
        // R0 has one port), then the list order.
        std::vector<stun::ServerEntry> ordered;
        for (auto& e : stunList) if (e.altPort && ordered.size() < 4) ordered.push_back(e);
        for (auto& e : stunList) if (std::find(ordered.begin(), ordered.end(), e) == ordered.end()) ordered.push_back(e);
        for (auto& r : examples::resolveServers(ordered, stunMax)) cfg.stunServers.push_back({r.ep, r.entry.altPort});
    }
    std::printf("stun %zu servers\n", cfg.stunServers.size());
    auto primary = io.openSocket(port);
    if (!primary) { std::fprintf(stderr, "cannot bind primary socket\n"); return 1; }
    cfg.primarySocket = *primary;
    {
        // Inside endpoint of the primary socket, for PeerInfo::localEndpoints.
        Endpoint le = io.localEndpoint(*primary);
        if (le.ip == 0 && !cfg.reflectors.empty()) le.ip = PlatformDatagramIo::localIpToward(cfg.reflectors[0].ip);
        std::printf("local %s\n", toString(le).c_str());
        std::fflush(stdout);
    }

    NatDiscovery disc(cfg, io);
    disc.start(Clock::now());
    uint32_t seen = 0;
    const TimePoint end = Clock::now() + std::chrono::seconds(timeoutSec);
    while (Clock::now() < end) {
        TimePoint next = disc.poll(Clock::now());
        if (disc.resultVersion() != seen) {
            seen = disc.resultVersion();
            print(disc.state() == DiscoveryState::Final ? "final" : "provisional", disc.result());
            if (disc.state() == DiscoveryState::Final) return 0;
        }
        io.wait(std::min(next, end), [&](SocketId s, const Endpoint& from, const uint8_t* d, size_t len) {
            disc.onDatagram(s, from, d, len, Clock::now());
        });
    }
    std::fprintf(stderr, "timeout\n");
    return 1;
}
