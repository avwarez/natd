// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd_reflector — runs the reflector role on N consecutive UDP ports.
//
//   natd_reflector --ip 198.51.100.10 --ports 3478-3479 --partner 198.51.100.11:3478   (R0)
//   natd_reflector --ip 198.51.100.11 --ports 3478 --partner 198.51.100.10:3478        (R1)
//
// With STUN servers as mirrors (DiscoveryConfig::stunServers, two-port ones
// included) clients send only to R0:3478. R0's second socket (3479) only
// sends the filtering test's "other port" reply, so the firewall may close
// it to inbound traffic; R1's firewall may accept UDP from R0 alone.
// Prints its counters on SIGINT/SIGTERM and exits.
#include "natd/platform_io.hpp"
#include "natd/reflector.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace natd;

static volatile std::sig_atomic_t g_stop = 0;
static void onSignal(int) { g_stop = 1; }

static bool parseRange(const std::string& s, uint16_t& lo, uint16_t& hi) {
    auto dash = s.find('-');
    unsigned long a = std::strtoul(s.c_str(), nullptr, 10);
    unsigned long b = dash == std::string::npos ? a : std::strtoul(s.c_str() + dash + 1, nullptr, 10);
    if (a == 0 || b < a || b > 65535) return false;
    lo = uint16_t(a); hi = uint16_t(b);
    return true;
}

int main(int argc, char** argv) {
    uint32_t ip = 0;
    uint16_t lo = 3478, hi = 3479;
    std::vector<Endpoint> partners;
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string k = argv[i], v = argv[i + 1];
        if (k == "--ip") { auto x = parseIp(v); if (!x) { std::fprintf(stderr, "bad --ip\n"); return 2; } ip = *x; }
        else if (k == "--ports") { if (!parseRange(v, lo, hi)) { std::fprintf(stderr, "bad --ports\n"); return 2; } }
        else if (k == "--partner") { auto e = parseEndpoint(v); if (!e) { std::fprintf(stderr, "bad --partner\n"); return 2; } partners.push_back(*e); }
        else { std::fprintf(stderr, "unknown option %s\n", k.c_str()); return 2; }
    }

    PlatformDatagramIo io(ip);
    std::vector<SocketId> socks;
    for (uint32_t p = lo; p <= hi; ++p) {
        auto s = io.openSocket(uint16_t(p));
        if (!s) { std::fprintf(stderr, "cannot bind port %u\n", p); return 1; }
        socks.push_back(*s);
    }

    struct Io : IReflectorIo {
        PlatformDatagramIo* io; std::vector<SocketId>* socks;
        void send(uint32_t pi, const Endpoint& to, const uint8_t* d, size_t len) override {
            io->send((*socks)[pi], to, d, len);
        }
    } rio;
    rio.io = &io;
    rio.socks = &socks;

    ReflectorConfig rc;
    rc.portCount = uint32_t(socks.size());
    rc.partners = partners;
    Reflector refl(rc, rio);

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::printf("reflector %s ports %u-%u partners %zu ready\n", toString(Endpoint{ip, lo}).c_str(), lo, hi,
                partners.size());
    std::fflush(stdout);

    TimePoint next = TimePoint::max();
    while (!g_stop) {
        io.wait(next, [&](SocketId s, const Endpoint& from, const uint8_t* d, size_t len) {
            uint32_t pi = uint32_t(s - socks.front());   // ids are consecutive from openSocket
            refl.onDatagram(pi, from, d, len, Clock::now());
        });
        next = refl.poll(Clock::now());
    }
    const auto& st = refl.stats();
    std::printf("requests=%llu replies=%llu forwardsSent=%llu forwardsServed=%llu droppedRate=%llu "
                "droppedInvalid=%llu droppedNotPartner=%llu refused=%llu partnerChecks=%llu partnerAnswers=%llu\n",
                (unsigned long long)st.requests, (unsigned long long)st.replies,
                (unsigned long long)st.forwardsSent, (unsigned long long)st.forwardsServed,
                (unsigned long long)st.droppedRate, (unsigned long long)st.droppedInvalid,
                (unsigned long long)st.droppedNotPartner, (unsigned long long)st.refused,
                (unsigned long long)st.partnerChecks, (unsigned long long)st.partnerAnswers);
    return 0;
}
