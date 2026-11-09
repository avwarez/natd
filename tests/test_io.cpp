// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// Platform adapter tests: PlatformDatagramIo on the loopback interface, and the
// STUN name resolver (dotted addresses and localhost only: no DNS needed).
// Same file on Linux (POSIX), Windows and Wine (Winsock). Exit 0 = passed.
#include "natd/platform_io.hpp"
#include "natd/resolve.hpp"

#include <thread>

#include <cstdio>
#include <cstring>
#include <vector>

using namespace natd;

static int g_fail = 0, g_checks = 0;
#define CHECK(c)                                                                         \
    do {                                                                                 \
        ++g_checks;                                                                      \
        if (!(c)) { ++g_fail; std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } \
    } while (0)

constexpr uint32_t kLo = 0x7F000001;   // 127.0.0.1

struct Rx { SocketId s; Endpoint from; std::vector<uint8_t> d; };

static std::vector<Rx> pump(PlatformDatagramIo& io, int ms, size_t want) {
    std::vector<Rx> got;
    TimePoint end = Clock::now() + Duration(ms);
    while (Clock::now() < end && got.size() < want)
        io.wait(end, [&](SocketId s, const Endpoint& f, const uint8_t* d, size_t n) {
            got.push_back({s, f, std::vector<uint8_t>(d, d + n)});
        });
    return got;
}

int main() {
    PlatformDatagramIo io(kLo);

    // Open, local endpoint
    auto a = io.openSocket(0), b = io.openSocket(0);
    CHECK(a && b);
    if (!a || !b) return 1;
    Endpoint ea = io.localEndpoint(*a), eb = io.localEndpoint(*b);
    CHECK(ea.ip == kLo && ea.port != 0);
    CHECK(eb.ip == kLo && eb.port != 0 && eb.port != ea.port);

    // A port in use cannot be bound again (exclusive bind on Windows)
    CHECK(!io.openSocket(ea.port));

    // Round trip, source address reported correctly
    const uint8_t msg[5] = {'h', 'e', 'l', 'l', 'o'};
    CHECK(io.send(*a, eb, msg, sizeof msg));
    auto got = pump(io, 1000, 1);
    CHECK(got.size() == 1);
    if (!got.empty()) {
        CHECK(got[0].s == *b);
        CHECK(got[0].from == ea);
        CHECK(got[0].d.size() == 5 && std::memcmp(got[0].d.data(), msg, 5) == 0);
    }

    // ICMP port unreachable: send to a port nobody listens on, then make sure
    // the same socket still receives (Windows: WSAECONNRESET, SIO_UDP_CONNRESET).
    auto c = io.openSocket(0);
    CHECK(c.has_value());
    Endpoint closed = io.localEndpoint(*c);
    io.closeSocket(*c);
    for (int i = 0; i < 3; ++i) io.send(*a, closed, msg, sizeof msg);
    pump(io, 200, 1000);   // let any error report arrive and be consumed
    CHECK(io.send(*b, ea, msg, sizeof msg));
    got = pump(io, 1000, 1);
    CHECK(got.size() == 1 && got[0].s == *a);

    // Several datagrams queued on one socket are all delivered in one wait
    for (int i = 0; i < 20; ++i) io.send(*b, ea, msg, sizeof msg);
    got = pump(io, 1000, 20);
    CHECK(got.size() == 20);

    // Closing a socket from inside the callback is safe
    for (int i = 0; i < 5; ++i) io.send(*b, ea, msg, sizeof msg);
    int seen = 0;
    TimePoint end = Clock::now() + Duration(300);
    while (Clock::now() < end)
        io.wait(end, [&](SocketId s, const Endpoint&, const uint8_t*, size_t) {
            ++seen;
            if (s == *a) io.closeSocket(*a);
        });
    CHECK(seen == 1);
    CHECK(!io.send(*a, eb, msg, sizeof msg));   // closed
    CHECK(io.socketCount() == 1);

    // wait() honours its deadline when nothing arrives
    TimePoint t0 = Clock::now();
    int n = io.wait(t0 + Duration(150), [](SocketId, const Endpoint&, const uint8_t*, size_t) {});
    auto el = std::chrono::duration_cast<Duration>(Clock::now() - t0).count();
    CHECK(n == 0);
    CHECK(el >= 100 && el < 1200);

    // Name resolution: dotted and localhost, order kept, duplicates and
    // names that do not resolve skipped, max honoured; the resolver thread
    CHECK(resolveIpv4("1.2.3.4") == 0x01020304);
    CHECK(resolveIpv4("localhost") == kLo);
    CHECK(resolveIpv4("no-such-host.invalid") == 0);
    const std::vector<stun::ServerEntry> list = {{"1.2.3.4", 3478, 3479}, {"no-such-host.invalid", 3478, 0},
                                                 {"1.2.3.4", 3478, 0}, {"localhost", 19302, 0}, {"5.6.7.8", 3478, 0}};
    const std::vector<StunEndpoint> r = resolveStunServers(list);
    CHECK(r.size() == 3);
    if (r.size() == 3) {
        CHECK(r[0].ep == (Endpoint{0x01020304, 3478}) && r[0].altPort == 3479);
        CHECK(r[1].ep == (Endpoint{kLo, 19302}) && r[2].ep == (Endpoint{0x05060708, 3478}));
    }
    CHECK(resolveStunServers(list, 2).size() == 2);
    {
        StunResolver res(list);
        for (int i = 0; i < 500 && !res.ready(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        CHECK(res.ready());
        const std::vector<StunEndpoint> rs = res.servers();
        CHECK(rs.size() == r.size() && (rs.empty() || rs[0].ep == r[0].ep));
    }
    {
        StunResolver gone(list);   // destroyed at once: never waits for its thread
    }

    std::printf("%d checks, %d failed\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
