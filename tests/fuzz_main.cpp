// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd_fuzz — robustness of natd against hostile datagrams.
//
// Six targets, each fed with a byte string:
//   decoders   every decoder and parser on the raw bytes; what decodes must
//              encode back to bytes that decode to the same thing
//   reflector  a script of datagrams from clients, a partner and strangers;
//              per source IP the reflector never sends more bytes than it
//              received (anti-amplification), and only to sources, partners
//              or targets named by a partner
//   punch      a script of datagrams towards a punch session (right and wrong
//              token, ACKs, other IPs, garbage, an obfuscated variant); it
//              sends only to the remote IP, at most maxPackets punches, and
//              no more ACKs than datagrams received from the remote IP
//   stream     a script of STREAM datagrams with the right token and hostile
//              KCP payloads (random, or real segments mutated), with writes,
//              reads and close; poll() never keeps answering "now"
//   discovery  a NAT discovery (and a QuickCheck) whose requests are answered
//              with hostile responses (right transaction id, any content),
//              garbage and strangers; it never holds more sockets than its
//              cap and closes all of them when destroyed
//   agent      an Agent (STUN-only discovery, then sessions) driven by a
//              script of application calls (connect, accept, write, read,
//              release, endpoint checks) and of datagrams (punches, ACKs and
//              STREAM messages with right or wrong tokens, STUN answers that
//              move the endpoint, garbage); events name only sessions the
//              application holds, each Closed comes once and nothing after
//              it, the caps hold, it sends only to STUN servers and to the
//              peers it was given, poll() does not keep answering "now", and
//              every session and socket is gone at the end
//
// No coverage guidance (the Pi has no compiler-rt for libFuzzer): each input
// is random bytes interpreted as a script, so that most steps build
// well-formed messages with hostile fields. Build with UBSan and
// _GLIBCXX_ASSERTIONS (cmake -DNATD_FUZZ=ON adds both); any undefined
// behaviour, out-of-range access or broken invariant aborts.
//
//   natd_fuzz [target|all] [iterations] [seed]   random inputs
//   natd_fuzz target --replay ITER SEED          one input again
//   natd_fuzz target FILE                        one input from a file
#include "natd/natd.hpp"
#include "natd/protocol.hpp"
#include "natd/stun.hpp"
#include "kcp_transport.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <random>
#include <set>
#include <string>

using namespace natd;

namespace {

// The input being run, for the replay command printed on a failure.
const char* g_target = "";
long g_iter = -1;
unsigned long long g_seed = 0;

void printReplay() {
    if (g_iter >= 0)
        std::fprintf(stderr, "replay: natd_fuzz %s --replay %ld %llu\n", g_target, g_iter, g_seed);
}

extern "C" void onSignal(int sig) {
    printReplay();
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

[[noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "INVARIANT BROKEN: %s\n", what);
    std::abort();
}
#define REQUIRE(c) do { if (!(c)) fail(#c); } while (0)

// Reads the input as a script; past the end it yields zeros.
struct Script {
    const uint8_t* p;
    size_t n, i = 0;
    bool done() const { return i >= n; }
    uint8_t u8() { return i < n ? p[i++] : 0; }
    uint16_t u16() { return uint16_t(u8() << 8 | u8()); }
    uint32_t u32() { return uint32_t(u16()) << 16 | u16(); }
    std::vector<uint8_t> bytes(size_t max) {
        size_t len = std::min<size_t>(u8() | size_t(u8() & 0x07) << 8, max);
        len = std::min(len, n - std::min(n, i));
        std::vector<uint8_t> b(p + i, p + i + len);
        i += len;
        return b;
    }
};

void mutate(std::vector<uint8_t>& b, Script& s) {
    for (int k = s.u8() % 4; k > 0; --k) {
        const uint8_t op = s.u8() % 5;
        const size_t at = b.empty() ? 0 : s.u16() % b.size();
        switch (op) {
        case 0: if (!b.empty()) b[at] ^= uint8_t(1u << (s.u8() % 8)); break;
        case 1: if (!b.empty()) b[at] = s.u8(); break;
        case 2: b.insert(b.begin() + long(at), s.u8()); break;
        case 3: if (!b.empty()) b.erase(b.begin() + long(at)); break;
        case 4: b.resize(at); break;
        }
    }
}

TxId txIdFrom(Script& s) {
    TxId t{};
    for (auto& x : t) x = s.u8();
    return t;
}

// A socket layer that records what the library sends.
struct FakeIo : IDatagramIo {
    struct Sent { SocketId sock; Endpoint to; std::vector<uint8_t> data; };
    std::set<SocketId> open{1};   // 1: the caller's primary socket
    SocketId next = 2;
    size_t maxOpen = 1;
    std::vector<Sent> sent;
    std::optional<SocketId> openSocket(uint16_t) override {
        open.insert(next);
        maxOpen = std::max(maxOpen, open.size());
        return next++;
    }
    void closeSocket(SocketId s) override { open.erase(s); }
    Endpoint localEndpoint(SocketId s) const override { return {0x0A000002, uint16_t(40000 + s)}; }
    bool send(SocketId s, const Endpoint& to, const uint8_t* d, size_t len) override {
        if (!open.count(s)) fail("send on a socket that is not open");
        sent.push_back({s, to, std::vector<uint8_t>(d, d + len)});
        return true;
    }
};

// A stand-in obfuscator: one marker byte, then the datagram XORed.
struct XorObfuscator : IDatagramObfuscator {
    std::vector<uint8_t> wrap(const uint8_t* d, size_t n) override {
        std::vector<uint8_t> o(n + 1);
        o[0] = 0xA5;
        for (size_t i = 0; i < n; ++i) o[i + 1] = d[i] ^ 0x5A;
        return o;
    }
    bool unwrap(const uint8_t* d, size_t n, std::vector<uint8_t>& out) override {
        if (n < 1 || d[0] != 0xA5) return false;
        out.resize(n - 1);
        for (size_t i = 1; i < n; ++i) out[i - 1] = d[i] ^ 0x5A;
        return true;
    }
};

std::vector<uint8_t> stunResponse(const TxId& tx, const Endpoint& mapped, Script& s) {
    std::vector<uint8_t> b;
    auto put16 = [&](uint16_t v) { b.push_back(uint8_t(v >> 8)); b.push_back(uint8_t(v)); };
    auto put32 = [&](uint32_t v) { put16(uint16_t(v >> 16)); put16(uint16_t(v)); };
    put16(0x0101);
    put16(0);
    put32(stun::kMagicCookie);
    b.insert(b.end(), tx.begin(), tx.end());
    const uint8_t attrs = s.u8() % 4;
    for (uint8_t k = 0; k <= attrs; ++k) {
        const uint8_t which = s.u8() % 4;
        if (which == 0 || k == 0) {   // XOR-MAPPED-ADDRESS
            put16(0x0020); put16(8); b.push_back(0); b.push_back(1);
            put16(uint16_t(mapped.port ^ (stun::kMagicCookie >> 16)));
            put32(mapped.ip ^ stun::kMagicCookie);
        } else if (which == 1) {      // MAPPED-ADDRESS
            put16(0x0001); put16(8); b.push_back(0); b.push_back(s.u8() % 3);
            put16(s.u16()); put32(s.u32());
        } else if (which == 2) {      // OTHER-ADDRESS
            put16(0x802C); put16(8); b.push_back(0); b.push_back(1);
            put16(s.u16()); put32(s.u32());
        } else {                      // anything
            auto v = s.bytes(40);
            put16(s.u16()); put16(uint16_t(v.size()));
            b.insert(b.end(), v.begin(), v.end());
            while (b.size() % 4) b.push_back(0);
        }
    }
    const uint16_t len = uint16_t(b.size() - 20);
    b[2] = uint8_t(len >> 8);
    b[3] = uint8_t(len);
    return b;
}

// --------------------------------------------------------------------------
void fuzzDecoders(const uint8_t* d, size_t n) {
    using namespace proto;
    isNatdPacket(d, n);
    peekType(d, n);
    stun::isStunPacket(d, n);
    if (auto m = decodeProbeReq(d, n)) {
        auto e = encode(*m);
        auto m2 = decodeProbeReq(e.data(), e.size());
        REQUIRE(m2 && m2->txId == m->txId && m2->mask == m->mask && m2->delayMs == m->delayMs);
    }
    if (auto m = decodeProbeResp(d, n)) {
        auto e = encode(*m);
        auto m2 = decodeProbeResp(e.data(), e.size());
        REQUIRE(m2 && m2->txId == m->txId && m2->observed == m->observed && m2->kind == m->kind && m2->caps == m->caps);
    }
    if (auto m = decodeForwardReq(d, n)) {
        auto e = encode(*m);
        auto m2 = decodeForwardReq(e.data(), e.size());
        REQUIRE(m2 && m2->txId == m->txId && m2->target == m->target);
    }
    if (auto m = decodePunch(d, n)) {
        auto e = encode(*m);
        auto m2 = decodePunch(e.data(), e.size());
        REQUIRE(m2 && m2->token == m->token && m2->ack == m->ack);
    }
    if (auto m = decodeStream(d, n)) {
        REQUIRE(m->len <= kMaxStreamPayload);
        REQUIRE(m->len == 0 || (m->payload >= d && m->payload + m->len <= d + n));
        auto e = encodeStream(m->token, m->flags, m->payload, m->len);
        auto m2 = decodeStream(e.data(), e.size());
        REQUIRE(m2 && m2->token == m->token && m2->flags == m->flags && m2->len == m->len &&
                std::equal(m->payload, m->payload + m->len, m2->payload));
    }
    if (auto r = stun::decodeBindingResponse(d, n)) (void)r->mapped.valid();
    if (auto pi = decodePeerInfo(d, n)) {
        REQUIRE(pi->localEndpoints.size() <= kMaxLocalEndpoints);
        auto e = encodePeerInfo(*pi);
        auto pi2 = decodePeerInfo(e.data(), e.size());
        REQUIRE(pi2);
        const auto e2 = encodePeerInfo(*pi2);
        if (e2 != e)
            for (size_t k = 0; k < std::min(e.size(), e2.size()); ++k)
                if (e[k] != e2[k]) { std::fprintf(stderr, "PeerInfo re-encoding differs at byte %zu\n", k); break; }
        REQUIRE(e2 == e);   // re-encoding is stable
    }
    const std::string text(reinterpret_cast<const char*>(d), n);
    for (auto& e : stun::parseServerList(text)) {
        REQUIRE(!e.host.empty() && e.port != 0);
        auto again = stun::parseServerList(stun::formatServerList({e}));
        if (!(again.size() == 1 && again[0] == e))
            std::fprintf(stderr, "entry host=[%s] port=%u alt=%u; formatted [%s]\n", e.host.c_str(), e.port, e.altPort,
                         stun::formatServerList({e}).c_str());
        REQUIRE(again.size() == 1 && again[0] == e);
    }
    parseEndpoint(text);
    parseIp(text);
}

// --------------------------------------------------------------------------
struct RecIo : IReflectorIo {
    std::vector<std::pair<Endpoint, size_t>> sent;
    void send(uint32_t port, const Endpoint& to, const uint8_t*, size_t len) override {
        if (port > 1) fail("reflector sent from a port it does not have");
        sent.push_back({to, len});
    }
};

void fuzzReflector(const uint8_t* d, size_t n) {
    Script s{d, n};
    const Endpoint partner{0xC6336402, 3478};
    ReflectorConfig cfg;
    cfg.portCount = 2;
    cfg.partners = {partner};
    cfg.ratePerIp = 50 + s.u8();
    cfg.burstPerIp = 10 + s.u8();
    cfg.maxPendingPerEndpoint = 1 + s.u8() % 4;
    cfg.maxPendingPerIp = 1 + s.u8() % 16;
    cfg.maxPendingTotal = 1 + s.u8() % 64;
    RecIo io;
    Reflector r(cfg, io);
    TimePoint now = TimePoint{} + std::chrono::hours(1);
    const Endpoint clients[4] = {{0x0A000001, 5000}, {0x0A000001, 5001}, {0x0B000001, 7000}, {0x64400001, 9000}};
    std::map<uint32_t, uint64_t> in, out;
    std::set<uint32_t> forwardTargets;
    std::set<Endpoint, bool (*)(const Endpoint&, const Endpoint&)> seen(
        [](const Endpoint& a, const Endpoint& b) { return a.ip != b.ip ? a.ip < b.ip : a.port < b.port; });
    auto account = [&] {
        for (auto& [to, len] : io.sent) {
            if (to.ip == partner.ip) continue;
            if (!seen.count(to) && !forwardTargets.count(to.ip)) fail("reflector sent to an endpoint that never wrote to it");
            out[to.ip] += len;
        }
        io.sent.clear();
    };
    while (!s.done()) {
        const uint8_t op = s.u8();
        const uint8_t who = s.u8() % 6;
        Endpoint from = who < 4 ? clients[who] : who == 4 ? partner : Endpoint{s.u32(), s.u16()};
        std::vector<uint8_t> dg;
        switch (op % 6) {
        case 0: case 1: {
            proto::ProbeReq q;
            q.txId = txIdFrom(s);
            q.mask = s.u8() & 0x07;
            q.delayMs = s.u8() & 1 ? s.u32() % 400000 : 0;
            dg = proto::encode(q);
            break;
        }
        case 2: {
            proto::ForwardReq f;
            f.txId = txIdFrom(s);
            f.target = {s.u32(), s.u16()};
            dg = proto::encode(f);
            break;
        }
        case 3: {
            proto::ProbeResp p;
            p.txId = txIdFrom(s);
            p.observed = {s.u32(), s.u16()};
            dg = proto::encode(p);
            break;
        }
        case 4: dg = s.bytes(256); break;
        case 5: now += Duration(s.u16() * 10); break;
        }
        if (op & 0x80) mutate(dg, s);
        if (!dg.empty()) {
            // The reflector knows its partner by IP (any port).
            if (from.ip == partner.ip) {
                if (auto f = proto::decodeForwardReq(dg.data(), dg.size())) forwardTargets.insert(f->target.ip);
            } else {
                in[from.ip] += dg.size();
                seen.insert(from);
            }
            r.onDatagram(s.u8() % 2, from, dg.data(), dg.size(), now);
        }
        now = std::max(now, std::min(r.poll(now), now + Duration(s.u8() * 20)));
        r.poll(now);
        account();
    }
    now += std::chrono::minutes(10);   // every delayed reply goes out
    for (int k = 0; k < 2000 && r.poll(now) <= now; ++k) {}
    r.poll(now);
    account();
    for (auto& [ip, bytes] : out)
        if (!forwardTargets.count(ip) && bytes > in[ip]) fail("reflector sent more bytes to an IP than it received from it");
}

// --------------------------------------------------------------------------
void fuzzPunch(const uint8_t* d, size_t n) {
    Script s{d, n};
    FakeIo io;
    NatProfile stable;
    stable.predictability = Predictability::Stable;
    stable.publicEndpoint = {0x5A000001, 4672};
    stable.details.mapping = MappingBehavior::EndpointIndependent;
    const Endpoint remote{0x5B000001, uint16_t(1024 + s.u16() % 60000)};
    PunchLimits lim;
    lim.maxPackets = 1 + s.u8() * 4;
    PunchSessionConfig c;
    c.plan = planDirect(stable, remote, lim);
    REQUIRE(c.plan.strategy == PunchStrategy::Direct);
    c.token = txIdFrom(s);
    TimePoint now = TimePoint{} + std::chrono::hours(1);
    c.startAt = now + Duration(s.u8() * 10);
    c.remoteIp = remote.ip;
    c.primarySocket = 1;
    const bool obf = s.u8() & 1;
    if (obf) c.obfuscator = std::make_shared<XorObfuscator>();
    XorObfuscator x;
    PunchSession ps(c, io);
    uint64_t fromRemote = 0;
    while (!s.done()) {
        const uint8_t op = s.u8();
        Endpoint from = op & 0x40 ? Endpoint{s.u32(), s.u16()} : Endpoint{remote.ip, uint16_t(op & 0x20 ? s.u16() : remote.port)};
        std::vector<uint8_t> dg;
        switch (op % 5) {
        case 0: case 1: {
            proto::Punch p;
            p.token = op & 0x10 ? txIdFrom(s) : c.token;
            p.ack = s.u8() & 1;
            dg = proto::encode(p);
            break;
        }
        case 2: dg = proto::encodeStream(c.token, s.u8(), nullptr, 0); break;
        case 3: dg = s.bytes(300); break;
        case 4: now += Duration(s.u16()); break;
        }
        if (op & 0x80) mutate(dg, s);
        if (obf && !dg.empty() && (s.u8() & 3)) dg = x.wrap(dg.data(), dg.size());
        if (!dg.empty()) {
            if (from.ip == remote.ip) ++fromRemote;
            ps.onDatagram(s.u8() & 7 ? 1 : 2, from, dg.data(), dg.size(), now);
        }
        TimePoint next = ps.poll(now);
        if (next <= now) next = ps.poll(now);
        now = std::max(now, std::min(next, now + Duration(s.u8() * 50)));
    }
    for (int k = 0; k < 100; ++k) {   // let the session run out
        now += Duration(1000);
        ps.poll(now);
    }
    uint64_t punches = 0, acks = 0;
    for (auto& m : io.sent) {
        if (m.to.ip != remote.ip) fail("punch sent to another IP than the remote one");
        std::vector<uint8_t> plain = m.data;
        if (obf) REQUIRE(x.unwrap(m.data.data(), m.data.size(), plain));
        auto p = proto::decodePunch(plain.data(), plain.size());
        if (!p) continue;
        REQUIRE(p->token == c.token);
        (p->ack ? acks : punches) += 1;
    }
    if (punches > uint64_t(c.plan.maxPackets)) fail("more punches than maxPackets");
    if (acks > fromRemote) fail("more ACKs than datagrams from the remote IP");
}

// --------------------------------------------------------------------------
void fuzzStream(const uint8_t* d, size_t n) {
    Script s{d, n};
    FakeIo io, peerIo;
    const Endpoint remote{0x5B000001, 5000};
    TimePoint now = TimePoint{} + std::chrono::hours(1);
    StreamConfig sc;
    sc.socket = 1;
    sc.remote = remote;
    sc.token = txIdFrom(s);
    sc.keepalive = Duration(1000 + s.u16() % 20000);
    sc.maxPayload = 200 + s.u16() % 1200;
    const auto kcp = test::kcpFactory(1 + s.u8());
    Stream st(sc, kcp, io, now);
    // A well-behaved peer whose segments are mutated on their way in.
    StreamConfig pc = sc;
    pc.remote = {0x5A000001, 4672};
    Stream peer(pc, kcp, peerIo, now);
    std::vector<uint8_t> buf(70000);
    int nowStreak = 0;
    while (!s.done()) {
        const uint8_t op = s.u8();
        std::vector<uint8_t> dg;
        switch (op % 8) {
        case 0: case 1: {   // a real segment from the peer, maybe mutated
            const size_t w = s.u16() % 5000;
            std::vector<uint8_t> data(w, uint8_t(op));
            peer.write(data.data(), data.size(), now);
            peer.poll(now);
            if (peerIo.sent.empty()) break;
            dg = peerIo.sent[s.u8() % peerIo.sent.size()].data;
            if (peerIo.sent.size() > 64) peerIo.sent.erase(peerIo.sent.begin(), peerIo.sent.begin() + 32);
            break;
        }
        case 2: {   // a STREAM message with a hostile KCP payload
            auto pl = s.bytes(proto::kMaxStreamPayload);
            dg = proto::encodeStream(sc.token, s.u8() & 0x03, pl.data(), pl.size());
            break;
        }
        case 3: dg = s.bytes(1500); break;
        case 4: {
            const size_t w = s.u16();
            std::vector<uint8_t> data(w, 0x33);
            st.write(data.data(), data.size(), now);
            break;
        }
        case 5: {
            const size_t got = st.read(buf.data(), s.u16() % buf.size());
            REQUIRE(got <= buf.size());
            break;
        }
        case 6: if (s.u8() < 16) st.close(now); break;
        case 7: now += Duration(s.u16()); break;
        }
        if (op & 0x80) mutate(dg, s);
        if (!dg.empty()) {
            Endpoint from = op & 0x40 ? Endpoint{s.u32(), s.u16()} : remote;
            st.onDatagram(s.u8() & 7 ? 1 : 2, from, dg.data(), dg.size(), now);
        }
        // The answers of our stream reach the peer, so that its window moves.
        for (auto& m : io.sent) peer.onDatagram(1, remote, m.data.data(), m.data.size(), now);
        io.sent.clear();
        const TimePoint next = st.poll(now);
        nowStreak = next <= now ? nowStreak + 1 : 0;
        if (nowStreak > 3) fail("Stream::poll keeps answering now (a caller would spin)");
        now = std::max(now, std::min(next, now + Duration(s.u8() * 10)));
        REQUIRE(st.readable() <= size_t(1) << 26);
    }
}

// --------------------------------------------------------------------------
template <class Engine>
void answerHostile(Engine& e, FakeIo& io, Script& s, TimePoint& now, const Endpoint& publicEp) {
    size_t answered = 0;
    while (!s.done()) {
        const uint8_t op = s.u8();
        if (op % 6 == 5) { now += Duration(s.u16() % 5000); }
        else if (!io.sent.empty()) {
            const auto& q = io.sent[(answered + s.u8()) % io.sent.size()];
            ++answered;
            std::vector<uint8_t> dg;
            Endpoint from = q.to;
            // the mapped endpoint: usually plausible, sometimes anything
            Endpoint mapped = op & 0x10 ? Endpoint{s.u32(), s.u16()}
                                        : Endpoint{publicEp.ip, uint16_t(publicEp.port + (op & 0x20 ? s.u8() : 0))};
            if (q.data.size() >= 20 && proto::isNatdPacket(q.data.data(), q.data.size())) {
                proto::ProbeResp r;
                std::copy(q.data.begin() + 8, q.data.begin() + 20, r.txId.begin());
                r.observed = mapped;
                r.kind = proto::ReplyKind(s.u8() % 6);
                r.caps = s.u8();
                dg = proto::encode(r);
                if (r.kind == proto::ReplyKind::Partner) from = {0xC6336402, from.port};
                if (r.kind == proto::ReplyKind::OtherPort) from.port = uint16_t(from.port + 1);
            } else if (q.data.size() >= 20) {
                TxId tx{};
                std::copy(q.data.begin() + 8, q.data.begin() + 20, tx.begin());
                dg = stunResponse(tx, mapped, s);
            }
            if (op & 0x80) mutate(dg, s);
            if (op & 0x40) from = {s.u32(), s.u16()};
            if (!dg.empty()) e.onDatagram(q.sock, from, dg.data(), dg.size(), now);
        }
        if (op % 7 == 6) {   // garbage on a random socket
            auto g = s.bytes(200);
            e.onDatagram(SocketId(1 + s.u8() % 8), Endpoint{s.u32(), s.u16()}, g.data(), g.size(), now);
        }
        const TimePoint next = e.poll(now);
        now = std::max(now, std::min(next, now + Duration(s.u8() * 20)));
        if (io.sent.size() > 4096) io.sent.erase(io.sent.begin(), io.sent.begin() + 2048);
    }
}

void fuzzDiscovery(const uint8_t* d, size_t n) {
    Script s{d, n};
    DiscoveryConfig cfg;
    cfg.reflectors = {{0xC6336401, {3478, 3479}}, {0xC6336402, {3478}}};
    cfg.stunServers = {{{0xC0000A0A, 3478}, 3479}, {{0xC0000A0B, 3478}, 0}, {{0xC0000A0C, 19302}, 0}};
    if (s.u8() & 1) cfg.reflectors.clear();   // STUN-only discovery
    cfg.primarySocket = 1;
    cfg.measureLifetime = s.u8() & 1;
    cfg.advanced.maxMappings = 4 + s.u8() % 100;
    uint32_t seed = s.u32();
    cfg.advanced.randomBytes = [seed](uint8_t* out, size_t len) mutable {
        for (size_t i = 0; i < len; ++i) { seed = seed * 1103515245u + 12345u; out[i] = uint8_t(seed >> 16); }
    };
    const Endpoint publicEp{0x5A000001, uint16_t(1024 + s.u16() % 60000)};
    FakeIo io;
    TimePoint now = TimePoint{} + std::chrono::hours(1);
    const bool quick = s.u8() < 64;
    {
        if (!quick) {
            NatDiscovery disc(cfg, io);
            disc.start(now);
            answerHostile(disc, io, s, now, publicEp);
            for (int k = 0; k < 600; ++k) { now += Duration(1000); disc.poll(now); }
            (void)disc.result();
        } else {
            NatProfile expected;
            expected.predictability = Predictability::Stable;
            expected.publicEndpoint = publicEp;
            QuickCheck qc(cfg, expected, io);
            qc.start(now);
            answerHostile(qc, io, s, now, publicEp);
            for (int k = 0; k < 120; ++k) { now += Duration(1000); qc.poll(now); }
            (void)qc.result();
        }
    }
    // The cap counts mappings; sockets are a subset of them (plus the primary).
    if (io.maxOpen > size_t(cfg.advanced.maxMappings) + 2) fail("discovery held more sockets than maxMappings");
    if (io.open.size() != 1) fail("discovery left sockets open after it was destroyed");
}


// What the agent target reached, printed after its run (an input that never
// gets a profile tests little).
struct { uint64_t inputs = 0, ready = 0, sessions = 0, open = 0, closed = 0; } g_agentReach;

void fuzzAgent(const uint8_t* d, size_t n) {
    ++g_agentReach.inputs;
    Script s{d, n};
    FakeIo io;
    AgentConfig cfg;
    const std::vector<StunEndpoint> stunServers = {{{0xC0000A0A, 3478}, 3479}, {{0xC0000A0B, 3478}, 3479},
                                                   {{0xC0000A0C, 19302}, 0}};
    cfg.discovery.stunServers = stunServers;
    cfg.discovery.primarySocket = 1;
    cfg.discovery.measureLifetime = false;
    uint32_t seed = s.u32();
    auto rnd = [seed](uint8_t* out, size_t len) mutable {
        for (size_t i = 0; i < len; ++i) { seed = seed * 1103515245u + 12345u; out[i] = uint8_t(seed >> 16); }
    };
    cfg.discovery.advanced.randomBytes = rnd;
    cfg.randomBytes = rnd;
    cfg.maxPunches = 1 + s.u8() % 4;
    cfg.maxWaiting = s.u8() % 4;
    cfg.maxSessions = 1 + s.u8() % 8;
    cfg.punchWait = Duration(100 + s.u16() % 20000);
    cfg.linger = Duration(s.u16() % 20000);
    cfg.checkReuse = Duration(s.u16() % 120000);
    std::set<uint32_t> allowed;   // where it may send
    for (auto& sv : stunServers) allowed.insert(sv.ep.ip);
    Endpoint publicEp{0x5A000001, uint16_t(1024 + s.u16() % 60000)};
    TimePoint now = TimePoint{} + std::chrono::hours(1);
    struct Held { bool incoming; Endpoint remote; TxId token; bool closed = false; bool open = false; };
    std::map<SessionId, Held> held;   // the application's sessions (not released)
    std::set<SessionId> released;
    std::vector<Endpoint> peers = {{0x5B000001, 4672}, {0x5B000002, 4672}, {0x5C000003, 50000}};
    {
        Agent agent(cfg, io, test::kcpFactory());
        agent.start(now);
        size_t answered = 0;   // io.sent entries already looked at
        // honest STUN answers, from the mapping the script chooses
        auto answerStun = [&](bool all) {
            for (; answered < io.sent.size(); ++answered) {
                const auto q = io.sent[answered];
                if (q.data.size() < 20 || !stun::isStunPacket(q.data.data(), q.data.size()) || !(all || (s.u8() & 1))) continue;
                TxId tx{};
                std::copy(q.data.begin() + 8, q.data.begin() + 20, tx.begin());
                Script plain{nullptr, 0};
                auto dg = stunResponse(tx, publicEp, plain);
                agent.onDatagram(q.sock, q.to, dg.data(), dg.size(), now);
            }
        };
        auto drain = [&] {
            AgentEvent e;
            while (agent.nextEvent(e)) {
                if (e.type == AgentEventType::ProfileReady || e.type == AgentEventType::EndpointChanged ||
                    e.type == AgentEventType::EndpointChecked) {
                    REQUIRE(e.session == 0);
                    continue;
                }
                if (released.count(e.session)) fail("event for a released session");
                auto it = held.find(e.session);
                if (it == held.end()) fail("event for a session the application never got");
                Held& h = it->second;
                if (h.closed) fail("event after Closed");
                switch (e.type) {
                case AgentEventType::Connected: REQUIRE(!h.incoming && !h.open); h.open = true; ++g_agentReach.open; break;
                case AgentEventType::Incoming:  REQUIRE(h.incoming && !h.open); h.open = true; ++g_agentReach.open; break;
                case AgentEventType::Readable:
                case AgentEventType::Writable:  REQUIRE(h.open); break;
                case AgentEventType::Closed:    h.closed = true; ++g_agentReach.closed; break;
                default: break;
                }
            }
        };
        int spins = 0;
        auto step = [&] {
            const TimePoint next = agent.poll(now);
            drain();
            if (next <= now) { if (++spins > 50) fail("poll() keeps answering now"); }
            else spins = 0;
            now = std::max(now, std::min(next, now + Duration(s.u8() * 20)));
            if (agent.sessionCount() > cfg.maxSessions) fail("more sessions than maxSessions");
            size_t punching = 0;
            for (auto& [id, h] : held) punching += agent.phase(id) == SessionPhase::Punching;
            if (punching > cfg.maxPunches) fail("more punch sessions than maxPunches");
        };
        for (int k = 0; k < 400 && !agent.profileReady(); ++k) {
            answerStun(true);
            now += Duration(50);
            step();
        }
        if (agent.profileReady()) ++g_agentReach.ready;
        while (!s.done()) {
            const uint8_t op = s.u8();
            auto pick = [&]() -> SessionId {
                if (held.empty()) return SessionId(s.u8());
                auto it = held.begin();
                std::advance(it, long(s.u8() % held.size()));
                return it->first;
            };
            switch (op % 12) {
            case 0: case 1: {   // connect / accept towards a peer
                Endpoint r = peers[s.u8() % peers.size()];
                if (s.u8() < 32) r = Endpoint{s.u32(), s.u16()};
                const TxId tok = txIdFrom(s);
                const bool inc = op % 12 == 1;
                const SessionId id = inc ? agent.accept(r, tok, now) : agent.connect(r, tok, now);
                if (id) {
                    if (held.count(id) || released.count(id)) fail("a session id given twice");
                    held[id] = Held{inc, r, tok};
                    ++g_agentReach.sessions;
                    allowed.insert(r.ip);
                }
                break;
            }
            case 2: case 3: {   // a punch or an ACK from a session's peer, or a stranger
                SessionId id = pick();
                auto it = held.find(id);
                proto::Punch p;
                p.token = it != held.end() && (s.u8() & 3) ? it->second.token : txIdFrom(s);
                p.ack = s.u8() & 1;
                auto dg = proto::encode(p);
                Endpoint from = it != held.end() && (s.u8() & 3) ? it->second.remote : Endpoint{s.u32(), s.u16()};
                if (op & 0x80) mutate(dg, s);
                agent.onDatagram(s.u8() & 7 ? 1 : SocketId(2 + s.u8() % 4), from, dg.data(), dg.size(), now);
                break;
            }
            case 4: {   // a STREAM message with hostile payload
                SessionId id = pick();
                auto it = held.find(id);
                const TxId tok = it != held.end() && (s.u8() & 3) ? it->second.token : txIdFrom(s);
                auto pl = s.bytes(1400);
                auto dg = proto::encodeStream(tok, s.u8() & 0x03, pl.data(), pl.size());
                Endpoint from = it != held.end() ? agent.remote(id) : Endpoint{s.u32(), s.u16()};
                if (!from.valid()) from = Endpoint{s.u32(), s.u16()};
                agent.onDatagram(1, from, dg.data(), dg.size(), now);
                break;
            }
            case 5: {   // the application writes
                auto b = s.bytes(4000);
                agent.write(pick(), b.data(), b.size(), now);
                break;
            }
            case 6: {   // reads
                uint8_t buf[2048];
                agent.read(pick(), buf, s.u8() % 2 ? sizeof buf : size_t(s.u8()));
                break;
            }
            case 7: {   // releases
                const SessionId id = pick();
                if (held.count(id)) { held.erase(id); released.insert(id); }
                agent.release(id, now);
                break;
            }
            case 8:   // the endpoint may have changed
                if (s.u8() < 64) publicEp.port = uint16_t(1024 + s.u16() % 60000);
                agent.checkEndpoint(now, s.u8() & 1);
                break;
            case 9: answerStun(false); break;
            case 10: {   // garbage
                auto g = s.bytes(300);
                agent.onDatagram(SocketId(1 + s.u8() % 6), Endpoint{s.u32(), s.u16()}, g.data(), g.size(), now);
                break;
            }
            case 11: now += Duration(s.u16()); break;
            }
            step();
            if (io.sent.size() > 8192) { io.sent.erase(io.sent.begin(), io.sent.begin() + 4096); answered = std::min(answered, io.sent.size()); }
        }
        for (auto& m : io.sent)
            if (!allowed.count(m.to.ip)) fail("sent to an address that is neither a STUN server nor a peer");
        // the application lets everything go: after the linger nothing is left
        for (auto& [id, h] : held) agent.release(id, now);
        held.clear();
        for (int k = 0; k < 200; ++k) { now += Duration(500); agent.poll(now); drain(); }
        if (agent.sessionCount() != 0) fail("sessions left after release and linger");
    }
    if (io.open.size() != 1) fail("the agent left sockets open after it was destroyed");
}

// --------------------------------------------------------------------------
struct Target { const char* name; void (*fn)(const uint8_t*, size_t); size_t maxLen; int defaultIters; };
const Target kTargets[] = {
    {"decoders", fuzzDecoders, 600, 200000},
    {"reflector", fuzzReflector, 3000, 5000},
    {"punch", fuzzPunch, 3000, 5000},
    {"stream", fuzzStream, 4000, 3000},
    {"discovery", fuzzDiscovery, 4000, 2000},
    {"agent", fuzzAgent, 4000, 2000},
};

// Seeds for the decoders: valid messages of every kind, mutated by the driver.
std::vector<std::vector<uint8_t>> decoderSeeds() {
    std::vector<std::vector<uint8_t>> v;
    TxId t{};
    for (size_t i = 0; i < t.size(); ++i) t[i] = uint8_t(i * 17);
    v.push_back(proto::encode(proto::ProbeReq{t, 7, 1000}));
    v.push_back(proto::encode(proto::ProbeResp{t, {0x01020304, 5000}, proto::ReplyKind::Partner, 0x87}));
    v.push_back(proto::encode(proto::ForwardReq{t, {0x01020304, 5000}}));
    v.push_back(proto::encode(proto::Punch{t, true}));
    const uint8_t pl[5] = {1, 2, 3, 4, 5};
    v.push_back(proto::encodeStream(t, 0, pl, sizeof pl));
    v.push_back(stun::encodeBindingRequest(t));
    std::vector<uint8_t> none;
    Script empty{nullptr, 0};
    v.push_back(stunResponse(t, {0x01020304, 5000}, empty));
    PeerInfo pi;
    pi.profile.predictability = Predictability::Bounded;
    pi.observed = {0x01020304, 5000};
    pi.localEndpoints = {{0x0A000001, 4000}, {0x64400001, 4001}};
    v.push_back(encodePeerInfo(pi));
    const std::string list = "stun.example.org:3478 alt=3479\nstun:1.2.3.4\n# c\n[::1]:3478\nhost:0\n";
    v.push_back(std::vector<uint8_t>(list.begin(), list.end()));
    return v;
}

std::vector<uint8_t> makeInput(const Target& t, std::mt19937_64& rng) {
    static const auto seeds = decoderSeeds();
    std::vector<uint8_t> in;
    if (t.fn == fuzzDecoders && rng() % 4) {
        in = seeds[rng() % seeds.size()];
        std::vector<uint8_t> m(64);
        for (auto& b : m) b = uint8_t(rng());
        Script s{m.data(), m.size()};
        mutate(in, s);
        return in;
    }
    in.resize(rng() % t.maxLen);
    for (auto& b : in) b = uint8_t(rng());
    return in;
}

int runRandom(const Target& t, long iters, uint64_t seed, long only = -1) {
    for (long i = only >= 0 ? only : 0; i < (only >= 0 ? only + 1 : iters); ++i) {
        g_target = t.name;
        g_iter = i;
        g_seed = seed;
        std::mt19937_64 rng(seed * 1000003u + uint64_t(i));
        const auto in = makeInput(t, rng);
        t.fn(in.data(), in.size());
        if (only < 0 && (i + 1) % std::max(1L, iters / 4) == 0)
            std::printf("  %-9s %ld/%ld\n", t.name, i + 1, iters), std::fflush(stdout);
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGABRT, onSignal);
    std::signal(SIGSEGV, onSignal);
    const std::string which = argc > 1 ? argv[1] : "all";
    if (argc > 2 && std::strcmp(argv[2], "--replay") == 0 && argc > 4) {
        for (auto& t : kTargets)
            if (which == t.name) return runRandom(t, 0, std::strtoull(argv[4], nullptr, 10), std::atol(argv[3]));
        return 2;
    }
    if (argc > 2 && !std::isdigit(static_cast<unsigned char>(argv[2][0]))) {
        std::ifstream f(argv[2], std::ios::binary);
        std::vector<uint8_t> in((std::istreambuf_iterator<char>(f)), {});
        for (auto& t : kTargets)
            if (which == t.name) { t.fn(in.data(), in.size()); return 0; }
        return 2;
    }
    const long mult = argc > 2 ? std::atol(argv[2]) : 1;
    const uint64_t seed = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 1;
    for (auto& t : kTargets) {
        if (which != "all" && which != t.name) continue;
        std::printf("%s (seed %llu)\n", t.name, (unsigned long long)seed);
        std::fflush(stdout);
        runRandom(t, long(t.defaultIters) * std::max(1L, mult), seed);
        if (t.fn == fuzzAgent)
            std::printf("  agent reached: %llu inputs, %llu with a profile, %llu sessions, %llu open, %llu closed\n",
                        (unsigned long long)g_agentReach.inputs, (unsigned long long)g_agentReach.ready,
                        (unsigned long long)g_agentReach.sessions, (unsigned long long)g_agentReach.open,
                        (unsigned long long)g_agentReach.closed);
    }
    std::printf("fuzz: no failure\n");
    return 0;
}
