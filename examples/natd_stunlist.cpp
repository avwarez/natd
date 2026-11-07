// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd_stunlist — checks a list of public STUN servers and keeps the good ones.
//
//   natd_stunlist [--in raw.txt] [--out stun-servers.txt] [--keep 24] [--min 10]
//                 [--pairs 4] [--rto 500]
//
// Reads "host[:port]" lines (default: the built-in list), resolves each host
// (first IPv4), sends Binding requests from one socket and keeps the servers
// that answer
//   - from exactly the address they were sent to, and
//   - with the mapped address most servers agree on (a server reporting
//     another one is wrong or lying),
//   - with the same endpoint to two requests from the same socket, and, when
//     at least 80% of the servers report the same port (endpoint-independent
//     mapping on this network), with that port.
// For each survivor it also looks for a second port on the same IP that
// answers (the announced OTHER-ADDRESS/CHANGED-ADDRESS port, then port+1 and
// 3479) and writes it as " alt=PORT": with a single-port reflector these
// servers provide the mapping test's same-IP, other-port pair.
// Written: the fastest --pairs two-port servers first, then the fastest of
// the rest, at most --keep in total. With fewer than --min survivors, or no
// two-port server at all, nothing is written and the exit code is 1, so a
// failed refresh never replaces a good list.
//
// Typical refresh (tools/update-stun-list.sh, .cmd): download a public list,
// e.g. https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt,
// then run this tool on it.
#include "natd/platform_io.hpp"
#include "natd/stun.hpp"
#include "resolve.hpp"
#include "../src/probe_engine.hpp"   // natd's transaction engine (internal header, in-tree tool)

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <map>
#include <string>

using namespace natd;
using namespace natd::examples;

int main(int argc, char** argv) {
    std::string in, out;
    size_t keep = 24, minGood = 10, minPairs = 4;
    int rtoMs = 500;   // RFC 8489 §6.2.1: initial RTO >= 500 ms
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", k.c_str()); std::exit(2); }
            return argv[++i];
        };
        if (k == "--in") in = val();
        else if (k == "--out") out = val();
        else if (k == "--keep") keep = size_t(std::strtoul(val().c_str(), nullptr, 10));
        else if (k == "--min") minGood = size_t(std::strtoul(val().c_str(), nullptr, 10));
        else if (k == "--pairs") minPairs = size_t(std::strtoul(val().c_str(), nullptr, 10));
        else if (k == "--rto") rtoMs = std::max(500, std::atoi(val().c_str()));
        else { std::fprintf(stderr, "unknown option %s\n", k.c_str()); return 2; }
    }

    PlatformDatagramIo io;   // starts Winsock before name resolution on Windows
    std::vector<stun::ServerEntry> list = stun::builtinServers();
    if (!in.empty()) {
        std::string text;
        if (!readFile(in, text)) { std::fprintf(stderr, "cannot read %s\n", in.c_str()); return 2; }
        list = stun::parseServerList(text);
    }
    auto servers = resolveServers(list);
    std::printf("%zu entries, %zu resolved\n", list.size(), servers.size());
    auto sock = io.openSocket(0);
    if (!sock) { std::fprintf(stderr, "cannot open a socket\n"); return 1; }

    struct Result { std::optional<Endpoint> mapped, other; Duration rtt{}; bool liar = false; };
    // Binding requests to every destination from one socket, through natd's
    // own transaction engine (src/probe_engine.hpp): retransmission as RFC
    // 8489 §6.2.1 asks (RTO from --rto, doubling, Rc = 7, Rm = 16), error
    // responses ending a transaction at once, at most 10 transactions per
    // server. Two transactions per destination: same socket and server, hence
    // the same mapping, so an honest server reports the same endpoint twice.
    AdvancedConfig ac;
    ac.rto = Duration(rtoMs);
    ac.probeSpacing = Duration(2);
    auto probeAll = [&](const std::vector<Endpoint>& dests) {
        detail::ProbeEngine eng(io, ac, {});
        for (size_t i = 0; i < dests.size(); ++i) eng.addStun(*sock, dests[i], int(i));
        auto rx = [&](SocketId s, const Endpoint& from, const uint8_t* d, size_t len) {
            eng.onDatagram(s, from, d, len, Clock::now());
        };
        for (;;) {
            const TimePoint next = eng.poll(Clock::now());
            if (eng.idle()) break;
            io.wait(std::min(next, Clock::now() + Duration(1000)), rx);
        }
        std::vector<Result> res(dests.size());
        for (const auto& p : eng.probes()) {
            Result& x = res[size_t(p.tag)];
            x.mapped = p.same ? p.same : p.ans1 ? p.ans1 : p.ans2;
            x.other = p.otherAddr;
            if (p.answeredAfter) x.rtt = *p.answeredAfter;
            x.liar = p.liar;
        }
        return res;
    };

    std::vector<Endpoint> eps;
    for (auto& sv : servers) eps.push_back(sv.ep);
    auto probes = probeAll(eps);

    std::map<uint32_t, int> votes;
    for (auto& p : probes) if (p.mapped) ++votes[p.mapped->ip];
    uint32_t mine = 0;
    int best = 0;
    for (auto& [ip, n] : votes) if (n > best) { best = n; mine = ip; }

    // From a network with endpoint-independent mapping (most home routers)
    // every honest server reports the same port too: when at least 80% agree,
    // the others are wrong.
    std::map<uint16_t, int> portVotes;
    int withMine = 0;
    for (auto& p : probes)
        if (p.mapped && p.mapped->ip == mine && !p.liar) { ++portVotes[p.mapped->port]; ++withMine; }
    uint16_t commonPort = 0;
    for (auto& [port, n] : portVotes)
        if (withMine >= 5 && n * 5 >= withMine * 4) commonPort = port;

    std::vector<size_t> good;
    int silent = 0, wrong = 0, wrongPort = 0;
    for (size_t i = 0; i < servers.size(); ++i) {
        if (!probes[i].mapped) ++silent;
        else if (probes[i].mapped->ip != mine) ++wrong;
        else if (probes[i].liar || (commonPort && probes[i].mapped->port != commonPort)) ++wrongPort;
        else good.push_back(i);
    }
    std::printf("port check: %s\n", commonPort ? "endpoint-independent mapping here, ports compared"
                                               : "mapping varies here, only the double query applies");

    // Second port on the same IP: the one given in the input, the announced
    // alternate (OTHER-ADDRESS / CHANGED-ADDRESS) when it is on the same IP,
    // then port+1 and 3479. The
    // first one answering with the right address is kept as altPort.
    std::vector<Endpoint> altDests;
    std::vector<std::pair<size_t, size_t>> altOf;   // (server, index in altDests)
    for (size_t i : good) {
        std::vector<uint16_t> cand;
        if (servers[i].entry.altPort) cand.push_back(servers[i].entry.altPort);   // from the input: verified too
        servers[i].entry.altPort = 0;
        const auto& o = probes[i].other;
        if (o && o->ip == servers[i].ep.ip) cand.push_back(o->port);
        cand.push_back(uint16_t(servers[i].ep.port + 1));
        cand.push_back(3479);
        for (uint16_t c : cand) {
            if (c == 0 || c == servers[i].ep.port) continue;
            bool dup = false;
            for (auto& [srv, k] : altOf) dup |= srv == i && altDests[k].port == c;
            if (dup) continue;
            altOf.push_back({i, altDests.size()});
            altDests.push_back({servers[i].ep.ip, c});
        }
    }
    auto alts = probeAll(altDests);
    for (auto& [i, k] : altOf)
        if (!servers[i].entry.altPort && alts[k].mapped && alts[k].mapped->ip == mine && !alts[k].liar &&
            (!commonPort || alts[k].mapped->port == commonPort))
            servers[i].entry.altPort = altDests[k].port;

    std::sort(good.begin(), good.end(), [&](size_t a, size_t b) { return probes[a].rtt < probes[b].rtt; });
    size_t pairsTotal = 0;
    for (size_t i : good) pairsTotal += servers[i].entry.altPort != 0;
    std::printf("answered %zu, silent %d, wrong mapped address %d, wrong port %d, two ports on the same IP %zu, "
                "public IP %s\n",
                good.size() + size_t(wrong + wrongPort), silent, wrong, wrongPort, pairsTotal,
                mine ? toString(Endpoint{mine, 0}).c_str() : "?");
    const size_t goodTotal = good.size();
    // Kept: the fastest minPairs two-port servers first (the mapping test
    // needs one when the reflector has a single port), then the fastest of
    // the rest, keep in total.
    std::vector<size_t> kept;
    for (size_t i : good) if (servers[i].entry.altPort && kept.size() < minPairs) kept.push_back(i);
    for (size_t i : good)
        if (kept.size() < keep && std::find(kept.begin(), kept.end(), i) == kept.end()) kept.push_back(i);
    good = kept;
    size_t pairsKept = 0;
    for (size_t i : good) {
        pairsKept += servers[i].entry.altPort != 0;
        std::printf("  %-34s %-21s %4lld ms%s\n", (servers[i].entry.host + ":" + std::to_string(servers[i].entry.port)).c_str(),
                    toString(servers[i].ep).c_str(), (long long)probes[i].rtt.count(),
                    servers[i].entry.altPort ? (" alt=" + std::to_string(servers[i].entry.altPort)).c_str() : "");
    }
    if (pairsKept < std::min<size_t>(minPairs, 1)) {
        std::fprintf(stderr, "no server answering on two ports: list not written\n");
        return 1;
    }
    if (good.size() < minGood) {
        std::fprintf(stderr, "only %zu good servers (minimum %zu): list not written\n", good.size(), minGood);
        return 1;
    }
    if (!out.empty()) {
        std::vector<stun::ServerEntry> entries;
        for (size_t i : good) entries.push_back(servers[i].entry);   // two-port servers first
        const std::string tmp = out + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            std::time_t t = std::time(nullptr);
            char date[32];
            std::strftime(date, sizeof date, "%Y-%m-%d %H:%M UTC", std::gmtime(&t));
            f << "# natd STUN servers, checked " << date << ": " << goodTotal << " of " << list.size()
              << " entries answered correctly (" << pairsTotal << " on two ports), " << entries.size() << " kept\n"
              << stun::formatServerList(entries);
            if (!f) { std::fprintf(stderr, "cannot write %s\n", tmp.c_str()); return 1; }
        }
        std::remove(out.c_str());
        if (std::rename(tmp.c_str(), out.c_str()) != 0) { std::fprintf(stderr, "cannot write %s\n", out.c_str()); return 1; }
        std::printf("wrote %zu servers to %s\n", entries.size(), out.c_str());
    }
    return 0;
}
