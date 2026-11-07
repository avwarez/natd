// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// The transaction engine of natd (internal): probes to the natd reflector
// and STUN Binding transactions, with pacing, retransmission (RFC 8489
// §6.2.1, RFC 8085 §3.1.3), at most maxOutstanding transactions per server
// (RFC 8489 §6.2), RTT estimates per server, and the matching of answers.
// Used by NatDiscovery, QuickCheck and natd_stunlist; the rules are written
// here once.
#pragma once

#include "natd/discovery.hpp"
#include "natd/protocol.hpp"
#include "natd/stun.hpp"

#include <algorithm>
#include <cmath>
#include <deque>
#include <map>
#include <optional>
#include <vector>

namespace natd::detail {

enum class ProbeKind : uint8_t { Basic, Filter, LifeSingle, LifeBidir };

struct Probe {
    TxId      tx{};
    SocketId  sock = 0;
    Endpoint  dest;
    uint8_t   mask = proto::ReplySame;
    uint32_t  delayMs = 0;
    ProbeKind kind = ProbeKind::Basic;
    int       tag = 0;
    uint16_t  localPort = 0;
    bool      stun = false;   // STUN Binding to a public server (Basic only)
    // STUN probes carry two transactions (same socket, same server, hence
    // the same NAT mapping): an honest server reports the same endpoint
    // twice; different answers mark the server as a liar and the sample is
    // dropped. With one answer only (the other lost) the answer is kept.
    TxId      tx2{};
    std::optional<Endpoint> ans1, ans2;
    bool      fail1 = false, fail2 = false;   // transaction failed (error response, RFC 8489 §6.3.3-4)
    std::optional<Endpoint> otherAddr;        // STUN OTHER-ADDRESS / CHANGED-ADDRESS of the first answer
    std::optional<Duration> answeredAfter;    // first answer, since the first request
    bool      liar = false;
    Duration  rto0{0};        // RTO of the first request; doubled per resend
    int       weight = 0;     // transactions counted against maxOutstanding
    uint8_t   caps = 0;       // reflector capabilities declared in the Same reply (proto::Caps)
    int       sendsLeft = 1;
    int       sent = 0;
    bool      queued = false;
    bool      done = false;
    TimePoint firstSent{}, lastSent{}, retryAt{}, sameAt{};
    std::optional<Endpoint> same, other, partner, delayed;
    bool refused = false;   // reflector could not queue the delayed reply
};

// Sends probes with pacing and retransmission, matches responses by txId.
class ProbeEngine {
public:
    ProbeEngine(IDatagramIo& io, const AdvancedConfig& cfg, std::vector<uint32_t> reflectorIps)
        : io_(io), cfg_(cfg), ips_(std::move(reflectorIps)) {
        rnd_ = cfg_.randomBytes ? cfg_.randomBytes : defaultRandomBytes();
    }

    int addStun(SocketId s, const Endpoint& dest, int tag, uint16_t localPort = 0) {
        int i = add(s, dest, proto::ReplySame, 0, ProbeKind::Basic, tag, localPort);
        Probe& p = v_[i];
        p.stun = true;
        p.sendsLeft = std::max(1, cfg_.stunRc);
        do { rnd_(p.tx2.data(), p.tx2.size()); } while (byTx_.count(p.tx2));
        byTx_[p.tx2] = i;
        return i;
    }

    int add(SocketId s, const Endpoint& dest, uint8_t mask, uint32_t delayMs, ProbeKind kind, int tag,
            uint16_t localPort = 0) {
        Probe p;
        do { rnd_(p.tx.data(), p.tx.size()); } while (byTx_.count(p.tx));
        p.sock = s;
        p.dest = dest;
        p.mask = mask;
        p.delayMs = delayMs;
        p.kind = kind;
        p.tag = tag;
        p.localPort = localPort;
        // A retransmission would refresh an outbound-only binding and spoil
        // the single-packet lifetime measurement.
        p.sendsLeft = kind == ProbeKind::LifeSingle ? 1 : 1 + std::max(0, cfg_.probeRetries);
        p.queued = true;
        int idx = int(v_.size());
        byTx_[p.tx] = idx;
        v_.push_back(p);
        queue_.push_back(idx);
        return idx;
    }

    bool onDatagram(SocketId s, const Endpoint& from, const uint8_t* d, size_t len, TimePoint now) {
        if (stun::isStunPacket(d, len)) return onStun(s, from, d, len, now);
        if (proto::peekType(d, len) != proto::MsgType::ProbeResp) return false;
        auto r = proto::decodeProbeResp(d, len);
        if (!r) return false;
        auto it = byTx_.find(r->txId);
        if (it == byTx_.end()) return false;
        Probe& p = v_[it->second];
        // Only the socket that sent the probe, and only reflector addresses.
        if (p.stun || p.sock != s || std::find(ips_.begin(), ips_.end(), from.ip) == ips_.end()) return false;
        if (p.done) return true;
        switch (r->kind) {
        case proto::ReplyKind::Same:
            if (!p.same) {
                p.same = r->observed; p.sameAt = now; p.caps = r->caps;
                if (p.sent == 1) sampleRtt(p.dest.ip, std::chrono::duration_cast<Duration>(now - p.lastSent), now);
            }
            break;
        case proto::ReplyKind::OtherPort: if (!p.other) p.other = r->observed; break;
        case proto::ReplyKind::Partner:   if (!p.partner) p.partner = r->observed; break;
        case proto::ReplyKind::Delayed:   if (!p.delayed) p.delayed = r->observed; break;
        case proto::ReplyKind::Refused:   p.refused = true; break;
        }
        switch (p.kind) {
        case ProbeKind::Basic: if (p.same) finish(p); break;
        case ProbeKind::Filter: if (p.same && p.other && p.partner) finish(p); break;
        case ProbeKind::LifeSingle:
        case ProbeKind::LifeBidir: if (p.delayed || p.refused) finish(p); break;
        }
        if (p.done) pump(now);
        return true;
    }

    TimePoint poll(TimePoint now) {
        for (int i = 0; i < int(v_.size()); ++i) {
            Probe& p = v_[i];
            if (p.done || p.queued || p.sent == 0) continue;
            const bool canRetry = !p.same && p.sendsLeft > 0 && now >= p.retryAt;
            switch (p.kind) {
            case ProbeKind::Basic:
                if (canRetry) requeue(i);
                else if (!p.same && now >= p.retryAt) settle(p);
                break;
            case ProbeKind::Filter:
                if (p.same && now >= p.sameAt + cfg_.forwardGrace) finish(p);
                else if (canRetry) requeue(i);
                else if (!p.same && now >= p.retryAt) finish(p);
                break;
            case ProbeKind::LifeBidir:
                if (canRetry) { requeue(i); break; }
                [[fallthrough]];
            case ProbeKind::LifeSingle:
                if (now >= p.lastSent + Duration(p.delayMs) + cfg_.probeTimeout) finish(p);
                break;
            }
        }
        pump(now);
        TimePoint t = TimePoint::max();
        if (nextSendable() != queue_.end()) t = std::min(t, std::max(now, nextSlot_));
        for (const Probe& p : v_) {
            if (p.done || p.queued || p.sent == 0) continue;
            switch (p.kind) {
            case ProbeKind::Basic: t = std::min(t, p.retryAt); break;
            case ProbeKind::Filter:
                t = std::min(t, p.same ? p.sameAt + cfg_.forwardGrace : p.retryAt);
                break;
            case ProbeKind::LifeBidir:
                if (!p.same && p.sendsLeft > 0) t = std::min(t, p.retryAt);
                [[fallthrough]];
            case ProbeKind::LifeSingle:
                t = std::min(t, p.lastSent + Duration(p.delayMs) + cfg_.probeTimeout);
                break;
            }
        }
        return t;
    }

    // STUN answer: only from the server the probe went to, on its socket.
    bool onStun(SocketId s, const Endpoint& from, const uint8_t* d, size_t len, TimePoint now) {
        auto r = stun::decodeBinding(d, len);
        if (!r) return false;
        auto it = byTx_.find(r->txId);
        if (it == byTx_.end()) return false;
        Probe& p = v_[it->second];
        if (!p.stun || p.sock != s || from != p.dest) return false;
        if (p.done) return true;
        const bool first = r->txId == p.tx;
        if (r->success) {
            if (!p.answeredAfter) {
                p.answeredAfter = std::chrono::duration_cast<Duration>(now - p.firstSent);
                p.otherAddr = r->other;
            }
            (first ? p.ans1 : p.ans2) = r->mapped;
            if (p.sent == 1) sampleRtt(p.dest.ip, std::chrono::duration_cast<Duration>(now - p.lastSent), now);
        } else {
            (first ? p.fail1 : p.fail2) = true;
        }
        if (p.ans1 && p.ans2) {
            if (*p.ans1 == *p.ans2) { p.same = p.ans1; p.sameAt = now; }
            else p.liar = true;
            finish(p);
        } else if ((p.ans1 || p.fail1) && (p.ans2 || p.fail2)) {
            settle(p);   // one answer and one failure, or two failures
        }
        if (p.done) pump(now);
        return true;
    }

    // Sends what the pacing and the outstanding limit allow. FIFO: the send
    // order is the order the mappings are created in, which the allocation
    // samples rely on; a full server holds the queue. Also called when an
    // answer frees room, so that the next request does not wait for poll().
    // Resends never wait for room (their transaction is already counted).
    void pump(TimePoint now) {
        while (now >= nextSlot_) {
            auto it = nextSendable();
            if (it == queue_.end()) break;
            const int i = *it;
            queue_.erase(it);
            if (transmit(i, now)) nextSlot_ = now + cfg_.probeSpacing;
        }
    }
    // Queue entry that may go now: a resend, or the first new probe if its
    // server has room (new probes keep their order).
    std::deque<int>::iterator nextSendable() {
        bool firstNew = true;
        for (auto it = queue_.begin(); it != queue_.end(); ++it) {
            const Probe& p = v_[*it];
            if (p.done || p.sent > 0) return it;
            if (firstNew && fits(p)) return it;
            firstNew = false;
        }
        return queue_.end();
    }

    // Every probe still open is a STUN probe that made stunStaleAfter
    // requests without any answer (and nothing waits in the queue).
    bool onlyStale() const {
        for (const Probe& p : v_) {
            if (p.done) continue;
            if (!p.stun || p.sent < std::max(1, cfg_.stunStaleAfter) || p.ans1 || p.ans2) return false;
        }
        return true;
    }

    const std::vector<Probe>& probes() const { return v_; }
    void clear() { v_.clear(); byTx_.clear(); queue_.clear(); outstanding_.clear(); pending_ = 0; }

private:
    void finish(Probe& p) {
        if (p.done) return;
        p.done = true;
        if (p.sent > 0) --pending_;
        if (p.weight) {
            auto it = outstanding_.find(p.dest.ip);
            if (it != outstanding_.end() && (it->second -= p.weight) <= 0) outstanding_.erase(it);
            p.weight = 0;
        }
    }
    // A STUN probe without its two answers: one answer is kept (the other
    // was lost or failed), unless the two disagreed.
    void settle(Probe& p) {
        if (p.stun && !p.liar && (p.ans1 || p.ans2)) { p.same = p.ans1 ? p.ans1 : p.ans2; p.sameAt = p.lastSent; }
        finish(p);
    }
    void requeue(int i) { v_[i].queued = true; queue_.push_back(i); }

    int weightOf(const Probe& p) const { return p.delayMs ? 0 : p.stun ? 2 : 1; }
    bool fits(const Probe& p) const {
        const int w = weightOf(p);
        if (!w || cfg_.maxOutstanding <= 0) return true;
        auto it = outstanding_.find(p.dest.ip);
        const int used = it == outstanding_.end() ? 0 : it->second;
        return used == 0 || used + w <= cfg_.maxOutstanding;
    }

    // RFC 6298 with the RFC 8489 exceptions: RTO starts at cfg.rto, 1 ms
    // accuracy; samples only from requests sent once (Karn); the estimate is
    // kept for 10 minutes per server IP. It never goes below cfg.rto: a slow
    // server gets a longer RTO, a fast one does not get resends faster than
    // the initial value (fewer resends than RFC 6298 would allow).
    struct Rtt { double srtt = 0, rttvar = 0; TimePoint at{}; };
    std::map<uint32_t, Rtt> rtt_;
    static constexpr Duration kRttStale{600000};
    void sampleRtt(uint32_t ip, Duration r, TimePoint now) {
        const double ms = double(std::max<int64_t>(0, r.count()));
        auto it = rtt_.find(ip);
        if (it == rtt_.end() || now - it->second.at > kRttStale) {
            rtt_[ip] = {ms, ms / 2, now};
            return;
        }
        Rtt& e = it->second;
        e.rttvar = 0.75 * e.rttvar + 0.25 * std::abs(e.srtt - ms);
        e.srtt = 0.875 * e.srtt + 0.125 * ms;
        e.at = now;
    }
    Duration rtoFor(uint32_t ip, TimePoint now) const {
        auto it = rtt_.find(ip);
        if (it == rtt_.end() || now - it->second.at > kRttStale) return std::max(Duration(1), cfg_.rto);
        const double v = it->second.srtt + std::max(1.0, 4 * it->second.rttvar);
        return Duration(std::clamp<int64_t>(int64_t(v + 0.5), std::max<int64_t>(1, cfg_.rto.count()), 60000));
    }

    // Returns false when nothing was sent (the probe was over already).
    bool transmit(int i, TimePoint now) {
        Probe& p = v_[i];
        p.queued = false;
        if (p.done) return false;
        if (p.sent == 0) {   // counted once the probe is really out
            ++pending_;
            p.firstSent = now;
            p.rto0 = rtoFor(p.dest.ip, now);
            p.weight = weightOf(p);
            if (p.weight) outstanding_[p.dest.ip] += p.weight;
        }
        // Only the transactions still open are resent.
        if (!p.stun) {
            auto b = proto::encode(proto::ProbeReq{p.tx, p.mask, p.delayMs});
            io_.send(p.sock, p.dest, b.data(), b.size());
        } else {
            if (!p.ans1 && !p.fail1) {
                auto b = stun::encodeBindingRequest(p.tx);
                io_.send(p.sock, p.dest, b.data(), b.size());
            }
            if (!p.ans2 && !p.fail2) {
                auto b2 = stun::encodeBindingRequest(p.tx2);
                io_.send(p.sock, p.dest, b2.data(), b2.size());
            }
        }
        ++p.sent;
        --p.sendsLeft;
        p.lastSent = now;
        // Next resend after RTO x 2^(n-1); after the last request a STUN
        // transaction waits Rm x RTO, a reflector probe one more doubling.
        const int shift = std::min(p.sent - 1, 20);
        const Duration doubled = p.rto0 * (int64_t(1) << shift);
        p.retryAt = now + (p.sendsLeft > 0 || !p.stun ? doubled : p.rto0 * std::max(1, cfg_.stunRm));
        return true;
    }

    IDatagramIo& io_;
    AdvancedConfig cfg_;
    RandomBytesFn rnd_;
    std::vector<uint32_t> ips_;
    std::vector<Probe> v_;
    std::map<TxId, int> byTx_;
    std::deque<int> queue_;
    std::map<uint32_t, int> outstanding_;   // server IP -> open transactions
    TimePoint nextSlot_{};
    int pending_ = 0;

public:
    // True when nothing is queued and no sent probe is still open.
    bool idle() const { return pending_ == 0 && queue_.empty(); }
};

} // namespace natd::detail
