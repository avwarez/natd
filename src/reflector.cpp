// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/reflector.hpp"
#include "natd/protocol.hpp"

#include <algorithm>
#include <queue>
#include <unordered_map>

namespace natd {

struct Reflector::Impl {
    struct Bucket {
        double    tokens = 0;
        TimePoint last{};
        uint32_t  pending = 0;
    };
    struct Delayed {
        TimePoint due;
        uint32_t  portIndex;
        Endpoint  to;
        TxId      tx;
        bool operator>(const Delayed& o) const { return due > o.due; }
    };

    ReflectorConfig cfg;
    IReflectorIo& io;
    ReflectorStats st;
    std::unordered_map<uint32_t, Bucket> buckets;
    std::unordered_map<uint64_t, uint32_t> pendingByEp;   // (ip << 16 | port) -> queued delayed replies
    std::priority_queue<Delayed, std::vector<Delayed>, std::greater<Delayed>> delayed;

    Impl(ReflectorConfig c, IReflectorIo& i) : cfg(std::move(c)), io(i) {
        if (cfg.portCount == 0) cfg.portCount = 1;
        rnd = defaultRandomBytes();
    }

    // Partner check state
    RandomBytesFn rnd;
    TxId checkTx{};
    TimePoint nextCheck{}, lastPartnerAnswer{};
    bool partnerSeen = false;

    bool checking() const { return !cfg.partners.empty() && cfg.partnerCheckInterval.count() > 0; }
    bool partnerAlive(TimePoint now) const {
        return checking() && partnerSeen && now - lastPartnerAnswer < cfg.partnerTimeout;
    }
    uint8_t caps(TimePoint now) const {
        uint8_t c = proto::CapValid;
        if (cfg.portCount > 1) c |= proto::CapOtherPort;
        if (checking()) {
            c |= proto::CapPartnerChecked;
            if (partnerAlive(now)) c |= proto::CapPartnerAlive;
        }
        return c;
    }
    TimePoint now_{};   // time of the datagram or poll being handled

    bool allow(uint32_t ip, TimePoint now) {
        if (buckets.size() >= cfg.maxTrackedIps && !buckets.count(ip)) {
            // Evict idle buckets (no pending delayed replies)
            for (auto it = buckets.begin(); it != buckets.end();) {
                if (it->second.pending == 0) it = buckets.erase(it); else ++it;
            }
            if (buckets.size() >= cfg.maxTrackedIps) return false;
        }
        auto [it, fresh] = buckets.try_emplace(ip);
        Bucket& b = it->second;
        if (fresh) { b.tokens = cfg.burstPerIp; b.last = now; }
        double dt = std::chrono::duration<double>(now - b.last).count();
        if (dt > 0) b.tokens = std::min(cfg.burstPerIp, b.tokens + dt * cfg.ratePerIp);
        b.last = now;
        if (b.tokens < 1.0) return false;
        b.tokens -= 1.0;
        return true;
    }

    static uint64_t epKey(const Endpoint& e) { return (uint64_t(e.ip) << 16) | e.port; }

    bool isPartner(const Endpoint& from) const {
        for (auto& p : cfg.partners) if (p.ip == from.ip) return true;
        return false;
    }

    void reply(uint32_t portIndex, const Endpoint& to, const TxId& tx, proto::ReplyKind kind) {
        proto::ProbeResp r{tx, to, kind, caps(now_)};
        auto b = proto::encode(r);
        io.send(portIndex, to, b.data(), b.size());
        ++st.replies;
    }

    bool onDatagram(uint32_t portIndex, const Endpoint& from, const uint8_t* d, size_t len, TimePoint now) {
        auto type = proto::peekType(d, len);
        if (!type) return false;
        now_ = now;
        if (portIndex >= cfg.portCount || !from.valid()) { ++st.droppedInvalid; return true; }

        if (*type == proto::MsgType::ProbeReq) {
            auto req = proto::decodeProbeReq(d, len);
            if (!req) { ++st.droppedInvalid; return true; }
            ++st.requests;
            if (!allow(from.ip, now)) { ++st.droppedRate; return true; }

            if (req->mask & proto::ReplySame) reply(portIndex, from, req->txId, proto::ReplyKind::Same);
            if ((req->mask & proto::ReplyOtherPort) && cfg.portCount > 1)
                reply((portIndex + 1) % cfg.portCount, from, req->txId, proto::ReplyKind::OtherPort);
            if ((req->mask & proto::ReplyPartner) && !cfg.partners.empty()) {
                // Target is the observed source, never something from the payload.
                proto::ForwardReq f{req->txId, from};
                auto b = proto::encode(f);
                io.send(portIndex, cfg.partners.front(), b.data(), b.size());
                ++st.forwardsSent;
            }
            if (req->delayMs > 0) {
                auto& bk = buckets[from.ip];
                const uint64_t ek = epKey(from);
                auto pe = pendingByEp.find(ek);
                const uint32_t epPending = pe == pendingByEp.end() ? 0 : pe->second;
                if (req->delayMs > cfg.maxDelayMs || epPending >= cfg.maxPendingPerEndpoint ||
                    bk.pending >= cfg.maxPendingPerIp || delayed.size() >= cfg.maxPendingTotal) {
                    ++st.droppedPending;
                    ++st.refused;
                    reply(portIndex, from, req->txId, proto::ReplyKind::Refused);
                } else {
                    ++bk.pending;
                    ++pendingByEp[ek];
                    delayed.push({now + Duration(req->delayMs), portIndex, from, req->txId});
                }
            }
            return true;
        }

        if (*type == proto::MsgType::ForwardReq) {
            auto f = proto::decodeForwardReq(d, len);
            if (!f) { ++st.droppedInvalid; return true; }
            if (!isPartner(from)) { ++st.droppedNotPartner; return true; }
            if (!allow(f->target.ip, now)) { ++st.droppedRate; return true; }
            reply(portIndex, f->target, f->txId, proto::ReplyKind::Partner);
            ++st.forwardsServed;
            return true;
        }
        // Answer to our partner check.
        if (*type == proto::MsgType::ProbeResp) {
            auto r = proto::decodeProbeResp(d, len);
            if (r && isPartner(from) && r->txId == checkTx && checking()) {
                partnerSeen = true;
                lastPartnerAnswer = now;
                ++st.partnerAnswers;
            }
            return true;
        }
        // Other natd types (punches) are not for a reflector.
        return true;
    }

    TimePoint poll(TimePoint now) {
        now_ = now;
        if (checking() && now >= nextCheck) {
            rnd(checkTx.data(), checkTx.size());
            auto b = proto::encode(proto::ProbeReq{checkTx, proto::ReplySame, 0});
            io.send(0, cfg.partners.front(), b.data(), b.size());
            ++st.partnerChecks;
            nextCheck = now + cfg.partnerCheckInterval;
        }
        while (!delayed.empty() && delayed.top().due <= now) {
            Delayed x = delayed.top();
            delayed.pop();
            auto it = buckets.find(x.to.ip);
            if (it != buckets.end() && it->second.pending) --it->second.pending;
            auto pe = pendingByEp.find(epKey(x.to));
            if (pe != pendingByEp.end() && --pe->second == 0) pendingByEp.erase(pe);
            reply(x.portIndex, x.to, x.tx, proto::ReplyKind::Delayed);
        }
        TimePoint t = delayed.empty() ? TimePoint::max() : delayed.top().due;
        if (checking()) t = std::min(t, nextCheck);
        return t;
    }
};

Reflector::Reflector(ReflectorConfig cfg, IReflectorIo& io)
    : impl_(std::make_unique<Impl>(std::move(cfg), io)) {}
Reflector::~Reflector() = default;
bool Reflector::onDatagram(uint32_t p, const Endpoint& f, const uint8_t* d, size_t l, TimePoint n) {
    return impl_->onDatagram(p, f, d, l, n);
}
TimePoint Reflector::poll(TimePoint now) { return impl_->poll(now); }
const ReflectorStats& Reflector::stats() const { return impl_->st; }
bool Reflector::partnerAlive(TimePoint now) const { return impl_->partnerAlive(now); }

} // namespace natd
