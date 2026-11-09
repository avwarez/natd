// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/stream.hpp"
#include "natd/protocol.hpp"

#include <algorithm>

namespace natd {

const char* toString(StreamState s) {
    switch (s) {
    case StreamState::Open: return "Open";
    case StreamState::Closing: return "Closing";
    case StreamState::Closed: return "Closed";
    case StreamState::Dead: return "Dead";
    }
    return "?";
}

struct Stream::Impl {
    StreamConfig cfg;
    IDatagramIo& io;
    std::unique_ptr<IStreamTransport> tr;
    TimePoint now, lastSent, lastHeard;
    StreamState st = StreamState::Open;
    bool peerFin = false;
    StreamStats stats;
    Duration jitter{0};   // extra wait before the next keepalive

    Impl(StreamConfig c, IDatagramIo& i, TimePoint t) : cfg(std::move(c)), io(i), now(t), lastSent(t), lastHeard(t) {
        if (!cfg.randomBytes) cfg.randomBytes = defaultRandomBytes();
        cfg.maxPayload = std::clamp<size_t>(cfg.maxPayload, 1, proto::kMaxStreamPayload);
        drawJitter();
    }

    void drawJitter() {
        uint32_t r = 0;
        cfg.randomBytes(reinterpret_cast<uint8_t*>(&r), sizeof r);
        const int64_t span = cfg.keepalive.count() / 10;
        jitter = Duration(span > 0 ? int64_t(r % uint32_t(span + 1)) : 0);
    }
    TimePoint keepaliveAt() const { return lastSent + cfg.keepalive + jitter; }
    TimePoint deadAt() const { return lastHeard + cfg.keepalive * cfg.deadAfter; }

    void send(uint8_t flags, const uint8_t* p, size_t len) {
        if (len > cfg.maxPayload) return;   // a transport bug: never more than it was told
        auto b = proto::encodeStream(cfg.token, flags, p, len);
        if (cfg.obfuscator) b = cfg.obfuscator->wrap(b.data(), b.size());
        io.send(cfg.socket, cfg.remote, b.data(), b.size());
        ++stats.datagramsOut;
        lastSent = now;
    }

    bool alive() const { return st == StreamState::Open || st == StreamState::Closing; }
};

TransportSet chooseTransport(TransportSet ours, TransportSet theirs) {
    const unsigned common = ours & (theirs ? theirs : kFirstTransport);
    for (int b = 7; b >= 0; --b)
        if (common & (1u << b)) return TransportSet(1u << b);
    return 0;
}

Stream::Stream(StreamConfig cfg, const StreamTransportFactory& transport, IDatagramIo& io, TimePoint now)
    : impl_(std::make_unique<Impl>(std::move(cfg), io, now)) {
    Impl& m = *impl_;
    if (transport) {
        StreamTransportInfo info;
        info.transport = m.cfg.transport;
        info.token = m.cfg.token;
        info.maxPayload = m.cfg.maxPayload;
        info.now = now;
        Impl* self = impl_.get();
        info.output = [self](const uint8_t* d, size_t len) { self->send(0, d, len); };
        m.tr = transport(info);
    }
    if (!m.tr) m.st = StreamState::Dead;
}
Stream::~Stream() = default;

bool Stream::onDatagram(SocketId s, const Endpoint& from, const uint8_t* d, size_t len, TimePoint now) {
    Impl& m = *impl_;
    if (s != m.cfg.socket || from != m.cfg.remote) return false;
    std::vector<uint8_t> plain;
    if (m.cfg.obfuscator) {
        if (!m.cfg.obfuscator->unwrap(d, len, plain)) return false;
        d = plain.data();
        len = plain.size();
    }
    auto msg = proto::decodeStream(d, len);
    if (!msg || msg->token != m.cfg.token) return false;
    m.now = now;
    ++m.stats.datagramsIn;
    if (!m.alive()) return true;
    m.lastHeard = now;
    if (msg->flags & proto::kStreamFlagFin) {
        m.peerFin = true;
        m.st = StreamState::Closed;
        return true;
    }
    if (msg->len) m.tr->input(msg->payload, msg->len, now);
    return true;
}

TimePoint Stream::poll(TimePoint now) {
    Impl& m = *impl_;
    m.now = now;
    if (!m.alive()) return TimePoint::max();
    TimePoint trAt = m.tr->poll(now);
    if (m.tr->failed() || now >= m.deadAt()) {
        m.st = StreamState::Dead;
        return TimePoint::max();
    }
    if (m.st == StreamState::Closing && m.tr->flushed()) {
        m.send(proto::kStreamFlagFin, nullptr, 0);
        m.st = StreamState::Closed;
        return TimePoint::max();
    }
    if (now >= m.keepaliveAt()) {
        m.send(proto::kStreamFlagKeepalive, nullptr, 0);
        ++m.stats.keepalivesOut;
        m.drawJitter();
    }
    // A transport that answers "now" again would make the caller spin.
    trAt = std::max(trAt, now + Duration(1));
    return std::min({trAt, m.keepaliveAt(), m.deadAt()});
}

size_t Stream::write(const uint8_t* d, size_t len, TimePoint now) {
    Impl& m = *impl_;
    m.now = now;
    if (m.st != StreamState::Open || len == 0) return 0;
    const size_t n = std::min(len, m.tr->write(d, len, now));
    m.stats.bytesWritten += n;
    return n;
}

bool Stream::writable() const {
    const Impl& m = *impl_;
    return m.st == StreamState::Open && m.tr->writable();
}

size_t Stream::readable() const { return impl_->tr ? impl_->tr->readable() : 0; }

size_t Stream::read(uint8_t* out, size_t max) {
    Impl& m = *impl_;
    if (!m.tr) return 0;
    const size_t n = std::min(max, m.tr->read(out, max));
    m.stats.bytesRead += n;
    return n;
}

void Stream::close(TimePoint now) {
    Impl& m = *impl_;
    m.now = now;
    if (m.st == StreamState::Open) m.st = StreamState::Closing;
}

StreamState Stream::state() const { return impl_->st; }
bool Stream::peerClosed() const { return impl_->peerFin; }
const StreamStats& Stream::stats() const { return impl_->stats; }
const StreamConfig& Stream::config() const { return impl_->cfg; }

} // namespace natd
