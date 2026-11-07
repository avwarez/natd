// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// KCP as a natd stream transport (IStreamTransport), for the tests and the
// fuzz driver. An application writes its own (eMule has one); this one shows
// the contract: KCP in stream mode, normal mode (congestion control on),
// segments of at most info.maxPayload bytes sent through info.output.
#pragma once

#include "natd/stream.hpp"

#include "ikcp.h"

#include <algorithm>
#include <deque>
#include <vector>

namespace natd::test {

class KcpTransport : public IStreamTransport {
public:
    explicit KcpTransport(const StreamTransportInfo& info, int window = 256)
        : out_(info.output), epoch_(info.now), window_(window) {
        const uint32_t conv = uint32_t(info.token[0]) | uint32_t(info.token[1]) << 8 |
                              uint32_t(info.token[2]) << 16 | uint32_t(info.token[3]) << 24;
        kcp_ = ikcp_create(conv, this);
        ikcp_setoutput(kcp_, &KcpTransport::output);
        kcp_->stream = 1;
        ikcp_setmtu(kcp_, int(std::clamp<size_t>(info.maxPayload, 64, 1400)));
        ikcp_wndsize(kcp_, window_, window_);
        ikcp_nodelay(kcp_, 0, 20, 0, 0);   // normal mode: congestion control on, 20 ms timer
    }
    ~KcpTransport() override { ikcp_release(kcp_); }

    void input(const uint8_t* d, size_t len, TimePoint) override {
        ikcp_input(kcp_, reinterpret_cast<const char*>(d), long(len));
        drain();
    }

    size_t write(const uint8_t* d, size_t len, TimePoint) override {
        const int room = 2 * window_ - ikcp_waitsnd(kcp_);
        if (room <= 0 || len == 0) return 0;
        // ikcp_send refuses a call of IKCP_WND_RCV (128) segments or more:
        // feed it in slices.
        size_t left = std::min(len, size_t(room) * size_t(kcp_->mss)), done = 0;
        const size_t slice = size_t(kMaxSegmentsPerSend) * size_t(kcp_->mss);
        while (left) {
            const size_t n = std::min(left, slice);
            if (ikcp_send(kcp_, reinterpret_cast<const char*>(d + done), int(n)) < 0) break;
            done += n;
            left -= n;
        }
        if (done) ikcp_flush(kcp_);
        return done;
    }
    bool writable() const override { return ikcp_waitsnd(kcp_) < 2 * window_; }
    size_t readable() const override { return rx_.size(); }
    size_t read(uint8_t* out, size_t max) override {
        const size_t n = std::min(max, rx_.size());
        std::copy_n(rx_.begin(), n, out);
        rx_.erase(rx_.begin(), rx_.begin() + long(n));
        return n;
    }

    TimePoint poll(TimePoint now) override {
        const uint32_t cur = ms(now);
        ikcp_update(kcp_, cur);
        drain();
        // write() flushes off KCP's interval grid, so a segment can be due
        // for retransmission before the next scheduled flush: ikcp_check()
        // then says "now" while ikcp_update() does nothing until the grid
        // point. Retransmit what is due at once.
        if (ikcp_check(kcp_, cur) == cur) ikcp_flush(kcp_);
        return now + Duration(ikcp_check(kcp_, cur) - cur);
    }
    bool flushed() const override { return ikcp_waitsnd(kcp_) == 0; }
    bool failed() const override { return kcp_->state == IUINT32(-1); }

private:
    static constexpr int kMaxSegmentsPerSend = 64;   // < IKCP_WND_RCV (128), see ikcp_send

    static int output(const char* buf, int len, ikcpcb*, void* user) {
        static_cast<KcpTransport*>(user)->out_(reinterpret_cast<const uint8_t*>(buf), size_t(len));
        return 0;
    }
    uint32_t ms(TimePoint t) const { return uint32_t(std::chrono::duration_cast<Duration>(t - epoch_).count()); }
    void drain() {
        for (;;) {
            const int n = ikcp_peeksize(kcp_);
            if (n <= 0) break;
            std::vector<char> buf(static_cast<size_t>(n));
            const int got = ikcp_recv(kcp_, buf.data(), n);
            if (got <= 0) break;
            rx_.insert(rx_.end(), buf.begin(), buf.begin() + got);
        }
    }

    std::function<void(const uint8_t*, size_t)> out_;
    TimePoint epoch_;
    int window_;
    ikcpcb* kcp_ = nullptr;
    std::deque<uint8_t> rx_;
};

inline StreamTransportFactory kcpFactory(int window = 256) {
    return [window](const StreamTransportInfo& info) -> std::unique_ptr<IStreamTransport> {
        return std::make_unique<KcpTransport>(info, window);
    };
}

} // namespace natd::test
