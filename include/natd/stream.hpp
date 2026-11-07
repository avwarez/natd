// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/stream.hpp — a byte stream over a punched UDP path (sans-I/O).
//
// natd runs the session; the application supplies the transport.
//   natd:        STREAM messages with the punch's session token (and the
//                session's obfuscation), only from the punched remote
//                endpoint on the punched socket; keepalives while the
//                transport is quiet; liveness; the graceful close (FIN once
//                the transport says everything written is through).
//   transport:   what goes inside the STREAM messages: reliability, order,
//                flow and congestion control (RFC 8085 §3.1 is its job). It
//                is an IStreamTransport the application implements, created
//                per session by a StreamTransportFactory; natd knows no
//                transport protocol. Both peers must run the same one: the
//                application says which in its offer (Offer::kind) if it may
//                ever have more than one.
//
// Path maintenance, which only natd can do since it knows the NAT:
//   - keepalive: when nothing was sent for `keepalive` (plus a jitter of up
//     to a tenth), an empty STREAM message keeps both NAT mappings and
//     filters open (RFC 4787 REQ-6: outbound traffic refreshes the binding);
//   - liveness: Dead when nothing arrived for `keepalive * deadAfter`, or
//     when the transport reports failed().
// The caller moves datagrams and time, as for the other natd objects.
#pragma once

#include "natd/types.hpp"

#include <functional>
#include <memory>

namespace natd {

// The application's transport for one stream. natd calls it from the
// calls the application makes into natd (never from another thread), and the
// transport sends only through StreamTransportInfo::output, synchronously.
class IStreamTransport {
public:
    virtual ~IStreamTransport() = default;
    // A payload the peer's transport sent (one STREAM message).
    virtual void input(const uint8_t* data, size_t len, TimePoint now) = 0;
    // Accepts what it can; returns the bytes taken (0 = full).
    virtual size_t write(const uint8_t* data, size_t len, TimePoint now) = 0;
    virtual bool writable() const = 0;
    // Bytes received in order and not read yet.
    virtual size_t readable() const = 0;
    virtual size_t read(uint8_t* out, size_t max) = 0;
    // Timers; returns the next time it wants to be called.
    virtual TimePoint poll(TimePoint now) = 0;
    // Everything written so far is through (acknowledged by the peer).
    virtual bool flushed() const = 0;
    // The transport gave up (the peer stopped acknowledging).
    virtual bool failed() const = 0;
};

struct StreamTransportInfo {
    TxId     token{};              // the session token, the same on both peers
    size_t   maxPayload = 0;       // largest payload output() takes
    TimePoint now{};
    // Sends one payload to the peer (natd adds the STREAM header, the token
    // and the obfuscation). Valid for the life of the transport.
    std::function<void(const uint8_t* data, size_t len)> output;
};

using StreamTransportFactory = std::function<std::unique_ptr<IStreamTransport>(const StreamTransportInfo&)>;

struct StreamConfig {
    SocketId socket = 0;          // the punched socket (PunchSession::establishedSocket)
    Endpoint remote;              // PunchSession::remoteEndpoint
    TxId     token{};             // the punch's session token
    // At least 15 s (RFC 8085 §3.5). Each keepalive comes after a random
    // extra of up to a tenth of the period (jitter, RFC 8085 §3.5, RFC 7675).
    Duration keepalive{20000};
    int      deadAfter = 3;       // keepalive periods of silence
    size_t   maxPayload = 1200;   // transport payload per datagram, <= proto::kMaxStreamPayload
    // Optional: the same obfuscator as the punch session (null: plain natd format).
    std::shared_ptr<IDatagramObfuscator> obfuscator;
    RandomBytesFn randomBytes;    // for the jitter; empty -> defaultRandomBytes()
};

enum class StreamState : uint8_t { Open, Closing, Closed, Dead };
const char* toString(StreamState);

struct StreamStats {
    uint64_t bytesWritten = 0, bytesRead = 0;
    uint64_t datagramsOut = 0, datagramsIn = 0, keepalivesOut = 0;
};

class Stream {
public:
    // The factory is required: without a transport the stream is Dead at once.
    Stream(StreamConfig cfg, const StreamTransportFactory& transport, IDatagramIo& io, TimePoint now);
    ~Stream();
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    // True if the datagram belongs to this stream (consumed).
    bool onDatagram(SocketId, const Endpoint& from, const uint8_t* data, size_t len, TimePoint now);
    TimePoint poll(TimePoint now);

    // What the transport takes; 0 = full (write again once writable()).
    size_t write(const uint8_t* data, size_t len, TimePoint now);
    bool   writable() const;
    size_t readable() const;
    size_t read(uint8_t* out, size_t max);
    // Graceful: FIN once the transport is flushed().
    void close(TimePoint now);

    StreamState state() const;
    bool peerClosed() const;
    const StreamStats& stats() const;
    const StreamConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace natd
