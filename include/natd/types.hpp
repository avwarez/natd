// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/types.hpp — basic types shared by the whole library.
//
// natd is a protocol-agnostic, sans-I/O library for NAT behavior discovery
// and UDP hole punching. It reasons only on IPv4 addresses and UDP ports.
// It owns no sockets, threads or timers: the caller moves datagrams and time.
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <memory>
#include <string>
#include <vector>

namespace natd {

using Clock     = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration  = std::chrono::milliseconds;

// IPv4 endpoint, host byte order.
struct Endpoint {
    uint32_t ip   = 0;
    uint16_t port = 0;

    bool valid() const { return ip != 0 && port != 0; }
    friend bool operator==(const Endpoint& a, const Endpoint& b) {
        return a.ip == b.ip && a.port == b.port;
    }
    friend bool operator!=(const Endpoint& a, const Endpoint& b) { return !(a == b); }
};

// Opaque socket handle owned by the caller.
using SocketId = uint32_t;

// 96-bit transaction id / session token.
using TxId = std::array<uint8_t, 12>;

// Source of random bytes. The default implementation is the operating
// system's CSPRNG (getrandom, BCryptGenRandom); callers may inject their own,
// which must be cryptographically secure too (RFC 8489 §5).
using RandomBytesFn = std::function<void(uint8_t* out, size_t len)>;
RandomBytesFn defaultRandomBytes();

// Raw UDP I/O implemented by the caller (client side).
// The library encodes and decodes its own wire format; the caller only moves
// bytes and delivers inbound datagrams to the library objects.
class IDatagramIo {
public:
    virtual ~IDatagramIo() = default;

    // Open an extra UDP socket. preferredLocalPort == 0 lets the OS choose.
    // Return std::nullopt on failure (e.g. port busy).
    virtual std::optional<SocketId> openSocket(uint16_t preferredLocalPort) = 0;
    virtual void closeSocket(SocketId) = 0;

    // Local endpoint of a socket; ip may be 0 if bound to INADDR_ANY.
    virtual Endpoint localEndpoint(SocketId) const = 0;

    virtual bool send(SocketId, const Endpoint& to, const uint8_t* data, size_t len) = 0;
};

// Optional obfuscation of a punch session's datagrams (PunchSession), so
// that natd's wire format ("NATD" header, token) is not recognisable on the
// path. natd does no cryptography: the application supplies the transform
// (for instance the obfuscation it already uses for its own traffic).
// Obfuscation, not secrecy: whoever knows the keys' inputs can read.
class IDatagramObfuscator {
public:
    virtual ~IDatagramObfuscator() = default;
    // The datagram as it goes on the wire.
    virtual std::vector<uint8_t> wrap(const uint8_t* data, size_t len) = 0;
    // The original datagram into out; false when the datagram is not one of
    // this session's (it is then left to the caller's other handlers).
    virtual bool unwrap(const uint8_t* data, size_t len, std::vector<uint8_t>& out) = 0;
};

// Helpers
std::string toString(const Endpoint&);
std::optional<Endpoint> parseEndpoint(const std::string& ipColonPort);
std::optional<uint32_t> parseIp(const std::string& dotted);
// 100.64.0.0/10 (RFC 6598 shared address space used by CGNATs)
inline bool isCgnatSpace(uint32_t ip) { return (ip & 0xFFC00000u) == 0x64400000u; }
// RFC 1918
inline bool isPrivate(uint32_t ip) {
    return (ip & 0xFF000000u) == 0x0A000000u || (ip & 0xFFF00000u) == 0xAC100000u ||
           (ip & 0xFFFF0000u) == 0xC0A80000u;
}

} // namespace natd
