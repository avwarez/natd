// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/stun.hpp — minimal STUN Binding client (RFC 8489), sans-I/O.
//
// natd uses public STUN servers only as mirrors: a Binding request from a
// socket returns the external endpoint the NAT gave to that (socket,
// server) pair. That is all the discovery needs for the samples that only
// count new mappings (the mapping probe towards a second IP and the
// same-socket allocation sample). Tests that need the server's cooperation
// (replies from another port or IP, delayed replies) stay on the natd
// reflector.
//
// Supported: Binding request (SOFTWARE only), Binding success response with
// XOR-MAPPED-ADDRESS or, from RFC 3489 servers, MAPPED-ADDRESS, and Binding
// error responses (the transaction fails). IPv4 only. Retransmissions follow
// RFC 8489 §6.2.1 (see AdvancedConfig: rto, stunRc, stunRm) and at most
// maxOutstanding transactions run towards one server (§6.2).
// No authentication: public servers offer none. The caller matches the
// transaction id and the source endpoint; NatDiscovery also requires the
// mapped IP to equal the one seen by the natd reflector (paired pooling,
// RFC 4787 REQ-2, RFC 6888 REQ-2), which drops servers that answer with a
// wrong address.
//
// The server list is data, refreshed by the application: parseServerList()
// reads the plain text format of public lists (one "host[:port]" per line,
// as published by https://github.com/pradt2/always-online-stun), and
// builtinServers() is a fallback verified when this version was written.
// Name resolution is left to the application (the library does no I/O).
#pragma once

#include "natd/types.hpp"

#include <optional>
#include <string>
#include <vector>

namespace natd::stun {

constexpr uint32_t kMagicCookie = 0x2112A442;
constexpr size_t   kHeaderSize = 20;
constexpr uint16_t kDefaultPort = 3478;

// STUN message header shape: top two bits zero, magic cookie, length a
// multiple of 4 matching the datagram. Lets callers that multiplex STUN with
// their own protocol tell the two apart.
bool isStunPacket(const uint8_t* data, size_t len);

// Binding request with a SOFTWARE attribute ("natd <version>", RFC 8489
// §6.1). The 96-bit transaction id is the natd TxId; it must be
// cryptographically random (§5), as defaultRandomBytes() is.
std::vector<uint8_t> encodeBindingRequest(const TxId& tx);

struct BindingResponse {
    TxId     txId{};
    Endpoint mapped;
    // OTHER-ADDRESS (RFC 5780) or CHANGED-ADDRESS (RFC 3489), when present:
    // the server's alternate address. Only a hint (natd_stunlist uses it to
    // find a second port on the same IP); many servers listen on a second
    // port without announcing it.
    std::optional<Endpoint> other;
};

// Any Binding response (success or error). success = false means the
// transaction failed: an error response, or a success response that RFC 8489
// §6.3.3 makes a failure (an unknown comprehension-required attribute, no
// IPv4 mapped address). Attributes after MESSAGE-INTEGRITY are ignored (§9).
// nullopt: not a well-formed Binding response.
struct BindingReply {
    TxId     txId{};
    bool     success = false;
    Endpoint mapped;
    std::optional<Endpoint> other;
};
std::optional<BindingReply> decodeBinding(const uint8_t* data, size_t len);

// Binding success response carrying an IPv4 (XOR-)MAPPED-ADDRESS (the
// successful cases of decodeBinding).
std::optional<BindingResponse> decodeBindingResponse(const uint8_t* data, size_t len);

struct ServerEntry {
    std::string host;               // name or dotted IPv4
    uint16_t    port = kDefaultPort;
    // Second port on the same IP that also answers Binding requests (0 =
    // none known). Such a server stands in for a second reflector port in the
    // mapping test (same IP, different port: RFC 4787 §4.1, RFC 5780 §4.3).
    uint16_t    altPort = 0;
    friend bool operator==(const ServerEntry& a, const ServerEntry& b) {
        return a.host == b.host && a.port == b.port && a.altPort == b.altPort;
    }
};

// One server per line: "host", "host:port" or "stun:host[:port]" (RFC 7064),
// optionally followed by " alt=PORT" (a second port on the same IP, written
// by natd_stunlist; other readers of the plain format see a normal entry if
// they stop at the first blank). Empty lines and lines starting with '#' are
// skipped, as are IPv6 entries and malformed lines. Duplicates (same host
// and port) are removed, the first one kept.
std::vector<ServerEntry> parseServerList(const std::string& text);
std::string formatServerList(const std::vector<ServerEntry>& list);

// Fallback list, servers that answered Binding requests from one vantage
// point on 2026-11-02 (independent operators, preference order; altPort set
// where the second port answered too). Refresh it at run time from a public
// list whenever possible.
const std::vector<ServerEntry>& builtinServers();

} // namespace natd::stun
