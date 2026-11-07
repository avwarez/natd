// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/stun.hpp"
#include "natd/version.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace natd::stun {
namespace {

constexpr uint16_t kBindingRequest = 0x0001;
constexpr uint16_t kBindingSuccess = 0x0101;
constexpr uint16_t kBindingError = 0x0111;
constexpr uint16_t kAttrMappedAddress = 0x0001;
constexpr uint16_t kAttrSourceAddress = 0x0004;    // RFC 3489
constexpr uint16_t kAttrChangedAddress = 0x0005;   // RFC 3489
constexpr uint16_t kAttrMessageIntegrity = 0x0008;
constexpr uint16_t kAttrMessageIntegritySha256 = 0x001C;
constexpr uint16_t kAttrXorMappedAddress = 0x0020;
constexpr uint16_t kAttrSoftware = 0x8022;
constexpr uint16_t kAttrFingerprint = 0x8028;
constexpr uint16_t kAttrOtherAddress = 0x802C;     // RFC 5780

// Comprehension-required attributes (0x0000-0x7FFF) natd understands in a
// Binding success response. Any other one makes the response a failure
// (RFC 8489 §6.3.3). SOURCE-ADDRESS and CHANGED-ADDRESS come from RFC 3489
// servers (backwards compatibility, RFC 8489 §12); the two integrity
// attributes only end the part of the message that counts (§9).
bool understood(uint16_t type) {
    switch (type) {
    case kAttrMappedAddress: case kAttrSourceAddress: case kAttrChangedAddress:
    case kAttrMessageIntegrity: case kAttrMessageIntegritySha256: case kAttrXorMappedAddress:
        return true;
    default:
        return type >= 0x8000;   // comprehension-optional: ignored when unknown
    }
}

uint16_t rd16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
uint32_t rd32(const uint8_t* p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

bool validHost(const std::string& h) {
    if (h.empty() || h.size() > 253) return false;
    for (char c : h)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_')) return false;
    return true;
}

} // namespace

bool isStunPacket(const uint8_t* d, size_t len) {
    if (len < kHeaderSize || (d[0] & 0xC0) != 0) return false;
    const size_t body = rd16(d + 2);
    return body % 4 == 0 && body + kHeaderSize == len && rd32(d + 4) == kMagicCookie;
}

std::vector<uint8_t> encodeBindingRequest(const TxId& tx) {
    // SOFTWARE in every request (RFC 8489 §6.1): the library name and version.
    const std::string sw = std::string("natd ") + versionString();
    const size_t padded = (sw.size() + 3) & ~size_t(3);
    const size_t body = 4 + padded;
    std::vector<uint8_t> b(kHeaderSize + body, 0);
    b[0] = uint8_t(kBindingRequest >> 8);
    b[1] = uint8_t(kBindingRequest);
    b[2] = uint8_t(body >> 8);
    b[3] = uint8_t(body);
    b[20] = uint8_t(kAttrSoftware >> 8);
    b[21] = uint8_t(kAttrSoftware & 0xFF);
    b[22] = uint8_t(sw.size() >> 8);
    b[23] = uint8_t(sw.size());
    std::copy(sw.begin(), sw.end(), b.begin() + 24);
    b[4] = uint8_t(kMagicCookie >> 24);
    b[5] = uint8_t((kMagicCookie >> 16) & 0xFF);
    b[6] = uint8_t((kMagicCookie >> 8) & 0xFF);
    b[7] = uint8_t(kMagicCookie & 0xFF);
    std::copy(tx.begin(), tx.end(), b.begin() + 8);
    return b;
}

std::optional<BindingReply> decodeBinding(const uint8_t* d, size_t len) {
    if (!isStunPacket(d, len)) return std::nullopt;
    const uint16_t type = rd16(d);
    if (type != kBindingSuccess && type != kBindingError) return std::nullopt;
    BindingReply r;
    std::copy(d + 8, d + 20, r.txId.begin());
    std::optional<Endpoint> xorMapped, mapped;
    bool unknownRequired = false;
    // After MESSAGE-INTEGRITY only MESSAGE-INTEGRITY-SHA256 and FINGERPRINT
    // count, after MESSAGE-INTEGRITY-SHA256 only FINGERPRINT (RFC 8489 §9).
    bool afterMi = false, afterMi256 = false;
    for (size_t i = kHeaderSize; i + 4 <= len;) {
        const uint16_t at = rd16(d + i), alen = rd16(d + i + 2);
        const uint8_t* v = d + i + 4;
        if (i + 4 + alen > len) return std::nullopt;
        i += 4 + ((size_t(alen) + 3) & ~size_t(3));
        if (afterMi256 && at != kAttrFingerprint) continue;
        if (afterMi && at != kAttrMessageIntegritySha256 && at != kAttrFingerprint) continue;
        if (at == kAttrMessageIntegrity) afterMi = true;
        if (at == kAttrMessageIntegritySha256) afterMi256 = true;
        if (!understood(at)) unknownRequired = true;
        // Address attribute: reserved, family (1 = IPv4; others ignored,
        // RFC 8489 §6.3.3), port, address.
        if ((at == kAttrXorMappedAddress || at == kAttrMappedAddress) && alen >= 8 && v[1] == 0x01) {
            Endpoint e{rd32(v + 4), rd16(v + 2)};
            if (at == kAttrXorMappedAddress) {
                e.port ^= uint16_t(kMagicCookie >> 16);
                e.ip ^= kMagicCookie;
                if (!xorMapped) xorMapped = e;
            } else if (!mapped) {
                mapped = e;
            }
        }
        if ((at == kAttrOtherAddress || at == kAttrChangedAddress) && alen >= 8 && v[1] == 0x01 && !r.other) {
            Endpoint e{rd32(v + 4), rd16(v + 2)};
            if (e.valid()) r.other = e;
        }
    }
    // An error response ends the transaction as failed, whatever it carries
    // (RFC 8489 §6.3.4: no ERROR-CODE or unknown attributes fail it as well,
    // and natd has no use for 3xx or 4xx retries). A success response with an
    // unknown comprehension-required attribute is discarded and fails the
    // transaction (§6.3.3); so does one without a usable IPv4 address.
    if (type == kBindingError || unknownRequired) return r;
    if (xorMapped) r.mapped = *xorMapped;
    else if (mapped) r.mapped = *mapped;   // RFC 3489 server (RFC 8489 §12)
    r.success = r.mapped.valid();
    return r;
}

std::optional<BindingResponse> decodeBindingResponse(const uint8_t* d, size_t len) {
    auto r = decodeBinding(d, len);
    if (!r || !r->success) return std::nullopt;
    return BindingResponse{r->txId, r->mapped, r->other};
}

std::vector<ServerEntry> parseServerList(const std::string& text) {
    std::vector<ServerEntry> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.compare(0, 5, "stun:") == 0) line = line.substr(5);
        uint16_t alt = 0;
        auto sp = line.find_first_of(" \t");
        if (sp != std::string::npos) {
            std::string rest = trim(line.substr(sp));
            line = line.substr(0, sp);
            if (rest.compare(0, 4, "alt=") != 0) continue;
            char* end = nullptr;
            unsigned long v = std::strtoul(rest.c_str() + 4, &end, 10);
            if (*end || v == 0 || v > 65535) continue;
            alt = uint16_t(v);
        }
        if (line.find('[') != std::string::npos || std::count(line.begin(), line.end(), ':') > 1) continue;   // IPv6
        ServerEntry e;
        auto colon = line.find(':');
        e.host = line.substr(0, colon);
        if (colon != std::string::npos) {
            const std::string p = line.substr(colon + 1);
            char* end = nullptr;
            unsigned long v = std::strtoul(p.c_str(), &end, 10);
            if (p.empty() || *end || v == 0 || v > 65535) continue;
            e.port = uint16_t(v);
        }
        if (!validHost(e.host)) continue;
        if (alt != e.port) e.altPort = alt;
        auto same = [&](const ServerEntry& x) { return x.host == e.host && x.port == e.port; };
        if (std::none_of(out.begin(), out.end(), same)) out.push_back(e);
    }
    return out;
}

std::string formatServerList(const std::vector<ServerEntry>& list) {
    std::string s;
    for (auto& e : list) {
        // A host named "stun" would read back as the "stun:" scheme prefix.
        if (e.host == "stun") s += "stun:";
        s += e.host + ":" + std::to_string(e.port);
        if (e.altPort) s += " alt=" + std::to_string(e.altPort);
        s += "\n";
    }
    return s;
}

const std::vector<ServerEntry>& builtinServers() {
    static const std::vector<ServerEntry> list = {
        {"stun.1und1.de", 3478, 3479},   {"stun.voipgate.com", 3478, 3479}, {"stun.t-online.de", 3478, 3479},
        {"stun.sipgate.net", 3478, 3479}, {"stun.sonetel.com", 3478, 3479},
        {"stun.nextcloud.com", 3478, 443}, {"stun.cloudflare.com", 3478},  {"stun.l.google.com", 19302},
        {"global.stun.twilio.com", 3478}, {"stun.voys.nl", 3478},          {"stun.hot-chilli.net", 3478},
        {"stun.framasoft.org", 3478},    {"stun.voip.blackberry.com", 3478}, {"stun.linphone.org", 3478},
        {"stun.siptrunk.com", 3478},     {"stun.freeswitch.org", 3478},
    };
    return list;
}

} // namespace natd::stun
