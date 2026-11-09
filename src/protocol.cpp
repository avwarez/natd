// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/protocol.hpp"

#include <cstring>

namespace natd::proto {
namespace {

constexpr uint8_t kMagic[4] = {'N', 'A', 'T', 'D'};

void put16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
void put32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
uint16_t get16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
uint32_t get32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

Bytes header(MsgType t, uint8_t flags, const TxId& tx, size_t total) {
    Bytes b(total, 0);
    std::memcpy(b.data(), kMagic, 4);
    b[4] = kVersion;
    b[5] = uint8_t(t);
    b[6] = flags;
    std::memcpy(b.data() + 8, tx.data(), tx.size());
    return b;
}

bool checkHeader(const uint8_t* d, size_t len, MsgType t, size_t minLen) {
    return len >= minLen && std::memcmp(d, kMagic, 4) == 0 && d[4] == kVersion && d[5] == uint8_t(t);
}

TxId readTx(const uint8_t* d) {
    TxId tx;
    std::memcpy(tx.data(), d + 8, tx.size());
    return tx;
}

} // namespace

bool isNatdPacket(const uint8_t* d, size_t len) {
    return d && len >= kHeaderSize && std::memcmp(d, kMagic, 4) == 0 && d[4] == kVersion;
}

std::optional<MsgType> peekType(const uint8_t* d, size_t len) {
    if (!isNatdPacket(d, len)) return std::nullopt;
    if (d[5] < 1 || d[5] > 4) return std::nullopt;
    return MsgType(d[5]);
}

Bytes encode(const ProbeReq& m) {
    Bytes b = header(MsgType::ProbeReq, 0, m.txId, kProbeReqSize);
    b[20] = m.mask;
    put32(&b[22], m.delayMs);
    return b;
}

Bytes encode(const ProbeResp& m) {
    Bytes b = header(MsgType::ProbeResp, 0, m.txId, kProbeRespSize);
    put32(&b[20], m.observed.ip);
    put16(&b[24], m.observed.port);
    b[26] = uint8_t(m.kind);
    b[27] = m.caps;
    return b;
}

Bytes encode(const ForwardReq& m) {
    Bytes b = header(MsgType::ForwardReq, 0, m.txId, kForwardReqSize);
    put32(&b[20], m.target.ip);
    put16(&b[24], m.target.port);
    return b;
}

Bytes encode(const Punch& m) {
    return header(MsgType::Punch, m.ack ? kPunchFlagAck : 0, m.token, kPunchSize);
}

std::optional<ProbeReq> decodeProbeReq(const uint8_t* d, size_t len) {
    // Requests shorter than kProbeReqSize are rejected: anti-amplification.
    if (!checkHeader(d, len, MsgType::ProbeReq, kProbeReqSize)) return std::nullopt;
    ProbeReq m;
    m.txId = readTx(d);
    m.mask = d[20] & (ReplySame | ReplyOtherPort | ReplyPartner);
    m.delayMs = get32(d + 22);
    if (m.delayMs > kMaxDelayMs) return std::nullopt;
    return m;
}

std::optional<ProbeResp> decodeProbeResp(const uint8_t* d, size_t len) {
    if (!checkHeader(d, len, MsgType::ProbeResp, kProbeRespSize)) return std::nullopt;
    if (d[26] > uint8_t(ReplyKind::Refused)) return std::nullopt;
    ProbeResp m;
    m.txId = readTx(d);
    m.observed = {get32(d + 20), get16(d + 24)};
    m.kind = ReplyKind(d[26]);
    m.caps = d[27];
    return m;
}

std::optional<ForwardReq> decodeForwardReq(const uint8_t* d, size_t len) {
    if (!checkHeader(d, len, MsgType::ForwardReq, kForwardReqSize)) return std::nullopt;
    ForwardReq m;
    m.txId = readTx(d);
    m.target = {get32(d + 20), get16(d + 24)};
    if (!m.target.valid()) return std::nullopt;
    return m;
}

std::optional<Punch> decodePunch(const uint8_t* d, size_t len) {
    if (!checkHeader(d, len, MsgType::Punch, kPunchSize)) return std::nullopt;
    Punch m;
    m.token = readTx(d);
    m.ack = (d[6] & kPunchFlagAck) != 0;
    return m;
}

} // namespace natd::proto
