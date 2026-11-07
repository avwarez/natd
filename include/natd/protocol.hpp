// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/protocol.hpp — natd wire format (v1).
//
// All integers big-endian. Every message starts with a 20-byte header:
//
//   0  magic   "NATD" (4)
//   4  version 1      (1)
//   5  type           (1)
//   6  flags          (1)
//   7  reserved 0     (1)
//   8  txId           (12)
//
// PROBE_REQ   client -> reflector                     total 128 bytes (padded)
//   20 mask        (1)  bit0 reply from same endpoint
//                       bit1 reply from another local port of the reflector
//                       bit2 reply from the partner reflector (other IP)
//   21 reserved    (1)
//   22 delayMs     (4)  >0: send an extra reply after delayMs from the same
//                       endpoint (binding lifetime test)
//   26 padding to 128    anti-amplification: one request triggers at most
//                        four 28-byte replies towards its source (same,
//                        other port, partner, delayed or refused) = 112 bytes,
//                        so the bytes sent back never exceed the bytes received
//
// PROBE_RESP  reflector -> client                     total 28 bytes
//   20 observedIp  (4)  source address of the PROBE_REQ as seen by reflector
//   24 observedPort(2)
//   26 kind        (1)  0 same, 1 other port, 2 partner, 3 delayed,
//                        4 refused (delayed reply not queued: reflector limits)
//   27 caps        (1)  what the reflector can do right now (0 from older
//                        reflectors: nothing declared, the field was reserved)
//                        bit7 valid: the other bits are meaningful
//                        bit0 partner reachable (answered a check recently)
//                        bit1 partner checked (bit0 is a measurement)
//                        bit2 another local port can send (other-port reply)
//
// FORWARD_REQ reflector -> partner reflector          total 28 bytes
//   20 targetIp    (4)  always the observed source of the original request,
//   24 targetPort  (2)  never an address taken from a client payload
//   26 reserved    (2)
//
// PUNCH       peer <-> peer                           total 20 bytes
//   txId = session token agreed through the signalling channel
//   flags bit0 = ACK
//
// STREAM      peer <-> peer, after the punch           total 20 + payload
//   txId = session token (the punch's)
//   flags bit0 = KEEPALIVE (no payload), bit1 = FIN (no payload)
//   20 payload: what the application's transport sends (IStreamTransport),
//      at most kMaxStreamPayload; natd does not read it
#pragma once

#include "natd/types.hpp"

#include <optional>
#include <vector>

namespace natd::proto {

constexpr uint8_t kVersion = 1;
constexpr size_t  kHeaderSize = 20;
constexpr size_t  kProbeReqSize = 128;
constexpr size_t  kProbeRespSize = 28;
constexpr size_t  kForwardReqSize = 28;
constexpr size_t  kPunchSize = 20;
constexpr size_t  kMaxStreamPayload = 1400;
constexpr uint32_t kMaxDelayMs = 300000;

enum class MsgType : uint8_t {
    ProbeReq = 1,
    ProbeResp = 2,
    ForwardReq = 3,
    Punch = 4,
    Stream = 5,
};

enum ReplyMask : uint8_t {
    ReplySame = 0x01,
    ReplyOtherPort = 0x02,
    ReplyPartner = 0x04,
};

enum class ReplyKind : uint8_t { Same = 0, OtherPort = 1, Partner = 2, Delayed = 3, Refused = 4 };

enum Caps : uint8_t {
    CapPartnerAlive = 0x01,
    CapPartnerChecked = 0x02,
    CapOtherPort = 0x04,
    CapValid = 0x80,
};

constexpr uint8_t kPunchFlagAck = 0x01;
constexpr uint8_t kStreamFlagKeepalive = 0x01;
constexpr uint8_t kStreamFlagFin = 0x02;

struct ProbeReq {
    TxId     txId{};
    uint8_t  mask = ReplySame;
    uint32_t delayMs = 0;
};

struct ProbeResp {
    TxId      txId{};
    Endpoint  observed;
    ReplyKind kind = ReplyKind::Same;
    uint8_t   caps = 0;   // Caps bits; 0 = not declared
};

struct ForwardReq {
    TxId     txId{};
    Endpoint target;
};

struct Punch {
    TxId token{};
    bool ack = false;
};

// Payload points into the decoded buffer.
struct StreamMsg {
    TxId           token{};
    uint8_t        flags = 0;
    const uint8_t* payload = nullptr;
    size_t         len = 0;
};

using Bytes = std::vector<uint8_t>;

// Cheap check usable by callers that multiplex natd traffic with their own
// protocol on the same socket.
bool isNatdPacket(const uint8_t* data, size_t len);
std::optional<MsgType> peekType(const uint8_t* data, size_t len);

Bytes encode(const ProbeReq&);
Bytes encode(const ProbeResp&);
Bytes encode(const ForwardReq&);
Bytes encode(const Punch&);
Bytes encodeStream(const TxId& token, uint8_t flags, const uint8_t* payload, size_t len);

std::optional<ProbeReq>   decodeProbeReq(const uint8_t* data, size_t len);
std::optional<ProbeResp>  decodeProbeResp(const uint8_t* data, size_t len);
std::optional<ForwardReq> decodeForwardReq(const uint8_t* data, size_t len);
std::optional<Punch>      decodePunch(const uint8_t* data, size_t len);
std::optional<StreamMsg>  decodeStream(const uint8_t* data, size_t len);

} // namespace natd::proto
