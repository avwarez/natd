# Changelog

All notable changes to natd. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the library
follows [Semantic Versioning](https://semver.org/): while the major version is
0, a minor release may change the API, a patch release never does. The wire
formats have versions of their own (`natd/version.hpp`), raised only by an
incompatible change of that format.

Each entry lists, when there are any: API changes (what an application must
change), wire format changes, behaviour changes, and fixes.

## [Unreleased]

## [0.1.4] - 2026-11-09

### API
- `TransportSet`, `kFirstTransport`, `chooseTransport()` (`natd/stream.hpp`):
  the stream transports an application runs, as a bitmask it defines.
  `AgentConfig::transports` (default `0x01`) says which the factory makes;
  the factory gets the agreed one in `StreamTransportInfo::transport`.
  `PunchSessionConfig::transports`, `PunchSession::transport()` and
  `noCommonTransport()`, `StreamConfig::transport` for those that use the
  pieces without the Agent.

### Wire format
- PUNCH byte 7, reserved until now, carries the sender's `TransportSet`.
  Both peers take the highest bit they have in common, on every signalling
  channel and with no message of its own. 0 (natd 0.1.3 and before) is
  taken as bit 0, so older peers keep working with an application whose
  first transport is still bit 0. The wire version stays 1.

### Behaviour
- A punch whose peer runs none of our transports ends at the peer's first
  packet with `Refused` (counted in `punchesRefused`), instead of a stream
  that could not work.

## [0.1.3] - 2026-11-08

### API
- `natd::mappingLifetime(const NatProfile&)`: how long the primary socket's
  mapping survives with no outgoing datagram, for an application that keeps
  its public port published (a LowID's port in Kad) and must send something
  before it. The measured lifetime when there is one (after inbound
  traffic, else outbound-only), also below RFC 4787 REQ-5; not measured and
  endpoint-independent mapping: 2 minutes (REQ-5 minimum, REQ-6 outbound
  refresh); nothing without a NAT, without a result, below the smallest
  measured value, or for a mapping that already breaks REQ-1.

## [0.1.2] - 2026-11-07

### Fixes
- Discovery from STUN servers alone declared UDP blocked when the first
  servers it asked did not answer (on eMule's test bench its IP filter
  dropped the answers of 13 of 16 built-in servers): it now asks the
  servers not asked yet, in parallel once the silent ones are stale, and
  declares UDP blocked only when none is left. 9 of 12 silent: Stable in
  17.7 s (was UdpBlocked at 39.5 s); all silent: UdpBlocked at 57 s.

## [0.1.1] - 2026-11-07

### API changes
- `AgentEventType::EndpointChecked`: an endpoint check ended, with or
  without a change; `Agent::lastCheckResult()` gives the result and
  `Agent::checking()` whether one is running, so that an application can
  log every check (`toString(QuickCheckResult)`).

## [0.1.0] - 2026-11-07

The first public release.

### Library
- `NatDiscovery`: mapping and filtering behaviour (RFC 4787, RFC 5780), port
  allocation pattern and rate, hairpinning, binding lifetime; from a pair of
  natd reflectors and/or public STUN servers, or from STUN servers only.
- `QuickCheck`: re-validation of a profile's public endpoint.
- `Reflector`: the server role, with anti-amplification and per-IP limits.
- `PeerInfo`, `predictNextPorts`, `planPunch`, `planDirect`,
  `sessionTokenFrom`, `PunchSession`: profile exchange, port prediction,
  punch planning and sessions.
- `Stream`: the session over the punched path (token, keepalives, dead-path
  detection, graceful close) around a transport the application supplies
  (`IStreamTransport`, `StreamTransportFactory`); natd contains no
  transport protocol (KCP is only the tests' transport, `tests/kcp`).
- `IDatagramObfuscator`: optional obfuscation of a session's datagrams.
- `sessionTokenFrom` and `tokenFrom`: SHA-256 truncated to 96 bits (an
  internal implementation, no external library). README: "Security
  considerations".
- `Agent::nextPoll()`: when `poll()` is wanted, also after a datagram or
  another call. Datagrams reach their stream by (socket, endpoint) in one
  lookup; a punch checks the source before it unwraps.
- One transaction engine (internal, `src/probe_engine.hpp`) for discovery,
  QuickCheck and `natd_stunlist`.
- `Agent(config, io, transport)`: one integration point for applications (profile, endpoint checks,
  punch caps and queue, punch to stream, lingering close, event queue,
  counters); `encodeOffer`, `decodeOffer`, `tokenFrom`.
- Socket adapters for POSIX and Winsock 2; a minimal STUN client and server
  list parser with a built-in list.
- `natd/version.hpp`: `NATD_VERSION*`, `versionString()`, and the versions of
  the wire formats.

### Standards conformance (README, "Standards conformance")
- RFC 8489: transaction IDs from the operating system's CSPRNG
  (`defaultRandomBytes()`; Windows links `bcrypt`); SOFTWARE in Binding
  requests; retransmission from an RTO of 500 ms, doubling, with an RTT
  estimate per server, Rc = 7, Rm = 16 (`AdvancedConfig::rto`, `stunRc`,
  `stunRm`); at most 10 transactions per server (`maxOutstanding`);
  `stun::decodeBinding`: error responses and unknown comprehension-required
  attributes fail the transaction, attributes after MESSAGE-INTEGRITY are
  ignored. A phase stops waiting for stale STUN transactions only when it no
  longer needs them (`stunStaleAfter`); QuickCheck asks the next server in
  parallel.
- RFC 8085: punch interval at least 3 s and keepalives at least 15 s with
  jitter (`StreamConfig::randomBytes`), unless a measured binding lifetime
  asks for less; reflector probes and the hairpin test back off
  exponentially. `natd_stunlist` retransmits the same way (`--rto`).

### Wire formats
- natd messages: version 1.
- `PeerInfo`: version 3 (decoders read 1 to 3).
- Offer: version 1 (`"NATD"`, version, kind, nonce).

### Tools and tests
- `natd_reflector`, `natd_probe`, `natd_stunlist`, `tools/update-stun-list`.
- Unit and simulation tests, socket adapter tests, network-namespace tests on
  real Linux NATs, and a fuzz driver with six targets.
