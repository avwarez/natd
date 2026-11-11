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

## [0.5.0] - 2026-11-11

The spray towards a peer of unknown NAT no longer assumes a block size or
alignment (those of one operator): it grows from the endpoint seen outwards.

### API
- `PunchLimits::unknownBlock` and `unknownAhead` are replaced by
  `unknownSpray` (192): the ports the second round sprays besides the
  endpoint.
- `PunchPlan::roundTargets`: with `wholeRange`, round `sprayFromRound` sends
  to the first 1 + `roundTargets` targets, each later round to twice as many.

### Behaviour
- `planUnknownPeer`, Stable side: the targets are the endpoint and then the
  ports nearest to it, a port i past it ranking as one 2i before it, up to
  `maxPackets`; the rounds after the first send to a window that doubles
  each round (193, 385, 769, then the rest of the 2000 packets). Measured
  in the simulator against a Stable APDF side, 20 seeds each: blocks of
  64/128 (aligned or not)/256 all punched, 512 18/20; sequential delta 1, 2,
  -1 and with other subscribers all punched in the second round.

### Fixes
- Simulator: a Bounded NAT whose block is full gives the subscriber another
  block (RFC 7422) instead of looping for a free port.

## [0.4.0] - 2026-11-11

A Predictable side (sequential ports) can now be punched over a channel that
carries only the endpoint it saw, as a Bounded one since 0.3.0.

### API
- `PunchLimits::unknownAhead` (64): with `planUnknownPeer`, a Stable side
  also sprays the ports just past the endpoint, beyond the end of its block.
- `Agent::punchable()`: Stable, Predictable or Bounded.

### Behaviour
- `planUnknownPeer`: a Predictable side punches as a Bounded one, the
  endpoint from its primary socket; a Bounded one no longer opens
  `maxSockets` sockets (the Stable side sprays the whole block, one mapping
  is met as well, and more would use up the block).
- `planPunch` is again as in 0.2.1: the block-following and the whole-range
  spray of 0.3.0 go, as nothing used them.

## [0.3.0] - 2026-11-10

A Bounded side (dependent mapping, random ports inside a block, as mobile
CGNs do) can now be punched over a channel that carries only the endpoint it
saw, such as an eD2K server's NAT callback.

### API
- `PeerNat` (`Stable`, `Unknown`) and `Agent::connect()`/`accept()` with an
  `Endpoint` and a `PeerNat`: `Stable` is the Endpoint-only call,
  `Unknown` plans with `planUnknownPeer`.
- `planUnknownPeer()`: a Stable side punches the endpoint alone in the first
  round and, from the second round on, also the whole aligned block of
  `PunchLimits::unknownBlock` (128) ports around it; a Bounded side punches
  the endpoint from `maxSockets` sockets.
- `Agent::punchable()`: Stable or Bounded (a punch with `PeerNat::Unknown`
  can work).
- `PunchLimits::unknownBlock`, `PunchPlan::wholeRange`,
  `PunchPlan::sprayFromRound`.

### Behaviour
- `planPunch`, birthday strategies: the hard side's block follows its
  observed endpoint when that lies outside the block the discovery measured
  (a CGN opens another block once the first is full; measured on a mobile
  CGN with 128-port blocks).
- A remote range that fits in one round (at most `maxTargets` ports) is
  sprayed whole every round, instead of a new slice per round: a hard side
  whose mapping opens after the first round is met by the next one.

### Fixes
- `Agent`: a request waiting for a punch session gave up after `punchWait`
  only once a session was free; until then `poll()` kept answering a time
  already past. It now gives up on time (found by the agent fuzz target).

## [0.2.1] - 2026-11-09

### API
- `natd/resolve.hpp`, a platform adapter like the socket ones:
  `resolveIpv4()`, `resolveStunServers()` (the built-in list by default: in
  order, one address per host, no duplicates or names that do not resolve)
  and `StunResolver`, which does it on a thread of its own so that the
  caller never waits for DNS (`ready()`, `servers()`); destroying it never
  waits either. The library links the platform's threads for it. The
  example tools use it.

### Documentation
- natd takes datagrams only from the endpoints it addressed (the STUN
  servers and reflectors it asked, the peer of a punch), so an application
  may hand them over before its own address filters.

## [0.2.0] - 2026-11-09

natd now ends where the hole is open: a punch that gets through hands the
application the path and everything it needs to use it, and what goes over
it is the application's. natd has no dependencies, also in its tests.

### API
- `Agent`: the events are `ProfileReady`, `EndpointChanged`,
  `EndpointChecked`, `Punched` and `PunchFailed` (with `PunchError::Refused`
  or `TimedOut`). After `Punched`, `takeResult()` hands over a
  `PunchResult` once: the socket (the primary one, or one natd opened, which
  becomes the application's), the local and remote endpoints, the keepalive
  interval, the mapping lifetime, the strategy, the token. `cancel()` gives
  up on a session not handed over. `Agent(cfg, io)`: no transport factory.
  `checkEndpoint(now)`: no `closeIfChanged`. `SessionPhase` is `None`,
  `Waiting`, `Punching`, `Punched`.
- Removed: `Stream`, `StreamConfig`, `StreamState`, `IStreamTransport`,
  `StreamTransportInfo`, `StreamTransportFactory`, `TransportSet`,
  `chooseTransport()` (`natd/stream.hpp`), `Agent::read()`, `write()`,
  `readable()`, `release()`, the events `Connected`, `Incoming`, `Readable`,
  `Writable`, `Closed`, `SessionError`, `AgentConfig::maxSessions`,
  `linger`, `keepalive`, `stream`, `transports`, the counters `streamsDead`
  and `streamsAddressChanged`, `PunchSessionConfig::transports`,
  `PunchSession::transport()` and `noCommonTransport()`.

### Wire format
- The STREAM message (type 5) is gone, and PUNCH byte 7 is reserved again
  (0.1.4 carried the transports there). The wire version stays 1: probes and
  punches are unchanged from 0.1.3.

### Behaviour
- A punch handed over still answers the peer's PUNCH packets until the
  punch budget ends, for a last ACK that was lost.
- A path that went silent no longer starts an endpoint check by itself: the
  application, which now knows when its path is dead, calls
  `checkEndpoint()`.

### Tests
- The KCP copy in `tests/kcp` and its adapter are gone, with the stream
  checks and the stream fuzz target.

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
