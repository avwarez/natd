# natd

A sans-I/O C++17 library for NAT behaviour discovery (IPv4/UDP) and UDP hole
punching. It owns no sockets, threads or timers: the application feeds it
datagrams and the current time, and sends what it asks to send.

natd is application-agnostic. It covers:

- **discovery** of the NAT in front of a socket: mapping and filtering
  behaviour (RFC 4787, RFC 5780), port allocation pattern, hairpinning and
  binding lifetime, from a pair of natd reflectors and/or public STUN servers;
- **punch planning and sessions** between two peers, from what each one
  learned about its own NAT (`PeerInfo`), exchanged over any signalling
  channel the application already has;
- **a stream session** (`Stream`) over the punched path: the session token,
  keepalives, dead-path detection and the graceful close, around a
  transport the application supplies (`IStreamTransport`; natd knows no
  transport protocol);
- **one object for applications** (`Agent`) that puts these together: the
  life of the profile, endpoint checks, caps and a queue for punch sessions,
  the move from punch to stream, a lingering close, and a queue of events;
- small **socket adapters** for POSIX and Winsock 2, for applications that do
  not bring their own I/O.

## Contents

| File | Purpose |
| --- | --- |
| `include/natd/*.hpp` | public API |
| `src/types.cpp`, `src/protocol.cpp` | types, wire format v1 |
| `src/reflector.cpp` | reflector role, with anti-abuse limits |
| `src/classify.cpp` | `classifyAllocation`, `toString` |
| `src/discovery.cpp` | `NatDiscovery`, `QuickCheck` |
| `src/probe_engine.hpp` | the transaction engine (internal): reflector probes and STUN transactions, retransmission, outstanding limit, RTT; also used by `natd_stunlist` |
| `src/sha256.cpp` | SHA-256 (internal), for the session tokens |
| `src/punch.cpp` | `PeerInfo`, `predictNextPorts`, `planPunch`, `planDirect`, `sessionTokenFrom`, `PunchSession` |
| `include/natd/version.hpp`, `src/version.cpp` | library version and wire format versions |
| `include/natd/agent.hpp`, `src/agent.cpp` | `Agent`: the integration point for applications; `encodeOffer`, `decodeOffer`, `tokenFrom` |
| `include/natd/stream.hpp`, `src/stream.cpp` | `Stream` and `IStreamTransport`: the session over the punched path (token, keepalives, dead-path detection, FIN) around the application's transport |
| `tests/kcp/`, `tests/kcp_transport.hpp` | KCP 1.7 (MIT licence), unmodified, and its adapter: the transport of the tests and the fuzz driver only |
| `sim/natsim.hpp` | simulation building blocks (NAT, STUN server, virtual clock), reusable by application simulators |
| `include/natd/stun.hpp`, `src/stun.cpp` | minimal STUN Binding client (RFC 8489), server list parser, built-in fallback list |
| `include/natd/posix_io.hpp`, `src/posix_io.cpp` | `IDatagramIo` adapter on POSIX sockets |
| `include/natd/winsock_io.hpp`, `src/winsock_io.cpp` | `IDatagramIo` adapter on Winsock 2 |
| `include/natd/platform_io.hpp` | `PlatformDatagramIo`: the adapter of the current platform |
| `cmake/aarch64-w64-mingw32.cmake`, `cmake/x86_64-w64-mingw32.cmake` | Windows ARM64 / x64 toolchains (llvm-mingw) |
| `tests/test_io.cpp` | socket adapter tests on loopback (POSIX and Winsock) |
| `dist/natd-win-x64/` | test package for Windows x64 (`run-tests.cmd`, no administrator rights needed) |
| `examples/natd_reflector.cpp`, `examples/natd_probe.cpp` | command-line reflector and probe |
| `examples/natd_stunlist.cpp`, `tools/update-stun-list.{sh,cmd}` | STUN list update: download, check, keep the good servers |
| `tests/netns/run.sh`, `tests/netns/stun_server.py` | tests on real Linux NATs (network namespaces + nftables), with local STUN servers |
| `tests/simnet.hpp` | in-process virtual-time simulator (configurable NATs, two reflectors, STUN servers, two peers) |
| `tests/test_main.cpp` | unit and simulation tests |
| `tests/fuzz_main.cpp` | fuzz driver |

Platforms: Linux (GCC, Clang), Windows with llvm-mingw (ARM64 and x64, tested
under Wine 11 ARM64) and MSVC (x64, Win32 and ARM64, built as a
subdirectory of an application's CI; the tests have not run there yet).

## Building and testing

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build
./build/natd_tests        # exit status 0 = every check passed
```

With UBSan:

```sh
cmake -S . -B build-ubsan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=undefined -fno-sanitize-recover=all -D_GLIBCXX_ASSERTIONS"
ninja -C build-ubsan && ./build-ubsan/natd_tests
```

(ASan does not start on some Raspberry Pi kernels because of the address
space layout; this is not a problem of the code.)

CMake options: `NATD_TESTS`, `NATD_EXAMPLES` (both on by default), `NATD_FUZZ`.
An application can add natd with `add_subdirectory` and link the `natd`
target.

### Fuzzing

`tests/fuzz_main.cpp` has six targets: decoders and parsers, the reflector,
the punch session, the stream (with the KCP test transport) under hostile segments, discovery and
QuickCheck with hostile answers, and the `Agent` driven by a script of
application calls and hostile datagrams. Besides crashes it checks properties: decode
and re-encode agree; the reflector never sends an IP more bytes than it
received from it, and only to sources, partners or targets a partner named;
the punch session sends only to the remote IP, at most `maxPackets`, and never
more ACKs than datagrams received; `Stream::poll()` does not keep answering
"now"; discovery stays within its mapping cap and closes every socket; the
`Agent` gives events only for sessions the application holds, one `Closed`
per session and nothing after it, keeps its caps, sends only to STUN servers
and to the peers it was given, and leaves no session or socket behind. There
is no coverage guidance (libFuzzer needs compiler-rt): each input is a random
script that builds mostly well-formed messages with hostile fields.

```sh
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DNATD_FUZZ=ON \
      -DCMAKE_CXX_FLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined" \
      -DCMAKE_C_FLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=undefined"
ninja -C build-fuzz natd_fuzz
./build-fuzz/natd_fuzz all 10 1    # every target, 10 x the base iterations, seed 1
./build-fuzz/natd_fuzz decoders --replay ITER SEED   # replays a failed case
```

### Memory errors

Where AddressSanitizer runs, build with `-fsanitize=address,undefined`. Where
it does not (the Raspberry Pi kernel), use Valgrind on a debug build:

```sh
cmake -S . -B build-vg -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-O1 -g" -DNATD_FUZZ=ON
cmake --build build-vg
valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite,indirect,possible ./build-vg/natd_tests
valgrind --error-exitcode=99 --leak-check=full ./build-vg/natd_fuzz all 1 11
```

### Windows

Cross-compiling for Windows ARM64 from Linux aarch64 (static binaries):

```sh
cmake -S . -B build-win -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-w64-mingw32.cmake \
      -DLLVM_MINGW=$HOME/toolchains/llvm-mingw-20261020-ucrt-ubuntu-22.04-aarch64
ninja -C build-win
WINEPREFIX=$HOME/.wine-natd wine build-win/natd_tests.exe
```

### Real NATs

Tests on real Linux NATs (needs root; creates and then removes three
namespaces, `natd-c`, `natd-n` and `natd-i`, and adds no rule on the host):

```sh
sudo tests/netns/run.sh build
```

With the Windows probe under Wine (run as a normal user inside the client
namespace):

```sh
sudo PROBE_CMD="sudo -u $USER env WINEPREFIX=$HOME/.wine-natd WINEDEBUG=-all wine build-win/natd_probe.exe" \
     tests/netns/run.sh build
```

Cases: `masquerade` (Stable, APD filtering, lifetime with a 12 s conntrack
timeout in the NAT namespace only), `masquerade random`,
`masquerade to :20480-22527 random` (Bounded), `masquerade fully-random`.

## Integrating natd: the Agent

An application creates one `Agent` on the UDP socket it already has (its
*primary socket*) and drives it like the other natd objects: every datagram
goes to `onDatagram()` before the application parses it, `poll()` is called
when it asks (`nextPoll()` says when, also after a datagram or another call
that moved a timer earlier), and events are read with `nextEvent()`. A
datagram reaches its stream in one lookup (by socket and endpoint), and a
punch looks at the source before it decodes or unwraps anything. The split
of responsibilities:

| natd (`Agent`) | the application |
|---|---|
| discovery, profile, endpoint checks (one at a time, at most one per `checkReuse`) | when to start (`start()`), the STUN server names (DNS is the application's) |
| "this datagram is mine" on the shared socket | the socket, and which protocol reads first |
| the offer format (`encodeOffer`: "NATD", version, kind, nonce) | where the offer travels: its own signalling channel |
| the session token from the bytes it is given (`tokenFrom`) | which bytes: something both peers know |
| punch, stream, keepalives, linger, caps on sessions | whether and with whom to punch, and the values of the caps |
| `EndpointChanged`; streams whose path is gone end as `Reset` | what makes it check (`checkEndpoint`) and what to do after (publish again, ...) |
| the obfuscation interface | the transform and its keys |
| no thread, no lock, no callback | threads and the lock around every call |
| the stream session: token, keepalives, liveness, FIN | the transport inside it (`IStreamTransport`): reliability, order, flow and congestion control |
| bytes over the stream | the protocol over them |

The transport contract (`natd/stream.hpp`): `input()` gets each payload the
peer's transport sent; `write()`, `read()`, `readable()` and `writable()`
are the stream's; `poll()` drives its timers; `flushed()` says that
everything written was acknowledged (natd sends the FIN only then);
`failed()` says it gave up (the stream is `Reset`). It sends through
`info.output`, at most `info.maxPayload` bytes at a time, synchronously
from inside these calls. Both peers must run the same transport: if an
application may ever change it, it says which in the offer (`Offer::kind`).
Changing the transport needs no new natd version.

A session belongs to the application from `connect()` or `accept()` until
`release()`. It ends with `Connected` or `Incoming`, and later with
`Closed`, which comes after the bytes that arrived before the end were read.
`Readable` and `Writable` are edge-triggered: one event, until the next
`read()`, or until `write()` returned 0 again.

```cpp
natd::AgentConfig cfg;
cfg.discovery.primarySocket = mySocket;
// The application's transport, one per session (KCP in eMule, see
// tests/kcp_transport.hpp for an example). natd calls it and carries what it
// sends through info.output; it never reads the payloads.
natd::StreamTransportFactory transport = [](const natd::StreamTransportInfo& info) {
    return std::make_unique<MyTransport>(info);
};
natd::Agent agent(cfg, myIo, transport);
agent.start(now, resolvedStunServers);

// peer A, after sending the offer over its own channel
auto offer = natd::encodeOffer({1, randomNonce});
natd::SessionId s = agent.connect(peerEndpoint, natd::tokenFrom(key, 16, randomNonce), now);

// peer B, when the offer arrives (from: the endpoint the channel saw)
if (auto o = natd::decodeOffer(data, len))
    agent.accept(from, natd::tokenFrom(key, 16, o->nonce), now);

natd::AgentEvent e;
while (agent.nextEvent(e)) { /* Connected, Incoming, Readable, Writable, Closed, ... */ }
```

### Public STUN servers

Discovery and endpoint checks use public STUN servers that other people run
for free. An application that ships to many users multiplies its load on
them, so natd keeps it low by default, and an application should not lower
these limits:

- the `Agent` shuffles the server list for each client (`shuffleStunServers`),
  so that no server takes everybody's first request;
- one discovery per start, and endpoint checks one at a time, at most one per
  `checkReuse` (60 s);
- the lifetime test, the most expensive part, needs natd's own reflector and
  never runs against STUN servers;
- the built-in list (`stun::builtinServers()`) is a fallback; an application
  with many users should refresh its list (`tools/update-stun-list`) and,
  better still, run its own STUN server or reflector.

In a simulation of 22 clients over 2.3 hours this came to about 18 requests
per client per hour, the busiest of 10 servers taking about a third of them.

## Versioning

natd follows [Semantic Versioning](https://semver.org/). The version is
written once, in `include/natd/version.hpp` (`NATD_VERSION_STRING`,
`NATD_VERSION` for `#if`, `natd::versionString()` for the compiled
library), and CMake reads it from there (`project(natd VERSION ...)`).
While the major version is 0, a minor release may change the API; a patch
release never does. The wire formats have versions of their own
(`kWireVersion`, `kPeerInfoVersion`, `kOfferWireVersion`), raised only by an
incompatible change of that format; peers with different library versions
interoperate as long as these match. Each release is a tag `vX.Y.Z` and an
entry in [CHANGELOG.md](CHANGELOG.md).

## Standards conformance

natd follows the RFCs it touches on the network, including their SHOULDs.
It departs from them only for a NAT it has measured to be outside them, and
only in ways that serve that NAT.

| Area | Rule | natd |
|---|---|---|
| STUN transaction ID | RFC 8489 §5: cryptographically random | `defaultRandomBytes()` is the OS CSPRNG (`getrandom`, `BCryptGenRandom`, `getentropy`); an injected source must be one too |
| STUN request | §6.1: SOFTWARE in requests | `natd <version>` |
| STUN retransmission | §6.2.1: RTO >= 500 ms, doubling, Rc = 7, failure Rm = 16 RTO after the last; RTO from RFC 6298 (Karn), cached 10 min | `AdvancedConfig::rto`, `stunRc`, `stunRm`; the estimate never goes below `rto` |
| Outstanding transactions | §6.2: at most 10 to one server | `maxOutstanding`; the send order is kept |
| Success response | §6.3.3: unknown comprehension-required attribute = failed transaction; unsupported family ignored | `stun::decodeBinding` (`success = false`) |
| Error response | §6.3.4: the transaction fails | at once, no wait for the timeout |
| After MESSAGE-INTEGRITY | §9: later attributes ignored (but MI-SHA256, FINGERPRINT) | as required |
| RFC 3489 servers | §12: MAPPED-ADDRESS, SOURCE-ADDRESS, CHANGED-ADDRESS | understood |
| Reflector probes | RFC 8085 §3.1.3: request/response with loss detection, initial interval >= 500 ms with exponential backoff | same schedule as STUN, `1 + probeRetries` requests |
| Hairpin test | RFC 8085 §3.1.3 | 3 sends at 0, RTO, 3 RTO |
| Punch | RFC 8085 §3.1.3: no return traffic yet = at most one datagram every 3 s | `punchInterval` >= 3 s (default 4 s), for `planDirect` and `planPunch` |
| Keepalive | RFC 8085 §3.5: >= 15 s, with jitter | stream 20 s + up to 10% random; profile default 15 s |
| Stream | RFC 8085 §3.1: congestion control | the application's transport (the KCP of the tests: normal mode, `nc = 0`) |
| Mapping, filtering, hairpin | RFC 4787 §4.1, §5, REQ-9; RFC 5780 §4.3-4.4 | classified as defined there |
| Mapping lifetime | RFC 4787 REQ-5 (>= 2 min), REQ-6 (outbound refresh) | `mappingLifetime()`: the measurement, else 2 min for an endpoint-independent mapping, else none |
| CGNAT | RFC 6888 REQ-4: port quota | `maxMappings` caps |

Exceptions, each one only after a measurement shows the NAT is outside RFC
4787:

- a binding lifetime shorter than REQ-5's 2 minutes: punch interval and
  keepalive follow the measurement (40% of the single-packet lifetime, 50%
  of the bidirectional one), down to `minInterval`, and `mappingLifetime()`
  gives the measured value;
- a dependent mapping (against REQ-1): `Predict` and the birthday strategies
  send to many ports of the peer's IP within one round; a NAT with
  endpoint-independent mapping never gets them (`Direct`);
- a dependent mapping whose port behaviour could not be tested: reported as
  APDM (`mappingPortTested = false`), the prudent reading.

A STUN transaction runs to its end (39.5 s with the defaults) unless the
discovery no longer needs it: once each open transaction has made
`stunStaleAfter` (4) requests without an answer, a phase that already has
what it needs (a decided mapping, enough samples) ends without them, and an
undecided mapping asks the next servers in parallel. QuickCheck asks its next
STUN server in parallel in the same way. A discovery from which nothing at all
answers therefore ends after about 40 s (before: 2 s).

## Security considerations

natd aims at the security of an unencrypted TCP connection between two
applications, no more.

- **Stream integrity.** A stream accepts a datagram only on the punched
  socket, from the punched remote endpoint, with the session token. The token
  is SHA-256 of what the application gives `tokenFrom`/`sessionTokenFrom`,
  truncated to 96 bits: with a random nonce that only the signalling channel
  carries, an off-path sender has to guess 96 bits (TCP: a 32-bit sequence
  number). Whoever sees the signalling (the two peers, a relay, anyone on the
  path) can derive the token and inject or alter data, as on a plain TCP
  connection. The protocol over the stream must not rely on more. A
  datagram transform that authenticates could be supplied through
  `IDatagramObfuscator`; natd does not ship one.
- **Addresses declared by the peer.** `planPunch` sends to the endpoints in
  the peer's `PeerInfo` (its observed endpoint and, behind the same NAT, up
  to 4 inside addresses), up to `maxPackets` per session with the birthday
  strategies. A peer that declares false addresses makes natd send its punch
  packets there. `planDirect` sends to one endpoint the signalling channel
  observed, a few packets per session.
- **Caps.** Sessions, punches at once and the waiting queue are capped: a
  flood of punch requests can occupy them, so legitimate punches are refused
  meanwhile, but memory and CPU stay bounded.
- **STUN servers.** A lying server can skew a profile; the defences are in
  "Resilience" (double transaction, the IP the others see, two servers
  agreeing). Transaction IDs come from the operating system's CSPRNG.
- **Reflector.** Rate limits per IP; it never sends an IP more bytes than it
  received from it.

## Implementation notes

- **Classification** (`classify.cpp`), in this order: PortPreserving,
  Sequential (constant step <= 16), SequentialNoisy (steps <= 64 with the
  same sign), RandomInBlock (span <= `maxBlockSize`, block aligned to a power
  of two), RandomFull. The confidence of the random case grows with the
  number of samples (1 - 2^(-n/4)), so adaptive sampling asks for another
  round when there are few samples.
- **Adaptive sampling**: each allocation round is classified on its own (the
  `roundGap` pause between rounds would otherwise look like an odd step).
- **Lifetime**: when no delayed reply arrives, `lifetimeMeasured=false` and
  the default timers are used, because a binding shorter than 5 s cannot be
  told apart from replies the reflector dropped.
- **Reflector**: requests are 128 bytes; at most four replies of 28 bytes go
  back to the source (112 bytes), so there is no amplification. Delayed
  replies are capped per endpoint (4), per IP (1024) and in total; beyond the
  cap the reflector answers `Refused` at once, so the client does not mistake
  a refusal for an expired binding (the values are reported unknown, not
  expired).
- **Allocation rate**: for sequential allocators, one extra probe after
  `driftGap` (2 s) measures the ports per second other subscribers take
  (`allocationRate`, estimated with +1). `predictNextPorts` widens its window
  with the age of the observation, taken as uniform up to
  `PunchLimits::observationAge`; probabilities are absolute. With Predict on
  both sides the estimate is P(no drift on A) x P(no drift on B).
- **Packet cap**: `PunchLimits::maxPackets` (2000) caps the PUNCH packets of
  any session whatever the plan; ACKs answer only packets received from the
  peer's IP.
- **Hairpinning**: right after the filtering test, the primary socket and the
  filtering socket send each other a PUNCH at their public endpoints (both
  directions, so that an address-dependent filter opens too). The result is
  `External` (the receiver sees the public endpoint, RFC 4787 REQ-9),
  `Internal` (it sees the internal address) or `None`. A negative result is
  conclusive only with an endpoint-independent mapping, otherwise it stays
  `Unknown`. No extra socket and no extra reflector port.
- **Same NAT** (same public IP on both sides, `PunchPlan::sameNat`): the
  public path counts only with hairpinning as RFC 4787 defines it (REQ-9,
  external source REQ-9a); with `None` or `Internal` its estimate is 0. The
  peer's internal addresses (`PeerInfo::localEndpoints`, at most 4, only RFC
  1918 private or RFC 6598 CGNAT addresses, only when the public IP matches)
  are tried in parallel; without a public path the strategy is `Local`
  (unknown estimate = 0). The session accepts PUNCH only from the signalled
  public IP or from the internal addresses the peer announced, always with
  the token. `localIpToward()` in the adapters finds the internal address
  without sending anything.
- **Punch**: `planPunch` is symmetric (the same `PunchLimits` on both sides).
  In the birthday strategy the stable side sprays a new slice of the range on
  every round, while the hard side keeps its K mappings alive: the success
  estimate counts every round of the budget. Three-way confirmation: punch,
  ACK, ACK. Targets outside `remoteIp` are dropped: the caller must take the
  IP from the signalling channel, not from what the peer declares.
- **Obfuscation** (`IDatagramObfuscator`, optional in `PunchSessionConfig`
  and `StreamConfig`): the application supplies a transformation of the
  datagrams of one session (`wrap` outgoing, `unwrap` incoming; `unwrap`
  returning false means the datagram is not for this session and is left to
  other handlers). natd does no cryptography itself. The same object goes to
  the punch session and to the stream that follows it. Without it the wire
  format is unchanged. This is obfuscation, not secrecy: anyone who knows the
  data the application derives the keys from can read the traffic.
- **Discovery without reflectors**: with STUN servers only, discovery gives a
  partial profile (mapping and allocation; filtering, hairpinning and
  lifetime `Unknown`). `planDirect` serves signalling channels that carry only
  the remote endpoint; `sessionTokenFrom` derives a session token from data
  both peers share.

## Reflector requirements

Recommended deployment:

- **R0**: one public IP, not behind a CGNAT or any NAT, with **one UDP port
  open to everybody** (e.g. 3478). It is the only address clients contact.
  The reflector also opens a second socket (e.g. 3479) for the "from another
  port" reply of the filtering test: that socket only sends, so **the
  firewall can keep it closed for incoming traffic**.
- **R1**: a second public IP, partner of R0 (reciprocal `--partner`), one
  port. It is needed only for the partner reply of the filtering test: it
  receives from R0 and sends to the client. **Its firewall can accept UDP
  from R0 only.**
- **Public STUN servers** as mirrors (`DiscoveryConfig::stunServers`):
  - the "same IP, other port" pair of the mapping test, from servers that
    answer on **two ports of the same IP** (`alt=` in the list): that is the
    only feature required, no special RFC 5780 function (neither
    CHANGE-REQUEST nor RESPONSE-PORT);
  - the second IP of the mapping test (the first port of those same servers);
  - the fresh destinations of the same-socket sample (any server).

Ports open to the public: **1**.

Availability measured on 2026-11-02 against the public list (three identical
runs): 165 of 175 servers answer correctly, **87 also on a second port of the
same IP** (79 on 3479; 76 distinct /16 blocks); by host name, 148 of 211
answer and 73 have the second port. Compared with a two-port deployment only
one role is affected (the mapping pair: from 165 to 87 usable servers); the
other roles keep every server.

The mapping test compares every pair of answered probes (RFC 4787 §4.1): same
IP and a different port with a different mapping = APDM; different IP and the
same mapping = EIM; different IP and a different mapping = ADM if a pair on
the same IP kept the mapping. If the chosen two-port servers do not answer,
discovery tries the next ones at once (at most twice).

Why this works: allocation samples count only the NAT's new mappings, and the
NAT makes one for every new destination, whoever it is; what matters to the
NAT is the destination address, not who answers. A STUN Binding (RFC 8489)
returns the external endpoint just as our probe does. What needs the server's
cooperation stays on our reflector: replies from another port and another IP
(filtering), delayed replies (lifetime), bursts of fresh sockets (allocation,
drift), with tokens and anti-abuse limits. STUN classifies nothing here: it
is only a mirror.

Defences against STUN servers we do not control:

- an answer is accepted only from the address and port queried, on the
  socket that sent, with the same 96-bit transaction id;
- the returned IP must be the one the reflector saw: with "paired" pooling
  (RFC 4787 REQ-2, mandatory for CGNATs in RFC 6888 REQ-2) every mapping of a
  host has the same IP, so a different address is a wrong answer (on the
  public list 2 servers answer with a bogus private address);
- 2 pairs in the mapping test and 2 spare destinations in the sample
  (`mappingStunProbes`, `allocSameSpare`), plus the adaptive second round;
- no reachable two-port server: ADM and APDM can no longer be told apart; a
  dependent mapping is reported as APDM (the prudent choice: same-socket
  sample, one mapping per target) and `mappingPortTested` stays false; ADM
  is rare in CGNATs (RFC 6888 asks for EIM);
- no reachable STUN server: the second IP is lost too (mapping `Unknown`,
  `Inconclusive`). No result becomes wrong.

Server list: `stun::parseServerList` reads the plain-text format of public
lists (one `host[:port]` per line); `stun::builtinServers()` is the fallback
(16 operators, checked on 2026-11-02). `tools/update-stun-list.sh` (Linux) and
`tools/update-stun-list.cmd` (Windows, with the bundled `curl.exe`) download
https://github.com/pradt2/always-online-stun (`valid_hosts.txt`, checked
hourly by its maintainers) and pass it to `natd_stunlist`, which resolves the
names, queries every server and keeps those that answer from the right
address with the IP the majority agrees on. For each one it looks for a
second port on the same IP (the one given in the input, the one announced in
OTHER-ADDRESS, port+1, 3479) and writes it as `alt=`. It writes the 4 fastest
two-port servers first, then the fastest of the others, 24 in all. With fewer
than 10 good servers, or no two-port server, the old list is kept. A typical
run: 211 entries, 157 resolved, 148 answer, 2 dropped for a wrong address,
about 50 s (mostly DNS). Then `natd_probe --stun-list stun-servers.txt`. The
library itself does no DNS and no HTTP.

Checked in the simulator: 90 of 90 classifications in the same class across
the recommended deployment, a two-port deployment and an eight-port one (9
models, 10 seeds; 86 also with the same pattern and step: the others are
sequential allocators read as `SequentialNoisy` with 10 samples instead of 8,
the more faithful reading when other subscribers take ports); port
dependence measured 90/90; R0:p1 and R1 receive nothing from clients; with 0
to 6 dead servers out of 12 the classification stays right (30 of 30, with the
second round); lying servers ignored. Field-by-field comparison (hairpinning,
lifetime, timers, block, drift): identical, except parity and estimated rate
on sequential allocators, which depend on how many mappings were opened
before. netns 6/6: the 4 real Linux NATs with clients contacting R0:3478
only, a firewall dropping UDP to R0:3479 and to R1 unless from R0 (0 packets
dropped, 4 partner replies served), local STUN servers, 4 of them on two
ports. Codec and second-port search tested against the real servers (Linux,
and Windows ARM64 under Wine).

Still possible: a two-port deployment (R0:p0 and R0:p1 open, any STUN server)
and a deployment without STUN, with 8 ports on R0 and R1 (e.g. 4 + 4), empty
`stunServers` and the ports of R1 listed; if R1 has ports, R1:p0 is the
second IP of the mapping test. Below 8 ports the same-socket sample gets
worse (minimum confidence 0.64 with 8, 0.59 with 7, 0.52 with 6, 0.43 with 5;
the `Inconclusive` threshold is 0.4). Clients need no listening ports.

### Resilience

Principle: an infrastructure failure or a misbehaving STUN server makes the
result less precise, never wrong. Failures tested in the simulator and, where
noted, in netns with real sockets:

| Failure | Without the mechanism | With it |
|---|---|---|
| R0 down, no other pair (netns) | `UdpBlocked` | partial profile from STUN: mapping and allocation; filtering, hairpinning and lifetime `Unknown`; `reflectorReached` false |
| R0 down, a second pair configured (netns) | - | moves to the next pair (`reflectors` = pairs R0, R1, ...), full profile |
| R1 down (netns) | EIF read as ADF | ADF with `filteringPartnerTested` false ("ADF or more permissive") |
| R0 without a second socket | ADF read as APDF | APDF with `filteringPortTested` false ("ADF or APDF") |
| Network change during discovery | data from two NATs mixed | restarts once (`restarts`) |
| STUN server with a made-up (random) port | sequential read as random; EIM read as APDM | dropped by the double query |
| STUN server with a fixed wrong port | same | equality wins; a dependent mapping seen through STUN needs 2 agreeing servers (3 without a reflector); up to 2 STUN samples are removed from the sample if the rest is a clean sequence |

Mechanisms:

- **The reflector declares what it can do.** Byte 27 of PROBE_RESP, formerly
  reserved: partner reachable (R0 checks it with a PROBE_REQ every 5 s, alive
  if it answered in the last 16 s), second socket present, and a bit saying
  the fields are valid. An older reflector sends 0, meaning "not declared",
  and the client behaves as before: no version change.
- **Double STUN query.** Two transactions per server from the same socket:
  same mapping, so an honest server reports the same port twice. It costs
  packets, not mappings.
- **Equality cannot be faked.** A server does not know the port another
  destination sees: "same mapping" decides on its own (EIM), "different
  mapping" must be confirmed by more servers.
- **Odd samples.** In the same-socket sample, if the result is not
  sequential, removing one or two STUN samples is tried: only a clean
  sequence over at least 6 samples counts. Reflector samples are never
  removed. On random allocators with liars, 0 sequential readings out of
  108.
- `natd_stunlist` applies the double query and, if at least 80% of the
  servers report the same port (an EIM mapping on the network it runs from),
  drops those that report another one.

The indicators `filteringPortTested`, `mappingPortTested`,
`reflectorReached` and `restarts` are local only and are not part of
`PeerInfo`: the "not verified" values are already the prudent choices for the
planner.

### Requirements per function

Reflector side (public IPs and ports) and client side (mappings created on
the CGNAT, i.e. ports of its per-subscriber block, RFC 6888 REQ-4). Counts
from the code, confirmed in the simulator (`mapping budget` in `natd_tests`).

| Function (RFC) | Reflector | STUN servers | Mappings on the CGNAT |
|---|---|---|---|
| Mapping (4787 §4.1, 5780 §4.3) | R0:p0 | 2 two-port servers (4 probes) | EIM 1, ADM 3, APDM 5 |
| Filtering (4787 §5, 5780 §4.4) | R0:p0; replies from R0:p1 (outgoing only) and partner R1 | 0 | 1 |
| Hairpinning (4787 REQ-9, 5780 §3.4) | 0 | 0 | EIM 0, otherwise 2 |
| Same-socket allocation (APDM only) | 0 | 5 (3 + 2 spare) | 5 |
| Fresh-socket allocation, parity (5128 §3.5, 4787 REQ-4) | 1 | R0:p0 | 16; +32, +64 if needed (EIM: always 16) |
| Drift (sequential only) | 1 | R0:p0 | 1 |
| Lifetime (4787 REQ-5, 5780 §4.6) | 1 | R0:p0 | 20 (2 per grid value, alive up to 180 s) |
| **Total** | **1 public port** (R0) + R0:p1 and R1 closed for incoming traffic | **7** (2 two-port) | see below |

Total mappings for a full discovery (with lifetime), measured over 20 seeds:
EIM 38, sequential ADM 43, sequential APDM 50, random APDM 49 (20 fewer
without lifetime). Worst case, every sampling round needed: 145 without a
cap. The cap `AdvancedConfig::maxMappings` is 100 (0 = none): extra rounds
are shortened or skipped, and lifetime keeps its share (20). Local sockets
open at the same time: at most 64 (one allocation round), 20 during the
lifetime test.

Punch, per session: `Direct` 1 mapping (with APDM one per target, plus up to
4 internal addresses); `Predict` from the EIM side 1; `Predict` with both
sides sequential one per predicted port (15 in the typical simulated case);
`BirthdaySpray` 1 (EIM side); `BirthdayListen` K = `maxSockets` (64). The cap
`PunchLimits::maxMappings` is 128: it limits K and, with APDM mappings, the
targets; the estimate follows the reduced plan and is the same on both sides.

### CGNAT limits (RFC 6888 REQ-4 and REQ-4c)

The simulator models a per-subscriber port quota and a rate limit on new
mappings (the CGNAT drops the packet that would need a refused mapping). The
client does not see the refusal, only a loss, so results become less precise
but not wrong: the classification stays right or becomes `Inconclusive`
(quota from 8 to 64, rate from 5 to 50 per second); the lifetime stays a lower
bound, only lower, hence more prudent timers. With a quota of at least 52
free ports discovery loses nothing. A port block inferred from few samples
(confidence < 0.4) is not used by the birthday strategy, which then sprays
the whole range.

## Status

Tested:

- the `Agent` in the simulator: discovery from STUN servers only, a direct
  punch between two CGNATs, 1 MB over the stream with write back-pressure,
  graceful close, a vanished peer (`Reset` and an endpoint check), a NAT
  that loses its mappings (`EndpointChanged`, streams `AddressChanged`), the
  punch caps and the waiting queue, and no direct punch behind an
  address+port dependent mapping (Linux, UBSan and Wine ARM64);
- the unit and simulation checks on Linux and under UBSan, including 1 MB
  between two EIM + APDF CGNATs with 5% loss, 10 minutes of idle time kept
  open by keepalives, a vanished peer detected, and obfuscated sessions
  (no datagram with the `"NATD"` header on the wire; different keys, or
  obfuscation on one side only, give no session);
- the socket adapter checks on Linux and under Wine ARM64, and cross-platform
  loopback between Linux and Windows;
- memory errors and leaks under Valgrind memcheck (AddressSanitizer does not
  start on the Raspberry Pi kernel): the unit and simulation checks, the
  socket adapter checks and every fuzz target with two seeds, 0 errors and
  no leak (2.47 million allocations in the unit checks, all freed);
- 9 netns cases with real Linux NATs and the recommended deployment, including
  R1 down, failover to a second pair and no reflector at all;
- the standards conformance in the simulator: the STUN retransmission times
  against two dead servers (0, 0.5, 1.5 ... 31.5 s, failure at 39.5 s), at
  most 10 open transactions per server (32 without the limit), error and
  unknown-attribute responses failing at once, and the same classification
  as before on every NAT model; `natd_stunlist` against the public list
  (111 of 158 resolved servers answer the new requests correctly);
- fuzzing of every target with several seeds, under UBSan and under Wine
  ARM64 (the `agent` target: 3 x 20000 inputs under UBSan, every one with a
  profile, about 36000 sessions each run). It found two bugs, both fixed: `formatServerList` wrote a host named
  `stun` in a form that read back as the `stun:` prefix, and `allocationRate`
  in `PeerInfo` was truncated instead of rounded.

Not tested yet:

1. Running the test package on real Windows x86_64 (`dist/natd-win-x64`).
2. A LAN test with the reflector on another machine (needs administrator
   rights only to open the Windows firewall for incoming traffic).
3. A real carrier NAT or CGNAT (so far only netfilter in network namespaces).
4. Full discovery against public R0/R1 reflectors and Internet STUN servers:
   this needs two public IPs; real STUN servers have been exercised only by
   `natd_stunlist` (codec and list).
5. A real punch between two applications behind NATs on the Internet (for
   eMule: two LowIDs finding each other through Kad).
6. Static analysis (clang-tidy, cppcheck, MSVC `/analyze`).
7. A long run: hours of discovery, endpoint checks and sessions opening and
   closing, watching memory, sockets and counters.
8. The cost of a stream (CPU per MB through `Stream` and a transport)
   against TCP.

Positive hairpinning is verified only in the simulator: Linux masquerade does
not hairpin (netns: `hairpin=None`), and a hairpinning Linux NAT needs a DNAT
rule per mapping.

Principle: strict adherence to the RFCs (4787, 5780, 6888 for the NAT;
8489 and 8085 for what natd sends, see "Standards conformance"), with no
invented handling for behaviour they do not recommend. In particular:

- peers behind the same CGNAT with different IPs from its pool are treated as
  different NATs; the normal punch goes through the NAT (hairpinning towards
  the pool);
- "arbitrary" pooling (discouraged by RFC 4787 REQ-2): `multiplePublicIps` is
  measured and reported, but the planner and the session do not handle it;
- `Internal` hairpinning (against REQ-9a) is treated as absent, with no
  learning of internal sources that were not announced.

Remaining choices: hard + hard = `Infeasible`; IPv4 only; UPnP, NAT-PMP and
PCP are out of scope (other libraries cover them, and they do not help
against a CGNAT).

## License

natd is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later
version. See [COPYING](COPYING).

The library has no third-party code. `tests/kcp/` (tests and fuzz driver
only) is KCP by Lin Wei, under the MIT licence (`tests/kcp/LICENSE`), which
is compatible with the GPL.
