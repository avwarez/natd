#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 avwarez
# natd end-to-end test on real Linux NATs (network namespaces + nftables).
#
#   sudo tests/netns/run.sh [build-dir]
#
# PROBE_CMD overrides the client command, e.g. the Windows build under Wine
# run as an unprivileged user inside the client namespace:
#   sudo PROBE_CMD="sudo -u $USER env WINEPREFIX=$HOME/.wine-natd WINEDEBUG=-all wine build-win/natd_probe.exe" \
#        tests/netns/run.sh build-cmake
#
# Topology (three fresh namespaces, nothing changes on the host):
#
#   natd-c  10.0.0.2 ──veth── 10.0.0.1  natd-n  198.51.100.1 ──veth── natd-i  198.51.100.10 (R0, port 3478 public)
#   client                    NAT (nftables masquerade)                        198.51.100.11 (R1, partner only)
#                                                                              198.51.100.20-29 (STUN servers)
#
# Deployment "option 1": clients reach R0 on one port (3478). R0 also runs a
# socket on 3479 for the filtering test's "other port" reply, but a firewall
# in natd-i drops inbound UDP to it; another rule drops whatever reaches R1
# from anyone but R0 (R1 serves only the partner link). The mapping test's
# same-IP pair and second IP and the same-socket samples come from ten STUN
# servers (tests/netns/stun_server.py), four of them on two ports.
# Each case installs one masquerade variant in natd-n, runs natd_probe in
# natd-c and checks the profile.
# Namespaces are removed on exit, whatever happens.
set -euo pipefail

BUILD=${1:-$(dirname "$0")/../../build-cmake}
BUILD=$(cd "$BUILD" && pwd)
PROBE=$BUILD/natd_probe
REFL=$BUILD/natd_reflector
[[ -x $PROBE && -x $REFL ]] || { echo "build natd_probe and natd_reflector first ($BUILD)"; exit 2; }
PROBE_CMD=${PROBE_CMD:-$PROBE}
[[ $EUID -eq 0 ]] || { echo "needs root: sudo $0 $*"; exit 2; }

C=natd-c N=natd-n I=natd-i
LOG=$(mktemp -d /tmp/natd-netns.XXXXXX)
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    for ns in $C $N $I; do ip netns del $ns 2>/dev/null || true; done
}
trap cleanup EXIT

for ns in $C $N $I; do
    if ip netns list | grep -qw "$ns"; then echo "namespace $ns already exists, refusing to touch it"; exit 2; fi
done

ip netns add $C; ip netns add $N; ip netns add $I
ip link add c0 netns $C type veth peer name n0 netns $N
ip link add n1 netns $N type veth peer name i0 netns $I
ip -n $C addr add 10.0.0.2/24 dev c0
ip -n $N addr add 10.0.0.1/24 dev n0
ip -n $N addr add 198.51.100.1/24 dev n1
ip -n $I addr add 198.51.100.10/24 dev i0
ip -n $I addr add 198.51.100.11/24 dev i0
for k in 12 13 $(seq 20 29); do ip -n $I addr add 198.51.100.$k/24 dev i0; done
for ns in $C $N $I; do ip -n $ns link set lo up; done
ip -n $C link set c0 up; ip -n $N link set n0 up; ip -n $N link set n1 up; ip -n $I link set i0 up
ip -n $C route add default via 10.0.0.1
ip netns exec $N sysctl -qw net.ipv4.ip_forward=1

# R0 accepts UDP on 3478 only; R1 accepts UDP only from R0 (the partner
# link); the rest is dropped and counted
# (ICMP errors from the NAT, e.g. after a filtered partner reply, are not UDP).
ip netns exec $I nft -f - <<EOF
table ip r1guard {
    chain in { type filter hook input priority 0;
        ip daddr 198.51.100.11 ip saddr != 198.51.100.10 meta l4proto udp counter drop
        ip daddr 198.51.100.10 udp dport 3479 counter drop; }
}
EOF
ip netns exec $I "$REFL" --ip 198.51.100.10 --ports 3478-3479 --partner 198.51.100.11:3478 >"$LOG/r0.log" 2>&1 &
R0PID=$!; PIDS+=($R0PID)
ip netns exec $I "$REFL" --ip 198.51.100.11 --ports 3478 --partner 198.51.100.10:3478 >"$LOG/r1.log" 2>&1 &
R1PID=$!; PIDS+=($R1PID)
# Second reflector pair, for the failover case.
ip netns exec $I "$REFL" --ip 198.51.100.12 --ports 3478-3479 --partner 198.51.100.13:3478 >"$LOG/r2.log" 2>&1 &
PIDS+=($!)
ip netns exec $I "$REFL" --ip 198.51.100.13 --ports 3478 --partner 198.51.100.12:3478 >"$LOG/r3.log" 2>&1 &
PIDS+=($!)
STUN_EPS=() STUN_LIST=("# local STUN servers, 20-23 on two ports")
for k in $(seq 20 29); do
    p=$(( k % 3 == 1 ? 19302 : 3478 ))
    STUN_EPS+=("198.51.100.$k:$p")
    if ((k <= 23)); then STUN_EPS+=("198.51.100.$k:$((p + 1))"); STUN_LIST+=("198.51.100.$k:$p alt=$((p + 1))")
    else STUN_LIST+=("198.51.100.$k:$p"); fi
done
printf '%s\n' "${STUN_LIST[@]}" >"$LOG/stun-servers.txt"
ip netns exec $I python3 "$(dirname "$0")/stun_server.py" "${STUN_EPS[@]}" >"$LOG/stun.log" 2>&1 &
PIDS+=($!)
sleep 0.5

PASS=0 FAIL=0
# conntrack(8) may be missing, so old entries cannot be flushed: every case
# uses its own primary port, so that no tuple from a previous rule is reused.
PORT=4662
field() { grep '^final ' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }

# run_case NAME "nft masquerade statement" PROBE_ARGS -- key=value ...
# REFLECTORS overrides the reflector options (default: the first pair).
REFLECTORS_DEFAULT="--reflector 198.51.100.10:3478 --reflector 198.51.100.11"
run_case() {
    local name=$1 masq=$2 args=$3; shift 4
    local refl=${REFLECTORS:-$REFLECTORS_DEFAULT}
    ip netns exec $N nft flush ruleset
    PORT=$((PORT + 10))
    ip netns exec $N nft -f - <<EOF
table ip nat {
    chain post { type nat hook postrouting priority srcnat; oifname "n1" $masq; }
}
EOF
    local out=$LOG/$name.out
    local t0=$SECONDS
    # shellcheck disable=SC2086  # PROBE_CMD is a command line on purpose
    if ! ip netns exec $C $PROBE_CMD --bind 10.0.0.2 --port $PORT \
            $refl --stun-list "$LOG/stun-servers.txt" \
            $args >"$out" 2>&1; then
        echo "FAIL $name: probe did not finish"; cat "$out"; FAIL=$((FAIL + 1)); return
    fi
    local ok=1 msg=""
    for kv in "$@"; do
        local k=${kv%%=*} want=${kv#*=} got
        got=$(field "$out" "$k")
        if [[ $want == \~* ]]; then         # ~regex
            [[ $got =~ ${want#\~} ]] || { ok=0; msg+=" $k=$got (want ${want#\~})"; }
        else
            [[ $got == "$want" ]] || { ok=0; msg+=" $k=$got (want $want)"; }
        fi
    done
    local summary
    summary=$(grep '^final ' "$out" | cut -d' ' -f2-6)
    if ((ok)); then echo "PASS $name ($((SECONDS - t0))s): $summary"; PASS=$((PASS + 1))
    else echo "FAIL $name:$msg"; grep '^final ' "$out"; FAIL=$((FAIL + 1)); fi
}

# 1. Plain masquerade: Linux keeps the source port when it can and reuses it
#    for every destination -> endpoint-independent mapping in practice;
#    conntrack filters by full 5-tuple -> address+port dependent filtering.
#    No hairpinning: a packet to the NAT's own public address is delivered to
#    the NAT box itself, not translated back (no DNAT rule).
#    Conntrack UDP timeout lowered in natd-n only to keep the lifetime test short.
ip netns exec $N sysctl -qw net.netfilter.nf_conntrack_udp_timeout=12 2>/dev/null || true
ip netns exec $N sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=60 2>/dev/null || true
run_case masquerade "masquerade" "--grid 5,10,15,20" -- \
    predictability=Stable mapping=EndpointIndependent filtering=AddressPortDependent behindNat=1 \
    public=198.51.100.1:4672 new=PortPreserving lifetimeMeasured=1 single=10 bidir=10 hairpin=None

# 2. Random port per new conntrack -> symmetric, random over the range.
run_case random "masquerade random" "--no-lifetime" -- \
    predictability=Unpredictable mapping=AddressPortDependent filtering=AddressPortDependent new=RandomFull \
    hairpin=Unknown

# 3. Random inside a 2048-port block -> Bounded, block found.
run_case block "meta l4proto udp masquerade to :20480-22527 random" "--no-lifetime" -- \
    predictability=Bounded mapping=AddressPortDependent same=RandomInBlock 'same.block=~^(20480\+2048|20480\+4096|16384\+8192|18432\+4096)$'

# 4. fully-random (PRNG instead of a hash): same class as 2.
run_case fully-random "masquerade fully-random" "--no-lifetime" -- \
    predictability=Unpredictable mapping=AddressPortDependent

# 5-7. Infrastructure faults: never a wrong result.
# R1 down: the partner check fails, R0 declares it (caps), the filtering is
# flagged as partner-untested instead of being trusted.
kill $R1PID; sleep 17   # > partnerTimeout (16 s)
run_case r1-down "masquerade" "--no-lifetime" -- \
    predictability=Stable filtering=AddressPortDependent partnerTested=0 portTested=1 reflector=1
# R0 down too: the second pair takes over, full profile.
kill $R0PID; sleep 0.2
REFLECTORS="$REFLECTORS_DEFAULT --reflector 198.51.100.12:3478 --reflector 198.51.100.13" \
run_case failover "masquerade" "--no-lifetime" -- \
    predictability=Stable mapping=EndpointIndependent filtering=AddressPortDependent partnerTested=1 reflector=1
# No reflector reachable: partial profile from the STUN servers, not UdpBlocked.
run_case no-reflector "masquerade" "--no-lifetime" -- \
    predictability=Stable mapping=EndpointIndependent filtering=Unknown reflector=0 lifetimeMeasured=0

echo "reflector counters:"; kill "${PIDS[@]}" 2>/dev/null || true; wait 2>/dev/null || true; PIDS=()
cat "$LOG/r0.log" "$LOG/r1.log" "$LOG/r2.log" "$LOG/r3.log" "$LOG/stun.log"
# Option 1: nobody tried R0:3479 or R1 (both firewall counters 0), yet R1
# served the partner replies and R0 the "other port" replies of the filtering
# test, which both pass the filtering cases above.
r1=$(grep '^requests=' "$LOG/r1.log")
dropped=$(ip netns exec $I nft list table ip r1guard | sed -n 's/.*packets \([0-9]*\).*/\1/p' | paste -sd+ | bc)
# (R1's own request counter also holds R0's partner checks.)
if [[ $r1 =~ forwardsServed=([1-9][0-9]*) && $dropped == 0 ]]; then
    echo "PASS option 1: only R0:3478 contacted (${BASH_REMATCH[0]} on R1, firewall drops $dropped)"; PASS=$((PASS + 1))
else
    echo "FAIL option 1: R1 $r1, firewall drops $dropped"; FAIL=$((FAIL + 1))
fi
if grep -q 'binding requests served' "$LOG/stun.log" && ! grep -q ': 0 binding' "$LOG/stun.log"; then
    echo "PASS STUN servers used: $(grep -o '[0-9]* binding requests' "$LOG/stun.log")"; PASS=$((PASS + 1))
else
    echo "FAIL STUN servers unused"; FAIL=$((FAIL + 1))
fi
echo "netns: $PASS passed, $FAIL failed (logs in $LOG)"
((FAIL == 0))
