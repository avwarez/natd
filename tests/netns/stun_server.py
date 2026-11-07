#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 avwarez
"""Minimal STUN Binding server (RFC 8489) for the netns test only.

    stun_server.py IP:PORT [IP:PORT ...]

Answers Binding requests with XOR-MAPPED-ADDRESS from the address they were
sent to. Prints the number of requests served on SIGTERM.
"""
import select, signal, socket, struct, sys

MAGIC = 0x2112A442
socks = []
for spec in sys.argv[1:]:
    ip, port = spec.rsplit(':', 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, int(port)))
    socks.append(s)
served = 0

def stop(*_):
    print(f"stun: {served} binding requests served on {len(socks)} addresses", flush=True)
    sys.exit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
print(f"stun: listening on {len(socks)} addresses", flush=True)
while True:
    for s in select.select(socks, [], [])[0]:
        d, (ip, port) = s.recvfrom(2048)
        if len(d) < 20 or d[0:2] != b'\x00\x01' or struct.unpack('!I', d[4:8])[0] != MAGIC:
            continue
        xip = struct.unpack('!I', socket.inet_aton(ip))[0] ^ MAGIC
        attr = struct.pack('!HHBBHI', 0x0020, 8, 0, 1, port ^ (MAGIC >> 16), xip)
        s.sendto(struct.pack('!HHI', 0x0101, len(attr), MAGIC) + d[8:20] + attr, (ip, port))
        served += 1
