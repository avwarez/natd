#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 avwarez
# Refreshes the STUN server list used by natd_probe (--stun-list).
#
#   tools/update-stun-list.sh [build-dir] [output-file]
#
# Downloads a public list checked hourly by its maintainers, then keeps only
# the servers that answer correctly from here (natd_stunlist). On any failure
# the previous list is left untouched.
set -euo pipefail
BUILD=${1:-$(dirname "$0")/../build-cmake}
OUT=${2:-stun-servers.txt}
URL=${NATD_STUN_LIST_URL:-https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt}
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
curl -fsSL --max-time 30 "$URL" -o "$RAW"
"$BUILD/natd_stunlist" --in "$RAW" --out "$OUT" --keep 24 --min 10
