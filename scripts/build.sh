#!/usr/bin/env bash
# Cross-compile the tc/eBPF object.  Run this on a Linux box with clang,
# llvm and libbpf headers (the VPS is the intended builder).
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SERVER_IP=${SERVER_IP:?set SERVER_IP to the SOCKS5 server IPv4 address}
SERVER_PORT=${SERVER_PORT:-1080}
BPF_TARGET=${BPF_TARGET:-bpfel}   # reference box is mipsel_24kc; use bpfeb for BE
OUT=${OUT:-$ROOT/build/s0cks5.o}

python3 - "$SERVER_IP" <<'PY'
import ipaddress
import sys

try:
    ipaddress.IPv4Address(sys.argv[1])
except ValueError as exc:
    raise SystemExit(f"SERVER_IP is not an IPv4 address: {exc}")
PY

IP_HEX=$(python3 - "$SERVER_IP" <<'PY'
import ipaddress
import sys

print(hex(int(ipaddress.IPv4Address(sys.argv[1]))))
PY
)

mkdir -p "$(dirname -- "$OUT")"

set -x
clang \
	-target "$BPF_TARGET" \
	-O2 -g -Wall -Wextra -Wno-unused-parameter \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu \
	-DSERVER_IP="$IP_HEX" \
	-DSERVER_PORT="$SERVER_PORT" \
	-c "$ROOT/bpf/s0cks5.c" \
	-o "$OUT"
set +x

echo "built $OUT (target=$BPF_TARGET server=$SERVER_IP:$SERVER_PORT)"
