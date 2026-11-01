#!/bin/sh
# Rebuild the eBPF object for a changed VPS endpoint and re-attach it.
#
# Usage:
#   SERVER_IP=203.0.113.10 SERVER_PORT=1080 \
#       ROUTER=root@192.0.2.10 ./scripts/redeploy-openwrt.sh [dev]
#
#   SKIP_BUILD=1 ...   reuse an existing build/s0cks5.o
#
# Run this on the Linux build host (clang + libbpf headers).  It copies the
# object and openwrt-attach.sh to the router's home directory, then attaches.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SERVER_IP=${SERVER_IP:?set SERVER_IP to the VPS/SOCKS5 server IPv4 address}
SERVER_PORT=${SERVER_PORT:-1080}
ROUTER=${ROUTER:?set ROUTER to user@router-address}
DEV=${1:-wan}
BPF_TARGET=${BPF_TARGET:-bpfel}
OBJ=${OBJ:-$ROOT/build/s0cks5.o}
SCP_OPTS=${SCP_OPTS:--O}   # OpenWrt/dropbear has no sftp-server

if [ "${SKIP_BUILD:-0}" = "1" ]; then
	[ -f "$OBJ" ] || {
		echo "missing $OBJ; build it first" >&2
		exit 1
	}
	echo "warning: SKIP_BUILD=1 cannot verify that $OBJ was built for $SERVER_IP:$SERVER_PORT" >&2
else
	SERVER_IP="$SERVER_IP" SERVER_PORT="$SERVER_PORT" \
		BPF_TARGET="$BPF_TARGET" OUT="$OBJ" \
		"$ROOT/scripts/build.sh"
fi

# shellcheck disable=SC2086
scp $SCP_OPTS "$OBJ" "$ROOT/scripts/openwrt-attach.sh" "$ROUTER:"
ssh "$ROUTER" "sh ./openwrt-attach.sh '$DEV' ./s0cks5.o"

echo
echo "eBPF redeployed for $SERVER_IP:$SERVER_PORT on $DEV"
echo "If the VPS endpoint changed, also re-run openwrt-nat-install.sh or openwrt-forward-install.sh on the router."
