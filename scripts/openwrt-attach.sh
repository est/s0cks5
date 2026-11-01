#!/bin/sh
# Run on the OpenWrt router.  Usage: openwrt-attach.sh [dev] [object]
set -eu

DEV=${1:-wan}
OBJ=${2:-/root/s0cks5.o}

command -v tc >/dev/null 2>&1 || {
	echo "tc is missing: opkg install tc-bpf kmod-sched-core kmod-sched-bpf" >&2
	exit 1
}
[ -f "$OBJ" ] || {
	echo "missing BPF object: $OBJ" >&2
	exit 1
}

# This replaces the clsact qdisc on DEV, so existing tc filters there are lost.
# Idempotent: drop stale filters/qdisc first.
tc qdisc del dev "$DEV" clsact 2>/dev/null || true
tc qdisc add dev "$DEV" clsact
tc filter add dev "$DEV" egress bpf da obj "$OBJ" sec tc
tc filter add dev "$DEV" ingress bpf da obj "$OBJ" sec tc

echo "attached $OBJ to $DEV (egress+ingress)"
tc filter show dev "$DEV" egress
tc filter show dev "$DEV" ingress
