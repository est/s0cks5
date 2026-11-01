#!/bin/sh
# Run on the OpenWrt router.  Usage: openwrt-detach.sh [dev]
set -eu

DEV=${1:-wan}

tc filter del dev "$DEV" egress 2>/dev/null || true
tc filter del dev "$DEV" ingress 2>/dev/null || true
tc qdisc del dev "$DEV" clsact 2>/dev/null || true

echo "detached from $DEV"
