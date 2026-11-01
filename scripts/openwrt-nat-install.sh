#!/bin/sh
# Run on the OpenWrt router.  Installs a kernel DNAT+SNAT rule so clients can
# use the router's LAN address as the SOCKS5 endpoint.
#
# Required:
#   SERVER_IP=203.0.113.10
# Optional:
#   SERVER_PORT=1080
#   LISTEN_ADDR=<router LAN IP, default: network.lan.ipaddr>
#   LISTEN_PORT=1080
set -eu

SERVER_IP=${SERVER_IP:?set SERVER_IP to the VPS/SOCKS5 server IPv4 address}
SERVER_PORT=${SERVER_PORT:-1080}
LISTEN_PORT=${LISTEN_PORT:-1080}

if [ -z "${LISTEN_ADDR:-}" ]; then
	LISTEN_ADDR=$(uci get network.lan.ipaddr 2>/dev/null || true)
fi
[ -n "$LISTEN_ADDR" ] || {
	echo "set LISTEN_ADDR to the router's LAN address" >&2
	exit 1
}
command -v nft >/dev/null 2>&1 || {
	echo "nft is missing; install nftables/kmod-nft-nat" >&2
	exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_SRC=$SCRIPT_DIR/openwrt-nat.init
INIT_DST=/etc/init.d/s0cks5-nat
CONF=/etc/s0cks5-nat.conf

umask 077
cat >"$CONF" <<EOF
LISTEN_ADDR='$LISTEN_ADDR'
LISTEN_PORT='$LISTEN_PORT'
SERVER_ADDR='$SERVER_IP'
SERVER_PORT='$SERVER_PORT'
EOF

cp "$INIT_SRC" "$INIT_DST"
chmod 0755 "$INIT_DST"

# The user-space socat forwarder and the kernel rule are alternatives.
if [ -x /etc/init.d/s0cks5-forward ]; then
	/etc/init.d/s0cks5-forward stop 2>/dev/null || true
	/etc/init.d/s0cks5-forward disable 2>/dev/null || true
	echo "disabled the socat forwarder (s0cks5-forward)"
fi

"$INIT_DST" enable
"$INIT_DST" restart
sleep 1

echo "DNAT $LISTEN_ADDR:$LISTEN_PORT -> $SERVER_IP:$SERVER_PORT (kernel nat)"
nft list table ip s0cks5nat
