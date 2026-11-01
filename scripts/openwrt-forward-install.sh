#!/bin/sh
# Run on the OpenWrt router.  Installs and starts a procd-managed socat
# forwarder:  LISTEN_ADDR:LISTEN_PORT  ->  SERVER_IP:SERVER_PORT
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

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_SRC=$SCRIPT_DIR/openwrt-forward.init
INIT_DST=/etc/init.d/s0cks5-forward
CONF=/etc/s0cks5-forward.conf

if ! command -v socat >/dev/null 2>&1; then
	opkg update
	opkg install socat
fi

umask 077
cat >"$CONF" <<EOF
LISTEN_ADDR='$LISTEN_ADDR'
LISTEN_PORT='$LISTEN_PORT'
SERVER_ADDR='$SERVER_IP'
SERVER_PORT='$SERVER_PORT'
EOF

install -m 0755 "$INIT_SRC" "$INIT_DST"

# If a manual socat from an earlier experiment is still holding the port,
# stop it so procd can bind.  Match only the listener for this port.
for pid in $(ps 2>/dev/null | awk '/[s]ocat TCP-LISTEN:'"$LISTEN_PORT"'/ { print $1 }'); do
	kill "$pid" 2>/dev/null || true
done

"$INIT_DST" stop 2>/dev/null || true
"$INIT_DST" enable
"$INIT_DST" restart
sleep 1

echo "forwarding $LISTEN_ADDR:$LISTEN_PORT -> $SERVER_IP:$SERVER_PORT"
netstat -ltn 2>/dev/null | grep -E "[:.]$LISTEN_PORT[[:space:]]" || true
