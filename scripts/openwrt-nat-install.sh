#!/bin/sh
# Run on the OpenWrt router.  Installs a kernel DNAT+SNAT hairpin so clients
# can use the router's address as the SOCKS5 endpoint.
#
# Required:
#   SERVER_IP=203.0.113.10
# Optional:
#   SERVER_PORT=1080
#   LISTEN_ADDR=any              # any local IPv4 (LAN and WAN), or a specific IP
#   LISTEN_PORT=1080
#
# Re-running this replaces /etc/s0cks5-nat.conf and deletes old rules, so a
# wrong previous IP or port is removed before the new rule is installed.
set -eu

SERVER_IP=${SERVER_IP:?set SERVER_IP to the VPS/SOCKS5 server IPv4 address}
SERVER_PORT=${SERVER_PORT:-1080}
LISTEN_PORT=${LISTEN_PORT:-1080}
LISTEN_ADDR=${LISTEN_ADDR:-any}

valid_ipv4() {
	echo "$1" | awk -F. '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= 4; i++) {
				if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255)
					exit 1
			}
			exit 0
		}'
}

valid_port() {
	case "$1" in
		'' | *[!0-9]*) return 1 ;;
	esac
	[ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_ipv4 "$SERVER_IP" || {
	echo "invalid SERVER_IP: $SERVER_IP" >&2
	exit 1
}
valid_port "$SERVER_PORT" || {
	echo "invalid SERVER_PORT: $SERVER_PORT" >&2
	exit 1
}
valid_port "$LISTEN_PORT" || {
	echo "invalid LISTEN_PORT: $LISTEN_PORT" >&2
	exit 1
}
if [ "$LISTEN_ADDR" != "any" ]; then
	valid_ipv4 "$LISTEN_ADDR" || {
		echo "invalid LISTEN_ADDR: $LISTEN_ADDR" >&2
		exit 1
	}
fi

command -v nft >/dev/null 2>&1 || {
	echo "nft is missing; install nftables/kmod-nft-nat" >&2
	exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_SRC=$SCRIPT_DIR/openwrt-nat.init
HOTPLUG_SRC=$SCRIPT_DIR/openwrt-nat.hotplug
INIT_DST=/etc/init.d/s0cks5-nat
HOTPLUG_DST=/etc/hotplug.d/iface/90-s0cks5-nat
CONF=/etc/s0cks5-nat.conf

if [ -r "$CONF" ]; then
	echo "replacing existing NAT config:"
	sed -n 's/^/  /p' "$CONF"
fi

umask 077
cat >"$CONF" <<EOF
LISTEN_ADDR='$LISTEN_ADDR'
LISTEN_PORT='$LISTEN_PORT'
SERVER_ADDR='$SERVER_IP'
SERVER_PORT='$SERVER_PORT'
EOF

cp "$INIT_SRC" "$INIT_DST"
chmod 0755 "$INIT_DST"
mkdir -p "$(dirname "$HOTPLUG_DST")"
cp "$HOTPLUG_SRC" "$HOTPLUG_DST"
chmod 0755 "$HOTPLUG_DST"

# The user-space socat forwarder and the kernel rule are alternatives.
if [ -x /etc/init.d/s0cks5-forward ]; then
	/etc/init.d/s0cks5-forward stop 2>/dev/null || true
	/etc/init.d/s0cks5-forward disable 2>/dev/null || true
	echo "disabled the socat forwarder (s0cks5-forward)"
fi

# Remove the current table and any legacy names from earlier experiments.
for table in s0cks5nat s0cks5_nat s0cks5; do
	nft delete table ip "$table" 2>/dev/null || true
done

"$INIT_DST" enable
"$INIT_DST" restart
sleep 1

echo "DNAT $LISTEN_ADDR:$LISTEN_PORT -> $SERVER_IP:$SERVER_PORT (kernel nat)"
nft list table ip s0cks5nat
