#!/bin/sh
# Run on the OpenWrt router: remove the LAN-facing SOCKS5 forwarder.
set -eu

/etc/init.d/s0cks5-forward stop 2>/dev/null || true
/etc/init.d/s0cks5-forward disable 2>/dev/null || true
rm -f /etc/init.d/s0cks5-forward /etc/s0cks5-forward.conf
echo "s0cks5 forwarder removed"
