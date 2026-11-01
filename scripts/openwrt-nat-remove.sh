#!/bin/sh
# Run on the OpenWrt router: remove the kernel NAT rule.
set -eu

/etc/init.d/s0cks5-nat stop 2>/dev/null || true
/etc/init.d/s0cks5-nat disable 2>/dev/null || true
rm -f /etc/init.d/s0cks5-nat /etc/s0cks5-nat.conf
echo "kernel NAT rule removed"
echo "to go back to socat: /etc/init.d/s0cks5-forward enable && /etc/init.d/s0cks5-forward start"
