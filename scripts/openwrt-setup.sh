#!/bin/sh
# Run on the OpenWrt router: install the tc/eBPF prerequisites.
set -eu

opkg update
opkg install tc-bpf kmod-sched-core kmod-sched-bpf
