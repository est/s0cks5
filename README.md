# s0cks5

SOCKS5 is fixed by RFC1928: a CONNECT request starts `05 01 00 ATYP`, and
DPI boxes love that signature. This experiment keeps the protocol but swaps
the version byte on the wire with `tc`/eBPF, then restores it on the way back.

Use it only on networks you own or are explicitly authorized to test.

## Wire format

| direction       | normal SOCKS5        | on the wire          |
| --------------- | -------------------- | -------------------- |
| client → server | `05 NN methods...`   | `16 NN methods...`   |
| client → server | `05 01 00 ATYP ...`  | `16 01 00 ATYP ...`  |
| server → client | `05 00`              | `16 00`              |
| server → client | `05 REP 00 ATYP ...` | `16 REP 00 ATYP ...` |

Only the first two control messages in each direction are touched. The
rewrite is length-preserving, so TCP sequence numbers never move. The server
speaks the mutated format directly; it does not run eBPF.

```
stock client → router tc/eBPF → mutated SOCKS5 → server
```

The router can also terminate the SOCKS5 endpoint (`socat` or DNAT); see below.

## Requirements

OpenWrt router:

```sh
opkg update
opkg install tc-bpf kmod-sched-core kmod-sched-bpf
# scripts/openwrt-setup.sh does this
```

Build host (Linux with clang; the VPS is fine):

```sh
apt-get install clang llvm libbpf-dev linux-libc-dev
```

Server: Python 3 and the standard library. Router endpoint: `socat` or
`nftables` with `kmod-nft-nat`.

## Build and attach

```sh
SERVER_IP=203.0.113.10 SERVER_PORT=1080 ./scripts/build.sh
# build/s0cks5.o; bpfel is the default, use BPF_TARGET=bpfeb for big-endian

scp build/s0cks5.o scripts/openwrt-attach.sh root@192.0.2.10:
ssh root@192.0.2.10 './openwrt-attach.sh wan ./s0cks5.o'
```

Attach to the interface that actually carries client traffic. On a bridge
that is the uplink slave port (`wan`), not `br-lan`.

Detach with `./openwrt-detach.sh wan`.

### Changing the VPS IP or port

`SERVER_IP` and `SERVER_PORT` are compiled into the eBPF object. Changing them
in the router forwarder/NAT alone is not enough. Rebuild and re-attach:

```sh
SERVER_IP=203.0.113.10 SERVER_PORT=1080 \
    ROUTER=root@192.0.2.10 ./scripts/redeploy-openwrt.sh wan
```

`SKIP_BUILD=1` reuses an existing `build/s0cks5.o`. Also re-run the router
endpoint installer if the VPS address changed (below).

## Run the server

```sh
python3 server/mutated_socks5.py --bind 0.0.0.0 --port 1080 -v
```

The source allowlist is optional:

```sh
printf '203.0.113.10/32\n' > /etc/s0cks5-allow.txt
python3 server/mutated_socks5.py --bind 0.0.0.0 --port 1080 \
    --allow-file /etc/s0cks5-allow.txt -v
```

Without `--allow`/`--allow-file`, any source is accepted. With either, only
listed CIDRs are accepted and everything else gets a TCP RST. `SIGHUP` reloads
the file. Invalid, TLS/HTTP-like and silent probes are reset; 3 bad handshakes
trigger a temporary ban. Defaults: 3 s handshake timeout, 8 connections/IP,
60 new connections/min/IP, 5 minute ban. Tune with `--handshake-timeout`,
`--max-per-ip`, `--rate`, `--ban-after`, `--ban-time`. `--allow-plain` is
debug-only.

## Make the router the SOCKS5 endpoint

### socat (portable)

```sh
scp scripts/openwrt-forward* root@192.0.2.10:
ssh root@192.0.2.10 \
    'SERVER_IP=203.0.113.10 SERVER_PORT=1080 \
     LISTEN_ADDR=192.0.2.10 LISTEN_PORT=1080 \
     ./openwrt-forward-install.sh'
```

Clients use `192.0.2.10:1080`. The LAN leg is normal SOCKS5; the router → VPS
leg is a new connection that the eBPF mutates. Remove with
`./openwrt-forward-remove.sh`.

### Kernel NAT (no socat)

DNAT redirects the connection; a `ct status dnat` masquerade handles the
return path:

```sh
nft add table ip s0cks5nat
nft add chain ip s0cks5nat prerouting \
    '{ type nat hook prerouting priority -110; policy accept; }'
nft add rule ip s0cks5nat prerouting \
    fib daddr type local ip daddr != 127.0.0.0/8 \
    tcp dport 1080 dnat to 203.0.113.10:1080
nft add chain ip s0cks5nat postrouting \
    '{ type nat hook postrouting priority 110; policy accept; }'
nft add rule ip s0cks5nat postrouting \
    ct status dnat ip daddr 203.0.113.10 tcp dport 1080 masquerade
```

Install it as a boot-time service instead:

```sh
scp scripts/openwrt-nat* root@192.0.2.10:
ssh root@192.0.2.10 \
    'SERVER_IP=203.0.113.10 SERVER_PORT=1080 \
     LISTEN_ADDR=any LISTEN_PORT=1080 \
     ./openwrt-nat-install.sh'
```

`LISTEN_ADDR=any` matches every local IPv4 address (LAN, WAN, aliases, future
DHCP changes); set a specific address to restrict exposure. The installer
validates IP/ports, replaces the old config/rules, disables socat, and enables
`S99s0cks5-nat` plus an `ifup` hotplug hook. `fw4 reload` leaves the table
intact. Re-run it after a VPS IP change, and remember the eBPF rebuild above.

## Test

```sh
curl --socks5-hostname 192.0.2.10:1080 http://example.com/
# direct to the VPS:
curl --socks5-hostname 203.0.113.10:1080 http://example.com/
```

On the server:

```sh
tcpdump -i eth0 -nn -X 'tcp port 1080'
```

Expect `16 ...` control messages, not `05 01 00`. Local server-only test:

```sh
python3 tests/mutated_client.py --proxy 127.0.0.1 --target example.com
```

## Notes

- Obfuscation, not encryption or authentication. A determined classifier can
  still fingerprint it.
- `CONNECT` only; no `BIND`, no `UDP ASSOCIATE`, no SOCKS auth.
- The eBPF match is IPv4-only; proxied targets can be IPv4, IPv6 or domains.
- The first two payload bytes of each control message must arrive in one TCP
  segment. Pipelined greeting+request is out of scope.
- Probes are reset; the listener stays up. A probe-triggered shutdown would
  itself be a DoS.
- If no allowlist is configured, the server is an open proxy; firewall it.

## License

GPL-3.0. See `LICENSE`. The eBPF file is dual-licensed
`GPL-2.0-only OR GPL-3.0-only` for kernel compatibility.
