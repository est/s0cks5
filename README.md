# s0cks5

SOCKS5 was a well defined protocol by RFC1928.

The header bytes are basically hard-coded and always begin with `0x05010003`

This project adds some ancient secret eBPF ingredients, for reasons 😉

Victims may include:

 - MITM boxes
 - DPI gateways

## The trick

An unmodified client behind the OpenWrt box keeps speaking normal SOCKS5.
The router's `tc`/eBPF program rewrites the two client control messages on
the uplink, and restores the two server control messages on the way back:

| direction       | normal SOCKS5          | on the wire            |
| --------------- | ---------------------- | ---------------------- |
| client → server | `05 NN methods...`     | `16 NN methods...`     |
| client → server | `05 01 00 ATYP ...`    | `16 01 00 ATYP ...`    |
| server → client | `05 00`                | `16 00`                |
| server → client | `05 REP 00 ATYP ...`   | `16 REP 00 ATYP ...`   |

The bytes `05 01 00 03` never appear on the wire. The replacement starts with
`16`, which is the opening byte of a TLS handshake record, so a dumb signature
matcher sees something that is at least not the SOCKS5 greeting. Rewriting
only the version byte also handles clients that offer more than one auth
method (curl sends `05 02 00 02`).

The rewrite is **length preserving**, so TCP sequence and acknowledgement
numbers do not move. No packet splitting, no `bpf_skb_adjust_room`, no
sequence-number fixup.

The server does not run eBPF: it simply listens for the mutated format. A
small Python server is included.

```
client ── normal SOCKS5 ──> OpenWrt (tc/eBPF) ── mutated SOCKS5 ──> server
client <─ normal SOCKS5 ── OpenWrt (tc/eBPF) <─ mutated SOCKS5 ── server
```

Only `CONNECT` is implemented; there is no authentication. The scope is the
first two control messages in each direction.

## Requirements

Router (OpenWrt 24.10, `mipsel_24kc` little-endian in the reference setup):

```sh
opkg update
opkg install tc-bpf kmod-sched-core kmod-sched-bpf
# or copy scripts/openwrt-setup.sh to the router and run it
```

Build host (the server or any Linux box):

```sh
apt-get install clang llvm libbpf-dev linux-libc-dev
```

The server only needs Python 3 and the standard library.

## Build

Pass the server endpoint as a parameter; nothing sensitive is stored in the
repository.

```sh
SERVER_IP=203.0.113.10 SERVER_PORT=1080 ./scripts/build.sh
# or
make SERVER_IP=203.0.113.10 SERVER_PORT=1080
```

The default target is `bpfel` because the MT7621 OpenWrt box is little-endian
(`mipsel_24kc`, even though `uname -m` prints `mips`). Use
`BPF_TARGET=bpfeb` for big-endian targets.

The object is written to `build/s0cks5.o` and is ignored by git.

## Run the server

Create an allowlist containing the address the VPS will see as the client
(the router's public egress address), plus loopback for local tests:

```sh
sudo install -m 600 /dev/null /etc/s0cks5-allow.txt
sudo tee /etc/s0cks5-allow.txt >/dev/null <<'EOF'
203.0.113.10/32
127.0.0.1/32
EOF
```

Then:

```sh
python3 server/mutated_socks5.py --bind 0.0.0.0 --port 1080 \
    --allow-file /etc/s0cks5-allow.txt -v
```

The server refuses to start on a non-loopback bind without
`--allow`/`--allow-file`, so it fails closed. `--allow CIDR` can be used
instead of a file. `SIGHUP` reloads the allowlist; a bad reload keeps the old
list rather than opening the service.

Probe handling defaults: 3 s handshake timeout, 8 concurrent connections per
IP, 60 new connections per minute per IP, and 3 bad handshakes trigger a
5 minute temporary ban. Non-allowlisted peers and malformed handshakes get a
TCP RST without a SOCKS reply. Tune with `--handshake-timeout`,
`--max-per-ip`, `--rate`, `--rate-window`, `--ban-after`, `--ban-time`.
`--allow-plain` remains debug-only.

The listener deliberately stays up during probes; shutting it down on a
probe would let any scanner take the service offline.

## Attach the eBPF program

Copy the object to the router and attach it to the uplink port (`wan` in the
reference setup):

```sh
ROUTER_USER=root         # example; use your router login
ROUTER_IP=192.0.2.10     # example; use your router address
scp build/s0cks5.o "$ROUTER_USER@$ROUTER_IP:s0cks5.o"
scp scripts/openwrt-attach.sh "$ROUTER_USER@$ROUTER_IP:"
ssh "$ROUTER_USER@$ROUTER_IP" './openwrt-attach.sh wan ./s0cks5.o'
```

Detach with:

```sh
ssh "$ROUTER_USER@$ROUTER_IP" './openwrt-detach.sh wan'
```

Attach to the interface that actually carries the client traffic. On a
bridge, that is the uplink slave port, not `br-lan`; forwarded frames bypass
the bridge master's qdisc.

## Make the router the SOCKS5 endpoint

Clients can keep pointing at the VPS address, or they can point at the router
and let it forward the connection. Two implementations are included: a
portable `socat` relay and a kernel-only DNAT rule. Both make the SOCKS5
service appear to live on OpenWrt:

```sh
scp scripts/openwrt-forward.init scripts/openwrt-forward-install.sh \
    scripts/openwrt-forward-remove.sh "$ROUTER_USER@$ROUTER_IP:"
ssh "$ROUTER_USER@$ROUTER_IP" \
    'SERVER_IP=203.0.113.10 SERVER_PORT=1080 \
     LISTEN_ADDR=192.0.2.10 LISTEN_PORT=1080 \
     ./openwrt-forward-install.sh'
```

The installer writes `/etc/s0cks5-forward.conf`, installs
`/etc/init.d/s0cks5-forward`, enables it at boot, and runs the equivalent of:

```sh
socat TCP-LISTEN:1080,bind=192.0.2.10,fork,reuseaddr \
      TCP:203.0.113.10:1080
```

Clients then use the router as the proxy:

```sh
curl --socks5-hostname 192.0.2.10:1080 http://example.com/
```

The LAN leg is ordinary SOCKS5. The router → VPS leg is a fresh TCP
connection, and that is the leg the eBPF on `wan` mutates. Keep `LISTEN_ADDR`
on the LAN address: the forwarder has no authentication. Remove it with
`./openwrt-forward-remove.sh`.

This is a userspace relay, so throughput is bounded by the router's CPU.

### Kernel NAT alternative (no socat)

`snat` alone is not enough: SNAT changes the source address, not the
destination. What redirects the connection is **DNAT**:

```
client -> 192.0.2.10:1080   --DNAT-->   client -> 203.0.113.10:1080
```

The return path then needs SNAT/MASQUERADE, otherwise the VPS replies
directly to the LAN client (or to an unroutable private address) and bypasses
the router. The rules below only masquerade the DNAT'd flow, using
`ct status dnat`, so unrelated traffic is untouched:

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

The installer packages the same rules as a boot-time service and disables the
socat forwarder:

```sh
scp scripts/openwrt-nat.init scripts/openwrt-nat.hotplug \
    scripts/openwrt-nat-install.sh scripts/openwrt-nat-remove.sh \
    "$ROUTER_USER@$ROUTER_IP:"
ssh "$ROUTER_USER@$ROUTER_IP" \
    'SERVER_IP=203.0.113.10 SERVER_PORT=1080 \
     LISTEN_ADDR=any LISTEN_PORT=1080 \
     ./openwrt-nat-install.sh'
```

`LISTEN_ADDR=any` (the default) uses `fib daddr type local`, so every current
and future local IPv4 address — LAN, WAN, aliases, DHCP changes — is covered
without editing the rule. Pass a specific address instead to restrict it to
one interface. Because `any` includes a WAN address, use a LAN address or a
firewall rule if you do not want the proxy reachable from outside.

The installer validates the IP and ports, prints the config it is replacing,
deletes the current `s0cks5nat` table and the legacy `s0cks5_nat`/`s0cks5`
names, then writes the new config and restarts the service. Re-run it after a
VPS or port change; a wrong previous rule is removed first.

The rule sits in `prerouting`, so it covers LAN and WAN clients, but not a
client running on the router itself; that client should use the VPS address
directly. NAT support comes from `kmod-nft-nat` (already present on the
reference box).

The service is enabled as `S99s0cks5-nat`, after the firewall at boot. The
`ifup` hotplug hook re-applies it when an interface comes up, and `fw4 reload`
leaves the separate `ip s0cks5nat` table intact. Check it with
`/etc/init.d/s0cks5-nat status`; `stop`/`start`/`restart`/`reload` work.

Remove it with `./openwrt-nat-remove.sh`, then re-enable socat with
`/etc/init.d/s0cks5-forward enable && /etc/init.d/s0cks5-forward start`.

On the reference bridged AP the DNAT'd packet is routed back out `br-lan` to
the default gateway, but it still leaves through the `wan` port, so the
`tc`/eBPF program sees the mutated leg. This is a hairpin NAT: it works here,
but it is more sensitive to firewall/zone changes than the socat relay. The
socat path remains the portable default.

## Test

Normal client, using the router as the endpoint (or connect to the VPS
address directly if you did not enable the forwarder/NAT):

```sh
curl --socks5-hostname 192.0.2.10:1080 http://example.com/
# direct:
curl --socks5-hostname 203.0.113.10:1080 http://example.com/
```

A quick probe check from a non-allowlisted source should produce no SOCKS
reply and a reset:

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 1 203.0.113.10 1080
```

Watch the wire on the server:

```sh
tcpdump -i eth0 -nn -X 'tcp port 1080'
```

The client's greeting should appear as `16 02 00 02` for curl (or `16 01 00`
for a one-method client), and the CONNECT request as `16 01 00 01 ...` (IPv4)
or `16 01 00 03 ...` (domain). The sequence `05 01 00` should not appear.

Test the server directly, bypassing the router, using the included mutated
client (run it on the server or another host that is not behind the eBPF
hook):

```sh
python3 tests/mutated_client.py \
    --proxy 127.0.0.1 --proxy-port 1080 \
    --target example.com --target-port 80
```

`curl` through the router is the real end-to-end test: the client, the
kernel's TCP stack and the server all see a valid stream.

## Notes and limitations

* This is obfuscation, not encryption or authentication. It defeats a fixed
  byte signature; it does not defeat a determined classifier.
* There is no SOCKS username/password. The security boundary is the server's
  source allowlist, so keep it narrow and use a host firewall as defense in
  depth. An allowlisted source is trusted to use the proxy.
* Probes and malformed handshakes are reset rather than answered, but the
  listener is not stopped. A probe-triggered shutdown would itself be a DoS.
* Only the first two control messages per direction are rewritten. A client
  that pipelines greeting + request in one TCP segment, or application data
  that begins with the SOCKS5 signature before the handshake completes, is
  out of scope. The first two payload bytes of a control message must arrive
  in one TCP segment; a one-byte first segment is passed through unmodified.
* `CONNECT` only, no `BIND`, no `UDP ASSOCIATE`, no username/password.
* The eBPF match is IPv4-only (the server address is configured as IPv4); the
  proxied target can still be IPv4, IPv6 or a domain name.

## Ubuntu

`apt-get install python3-bpfcc`

The included eBPF program is compiled with clang and loaded with `tc`, so
`python3-bpfcc` is not required by this repository.
