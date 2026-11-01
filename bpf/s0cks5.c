// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
/*
 * s0cks5 - a deliberately "incorrect" SOCKS5 handshake on the wire.
 *
 * The tc program sits on the router's uplink.  For connections to the
 * configured SOCKS5 server it rewrites the two client control messages and
 * the two server control messages:
 *
 *   client -> server      05 NN ...      ->   16 NN ...
 *   client -> server      05 01 00 ...   ->   16 01 00 ...
 *   server -> client      16 00 ...      ->   05 00 ...
 *                         16 REP 00 ...  ->   05 REP 00 ...
 *
 * The server speaks the mutated format directly, so the return direction is
 * a restore, not a mutation.  Only the version byte of the first two control
 * messages in each direction is touched, and the rewrite is length
 * preserving, so TCP sequence/ack numbers never move.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef SERVER_IP
#error "SERVER_IP must be defined in host byte order, e.g. -DSERVER_IP=0x2d87a2cf"
#endif

#ifndef SERVER_PORT
#define SERVER_PORT 1080
#endif

#define MAX_FLOWS 65536

struct flow_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u16 pad;
};

struct flow_state {
	__u32 last_seq;
	__u8 count; /* control messages already rewritten, max 2 */
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_FLOWS);
	__type(key, struct flow_key);
	__type(value, struct flow_state);
} flows SEC(".maps");

static __always_inline int matches_server(__be32 addr, __be16 port)
{
	return addr == bpf_htonl(SERVER_IP) && port == bpf_htons(SERVER_PORT);
}

SEC("tc")
int s0cks5_mutate(struct __sk_buff *skb)
{
	struct ethhdr eth;
	__be16 proto;
	__u32 l3off = sizeof(eth);

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
		return TC_ACT_OK;

	proto = eth.h_proto;
	if (proto == bpf_htons(ETH_P_8021Q)) {
		struct vlan_hdr {
			__be16 tci;
			__be16 encap_proto;
		} vh;

		if (bpf_skb_load_bytes(skb, l3off, &vh, sizeof(vh)) < 0)
			return TC_ACT_OK;
		proto = vh.encap_proto;
		l3off += sizeof(vh);
	}

	if (proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr ip;
	if (bpf_skb_load_bytes(skb, l3off, &ip, sizeof(ip)) < 0)
		return TC_ACT_OK;
	if (ip.version != 4 || ip.protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	__u32 ihl = (__u32)ip.ihl * 4;
	if (ihl < sizeof(ip))
		return TC_ACT_OK;

	__u32 l4off = l3off + ihl;
	struct tcphdr tcp;
	if (bpf_skb_load_bytes(skb, l4off, &tcp, sizeof(tcp)) < 0)
		return TC_ACT_OK;
	if (tcp.doff < 5)
		return TC_ACT_OK;

	__u32 poff = l4off + (__u32)tcp.doff * 4;
	if (poff >= skb->len || skb->len - poff < 2)
		return TC_ACT_OK;

	int c2s;
	if (matches_server(ip.daddr, tcp.dest))
		c2s = 1;
	else if (matches_server(ip.saddr, tcp.source))
		c2s = 0;
	else
		return TC_ACT_OK;

	struct flow_key key = {
		.saddr = ip.saddr,
		.daddr = ip.daddr,
		.sport = tcp.source,
		.dport = tcp.dest,
	};

	if (tcp.syn) {
		struct flow_state zero = {};

		bpf_map_update_elem(&flows, &key, &zero, BPF_ANY);
		return TC_ACT_OK;
	}
	if (tcp.rst) {
		bpf_map_delete_elem(&flows, &key);
		return TC_ACT_OK;
	}

	struct flow_state *st = bpf_map_lookup_elem(&flows, &key);
	if (!st) {
		struct flow_state zero = {};

		bpf_map_update_elem(&flows, &key, &zero, BPF_ANY);
		st = bpf_map_lookup_elem(&flows, &key);
		if (!st)
			return TC_ACT_OK;
	}

	__u8 b[2];
	if (bpf_skb_load_bytes(skb, poff, b, sizeof(b)) < 0)
		return TC_ACT_OK;

	if (c2s) {
		/* Greeting (05 NMETHODS ...) and CONNECT request (05 01 00 ATYP). */
		if (b[0] != 0x05)
			return TC_ACT_OK;
		/* A retransmission of the last control message is still rewritten. */
		if (st->count >= 2 && tcp.seq != st->last_seq)
			return TC_ACT_OK;

		__u8 nb[2] = { 0x16, b[1] };
		/* bpf_l4_csum_replace() wants the word as the CPU reads it. */
		__u16 old = bpf_ntohs((__u16)((0x05 << 8) | b[1]));
		__u16 new = bpf_ntohs((__u16)((0x16 << 8) | b[1]));

		if (bpf_skb_store_bytes(skb, poff, nb, sizeof(nb), 0) < 0)
			return TC_ACT_OK;
		bpf_l4_csum_replace(skb, l4off + __builtin_offsetof(struct tcphdr, check),
				    old, new, 2);
		if (st->count < 2) {
			st->count++;
			st->last_seq = tcp.seq;
		}
		return TC_ACT_OK;
	}

	/* Server -> client: method selection (16 00) and reply (16 REP 00 ATYP). */
	if (b[0] != 0x16)
		return TC_ACT_OK;
	if (st->count >= 2 && tcp.seq != st->last_seq)
		return TC_ACT_OK;

	__u8 nb = 0x05;
	if (bpf_skb_store_bytes(skb, poff, &nb, sizeof(nb), 0) < 0)
		return TC_ACT_OK;

	__u16 old = bpf_ntohs((__u16)((0x16 << 8) | b[1]));
	__u16 new = bpf_ntohs((__u16)((0x05 << 8) | b[1]));

	bpf_l4_csum_replace(skb, l4off + __builtin_offsetof(struct tcphdr, check),
			    old, new, 2);
	if (st->count < 2) {
		st->count++;
		st->last_seq = tcp.seq;
	}
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
