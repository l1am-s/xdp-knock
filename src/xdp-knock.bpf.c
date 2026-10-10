#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "shared.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define BOUNDS_CHECK(ptr, end) ((void *)((ptr) + 1) <= (end))


__u16 knock_port SEC(".bss") = 0;
__u16 access_window_s SEC(".bss") = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, member_t);
	__type(value, __u64);
} allowed_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

SEC("xdp")
int xdp_check_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	member_t ip_conn = {0};		

	struct iphdr *iph = (void *)(eth+1);
	struct ipv6hdr *ip6h = (void *)(eth+1);
	uint8_t prtcl = 0;
	int ver = 4;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		if ((void *)(iph + 1) > data_end)
			return XDP_DROP;
		prtcl = iph->protocol;
        ip_conn.ip_parts[0] = iph->saddr;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		if ((void *)(ip6h + 1) > data_end)
			return XDP_DROP;
		prtcl = ip6h->nexthdr;
		ver = 6;
        __builtin_memcpy(ip_conn.ip_parts, &ip6h->saddr, 16);
    }

	// CHECK IF AUTHORIZED
	__u64 *result = bpf_map_lookup_elem(&allowed_map, &ip_conn);
	bpf_printk("CHECKING AUTH - RESULT: %d", result);
	if (result) {
		if ((bpf_ktime_get_ns() - *result) < (access_window_s * 1000000000ULL)) {
			return XDP_PASS;
		} else {
			bpf_map_delete_elem(&allowed_map, &ip_conn);
		}
	}

	if (prtcl != IPPROTO_UDP) return XDP_DROP;

	struct udphdr *udph = NULL;
	if (ver == 6) {
		udph = (void *)(ip6h+1);
	} else if (ver == 4) {
		udph = (void *)(iph+1);
	}

	if ((void *)(udph+1) > data_end)
		return XDP_DROP;

	if (bpf_ntohs(udph->dest) != knock_port) 
		return XDP_DROP;
	
	bpf_printk("NEW UDP REQ RECV - KNOCK_PORT %d", bpf_ntohs(udph->len));

	if (bpf_ntohs(udph->len) != 48)
		return XDP_DROP;

	bpf_printk("VALID SIZE");


	void *udp_data = (void *)(udph + 1); // skip 8 bytes of udp header
	if (udp_data + 40 > data_end)
		return XDP_DROP;

	packet_t *event = bpf_ringbuf_reserve(&events_rb, sizeof(*event), 0);
	if (!event) return XDP_DROP;

	event->src_address = ip_conn;

	__builtin_memcpy(event->payload_data, udp_data, 40);

	bpf_ringbuf_submit(event, 0);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
