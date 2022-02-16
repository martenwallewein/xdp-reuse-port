#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <endian.h>
#include "bpf_helpers.h"

#define SCION_ENDHOST_PORT 30041
#define NUM_CPU 10

/* Special map type that can XDP_REDIRECT frames to another CPU */
BPF_MAP_DEF(cpu_map) = {
    .map_type = BPF_MAP_TYPE_CPUMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 8,
};
BPF_MAP_ADD(cpu_map);

BPF_MAP_DEF(rxcnt) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};
BPF_MAP_ADD(rxcnt);

static inline void count_tx(__u32 protocol, __u64* newrc)
{
	__u64 *rxcnt_count;
    rxcnt_count = bpf_map_lookup_elem(&rxcnt, &protocol);
    
    if (rxcnt_count) {
        *rxcnt_count += 1;
        *newrc = *rxcnt_count;
    }
        
}

SEC("xdp") int xdp_sock(struct xdp_md *ctx) {
    __u32* conf_port = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    size_t offset = sizeof(struct ether_header) +
                    sizeof(struct iphdr) + sizeof(struct udphdr);

    if(data + offset > data_end) {
        return XDP_PASS; // too short
    }

    const struct ether_header *eh = (const struct ether_header *)data;
    if(eh->ether_type != htobe16(ETHERTYPE_IP)) {
        return XDP_PASS; // not IP
    }
    

    __u32 port = 0;
    struct iphdr *iph = (struct iphdr *)(eh + 1);
    if(iph->protocol != IPPROTO_UDP) {
      return XDP_PASS;
    }

    struct udphdr *udph = (struct udphdr *)(iph + 1);
    port = be16toh(udph->uh_dport);
    __u32 src_port = be16toh(udph->uh_sport);

    // TODO: Port lookup
    if (port == 51000) {
        __u64 rx = 0;
        count_tx(0, &rx);
        __u32 cpu = rx % NUM_CPU;
        count_tx(cpu, &rx);
        udph->uh_sport = htobe16(src_port + (cpu * 10));
        udph->check = 0;
    }

   return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
