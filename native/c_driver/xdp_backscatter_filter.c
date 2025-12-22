/**
 * NetStress XDP Backscatter Filter
 * eBPF program to drop incoming SYN-ACK and RST packets at NIC level
 */

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>


/* ============================================================================
 * BPF Map Definitions
 * ============================================================================
 */

// Statistics map to track dropped/passed packets
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 6);
  __type(key, __u32);
  __type(value, __u64);
} stats_map SEC(".maps");

// Statistics keys
#define STAT_PACKETS_DROPPED 0
#define STAT_PACKETS_PASSED 1
#define STAT_BYTES_DROPPED 2
#define STAT_BYTES_PASSED 3
#define STAT_SYN_ACK_DROPPED 4
#define STAT_RST_DROPPED 5

/* ============================================================================
 * Helper Functions
 * ============================================================================
 */

static __always_inline void update_stat(__u32 key, __u64 increment) {
  __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
  if (value) {
    __sync_fetch_and_add(value, increment);
  }
}

static __always_inline int parse_ethernet(void *data, void *data_end,
                                          struct ethhdr **eth) {
  *eth = data;
  if ((void *)(*eth + 1) > data_end) {
    return -1;
  }
  return 0;
}

static __always_inline int parse_ip(void *data, void *data_end,
                                    struct iphdr **ip) {
  *ip = data;
  if ((void *)(*ip + 1) > data_end) {
    return -1;
  }

  // Check IP header length
  if ((*ip)->ihl < 5) {
    return -1;
  }

  // Ensure we have the full IP header
  if ((void *)(*ip) + ((*ip)->ihl * 4) > data_end) {
    return -1;
  }

  return 0;
}

static __always_inline int parse_tcp(void *data, void *data_end,
                                     struct tcphdr **tcp) {
  *tcp = data;
  if ((void *)(*tcp + 1) > data_end) {
    return -1;
  }

  // Check TCP header length
  if ((*tcp)->doff < 5) {
    return -1;
  }

  // Ensure we have the full TCP header
  if ((void *)(*tcp) + ((*tcp)->doff * 4) > data_end) {
    return -1;
  }

  return 0;
}

/* ============================================================================
 * Main XDP Program
 * ============================================================================
 */

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth;
  struct iphdr *ip;
  struct tcphdr *tcp;

  __u32 packet_size = data_end - data;

  // Parse Ethernet header
  if (parse_ethernet(data, data_end, &eth) < 0) {
    goto pass;
  }

  // Only process IPv4 packets
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    goto pass;
  }

  // Parse IP header
  void *ip_start = data + sizeof(struct ethhdr);
  if (parse_ip(ip_start, data_end, &ip) < 0) {
    goto pass;
  }

  // Only process TCP packets
  if (ip->protocol != IPPROTO_TCP) {
    goto pass;
  }

  // Parse TCP header
  void *tcp_start = ip_start + (ip->ihl * 4);
  if (parse_tcp(tcp_start, data_end, &tcp) < 0) {
    goto pass;
  }

  // Check for SYN-ACK packets (SYN=1, ACK=1)
  if (tcp->syn && tcp->ack) {
    update_stat(STAT_PACKETS_DROPPED, 1);
    update_stat(STAT_BYTES_DROPPED, packet_size);
    update_stat(STAT_SYN_ACK_DROPPED, 1);
    return XDP_DROP;
  }

  // Check for RST packets (RST=1)
  if (tcp->rst) {
    update_stat(STAT_PACKETS_DROPPED, 1);
    update_stat(STAT_BYTES_DROPPED, packet_size);
    update_stat(STAT_RST_DROPPED, 1);
    return XDP_DROP;
  }

pass:
  // Pass all other packets
  update_stat(STAT_PACKETS_PASSED, 1);
  update_stat(STAT_BYTES_PASSED, packet_size);
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";