/*
 * XDP Packet Redirect Program for NetStress Titanium v3.0
 *
 * This eBPF program runs in the kernel and redirects packets to AF_XDP sockets
 * for zero-copy userspace processing.
 *
 * **Task 3.1: Write eBPF program for packet redirect**
 * **Validates: Requirements 2.1, 18.1**
 */

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


/* XSK map to store AF_XDP socket file descriptors */
struct {
  __uint(type, BPF_MAP_TYPE_XSKMAP);
  __uint(max_entries, 64); /* Support up to 64 queues */
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

/* Statistics map for monitoring XDP program performance */
struct xdp_stats {
  __u64 packets_processed;
  __u64 packets_redirected;
  __u64 packets_dropped;
  __u64 packets_passed;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct xdp_stats);
} stats_map SEC(".maps");

/* Helper function to update statistics */
static __always_inline void update_stats(__u32 action) {
  __u32 key = 0;
  struct xdp_stats *stats = bpf_map_lookup_elem(&stats_map, &key);

  if (!stats)
    return;

  stats->packets_processed++;

  switch (action) {
  case XDP_REDIRECT:
    stats->packets_redirected++;
    break;
  case XDP_DROP:
    stats->packets_dropped++;
    break;
  case XDP_PASS:
    stats->packets_passed++;
    break;
  }
}

/* Helper function to parse Ethernet header */
static __always_inline int parse_ethhdr(void *data, void *data_end,
                                        struct ethhdr **eth) {
  *eth = data;

  if ((void *)(*eth + 1) > data_end)
    return -1;

  return 0;
}

/* Helper function to parse IP header */
static __always_inline int parse_iphdr(void *data, void *data_end,
                                       struct iphdr **ip) {
  *ip = data;

  if ((void *)(*ip + 1) > data_end)
    return -1;

  /* Check IP header length */
  if ((*ip)->ihl < 5)
    return -1;

  return 0;
}

/*
 * Main XDP program entry point
 *
 * This function is called for every packet received on the interface.
 * It decides whether to:
 * - XDP_REDIRECT: Send packet to AF_XDP socket for userspace processing
 * - XDP_PASS: Let packet continue through kernel network stack
 * - XDP_DROP: Drop the packet
 */
SEC("xdp")
int xdp_redirect(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth;
  struct iphdr *ip;
  __u32 queue_id;
  __u32 action = XDP_PASS; /* Default action */

  /* Parse Ethernet header */
  if (parse_ethhdr(data, data_end, &eth) < 0) {
    action = XDP_DROP;
    goto out;
  }

  /* Only process IP packets */
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    action = XDP_PASS;
    goto out;
  }

  /* Parse IP header */
  if (parse_iphdr(data + sizeof(*eth), data_end, &ip) < 0) {
    action = XDP_DROP;
    goto out;
  }

  /* Get RX queue ID for multi-queue NICs */
  queue_id = ctx->rx_queue_index;

  /*
   * Redirect packets to AF_XDP socket based on queue ID
   * This enables zero-copy packet processing in userspace
   */
  if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
    action = XDP_REDIRECT;

    /* Redirect to AF_XDP socket */
    if (bpf_redirect_map(&xsks_map, queue_id, 0) == XDP_REDIRECT) {
      update_stats(XDP_REDIRECT);
      return XDP_REDIRECT;
    }
  }

  /*
   * If no AF_XDP socket is configured for this queue,
   * pass packet to kernel network stack
   */
  action = XDP_PASS;

out:
  update_stats(action);
  return action;
}

/* License required for eBPF programs */
char _license[] SEC("license") = "GPL";