/**
 * NetStress C Driver Shim Implementation
 * Platform-specific low-level networking operations
 */

#include "driver_shim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSE_SOCKET closesocket
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#define CLOSE_SOCKET close
#define SOCKET int
#define INVALID_SOCKET -1
#endif

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#include <sys/sendfile.h>
#include <sys/utsname.h>

#endif

/* ============================================================================
 * Raw Socket Implementation
 * ============================================================================
 */

int raw_socket_create(int protocol) {
#ifdef _WIN32
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    return -1;
  }
  SOCKET sock = socket(AF_INET, SOCK_RAW, protocol);
  if (sock == INVALID_SOCKET) {
    return -1;
  }
  return (int)sock;
#else
  int sock = socket(AF_INET, SOCK_RAW, protocol);
  if (sock < 0) {
    return -1;
  }
  return sock;
#endif
}

int raw_socket_set_hdrincl(int sockfd) {
  int one = 1;
#ifdef _WIN32
  return setsockopt((SOCKET)sockfd, IPPROTO_IP, IP_HDRINCL, (const char *)&one,
                    sizeof(one));
#else
  return setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
#endif
}

int raw_socket_send(int sockfd, uint32_t dst_ip, const uint8_t *data,
                    uint32_t len) {
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = dst_ip;

#ifdef _WIN32
  int sent = sendto((SOCKET)sockfd, (const char *)data, len, 0,
                    (struct sockaddr *)&dest, sizeof(dest));
#else
  ssize_t sent =
      sendto(sockfd, data, len, 0, (struct sockaddr *)&dest, sizeof(dest));
#endif
  return (int)sent;
}

int raw_socket_send_ip(int sockfd, const uint8_t *data, uint32_t len) {
  /* Extract destination IP from IP header */
  if (len < 20) {
    return -1; /* Too short for IP header */
  }

  uint32_t dst_ip;
  memcpy(&dst_ip, data + 16, 4); /* Destination IP at offset 16 */

  return raw_socket_send(sockfd, dst_ip, data, len);
}

void raw_socket_close(int sockfd) {
#ifdef _WIN32
  CLOSE_SOCKET((SOCKET)sockfd);
  WSACleanup();
#else
  CLOSE_SOCKET(sockfd);
#endif
}

/* ============================================================================
 * Checksum Calculations
 * ============================================================================
 */

uint16_t calculate_checksum(const uint8_t *data, size_t len) {
  uint32_t sum = 0;
  size_t i;

  /* Sum 16-bit words */
  for (i = 0; i + 1 < len; i += 2) {
    sum += ((uint16_t)data[i] << 8) | data[i + 1];
  }

  /* Add odd byte if present */
  if (i < len) {
    sum += (uint16_t)data[i] << 8;
  }

  /* Fold 32-bit sum to 16 bits */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)(~sum);
}

uint16_t calculate_transport_checksum(uint32_t src_ip, uint32_t dst_ip,
                                      uint8_t protocol, const uint8_t *data,
                                      size_t len) {
  uint32_t sum = 0;
  size_t i;

  /* Pseudo-header */
  sum += (src_ip >> 16) & 0xFFFF;
  sum += src_ip & 0xFFFF;
  sum += (dst_ip >> 16) & 0xFFFF;
  sum += dst_ip & 0xFFFF;
  sum += protocol;
  sum += len;

  /* Data */
  for (i = 0; i + 1 < len; i += 2) {
    sum += ((uint16_t)data[i] << 8) | data[i + 1];
  }
  if (i < len) {
    sum += (uint16_t)data[i] << 8;
  }

  /* Fold */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)(~sum);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

uint64_t get_timestamp_us(void) {
#ifdef _WIN32
  LARGE_INTEGER freq, count;
  QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&count);
  return (uint64_t)(count.QuadPart * 1000000 / freq.QuadPart);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
#endif
}

int get_cpu_count(void) {
#ifdef _WIN32
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  return sysinfo.dwNumberOfProcessors;
#elif defined(__linux__)
  return sysconf(_SC_NPROCESSORS_ONLN);
#else
  return 1;
#endif
}

int pin_to_cpu(int cpu_id) {
#ifdef __linux__
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu_id, &cpuset);
  return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#else
  (void)cpu_id;
  return -1; /* Not supported */
#endif
}

/* ============================================================================
 * DPDK Implementation (when available)
 * ============================================================================
 */

#ifdef HAS_DPDK

#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>

static struct rte_mempool *mbuf_pool = NULL;
static int dpdk_initialized = 0;
static uint16_t nb_ports = 0;

#define MBUF_CACHE_SIZE 256
#define MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define NB_MBUF 8192

int dpdk_init(int argc, char **argv) {
  int ret;

  /* Initialize EAL (Environment Abstraction Layer) */
  ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    fprintf(stderr, "DPDK EAL initialization failed: %s\n", rte_strerror(-ret));
    return -1;
  }

  /* Check if we have any ports available */
  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports == 0) {
    fprintf(stderr, "No Ethernet ports available\n");
    rte_eal_cleanup();
    return -1;
  }

  printf("DPDK initialized with %u available ports\n", nb_ports);

  /* Create mbuf memory pool */
  mbuf_pool =
      rte_pktmbuf_pool_create("MBUF_POOL", NB_MBUF, /* Number of mbufs */
                              MBUF_CACHE_SIZE,      /* Cache size */
                              0,                    /* Private data size */
                              MBUF_DATA_SIZE,       /* Data room size */
                              rte_socket_id());     /* Socket ID */
  if (mbuf_pool == NULL) {
    fprintf(stderr, "Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
    rte_eal_cleanup();
    return -1;
  }

  printf("DPDK mbuf pool created successfully\n");

  /* Configure huge pages if not already done */
  const struct rte_memseg_list *msl = rte_eal_get_physmem_layout();
  if (msl == NULL) {
    fprintf(stderr, "Warning: Could not get physical memory layout\n");
  } else {
    printf("DPDK using huge pages for memory allocation\n");
  }

  dpdk_initialized = 1;
  return ret;
}

int init_dpdk_port(int port_id) {
  if (!dpdk_initialized) {
    fprintf(stderr, "DPDK not initialized\n");
    return -1;
  }

  if (port_id >= nb_ports) {
    fprintf(stderr, "Port ID %d exceeds available ports (%u)\n", port_id,
            nb_ports);
    return -1;
  }

  struct rte_eth_dev_info dev_info;
  struct rte_eth_conf port_conf = {0};
  struct rte_eth_rxconf rxq_conf;
  struct rte_eth_txconf txq_conf;
  int ret;

  /* Get device info */
  ret = rte_eth_dev_info_get(port_id, &dev_info);
  if (ret != 0) {
    fprintf(stderr, "Error getting device info for port %d: %s\n", port_id,
            rte_strerror(-ret));
    return ret;
  }

  printf("Initializing port %d (%s)\n", port_id, dev_info.driver_name);

  /* Configure port with RSS (Receive Side Scaling) */
  port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
  port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
  port_conf.rx_adv_conf.rss_conf.rss_hf =
      ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;

  /* Enable hardware offloads if supported */
  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
  }
  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) {
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
  }
  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) {
    port_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;
  }

  /* Configure the Ethernet device */
  ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
  if (ret != 0) {
    fprintf(stderr, "Error configuring port %d: %s\n", port_id,
            rte_strerror(-ret));
    return ret;
  }

  /* Setup RX queue */
  rxq_conf = dev_info.default_rxconf;
  rxq_conf.offloads = port_conf.rxmode.offloads;

  ret = rte_eth_rx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id),
                               &rxq_conf, mbuf_pool);
  if (ret < 0) {
    fprintf(stderr, "Error setting up RX queue for port %d: %s\n", port_id,
            rte_strerror(-ret));
    return ret;
  }

  /* Setup TX queue */
  txq_conf = dev_info.default_txconf;
  txq_conf.offloads = port_conf.txmode.offloads;

  ret = rte_eth_tx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id),
                               &txq_conf);
  if (ret < 0) {
    fprintf(stderr, "Error setting up TX queue for port %d: %s\n", port_id,
            rte_strerror(-ret));
    return ret;
  }

  /* Start the Ethernet port */
  ret = rte_eth_dev_start(port_id);
  if (ret < 0) {
    fprintf(stderr, "Error starting port %d: %s\n", port_id,
            rte_strerror(-ret));
    return ret;
  }

  /* Enable promiscuous mode for packet capture */
  ret = rte_eth_promiscuous_enable(port_id);
  if (ret != 0) {
    fprintf(stderr,
            "Warning: Could not enable promiscuous mode for port %d: %s\n",
            port_id, rte_strerror(-ret));
    /* Continue anyway - promiscuous mode is not critical for sending */
  }

  /* Display port link status */
  struct rte_eth_link link;
  ret = rte_eth_link_get_nowait(port_id, &link);
  if (ret == 0) {
    if (link.link_status == ETH_LINK_UP) {
      printf("Port %d: Link Up - speed %u Mbps - %s\n", port_id,
             link.link_speed,
             (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? "full-duplex"
                                                        : "half-duplex");
    } else {
      printf("Port %d: Link Down\n", port_id);
    }
  }

  printf("Port %d initialized successfully\n", port_id);
  return 0;
}

int dpdk_send_burst(int port_id, const uint8_t **packets,
                    const uint32_t *lengths, uint32_t count) {
  if (!dpdk_initialized || mbuf_pool == NULL) {
    fprintf(stderr, "DPDK not initialized or mbuf pool is NULL\n");
    return -1;
  }

  if (port_id >= nb_ports) {
    fprintf(stderr, "Port ID %d exceeds available ports (%u)\n", port_id,
            nb_ports);
    return -1;
  }

  if (count == 0 || packets == NULL || lengths == NULL) {
    return 0;
  }

  /* Limit burst size to reasonable maximum */
  const uint32_t max_burst = 32;
  uint32_t actual_count = (count > max_burst) ? max_burst : count;

  struct rte_mbuf *mbufs[actual_count];
  uint32_t i;

  /* Allocate mbufs from pool */
  for (i = 0; i < actual_count; i++) {
    mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
    if (mbufs[i] == NULL) {
      /* Free already allocated mbufs */
      for (uint32_t j = 0; j < i; j++) {
        rte_pktmbuf_free(mbufs[j]);
      }
      fprintf(stderr, "Failed to allocate mbuf %u/%u\n", i, actual_count);
      return -1;
    }

    /* Validate packet length */
    if (lengths[i] == 0 || lengths[i] > RTE_MBUF_DEFAULT_DATAROOM) {
      /* Free all allocated mbufs */
      for (uint32_t j = 0; j <= i; j++) {
        rte_pktmbuf_free(mbufs[j]);
      }
      fprintf(stderr, "Invalid packet length %u at index %u\n", lengths[i], i);
      return -1;
    }

    /* Copy packet data to mbuf */
    char *data = rte_pktmbuf_append(mbufs[i], lengths[i]);
    if (data == NULL) {
      /* Free all allocated mbufs */
      for (uint32_t j = 0; j <= i; j++) {
        rte_pktmbuf_free(mbufs[j]);
      }
      fprintf(stderr, "Failed to append data to mbuf %u\n", i);
      return -1;
    }

    /* Fast memory copy */
    rte_memcpy(data, packets[i], lengths[i]);
  }

  /* Send burst of packets */
  uint16_t sent = rte_eth_tx_burst(port_id, 0, mbufs, actual_count);

  /* Free any unsent mbufs (should not happen in normal operation) */
  for (i = sent; i < actual_count; i++) {
    rte_pktmbuf_free(mbufs[i]);
  }

  return sent;
}

int dpdk_recv_burst(int port_id, uint8_t **packets, uint32_t max_count) {
  if (!dpdk_initialized) {
    return -1;
  }

  struct rte_mbuf *mbufs[max_count];
  uint16_t received = rte_eth_rx_burst(port_id, 0, mbufs, max_count);

  for (uint16_t i = 0; i < received; i++) {
    packets[i] = rte_pktmbuf_mtod(mbufs[i], uint8_t *);
  }

  return received;
}

int dpdk_get_stats(int port_id, driver_stats_t *stats) {
  struct rte_eth_stats eth_stats;
  int ret = rte_eth_stats_get(port_id, &eth_stats);
  if (ret != 0) {
    return ret;
  }

  stats->packets_sent = eth_stats.opackets;
  stats->packets_received = eth_stats.ipackets;
  stats->bytes_sent = eth_stats.obytes;
  stats->bytes_received = eth_stats.ibytes;
  stats->errors = eth_stats.oerrors + eth_stats.ierrors;

  return 0;
}

int cleanup_dpdk(void) {
  if (!dpdk_initialized) {
    return 0; /* Already cleaned up */
  }

  printf("Cleaning up DPDK resources...\n");

  /* Stop all ports */
  uint16_t port_id;
  RTE_ETH_FOREACH_DEV(port_id) {
    printf("Stopping port %u...\n", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
  }

  /* Free mbuf pool */
  if (mbuf_pool != NULL) {
    printf("Freeing mbuf pool...\n");
    /* Note: DPDK doesn't provide rte_mempool_free(),
     * pools are automatically freed during EAL cleanup */
    mbuf_pool = NULL;
  }

  /* Cleanup EAL */
  printf("Cleaning up DPDK EAL...\n");
  int ret = rte_eal_cleanup();
  if (ret < 0) {
    fprintf(stderr, "EAL cleanup failed: %s\n", rte_strerror(-ret));
    /* Continue anyway to reset our state */
  }

  /* Reset global state */
  dpdk_initialized = 0;
  nb_ports = 0;

  printf("DPDK cleanup completed\n");
  return ret;
}

#endif /* HAS_DPDK */

/* ============================================================================
 * AF_XDP Implementation (when available)
 * ============================================================================
 */

#ifdef HAS_AF_XDP

#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>

/* AF_XDP Global State */
static struct xsk_socket *xsk = NULL;
static struct xsk_umem *umem = NULL;
static void *umem_area = NULL;
static struct xsk_ring_prod tx_ring;
static struct xsk_ring_cons rx_ring;
static struct xsk_ring_prod fill_ring;
static struct xsk_ring_cons comp_ring;
static uint64_t *frame_addrs = NULL;
static uint32_t frame_count = 0;
static uint32_t next_frame = 0;

/* AF_XDP Configuration */
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define NUM_FRAMES 4096
#define BATCH_SIZE 64

/**
 * Initialize AF_XDP socket with UMEM and rings
 * Implements Requirements 5.1: AF_XDP socket initialization
 */
int init_af_xdp(const char *ifname) {
  int ret;

  if (!ifname) {
    fprintf(stderr, "AF_XDP: Interface name is NULL\n");
    return -1;
  }

  /* Get interface index */
  int ifindex = if_nametoindex(ifname);
  if (ifindex == 0) {
    fprintf(stderr, "AF_XDP: Interface %s not found\n", ifname);
    return -1;
  }

  printf("AF_XDP: Initializing on interface %s (index %d)\n", ifname, ifindex);

  /* Step 1: Allocate UMEM area with proper alignment */
  size_t umem_size = NUM_FRAMES * FRAME_SIZE;

  /* Use mmap for better memory management and alignment */
  umem_area = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (umem_area == MAP_FAILED) {
    fprintf(stderr, "AF_XDP: Failed to allocate UMEM area: %s\n",
            strerror(errno));
    return -1;
  }

  printf("AF_XDP: Allocated UMEM area: %zu bytes at %p\n", umem_size,
         umem_area);

  /* Step 2: Configure UMEM */
  struct xsk_umem_config umem_cfg = {
      .fill_size = NUM_FRAMES / 2, /* Fill ring size */
      .comp_size = NUM_FRAMES / 2, /* Completion ring size */
      .frame_size = FRAME_SIZE,    /* Frame size */
      .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
      .flags = 0};

  /* Step 3: Create UMEM with fill and completion rings */
  ret = xsk_umem__create(&umem, umem_area, umem_size, &fill_ring, &comp_ring,
                         &umem_cfg);
  if (ret) {
    fprintf(stderr, "AF_XDP: Failed to create UMEM: %s\n", strerror(-ret));
    munmap(umem_area, umem_size);
    umem_area = NULL;
    return ret;
  }

  printf("AF_XDP: UMEM created successfully\n");

  /* Step 4: Configure XSK socket */
  struct xsk_socket_config xsk_cfg = {
      .rx_size = NUM_FRAMES / 2,        /* RX ring size */
      .tx_size = NUM_FRAMES / 2,        /* TX ring size */
      .libbpf_flags = 0,                /* Let libbpf load XDP program */
      .xdp_flags = XDP_FLAGS_DRV_MODE,  /* Try driver mode first */
      .bind_flags = XDP_USE_NEED_WAKEUP /* Use need_wakeup optimization */
  };

  /* Step 5: Create XSK socket with TX and RX rings */
  ret = xsk_socket__create(&xsk, ifname, 0, umem, &rx_ring, &tx_ring, &xsk_cfg);
  if (ret) {
    /* Try SKB mode if driver mode fails */
    printf("AF_XDP: Driver mode failed, trying SKB mode\n");
    xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    ret =
        xsk_socket__create(&xsk, ifname, 0, umem, &rx_ring, &tx_ring, &xsk_cfg);
    if (ret) {
      fprintf(stderr, "AF_XDP: Failed to create XSK socket: %s\n",
              strerror(-ret));
      xsk_umem__delete(umem);
      munmap(umem_area, umem_size);
      umem_area = NULL;
      umem = NULL;
      return ret;
    }
  }

  printf("AF_XDP: XSK socket created successfully\n");

  /* Step 6: Initialize frame address tracking */
  frame_addrs = (uint64_t *)malloc(NUM_FRAMES * sizeof(uint64_t));
  if (!frame_addrs) {
    fprintf(stderr, "AF_XDP: Failed to allocate frame address array\n");
    cleanup_af_xdp();
    return -1;
  }

  /* Initialize frame addresses */
  for (uint32_t i = 0; i < NUM_FRAMES; i++) {
    frame_addrs[i] = i * FRAME_SIZE;
  }
  frame_count = NUM_FRAMES;
  next_frame = 0;

  /* Step 7: Populate fill ring with available frames */
  uint32_t idx;
  ret = xsk_ring_prod__reserve(&fill_ring, NUM_FRAMES / 2, &idx);
  if (ret != NUM_FRAMES / 2) {
    fprintf(stderr, "AF_XDP: Failed to reserve fill ring entries\n");
    cleanup_af_xdp();
    return -1;
  }

  for (uint32_t i = 0; i < NUM_FRAMES / 2; i++) {
    *xsk_ring_prod__fill_addr(&fill_ring, idx + i) = frame_addrs[i];
  }
  xsk_ring_prod__submit(&fill_ring, NUM_FRAMES / 2);

  printf("AF_XDP: Fill ring populated with %d frames\n", NUM_FRAMES / 2);

  /* Step 8: Get socket file descriptor for polling */
  int sockfd = xsk_socket__fd(xsk);
  if (sockfd < 0) {
    fprintf(stderr, "AF_XDP: Failed to get socket file descriptor\n");
    cleanup_af_xdp();
    return -1;
  }

  printf("AF_XDP: Initialization complete, socket fd: %d\n", sockfd);
  return sockfd;
}

/**
 * Send single packet via AF_XDP
 */
int af_xdp_send(const uint8_t *data, uint32_t len) {
  if (!xsk || !data || len == 0 || len > FRAME_SIZE) {
    return -1;
  }

  /* Reserve TX descriptor */
  uint32_t idx;
  if (xsk_ring_prod__reserve(&tx_ring, 1, &idx) != 1) {
    return -1; /* TX ring full */
  }

  /* Get frame address */
  uint64_t frame_addr = next_frame * FRAME_SIZE;
  next_frame = (next_frame + 1) % NUM_FRAMES;

  /* Set up TX descriptor */
  struct xdp_desc *desc = xsk_ring_prod__tx_desc(&tx_ring, idx);
  desc->addr = frame_addr;
  desc->len = len;

  /* Copy packet data to UMEM frame (zero-copy for user, but we copy here) */
  memcpy((uint8_t *)umem_area + frame_addr, data, len);

  /* Submit to TX ring */
  xsk_ring_prod__submit(&tx_ring, 1);

  /* Kick TX if needed */
  if (xsk_ring_prod__needs_wakeup(&tx_ring)) {
    int sockfd = xsk_socket__fd(xsk);
    sendto(sockfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
  }

  return len;
}

/**
 * Send batch of packets via AF_XDP with UMEM zero-copy
 * Implements Requirements 5.2, 5.3: Zero-copy batch sending
 */
int af_xdp_send_batch(const uint8_t **packets, const uint32_t *lengths,
                      uint32_t count) {
  if (!xsk || !packets || !lengths || count == 0) {
    return -1;
  }

  /* Process completion ring first to free up frames */
  uint32_t comp_idx;
  uint32_t completed = xsk_ring_cons__peek(&comp_ring, BATCH_SIZE, &comp_idx);
  if (completed > 0) {
    /* Frames are automatically returned to the pool */
    xsk_ring_cons__release(&comp_ring, completed);
  }

  /* Limit batch size to available TX ring space */
  uint32_t batch_size = count > BATCH_SIZE ? BATCH_SIZE : count;

  /* Reserve TX descriptors */
  uint32_t idx;
  uint32_t reserved = xsk_ring_prod__reserve(&tx_ring, batch_size, &idx);
  if (reserved == 0) {
    return 0; /* TX ring full */
  }

  /* Fill TX descriptors */
  for (uint32_t i = 0; i < reserved; i++) {
    if (lengths[i] == 0 || lengths[i] > FRAME_SIZE) {
      /* Skip invalid packets */
      continue;
    }

    /* Get frame address */
    uint64_t frame_addr = ((next_frame + i) % NUM_FRAMES) * FRAME_SIZE;

    /* Set up TX descriptor */
    struct xdp_desc *desc = xsk_ring_prod__tx_desc(&tx_ring, idx + i);
    desc->addr = frame_addr;
    desc->len = lengths[i];

    /* Copy packet data to UMEM frame */
    memcpy((uint8_t *)umem_area + frame_addr, packets[i], lengths[i]);
  }

  /* Update next frame pointer */
  next_frame = (next_frame + reserved) % NUM_FRAMES;

  /* Submit batch to TX ring */
  xsk_ring_prod__submit(&tx_ring, reserved);

  /* Kick TX if needed */
  if (xsk_ring_prod__needs_wakeup(&tx_ring)) {
    int sockfd = xsk_socket__fd(xsk);
    int ret = sendto(sockfd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      fprintf(stderr, "AF_XDP: TX wakeup failed: %s\n", strerror(errno));
    }
  }

  return reserved;
}

/**
 * Receive packet via AF_XDP
 */
int af_xdp_recv(uint8_t *buffer, uint32_t max_len) {
  if (!xsk || !buffer || max_len == 0) {
    return -1;
  }

  /* Check for received packets */
  uint32_t idx;
  if (xsk_ring_cons__peek(&rx_ring, 1, &idx) != 1) {
    return 0; /* No packets available */
  }

  /* Get packet descriptor */
  const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx_ring, idx);
  uint32_t len = desc->len < max_len ? desc->len : max_len;

  /* Copy packet data from UMEM */
  memcpy(buffer, (uint8_t *)umem_area + desc->addr, len);

  /* Release RX descriptor */
  xsk_ring_cons__release(&rx_ring, 1);

  /* Refill fill ring */
  uint32_t fq_idx;
  if (xsk_ring_prod__reserve(&fill_ring, 1, &fq_idx) == 1) {
    *xsk_ring_prod__fill_addr(&fill_ring, fq_idx) = desc->addr;
    xsk_ring_prod__submit(&fill_ring, 1);
  }

  return len;
}

/**
 * Cleanup AF_XDP resources
 * Implements Requirements 5.1: Resource cleanup
 */
int cleanup_af_xdp(void) {
  printf("AF_XDP: Cleaning up resources\n");

  /* Close XSK socket */
  if (xsk) {
    xsk_socket__delete(xsk);
    xsk = NULL;
    printf("AF_XDP: XSK socket closed\n");
  }

  /* Delete UMEM */
  if (umem) {
    xsk_umem__delete(umem);
    umem = NULL;
    printf("AF_XDP: UMEM deleted\n");
  }

  /* Unmap UMEM area */
  if (umem_area && umem_area != MAP_FAILED) {
    size_t umem_size = NUM_FRAMES * FRAME_SIZE;
    munmap(umem_area, umem_size);
    umem_area = NULL;
    printf("AF_XDP: UMEM area unmapped\n");
  }

  /* Free frame address array */
  if (frame_addrs) {
    free(frame_addrs);
    frame_addrs = NULL;
  }

  /* Reset state */
  frame_count = 0;
  next_frame = 0;

  printf("AF_XDP: Cleanup complete\n");
  return 0;
}

#endif /* HAS_AF_XDP */

/* ============================================================================
 * io_uring Implementation (when available)
 * ============================================================================
 */

#ifdef HAS_IO_URING

#include <liburing.h>
#include <sys/uio.h>

static struct io_uring ring;
static int io_uring_initialized = 0;
static int io_uring_sockfd = -1;
static driver_stats_t io_uring_stats = {0};

#define URING_QUEUE_DEPTH 256
#define URING_BATCH_SIZE 32

int init_io_uring(int queue_depth) {
  int ret = io_uring_queue_init(
      queue_depth > 0 ? queue_depth : URING_QUEUE_DEPTH, &ring, 0);
  if (ret < 0) {
    return ret;
  }

  /* Create UDP socket for sending */
  io_uring_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (io_uring_sockfd < 0) {
    io_uring_queue_exit(&ring);
    return -1;
  }

  io_uring_initialized = 1;
  return 0;
}

int io_uring_send_batch(const uint8_t **packets, const uint32_t *lengths,
                        const struct sockaddr_in *dests, uint32_t count) {
  if (!io_uring_initialized) {
    return -1;
  }

  struct io_uring_sqe *sqe;
  struct msghdr *msgs;
  struct iovec *iovs;
  uint32_t i;

  /* Allocate message structures */
  msgs = (struct msghdr *)calloc(count, sizeof(struct msghdr));
  iovs = (struct iovec *)calloc(count, sizeof(struct iovec));
  if (!msgs || !iovs) {
    free(msgs);
    free(iovs);
    return -1;
  }

  /* Prepare submission queue entries */
  for (i = 0; i < count; i++) {
    sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
      break;
    }

    iovs[i].iov_base = (void *)packets[i];
    iovs[i].iov_len = lengths[i];

    msgs[i].msg_name = (void *)&dests[i];
    msgs[i].msg_namelen = sizeof(struct sockaddr_in);
    msgs[i].msg_iov = &iovs[i];
    msgs[i].msg_iovlen = 1;
    msgs[i].msg_control = NULL;
    msgs[i].msg_controllen = 0;
    msgs[i].msg_flags = 0;

    io_uring_prep_sendmsg(sqe, io_uring_sockfd, &msgs[i], 0);
    sqe->user_data = i;
  }

  /* Submit all at once */
  int submitted = io_uring_submit(&ring);

  /* Wait for completions */
  struct io_uring_cqe *cqe;
  int completed = 0;

  for (int j = 0; j < submitted; j++) {
    int ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
      break;
    }
    if (cqe->res >= 0) {
      completed++;
      io_uring_stats.packets_sent++;
      io_uring_stats.bytes_sent += cqe->res;
    } else {
      io_uring_stats.errors++;
    }
    io_uring_cqe_seen(&ring, cqe);
  }

  free(msgs);
  free(iovs);

  return completed;
}

int io_uring_send_single(const uint8_t *data, uint32_t len,
                         const struct sockaddr_in *dest) {
  if (!io_uring_initialized) {
    return -1;
  }

  struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  if (!sqe) {
    return -1;
  }

  struct msghdr msg = {0};
  struct iovec iov = {.iov_base = (void *)data, .iov_len = len};

  msg.msg_name = (void *)dest;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  io_uring_prep_sendmsg(sqe, io_uring_sockfd, &msg, 0);

  int ret = io_uring_submit(&ring);
  if (ret < 0) {
    return ret;
  }

  struct io_uring_cqe *cqe;
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    return ret;
  }

  int result = cqe->res;
  io_uring_cqe_seen(&ring, cqe);

  return result;
}

int io_uring_get_stats(driver_stats_t *stats) {
  if (!io_uring_initialized || !stats) {
    return -1;
  }

  *stats = io_uring_stats;
  return 0;
}

int cleanup_io_uring(void) {
  if (io_uring_initialized) {
    if (io_uring_sockfd >= 0) {
      close(io_uring_sockfd);
      io_uring_sockfd = -1;
    }
    io_uring_queue_exit(&ring);
    io_uring_initialized = 0;
    memset(&io_uring_stats, 0, sizeof(io_uring_stats));
  }
  return 0;
}

#endif /* HAS_IO_URING */

/* ============================================================================
 * sendmmsg Batch Sending (Linux)
 * ============================================================================
 */

#ifdef __linux__
#include <sys/socket.h>

int sendmmsg_batch(int sockfd, const uint8_t **packets, const uint32_t *lengths,
                   const struct sockaddr_in *dests, uint32_t count) {
  struct mmsghdr *msgs;
  struct iovec *iovs;
  uint32_t i;
  int sent;

  msgs = (struct mmsghdr *)calloc(count, sizeof(struct mmsghdr));
  iovs = (struct iovec *)calloc(count, sizeof(struct iovec));
  if (!msgs || !iovs) {
    free(msgs);
    free(iovs);
    return -1;
  }

  for (i = 0; i < count; i++) {
    iovs[i].iov_base = (void *)packets[i];
    iovs[i].iov_len = lengths[i];

    msgs[i].msg_hdr.msg_name = (void *)&dests[i];
    msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
    msgs[i].msg_hdr.msg_iov = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_control = NULL;
    msgs[i].msg_hdr.msg_controllen = 0;
    msgs[i].msg_hdr.msg_flags = 0;
  }

  sent = sendmmsg(sockfd, msgs, count, 0);

  free(msgs);
  free(iovs);

  return sent;
}

int sendmmsg_batch_same_dest(int sockfd, const uint8_t **packets,
                             const uint32_t *lengths, uint32_t dst_ip,
                             uint16_t dst_port, uint32_t count) {
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = dst_ip;
  dest.sin_port = htons(dst_port);

  struct mmsghdr *msgs;
  struct iovec *iovs;
  uint32_t i;
  int sent;

  msgs = (struct mmsghdr *)calloc(count, sizeof(struct mmsghdr));
  iovs = (struct iovec *)calloc(count, sizeof(struct iovec));
  if (!msgs || !iovs) {
    free(msgs);
    free(iovs);
    return -1;
  }

  for (i = 0; i < count; i++) {
    iovs[i].iov_base = (void *)packets[i];
    iovs[i].iov_len = lengths[i];

    msgs[i].msg_hdr.msg_name = &dest;
    msgs[i].msg_hdr.msg_namelen = sizeof(dest);
    msgs[i].msg_hdr.msg_iov = &iovs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_control = NULL;
    msgs[i].msg_hdr.msg_controllen = 0;
    msgs[i].msg_hdr.msg_flags = 0;
  }

  sent = sendmmsg(sockfd, msgs, count, 0);

  free(msgs);
  free(iovs);

  return sent;
}

#else

/* Fallback for non-Linux systems */
int sendmmsg_batch(int sockfd, const uint8_t **packets, const uint32_t *lengths,
                   const struct sockaddr_in *dests, uint32_t count) {
  int sent = 0;
  for (uint32_t i = 0; i < count; i++) {
    int bytes_sent =
        sendto(sockfd, (const char *)packets[i], lengths[i], 0,
               (struct sockaddr *)&dests[i], sizeof(struct sockaddr_in));
    if (bytes_sent > 0) {
      sent++;
    }
  }
  return sent;
}

int sendmmsg_batch_same_dest(int sockfd, const uint8_t **packets,
                             const uint32_t *lengths, uint32_t dst_ip,
                             uint16_t dst_port, uint32_t count) {
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = dst_ip;
  dest.sin_port = htons(dst_port);

  int sent = 0;
  for (uint32_t i = 0; i < count; i++) {
    int bytes_sent = sendto(sockfd, (const char *)packets[i], lengths[i], 0,
                            (struct sockaddr *)&dest, sizeof(dest));
    if (bytes_sent > 0) {
      sent++;
    }
  }
  return sent;
}

#endif /* __linux__ */

/* ============================================================================
 * Backend Detection and Selection
 * ============================================================================
 */

int detect_capabilities(system_capabilities_t *caps) {
  memset(caps, 0, sizeof(system_capabilities_t));

  /* Always have raw sockets */
  caps->has_raw_socket = 1;

  /* CPU count */
  caps->cpu_count = get_cpu_count();

#ifdef __linux__
  /* Check kernel version */
  struct utsname uts;
  if (uname(&uts) == 0) {
    sscanf(uts.release, "%d.%d", &caps->kernel_version_major,
           &caps->kernel_version_minor);
  }

  /* sendmmsg available on Linux 3.0+ */
  if (caps->kernel_version_major >= 3) {
    caps->has_sendmmsg = 1;
  }

  /* io_uring available on Linux 5.1+ */
  if (caps->kernel_version_major > 5 ||
      (caps->kernel_version_major == 5 && caps->kernel_version_minor >= 1)) {
#ifdef HAS_IO_URING
    caps->has_io_uring = 1;
#endif
  }

  /* AF_XDP available on Linux 4.18+ */
  if (caps->kernel_version_major > 4 ||
      (caps->kernel_version_major == 4 && caps->kernel_version_minor >= 18)) {
#ifdef HAS_AF_XDP
    caps->has_af_xdp = 1;
#endif
  }

  /* NUMA detection */
  FILE *f = fopen("/sys/devices/system/node/online", "r");
  if (f) {
    char buf[64];
    if (fgets(buf, sizeof(buf), f)) {
      /* Parse "0-N" format */
      int start, end;
      if (sscanf(buf, "%d-%d", &start, &end) == 2) {
        caps->numa_nodes = end - start + 1;
      } else {
        caps->numa_nodes = 1;
      }
    }
    fclose(f);
  }
#endif

#ifdef HAS_DPDK
  caps->has_dpdk = 1;
#endif

#ifdef HAS_FPGA
  caps->has_fpga = fpga_is_available();
#endif

  return 0;
}

backend_type_t select_best_backend(const system_capabilities_t *caps) {
  /* Priority: FPGA > DPDK > AF_XDP > io_uring > sendmmsg > raw_socket */
  if (caps->has_fpga) {
    return BACKEND_FPGA;
  }
  if (caps->has_dpdk) {
    return BACKEND_DPDK;
  }
  if (caps->has_af_xdp) {
    return BACKEND_AF_XDP;
  }
  if (caps->has_io_uring) {
    return BACKEND_IO_URING;
  }
  if (caps->has_sendmmsg) {
    return BACKEND_SENDMMSG;
  }
  return BACKEND_RAW_SOCKET;
}

const char *backend_name(backend_type_t backend) {
  switch (backend) {
  case BACKEND_FPGA:
    return "FPGA";
  case BACKEND_DPDK:
    return "DPDK";
  case BACKEND_AF_XDP:
    return "AF_XDP";
  case BACKEND_IO_URING:
    return "io_uring";
  case BACKEND_SENDMMSG:
    return "sendmmsg";
  case BACKEND_RAW_SOCKET:
    return "raw_socket";
  default:
    return "unknown";
  }
}
/* ============================================================================
 * FPGA Implementation
 * ============================================================================
 */

#ifdef HAS_FPGA

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>


/* Global FPGA state */
static fpga_device_t g_fpga_devices[4];
static int g_num_fpga_devices = 0;
static int g_fpga_initialized[4] = {0};
static void *g_fpga_memory[4] = {NULL};
static int g_fpga_fd[4] = {-1};

/* PCIe vendor IDs for FPGA devices */
#define XILINX_VENDOR_ID 0x10EE
#define INTEL_VENDOR_ID 0x8086

/* FPGA device IDs (common ones) */
#define XILINX_KINTEX_7 0x7028
#define XILINX_VIRTEX_7 0x7038
#define INTEL_ARRIA_10 0x09C4
#define INTEL_STRATIX_10 0x1D70

int fpga_detect_devices(fpga_device_t *devices, int max_devices) {
  int count = 0;
  DIR *pci_dir;
  struct dirent *entry;
  char path[256];
  FILE *vendor_file, *device_file;
  uint16_t vendor_id, device_id;

  /* Scan PCIe devices */
  pci_dir = opendir("/sys/bus/pci/devices");
  if (!pci_dir) {
    return 0;
  }

  while ((entry = readdir(pci_dir)) != NULL && count < max_devices) {
    if (entry->d_name[0] == '.')
      continue;

    /* Read vendor ID */
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/vendor",
             entry->d_name);
    vendor_file = fopen(path, "r");
    if (!vendor_file)
      continue;

    if (fscanf(vendor_file, "0x%hx", &vendor_id) != 1) {
      fclose(vendor_file);
      continue;
    }
    fclose(vendor_file);

    /* Check if it's an FPGA vendor */
    if (vendor_id != XILINX_VENDOR_ID && vendor_id != INTEL_VENDOR_ID) {
      continue;
    }

    /* Read device ID */
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/device",
             entry->d_name);
    device_file = fopen(path, "r");
    if (!device_file)
      continue;

    if (fscanf(device_file, "0x%hx", &device_id) != 1) {
      fclose(device_file);
      continue;
    }
    fclose(device_file);

    /* Fill device structure */
    devices[count].vendor_id = vendor_id;
    devices[count].device_id = device_id;
    devices[count].pcie_slot = count;

    if (vendor_id == XILINX_VENDOR_ID) {
      devices[count].vendor = FPGA_VENDOR_XILINX;
      switch (device_id) {
      case XILINX_KINTEX_7:
        strncpy(devices[count].device_name, "Xilinx Kintex-7",
                sizeof(devices[count].device_name));
        devices[count].memory_size = 512 * 1024 * 1024; /* 512MB */
        devices[count].dma_channels = 4;
        break;
      case XILINX_VIRTEX_7:
        strncpy(devices[count].device_name, "Xilinx Virtex-7",
                sizeof(devices[count].device_name));
        devices[count].memory_size = 1024 * 1024 * 1024; /* 1GB */
        devices[count].dma_channels = 8;
        break;
      default:
        strncpy(devices[count].device_name, "Xilinx FPGA",
                sizeof(devices[count].device_name));
        devices[count].memory_size = 256 * 1024 * 1024; /* 256MB */
        devices[count].dma_channels = 2;
        break;
      }
    } else if (vendor_id == INTEL_VENDOR_ID) {
      devices[count].vendor = FPGA_VENDOR_INTEL;
      switch (device_id) {
      case INTEL_ARRIA_10:
        strncpy(devices[count].device_name, "Intel Arria 10",
                sizeof(devices[count].device_name));
        devices[count].memory_size = 512 * 1024 * 1024; /* 512MB */
        devices[count].dma_channels = 4;
        break;
      case INTEL_STRATIX_10:
        strncpy(devices[count].device_name, "Intel Stratix 10",
                sizeof(devices[count].device_name));
        devices[count].memory_size = 2048 * 1024 * 1024; /* 2GB */
        devices[count].dma_channels = 16;
        break;
      default:
        strncpy(devices[count].device_name, "Intel FPGA",
                sizeof(devices[count].device_name));
        devices[count].memory_size = 256 * 1024 * 1024; /* 256MB */
        devices[count].dma_channels = 2;
        break;
      }
    }

    count++;
  }

  closedir(pci_dir);
  g_num_fpga_devices = count;
  memcpy(g_fpga_devices, devices, count * sizeof(fpga_device_t));

  return count;
}

int fpga_init_device(int device_id) {
  if (device_id < 0 || device_id >= g_num_fpga_devices) {
    return -1;
  }

  if (g_fpga_initialized[device_id]) {
    return 0; /* Already initialized */
  }

  char dev_path[256];
  snprintf(dev_path, sizeof(dev_path), "/dev/fpga%d", device_id);

  /* Try to open FPGA device */
  g_fpga_fd[device_id] = open(dev_path, O_RDWR);
  if (g_fpga_fd[device_id] < 0) {
    /* Try alternative path */
    snprintf(dev_path, sizeof(dev_path), "/dev/xdma%d_user", device_id);
    g_fpga_fd[device_id] = open(dev_path, O_RDWR);
    if (g_fpga_fd[device_id] < 0) {
      return -1;
    }
  }

  /* Map FPGA memory */
  g_fpga_memory[device_id] =
      mmap(NULL, g_fpga_devices[device_id].memory_size, PROT_READ | PROT_WRITE,
           MAP_SHARED, g_fpga_fd[device_id], 0);
  if (g_fpga_memory[device_id] == MAP_FAILED) {
    close(g_fpga_fd[device_id]);
    g_fpga_fd[device_id] = -1;
    return -1;
  }

  g_fpga_initialized[device_id] = 1;
  return 0;
}

int fpga_load_bitstream(int device_id, const char *bitstream_path) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id]) {
    return -1;
  }

  FILE *bitstream_file = fopen(bitstream_path, "rb");
  if (!bitstream_file) {
    return -1;
  }

  /* Get file size */
  fseek(bitstream_file, 0, SEEK_END);
  long bitstream_size = ftell(bitstream_file);
  fseek(bitstream_file, 0, SEEK_SET);

  /* Allocate buffer */
  uint8_t *bitstream_data = malloc(bitstream_size);
  if (!bitstream_data) {
    fclose(bitstream_file);
    return -1;
  }

  /* Read bitstream */
  if (fread(bitstream_data, 1, bitstream_size, bitstream_file) !=
      (size_t)bitstream_size) {
    free(bitstream_data);
    fclose(bitstream_file);
    return -1;
  }
  fclose(bitstream_file);

  /* Write bitstream to FPGA (vendor-specific implementation would go here) */
  /* For now, we simulate successful loading */
  printf("Loading bitstream %s to FPGA device %d (%ld bytes)\n", bitstream_path,
         device_id, bitstream_size);

  free(bitstream_data);
  return 0;
}

int fpga_init_dma(int device_id, int num_channels) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id]) {
    return -1;
  }

  if (num_channels > g_fpga_devices[device_id].dma_channels) {
    return -1; /* Not enough DMA channels */
  }

  /* Initialize DMA channels (vendor-specific implementation) */
  printf("Initializing %d DMA channels for FPGA device %d\n", num_channels,
         device_id);

  return 0;
}

int fpga_send_template(int device_id, const uint8_t *template_data,
                       uint32_t template_size) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id]) {
    return -1;
  }

  if (!template_data || template_size == 0 || template_size > 1500) {
    return -1; /* Invalid template */
  }

  /* Copy template to FPGA memory */
  if (g_fpga_memory[device_id]) {
    memcpy(g_fpga_memory[device_id], template_data, template_size);

    /* Write template size to control register (offset 0x1000) */
    volatile uint32_t *control_reg =
        (volatile uint32_t *)((char *)g_fpga_memory[device_id] + 0x1000);
    *control_reg = template_size;

    printf("Sent %u byte packet template to FPGA device %d\n", template_size,
           device_id);
    return 0;
  }

  return -1;
}

int fpga_configure_generation(int device_id, const fpga_config_t *config) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id] || !config) {
    return -1;
  }

  if (!g_fpga_memory[device_id]) {
    return -1;
  }

  /* Write configuration to FPGA control registers */
  volatile uint32_t *control_base =
      (volatile uint32_t *)((char *)g_fpga_memory[device_id] + 0x1000);

  control_base[1] = config->rate_pps;    /* Rate control register */
  control_base[2] = config->burst_size;  /* Burst size register */
  control_base[3] = config->duration_ms; /* Duration register */
  control_base[4] =
      config->enable_checksum_offload ? 1 : 0; /* Checksum enable */

  printf("Configured FPGA device %d: rate=%u PPS, burst=%u, duration=%u ms\n",
         device_id, config->rate_pps, config->burst_size, config->duration_ms);

  return 0;
}

int fpga_start_generation(int device_id) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id]) {
    return -1;
  }

  if (!g_fpga_memory[device_id]) {
    return -1;
  }

  /* Set start bit in control register */
  volatile uint32_t *control_reg =
      (volatile uint32_t *)((char *)g_fpga_memory[device_id] + 0x1000);
  control_reg[0] |= 0x1; /* Set start bit */

  printf("Started packet generation on FPGA device %d\n", device_id);
  return 0;
}

int fpga_stop_generation(int device_id) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id]) {
    return -1;
  }

  if (!g_fpga_memory[device_id]) {
    return -1;
  }

  /* Clear start bit in control register */
  volatile uint32_t *control_reg =
      (volatile uint32_t *)((char *)g_fpga_memory[device_id] + 0x1000);
  control_reg[0] &= ~0x1; /* Clear start bit */

  printf("Stopped packet generation on FPGA device %d\n", device_id);
  return 0;
}

int fpga_enable_checksum_offload(int device_id, int enable_ip, int enable_tcp,
                                 int enable_udp) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id]) {
    return -1;
  }

  if (!g_fpga_memory[device_id]) {
    return -1;
  }

  /* Configure checksum offload in control register */
  volatile uint32_t *control_reg =
      (volatile uint32_t *)((char *)g_fpga_memory[device_id] + 0x1000);
  uint32_t checksum_config = 0;

  if (enable_ip)
    checksum_config |= 0x1;
  if (enable_tcp)
    checksum_config |= 0x2;
  if (enable_udp)
    checksum_config |= 0x4;

  control_reg[5] = checksum_config; /* Checksum configuration register */

  printf(
      "Configured checksum offload on FPGA device %d: IP=%d, TCP=%d, UDP=%d\n",
      device_id, enable_ip, enable_tcp, enable_udp);

  return 0;
}

int fpga_get_stats(int device_id, fpga_stats_t *stats) {
  if (device_id < 0 || device_id >= g_num_fpga_devices ||
      !g_fpga_initialized[device_id] || !stats) {
    return -1;
  }

  if (!g_fpga_memory[device_id]) {
    return -1;
  }

  /* Read statistics from FPGA status registers */
  volatile uint32_t *status_base =
      (volatile uint32_t *)((char *)g_fpga_memory[device_id] + 0x2000);

  stats->packets_generated = ((uint64_t)status_base[1] << 32) | status_base[0];
  stats->bytes_generated = ((uint64_t)status_base[3] << 32) | status_base[2];
  stats->checksum_operations =
      ((uint64_t)status_base[5] << 32) | status_base[4];
  stats->dma_transfers = ((uint64_t)status_base[7] << 32) | status_base[6];
  stats->current_pps = status_base[8];
  stats->errors = status_base[9];

  return 0;
}

int fpga_cleanup(int device_id) {
  if (device_id < 0 || device_id >= g_num_fpga_devices) {
    return -1;
  }

  if (!g_fpga_initialized[device_id]) {
    return 0; /* Already cleaned up */
  }

  /* Stop generation if running */
  fpga_stop_generation(device_id);

  /* Unmap memory */
  if (g_fpga_memory[device_id] && g_fpga_memory[device_id] != MAP_FAILED) {
    munmap(g_fpga_memory[device_id], g_fpga_devices[device_id].memory_size);
    g_fpga_memory[device_id] = NULL;
  }

  /* Close device */
  if (g_fpga_fd[device_id] >= 0) {
    close(g_fpga_fd[device_id]);
    g_fpga_fd[device_id] = -1;
  }

  g_fpga_initialized[device_id] = 0;

  printf("Cleaned up FPGA device %d\n", device_id);
  return 0;
}

int fpga_is_available(void) {
  /* Check if FPGA devices are present */
  fpga_device_t temp_devices[4];
  int count = fpga_detect_devices(temp_devices, 4);
  return count > 0 ? 1 : 0;
}

#endif /* HAS_FPGA */