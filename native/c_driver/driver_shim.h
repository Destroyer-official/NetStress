/**
 * NetStress C Driver Shim
 * Low-level hardware interface for DPDK, AF_XDP, and raw sockets
 */

#ifndef NETSTRESS_DRIVER_SHIM_H
#define NETSTRESS_DRIVER_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Common Types
 * ============================================================================
 */

typedef struct {
  uint32_t packets_sent;
  uint32_t packets_received;
  uint32_t bytes_sent;
  uint32_t bytes_received;
  uint32_t errors;
} driver_stats_t;

typedef struct {
  const char *interface;
  uint16_t port_id;
  uint32_t num_queues;
  uint32_t ring_size;
  uint32_t burst_size;
  int promiscuous;
} driver_config_t;

/* ============================================================================
 * DPDK Functions (when HAS_DPDK is defined)
 * ============================================================================
 */

#ifdef HAS_DPDK

/**
 * Initialize DPDK EAL (Environment Abstraction Layer)
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, negative on error
 */
int dpdk_init(int argc, char **argv);

/**
 * Initialize a DPDK port for packet I/O
 * @param port_id Port identifier
 * @return 0 on success, negative on error
 */
int init_dpdk_port(int port_id);

/**
 * Send a burst of packets via DPDK
 * @param port_id Port identifier
 * @param packets Array of packet data pointers
 * @param lengths Array of packet lengths
 * @param count Number of packets
 * @return Number of packets sent
 */
int dpdk_send_burst(int port_id, const uint8_t **packets,
                    const uint32_t *lengths, uint32_t count);

/**
 * Receive a burst of packets via DPDK
 * @param port_id Port identifier
 * @param packets Output array for packet data
 * @param max_count Maximum packets to receive
 * @return Number of packets received
 */
int dpdk_recv_burst(int port_id, uint8_t **packets, uint32_t max_count);

/**
 * Get DPDK port statistics
 * @param port_id Port identifier
 * @param stats Output statistics structure
 * @return 0 on success
 */
int dpdk_get_stats(int port_id, driver_stats_t *stats);

/**
 * Cleanup DPDK resources
 * @return 0 on success
 */
int cleanup_dpdk(void);

#else

/* Stub implementations when DPDK is not available */
static inline int dpdk_init(int argc, char **argv) {
  (void)argc;
  (void)argv;
  return -1;
}
static inline int init_dpdk_port(int port_id) {
  (void)port_id;
  return -1;
}
static inline int dpdk_send_burst(int port_id, const uint8_t **packets,
                                  const uint32_t *lengths, uint32_t count) {
  (void)port_id;
  (void)packets;
  (void)lengths;
  (void)count;
  return -1;
}
static inline int dpdk_recv_burst(int port_id, uint8_t **packets,
                                  uint32_t max_count) {
  (void)port_id;
  (void)packets;
  (void)max_count;
  return -1;
}
static inline int dpdk_get_stats(int port_id, driver_stats_t *stats) {
  (void)port_id;
  (void)stats;
  return -1;
}
static inline int cleanup_dpdk(void) { return 0; }

#endif /* HAS_DPDK */

/* ============================================================================
 * AF_XDP Functions (when HAS_AF_XDP is defined)
 * ============================================================================
 */

#ifdef HAS_AF_XDP

/**
 * Initialize AF_XDP socket on interface
 * @param ifname Interface name (e.g., "eth0")
 * @return Socket descriptor or negative on error
 */
int init_af_xdp(const char *ifname);

/**
 * Send packet via AF_XDP
 * @param data Packet data
 * @param len Packet length
 * @return 0 on success, negative on error
 */
int af_xdp_send(const uint8_t *data, uint32_t len);

/**
 * Send batch of packets via AF_XDP
 * @param packets Array of packet data
 * @param lengths Array of lengths
 * @param count Number of packets
 * @return Number of packets sent
 */
int af_xdp_send_batch(const uint8_t **packets, const uint32_t *lengths,
                      uint32_t count);

/**
 * Receive packet via AF_XDP
 * @param buffer Output buffer
 * @param max_len Maximum buffer size
 * @return Bytes received or negative on error
 */
int af_xdp_recv(uint8_t *buffer, uint32_t max_len);

/**
 * Cleanup AF_XDP resources
 * @return 0 on success
 */
int cleanup_af_xdp(void);

#else

/* Stub implementations when AF_XDP is not available */
static inline int init_af_xdp(const char *ifname) {
  (void)ifname;
  return -1;
}
static inline int af_xdp_send(const uint8_t *data, uint32_t len) {
  (void)data;
  (void)len;
  return -1;
}
static inline int af_xdp_send_batch(const uint8_t **packets,
                                    const uint32_t *lengths, uint32_t count) {
  (void)packets;
  (void)lengths;
  (void)count;
  return -1;
}
static inline int af_xdp_recv(uint8_t *buffer, uint32_t max_len) {
  (void)buffer;
  (void)max_len;
  return -1;
}
static inline int cleanup_af_xdp(void) { return 0; }

#endif /* HAS_AF_XDP */

/* ============================================================================
 * Raw Socket Functions (always available)
 * ============================================================================
 */

/**
 * Create a raw socket
 * @param protocol IP protocol number (IPPROTO_RAW, IPPROTO_TCP, etc.)
 * @return Socket descriptor or negative on error
 */
int raw_socket_create(int protocol);

/**
 * Send raw packet
 * @param sockfd Socket descriptor
 * @param dst_ip Destination IP (network byte order)
 * @param data Packet data
 * @param len Packet length
 * @return Bytes sent or negative on error
 */
int raw_socket_send(int sockfd, uint32_t dst_ip, const uint8_t *data,
                    uint32_t len);

/**
 * Send raw packet with IP header included
 * @param sockfd Socket descriptor
 * @param data Full packet including IP header
 * @param len Packet length
 * @return Bytes sent or negative on error
 */
int raw_socket_send_ip(int sockfd, const uint8_t *data, uint32_t len);

/**
 * Close raw socket
 * @param sockfd Socket descriptor
 */
void raw_socket_close(int sockfd);

/**
 * Set socket option for IP_HDRINCL
 * @param sockfd Socket descriptor
 * @return 0 on success
 */
int raw_socket_set_hdrincl(int sockfd);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * Calculate IP checksum
 * @param data Data buffer
 * @param len Data length
 * @return Checksum value
 */
uint16_t calculate_checksum(const uint8_t *data, size_t len);

/**
 * Calculate TCP/UDP checksum with pseudo-header
 * @param src_ip Source IP
 * @param dst_ip Destination IP
 * @param protocol Protocol number
 * @param data Segment data
 * @param len Segment length
 * @return Checksum value
 */
uint16_t calculate_transport_checksum(uint32_t src_ip, uint32_t dst_ip,
                                      uint8_t protocol, const uint8_t *data,
                                      size_t len);

/**
 * Get current timestamp in microseconds
 * @return Timestamp
 */
uint64_t get_timestamp_us(void);

/**
 * Get number of CPU cores
 * @return CPU count
 */
int get_cpu_count(void);

/**
 * Pin current thread to CPU core
 * @param cpu_id CPU core ID
 * @return 0 on success
 */
int pin_to_cpu(int cpu_id);

/* ============================================================================
 * io_uring Functions (when HAS_IO_URING is defined)
 * ============================================================================
 */

#ifdef HAS_IO_URING

/**
 * Initialize io_uring for async I/O
 * @param queue_depth Size of submission/completion queues
 * @return 0 on success, negative on error
 */
int init_io_uring(int queue_depth);

/**
 * Send batch of packets via io_uring
 * @param packets Array of packet data
 * @param lengths Array of lengths
 * @param dests Array of destination addresses
 * @param count Number of packets
 * @return Number of packets sent
 */
int io_uring_send_batch(const uint8_t **packets, const uint32_t *lengths,
                        const struct sockaddr_in *dests, uint32_t count);

/**
 * Send single packet via io_uring
 * @param data Packet data
 * @param len Packet length
 * @param dest Destination address
 * @return Bytes sent or negative on error
 */
int io_uring_send_single(const uint8_t *data, uint32_t len,
                         const struct sockaddr_in *dest);

/**
 * Cleanup io_uring resources
 * @return 0 on success
 */
int cleanup_io_uring(void);

/**
 * Get io_uring statistics
 * @param stats Output statistics structure
 * @return 0 on success
 */
int io_uring_get_stats(driver_stats_t *stats);

#else

/* Stub implementations when io_uring is not available */
static inline int init_io_uring(int queue_depth) {
  (void)queue_depth;
  return -1;
}
static inline int io_uring_send_batch(const uint8_t **packets,
                                      const uint32_t *lengths,
                                      const struct sockaddr_in *dests,
                                      uint32_t count) {
  (void)packets;
  (void)lengths;
  (void)dests;
  (void)count;
  return -1;
}
static inline int io_uring_send_single(const uint8_t *data, uint32_t len,
                                       const struct sockaddr_in *dest) {
  (void)data;
  (void)len;
  (void)dest;
  return -1;
}
static inline int io_uring_get_stats(driver_stats_t *stats) {
  (void)stats;
  return -1;
}
static inline int cleanup_io_uring(void) { return 0; }

#endif /* HAS_IO_URING */

/* ============================================================================
 * sendmmsg Batch Sending Functions
 * ============================================================================
 */

/**
 * Send batch of packets using sendmmsg (Linux) or fallback loop
 * @param sockfd Socket descriptor
 * @param packets Array of packet data
 * @param lengths Array of lengths
 * @param dests Array of destination addresses
 * @param count Number of packets
 * @return Number of packets sent
 */
int sendmmsg_batch(int sockfd, const uint8_t **packets, const uint32_t *lengths,
                   const struct sockaddr_in *dests, uint32_t count);

/**
 * Send batch of packets to same destination
 * @param sockfd Socket descriptor
 * @param packets Array of packet data
 * @param lengths Array of lengths
 * @param dst_ip Destination IP (network byte order)
 * @param dst_port Destination port (host byte order)
 * @param count Number of packets
 * @return Number of packets sent
 */
int sendmmsg_batch_same_dest(int sockfd, const uint8_t **packets,
                             const uint32_t *lengths, uint32_t dst_ip,
                             uint16_t dst_port, uint32_t count);

/* ============================================================================
 * Backend Detection and Selection
 * ============================================================================
 */

typedef enum {
  BACKEND_NONE = 0,
  BACKEND_RAW_SOCKET = 1,
  BACKEND_SENDMMSG = 2,
  BACKEND_IO_URING = 3,
  BACKEND_AF_XDP = 4,
  BACKEND_DPDK = 5,
  BACKEND_FPGA = 6
} backend_type_t;

typedef struct {
  int has_dpdk;
  int has_af_xdp;
  int has_io_uring;
  int has_sendmmsg;
  int has_raw_socket;
  int has_fpga;
  int kernel_version_major;
  int kernel_version_minor;
  int cpu_count;
  int numa_nodes;
} system_capabilities_t;

/**
 * Detect system capabilities for backend selection
 * @param caps Output capabilities structure
 * @return 0 on success
 */
int detect_capabilities(system_capabilities_t *caps);

/**
 * Select best available backend based on capabilities
 * @param caps System capabilities
 * @return Best available backend type
 */
backend_type_t select_best_backend(const system_capabilities_t *caps);

/**
 * Get human-readable backend name
 * @param backend Backend type
 * @return Backend name string
 */
const char *backend_name(backend_type_t backend);

/* ============================================================================
 * XDP/eBPF Functions (when HAS_LIBBPF is defined)
 * ============================================================================
 */

#ifdef HAS_LIBBPF
#include "xdp_loader.h"
#else

/* Stub implementations when XDP is not available */
typedef struct xdp_context_t xdp_context_t;
typedef struct {
  uint64_t packets_dropped;
  uint64_t packets_passed;
  uint64_t bytes_dropped;
  uint64_t bytes_passed;
  uint64_t syn_ack_dropped;
  uint64_t rst_dropped;
} xdp_stats_t;

static inline xdp_context_t *
xdp_load_program(const char *ifname, const char *bytecode_path, int flags) {
  (void)ifname;
  (void)bytecode_path;
  (void)flags;
  return NULL;
}
static inline int xdp_unload_program(xdp_context_t *ctx) {
  (void)ctx;
  return -1;
}
static inline int xdp_get_stats(xdp_context_t *ctx, xdp_stats_t *stats) {
  (void)ctx;
  (void)stats;
  return -1;
}
static inline int xdp_is_supported(const char *ifname) {
  (void)ifname;
  return 0;
}
static inline int install_iptables_fallback(const char *interface) {
  (void)interface;
  return -1;
}
static inline int remove_iptables_fallback(const char *interface) {
  (void)interface;
  return -1;
}
static inline int iptables_available(void) { return 0; }
static inline void xdp_free_context(xdp_context_t *ctx) { (void)ctx; }

#endif /* HAS_LIBBPF */

/* ============================================================================
 * FPGA Functions (when HAS_FPGA is defined)
 * ============================================================================
 */

#ifdef HAS_FPGA

typedef enum {
  FPGA_VENDOR_XILINX = 0,
  FPGA_VENDOR_INTEL = 1,
  FPGA_VENDOR_UNKNOWN = 2
} fpga_vendor_t;

typedef struct {
  fpga_vendor_t vendor;
  uint16_t device_id;
  uint16_t vendor_id;
  char device_name[64];
  uint32_t memory_size;
  uint32_t dma_channels;
  int pcie_slot;
} fpga_device_t;

typedef struct {
  uint8_t *template_data;
  uint32_t template_size;
  uint32_t rate_pps;
  uint32_t burst_size;
  uint32_t duration_ms;
  int enable_checksum_offload;
} fpga_config_t;

typedef struct {
  uint64_t packets_generated;
  uint64_t bytes_generated;
  uint64_t checksum_operations;
  uint64_t dma_transfers;
  uint32_t current_pps;
  uint32_t errors;
} fpga_stats_t;

/**
 * Detect FPGA devices via PCIe enumeration
 * @param devices Output array for detected devices
 * @param max_devices Maximum number of devices to detect
 * @return Number of devices found
 */
int fpga_detect_devices(fpga_device_t *devices, int max_devices);

/**
 * Initialize FPGA device and DMA channels
 * @param device_id Device index from detection
 * @return 0 on success, negative on error
 */
int fpga_init_device(int device_id);

/**
 * Load bitstream to FPGA
 * @param device_id Device index
 * @param bitstream_path Path to bitstream file
 * @return 0 on success, negative on error
 */
int fpga_load_bitstream(int device_id, const char *bitstream_path);

/**
 * Initialize DMA channels for packet transfer
 * @param device_id Device index
 * @param num_channels Number of DMA channels to initialize
 * @return 0 on success, negative on error
 */
int fpga_init_dma(int device_id, int num_channels);

/**
 * Send packet template to FPGA for hardware generation
 * @param device_id Device index
 * @param template_data Packet template data
 * @param template_size Size of template
 * @return 0 on success, negative on error
 */
int fpga_send_template(int device_id, const uint8_t *template_data,
                       uint32_t template_size);

/**
 * Configure packet generation parameters
 * @param device_id Device index
 * @param config Generation configuration
 * @return 0 on success, negative on error
 */
int fpga_configure_generation(int device_id, const fpga_config_t *config);

/**
 * Start packet generation on FPGA
 * @param device_id Device index
 * @return 0 on success, negative on error
 */
int fpga_start_generation(int device_id);

/**
 * Stop packet generation on FPGA
 * @param device_id Device index
 * @return 0 on success, negative on error
 */
int fpga_stop_generation(int device_id);

/**
 * Enable checksum offload on FPGA
 * @param device_id Device index
 * @param enable_ip Enable IP checksum offload
 * @param enable_tcp Enable TCP checksum offload
 * @param enable_udp Enable UDP checksum offload
 * @return 0 on success, negative on error
 */
int fpga_enable_checksum_offload(int device_id, int enable_ip, int enable_tcp,
                                 int enable_udp);

/**
 * Get FPGA statistics
 * @param device_id Device index
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int fpga_get_stats(int device_id, fpga_stats_t *stats);

/**
 * Cleanup FPGA resources
 * @param device_id Device index
 * @return 0 on success
 */
int fpga_cleanup(int device_id);

/**
 * Check if FPGA is available and functional
 * @return 1 if available, 0 if not
 */
int fpga_is_available(void);

#else

/* Stub implementations when FPGA is not available */
typedef enum {
  FPGA_VENDOR_XILINX = 0,
  FPGA_VENDOR_INTEL = 1,
  FPGA_VENDOR_UNKNOWN = 2
} fpga_vendor_t;

typedef struct {
  fpga_vendor_t vendor;
  uint16_t device_id;
  uint16_t vendor_id;
  char device_name[64];
  uint32_t memory_size;
  uint32_t dma_channels;
  int pcie_slot;
} fpga_device_t;

typedef struct {
  uint8_t *template_data;
  uint32_t template_size;
  uint32_t rate_pps;
  uint32_t burst_size;
  uint32_t duration_ms;
  int enable_checksum_offload;
} fpga_config_t;

typedef struct {
  uint64_t packets_generated;
  uint64_t bytes_generated;
  uint64_t checksum_operations;
  uint64_t dma_transfers;
  uint32_t current_pps;
  uint32_t errors;
} fpga_stats_t;

static inline int fpga_detect_devices(fpga_device_t *devices, int max_devices) {
  (void)devices;
  (void)max_devices;
  return 0;
}
static inline int fpga_init_device(int device_id) {
  (void)device_id;
  return -1;
}
static inline int fpga_load_bitstream(int device_id,
                                      const char *bitstream_path) {
  (void)device_id;
  (void)bitstream_path;
  return -1;
}
static inline int fpga_init_dma(int device_id, int num_channels) {
  (void)device_id;
  (void)num_channels;
  return -1;
}
static inline int fpga_send_template(int device_id,
                                     const uint8_t *template_data,
                                     uint32_t template_size) {
  (void)device_id;
  (void)template_data;
  (void)template_size;
  return -1;
}
static inline int fpga_configure_generation(int device_id,
                                            const fpga_config_t *config) {
  (void)device_id;
  (void)config;
  return -1;
}
static inline int fpga_start_generation(int device_id) {
  (void)device_id;
  return -1;
}
static inline int fpga_stop_generation(int device_id) {
  (void)device_id;
  return -1;
}
static inline int fpga_enable_checksum_offload(int device_id, int enable_ip,
                                               int enable_tcp, int enable_udp) {
  (void)device_id;
  (void)enable_ip;
  (void)enable_tcp;
  (void)enable_udp;
  return -1;
}
static inline int fpga_get_stats(int device_id, fpga_stats_t *stats) {
  (void)device_id;
  (void)stats;
  return -1;
}
static inline int fpga_cleanup(int device_id) {
  (void)device_id;
  return 0;
}
static inline int fpga_is_available(void) { return 0; }

#endif /* HAS_FPGA */

#ifdef __cplusplus
}
#endif

#endif /* NETSTRESS_DRIVER_SHIM_H */
