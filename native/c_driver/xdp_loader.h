/**
 * NetStress XDP/eBPF Loader
 * Kernel-level packet filtering using eBPF/XDP
 */

#ifndef NETSTRESS_XDP_LOADER_H
#define NETSTRESS_XDP_LOADER_H

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * XDP Types and Structures
 * ============================================================================
 */

typedef struct {
  uint64_t packets_dropped;
  uint64_t packets_passed;
  uint64_t bytes_dropped;
  uint64_t bytes_passed;
  uint64_t syn_ack_dropped;
  uint64_t rst_dropped;
} xdp_stats_t;

typedef enum {
  XDP_FLAGS_UPDATE_IF_NOEXIST = (1U << 0),
  XDP_FLAGS_SKB_MODE = (1U << 1),
  XDP_FLAGS_DRV_MODE = (1U << 2),
  XDP_FLAGS_HW_MODE = (1U << 3),
  XDP_FLAGS_REPLACE = (1U << 4)
} xdp_flags_t;

typedef struct {
  const char *interface;
  xdp_flags_t flags;
  int map_fd;
  int prog_fd;
  int attached;
} xdp_context_t;

/* ============================================================================
 * XDP Program Loading Functions
 * ============================================================================
 */

/**
 * Load XDP program from bytecode file
 * @param ifname Interface name (e.g., "eth0")
 * @param bytecode_path Path to compiled eBPF bytecode file
 * @param flags XDP attachment flags
 * @return XDP context pointer or NULL on error
 */
xdp_context_t *xdp_load_program(const char *ifname, const char *bytecode_path,
                                xdp_flags_t flags);

/**
 * Load XDP program from bytecode buffer
 * @param ifname Interface name
 * @param bytecode eBPF bytecode buffer
 * @param bytecode_len Length of bytecode
 * @param flags XDP attachment flags
 * @return XDP context pointer or NULL on error
 */
xdp_context_t *xdp_load_program_from_buffer(const char *ifname,
                                            const uint8_t *bytecode,
                                            size_t bytecode_len,
                                            xdp_flags_t flags);

/**
 * Unload XDP program from interface
 * @param ctx XDP context
 * @return 0 on success, negative on error
 */
int xdp_unload_program(xdp_context_t *ctx);

/**
 * Get XDP statistics from BPF map
 * @param ctx XDP context
 * @param stats Output statistics structure
 * @return 0 on success, negative on error
 */
int xdp_get_stats(xdp_context_t *ctx, xdp_stats_t *stats);

/**
 * Reset XDP statistics
 * @param ctx XDP context
 * @return 0 on success, negative on error
 */
int xdp_reset_stats(xdp_context_t *ctx);

/**
 * Check if XDP is supported on interface
 * @param ifname Interface name
 * @return 1 if supported, 0 if not, negative on error
 */
int xdp_is_supported(const char *ifname);

/**
 * Get interface index from name
 * @param ifname Interface name
 * @return Interface index or negative on error
 */
int get_ifindex(const char *ifname);

/* ============================================================================
 * Fallback Functions (iptables)
 * ============================================================================
 */

/**
 * Install iptables rules as XDP fallback
 * @param interface Interface name
 * @return 0 on success, negative on error
 */
int install_iptables_fallback(const char *interface);

/**
 * Remove iptables fallback rules
 * @param interface Interface name
 * @return 0 on success, negative on error
 */
int remove_iptables_fallback(const char *interface);

/**
 * Check if iptables is available
 * @return 1 if available, 0 if not
 */
int iptables_available(void);

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

/**
 * Compile eBPF source to bytecode
 * @param source_path Path to .c source file
 * @param output_path Path for output bytecode
 * @return 0 on success, negative on error
 */
int compile_ebpf_program(const char *source_path, const char *output_path);

/**
 * Get XDP mode string for debugging
 * @param flags XDP flags
 * @return Mode string
 */
const char *xdp_mode_string(xdp_flags_t flags);

/**
 * Free XDP context
 * @param ctx XDP context to free
 */
void xdp_free_context(xdp_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* NETSTRESS_XDP_LOADER_H */