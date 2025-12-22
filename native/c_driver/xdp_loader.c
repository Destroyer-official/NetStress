/**
 * NetStress XDP/eBPF Loader Implementation
 * Kernel-level packet filtering using eBPF/XDP
 */

#include "xdp_loader.h"
#include <errno.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#ifdef HAS_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#else
// Stub definitions when libbpf is not available
#define BPF_PROG_TYPE_XDP 6
#define BPF_MAP_TYPE_ARRAY 2
#define XDP_PASS 2
#define XDP_DROP 1
#endif

/* ============================================================================
 * Internal Helper Functions
 * ============================================================================
 */

static int get_ifindex_internal(const char *ifname) {
  int index = if_nametoindex(ifname);
  if (index == 0) {
    fprintf(stderr, "Interface %s not found: %s\n", ifname, strerror(errno));
    return -1;
  }
  return index;
}

static int check_kernel_version(void) {
  FILE *fp = fopen("/proc/version", "r");
  if (!fp)
    return 0;

  char line[256];
  if (fgets(line, sizeof(line), fp)) {
    int major, minor;
    if (sscanf(line, "Linux version %d.%d", &major, &minor) == 2) {
      fclose(fp);
      // XDP requires kernel 4.8+
      return (major > 4 || (major == 4 && minor >= 8));
    }
  }
  fclose(fp);
  return 0;
}

/* ============================================================================
 * XDP Program Loading Functions
 * ============================================================================
 */

xdp_context_t *xdp_load_program(const char *ifname, const char *bytecode_path,
                                xdp_flags_t flags) {
  if (!ifname || !bytecode_path) {
    fprintf(stderr, "Invalid parameters for XDP load\n");
    return NULL;
  }

  // Check kernel version
  if (!check_kernel_version()) {
    fprintf(stderr, "XDP requires Linux kernel 4.8 or later\n");
    return NULL;
  }

  // Get interface index
  int ifindex = get_ifindex_internal(ifname);
  if (ifindex < 0) {
    return NULL;
  }

  // Allocate context
  xdp_context_t *ctx = calloc(1, sizeof(xdp_context_t));
  if (!ctx) {
    fprintf(stderr, "Failed to allocate XDP context\n");
    return NULL;
  }

  ctx->interface = strdup(ifname);
  ctx->flags = flags;
  ctx->prog_fd = -1;
  ctx->map_fd = -1;
  ctx->attached = 0;

#ifdef HAS_LIBBPF
  struct bpf_object *obj = NULL;
  struct bpf_program *prog = NULL;
  struct bpf_map *map = NULL;

  // Load BPF object from file
  obj = bpf_object__open(bytecode_path);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "Failed to open BPF object: %s\n", bytecode_path);
    goto error;
  }

  // Load BPF program into kernel
  if (bpf_object__load(obj)) {
    fprintf(stderr, "Failed to load BPF object into kernel\n");
    goto error;
  }

  // Find XDP program
  prog = bpf_object__find_program_by_name(obj, "xdp_filter");
  if (!prog) {
    // Try generic name
    prog = bpf_program__next(NULL, obj);
    if (!prog) {
      fprintf(stderr, "No XDP program found in object\n");
      goto error;
    }
  }

  ctx->prog_fd = bpf_program__fd(prog);
  if (ctx->prog_fd < 0) {
    fprintf(stderr, "Failed to get program FD\n");
    goto error;
  }

  // Find statistics map
  map = bpf_object__find_map_by_name(obj, "stats_map");
  if (map) {
    ctx->map_fd = bpf_map__fd(map);
  }

  // Attach XDP program to interface
  uint32_t xdp_flags = 0;
  if (flags & XDP_FLAGS_SKB_MODE)
    xdp_flags |= XDP_FLAGS_SKB_MODE;
  if (flags & XDP_FLAGS_DRV_MODE)
    xdp_flags |= XDP_FLAGS_DRV_MODE;
  if (flags & XDP_FLAGS_HW_MODE)
    xdp_flags |= XDP_FLAGS_HW_MODE;

  if (bpf_set_link_xdp_fd(ifindex, ctx->prog_fd, xdp_flags) < 0) {
    fprintf(stderr, "Failed to attach XDP program to interface %s: %s\n",
            ifname, strerror(errno));
    goto error;
  }

  ctx->attached = 1;
  printf("XDP program loaded and attached to %s (mode: %s)\n", ifname,
         xdp_mode_string(flags));
  return ctx;

error:
  if (obj)
    bpf_object__close(obj);
  xdp_free_context(ctx);
  return NULL;

#else
  fprintf(stderr, "XDP support not compiled in (missing libbpf)\n");
  xdp_free_context(ctx);
  return NULL;
#endif
}

xdp_context_t *xdp_load_program_from_buffer(const char *ifname,
                                            const uint8_t *bytecode,
                                            size_t bytecode_len,
                                            xdp_flags_t flags) {
  if (!ifname || !bytecode || bytecode_len == 0) {
    fprintf(stderr, "Invalid parameters for XDP load from buffer\n");
    return NULL;
  }

  // Write bytecode to temporary file
  char temp_path[] = "/tmp/netstress_xdp_XXXXXX";
  int temp_fd = mkstemp(temp_path);
  if (temp_fd < 0) {
    fprintf(stderr, "Failed to create temporary file: %s\n", strerror(errno));
    return NULL;
  }

  if (write(temp_fd, bytecode, bytecode_len) != (ssize_t)bytecode_len) {
    fprintf(stderr, "Failed to write bytecode to temporary file\n");
    close(temp_fd);
    unlink(temp_path);
    return NULL;
  }
  close(temp_fd);

  // Load from temporary file
  xdp_context_t *ctx = xdp_load_program(ifname, temp_path, flags);

  // Clean up temporary file
  unlink(temp_path);

  return ctx;
}

int xdp_unload_program(xdp_context_t *ctx) {
  if (!ctx)
    return -1;

  int result = 0;

  if (ctx->attached) {
    int ifindex = get_ifindex_internal(ctx->interface);
    if (ifindex >= 0) {
#ifdef HAS_LIBBPF
      if (bpf_set_link_xdp_fd(ifindex, -1, 0) < 0) {
        fprintf(stderr, "Failed to detach XDP program from %s: %s\n",
                ctx->interface, strerror(errno));
        result = -1;
      } else {
        printf("XDP program detached from %s\n", ctx->interface);
        ctx->attached = 0;
      }
#endif
    }
  }

  if (ctx->prog_fd >= 0) {
    close(ctx->prog_fd);
    ctx->prog_fd = -1;
  }

  if (ctx->map_fd >= 0) {
    close(ctx->map_fd);
    ctx->map_fd = -1;
  }

  return result;
}

int xdp_get_stats(xdp_context_t *ctx, xdp_stats_t *stats) {
  if (!ctx || !stats || ctx->map_fd < 0) {
    return -1;
  }

  memset(stats, 0, sizeof(xdp_stats_t));

#ifdef HAS_LIBBPF
  // Read statistics from BPF map
  uint32_t key;
  uint64_t value;

  // packets_dropped (key 0)
  key = 0;
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) == 0) {
    stats->packets_dropped = value;
  }

  // packets_passed (key 1)
  key = 1;
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) == 0) {
    stats->packets_passed = value;
  }

  // bytes_dropped (key 2)
  key = 2;
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) == 0) {
    stats->bytes_dropped = value;
  }

  // bytes_passed (key 3)
  key = 3;
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) == 0) {
    stats->bytes_passed = value;
  }

  // syn_ack_dropped (key 4)
  key = 4;
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) == 0) {
    stats->syn_ack_dropped = value;
  }

  // rst_dropped (key 5)
  key = 5;
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) == 0) {
    stats->rst_dropped = value;
  }

  return 0;
#else
  return -1;
#endif
}

int xdp_reset_stats(xdp_context_t *ctx) {
  if (!ctx || ctx->map_fd < 0) {
    return -1;
  }

#ifdef HAS_LIBBPF
  uint32_t key;
  uint64_t zero = 0;

  // Reset all statistics counters
  for (key = 0; key < 6; key++) {
    if (bpf_map_update_elem(ctx->map_fd, &key, &zero, BPF_ANY) < 0) {
      fprintf(stderr, "Failed to reset stats key %u: %s\n", key,
              strerror(errno));
      return -1;
    }
  }

  return 0;
#else
  return -1;
#endif
}

int xdp_is_supported(const char *ifname) {
  if (!ifname)
    return 0;

  // Check kernel version
  if (!check_kernel_version()) {
    return 0;
  }

  // Check if interface exists
  if (get_ifindex_internal(ifname) < 0) {
    return 0;
  }

#ifdef HAS_LIBBPF
  // Try to query XDP capabilities
  int ifindex = get_ifindex_internal(ifname);
  if (ifindex < 0)
    return 0;

  // Check if we can get current XDP program (even if none is attached)
  uint32_t prog_id = 0;
  if (bpf_get_link_xdp_id(ifindex, &prog_id, 0) == 0) {
    return 1; // XDP is supported
  }
#endif

  return 0; // XDP not supported or libbpf not available
}

int get_ifindex(const char *ifname) { return get_ifindex_internal(ifname); }

/* ============================================================================
 * Fallback Functions (iptables)
 * ============================================================================
 */

int install_iptables_fallback(const char *interface) {
  if (!interface)
    return -1;

  char cmd[512];
  int result = 0;

  // Drop incoming SYN-ACK packets
  snprintf(cmd, sizeof(cmd),
           "iptables -I INPUT -i %s -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP "
           "2>/dev/null",
           interface);
  if (system(cmd) != 0) {
    fprintf(stderr, "Failed to install SYN-ACK drop rule\n");
    result = -1;
  }

  // Drop incoming RST packets
  snprintf(
      cmd, sizeof(cmd),
      "iptables -I INPUT -i %s -p tcp --tcp-flags RST RST -j DROP 2>/dev/null",
      interface);
  if (system(cmd) != 0) {
    fprintf(stderr, "Failed to install RST drop rule\n");
    result = -1;
  }

  if (result == 0) {
    printf("Installed iptables fallback rules for interface %s\n", interface);
  }

  return result;
}

int remove_iptables_fallback(const char *interface) {
  if (!interface)
    return -1;

  char cmd[512];
  int result = 0;

  // Remove SYN-ACK drop rule
  snprintf(cmd, sizeof(cmd),
           "iptables -D INPUT -i %s -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP "
           "2>/dev/null",
           interface);
  system(cmd); // Ignore errors - rule might not exist

  // Remove RST drop rule
  snprintf(
      cmd, sizeof(cmd),
      "iptables -D INPUT -i %s -p tcp --tcp-flags RST RST -j DROP 2>/dev/null",
      interface);
  system(cmd); // Ignore errors - rule might not exist

  printf("Removed iptables fallback rules for interface %s\n", interface);
  return 0;
}

int iptables_available(void) {
  return (system("which iptables >/dev/null 2>&1") == 0);
}

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

int compile_ebpf_program(const char *source_path, const char *output_path) {
  if (!source_path || !output_path)
    return -1;

  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "clang -O2 -target bpf -c %s -o %s 2>/dev/null",
           source_path, output_path);

  return (system(cmd) == 0) ? 0 : -1;
}

const char *xdp_mode_string(xdp_flags_t flags) {
  if (flags & XDP_FLAGS_HW_MODE)
    return "hardware";
  if (flags & XDP_FLAGS_DRV_MODE)
    return "native";
  if (flags & XDP_FLAGS_SKB_MODE)
    return "generic";
  return "auto";
}

void xdp_free_context(xdp_context_t *ctx) {
  if (!ctx)
    return;

  if (ctx->interface) {
    free((void *)ctx->interface);
  }

  free(ctx);
}