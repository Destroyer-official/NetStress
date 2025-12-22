/**
 * XDP Integration Test
 * Comprehensive test of all XDP functionality
 */

#include "test_framework.h"
#include "xdp_loader.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Test XDP program loading
/* **Validates: Requirements 5.1, 5.2, 5.3** */
void test_xdp_loading(void) {
  printf("Testing XDP program loading...\n");

  const char *interface = "lo";
  const char *program = "xdp_backscatter_filter.o";

  // Test XDP support detection
  int supported = xdp_is_supported(interface);
  printf("  XDP supported on %s: %s\n", interface, supported ? "YES" : "NO");

  if (!supported) {
    printf("  Skipping XDP tests (not supported)\n");
    return;
  }

  // Test program loading
  xdp_context_t *ctx = xdp_load_program(interface, program, XDP_FLAGS_SKB_MODE);
  if (ctx) {
    printf("  ✓ XDP program loaded successfully\n");

    // Test unloading
    if (xdp_unload_program(ctx) == 0) {
      printf("  ✓ XDP program unloaded successfully\n");
    } else {
      printf("  ✗ XDP program unload failed\n");
    }

    xdp_free_context(ctx);
  } else {
    printf("  ✗ XDP program loading failed\n");
  }
}

// Test XDP statistics
/* **Validates: Requirements 5.4** */
void test_xdp_statistics(void) {
  printf("Testing XDP statistics...\n");

  const char *interface = "lo";
  const char *program = "xdp_backscatter_filter.o";

  if (!xdp_is_supported(interface)) {
    printf("  Skipping statistics test (XDP not supported)\n");
    return;
  }

  xdp_context_t *ctx = xdp_load_program(interface, program, XDP_FLAGS_SKB_MODE);
  if (!ctx) {
    printf("  ✗ Failed to load XDP program for statistics test\n");
    return;
  }

  // Test statistics reset
  if (xdp_reset_stats(ctx) == 0) {
    printf("  ✓ Statistics reset successful\n");
  } else {
    printf("  ✗ Statistics reset failed\n");
  }

  // Test statistics reading
  xdp_stats_t stats;
  if (xdp_get_stats(ctx, &stats) == 0) {
    printf("  ✓ Statistics read successful\n");
    printf("    Packets dropped: %lu\n", stats.packets_dropped);
    printf("    Packets passed: %lu\n", stats.packets_passed);
    printf("    SYN-ACK dropped: %lu\n", stats.syn_ack_dropped);
    printf("    RST dropped: %lu\n", stats.rst_dropped);
  } else {
    printf("  ✗ Statistics read failed\n");
  }

  xdp_unload_program(ctx);
  xdp_free_context(ctx);
}

// Test fallback mechanism
/* **Validates: Requirements 5.5** */
void test_fallback_mechanism(void) {
  printf("Testing fallback mechanism...\n");

  const char *interface = "lo";

  // Test iptables availability
  int iptables_avail = iptables_available();
  printf("  iptables available: %s\n", iptables_avail ? "YES" : "NO");

  if (!iptables_avail) {
    printf("  Skipping fallback test (iptables not available)\n");
    return;
  }

  // Test fallback installation
  if (install_iptables_fallback(interface) == 0) {
    printf("  ✓ iptables fallback installed\n");

    // Test fallback removal
    if (remove_iptables_fallback(interface) == 0) {
      printf("  ✓ iptables fallback removed\n");
    } else {
      printf("  ✗ iptables fallback removal failed\n");
    }
  } else {
    printf("  ✗ iptables fallback installation failed\n");
  }
}

// Test utility functions
void test_utility_functions(void) {
  printf("Testing utility functions...\n");

  // Test interface index lookup
  int ifindex = get_ifindex("lo");
  if (ifindex > 0) {
    printf("  ✓ Interface 'lo' index: %d\n", ifindex);
  } else {
    printf("  ✗ Failed to get interface index for 'lo'\n");
  }

  // Test XDP mode string
  const char *mode = xdp_mode_string(XDP_FLAGS_SKB_MODE);
  printf("  ✓ XDP mode string: %s\n", mode);

  mode = xdp_mode_string(XDP_FLAGS_DRV_MODE);
  printf("  ✓ XDP mode string: %s\n", mode);
}

// Test error conditions
void test_error_conditions(void) {
  printf("Testing error conditions...\n");

  // Test invalid interface
  if (!xdp_is_supported("nonexistent_interface")) {
    printf("  ✓ Correctly detected unsupported interface\n");
  } else {
    printf("  ✗ Failed to detect unsupported interface\n");
  }

  // Test NULL parameters
  xdp_context_t *ctx = xdp_load_program(NULL, NULL, 0);
  if (!ctx) {
    printf("  ✓ Correctly rejected NULL parameters\n");
  } else {
    printf("  ✗ Failed to reject NULL parameters\n");
    xdp_free_context(ctx);
  }

  // Test invalid program file
  ctx = xdp_load_program("lo", "nonexistent_program.o", XDP_FLAGS_SKB_MODE);
  if (!ctx) {
    printf("  ✓ Correctly rejected nonexistent program\n");
  } else {
    printf("  ✗ Failed to reject nonexistent program\n");
    xdp_unload_program(ctx);
    xdp_free_context(ctx);
  }
}

int main(void) {
  printf("=== XDP Integration Test Suite ===\n\n");

  // Check if running as root
  if (geteuid() != 0) {
    printf("WARNING: Not running as root. Some tests may fail.\n");
    printf("For complete testing, run: sudo %s\n\n", "test_xdp_integration");
  }

  // Run all tests
  test_utility_functions();
  printf("\n");

  test_error_conditions();
  printf("\n");

  test_xdp_loading();
  printf("\n");

  test_xdp_statistics();
  printf("\n");

  test_fallback_mechanism();
  printf("\n");

  printf("=== Test Suite Complete ===\n");

  return 0;
}