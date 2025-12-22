/**
 * Test XDP Fallback Mechanism
 * Demonstrates XDP loading with graceful fallback to iptables
 */

#include "xdp_loader.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int running = 1;

void signal_handler(int sig) {
  (void)sig;
  running = 0;
  printf("\nShutting down...\n");
}

int test_xdp_fallback(const char *interface) {
  printf("=== Testing XDP Fallback Mechanism ===\n");
  printf("Interface: %s\n", interface);

  // Step 1: Check XDP support
  printf("\n1. Checking XDP support...\n");
  int xdp_supported = xdp_is_supported(interface);
  printf("XDP supported: %s\n", xdp_supported ? "YES" : "NO");

  // Step 2: Check iptables availability
  printf("\n2. Checking iptables availability...\n");
  int iptables_avail = iptables_available();
  printf("iptables available: %s\n", iptables_avail ? "YES" : "NO");

  if (!xdp_supported && !iptables_avail) {
    printf("ERROR: Neither XDP nor iptables is available!\n");
    return 1;
  }

  xdp_context_t *ctx = NULL;
  int using_iptables = 0;

  // Step 3: Try to load XDP program
  if (xdp_supported) {
    printf("\n3. Attempting to load XDP program...\n");
    ctx = xdp_load_program(interface, "xdp_backscatter_filter.o",
                           XDP_FLAGS_SKB_MODE);

    if (ctx) {
      printf("SUCCESS: XDP program loaded\n");
    } else {
      printf("FAILED: XDP program loading failed\n");
      xdp_supported = 0; // Mark as unsupported for fallback
    }
  }

  // Step 4: Fallback to iptables if XDP failed
  if (!xdp_supported && iptables_avail) {
    printf("\n4. Falling back to iptables...\n");
    if (install_iptables_fallback(interface) == 0) {
      printf("SUCCESS: iptables fallback rules installed\n");
      using_iptables = 1;
    } else {
      printf("FAILED: iptables fallback installation failed\n");
      return 1;
    }
  }

  // Step 5: Monitor for a short time
  printf("\n5. Monitoring (5 seconds)...\n");
  if (ctx) {
    // Monitor XDP statistics
    xdp_stats_t stats;
    for (int i = 0; i < 5; i++) {
      sleep(1);
      if (xdp_get_stats(ctx, &stats) == 0) {
        printf("XDP Stats - Dropped: %lu, Passed: %lu\n", stats.packets_dropped,
               stats.packets_passed);
      }
    }
  } else if (using_iptables) {
    // Just wait for iptables (no easy way to get stats)
    printf("iptables rules active (no real-time stats available)\n");
    sleep(5);
  }

  // Step 6: Cleanup
  printf("\n6. Cleaning up...\n");
  if (ctx) {
    if (xdp_unload_program(ctx) == 0) {
      printf("SUCCESS: XDP program unloaded\n");
    } else {
      printf("WARNING: XDP program unload failed\n");
    }
    xdp_free_context(ctx);
  }

  if (using_iptables) {
    if (remove_iptables_fallback(interface) == 0) {
      printf("SUCCESS: iptables fallback rules removed\n");
    } else {
      printf("WARNING: iptables fallback removal failed\n");
    }
  }

  printf("\n=== Test Complete ===\n");
  return 0;
}

int main(int argc, char *argv[]) {
  const char *interface = "lo"; // Default to loopback

  if (argc > 1) {
    interface = argv[1];
  }

  /* **Validates: Requirements 5.2** */
  printf("XDP Fallback Test\n");
  printf("Usage: %s [interface]\n", argv[0]);
  printf(
      "Note: This test requires root privileges for both XDP and iptables\n\n");

  // Check if running as root
  if (geteuid() != 0) {
    printf("WARNING: Not running as root. XDP and iptables operations may "
           "fail.\n");
    printf("Try: sudo %s %s\n\n", argv[0], interface);
  }

  // Set up signal handler
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  return test_xdp_fallback(interface);
}