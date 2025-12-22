/**
 * Test XDP Statistics Collection
 * Demonstrates XDP program loading and statistics retrieval
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

void print_stats(const xdp_stats_t *stats) {
  printf("\n=== XDP Statistics ===\n");
  printf("Packets dropped:    %lu\n", stats->packets_dropped);
  printf("Packets passed:     %lu\n", stats->packets_passed);
  printf("Bytes dropped:      %lu\n", stats->bytes_dropped);
  printf("Bytes passed:       %lu\n", stats->bytes_passed);
  printf("SYN-ACK dropped:    %lu\n", stats->syn_ack_dropped);
  printf("RST dropped:        %lu\n", stats->rst_dropped);
  printf("======================\n");
}

int main(int argc, char *argv[]) {
  const char *interface = "lo"; // Default to loopback
  const char *xdp_program = "xdp_backscatter_filter.o";

  if (argc > 1) {
    interface = argv[1];
  }

  if (argc > 2) {
    xdp_program = argv[2];
  }

  printf("Testing XDP statistics collection on interface: %s\n", interface);
  printf("XDP program: %s\n", xdp_program);

  // Check if XDP is supported
  if (!xdp_is_supported(interface)) {
    printf("XDP not supported on interface %s\n", interface);
    printf("This could be due to:\n");
    printf("- Kernel version < 4.8\n");
    printf("- Interface doesn't exist\n");
    printf("- Missing libbpf support\n");
    printf("- Insufficient privileges (try sudo)\n");
    return 1;
  }

  printf("XDP is supported on interface %s\n", interface);

  // Load XDP program
  xdp_context_t *ctx =
      xdp_load_program(interface, xdp_program, XDP_FLAGS_SKB_MODE);
  if (!ctx) {
    printf("Failed to load XDP program\n");
    printf("Make sure to compile the XDP program first:\n");
    printf("  make %s\n", xdp_program);
    return 1;
  }

  printf("XDP program loaded successfully\n");

  // Set up signal handler for graceful shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // Reset statistics
  if (xdp_reset_stats(ctx) == 0) {
    printf("Statistics reset\n");
  }

  printf("Monitoring statistics (Press Ctrl+C to stop)...\n");

  // Monitor statistics
  xdp_stats_t stats;
  int iteration = 0;

  while (running) {
    sleep(2);

    if (xdp_get_stats(ctx, &stats) == 0) {
      if (iteration % 10 == 0) { // Print header every 20 seconds
        printf("\n%10s %10s %10s %10s %10s %10s\n", "Dropped", "Passed",
               "B-Drop", "B-Pass", "SYN-ACK", "RST");
        printf(
            "--------------------------------------------------------------\n");
      }

      printf("%10lu %10lu %10lu %10lu %10lu %10lu\n", stats.packets_dropped,
             stats.packets_passed, stats.bytes_dropped, stats.bytes_passed,
             stats.syn_ack_dropped, stats.rst_dropped);
    } else {
      printf("Failed to read statistics\n");
    }

    iteration++;
  }

  // Final statistics
  if (xdp_get_stats(ctx, &stats) == 0) {
    print_stats(&stats);
  }

  // Unload XDP program
  if (xdp_unload_program(ctx) == 0) {
    printf("XDP program unloaded successfully\n");
  } else {
    printf("Failed to unload XDP program\n");
  }

  xdp_free_context(ctx);

  return 0;
}