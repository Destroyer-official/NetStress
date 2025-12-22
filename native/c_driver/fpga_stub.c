/**
 * FPGA Stub Implementation
 *
 * Honest capability reporting for FPGA hardware.
 * This stub reports "FPGA: Not Available" when no real FPGA hardware is
 * present.
 *
 * Requirements: 4.1, 4.2, 4.3
 * - No fake FPGA simulation code
 * - Honest reporting of FPGA availability
 * - No fake "Initializing FPGA" messages
 */

#include "driver_shim.h"
#include <stdio.h>
#include <string.h>

/**
 * Check if FPGA hardware is available
 * @return 0 (not available) - honest reporting
 */
int fpga_is_available(void) { return 0; /* FPGA: Not Available */ }

/**
 * Get FPGA availability status as human-readable string
 * @return Status string
 */
const char *fpga_get_status(void) { return "FPGA: Not Available"; }

/**
 * Detect FPGA devices - returns 0 as no real FPGA hardware is present
 * @param devices Output array (unused)
 * @param max_devices Maximum devices to detect (unused)
 * @return 0 - no devices found
 */
int fpga_detect_devices(fpga_device_t *devices, int max_devices) {
  (void)devices;
  (void)max_devices;
  /* Honest reporting: No FPGA devices available */
  return 0;
}

/**
 * Initialize FPGA device - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_init_device(int device_id) {
  (void)device_id;
  /* No fake "Initializing FPGA" messages - honest failure */
  return -1;
}

/**
 * Load bitstream to FPGA - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @param bitstream_path Path to bitstream (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_load_bitstream(int device_id, const char *bitstream_path) {
  (void)device_id;
  (void)bitstream_path;
  return -1;
}

/**
 * Initialize DMA channels - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @param num_channels Number of channels (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_init_dma(int device_id, int num_channels) {
  (void)device_id;
  (void)num_channels;
  return -1;
}

/**
 * Send packet template to FPGA - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @param template_data Template data (unused)
 * @param template_size Template size (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_send_template(int device_id, const uint8_t *template_data,
                       uint32_t template_size) {
  (void)device_id;
  (void)template_data;
  (void)template_size;
  return -1;
}

/**
 * Configure packet generation - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @param config Configuration (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_configure_generation(int device_id, const fpga_config_t *config) {
  (void)device_id;
  (void)config;
  return -1;
}

/**
 * Start packet generation - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_start_generation(int device_id) {
  (void)device_id;
  return -1;
}

/**
 * Stop packet generation - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_stop_generation(int device_id) {
  (void)device_id;
  return -1;
}

/**
 * Enable checksum offload - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @param enable_ip Enable IP checksum (unused)
 * @param enable_tcp Enable TCP checksum (unused)
 * @param enable_udp Enable UDP checksum (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_enable_checksum_offload(int device_id, int enable_ip, int enable_tcp,
                                 int enable_udp) {
  (void)device_id;
  (void)enable_ip;
  (void)enable_tcp;
  (void)enable_udp;
  return -1;
}

/**
 * Get FPGA statistics - fails as no real FPGA hardware is present
 * @param device_id Device index (unused)
 * @param stats Output statistics (unused)
 * @return -1 (failure) - no FPGA hardware available
 */
int fpga_get_stats(int device_id, fpga_stats_t *stats) {
  (void)device_id;
  (void)stats;
  return -1;
}

/**
 * Cleanup FPGA resources - succeeds (nothing to clean up)
 * @param device_id Device index (unused)
 * @return 0 (success) - nothing to clean up
 */
int fpga_cleanup(int device_id) {
  (void)device_id;
  return 0;
}

/**
 * Print FPGA capability report
 * Provides honest reporting of FPGA availability
 */
void fpga_print_capability_report(void) {
  printf("=== FPGA Capability Report ===\n");
  printf("Status: %s\n", fpga_get_status());
  printf("Devices detected: 0\n");
  printf("Hardware acceleration: Not available\n");
  printf("\nNote: FPGA acceleration requires actual PCIe FPGA hardware\n");
  printf("      (Xilinx/Intel) with appropriate drivers installed.\n");
  printf("==============================\n");
}
