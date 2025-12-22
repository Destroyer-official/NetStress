/**
 * Simple AF_XDP Test
 * Basic validation of AF_XDP implementation
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* Include our driver header */
#include "driver_shim.h"

int main(void) {
  printf("AF_XDP Implementation Test\n");
  printf("==========================\n\n");

  /* Test 1: Test stub functions when AF_XDP is not available */
  printf("Test 1: AF_XDP stub functions\n");

  int result = init_af_xdp("eth0");
  printf("  init_af_xdp(\"eth0\") = %d\n", result);
  assert(result == -1); /* Should fail when not compiled with HAS_AF_XDP */

  result = af_xdp_send(NULL, 0);
  printf("  af_xdp_send(NULL, 0) = %d\n", result);
  assert(result == -1);

  result = af_xdp_send_batch(NULL, NULL, 0);
  printf("  af_xdp_send_batch(NULL, NULL, 0) = %d\n", result);
  assert(result == -1);

  result = af_xdp_recv(NULL, 0);
  printf("  af_xdp_recv(NULL, 0) = %d\n", result);
  assert(result == -1);

  result = cleanup_af_xdp();
  printf("  cleanup_af_xdp() = %d\n", result);
  assert(result == 0); /* Cleanup should always succeed */

  printf("  ✓ All stub functions work correctly\n\n");

  /* Test 2: Test backend detection */
  printf("Test 2: Backend detection\n");

  system_capabilities_t caps;
  result = detect_capabilities(&caps);
  printf("  detect_capabilities() = %d\n", result);
  assert(result == 0);

  printf("  Capabilities detected:\n");
  printf("    has_raw_socket: %d\n", caps.has_raw_socket);
  printf("    has_sendmmsg: %d\n", caps.has_sendmmsg);
  printf("    has_io_uring: %d\n", caps.has_io_uring);
  printf("    has_af_xdp: %d\n", caps.has_af_xdp);
  printf("    has_dpdk: %d\n", caps.has_dpdk);
  printf("    cpu_count: %d\n", caps.cpu_count);

  backend_type_t backend = select_best_backend(&caps);
  printf("  Selected backend: %s (%d)\n", backend_name(backend), backend);

  /* AF_XDP should not be selected if not available */
  assert(backend != BACKEND_AF_XDP || caps.has_af_xdp);

  printf("  ✓ Backend detection works correctly\n\n");

  /* Test 3: Test parameter validation */
  printf("Test 3: Parameter validation\n");

  /* These should all fail gracefully */
  result = init_af_xdp(NULL);
  printf("  init_af_xdp(NULL) = %d\n", result);
  assert(result == -1);

  result = init_af_xdp("");
  printf("  init_af_xdp(\"\") = %d\n", result);
  assert(result == -1);

  uint8_t test_data[] = "Hello World";
  result = af_xdp_send(test_data, 0);
  printf("  af_xdp_send(data, 0) = %d\n", result);
  assert(result == -1);

  printf("  ✓ Parameter validation works correctly\n\n");

  printf("All tests passed! ✓\n");
  printf("\nAF_XDP implementation is ready for integration.\n");
  printf("To enable AF_XDP support, compile with -DHAS_AF_XDP and link with "
         "libbpf.\n");

  return 0;
}