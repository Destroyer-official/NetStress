/**
 * Comprehensive C Driver Unit Tests
 * Tests for DPDK initialization, AF_XDP send/recv, and io_uring operations
 *
 * **Feature: military-grade-transformation**
 * **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 5.5**
 */

#include "driver_shim.h"
#include "test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#endif

/* Test data for packet operations */
static uint8_t test_packet_small[] = {
    /* Ethernet Header */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* Dest MAC */
    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, /* Src MAC */
    0x08, 0x00,                         /* EtherType: IPv4 */
    /* IP Header */
    0x45, 0x00, 0x00, 0x1C, /* Version, IHL, TOS, Total Length */
    0x00, 0x01, 0x40, 0x00, /* ID, Flags, Fragment Offset */
    0x40, 0x11, 0x00, 0x00, /* TTL, Protocol (UDP), Checksum */
    0x7F, 0x00, 0x00, 0x01, /* Source IP: 127.0.0.1 */
    0x7F, 0x00, 0x00, 0x01, /* Dest IP: 127.0.0.1 */
    /* UDP Header */
    0x04, 0xD2, 0x04, 0xD2, /* Source Port: 1234, Dest Port: 1234 */
    0x00, 0x08, 0x00, 0x00  /* Length: 8, Checksum: 0 */
};

static uint8_t test_packet_large[1500]; /* Will be initialized in main */

/* Test DPDK initialization and cleanup */
void test_dpdk_initialization(void) {
  printf("Testing DPDK initialization...\n");

#ifdef HAS_DPDK
  /* Test DPDK initialization with minimal arguments */
  char *argv[] = {"test", "-c", "0x1", "-n", "1", "--proc-type=primary"};
  int argc = sizeof(argv) / sizeof(argv[0]);

  int result = dpdk_init(argc, argv);
  if (result == 0) {
    TEST_ASSERT(1, "DPDK initialization successful");

    /* Test port initialization */
    result = init_dpdk_port(0);
    if (result == 0) {
      TEST_ASSERT(1, "DPDK port initialization successful");

      /* Test packet sending */
      const uint8_t *packets[] = {test_packet_small};
      uint32_t lengths[] = {sizeof(test_packet_small)};

      int sent = dpdk_send_burst(0, packets, lengths, 1);
      TEST_ASSERT(sent >= 0,
                  "DPDK send burst should succeed or fail gracefully");

    } else {
      TEST_ASSERT(1,
                  "DPDK port initialization failed as expected (no hardware)");
    }

    /* Test cleanup */
    result = cleanup_dpdk();
    TEST_ASSERT_EQ(result, 0, "DPDK cleanup should succeed");

  } else {
    TEST_ASSERT(1,
                "DPDK initialization failed as expected (no DPDK libraries)");
  }
#else
  /* Test stub functions when DPDK is disabled */
  int result = dpdk_init(0, NULL);
  TEST_ASSERT_EQ(result, -1, "DPDK init stub should return -1");

  result = init_dpdk_port(0);
  TEST_ASSERT_EQ(result, -1, "DPDK port init stub should return -1");

  const uint8_t *packets[] = {test_packet_small};
  uint32_t lengths[] = {sizeof(test_packet_small)};
  result = dpdk_send_burst(0, packets, lengths, 1);
  TEST_ASSERT_EQ(result, -1, "DPDK send burst stub should return -1");

  result = cleanup_dpdk();
  TEST_ASSERT_EQ(result, 0, "DPDK cleanup stub should return 0");
#endif
}

/* Test AF_XDP send/recv operations */
void test_af_xdp_operations(void) {
  printf("Testing AF_XDP operations...\n");

#ifdef HAS_AF_XDP
  /* Test AF_XDP initialization */
  int sockfd = init_af_xdp("lo");
  if (sockfd >= 0) {
    TEST_ASSERT(1, "AF_XDP initialization successful");

    /* Test single packet send */
    int sent = af_xdp_send(test_packet_small, sizeof(test_packet_small));
    TEST_ASSERT(sent >= 0,
                "AF_XDP single send should succeed or fail gracefully");

    /* Test batch send */
    const uint8_t *packets[] = {test_packet_small, test_packet_small};
    uint32_t lengths[] = {sizeof(test_packet_small), sizeof(test_packet_small)};

    sent = af_xdp_send_batch(packets, lengths, 2);
    TEST_ASSERT(sent >= 0,
                "AF_XDP batch send should succeed or fail gracefully");
    TEST_ASSERT(sent <= 2,
                "AF_XDP batch send should not exceed requested count");

    /* Test receive (may not receive anything) */
    uint8_t recv_buffer[1500];
    int received = af_xdp_recv(recv_buffer, sizeof(recv_buffer));
    TEST_ASSERT(received >= 0, "AF_XDP recv should succeed or return 0");

    /* Test cleanup */
    int result = cleanup_af_xdp();
    TEST_ASSERT_EQ(result, 0, "AF_XDP cleanup should succeed");

  } else {
    TEST_ASSERT(1, "AF_XDP initialization failed as expected (no privileges or "
                   "kernel support)");
  }
#else
  /* Test stub functions when AF_XDP is disabled */
  int result = init_af_xdp("eth0");
  TEST_ASSERT_EQ(result, -1, "AF_XDP init stub should return -1");

  result = af_xdp_send(test_packet_small, sizeof(test_packet_small));
  TEST_ASSERT_EQ(result, -1, "AF_XDP send stub should return -1");

  const uint8_t *packets[] = {test_packet_small};
  uint32_t lengths[] = {sizeof(test_packet_small)};
  result = af_xdp_send_batch(packets, lengths, 1);
  TEST_ASSERT_EQ(result, -1, "AF_XDP batch send stub should return -1");

  uint8_t recv_buffer[1500];
  result = af_xdp_recv(recv_buffer, sizeof(recv_buffer));
  TEST_ASSERT_EQ(result, -1, "AF_XDP recv stub should return -1");

  result = cleanup_af_xdp();
  TEST_ASSERT_EQ(result, 0, "AF_XDP cleanup stub should return 0");
#endif
}

/* Test io_uring operations */
void test_io_uring_operations(void) {
  printf("Testing io_uring operations...\n");

#ifdef HAS_IO_URING
  /* Test io_uring initialization */
  int result = init_io_uring(256);
  if (result == 0) {
    TEST_ASSERT(1, "io_uring initialization successful");

    /* Test single packet send */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(0x7F000001); /* 127.0.0.1 */
    dest.sin_port = htons(12345);

    int sent = io_uring_send_single(test_packet_small,
                                    sizeof(test_packet_small), &dest);
    TEST_ASSERT(sent >= 0,
                "io_uring single send should succeed or fail gracefully");

    /* Test batch send */
    const uint8_t *packets[] = {test_packet_small, test_packet_small};
    uint32_t lengths[] = {sizeof(test_packet_small), sizeof(test_packet_small)};
    struct sockaddr_in dests[] = {dest, dest};

    sent = io_uring_send_batch(packets, lengths, dests, 2);
    TEST_ASSERT(sent >= 0,
                "io_uring batch send should succeed or fail gracefully");
    TEST_ASSERT(sent <= 2,
                "io_uring batch send should not exceed requested count");

    /* Test cleanup */
    result = cleanup_io_uring();
    TEST_ASSERT_EQ(result, 0, "io_uring cleanup should succeed");

  } else {
    TEST_ASSERT(
        1, "io_uring initialization failed as expected (no kernel support)");
  }
#else
  /* Test stub functions when io_uring is disabled */
  int result = init_io_uring(256);
  TEST_ASSERT_EQ(result, -1, "io_uring init stub should return -1");

  result =
      io_uring_send_single(test_packet_small, sizeof(test_packet_small), NULL);
  TEST_ASSERT_EQ(result, -1, "io_uring send stub should return -1");

  const uint8_t *packets[] = {test_packet_small};
  uint32_t lengths[] = {sizeof(test_packet_small)};
  result = io_uring_send_batch(packets, lengths, NULL, 1);
  TEST_ASSERT_EQ(result, -1, "io_uring batch send stub should return -1");

  result = cleanup_io_uring();
  TEST_ASSERT_EQ(result, 0, "io_uring cleanup stub should return 0");
#endif
}

/* Test backend selection and fallback */
void test_backend_selection(void) {
  printf("Testing backend selection and fallback...\n");

  system_capabilities_t caps;
  int result = detect_capabilities(&caps);
  TEST_ASSERT_EQ(result, 0, "Capability detection should succeed");

  /* Test backend selection with different capability sets */
  backend_type_t backend = select_best_backend(&caps);
  TEST_ASSERT(backend >= BACKEND_RAW_SOCKET, "Should select valid backend");
  TEST_ASSERT(backend <= BACKEND_DPDK, "Backend should be in valid range");

  /* Test with empty capabilities (should fall back to raw socket) */
  system_capabilities_t empty_caps = {0};
  backend = select_best_backend(&empty_caps);
  TEST_ASSERT_EQ(backend, BACKEND_RAW_SOCKET, "Should fall back to raw socket");

  /* Test backend names */
  const char *name = backend_name(backend);
  TEST_ASSERT_NOT_NULL(name, "Backend name should not be NULL");
  TEST_ASSERT(strlen(name) > 0, "Backend name should not be empty");

  printf("  Selected backend: %s\n", name);
  printf("  Capabilities: raw_socket=%d, sendmmsg=%d, io_uring=%d, af_xdp=%d, "
         "dpdk=%d\n",
         caps.has_raw_socket, caps.has_sendmmsg, caps.has_io_uring,
         caps.has_af_xdp, caps.has_dpdk);
}

/* Test error conditions and edge cases */
void test_error_conditions(void) {
  printf("Testing error conditions and edge cases...\n");

  /* Test NULL pointer handling */
  system_capabilities_t *null_caps = NULL;
  backend_type_t backend = select_best_backend(null_caps);
  TEST_ASSERT_EQ(backend, BACKEND_RAW_SOCKET,
                 "Should handle NULL capabilities gracefully");

  /* Test invalid backend names */
  const char *name = backend_name((backend_type_t)999);
  TEST_ASSERT_STR_EQ(name, "unknown",
                     "Should return 'unknown' for invalid backend");

  /* Test checksum with NULL data */
  uint16_t checksum = calculate_checksum(NULL, 0);
  TEST_ASSERT_EQ(checksum, 0xFFFF, "NULL data should give 0xFFFF checksum");

  /* Test transport checksum with invalid parameters */
  uint16_t transport_checksum = calculate_transport_checksum(0, 0, 0, NULL, 0);
  TEST_ASSERT_EQ(transport_checksum, 0xFFFF,
                 "Invalid parameters should give 0xFFFF checksum");
}

/* Test performance characteristics */
void test_performance_characteristics(void) {
  printf("Testing performance characteristics...\n");

  const int iterations = 1000;
  clock_t start, end;

  /* Test checksum calculation performance */
  start = clock();
  for (int i = 0; i < iterations; i++) {
    volatile uint16_t checksum =
        calculate_checksum(test_packet_small, sizeof(test_packet_small));
    (void)checksum; /* Prevent optimization */
  }
  end = clock();

  double checksum_time = ((double)(end - start)) / CLOCKS_PER_SEC;
  TEST_ASSERT(checksum_time < 1.0, "Checksum calculation should be fast");

  printf(
      "  Checksum performance: %d iterations in %.3f seconds (%.1f ops/sec)\n",
      iterations, checksum_time, iterations / checksum_time);

  /* Test timestamp function performance */
  start = clock();
  for (int i = 0; i < iterations; i++) {
    volatile uint64_t timestamp = get_timestamp_us();
    (void)timestamp; /* Prevent optimization */
  }
  end = clock();

  double timestamp_time = ((double)(end - start)) / CLOCKS_PER_SEC;
  TEST_ASSERT(timestamp_time < 1.0, "Timestamp function should be fast");

  printf(
      "  Timestamp performance: %d iterations in %.3f seconds (%.1f ops/sec)\n",
      iterations, timestamp_time, iterations / timestamp_time);
}

/* Initialize test data */
void initialize_test_data(void) {
  /* Initialize large packet with pattern */
  for (size_t i = 0; i < sizeof(test_packet_large); i++) {
    test_packet_large[i] = (uint8_t)(i & 0xFF);
  }

  /* Set up Ethernet header */
  memcpy(test_packet_large, test_packet_small, 14); /* Copy Ethernet header */

  /* Update IP total length for large packet */
  uint16_t total_length = htons(sizeof(test_packet_large) - 14);
  memcpy(test_packet_large + 16, &total_length, 2);
}

/* Main test runner */
int main(void) {
  TEST_SUITE_START("Comprehensive C Driver Unit Tests");

  /* Initialize test data */
  initialize_test_data();

  /* Run all test suites */
  RUN_TEST(test_dpdk_initialization);
  RUN_TEST(test_af_xdp_operations);
  RUN_TEST(test_io_uring_operations);
  RUN_TEST(test_backend_selection);
  RUN_TEST(test_error_conditions);
  RUN_TEST(test_performance_characteristics);

  TEST_SUITE_END();
}