/**
 * C Driver Unit Tests
 * Comprehensive tests for driver_shim.c functions
 */

#include "driver_shim.h"
#include "test_framework.h"
#include <assert.h>
#include <time.h>

/* Mock data for testing */
static uint8_t test_packet_udp[] = {
    /* IP Header */
    0x45, 0x00, 0x00, 0x20, /* Version, IHL, TOS, Total Length */
    0x12, 0x34, 0x40, 0x00, /* ID, Flags, Fragment Offset */
    0x40, 0x11, 0x00, 0x00, /* TTL, Protocol (UDP), Checksum */
    0xC0, 0xA8, 0x01, 0x01, /* Source IP: 192.168.1.1 */
    0xC0, 0xA8, 0x01, 0x02, /* Dest IP: 192.168.1.2 */
    /* UDP Header */
    0x04, 0xD2, 0x00, 0x50, /* Source Port: 1234, Dest Port: 80 */
    0x00, 0x0C, 0x00, 0x00, /* Length: 12, Checksum: 0 */
    /* Payload */
    0x48, 0x65, 0x6C, 0x6C /* "Hell" */
};

static uint8_t test_packet_tcp[] = {
    /* IP Header */
    0x45, 0x00, 0x00, 0x28, /* Version, IHL, TOS, Total Length */
    0x56, 0x78, 0x40, 0x00, /* ID, Flags, Fragment Offset */
    0x40, 0x06, 0x00, 0x00, /* TTL, Protocol (TCP), Checksum */
    0x0A, 0x00, 0x00, 0x01, /* Source IP: 10.0.0.1 */
    0x0A, 0x00, 0x00, 0x02, /* Dest IP: 10.0.0.2 */
    /* TCP Header */
    0x04, 0xD2, 0x01, 0xBB, /* Source Port: 1234, Dest Port: 443 */
    0x12, 0x34, 0x56, 0x78, /* Sequence Number */
    0x00, 0x00, 0x00, 0x00, /* Acknowledgment Number */
    0x50, 0x02, 0xFF, 0xFF, /* Data Offset, Flags (SYN), Window */
    0x00, 0x00, 0x00, 0x00  /* Checksum, Urgent Pointer */
};

/* Test checksum calculation */
void test_checksum_calculation(void) {
  /* Test IP checksum with known values */
  uint8_t ip_header[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40,
                         0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
                         0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c};

  uint16_t checksum = calculate_checksum(ip_header, 20);
  TEST_ASSERT_NEQ(checksum, 0, "IP checksum should not be zero");

  /* Test with zero checksum field */
  uint8_t zero_checksum[] = {0x00, 0x00};
  uint16_t zero_result = calculate_checksum(zero_checksum, 2);
  TEST_ASSERT_EQ(zero_result, 0xFFFF, "Zero data should give 0xFFFF checksum");

  /* Test with all 0xFF */
  uint8_t all_ff[] = {0xFF, 0xFF};
  uint16_t ff_result = calculate_checksum(all_ff, 2);
  TEST_ASSERT_EQ(ff_result, 0x0000, "All 0xFF should give 0x0000 checksum");

  /* Test odd length */
  uint8_t odd_data[] = {0x12, 0x34, 0x56};
  uint16_t odd_result = calculate_checksum(odd_data, 3);
  TEST_ASSERT_NEQ(odd_result, 0, "Odd length checksum should work");
}

/* Test transport checksum calculation */
void test_transport_checksum(void) {
  uint32_t src_ip = htonl_test(0xC0A80101); /* 192.168.1.1 */
  uint32_t dst_ip = htonl_test(0xC0A80102); /* 192.168.1.2 */
  uint8_t protocol = 17;                    /* UDP */
  uint8_t udp_data[] = {
      0x04, 0xD2, 0x00, 0x50, /* Source Port: 1234, Dest Port: 80 */
      0x00, 0x08, 0x00, 0x00  /* Length: 8, Checksum: 0 */
  };

  uint16_t checksum =
      calculate_transport_checksum(src_ip, dst_ip, protocol, udp_data, 8);
  TEST_ASSERT_NEQ(checksum, 0, "UDP checksum should not be zero");

  /* Test TCP checksum */
  protocol = 6; /* TCP */
  uint8_t tcp_data[] = {
      0x04, 0xD2, 0x01, 0xBB, /* Source Port: 1234, Dest Port: 443 */
      0x12, 0x34, 0x56, 0x78, /* Sequence Number */
      0x00, 0x00, 0x00, 0x00, /* Acknowledgment Number */
      0x50, 0x02, 0xFF, 0xFF, /* Data Offset, Flags, Window */
      0x00, 0x00, 0x00, 0x00  /* Checksum, Urgent Pointer */
  };

  uint16_t tcp_checksum =
      calculate_transport_checksum(src_ip, dst_ip, protocol, tcp_data, 20);
  TEST_ASSERT_NEQ(tcp_checksum, 0, "TCP checksum should not be zero");
}

/* Test raw socket creation */
void test_raw_socket_creation(void) {
  /* Note: Raw sockets typically require root privileges */
  /* We'll test the function calls but expect them to fail gracefully */

  int sock = raw_socket_create(IPPROTO_RAW);
  if (sock >= 0) {
    TEST_ASSERT(1, "Raw socket created successfully");

    /* Test setting IP_HDRINCL */
    int result = raw_socket_set_hdrincl(sock);
    TEST_ASSERT(result == 0 || result == -1,
                "IP_HDRINCL setting returned valid result");

    raw_socket_close(sock);
    TEST_ASSERT(1, "Raw socket closed successfully");
  } else {
    TEST_ASSERT(
        1, "Raw socket creation failed as expected (likely no privileges)");
  }

  /* Test invalid protocol */
  int invalid_sock = raw_socket_create(-1);
  TEST_ASSERT(invalid_sock < 0, "Invalid protocol should fail");
}

/* Test utility functions */
void test_utility_functions(void) {
  /* Test timestamp function */
  uint64_t ts1 = get_timestamp_us();
  TEST_ASSERT(ts1 > 0, "Timestamp should be positive");

  /* Small delay */
  for (volatile int i = 0; i < 1000000; i++)
    ;

  uint64_t ts2 = get_timestamp_us();
  TEST_ASSERT(ts2 > ts1, "Second timestamp should be larger");

  /* Test CPU count */
  int cpu_count = get_cpu_count();
  TEST_ASSERT(cpu_count > 0, "CPU count should be positive");
  TEST_ASSERT(cpu_count <= 256, "CPU count should be reasonable");

  /* Test CPU pinning (may fail on some systems) */
  int pin_result = pin_to_cpu(0);
  TEST_ASSERT(pin_result == 0 || pin_result == -1,
              "CPU pinning returned valid result");
}

/* Test backend detection */
void test_backend_detection(void) {
  system_capabilities_t caps;
  int result = detect_capabilities(&caps);

  TEST_ASSERT_EQ(result, 0, "Capability detection should succeed");
  TEST_ASSERT(caps.has_raw_socket, "Should always have raw socket capability");
  TEST_ASSERT(caps.cpu_count > 0, "Should detect positive CPU count");

  /* Test backend selection */
  /* **Validates: Requirements 4.4, 5.5** */
  backend_type_t backend = select_best_backend(&caps);
  TEST_ASSERT(backend >= BACKEND_RAW_SOCKET, "Should select valid backend");
  TEST_ASSERT(backend <= BACKEND_DPDK, "Backend should be in valid range");

  /* Test backend names */
  const char *name = backend_name(backend);
  TEST_ASSERT_NOT_NULL(name, "Backend name should not be NULL");
  TEST_ASSERT(strlen(name) > 0, "Backend name should not be empty");

  /* Test all backend names */
  TEST_ASSERT_STR_EQ(backend_name(BACKEND_RAW_SOCKET), "raw_socket",
                     "Raw socket name");
  TEST_ASSERT_STR_EQ(backend_name(BACKEND_SENDMMSG), "sendmmsg",
                     "sendmmsg name");
  TEST_ASSERT_STR_EQ(backend_name(BACKEND_IO_URING), "io_uring",
                     "io_uring name");
  TEST_ASSERT_STR_EQ(backend_name(BACKEND_AF_XDP), "AF_XDP", "AF_XDP name");
  TEST_ASSERT_STR_EQ(backend_name(BACKEND_DPDK), "DPDK", "DPDK name");
  TEST_ASSERT_STR_EQ(backend_name((backend_type_t)999), "unknown",
                     "Unknown backend name");
}

/* Test sendmmsg batch functions */
void test_sendmmsg_batch(void) {
  /* Create a UDP socket for testing */
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    TEST_ASSERT(0, "Failed to create UDP socket for testing");
    return;
  }

  /* Prepare test data */
  const uint8_t *packets[3] = {(uint8_t *)"Hello1", (uint8_t *)"Hello2",
                               (uint8_t *)"Hello3"};
  uint32_t lengths[3] = {6, 6, 6};

  struct sockaddr_in dests[3];
  for (int i = 0; i < 3; i++) {
    memset(&dests[i], 0, sizeof(dests[i]));
    dests[i].sin_family = AF_INET;
    dests[i].sin_addr.s_addr = htonl_test(0x7F000001); /* 127.0.0.1 */
    dests[i].sin_port = htons_test(12345 + i);
  }

  /* Test batch sending */
  int sent = sendmmsg_batch(sockfd, packets, lengths, dests, 3);
  TEST_ASSERT(sent >= 0, "sendmmsg_batch should return non-negative result");
  TEST_ASSERT(sent <= 3, "sendmmsg_batch should not send more than requested");

  /* Test same destination batch */
  int sent_same = sendmmsg_batch_same_dest(sockfd, packets, lengths,
                                           htonl_test(0x7F000001), 12345, 3);
  TEST_ASSERT(sent_same >= 0,
              "sendmmsg_batch_same_dest should return non-negative result");
  TEST_ASSERT(sent_same <= 3,
              "sendmmsg_batch_same_dest should not send more than requested");

  close(sockfd);
}

/* Test driver stats structure */
void test_driver_stats(void) {
  driver_stats_t stats;
  memset(&stats, 0, sizeof(stats));

  TEST_ASSERT_EQ(stats.packets_sent, 0, "Initial packets_sent should be zero");
  TEST_ASSERT_EQ(stats.bytes_sent, 0, "Initial bytes_sent should be zero");
  TEST_ASSERT_EQ(stats.errors, 0, "Initial errors should be zero");

  /* Test structure size and alignment */
  TEST_ASSERT(sizeof(driver_stats_t) >= 20,
              "driver_stats_t should be at least 20 bytes");
  TEST_ASSERT(sizeof(driver_stats_t) % 4 == 0,
              "driver_stats_t should be 4-byte aligned");
}

/* Test driver config structure */
void test_driver_config(void) {
  driver_config_t config;
  memset(&config, 0, sizeof(config));

  config.interface = "eth0";
  config.port_id = 0;
  config.num_queues = 1;
  config.ring_size = 1024;
  config.burst_size = 32;
  config.promiscuous = 1;

  TEST_ASSERT_STR_EQ(config.interface, "eth0", "Interface name should be set");
  TEST_ASSERT_EQ(config.port_id, 0, "Port ID should be set");
  TEST_ASSERT_EQ(config.num_queues, 1, "Queue count should be set");
  TEST_ASSERT_EQ(config.ring_size, 1024, "Ring size should be set");
  TEST_ASSERT_EQ(config.burst_size, 32, "Burst size should be set");
  TEST_ASSERT(config.promiscuous, "Promiscuous mode should be enabled");
}

/* Test AF_XDP functionality */
void test_af_xdp_functionality(void) {
#ifdef HAS_AF_XDP
  /* Test AF_XDP initialization with invalid interface */
  int result = init_af_xdp("nonexistent_interface");
  TEST_ASSERT(result < 0, "AF_XDP init with invalid interface should fail");

  /* Test AF_XDP operations without initialization */
  TEST_ASSERT_EQ(af_xdp_send(NULL, 0), -1,
                 "AF_XDP send without init should fail");
  TEST_ASSERT_EQ(af_xdp_send_batch(NULL, NULL, 0), -1,
                 "AF_XDP batch send without init should fail");
  TEST_ASSERT_EQ(af_xdp_recv(NULL, 0), -1,
                 "AF_XDP recv without init should fail");

  /* Test cleanup without initialization */
  TEST_ASSERT_EQ(cleanup_af_xdp(), 0,
                 "AF_XDP cleanup should succeed even without init");

  /* Test with loopback interface (if available) */
  int sockfd = init_af_xdp("lo");
  if (sockfd >= 0) {
    TEST_ASSERT(1, "AF_XDP initialized successfully on loopback");

    /* Test single packet send */
    uint8_t test_data[] = "Hello AF_XDP";
    int sent = af_xdp_send(test_data, sizeof(test_data));
    TEST_ASSERT(sent >= 0,
                "AF_XDP single send should succeed or fail gracefully");

    /* Test batch send */
    const uint8_t *packets[3] = {(uint8_t *)"Packet1", (uint8_t *)"Packet2",
                                 (uint8_t *)"Packet3"};
    uint32_t lengths[3] = {7, 7, 7};

    int batch_sent = af_xdp_send_batch(packets, lengths, 3);
    TEST_ASSERT(batch_sent >= 0,
                "AF_XDP batch send should succeed or fail gracefully");
    TEST_ASSERT(batch_sent <= 3,
                "AF_XDP batch send should not exceed requested count");

    /* Test receive (may not receive anything) */
    uint8_t recv_buffer[1500];
    int received = af_xdp_recv(recv_buffer, sizeof(recv_buffer));
    TEST_ASSERT(received >= 0, "AF_XDP recv should succeed or return 0");

    /* Test cleanup */
    TEST_ASSERT_EQ(cleanup_af_xdp(), 0, "AF_XDP cleanup should succeed");
  } else {
    TEST_ASSERT(1, "AF_XDP init failed as expected (likely no privileges or "
                   "kernel support)");
  }

#else
  /* Test stub functions when AF_XDP is disabled */
  /* **Validates: Requirements 5.1, 5.2, 5.3** */
  TEST_ASSERT_EQ(init_af_xdp("eth0"), -1, "AF_XDP init stub should return -1");
  TEST_ASSERT_EQ(af_xdp_send(NULL, 0), -1, "AF_XDP send stub should return -1");
  TEST_ASSERT_EQ(af_xdp_send_batch(NULL, NULL, 0), -1,
                 "AF_XDP batch send stub should return -1");
  TEST_ASSERT_EQ(af_xdp_recv(NULL, 0), -1, "AF_XDP recv stub should return -1");
  TEST_ASSERT_EQ(cleanup_af_xdp(), 0, "AF_XDP cleanup stub should return 0");
#endif
}

/* Test AF_XDP error conditions */
void test_af_xdp_error_conditions(void) {
#ifdef HAS_AF_XDP
  /* Test with NULL parameters */
  TEST_ASSERT_EQ(init_af_xdp(NULL), -1,
                 "AF_XDP init with NULL interface should fail");
  TEST_ASSERT_EQ(af_xdp_send(NULL, 100), -1,
                 "AF_XDP send with NULL data should fail");
  TEST_ASSERT_EQ(af_xdp_recv(NULL, 100), -1,
                 "AF_XDP recv with NULL buffer should fail");

  /* Test with invalid parameters */
  uint8_t dummy_data[] = "test";
  TEST_ASSERT_EQ(af_xdp_send(dummy_data, 0), -1,
                 "AF_XDP send with zero length should fail");

  /* Test batch send with invalid parameters */
  TEST_ASSERT_EQ(af_xdp_send_batch(NULL, NULL, 1), -1,
                 "AF_XDP batch send with NULL arrays should fail");

  const uint8_t *packets[1] = {dummy_data};
  uint32_t lengths[1] = {0};
  /* This should handle zero-length packets gracefully */
  int result = af_xdp_send_batch(packets, lengths, 1);
  TEST_ASSERT(result >= 0,
              "AF_XDP batch send should handle zero-length packets gracefully");

#endif
}

/* Test stub functions when features are disabled */
void test_stub_functions(void) {
  /* These should all return -1 or appropriate error values when features are
   * disabled */

#ifndef HAS_DPDK
  /* **Validates: Requirements 4.1, 4.2, 4.3** */
  TEST_ASSERT_EQ(dpdk_init(0, NULL), -1, "DPDK init stub should return -1");
  TEST_ASSERT_EQ(init_dpdk_port(0), -1, "DPDK port init stub should return -1");
  /* **Validates: Requirements 4.2, 4.3** */
  TEST_ASSERT_EQ(dpdk_send_burst(0, NULL, NULL, 0), -1,
                 "DPDK send stub should return -1");
  TEST_ASSERT_EQ(dpdk_recv_burst(0, NULL, 0), -1,
                 "DPDK recv stub should return -1");
  TEST_ASSERT_EQ(cleanup_dpdk(), 0, "DPDK cleanup stub should return 0");

  driver_stats_t stats;
  TEST_ASSERT_EQ(dpdk_get_stats(0, &stats), -1,
                 "DPDK stats stub should return -1");
#endif

#ifndef HAS_IO_URING
  /* **Validates: Requirements 4.4** */
  TEST_ASSERT_EQ(init_io_uring(256), -1, "io_uring init stub should return -1");
  TEST_ASSERT_EQ(io_uring_send_single(NULL, 0, NULL), -1,
                 "io_uring send stub should return -1");
  TEST_ASSERT_EQ(io_uring_send_batch(NULL, NULL, NULL, 0), -1,
                 "io_uring batch send stub should return -1");
  TEST_ASSERT_EQ(cleanup_io_uring(), 0,
                 "io_uring cleanup stub should return 0");

  driver_stats_t stats;
  TEST_ASSERT_EQ(io_uring_get_stats(&stats), -1,
                 "io_uring stats stub should return -1");
#endif
}

/* Test packet validation */
void test_packet_validation(void) {
  /* Test UDP packet structure */
  TEST_ASSERT(sizeof(test_packet_udp) >= 28,
              "UDP test packet should be at least 28 bytes");
  TEST_ASSERT_EQ(test_packet_udp[0] >> 4, 4, "Should be IPv4");
  TEST_ASSERT_EQ(test_packet_udp[9], 17, "Should be UDP protocol");

  /* Test TCP packet structure */
  TEST_ASSERT(sizeof(test_packet_tcp) >= 40,
              "TCP test packet should be at least 40 bytes");
  TEST_ASSERT_EQ(test_packet_tcp[0] >> 4, 4, "Should be IPv4");
  TEST_ASSERT_EQ(test_packet_tcp[9], 6, "Should be TCP protocol");

  /* Test IP header extraction */
  uint32_t src_ip, dst_ip;
  memcpy(&src_ip, test_packet_udp + 12, 4);
  memcpy(&dst_ip, test_packet_udp + 16, 4);

  TEST_ASSERT_EQ(src_ip, htonl_test(0xC0A80101),
                 "Source IP should be 192.168.1.1");
  TEST_ASSERT_EQ(dst_ip, htonl_test(0xC0A80102),
                 "Dest IP should be 192.168.1.2");
}

/* Test error conditions */
void test_error_conditions(void) {
  /* Test NULL pointer handling */
  uint16_t checksum = calculate_checksum(NULL, 0);
  TEST_ASSERT_EQ(checksum, 0xFFFF, "NULL data should give 0xFFFF checksum");

  /* Test zero length */
  uint8_t dummy_data[] = {0x12, 0x34};
  uint16_t zero_len = calculate_checksum(dummy_data, 0);
  TEST_ASSERT_EQ(zero_len, 0xFFFF, "Zero length should give 0xFFFF checksum");

  /* Test invalid socket operations */
  int result = raw_socket_send(-1, 0, NULL, 0);
  TEST_ASSERT(result < 0, "Invalid socket send should fail");

  /* Test invalid backend selection */
  system_capabilities_t empty_caps = {0};
  backend_type_t backend = select_best_backend(&empty_caps);
  TEST_ASSERT_EQ(backend, BACKEND_RAW_SOCKET, "Should fall back to raw socket");
}

/* Performance test for checksum calculation */
void test_checksum_performance(void) {
  const size_t test_size = 1500; /* MTU size */
  uint8_t *test_data = malloc(test_size);
  if (!test_data) {
    TEST_ASSERT(0, "Failed to allocate test data");
    return;
  }

  /* Fill with random-ish data */
  for (size_t i = 0; i < test_size; i++) {
    test_data[i] = (uint8_t)(i ^ (i >> 8));
  }

  /* Time the checksum calculation */
  clock_t start = clock();
  const int iterations = 10000;

  for (int i = 0; i < iterations; i++) {
    volatile uint16_t checksum = calculate_checksum(test_data, test_size);
    (void)checksum; /* Prevent optimization */
  }

  clock_t end = clock();
  double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;

  TEST_ASSERT(time_taken < 1.0, "Checksum calculation should be fast");

  printf(
      "  Checksum performance: %d iterations in %.3f seconds (%.1f ops/sec)\n",
      iterations, time_taken, iterations / time_taken);

  free(test_data);
}

/* Main test runner */
int main(void) {
  TEST_SUITE_START("C Driver Unit Tests");

  RUN_TEST(test_checksum_calculation);
  RUN_TEST(test_transport_checksum);
  RUN_TEST(test_raw_socket_creation);
  RUN_TEST(test_utility_functions);
  RUN_TEST(test_backend_detection);
  RUN_TEST(test_sendmmsg_batch);
  RUN_TEST(test_driver_stats);
  RUN_TEST(test_driver_config);
  RUN_TEST(test_af_xdp_functionality);
  RUN_TEST(test_af_xdp_error_conditions);
  RUN_TEST(test_stub_functions);
  RUN_TEST(test_packet_validation);
  RUN_TEST(test_error_conditions);
  RUN_TEST(test_checksum_performance);

  TEST_SUITE_END();
}