/*
 * sendmmsg Benchmark Executable
 * Measures sendmmsg batch sending performance
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


#ifdef __linux__
#define _GNU_SOURCE
#include <sys/socket.h>
#endif

typedef struct {
  char target[256];
  int port;
  int duration;
  int packet_size;
  uint64_t packets_sent;
  uint64_t bytes_sent;
  int errors;
  double start_time;
  double end_time;
} benchmark_config_t;

static volatile int running = 1;

void signal_handler(int sig) { running = 0; }

double get_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec / 1000000.0;
}

#ifdef __linux__
int sendmmsg_benchmark(benchmark_config_t *config) {
  int sockfd;
  struct sockaddr_in addr;
  char *packet_data;
  const int batch_size = 32;
  struct mmsghdr msgs[batch_size];
  struct iovec iovecs[batch_size];

  printf("sendmmsg benchmark starting...\n");

  // Create socket
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Error: Cannot create socket: %s\n", strerror(errno));
    return -1;
  }

  // Setup target address
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(config->port);
  inet_pton(AF_INET, config->target, &addr.sin_addr);

  // Allocate packet data
  packet_data = malloc(config->packet_size);
  if (!packet_data) {
    fprintf(stderr, "Error: Cannot allocate packet data\n");
    close(sockfd);
    return -1;
  }
  memset(packet_data, 0xAB, config->packet_size);

  // Setup mmsghdr structures
  for (int i = 0; i < batch_size; i++) {
    iovecs[i].iov_base = packet_data;
    iovecs[i].iov_len = config->packet_size;

    msgs[i].msg_hdr.msg_name = &addr;
    msgs[i].msg_hdr.msg_namelen = sizeof(addr);
    msgs[i].msg_hdr.msg_iov = &iovecs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_control = NULL;
    msgs[i].msg_hdr.msg_controllen = 0;
    msgs[i].msg_hdr.msg_flags = 0;
  }

  printf("sendmmsg initialized, starting benchmark...\n");

  config->start_time = get_time();
  double end_time = config->start_time + config->duration;

  while (running && get_time() < end_time) {
    int sent = sendmmsg(sockfd, msgs, batch_size, 0);
    if (sent > 0) {
      config->packets_sent += sent;
      config->bytes_sent += sent * config->packet_size;
    } else {
      config->errors++;
      // Small delay on error
      usleep(1000);
    }

    // Small yield every 1000 batches
    if ((config->packets_sent / batch_size) % 1000 == 0) {
      usleep(1);
    }
  }

  config->end_time = get_time();

  // Cleanup
  free(packet_data);
  close(sockfd);

  return 0;
}
#endif

int fallback_benchmark(benchmark_config_t *config) {
  // Fallback implementation when sendmmsg is not available
  printf("sendmmsg not available, using regular sendto...\n");

  int sockfd;
  struct sockaddr_in addr;
  char *packet_data;

  // Create socket
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Error: Cannot create socket: %s\n", strerror(errno));
    return -1;
  }

  // Setup target address
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(config->port);
  inet_pton(AF_INET, config->target, &addr.sin_addr);

  // Allocate packet data
  packet_data = malloc(config->packet_size);
  if (!packet_data) {
    fprintf(stderr, "Error: Cannot allocate packet data\n");
    close(sockfd);
    return -1;
  }
  memset(packet_data, 0xAB, config->packet_size);

  config->start_time = get_time();
  double end_time = config->start_time + config->duration;

  // Use regular sendto in a loop
  while (running && get_time() < end_time) {
    ssize_t sent = sendto(sockfd, packet_data, config->packet_size, 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    if (sent > 0) {
      config->packets_sent++;
      config->bytes_sent += sent;
    } else {
      config->errors++;
    }

    // Small delay every 1000 packets
    if (config->packets_sent % 1000 == 0) {
      usleep(1);
    }
  }

  config->end_time = get_time();

  // Cleanup
  free(packet_data);
  close(sockfd);

  return 0;
}

void print_results(benchmark_config_t *config) {
  double duration = config->end_time - config->start_time;
  double pps = config->packets_sent / duration;
  double bps = config->bytes_sent / duration;

  // Output JSON for Python script
  printf("{\n");
  printf("  \"duration\": %.3f,\n", duration);
  printf("  \"packets_sent\": %lu,\n", config->packets_sent);
  printf("  \"bytes_sent\": %lu,\n", config->bytes_sent);
  printf("  \"pps\": %.0f,\n", pps);
  printf("  \"bps\": %.0f,\n", bps);
  printf("  \"errors\": %d\n", config->errors);
  printf("}\n");
}

int main(int argc, char *argv[]) {
  benchmark_config_t config = {0};

  // Default values
  strcpy(config.target, "127.0.0.1");
  config.port = 12345;
  config.duration = 10;
  config.packet_size = 1472;

  // Parse command line arguments
  int opt;
  while ((opt = getopt(argc, argv, "t:p:d:s:h")) != -1) {
    switch (opt) {
    case 't':
      strncpy(config.target, optarg, sizeof(config.target) - 1);
      break;
    case 'p':
      config.port = atoi(optarg);
      break;
    case 'd':
      config.duration = atoi(optarg);
      break;
    case 's':
      config.packet_size = atoi(optarg);
      break;
    case 'h':
      printf("Usage: %s [-t target] [-p port] [-d duration] [-s packet_size]\n",
             argv[0]);
      return 0;
    default:
      fprintf(stderr, "Unknown option: %c\n", opt);
      return 1;
    }
  }

  // Handle signals
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  int ret;

#ifdef __linux__
  ret = sendmmsg_benchmark(&config);
#else
  ret = fallback_benchmark(&config);
#endif

  if (ret == 0) {
    print_results(&config);
  } else {
    fprintf(stderr, "Benchmark failed\n");
    return 1;
  }

  return 0;
}