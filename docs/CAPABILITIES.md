<h1 align="center">⚡ Capabilities & Features</h1>

<p align="center">
  <b>Complete overview of NetStress features and capabilities</b>
</p>

---

## 📋 Table of Contents

- [Feature Overview](#-feature-overview)
- [Protocol Support](#-protocol-support)
- [Platform Support](#-platform-support)
- [Performance](#-performance)
- [Backend Technologies](#-backend-technologies)
- [AI/ML Features](#-aiml-features)
- [Safety Features](#-safety-features)
- [Limitations](#-limitations)

---

## ✨ Feature Overview

### Core Features

| Feature       | Status | Description                      |
| ------------- | ------ | -------------------------------- |
| UDP Flood     | ✅     | High-speed UDP packet generation |
| TCP Flood     | ✅     | TCP connection flooding          |
| HTTP Flood    | ✅     | HTTP GET/POST request flooding   |
| HTTPS Flood   | ✅     | HTTPS request flooding with TLS  |
| DNS Flood     | ✅     | DNS query flooding               |
| ICMP Flood    | ✅     | ICMP echo request flooding       |
| Slowloris     | ✅     | Slow HTTP connection exhaustion  |
| TCP SYN Flood | ✅     | Raw SYN packet flooding          |
| TCP ACK Flood | ✅     | Raw ACK packet flooding          |
| Amplification | ✅     | NTP, Memcached, WS-Discovery     |

### Advanced Features

| Feature         | Status | Description                  |
| --------------- | ------ | ---------------------------- |
| AI Optimization | ✅     | Adaptive attack optimization |
| Multi-threading | ✅     | Parallel packet generation   |
| Cross-platform  | ✅     | Windows, Linux, macOS        |
| Native Engine   | ✅     | High-performance Rust engine |
| Real-time Stats | ✅     | Live performance metrics     |
| Audit Logging   | ✅     | Complete operation logging   |

---

## 🔌 Protocol Support

### Layer 4 (Transport Layer)

| Protocol      | Root Required | Performance | Use Case            |
| ------------- | ------------- | ----------- | ------------------- |
| **UDP**       | No            | ⭐⭐⭐⭐⭐  | Bandwidth testing   |
| **TCP**       | No            | ⭐⭐⭐⭐    | Connection testing  |
| **TCP-SYN**   | Yes           | ⭐⭐⭐⭐⭐  | SYN flood testing   |
| **TCP-ACK**   | Yes           | ⭐⭐⭐⭐⭐  | Firewall testing    |
| **PUSH-ACK**  | Yes           | ⭐⭐⭐⭐    | Application testing |
| **SYN-SPOOF** | Yes           | ⭐⭐⭐⭐⭐  | Reflection testing  |
| **ICMP**      | Yes           | ⭐⭐⭐⭐⭐  | Ping flood testing  |

### Layer 7 (Application Layer)

| Protocol  | Root Required | Performance | Use Case              |
| --------- | ------------- | ----------- | --------------------- |
| **HTTP**  | No            | ⭐⭐⭐      | Web server testing    |
| **HTTPS** | No            | ⭐⭐        | TLS server testing    |
| **DNS**   | No            | ⭐⭐⭐⭐    | DNS server testing    |
| **SLOW**  | No            | ⭐          | Connection exhaustion |

### Amplification

| Protocol         | Amplification Factor | Root Required |
| ---------------- | -------------------- | ------------- |
| **NTP**          | ~556x                | Yes           |
| **Memcached**    | ~50,000x             | Yes           |
| **WS-Discovery** | ~10-500x             | Yes           |

---

## 🖥️ Platform Support

### Windows

| Feature         | Windows 10 | Windows 11 | Server 2016+ |
| --------------- | ---------- | ---------- | ------------ |
| Basic protocols | ✅         | ✅         | ✅           |
| Raw sockets     | ✅ (Admin) | ✅ (Admin) | ✅ (Admin)   |
| IOCP            | ✅         | ✅         | ✅           |
| Native engine   | ✅         | ✅         | ✅           |

### Linux

| Feature         | Ubuntu    | Debian    | RHEL/CentOS | Arch      |
| --------------- | --------- | --------- | ----------- | --------- |
| Basic protocols | ✅        | ✅        | ✅          | ✅        |
| Raw sockets     | ✅ (root) | ✅ (root) | ✅ (root)   | ✅ (root) |
| sendmmsg        | ✅        | ✅        | ✅          | ✅        |
| io_uring        | ✅ (5.1+) | ✅ (5.1+) | ✅ (5.1+)   | ✅ (5.1+) |
| Native engine   | ✅        | ✅        | ✅          | ✅        |

### macOS

| Feature         | macOS 10.14+ | macOS 11+ (Intel) | macOS 11+ (ARM) |
| --------------- | ------------ | ----------------- | --------------- |
| Basic protocols | ✅           | ✅                | ✅              |
| Raw sockets     | ✅ (root)    | ✅ (root)         | ✅ (root)       |
| kqueue          | ✅           | ✅                | ✅              |
| Native engine   | ✅           | ✅                | ✅              |

---

## 📊 Performance

### Python Only (No Native Engine)

| Platform | Protocol | Threads | Expected PPS |
| -------- | -------- | ------- | ------------ |
| Linux    | UDP      | 4       | 100K-300K    |
| Linux    | TCP      | 4       | 10K-50K      |
| Linux    | HTTP     | 4       | 1K-5K        |
| Windows  | UDP      | 4       | 50K-150K     |
| Windows  | TCP      | 4       | 5K-30K       |
| macOS    | UDP      | 4       | 80K-200K     |
| macOS    | TCP      | 4       | 8K-40K       |

### With Native Engine

| Platform | Protocol | Threads | Expected PPS  |
| -------- | -------- | ------- | ------------- |
| Linux    | UDP      | 4       | **1M-5M**     |
| Linux    | TCP      | 4       | **100K-500K** |
| Linux    | HTTP     | 4       | **10K-50K**   |
| Windows  | UDP      | 4       | **500K-2M**   |
| Windows  | TCP      | 4       | **50K-200K**  |
| macOS    | UDP      | 4       | **500K-2M**   |
| macOS    | TCP      | 4       | **50K-200K**  |

### Performance Factors

| Factor            | Impact | Optimization           |
| ----------------- | ------ | ---------------------- |
| CPU cores         | High   | Use more threads       |
| Network interface | High   | Use faster NIC         |
| Packet size       | Medium | Smaller = higher PPS   |
| Protocol          | Medium | UDP > TCP > HTTP       |
| Target distance   | Medium | Local > LAN > Internet |
| System load       | Medium | Close other apps       |

---

## 🔧 Backend Technologies

### Priority Order

The system automatically selects the best available backend:

```
DPDK (100M+ PPS)
    ↓
AF_XDP (10-50M PPS)
    ↓
io_uring (5-20M PPS)
    ↓
sendmmsg (1-5M PPS)
    ↓
Raw Sockets (200K-1M PPS)
    ↓
Python Sockets (50-500K PPS)
```

### Backend Details

| Backend         | Platform    | Description        | Performance |
| --------------- | ----------- | ------------------ | ----------- |
| **DPDK**        | Linux       | Kernel bypass      | 100M+ PPS   |
| **AF_XDP**      | Linux 4.18+ | Zero-copy          | 10-50M PPS  |
| **io_uring**    | Linux 5.1+  | Async I/O          | 5-20M PPS   |
| **sendmmsg**    | Linux       | Batch syscalls     | 1-5M PPS    |
| **kqueue**      | macOS       | Event notification | 500K-2M PPS |
| **IOCP**        | Windows     | Async I/O          | 500K-2M PPS |
| **Raw Sockets** | All         | Standard raw       | 200K-1M PPS |
| **Python**      | All         | Fallback           | 50-500K PPS |

---

## 🤖 AI/ML Features

### Adaptive Optimization

| Feature                   | Description                                  |
| ------------------------- | -------------------------------------------- |
| **Rate Control**          | Adjusts packet rate based on target response |
| **Pattern Learning**      | Learns effective attack patterns             |
| **Defense Detection**     | Detects and adapts to defenses               |
| **Resource Optimization** | Balances CPU/memory usage                    |

### Real-Time Intelligence

| Feature                   | Description                              |
| ------------------------- | ---------------------------------------- |
| **Response Analysis**     | Measures actual target response times    |
| **Success Tracking**      | Tracks connection success rates          |
| **Effectiveness Scoring** | 0-100% score based on target degradation |
| **Baseline Comparison**   | Detects target degradation vs baseline   |

### Insights Generation

| Insight Type             | Description                   |
| ------------------------ | ----------------------------- |
| Performance Analysis     | Identifies bottlenecks        |
| Target Behavior          | Analyzes target responses     |
| Optimization Suggestions | Recommends parameter changes  |
| Trend Detection          | Identifies patterns over time |

---

## 🛡️ Safety Features

| Feature               | Description                              |
| --------------------- | ---------------------------------------- |
| **Target Validation** | Validates targets before testing         |
| **Rate Limiting**     | Prevents excessive resource usage        |
| **Audit Logging**     | Logs all operations                      |
| **Emergency Stop**    | Ctrl+C stops immediately                 |
| **Blocked Targets**   | Prevents testing critical infrastructure |

---

## ⚠️ Limitations

### What NetStress Cannot Do

| Limitation               | Reason                                 |
| ------------------------ | -------------------------------------- |
| Bypass DDoS protection   | Commercial services will block attacks |
| Guarantee performance    | Depends on many factors                |
| Spoof source IP          | Only SYN-SPOOF can spoof               |
| Attack without detection | Your IP is visible                     |
| Bypass firewalls         | Stateful firewalls block most attacks  |

### Known Limitations

| Limitation        | Reason                 | Workaround            |
| ----------------- | ---------------------- | --------------------- |
| Python GIL        | Limits multi-threading | Use native engine     |
| Socket limits     | OS limits open sockets | Increase ulimit       |
| MTU fragmentation | Large packets fragment | Use 1472 byte packets |
| Rate limiting     | Target may rate limit  | Use multiple sources  |

---

## 📈 Comparison

| Feature            | NetStress | hping3     | LOIC    | Slowloris |
| ------------------ | --------- | ---------- | ------- | --------- |
| Cross-platform     | ✅        | Linux only | ✅      | ✅        |
| Multiple protocols | ✅        | ✅         | Limited | HTTP only |
| AI optimization    | ✅        | ❌         | ❌      | ❌        |
| Native engine      | ✅        | N/A        | ❌      | ❌        |
| Performance        | 1M+ PPS   | 100K PPS   | 50K PPS | N/A       |
| Active development | ✅        | Limited    | ❌      | Limited   |

---

<p align="center">
  <b>Ready to get started? Check the <a href="QUICK_START.md">Quick Start Guide</a>!</b>
</p>
