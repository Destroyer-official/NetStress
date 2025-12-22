<h1 align="center">❓ Frequently Asked Questions</h1>

<p align="center">
  <b>Everything you need to know about NetStress</b>
</p>

---

## 📋 Table of Contents

- [General Questions](#-general-questions)
- [Installation](#-installation)
- [Usage](#-usage)
- [Performance](#-performance)
- [Protocols](#-protocols)
- [Troubleshooting](#-troubleshooting)
- [Security & Legal](#-security--legal)
- [Development](#-development)

---

## 🌐 General Questions

<details>
<summary><b>What is NetStress?</b></summary>

NetStress is a high-performance network stress testing framework designed for:

- **Security Professionals** - Testing network infrastructure resilience
- **System Administrators** - Validating server capacity
- **Researchers** - Studying network behavior under load
- **Penetration Testers** - Assessing DDoS resilience

It generates network traffic using various protocols to test how systems respond under high load conditions.

</details>

<details>
<summary><b>What makes NetStress different from other tools?</b></summary>

| Feature            | NetStress | hping3     | LOIC    | Slowloris |
| ------------------ | --------- | ---------- | ------- | --------- |
| Cross-platform     | ✅        | Linux only | ✅      | ✅        |
| Multiple protocols | ✅        | ✅         | Limited | HTTP only |
| AI optimization    | ✅        | ❌         | ❌      | ❌        |
| Native engine      | ✅        | N/A        | ❌      | ❌        |
| Active development | ✅        | Limited    | ❌      | Limited   |
| Performance        | 1M+ PPS   | 100K PPS   | 50K PPS | N/A       |

</details>

<details>
<summary><b>What platforms are supported?</b></summary>

| Platform    | Version              | Status          |
| ----------- | -------------------- | --------------- |
| **Windows** | 10, 11, Server 2016+ | ✅ Full support |
| **Linux**   | Kernel 4.4+          | ✅ Full support |
| **macOS**   | 10.14 (Mojave)+      | ✅ Full support |

</details>

<details>
<summary><b>Is NetStress free?</b></summary>

Yes! NetStress is open-source software released under the MIT License. You can use, modify, and distribute it freely.

</details>

---

## 📦 Installation

<details>
<summary><b>What Python version do I need?</b></summary>

**Minimum:** Python 3.8  
**Recommended:** Python 3.10 or higher

Check your version:

```bash
python --version
```

</details>

<details>
<summary><b>How do I install NetStress?</b></summary>

```bash
# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip install -r requirements.txt

# Verify installation
python ddos.py --status
```

See [INSTALLATION.md](INSTALLATION.md) for detailed instructions.

</details>

<details>
<summary><b>Do I need Rust or C compilers?</b></summary>

**No!** The basic installation works with Python only.

For higher performance, you can install the pre-built native engine:

```bash
python scripts/install_native.py
```

No compilation required - it downloads a pre-built binary.

</details>

<details>
<summary><b>Why is scapy failing on Windows?</b></summary>

Scapy requires Npcap on Windows:

1. Download from [npcap.com](https://npcap.com/)
2. Install with "WinPcap API-compatible Mode" checked
3. Restart your terminal
4. Install scapy: `pip install scapy`

</details>

<details>
<summary><b>How do I update NetStress?</b></summary>

```bash
cd NetStress
git pull
pip install -r requirements.txt --upgrade
```

</details>

---

## 💻 Usage

<details>
<summary><b>What's the basic command syntax?</b></summary>

```bash
python ddos.py -i <TARGET> -p <PORT> -t <PROTOCOL> -d <DURATION>
```

**Example:**

```bash
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60
```

</details>

<details>
<summary><b>What do the arguments mean?</b></summary>

| Argument     | Short | Description         | Example            |
| ------------ | ----- | ------------------- | ------------------ |
| `--ip`       | `-i`  | Target IP/hostname  | `-i 192.168.1.100` |
| `--port`     | `-p`  | Target port         | `-p 80`            |
| `--type`     | `-t`  | Protocol type       | `-t UDP`           |
| `--duration` | `-d`  | Duration (seconds)  | `-d 60`            |
| `--threads`  | `-x`  | Worker threads      | `-x 8`             |
| `--size`     | `-s`  | Packet size (bytes) | `-s 1472`          |
| `--verbose`  | `-v`  | Detailed output     | `-v`               |

</details>

<details>
<summary><b>Why do some protocols require root/admin?</b></summary>

Protocols like TCP-SYN, ICMP, and amplification attacks use **raw sockets**, which require elevated privileges for security reasons.

**Linux/macOS:**

```bash
sudo python3 ddos.py -i TARGET -p 80 -t TCP-SYN
```

**Windows:**
Run PowerShell as Administrator.

</details>

<details>
<summary><b>How many threads should I use?</b></summary>

| CPU Cores | Recommended Threads |
| --------- | ------------------- |
| 2 cores   | 2-4 threads         |
| 4 cores   | 4-8 threads         |
| 8 cores   | 8-16 threads        |
| 16+ cores | 16-32 threads       |

For Slowloris attacks, use 100-1000 threads.

</details>

<details>
<summary><b>What packet size should I use?</b></summary>

| Goal              | Packet Size | Command             |
| ----------------- | ----------- | ------------------- |
| Maximum PPS       | 64 bytes    | `-s 64`             |
| Balanced          | 512 bytes   | `-s 512`            |
| Maximum bandwidth | 1472 bytes  | `-s 1472` (default) |

**Note:** 1472 bytes is optimal for MTU 1500 (avoids fragmentation).

</details>

---

## ⚡ Performance

<details>
<summary><b>What performance can I expect?</b></summary>

### Python Only

| Platform | Protocol | Expected PPS |
| -------- | -------- | ------------ |
| Linux    | UDP      | 100K-300K    |
| Linux    | TCP      | 10K-50K      |
| Windows  | UDP      | 50K-150K     |
| macOS    | UDP      | 80K-200K     |

### With Native Engine

| Platform | Protocol | Expected PPS |
| -------- | -------- | ------------ |
| Linux    | UDP      | 1M-5M        |
| Linux    | TCP      | 100K-500K    |
| Windows  | UDP      | 500K-2M      |
| macOS    | UDP      | 500K-2M      |

</details>

<details>
<summary><b>How do I improve performance?</b></summary>

1. **Install native engine:**

   ```bash
   python scripts/install_native.py
   ```

2. **Use more threads:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -x 8
   ```

3. **Use smaller packets:**

   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -s 64
   ```

4. **Close other applications**

5. **Use wired network** instead of WiFi

</details>

<details>
<summary><b>Why is my PPS lower than expected?</b></summary>

Common causes:

| Issue                 | Solution              |
| --------------------- | --------------------- |
| Network bottleneck    | Check NIC speed       |
| CPU bottleneck        | Use fewer threads     |
| Target rate limiting  | Normal behavior       |
| Firewall interference | Check local firewall  |
| Other processes       | Close background apps |

Check with: `python ddos.py --status`

</details>

<details>
<summary><b>What is the native engine?</b></summary>

The native engine is a high-performance Rust implementation that:

- Bypasses Python's GIL (Global Interpreter Lock)
- Uses optimized system calls (sendmmsg, io_uring)
- Provides 10-100x performance improvement

Install it with:

```bash
python scripts/install_native.py
```

</details>

---

## 🔌 Protocols

<details>
<summary><b>Which protocol should I use?</b></summary>

| Goal                  | Protocol | Command          |
| --------------------- | -------- | ---------------- |
| Bandwidth test        | UDP      | `-t UDP`         |
| Connection test       | TCP      | `-t TCP`         |
| Web server test       | HTTP     | `-t HTTP`        |
| HTTPS server test     | HTTPS    | `-t HTTPS`       |
| DNS server test       | DNS      | `-t DNS`         |
| Connection exhaustion | SLOW     | `-t SLOW -x 500` |
| Firewall test         | TCP-SYN  | `-t TCP-SYN`     |

</details>

<details>
<summary><b>What's the difference between UDP and TCP?</b></summary>

| Feature     | UDP               | TCP                 |
| ----------- | ----------------- | ------------------- |
| Connection  | Connectionless    | Connection-oriented |
| Speed       | Faster            | Slower              |
| Handshake   | None              | 3-way handshake     |
| Reliability | No guarantee      | Guaranteed delivery |
| Use case    | Bandwidth testing | Connection testing  |

</details>

<details>
<summary><b>What is Slowloris?</b></summary>

Slowloris is an attack that:

1. Opens many HTTP connections
2. Sends partial HTTP headers slowly
3. Keeps connections open indefinitely
4. Exhausts the server's connection pool

```bash
python ddos.py -i TARGET -p 80 -t SLOW -x 500 -d 300
```

Effective against servers with limited connection pools.

</details>

<details>
<summary><b>What are amplification attacks?</b></summary>

Amplification attacks use protocols that respond with more data than requested:

| Protocol     | Amplification Factor |
| ------------ | -------------------- |
| NTP          | ~556x                |
| Memcached    | ~50,000x             |
| DNS          | ~28-54x              |
| WS-Discovery | ~10-500x             |

**⚠️ Warning:** These require vulnerable third-party servers and should only be used in controlled environments.

</details>

---

## 🔧 Troubleshooting

<details>
<summary><b>"Permission denied" error</b></summary>

You need root/admin privileges for raw socket protocols:

**Linux/macOS:**

```bash
sudo python3 ddos.py -i TARGET -p 80 -t TCP-SYN
```

**Windows:**
Run PowerShell as Administrator.

</details>

<details>
<summary><b>"Module not found" error</b></summary>

Install dependencies:

```bash
pip install -r requirements.txt --force-reinstall
```

</details>

<details>
<summary><b>"Connection refused" error</b></summary>

The target is not accepting connections. Verify:

- Target is running
- Port is correct
- Firewall allows connection

Test with:

```bash
nc -zv TARGET PORT
```

</details>

<details>
<summary><b>"Network unreachable" error</b></summary>

Check network connectivity:

```bash
ping TARGET
```

If ping fails, check your network configuration.

</details>

<details>
<summary><b>Low performance</b></summary>

1. Check system status:

   ```bash
   python ddos.py --status
   ```

2. Install native engine:

   ```bash
   python scripts/install_native.py
   ```

3. Use more threads:
   ```bash
   python ddos.py -i TARGET -p 80 -t UDP -x 8
   ```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for more solutions.

</details>

---

## 🔒 Security & Legal

<details>
<summary><b>Is NetStress legal to use?</b></summary>

**Yes**, when used on:

- ✅ Systems you own
- ✅ Systems with explicit written permission

**No**, when used on:

- ❌ Systems without authorization
- ❌ Public infrastructure
- ❌ Any system you don't have permission to test

Unauthorized use is illegal in most jurisdictions.

</details>

<details>
<summary><b>Can the target trace me?</b></summary>

**Yes.** Your IP address is visible in packet headers unless you use:

- VPN
- Proxy
- SYN-SPOOF (spoofs source IP, but responses go elsewhere)

</details>

<details>
<summary><b>Is my traffic encrypted?</b></summary>

Only HTTPS protocol uses encryption. Other protocols send data in plaintext.

</details>

<details>
<summary><b>Does NetStress have safety features?</b></summary>

Yes:

- **Target validation** - Validates targets before testing
- **Rate limiting** - Prevents excessive resource usage
- **Audit logging** - Logs all operations
- **Emergency stop** - Ctrl+C stops immediately
- **Blocked targets** - Prevents testing critical infrastructure

</details>

---

## 👨‍💻 Development

<details>
<summary><b>How do I contribute?</b></summary>

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Run tests: `pytest tests/`
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

</details>

<details>
<summary><b>How do I run tests?</b></summary>

```bash
# All tests
pytest tests/

# Specific test file
pytest tests/test_attacks.py

# With coverage
pytest tests/ --cov=core
```

</details>

<details>
<summary><b>How do I build the native engine from source?</b></summary>

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cd native/rust_engine
pip install maturin
maturin develop --release
```

</details>

<details>
<summary><b>Where can I report bugs?</b></summary>

Open an issue on GitHub:
[github.com/Destroyer-official/NetStress/issues](https://github.com/Destroyer-official/NetStress/issues)

Include:

- OS and Python version
- Command you ran
- Full error message
- Steps to reproduce

</details>

---

## 🆘 Still Need Help?

<table>
<tr>
<td width="33%" align="center">

### 📖 Documentation

[Full Docs](DOCUMENTATION_INDEX.md)

</td>
<td width="33%" align="center">

### 🔧 Troubleshooting

[Troubleshooting Guide](TROUBLESHOOTING.md)

</td>
<td width="33%" align="center">

### 💬 Community

[GitHub Issues](https://github.com/Destroyer-official/NetStress/issues)

</td>
</tr>
</table>

---

<p align="center">
  <b>Can't find your answer? <a href="https://github.com/Destroyer-official/NetStress/issues/new">Open an issue</a>!</b>
</p>
