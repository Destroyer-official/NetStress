<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

<h1 align="center">
  <br>
  🌐 NetStress
  <br>
</h1>

<h4 align="center">High-Performance Network Stress Testing Framework</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Destroyer-official/NetStress/main/docs/assets/demo.gif" alt="NetStress Demo" width="700">
</p>

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized security testing and research only.**
>
> - ✅ Test systems you own
> - ✅ Test with explicit written permission
> - ❌ Never attack systems without authorization
> - ❌ Unauthorized use is illegal in most jurisdictions
>
> By using this software, you agree to use it responsibly and legally.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🚀 High Performance

- **1M+ PPS** with native Rust engine
- Multi-threaded packet generation
- Zero-copy networking support
- Adaptive rate control

</td>
<td width="50%">

### 🔧 Multiple Protocols

- Layer 4: UDP, TCP, ICMP, SYN, ACK
- Layer 7: HTTP, HTTPS, DNS, Slowloris
- Amplification: NTP, Memcached, WS-Discovery
- Custom payload support

</td>
</tr>
<tr>
<td width="50%">

### 🤖 AI-Powered

- Adaptive attack optimization
- Real-time target analysis
- Defense detection & evasion
- Performance insights

</td>
<td width="50%">

### 🛡️ Safety Built-In

- Target validation
- Rate limiting
- Audit logging
- Emergency stop (Ctrl+C)

</td>
</tr>
</table>

---

## 🚀 Quick Start

### One-Line Install

```bash
git clone https://github.com/Destroyer-official/NetStress.git && cd NetStress && pip install -r requirements.txt
```

### Run Your First Test

```bash
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60
```

### Check System Status

```bash
python ddos.py --status
```

---

## 📦 Installation

### Prerequisites

| Requirement | Version                               |
| ----------- | ------------------------------------- |
| Python      | 3.8+                                  |
| RAM         | 2GB minimum                           |
| OS          | Windows 10+, Linux 4.4+, macOS 10.14+ |

### Method 1: Standard Installation

```bash
# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip install -r requirements.txt

# Verify installation
python ddos.py --status
```

### Method 2: Pre-Built Binary (No Python Required)

<details>
<summary><b>🐧 Linux</b></summary>

```bash
wget https://github.com/Destroyer-official/NetStress/releases/latest/download/netstress-linux-x86_64.tar.gz
tar -xzf netstress-linux-x86_64.tar.gz
chmod +x netstress
./netstress --help
```

</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
Invoke-WebRequest -Uri "https://github.com/Destroyer-official/NetStress/releases/latest/download/netstress-win-amd64.zip" -OutFile "netstress.zip"
Expand-Archive netstress.zip -DestinationPath .
.\netstress.exe --help
```

</details>

### Method 3: High-Performance (Native Engine)

```bash
# Install native Rust engine for 10x+ performance
python scripts/install_native.py
```

---

## 📖 Usage

### Basic Syntax

```bash
python ddos.py -i <TARGET> -p <PORT> -t <PROTOCOL> [OPTIONS]
```

### Command Reference

| Argument     | Short | Description           | Default  |
| ------------ | ----- | --------------------- | -------- |
| `--ip`       | `-i`  | Target IP/hostname    | Required |
| `--port`     | `-p`  | Target port (1-65535) | Required |
| `--type`     | `-t`  | Protocol type         | Required |
| `--duration` | `-d`  | Duration (seconds)    | 60       |
| `--threads`  | `-x`  | Worker threads        | 4        |
| `--size`     | `-s`  | Packet size (bytes)   | 1472     |
| `--verbose`  | `-v`  | Detailed output       | Off      |
| `--status`   |       | Show capabilities     | -        |

### Protocol Types

<details>
<summary><b>Layer 4 Protocols</b></summary>

| Protocol    | Description          | Root Required |
| ----------- | -------------------- | ------------- |
| `UDP`       | UDP packet flood     | No            |
| `TCP`       | TCP connection flood | No            |
| `TCP-SYN`   | SYN packet flood     | Yes           |
| `TCP-ACK`   | ACK packet flood     | Yes           |
| `PUSH-ACK`  | PSH+ACK flood        | Yes           |
| `SYN-SPOOF` | Spoofed SYN flood    | Yes           |
| `ICMP`      | ICMP echo flood      | Yes           |

</details>

<details>
<summary><b>Layer 7 Protocols</b></summary>

| Protocol | Description         | Root Required |
| -------- | ------------------- | ------------- |
| `HTTP`   | HTTP GET/POST flood | No            |
| `HTTPS`  | HTTPS request flood | No            |
| `DNS`    | DNS query flood     | No            |
| `SLOW`   | Slowloris attack    | No            |

</details>

<details>
<summary><b>Amplification Protocols</b></summary>

| Protocol       | Amplification | Root Required |
| -------------- | ------------- | ------------- |
| `NTP`          | ~556x         | Yes           |
| `MEMCACHED`    | ~50,000x      | Yes           |
| `WS-DISCOVERY` | ~10-500x      | Yes           |

</details>

### Examples

```bash
# UDP flood (60 seconds)
python ddos.py -i 192.168.1.100 -p 80 -t UDP -d 60

# TCP with 8 threads
python ddos.py -i 192.168.1.100 -p 80 -t TCP -x 8 -d 60

# HTTP flood
python ddos.py -i 192.168.1.100 -p 80 -t HTTP -d 60

# SYN flood (requires root)
sudo python ddos.py -i 192.168.1.100 -p 80 -t TCP-SYN -d 60

# Slowloris (500 connections)
python ddos.py -i 192.168.1.100 -p 80 -t SLOW -x 500 -d 300

# AI-optimized attack
python ddos.py -i 192.168.1.100 -p 80 -t UDP --ai-optimize -d 60
```

---

## 📊 Performance

### Expected Performance

| Platform | Protocol | Python Only   | With Native Engine |
| -------- | -------- | ------------- | ------------------ |
| Linux    | UDP      | 100K-300K PPS | 1M-5M PPS          |
| Linux    | TCP      | 10K-50K CPS   | 100K-500K CPS      |
| Windows  | UDP      | 50K-150K PPS  | 500K-2M PPS        |
| Windows  | TCP      | 5K-30K CPS    | 50K-200K CPS       |
| macOS    | UDP      | 80K-200K PPS  | 500K-2M PPS        |

### Backend Priority

```
DPDK (100M+ PPS) → AF_XDP (10-50M PPS) → io_uring (5-20M PPS)
→ sendmmsg (1-5M PPS) → Raw Sockets (200K-1M PPS) → Python (50-500K PPS)
```

---

## 🏗️ Architecture

```
NetStress/
├── 📄 ddos.py              # Main entry point
├── 📁 core/                # Core modules
│   ├── 🤖 ai/              # AI/ML optimization
│   ├── 📊 analytics/       # Statistics & metrics
│   ├── ⚔️ attacks/         # Attack implementations
│   ├── 🔧 performance/     # Performance optimization
│   ├── 🌐 protocols/       # Protocol handlers
│   └── 🛡️ safety/          # Safety controls
├── 📁 native/              # Rust engine (optional)
├── 📁 tests/               # Test suite
└── 📁 docs/                # Documentation
```

---

## 📚 Documentation

| Document                                      | Description              |
| --------------------------------------------- | ------------------------ |
| [📖 Quick Start](docs/QUICK_START.md)         | Get started in 5 minutes |
| [⚙️ Installation](docs/INSTALLATION.md)       | Detailed setup guide     |
| [💻 CLI Reference](docs/CLI_USAGE.md)         | Command-line options     |
| [🏛️ Architecture](docs/ARCHITECTURE.md)       | System design            |
| [⚡ Performance](docs/PERFORMANCE_TUNING.md)  | Optimization tips        |
| [🔧 Troubleshooting](docs/TROUBLESHOOTING.md) | Problem solving          |
| [❓ FAQ](docs/FAQ.md)                         | Common questions         |
| [🔒 Security](docs/SECURITY.md)               | Security features        |

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/CONTRIBUTING.md) before submitting a pull request.

```bash
# Fork, clone, and create a branch
git checkout -b feature/amazing-feature

# Make changes and test
pytest tests/

# Submit pull request
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) - Packet manipulation
- [aiohttp](https://docs.aiohttp.org/) - Async HTTP
- [psutil](https://psutil.readthedocs.io/) - System monitoring

---

<p align="center">
  <b>⭐ Star this repo if you find it useful!</b>
</p>

<p align="center">
  Made with ❤️ for the security research community
</p>
