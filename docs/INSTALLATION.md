<h1 align="center">📦 Installation Guide</h1>

<p align="center">
  <b>Complete installation instructions for all platforms</b>
</p>

---

## 📋 Table of Contents

- [Requirements](#-requirements)
- [Quick Install](#-quick-install)
- [Platform-Specific Installation](#-platform-specific-installation)
- [Native Engine Installation](#-native-engine-installation)
- [Pre-Built Binaries](#-pre-built-binaries)
- [Docker Installation](#-docker-installation)
- [Verification](#-verification)
- [Troubleshooting](#-troubleshooting)

---

## ✅ Requirements

### System Requirements

| Component   | Minimum       | Recommended      |
| ----------- | ------------- | ---------------- |
| **CPU**     | 2 cores       | 4+ cores         |
| **RAM**     | 2 GB          | 4+ GB            |
| **Storage** | 500 MB        | 1+ GB            |
| **Network** | Any interface | Gigabit Ethernet |

### Software Requirements

| Software   | Version | Required                        |
| ---------- | ------- | ------------------------------- |
| **Python** | 3.8+    | ✅ Yes                          |
| **pip**    | 20.0+   | ✅ Yes                          |
| **Git**    | Any     | ✅ Yes                          |
| **Rust**   | 1.70+   | ❌ Optional (for native engine) |

### Supported Operating Systems

| OS              | Version              | Status          |
| --------------- | -------------------- | --------------- |
| **Windows**     | 10, 11, Server 2016+ | ✅ Full Support |
| **Ubuntu**      | 18.04+               | ✅ Full Support |
| **Debian**      | 10+                  | ✅ Full Support |
| **CentOS/RHEL** | 7+                   | ✅ Full Support |
| **Fedora**      | 32+                  | ✅ Full Support |
| **Arch Linux**  | Rolling              | ✅ Full Support |
| **macOS**       | 10.14+               | ✅ Full Support |

---

## 🚀 Quick Install

### One-Line Installation

```bash
git clone https://github.com/Destroyer-official/NetStress.git && cd NetStress && pip install -r requirements.txt
```

### Step-by-Step

```bash
# 1. Clone repository
git clone https://github.com/Destroyer-official/NetStress.git

# 2. Enter directory
cd NetStress

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python ddos.py --status
```

---

## 🖥️ Platform-Specific Installation

### 🐧 Linux

<details>
<summary><b>Ubuntu / Debian</b></summary>

```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip python3-dev build-essential git

# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 ddos.py --status
```

**For raw socket attacks (TCP-SYN, ICMP):**

```bash
sudo python3 ddos.py -i TARGET -p 80 -t TCP-SYN
```

**Or set capabilities (more secure):**

```bash
sudo setcap cap_net_raw+ep $(which python3)
python3 ddos.py -i TARGET -p 80 -t TCP-SYN
```

</details>

<details>
<summary><b>CentOS / RHEL / Fedora</b></summary>

```bash
# Install Python and development tools
sudo dnf install python3 python3-pip python3-devel gcc git

# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 ddos.py --status
```

</details>

<details>
<summary><b>Arch Linux</b></summary>

```bash
# Install Python
sudo pacman -S python python-pip base-devel git

# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip install -r requirements.txt

# Verify installation
python ddos.py --status
```

</details>

### 🪟 Windows

<details>
<summary><b>Windows 10 / 11</b></summary>

**Step 1: Install Python**

1. Download Python from [python.org](https://www.python.org/downloads/)
2. Run installer
3. ✅ Check "Add Python to PATH"
4. Click "Install Now"

**Step 2: Install Git**

1. Download Git from [git-scm.com](https://git-scm.com/download/win)
2. Run installer with default options

**Step 3: Install NetStress**

Open PowerShell as Administrator:

```powershell
# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip install -r requirements.txt

# Verify installation
python ddos.py --status
```

**Step 4: Install Npcap (for raw sockets)**

1. Download from [npcap.com](https://npcap.com/)
2. Install with "WinPcap API-compatible Mode" checked
3. Restart PowerShell

</details>

### 🍎 macOS

<details>
<summary><b>macOS 10.14+</b></summary>

**Step 1: Install Homebrew (if not installed)**

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Step 2: Install Python**

```bash
brew install python git
```

**Step 3: Install NetStress**

```bash
# Clone repository
git clone https://github.com/Destroyer-official/NetStress.git
cd NetStress

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 ddos.py --status
```

**For raw socket attacks:**

```bash
sudo python3 ddos.py -i TARGET -p 80 -t TCP-SYN
```

</details>

---

## ⚡ Native Engine Installation

The native Rust engine provides 10-100x performance improvement.

### Method 1: Pre-Built Binary (Recommended)

```bash
python scripts/install_native.py
```

This downloads a pre-built binary for your platform. No Rust installation required.

### Method 2: Build from Source

<details>
<summary><b>Build Instructions</b></summary>

**Step 1: Install Rust**

```bash
# Linux/macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Windows (PowerShell)
Invoke-WebRequest -Uri https://win.rustup.rs -OutFile rustup-init.exe
.\rustup-init.exe
```

**Step 2: Install maturin**

```bash
pip install maturin
```

**Step 3: Build**

```bash
cd native/rust_engine
maturin develop --release
```

**Step 4: Verify**

```bash
cd ../..
python ddos.py --status
# Should show "Native Engine: Yes"
```

</details>

---

## 📦 Pre-Built Binaries

No Python or Rust required! Download and run.

### Linux

```bash
# Download
wget https://github.com/Destroyer-official/NetStress/releases/latest/download/netstress-linux-x86_64.tar.gz

# Extract
tar -xzf netstress-linux-x86_64.tar.gz

# Make executable
chmod +x netstress

# Run
./netstress --help
```

### Windows

```powershell
# Download
Invoke-WebRequest -Uri "https://github.com/Destroyer-official/NetStress/releases/latest/download/netstress-win-amd64.zip" -OutFile "netstress.zip"

# Extract
Expand-Archive netstress.zip -DestinationPath .

# Run
.\netstress.exe --help
```

---

## 🐳 Docker Installation

<details>
<summary><b>Docker Instructions</b></summary>

**Build Image**

```bash
docker build -t netstress .
```

**Run Container**

```bash
# Basic usage
docker run --rm netstress -i TARGET -p 80 -t UDP -d 60

# With network access
docker run --rm --network host netstress -i TARGET -p 80 -t UDP -d 60

# Interactive mode
docker run -it --rm netstress --status
```

**Docker Compose**

```yaml
version: "3"
services:
  netstress:
    build: .
    network_mode: host
    command: ["-i", "TARGET", "-p", "80", "-t", "UDP", "-d", "60"]
```

</details>

---

## ✅ Verification

### Check Installation

```bash
python ddos.py --status
```

**Expected Output:**

```
╔══════════════════════════════════════════════════════════════╗
║              NetStress System Status                         ║
╠══════════════════════════════════════════════════════════════╣
║  Platform: Linux 5.15.0                                      ║
║  Python: 3.10.6                                              ║
║  CPU Cores: 8                                                ║
║  Root/Admin: No                                              ║
║                                                              ║
║  Module Status:                                              ║
║    Native Engine: Yes                                        ║
║    Safety: Yes                                               ║
║    AI/ML: Yes                                                ║
║    Analytics: Yes                                            ║
║    Performance: Yes                                          ║
╚══════════════════════════════════════════════════════════════╝
```

### Test Run

```bash
# Safe test against localhost
python ddos.py -i 127.0.0.1 -p 9999 -t UDP -d 5
```

---

## 🔧 Troubleshooting

### Common Issues

<details>
<summary><b>"pip: command not found"</b></summary>

**Linux:**

```bash
sudo apt install python3-pip  # Debian/Ubuntu
sudo dnf install python3-pip  # Fedora/RHEL
```

**macOS:**

```bash
brew install python
```

**Windows:**
Reinstall Python with "Add to PATH" checked.

</details>

<details>
<summary><b>"ModuleNotFoundError"</b></summary>

```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Or install specific module
pip install <module_name>
```

</details>

<details>
<summary><b>Scapy installation fails on Windows</b></summary>

1. Install Npcap from [npcap.com](https://npcap.com/)
2. Check "WinPcap API-compatible Mode"
3. Restart terminal
4. Run: `pip install scapy`

</details>

<details>
<summary><b>"Permission denied" for raw sockets</b></summary>

**Linux/macOS:**

```bash
sudo python3 ddos.py ...
```

**Windows:**
Run PowerShell as Administrator.

</details>

<details>
<summary><b>Native engine not loading</b></summary>

```bash
# Reinstall native engine
python scripts/install_native.py --force

# Or build from source
cd native/rust_engine
maturin develop --release
```

</details>

---

## 📚 Next Steps

<table>
<tr>
<td width="33%" align="center">

### 🚀 Quick Start

[Get Started](QUICK_START.md)

</td>
<td width="33%" align="center">

### 💻 CLI Reference

[Commands](CLI_USAGE.md)

</td>
<td width="33%" align="center">

### ⚡ Performance

[Optimization](PERFORMANCE_TUNING.md)

</td>
</tr>
</table>

---

<p align="center">
  <b>Installation complete? <a href="QUICK_START.md">Start your first test!</a></b>
</p>
