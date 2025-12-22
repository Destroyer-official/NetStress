# NetStress Build Instructions

This document provides comprehensive build instructions for NetStress across all supported platforms, including both Python-only mode and the high-performance native engine.

## Quick Start

For most users, the automated installation scripts are recommended:

```bash
# Linux/macOS
curl -sSL https://raw.githubusercontent.com/Destroyer-official/-NetStress-/main/scripts/install.sh | bash

# Windows (PowerShell as Administrator)
iwr -useb https://raw.githubusercontent.com/Destroyer-official/-NetStress-/main/scripts/install.ps1 | iex
```

## Manual Installation

### Prerequisites

#### All Platforms

- **Python 3.8+** (3.9+ recommended)
- **Git** for cloning the repository
- **pip** for Python package management

#### Platform-Specific Requirements

**Linux:**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv build-essential git curl
sudo apt install libpcap-dev libffi-dev libssl-dev pkg-config  # For advanced features

# CentOS/RHEL/Fedora
sudo dnf install python3 python3-pip git curl gcc gcc-c++ make
sudo dnf install libpcap-devel libffi-devel openssl-devel pkgconfig  # For advanced features
```

**Windows:**

- Install Python from [python.org](https://python.org/downloads/)
- Install Git from [git-scm.com](https://git-scm.com/download/win)
- Install Visual Studio Build Tools or Visual Studio Community
- Install Npcap from [nmap.org/npcap](https://nmap.org/npcap/) (for packet capture)

**macOS:**

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 git libpcap
xcode-select --install  # Install Xcode Command Line Tools
```

## Basic Installation (Python Only)

### 1. Clone Repository

```bash
git clone https://github.com/Destroyer-official/-NetStress-.git
cd -NetStress-
```

### 2. Create Virtual Environment

```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install core dependencies
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

### 4. Verify Installation

```bash
# Test basic functionality
python ddos.py --help
python ddos.py --status

# Run tests
python -m pytest tests/ -v
```

## Native Engine Build (High Performance)

The native engine provides 10-100x performance improvement through Rust and C components.

### Prerequisites for Native Engine

#### Rust Installation

```bash
# Install Rust (all platforms)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

#### Platform-Specific Native Dependencies

**Linux:**

```bash
# Ubuntu/Debian
sudo apt install build-essential libssl-dev pkg-config
sudo apt install linux-headers-$(uname -r)  # For kernel modules

# For advanced backends (optional)
sudo apt install dpdk dpdk-dev              # DPDK support
sudo apt install libbpf-dev                 # AF_XDP support
sudo apt install liburing-dev               # io_uring support

# CentOS/RHEL/Fedora
sudo dnf groupinstall "Development Tools"
sudo dnf install openssl-devel pkgconfig kernel-devel

# For advanced backends (optional)
sudo dnf install dpdk-devel libbpf-devel liburing-devel
```

**Windows:**

```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

# Install Windows SDK (for advanced features)
# Download from: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
```

**macOS:**

```bash
# Xcode Command Line Tools (if not already installed)
xcode-select --install

# Additional dependencies
brew install openssl pkg-config
```

### Build Native Engine

#### 1. Install maturin (Rust-Python bridge)

```bash
pip install maturin
```

#### 2. Build Rust Engine

```bash
# Navigate to Rust engine directory
cd native/rust_engine

# Development build (faster compilation, debug symbols)
maturin develop

# Release build (optimized, recommended for production)
maturin develop --release

# Build with specific features
maturin develop --release --features "sendmmsg,io_uring"  # Linux
maturin develop --release --features "iocp"              # Windows
maturin develop --release --features "kqueue"            # macOS
```

#### 3. Build C Driver (Advanced Backends)

```bash
# Navigate to C driver directory
cd native/c_driver

# Linux
make clean && make

# Windows (with Visual Studio)
cl /O2 driver_shim.c /Fe:driver_shim.dll

# macOS
make clean && make
```

#### 4. Verify Native Engine

```bash
# Test native engine availability
python -c "
try:
    import netstress_engine
    print('Native engine available')
    print(f'Backends: {netstress_engine.get_capabilities()}')
except ImportError:
    print('Native engine not available')
"

# Run native engine tests
python -m pytest tests/test_native_engine.py -v
```

## Advanced Build Options

### Feature Flags

The Rust engine supports various feature flags for different backends:

```bash
# Linux features
maturin develop --release --features "sendmmsg"     # sendmmsg batch sending
maturin develop --release --features "io_uring"     # io_uring async I/O
maturin develop --release --features "af_xdp"       # AF_XDP kernel bypass
maturin develop --release --features "dpdk"         # DPDK kernel bypass

# Windows features
maturin develop --release --features "iocp"         # I/O Completion Ports
maturin develop --release --features "registered_io" # Registered I/O

# macOS features
maturin develop --release --features "kqueue"       # kqueue event handling

# Combined features
maturin develop --release --features "sendmmsg,io_uring,af_xdp"
```

### DPDK Build (Linux Only)

DPDK provides the highest performance but requires additional setup:

#### 1. Install DPDK

```bash
# Ubuntu/Debian
sudo apt install dpdk dpdk-dev

# CentOS/RHEL/Fedora
sudo dnf install dpdk-devel

# Or build from source
wget https://fast.dpdk.org/rel/dpdk-23.11.tar.xz
tar xf dpdk-23.11.tar.xz
cd dpdk-23.11
meson build
cd build
ninja
sudo ninja install
```

#### 2. Configure Hugepages

```bash
# Configure hugepages (required for DPDK)
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Make persistent
echo 'vm.nr_hugepages=1024' | sudo tee -a /etc/sysctl.conf
```

#### 3. Bind Network Interface

```bash
# Install DPDK tools
sudo apt install dpdk-dev

# Bind interface to DPDK (replace eth1 with your interface)
sudo dpdk-devbind.py --bind=uio_pci_generic eth1

# Verify binding
dpdk-devbind.py --status
```

#### 4. Build with DPDK

```bash
cd native/rust_engine
maturin develop --release --features "dpdk"
```

### Cross-Compilation

#### Linux to Windows

```bash
# Install cross-compilation target
rustup target add x86_64-pc-windows-gnu

# Install mingw-w64
sudo apt install mingw-w64

# Build for Windows
cd native/rust_engine
maturin build --release --target x86_64-pc-windows-gnu
```

#### Linux to macOS

```bash
# Install cross-compilation target
rustup target add x86_64-apple-darwin

# Install osxcross (complex setup, see osxcross documentation)
# Build for macOS
cd native/rust_engine
maturin build --release --target x86_64-apple-darwin
```

## Distribution Builds

### Building Wheels

```bash
# Build wheel for current platform
cd native/rust_engine
maturin build --release

# Build wheels for multiple platforms (requires setup)
maturin build --release --target x86_64-unknown-linux-gnu
maturin build --release --target x86_64-pc-windows-msvc
maturin build --release --target x86_64-apple-darwin

# Wheels will be in target/wheels/
```

### Docker Build

```dockerfile
# Dockerfile for Linux build
FROM rust:1.70 as rust-builder

WORKDIR /app
COPY native/rust_engine/ ./
RUN cargo build --release

FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
COPY --from=rust-builder /app/target/release/libnetstress_engine.so ./

RUN pip install -e .

CMD ["python", "ddos.py", "--help"]
```

```bash
# Build Docker image
docker build -t netstress:latest .

# Run container
docker run --rm -it --cap-add=NET_RAW netstress:latest
```

## Platform-Specific Build Notes

### Linux

#### Performance Optimizations

```bash
# Kernel parameters for high performance
echo 'net.core.rmem_max = 268435456' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 268435456' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_timestamps = 0' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# CPU governor for performance
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

#### Capabilities Setup

```bash
# Allow raw sockets without root (alternative to sudo)
sudo setcap cap_net_raw+ep $(which python3)

# Or for the specific binary
sudo setcap cap_net_raw+ep ./venv/bin/python
```

### Windows

#### Visual Studio Setup

```powershell
# Install Visual Studio Build Tools
# Required components:
# - MSVC v143 - VS 2022 C++ x64/x86 build tools
# - Windows 11 SDK (latest version)
# - CMake tools for Visual Studio

# Verify installation
where cl
where link
```

#### Windows Defender Exclusions

```powershell
# Add exclusions for Windows Defender (run as Administrator)
Add-MpPreference -ExclusionPath "C:\path\to\NetStress"
Add-MpPreference -ExclusionProcess "python.exe"
```

### macOS

#### Xcode Setup

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Verify installation
xcode-select -p
gcc --version
```

#### SIP Considerations

```bash
# Check SIP status
csrutil status

# If SIP is enabled, some features may be limited
# Consider disabling SIP for development (not recommended for production)
```

## Troubleshooting

### Common Build Issues

#### "Rust compiler not found"

```bash
# Reinstall Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup update
```

#### "maturin not found"

```bash
# Install maturin in the correct environment
pip install --upgrade maturin

# Or install with cargo
cargo install maturin
```

#### "libpcap not found" (Linux)

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# CentOS/RHEL/Fedora
sudo dnf install libpcap-devel
```

#### "Microsoft Visual C++ 14.0 is required" (Windows)

```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
```

#### "Permission denied" for raw sockets

```bash
# Linux/macOS - run with sudo
sudo python ddos.py [options]

# Or set capabilities (Linux only)
sudo setcap cap_net_raw+ep $(which python3)

# Windows - run as Administrator
# Right-click Command Prompt -> "Run as administrator"
```

### Performance Issues

#### Low packet rates

```bash
# Check available backends
python -c "
from core.native_engine import get_capabilities
print(get_capabilities())
"

# Verify native engine is loaded
python -c "
try:
    import netstress_engine
    print('Native engine loaded')
except ImportError:
    print('Using Python fallback')
"
```

#### Memory issues

```bash
# Monitor memory usage
python -c "
import psutil
print(f'Available memory: {psutil.virtual_memory().available / 1024**3:.1f} GB')
"

# Reduce thread count or packet size if needed
python ddos.py -i target -p 80 -t UDP --threads 2 --size 512
```

## Testing the Build

### Basic Tests

```bash
# Run all tests
make test

# Run specific test suites
python -m pytest tests/test_basic.py -v
python -m pytest tests/test_native_engine.py -v
python -m pytest tests/test_advanced_features.py -v

# Run performance benchmarks
python -m pytest tests/test_performance.py -v --benchmark-only
```

### Manual Testing

```bash
# Test basic functionality
python ddos.py --help
python ddos.py --status

# Test against localhost (safe)
python ddos.py -i 127.0.0.1 -p 9999 -t UDP -d 5 --dry-run

# Test native engine
python -c "
import netstress_engine
engine = netstress_engine.PacketEngine('127.0.0.1', 9999, 1, 1024)
print('Native engine test passed')
"
```

### Continuous Integration

```yaml
# .github/workflows/build.yml
name: Build and Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: [3.8, 3.9, "3.10", 3.11]

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install maturin pytest

      - name: Build native engine
        run: |
          cd native/rust_engine
          maturin develop --release

      - name: Run tests
        run: |
          python -m pytest tests/ -v
```

## Support

### Getting Help

- **Documentation:** [docs/](docs/)
- **Issues:** [GitHub Issues](https://github.com/Destroyer-official/-NetStress-/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Destroyer-official/-NetStress-/discussions)

### Reporting Build Issues

When reporting build issues, please include:

1. Operating system and version
2. Python version (`python --version`)
3. Rust version (`rustc --version`)
4. Complete error message
5. Build command used
6. System specifications (CPU, RAM, etc.)

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to the project.

---

**Last Updated:** December 2024  
**Version:** 2.0.0
