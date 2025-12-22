# Cross-Platform Guide

## Overview

NetStress provides true cross-platform performance parity through platform-specific optimizations and adaptive backend selection. This guide covers platform-specific features, limitations, and optimization strategies.

## Platform Support Matrix

| Feature                | Windows | macOS | Linux | ARM64 | ARM32 |
| ---------------------- | ------- | ----- | ----- | ----- | ----- |
| **Basic UDP/TCP**      | ✅      | ✅    | ✅    | ✅    | ✅    |
| **Raw Sockets**        | ✅¹     | ✅²   | ✅    | ✅    | ✅    |
| **Zero-Copy I/O**      | ✅³     | ✅⁴   | ✅⁵   | ✅    | ❌    |
| **SIMD Optimization**  | ✅⁶     | ✅⁷   | ✅⁶   | ✅⁸   | ❌    |
| **Hardware Detection** | ✅      | ✅    | ✅    | ✅    | ✅    |
| **JA4 Spoofing**       | ✅      | ✅    | ✅    | ✅    | ✅    |
| **DoH Tunneling**      | ✅      | ✅    | ✅    | ✅    | ✅    |
| **P2P Coordination**   | ✅      | ✅    | ✅    | ✅    | ✅    |

¹ Requires Administrator privileges  
² Requires sudo privileges  
³ RIO on Server 2016+, IOCP fallback  
⁴ Network.framework on Ventura+, kqueue fallback  
⁵ DPDK/AF_XDP/io_uring/sendmmsg chain  
⁶ AVX2/AVX-512 on x86_64  
⁷ AVX2 on Intel, NEON on Apple Silicon  
⁸ NEON on ARM64

## Windows Platform

### Supported Versions

- **Windows 10** (1903+): Full support with IOCP backend
- **Windows 11**: Full support with enhanced performance
- **Windows Server 2016+**: Maximum performance with RIO backend
- **Windows Server 2019/2022**: Optimal performance and features

### Backend Selection Chain

```
RIO (Server 2016+) → IOCP → Winsock2
```

#### Registered I/O (RIO) Backend

```python
from core.platform.windows_rio import RioBackend

# Check RIO availability
if RioBackend.is_available():
    print("RIO backend available - maximum performance")
    backend = RioBackend()

    # RIO features:
    # - Zero-copy packet transmission
    # - Kernel bypass for reduced latency
    # - Scalable to millions of connections
    # - Hardware offload support
```

**RIO Requirements:**

- Windows Server 2016 or later
- Administrator privileges
- Compatible network adapter
- Sufficient system resources

**RIO Performance:**

- **Throughput**: Up to 50M+ PPS on enterprise hardware
- **Latency**: Sub-microsecond packet transmission
- **CPU Usage**: 50-70% lower than traditional sockets
- **Memory**: Zero-copy reduces memory bandwidth

#### I/O Completion Ports (IOCP) Backend

```python
from core.platform.windows_iocp import IocpBackend

# IOCP is available on all Windows versions
backend = IocpBackend()

# IOCP features:
# - Asynchronous I/O operations
# - Efficient thread pool management
# - Scalable to thousands of connections
# - Good performance on all Windows versions
```

**IOCP Performance:**

- **Throughput**: Up to 10M+ PPS on high-end hardware
- **Latency**: Low-latency async operations
- **CPU Usage**: Efficient thread utilization
- **Scalability**: Excellent for high connection counts

### Windows-Specific Optimizations

#### Network Adapter Configuration

```powershell
# Run as Administrator

# Enable Receive Side Scaling (RSS)
netsh int tcp set global rss=enabled

# Enable TCP Chimney Offload
netsh int tcp set global chimney=enabled

# Optimize TCP auto-tuning
netsh int tcp set global autotuninglevel=normal

# Increase network buffer sizes
netsh int tcp set global netdma=enabled
```

#### Windows Defender Exclusions

```powershell
# Add NetStress to Windows Defender exclusions
Add-MpPreference -ExclusionPath "C:\path\to\netstress"
Add-MpPreference -ExclusionProcess "python.exe"

# Temporarily disable real-time protection (for testing)
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Power Management

```powershell
# Set high performance power plan
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Disable USB selective suspend
powercfg -setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
```

### Windows Troubleshooting

#### Common Issues

1. **"Access Denied" errors**: Run as Administrator
2. **Low performance**: Check Windows Defender exclusions
3. **RIO not available**: Verify Windows Server version
4. **Firewall blocking**: Configure Windows Firewall rules

#### Performance Debugging

```python
from core.diagnostics.windows import WindowsProfiler

profiler = WindowsProfiler()
report = profiler.analyze_performance()

print(f"RIO Available: {report.rio_available}")
print(f"IOCP Threads: {report.iocp_threads}")
print(f"Network Offload: {report.network_offload}")
```

## macOS Platform

### Supported Versions

- **macOS 12.0+ (Monterey)**: Full support
- **macOS 13.0+ (Ventura)**: Network.framework backend
- **macOS 14.0+ (Sonoma)**: Enhanced performance
- **Apple Silicon (M1/M2/M3)**: Native ARM64 optimization

### Backend Selection Chain

```
Network.framework (Ventura+) → kqueue → BSD sockets
```

#### Network.framework Backend

```python
from core.platform.macos_network import NetworkFrameworkBackend

# Check Network.framework availability
if NetworkFrameworkBackend.is_available():
    print("Network.framework available - Apple optimized")
    backend = NetworkFrameworkBackend()

    # Network.framework features:
    # - Apple's modern networking stack
    # - Optimized for Apple Silicon
    # - Integrated with system networking
    # - Enhanced security and privacy
```

**Network.framework Requirements:**

- macOS 13.0+ (Ventura)
- Compatible with all Mac hardware
- No special privileges required for basic operations
- sudo required for raw sockets

**Network.framework Performance:**

- **Throughput**: Up to 10M+ PPS on Apple Silicon
- **Latency**: Optimized for Apple hardware
- **CPU Usage**: Efficient on Apple Silicon unified memory
- **Integration**: Seamless with macOS networking

#### kqueue Backend

```python
from core.platform.macos_kqueue import KqueueBackend

# kqueue is available on all macOS versions
backend = KqueueBackend()

# kqueue features:
# - Event-driven I/O multiplexing
# - Low-latency event notification
# - Scalable to thousands of connections
# - POSIX-compliant implementation
```

### Apple Silicon Optimization

#### ARM64 NEON SIMD

```rust
// Rust SIMD optimization for Apple Silicon
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[cfg(target_arch = "aarch64")]
unsafe fn process_packets_neon(packets: &mut [u8]) {
    let mut i = 0;
    while i + 16 <= packets.len() {
        let data = vld1q_u8(packets.as_ptr().add(i));
        let processed = vaddq_u8(data, vdupq_n_u8(1));
        vst1q_u8(packets.as_mut_ptr().add(i), processed);
        i += 16;
    }
}
```

#### Unified Memory Architecture

```python
# Optimize for Apple Silicon unified memory
config = EngineConfig(
    target="127.0.0.1",
    port=80,
    buffer_size=4 * 1024 * 1024,  # Larger buffers benefit from UMA
    threads=8,  # Optimal for M1/M2 performance cores
    memory_pool_size=1024 * 1024 * 1024  # 1GB pool
)
```

### macOS-Specific Optimizations

#### System Configuration

```bash
# Increase socket buffer limits
sudo sysctl -w net.inet.tcp.sendspace=1048576
sudo sysctl -w net.inet.tcp.recvspace=1048576
sudo sysctl -w net.inet.udp.maxdgram=65536

# Increase file descriptor limits
sudo launchctl limit maxfiles 65536 200000
ulimit -n 65536

# Disable TCP delayed ACK (for testing)
sudo sysctl -w net.inet.tcp.delayed_ack=0
```

#### Security Settings

```bash
# Allow raw socket access (requires sudo)
sudo dscl . -create /Groups/netdev
sudo dscl . -create /Groups/netdev PrimaryGroupID 220
sudo dseditgroup -o edit -a $(whoami) -t user netdev

# System Integrity Protection considerations
# SIP may restrict some low-level operations
csrutil status
```

### macOS Troubleshooting

#### Common Issues

1. **Permission denied**: Use sudo for raw sockets
2. **Low performance**: Check Activity Monitor for CPU throttling
3. **Network.framework unavailable**: Update to macOS 13+
4. **File descriptor limits**: Increase ulimit settings

## Linux Platform

### Supported Distributions

- **Ubuntu 20.04+**: Full support with all backends
- **CentOS 8+**: Enterprise-grade performance
- **Debian 11+**: Stable platform support
- **Arch Linux**: Latest kernel features
- **RHEL 8+**: Enterprise deployment

### Backend Selection Chain

```
DPDK → AF_XDP (4.18+) → io_uring (5.1+) → sendmmsg → raw socket
```

#### DPDK Backend (Enterprise)

```python
from core.platform.linux_dpdk import DpdkBackend

# Check DPDK availability
if DpdkBackend.is_available():
    print("DPDK available - maximum performance")
    backend = DpdkBackend()

    # DPDK features:
    # - Kernel bypass networking
    # - Poll-mode drivers (PMD)
    # - Zero-copy packet processing
    # - 100M+ PPS capability
```

**DPDK Requirements:**

- Compatible network adapter
- Hugepage support
- Root privileges
- Dedicated CPU cores

**DPDK Performance:**

- **Throughput**: 100M+ PPS on enterprise hardware
- **Latency**: Sub-microsecond packet processing
- **CPU Usage**: Dedicated cores for maximum performance
- **Memory**: Hugepage-optimized memory pools

#### AF_XDP Backend

```python
from core.platform.linux_afxdp import AfXdpBackend

# Check AF_XDP availability (kernel 4.18+)
if AfXdpBackend.is_available():
    print("AF_XDP available - zero-copy kernel space")
    backend = AfXdpBackend()

    # AF_XDP features:
    # - Zero-copy packet I/O
    # - Kernel space processing
    # - XDP program integration
    # - High performance without kernel bypass
```

**AF_XDP Requirements:**

- Linux kernel 4.18+
- XDP-compatible network driver
- Root privileges
- BPF/XDP program support

#### io_uring Backend

```python
from core.platform.linux_uring import IoUringBackend

# Check io_uring availability (kernel 5.1+)
if IoUringBackend.is_available():
    print("io_uring available - modern async I/O")
    backend = IoUringBackend()

    # io_uring features:
    # - Modern async I/O interface
    # - Reduced system call overhead
    # - Batch operation support
    # - High performance I/O
```

### Linux-Specific Optimizations

#### Kernel Parameters

```bash
# Network performance tuning
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 30000' | sudo tee -a /etc/sysctl.conf
echo 'net.core.netdev_budget = 600' | sudo tee -a /etc/sysctl.conf

# TCP optimization
echo 'net.ipv4.tcp_rmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control = bbr' | sudo tee -a /etc/sysctl.conf

# Apply settings
sudo sysctl -p
```

#### Hugepage Configuration

```bash
# Configure 2MB hugepages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Configure 1GB hugepages (for DPDK)
echo 4 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages

# Make persistent
echo 'vm.nr_hugepages = 1024' | sudo tee -a /etc/sysctl.conf
```

#### CPU Isolation

```bash
# Isolate CPUs for dedicated packet processing
# Add to GRUB_CMDLINE_LINUX in /etc/default/grub
GRUB_CMDLINE_LINUX="isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7"

# Update GRUB and reboot
sudo update-grub
sudo reboot
```

#### IRQ Affinity

```bash
# Distribute network interrupts across CPUs
echo 2 | sudo tee /proc/irq/24/smp_affinity  # CPU 1
echo 4 | sudo tee /proc/irq/25/smp_affinity  # CPU 2
echo 8 | sudo tee /proc/irq/26/smp_affinity  # CPU 3

# Or use irqbalance for automatic distribution
sudo systemctl enable irqbalance
sudo systemctl start irqbalance
```

## ARM Platform Support

### ARM64 (AArch64)

- **Raspberry Pi 4/5**: Low-tier performance optimization
- **AWS Graviton**: Server-grade ARM optimization
- **Apple Silicon**: macOS-specific optimizations
- **NVIDIA Jetson**: Edge computing optimization

#### ARM64 NEON Optimization

```rust
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[cfg(target_arch = "aarch64")]
pub fn checksum_neon(data: &[u8]) -> u32 {
    unsafe {
        let mut sum = vdupq_n_u32(0);
        let mut i = 0;

        while i + 16 <= data.len() {
            let bytes = vld1q_u8(data.as_ptr().add(i));
            let words = vreinterpretq_u32_u8(bytes);
            sum = vaddq_u32(sum, words);
            i += 16;
        }

        // Horizontal sum
        let sum64 = vpaddlq_u32(sum);
        let sum_final = vaddvq_u64(sum64);
        sum_final as u32
    }
}
```

### ARM32 (ARMv7)

- **Raspberry Pi 3**: Basic functionality
- **BeagleBone**: Embedded applications
- **Limited Performance**: No SIMD optimization

#### ARM32 Limitations

```python
# ARM32 configuration with limitations
config = EngineConfig(
    target="127.0.0.1",
    port=80,
    threads=1,  # Single-threaded on ARM32
    buffer_size=64 * 1024 * 1024,  # Smaller buffers
    simd_enabled=False,  # No SIMD support
    rate_limit=10000  # Conservative rate limit
)
```

## Performance Comparison

### Relative Performance by Platform

| Platform                      | Backend           | Relative Performance | Notes                           |
| ----------------------------- | ----------------- | -------------------- | ------------------------------- |
| **Linux + DPDK**              | DPDK              | 100%                 | Maximum theoretical performance |
| **Linux + AF_XDP**            | AF_XDP            | 90%                  | Kernel space zero-copy          |
| **Windows + RIO**             | RIO               | 85%                  | Windows zero-copy               |
| **Linux + io_uring**          | io_uring          | 80%                  | Modern async I/O                |
| **macOS + Network.framework** | Network.framework | 75%                  | Apple optimized                 |
| **Linux + sendmmsg**          | sendmmsg          | 70%                  | Batch operations                |
| **Windows + IOCP**            | IOCP              | 65%                  | Async I/O                       |
| **macOS + kqueue**            | kqueue            | 60%                  | Event-driven I/O                |
| **All + BSD sockets**         | BSD               | 50%                  | Standard sockets                |

### Architecture Performance

| Architecture         | SIMD    | Relative Performance | Notes                    |
| -------------------- | ------- | -------------------- | ------------------------ |
| **x86_64 + AVX-512** | AVX-512 | 100%                 | Maximum SIMD performance |
| **x86_64 + AVX2**    | AVX2    | 85%                  | Standard x86_64 SIMD     |
| **ARM64 + NEON**     | NEON    | 80%                  | ARM SIMD optimization    |
| **x86_64 (no SIMD)** | None    | 60%                  | Scalar operations only   |
| **ARM32**            | None    | 40%                  | Limited performance      |

## Cross-Platform Development

### Conditional Compilation

```rust
// Platform-specific code compilation
#[cfg(target_os = "windows")]
mod windows_backend;

#[cfg(target_os = "macos")]
mod macos_backend;

#[cfg(target_os = "linux")]
mod linux_backend;

// Architecture-specific optimizations
#[cfg(target_arch = "x86_64")]
mod x86_simd;

#[cfg(target_arch = "aarch64")]
mod arm_simd;
```

### Runtime Detection

```python
from core.platform.detector import PlatformDetector

detector = PlatformDetector()

# Detect platform capabilities
caps = detector.detect_capabilities()
print(f"Platform: {caps.platform}")
print(f"Architecture: {caps.architecture}")
print(f"Available backends: {caps.backends}")
print(f"SIMD support: {caps.simd_features}")

# Select optimal configuration
config = detector.get_optimal_config()
```

### Testing Across Platforms

#### Continuous Integration

```yaml
# GitHub Actions example
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
    python-version: [3.8, 3.9, 3.10, 3.11]
    architecture: [x64, arm64]
```

#### Platform-Specific Tests

```python
import pytest
import platform

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
def test_rio_backend():
    # Windows RIO backend test
    pass

@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS-specific test")
def test_network_framework():
    # macOS Network.framework test
    pass

@pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific test")
def test_af_xdp_backend():
    # Linux AF_XDP backend test
    pass
```

## Migration Guide

### From Single Platform to Cross-Platform

1. **Identify Platform Dependencies**: Audit code for platform-specific calls
2. **Abstract Backend Interface**: Create common interface for all backends
3. **Implement Platform Detection**: Add runtime platform detection
4. **Add Fallback Chains**: Implement graceful backend fallback
5. **Test on All Platforms**: Comprehensive cross-platform testing

### Best Practices

1. **Use Abstraction Layers**: Hide platform differences behind common APIs
2. **Implement Graceful Fallback**: Always have a working fallback option
3. **Test Early and Often**: Regular testing on all target platforms
4. **Document Platform Differences**: Clear documentation of platform-specific behavior
5. **Monitor Performance**: Track performance across all platforms

This cross-platform guide ensures NetStress delivers consistent performance and functionality across all supported platforms while leveraging platform-specific optimizations for maximum performance.
