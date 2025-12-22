# NetStress Native Engine - Power Trio Architecture

High-performance packet generation using the "Sandwich" architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    PYTHON LAYER (Brain)                      │
│  ddos.py │ CLI │ AI/ML │ Analytics │ Configuration          │
├─────────────────────────────────────────────────────────────┤
│                    RUST LAYER (Engine)                       │
│  netstress_engine │ Packet Gen │ Threading │ Lock-Free      │
├─────────────────────────────────────────────────────────────┤
│                    C LAYER (Metal)                           │
│  DPDK │ AF_XDP │ io_uring │ sendmmsg │ Raw Sockets          │
└─────────────────────────────────────────────────────────────┘
```

## Performance Targets

| Backend     | Target PPS | Target Bandwidth |
| ----------- | ---------- | ---------------- |
| DPDK        | 100M+      | 100+ Gbps        |
| AF_XDP      | 10M-50M    | 40-100 Gbps      |
| io_uring    | 1M-10M     | 10-40 Gbps       |
| sendmmsg    | 500K-2M    | 5-20 Gbps        |
| Raw Socket  | 50K-500K   | 1-5 Gbps         |
| Pure Python | 10K-50K    | 0.1-0.5 Gbps     |

## Directory Structure

```
native/
├── rust_engine/          # Rust packet engine (PyO3)
│   ├── src/
│   │   ├── lib.rs            # PyO3 module definition
│   │   ├── engine.rs         # Flood engine implementation
│   │   ├── packet.rs         # Packet building
│   │   ├── stats.rs          # Statistics tracking
│   │   ├── pool.rs           # Buffer pool management
│   │   ├── simd.rs           # SIMD-accelerated operations
│   │   ├── queue.rs          # Lock-free MPMC queues
│   │   ├── backend.rs        # Backend abstraction trait
│   │   ├── backend_selector.rs # Auto-detection & fallback
│   │   ├── rate_limiter.rs   # Precision rate limiting
│   │   ├── protocol_builder.rs # Enhanced protocol builders
│   │   ├── atomic_stats.rs   # Lock-free statistics
│   │   └── safety.rs         # Safety controls & compliance
│   └── Cargo.toml
│
└── c_driver/             # C hardware interface
    ├── driver_shim.c     # Backend implementations
    └── driver_shim.h     # API definitions
```

## Building

### Quick Build

```bash
# Use Makefile for platform-specific builds
make build-native          # Auto-detect platform and build
make build-native-linux     # Linux with sendmmsg + io_uring
make build-native-windows   # Windows with IOCP
make build-native-macos     # macOS with kqueue
make build-native-full      # Linux with all features (DPDK, AF_XDP, etc.)
```

### Prerequisites

**All Platforms:**

- Rust 1.70+ with `cargo`
- Python 3.8+ with `maturin`
- C compiler (gcc/clang/MSVC)

**Linux:**

```bash
sudo apt install build-essential libssl-dev pkg-config
sudo apt install linux-headers-$(uname -r)  # For kernel modules
```

**Windows:**

- Visual Studio Build Tools 2022
- Windows SDK (latest)

**macOS:**

```bash
xcode-select --install
brew install openssl pkg-config
```

### Manual Build

```bash
cd native/rust_engine

# Install maturin
pip install maturin

# Development build
maturin develop

# Release build (optimized)
maturin develop --release

# Platform-specific features
maturin develop --release --features "sendmmsg,io_uring"  # Linux
maturin develop --release --features "iocp"              # Windows
maturin develop --release --features "kqueue"            # macOS

# Build wheel for distribution
maturin build --release
```

### Advanced Features (Linux Only)

#### DPDK Support

```bash
# Install DPDK
sudo apt install dpdk dpdk-dev

# Configure hugepages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Build with DPDK
maturin develop --release --features "dpdk"
```

#### AF_XDP Support

```bash
# Install libbpf
sudo apt install libbpf-dev

# Build with AF_XDP
maturin develop --release --features "af_xdp"
```

For complete build instructions, see [BUILD_INSTRUCTIONS.md](../docs/BUILD_INSTRUCTIONS.md).

## Usage from Python

```python
from core.native_engine import UltimateEngine, EngineConfig, Protocol

# Create configuration
config = EngineConfig(
    target="192.168.1.1",
    port=80,
    protocol=Protocol.UDP,
    threads=4,
    packet_size=1472,
    rate_limit=100000,  # 100K PPS
)

# Create and use engine
engine = UltimateEngine(config)
engine.start()

import time
time.sleep(10)

stats = engine.stop()
print(f"Sent {stats.packets_sent} packets at {stats.pps:.0f} PPS")
print(f"Bandwidth: {stats.gbps:.2f} Gbps")
```

### Using Context Manager

```python
with UltimateEngine(config) as engine:
    time.sleep(10)
    print(engine.get_stats())
```

### Quick Flood Function

```python
from core.native_engine import quick_flood

stats = quick_flood(
    target="192.168.1.1",
    port=80,
    duration=10,
    protocol="udp",
    rate_limit=50000,
)
print(f"Result: {stats.pps:.0f} PPS")
```

## Backend Selection

The engine automatically selects the best available backend:

1. **DPDK** - Kernel bypass, requires DPDK libraries
2. **AF_XDP** - Linux 4.18+, requires root
3. **io_uring** - Linux 5.1+, async I/O
4. **sendmmsg** - Linux 3.0+, batch syscalls
5. **Raw Socket** - Always available
6. **Python** - Fallback when native unavailable

Check available backends:

```python
from core.native_engine import get_capabilities

caps = get_capabilities()
print(f"Platform: {caps.platform}")
print(f"Native available: {caps.native_available}")
print(f"DPDK: {caps.has_dpdk}")
print(f"AF_XDP: {caps.has_af_xdp}")
print(f"io_uring: {caps.has_io_uring}")
```

## Features

### SIMD Acceleration

- AVX2/SSE2 checksum calculation
- Vectorized memory operations
- 2-4x faster packet building

### Lock-Free Data Structures

- MPMC queues for packet passing
- Atomic statistics counters
- Work-stealing for load balancing

### Precision Rate Limiting

- Token bucket with nanosecond timing
- Configurable burst allowance
- Within 5% of target rate

### Memory Safety

- Rust guarantees no buffer overflows
- Pre-allocated buffer pools
- Zero-copy where possible

### Protocol Builders with Spoofing

```python
# Build packets with IP spoofing
import netstress_engine as ne

# UDP with spoofed source IP from CIDR range
packet = ne.build_udp_packet("192.168.1.1", 80, b"payload", "10.0.0.0/8")

# TCP SYN flood with spoofing
syn_packet = ne.build_tcp_syn("192.168.1.1", 80, "172.16.0.0/12")

# Generate batch of packets
packets = ne.generate_packet_batch("192.168.1.1", 80, "udp", 1400, 1000, "10.0.0.0/8")
```

### Safety Controls

```python
import netstress_engine as ne

# Create safety controller
safety = ne.PySafetyController(max_pps=100000)

# Authorize targets
safety.authorize_ip("192.168.1.1")
safety.authorize_cidr("10.0.0.0/8")
safety.authorize_domain("*.example.com")

# Check authorization
if safety.is_authorized("192.168.1.1"):
    print("Target authorized")

# Emergency stop
safety.emergency_stop("Test complete")
print(f"Stopped: {safety.is_stopped()}")
```

### Real-Time Statistics

```python
import netstress_engine as ne

# Get Prometheus-format metrics
metrics = ne.get_prometheus_metrics()
print(metrics)

# Get JSON metrics
json_stats = ne.get_realtime_stats_json()
print(json_stats)

# Get capability report
report = ne.get_capability_report()
print(f"Platform: {report['platform']}")
print(f"Available backends: {report['available_backends']}")
```

### Tamper-Evident Audit Logging

```python
import netstress_engine as ne

# Create audit logger (with optional file output)
audit = ne.PyAuditLogger.with_file("audit.log")

# Log events
audit.log_engine_start("192.168.1.1", "udp,100kpps")
audit.log_target_authorized("192.168.1.1")
audit.log_emergency_stop("Test complete")

# Verify chain integrity
result = audit.verify_chain()
print(f"Chain valid: {result['valid']}")
print(f"Entries checked: {result['entries_checked']}")

# Export to JSON
json_export = audit.export_json()
```

## Testing

```bash
# Run Rust tests
cd native/rust_engine
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## Troubleshooting

### "Native engine not available"

The Rust engine hasn't been compiled. Run:

```bash
cd native/rust_engine
maturin develop --release
```

### "Permission denied" for raw sockets

Raw sockets require root/admin privileges:

```bash
sudo python your_script.py
```

### Low performance on Linux

Enable kernel optimizations:

```bash
# Increase socket buffer sizes
sudo sysctl -w net.core.rmem_max=268435456
sudo sysctl -w net.core.wmem_max=268435456

# Disable TCP timestamps
sudo sysctl -w net.ipv4.tcp_timestamps=0
```

## License

MIT License - See LICENSE file
