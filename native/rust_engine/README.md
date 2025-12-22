# NetStress Native Engine

High-performance Rust-based packet engine for NetStress network stress testing framework.

## Overview

This is the core engine component of the NetStress "Power Trio" architecture:

- **Python (Brain)**: Configuration, AI/ML, reporting
- **Rust (Engine)**: High-speed packet generation, memory safety
- **C (Metal)**: DPDK, AF_XDP, io_uring, raw sockets

## Features

- Multi-threaded packet generation
- SIMD-accelerated checksum calculation
- Lock-free queues for inter-thread communication
- Nanosecond-precision rate limiting
- Atomic statistics collection
- Cross-platform support (Linux, Windows, macOS)

## Building

### Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- Python 3.8+
- maturin (`pip install maturin`)

### Build Commands

```bash
# Development build
maturin develop

# Release build (optimized)
maturin develop --release

# Build wheel for distribution
maturin build --release
```

## Usage

```python
import netstress_engine

# Get system capabilities
caps = netstress_engine.get_capabilities()
print(f"Platform: {caps['platform']}")

# Create and start engine
engine = netstress_engine.PacketEngine("127.0.0.1", 8080, 4, 1472)
engine.start()

# Get statistics
stats = engine.get_stats()
print(f"PPS: {stats['pps']}")

# Stop engine
engine.stop()
```

## Performance Targets

| Backend    | Target PPS | Platform    |
| ---------- | ---------- | ----------- |
| DPDK       | 100M+      | Linux       |
| AF_XDP     | 10M-50M    | Linux 4.18+ |
| io_uring   | 1M-10M     | Linux 5.1+  |
| sendmmsg   | 500K-2M    | Linux       |
| Raw Socket | 50K-500K   | All         |

## License

MIT License
