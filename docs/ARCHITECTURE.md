# NetStress Architecture

Technical architecture and design documentation.

---

## System Overview

NetStress uses a layered architecture with optional native acceleration:

```
┌─────────────────────────────────────────────────────────────┐
│                      User Interface                          │
│                    (Command Line / API)                      │
├─────────────────────────────────────────────────────────────┤
│                    Attack Orchestrator                       │
│              (Protocol Selection, Threading)                 │
├─────────────────────────────────────────────────────────────┤
│                    Protocol Engines                          │
│         (UDP, TCP, HTTP, DNS, ICMP, Slowloris)              │
├─────────────────────────────────────────────────────────────┤
│                    Backend Layer                             │
│    (Python Sockets / Native Engine / Platform APIs)         │
├─────────────────────────────────────────────────────────────┤
│                    Operating System                          │
│              (Network Stack, Raw Sockets)                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
NetStress/
├── ddos.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── core/                   # Core modules
│   ├── __init__.py
│   ├── ai/                 # AI/ML optimization
│   │   ├── adaptive_strategy.py
│   │   ├── ai_orchestrator.py
│   │   ├── attack_insights.py
│   │   ├── defense_evasion.py
│   │   └── reinforcement_learning.py
│   ├── analytics/          # Statistics and metrics
│   │   ├── metrics_collector.py
│   │   ├── performance_tracker.py
│   │   └── visualization_engine.py
│   ├── attacks/            # Attack implementations
│   │   ├── adaptive.py
│   │   ├── amplification.py
│   │   ├── application.py
│   │   ├── connection.py
│   │   ├── layer4.py
│   │   ├── layer7.py
│   │   └── orchestrator.py
│   ├── capabilities/       # System capability detection
│   │   └── capability_report.py
│   ├── config/             # Configuration management
│   │   └── production_config.py
│   ├── evasion/            # Evasion techniques
│   │   ├── human_behavior.py
│   │   ├── protocol_obfuscation.py
│   │   └── timing_patterns.py
│   ├── health/             # Health monitoring
│   │   └── self_healing.py
│   ├── memory/             # Memory management
│   │   ├── gc_optimizer.py
│   │   ├── lockfree.py
│   │   └── pool_manager.py
│   ├── native_engine.py    # Native engine interface
│   ├── networking/         # Network operations
│   │   ├── buffer_manager.py
│   │   ├── dns_engine.py
│   │   ├── http_engine.py
│   │   ├── socket_factory.py
│   │   ├── tcp_engine.py
│   │   └── udp_engine.py
│   ├── performance/        # Performance optimization
│   │   ├── hardware_acceleration.py
│   │   ├── kernel_optimizations.py
│   │   ├── ultra_engine.py
│   │   └── zero_copy.py
│   ├── platform/           # Platform abstraction
│   │   ├── abstraction.py
│   │   ├── backend_detection.py
│   │   ├── capabilities.py
│   │   └── detection.py
│   ├── protocols/          # Protocol implementations
│   │   ├── real_dns.py
│   │   ├── real_http.py
│   │   ├── real_tcp.py
│   │   ├── real_udp.py
│   │   └── ssl_engine.py
│   ├── recon/              # Reconnaissance
│   │   ├── analyzer.py
│   │   ├── fingerprint.py
│   │   └── scanner.py
│   ├── safety/             # Safety controls
│   │   ├── audit_logging.py
│   │   ├── blocked_targets.txt
│   │   ├── emergency_shutdown.py
│   │   └── protection_mechanisms.py
│   └── target/             # Target analysis
│       ├── profiler.py
│       ├── resolver.py
│       └── vulnerability.py
├── native/                 # Native Rust/C engine
│   └── rust_engine/
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── engine.rs
│       │   ├── packet.rs
│       │   └── ...
│       └── pyproject.toml
├── tests/                  # Test suite
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── property/           # Property-based tests
├── docs/                   # Documentation
├── scripts/                # Utility scripts
│   ├── install_native.py
│   └── ...
└── examples/               # Usage examples
```

---

## Component Details

### Main Entry Point (ddos.py)

The main entry point handles:

- Command-line argument parsing
- System capability detection
- Protocol selection
- Worker thread management
- Statistics collection and reporting

```python
# Simplified flow
def main():
    args = parse_arguments()
    capabilities = detect_capabilities()
    engine = select_engine(args, capabilities)
    workers = spawn_workers(engine, args.threads)
    run_attack(workers, args.duration)
    report_statistics()
```

### Attack Orchestrator

Coordinates attack execution:

- Selects appropriate protocol engine
- Manages worker threads/processes
- Handles rate limiting
- Collects statistics

### Protocol Engines

Each protocol has a dedicated engine:

| Engine  | File                           | Description             |
| ------- | ------------------------------ | ----------------------- |
| UDP     | `core/protocols/real_udp.py`   | UDP packet generation   |
| TCP     | `core/protocols/real_tcp.py`   | TCP connection handling |
| HTTP    | `core/protocols/real_http.py`  | HTTP request generation |
| DNS     | `core/protocols/real_dns.py`   | DNS query generation    |
| SSL/TLS | `core/protocols/ssl_engine.py` | TLS handshake handling  |

### Backend Layer

Abstracts platform-specific networking:

```
┌─────────────────────────────────────────────────────────────┐
│                    Backend Selector                          │
├─────────────────────────────────────────────────────────────┤
│  Native Engine  │  Platform APIs  │  Python Sockets         │
│  (Rust/C)       │  (sendmmsg,     │  (socket.socket)        │
│                 │   io_uring,     │                         │
│                 │   IOCP, kqueue) │                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Packet Generation Flow

```
1. User Input
   └── Arguments parsed (target, port, protocol, duration)

2. Initialization
   ├── Resolve target hostname
   ├── Detect system capabilities
   └── Select optimal backend

3. Worker Spawning
   ├── Create worker threads/processes
   ├── Initialize sockets per worker
   └── Pre-allocate packet buffers

4. Packet Generation Loop
   ├── Generate packet payload
   ├── Send packet via backend
   ├── Update statistics
   └── Check rate limit

5. Completion
   ├── Stop workers
   ├── Aggregate statistics
   └── Report results
```

### Statistics Flow

```
Worker 1 ──┐
Worker 2 ──┼──> Statistics Aggregator ──> Reporter
Worker 3 ──┤
Worker N ──┘
```

---

## Threading Model

### Python Threading

```
Main Thread
├── Worker Thread 1 (socket 1)
├── Worker Thread 2 (socket 2)
├── Worker Thread 3 (socket 3)
└── Worker Thread N (socket N)
```

Each worker thread:

- Has its own socket
- Generates packets independently
- Updates shared statistics atomically

### Native Engine Threading

The native Rust engine uses:

- Tokio async runtime
- Lock-free data structures
- CPU affinity for workers

---

## Memory Management

### Buffer Pool

Pre-allocated buffers reduce allocation overhead:

```python
class PacketBuffer:
    def __init__(self, count, size):
        self.buffers = [bytearray(size) for _ in range(count)]
        self.free_indices = list(range(count))

    def acquire(self):
        # Get buffer from pool

    def release(self, idx):
        # Return buffer to pool
```

### Zero-Copy

On supported platforms:

- Linux: `MSG_ZEROCOPY` socket option
- Uses `sendfile()` where applicable
- Avoids kernel-userspace copies

---

## Platform Abstraction

### Backend Detection

```python
def detect_backend():
    if platform == "Linux":
        if has_dpdk():
            return "dpdk"
        if has_af_xdp():
            return "af_xdp"
        if has_io_uring():
            return "io_uring"
        if has_sendmmsg():
            return "sendmmsg"
    elif platform == "Windows":
        if has_rio():
            return "registered_io"
        return "iocp"
    elif platform == "Darwin":
        return "kqueue"
    return "python"
```

### Platform-Specific Optimizations

| Platform | Optimization | Description                        |
| -------- | ------------ | ---------------------------------- |
| Linux    | sendmmsg     | Batch multiple packets per syscall |
| Linux    | io_uring     | Async I/O with submission queue    |
| Linux    | AF_XDP       | Zero-copy packet processing        |
| Windows  | IOCP         | Async I/O completion ports         |
| Windows  | RIO          | Pre-registered buffers             |
| macOS    | kqueue       | Event notification                 |

---

## Native Engine Architecture

### Sandwich Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Python Layer                              │
│              (Configuration, Control, Reporting)             │
├─────────────────────────────────────────────────────────────┤
│                    Rust Engine                               │
│         (Packet Generation, Threading, Memory Safety)        │
├─────────────────────────────────────────────────────────────┤
│                    C/System Layer                            │
│              (DPDK, AF_XDP, io_uring, Raw Sockets)          │
└─────────────────────────────────────────────────────────────┘
```

### Rust Engine Components

| Component    | Description            |
| ------------ | ---------------------- |
| `engine.rs`  | Main engine logic      |
| `packet.rs`  | Packet generation      |
| `backend.rs` | Backend abstraction    |
| `stats.rs`   | Statistics collection  |
| `pool.rs`    | Memory pool management |

---

## AI/ML Integration

### Attack Optimization

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Orchestrator                           │
├─────────────────────────────────────────────────────────────┤
│  Adaptive Strategy  │  Defense Detection  │  Insights       │
│  Engine             │  AI                 │  Generator      │
├─────────────────────────────────────────────────────────────┤
│                    Attack Engine                             │
└─────────────────────────────────────────────────────────────┘
```

### Feedback Loop

```
Attack ──> Target Response ──> Analysis ──> Parameter Adjustment ──> Attack
```

---

## Safety Systems

### Protection Layers

1. **Target Validation**: Checks against blocked targets
2. **Rate Limiting**: Prevents resource exhaustion
3. **Audit Logging**: Records all operations
4. **Emergency Stop**: Ctrl+C handler

### Blocked Targets

```
# core/safety/blocked_targets.txt
# Critical infrastructure that should never be tested
localhost
127.0.0.1
*.gov
*.mil
```

---

## Error Handling

### Error Categories

| Category          | Handling           |
| ----------------- | ------------------ |
| Network errors    | Retry with backoff |
| Permission errors | Report and exit    |
| Resource errors   | Reduce load        |
| Fatal errors      | Clean shutdown     |

### Graceful Shutdown

```python
def signal_handler(signum, frame):
    logger.info("Shutdown requested")
    stop_all_workers()
    report_final_statistics()
    cleanup_resources()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
```

---

## Testing Architecture

### Test Categories

| Category    | Location             | Description                 |
| ----------- | -------------------- | --------------------------- |
| Unit        | `tests/unit/`        | Individual component tests  |
| Integration | `tests/integration/` | Component interaction tests |
| Property    | `tests/property/`    | Property-based tests        |

### Test Execution

```bash
# Run all tests
pytest tests/

# Run specific category
pytest tests/unit/
pytest tests/integration/
pytest tests/property/

# Run with coverage
pytest --cov=core tests/
```

---

## See Also

- [CAPABILITIES.md](CAPABILITIES.md) - Feature capabilities
- [PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md) - Optimization guide
- [API_REFERENCE.md](API_REFERENCE.md) - API documentation
