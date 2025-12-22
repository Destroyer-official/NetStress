# Power Trio Integration Tests

This document describes the comprehensive integration tests for the NetStress "Power Trio" architecture that tests the full Python → Rust → C flow.

## Architecture Overview

The Power Trio uses a "Sandwich" architecture:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PYTHON LAYER (Brain)                                 │
│  ddos.py │ main.py │ CLI │ AI/ML │ Analytics │ Configuration │ Reporting   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         RUST LAYER (Engine)                                  │
│  netstress_engine (PyO3) │ Packet Gen │ Threading │ Lock-Free Queues        │
├─────────────────────────────────────────────────────────────────────────────┤
│                         C LAYER (Metal)                                      │
│  driver_shim.c │ DPDK │ AF_XDP │ io_uring │ sendmmsg │ Raw Sockets          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Test Coverage

### Core Integration Tests (`TestPowerTrioIntegration`)

1. **Python → Rust → C Flow Basic** - Tests the complete integration flow
2. **Rust Module Direct Access** - Tests direct Rust module functionality
3. **C Driver Integration** - Tests C driver integration through Rust
4. **Protocol Support** - Tests UDP, TCP, ICMP, HTTP through full stack
5. **Backend Fallback Chain** - Tests DPDK → AF_XDP → io_uring → sendmmsg → raw_socket
6. **Statistics Accuracy** - Tests statistics accuracy across all layers
7. **Memory Safety** - Tests memory safety across FFI boundaries
8. **Concurrent Engines** - Tests resource isolation between engines
9. **Error Propagation** - Tests error propagation from C → Rust → Python
10. **Platform Optimizations** - Tests platform-specific optimizations
11. **Rate Limiting** - Tests rate limiting enforcement across layers

### Property-Based Tests (`TestPowerTrioPropertyBased`)

Tests various combinations of:

- Target configurations (IP addresses, ports)
- Thread counts (1, 2, 4)
- Rate limits (100, 1000, 10000, unlimited)
- Protocols (UDP, TCP, ICMP, HTTP)
- Backends (auto, python, native)
- Packet sizes (64, 512, 1024, 1472 bytes)

### Stress Tests (`TestPowerTrioStressTests`)

1. **Long Running Engine** - Tests extended operation (1+ seconds)
2. **Rapid Start/Stop Cycles** - Tests memory safety with rapid cycles
3. **High Thread Count** - Tests coordination with many threads
4. **Memory Pressure** - Tests handling of memory pressure
5. **Concurrent Protocols** - Tests multiple protocols simultaneously

### Error Handling Tests (`TestPowerTrioErrorHandling`)

1. **Rust Error Propagation** - Tests error propagation from Rust to Python
2. **C Driver Error Handling** - Tests C driver error handling through Rust
3. **FFI Boundary Errors** - Tests error handling at FFI boundaries
4. **Resource Cleanup** - Tests proper cleanup on errors

### Performance Tests (`TestPowerTrioPerformance`)

1. **Native vs Python Comparison** - Compares backend performance
2. **Throughput Scaling** - Tests scaling with thread count
3. **Memory Usage Stability** - Tests for memory leaks
4. **Latency Consistency** - Tests start/stop latency requirements

### Compliance Tests (`TestPowerTrioCompliance`)

Tests compliance with specific requirements:

1. **Requirement 1** - Rust Engine Core (start within 10ms, SIMD, memory pools)
2. **Requirement 3** - Python-Rust Integration (PyO3, zero-copy, exceptions)
3. **Requirement 5** - Backend Selection and Fallback
4. **Requirement 6** - Real-Time Statistics (100ms updates, atomic counters)
5. **Requirement 9** - Safety and Compliance (authorization, emergency stop)
6. **Requirement 10** - Cross-Platform Support

### Documentation Tests (`TestPowerTrioDocumentation`)

1. **Design Document Examples** - Tests examples from design document work
2. **API Consistency** - Tests API matches specification

## Test Modes

### Full Integration Mode

When all components are available:

- `INTEGRATION_AVAILABLE = True`
- `NATIVE_ENGINE_AVAILABLE = True`
- `RUST_MODULE_AVAILABLE = True`

Tests the complete Python → Rust → C flow with all backends.

### Limited Integration Mode

When only Python components are available:

- `INTEGRATION_AVAILABLE = True`
- `NATIVE_ENGINE_AVAILABLE = False`
- `RUST_MODULE_AVAILABLE = False`

Tests Python layer with fallback engine.

### Mock Mode

When no components are available:

- `INTEGRATION_AVAILABLE = False`

Uses mock objects for basic test structure validation.

## Running Tests

### Prerequisites

1. **Python Layer**: Always available
2. **Rust Layer**: Requires building the Rust engine:
   ```bash
   cd native/rust_engine
   maturin develop --release
   ```
3. **C Layer**: Requires C driver compilation:
   ```bash
   cd native/c_driver
   make
   ```

### Test Execution

```bash
# Run all integration tests
python -m pytest tests/test_integration_power_trio.py -v

# Run specific test class
python -m pytest tests/test_integration_power_trio.py::TestPowerTrioIntegration -v

# Run with coverage
python -m pytest tests/test_integration_power_trio.py --cov=core.native_engine

# Check test runner status
python test_integration_runner.py
```

### Test Configuration

Tests use safe defaults:

- Target: `127.0.0.1` (localhost only)
- Duration: `0.1` seconds (very brief)
- Packet size: `64` bytes (small)
- Rate limits: Low values to avoid overwhelming system

## Expected Results

### Full Integration Mode

- All 100+ tests should pass
- Performance tests should show native > Python performance
- All backends should be detected and tested
- Memory safety tests should pass without leaks

### Limited Integration Mode

- ~70% of tests should pass (Python-only functionality)
- Backend tests will be skipped
- Performance comparisons will be limited
- Basic functionality should work

### Common Issues

1. **Permission Errors**: Raw sockets may require administrator privileges
2. **Port Conflicts**: Tests use port 9999, ensure it's available
3. **Firewall Blocking**: Local firewall may block test traffic
4. **Resource Limits**: High thread count tests may hit OS limits

## Integration Points Tested

### Python ↔ Rust (PyO3)

- Module loading and initialization
- Data type conversion (Python dict ↔ Rust struct)
- Error propagation and exception handling
- Memory management across FFI boundary
- Zero-copy data transfer with PyBytes

### Rust ↔ C (FFI)

- Function call overhead and safety
- Data structure marshaling
- Error code propagation
- Resource management and cleanup
- Backend detection and selection

### End-to-End Flow

- Configuration: Python → Rust → C
- Packet Generation: C → Rust → Python (stats)
- Error Handling: C → Rust → Python (exceptions)
- Resource Cleanup: Python → Rust → C

## Performance Validation

Tests validate the performance targets from the design:

| Backend     | Target PPS | Target Bandwidth | Latency |
| ----------- | ---------- | ---------------- | ------- |
| DPDK        | 100M+      | 100+ Gbps        | < 1μs   |
| AF_XDP      | 10M-50M    | 40-100 Gbps      | < 10μs  |
| io_uring    | 1M-10M     | 10-40 Gbps       | < 100μs |
| sendmmsg    | 500K-2M    | 5-20 Gbps        | < 1ms   |
| Raw Socket  | 50K-500K   | 1-5 Gbps         | < 10ms  |
| Pure Python | 10K-50K    | 0.1-0.5 Gbps     | > 10ms  |

## Safety Validation

Tests ensure safety controls work across all layers:

- Target authorization cannot be bypassed
- Rate limiting is enforced in Rust (not Python)
- Emergency stop works within 100ms
- Memory safety is maintained across FFI
- Resource cleanup prevents leaks

## Maintenance

### Adding New Tests

1. Follow the existing test class structure
2. Use descriptive test names that explain what's being tested
3. Include proper skip conditions for unavailable components
4. Add both positive and negative test cases
5. Update this documentation

### Debugging Test Failures

1. Check component availability flags
2. Verify system permissions (raw sockets need admin)
3. Check for port conflicts
4. Review error messages for FFI boundary issues
5. Use test runner for component-by-component diagnosis

This comprehensive test suite ensures the Power Trio architecture works correctly across all layers and provides confidence in the integration between Python, Rust, and C components.
