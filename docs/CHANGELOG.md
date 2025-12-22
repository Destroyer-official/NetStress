# Changelog

All notable changes to NetStress will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2024-12-18

### 🧹 Production-Ready Cleanup

This release focuses on project organization and production readiness.

### Added

- Organized test structure (unit/, integration/, property/ folders)
- Shared pytest configuration (conftest.py)
- Archive manifest for moved files
- Updated documentation with accurate feature status

### Changed

- Moved all root-level test files to NetStress/archive/old_tests/
- Moved benchmark files to NetStress/benchmarks/
- Moved checkpoint reports to NetStress/docs/reports/
- Consolidated duplicate models/ and audit_logs/ directories
- Updated README with realistic performance expectations
- Updated CAPABILITIES.md with honest feature assessment

### Removed

- Cleaned up root directory (removed $null, empty folders)
- Removed duplicate files across directories

---

## [2.0.0] - 2024-12-17

### 🎯 Military-Grade Transformation

This release represents a complete transformation to 100% genuine military-grade implementation with true cross-platform support and adaptive performance scaling.

### Added

#### Cross-Platform Backend Support

- **Windows RIO (Registered I/O)**: True zero-copy networking for Windows Server 2016+
- **macOS Network.framework**: Modern userspace networking for Apple Silicon
- **Linux AF_XDP**: Zero-copy packet I/O with kernel 4.18+ support
- **Automatic Fallback Chains**: Graceful degradation on all platforms

#### Adaptive Hardware Detection

- Automatic CPU detection (cores, threads, architecture, SIMD features)
- Memory detection (RAM size, speed, NUMA topology)
- Network detection (NIC speed, capabilities, bonding)
- GPU detection (CUDA/OpenCL availability)
- Device tier classification (Low/Medium/High/Enterprise)

#### Advanced Evasion Capabilities

- **JA4 Fingerprint Spoofing**: Bypass modern WAFs (Cloudflare, Akamai, AWS Shield)
- **DoH Tunneling**: RFC 8484 compliant DNS-over-HTTPS encapsulation
- **Protocol Morphing**: HTTP/2, HTTP/3, WebSocket, DNS frame generation
- **Traffic Shaping**: Human-like timing patterns

#### Distributed Coordination

- **P2P Kademlia DHT**: Decentralized peer discovery
- **NTP Synchronization**: Sub-50ms attack timing across nodes
- **Mesh Networking**: No single point of failure

#### Property-Based Testing

- 13 correctness properties verified with Hypothesis
- Backend fallback chain integrity tests
- Hardware detection completeness tests
- Protocol compliance tests

### Changed

- Removed all fake/simulated code
- Renamed "quantum_optimizer" to "genetic_optimizer" (honest terminology)
- Updated FPGA code to report "Not Available" when no hardware present
- Improved error handling and logging throughout

### Removed

- Fake FPGA simulation code
- "Quantum" marketing terminology
- Placeholder RDMA code
- Simulated hardware messages

### Fixed

- Backend selection now correctly follows priority order
- Hardware detection works correctly on all platforms
- Property tests now pass consistently
- Memory leaks in packet generation fixed

## [1.5.0] - 2024-11-01

### Added

- Initial Rust engine integration
- Basic cross-platform support
- GUI interface

### Changed

- Improved performance on Linux
- Better error messages

## [1.0.0] - 2024-09-01

### Added

- Initial release
- Basic UDP/TCP flood capabilities
- Command-line interface
- Python-only implementation

---

## Migration Guide

### From 1.x to 2.0

#### Breaking Changes

1. **Configuration Format**

   ```python
   # Old (1.x)
   engine = Engine(target="127.0.0.1", threads=4)

   # New (2.0)
   engine = UltimateEngine(target="127.0.0.1")  # Threads auto-detected
   ```

2. **Backend Selection**

   ```python
   # Old (1.x)
   engine = Engine(backend="raw_socket")

   # New (2.0)
   engine = UltimateEngine(native=True)  # Auto-selects best backend
   ```

3. **Statistics**

   ```python
   # Old (1.x)
   stats = engine.stats
   print(stats['pps'])

   # New (2.0)
   stats = engine.get_stats()
   print(stats.pps)  # Now a dataclass
   ```

#### New Features to Adopt

1. **Adaptive Scaling**: Let the system auto-detect optimal settings
2. **JA4 Spoofing**: Enable for WAF bypass
3. **DoH Tunneling**: Use for covert traffic
4. **P2P Mode**: Enable for distributed testing

---

## Version History

| Version | Date       | Highlights                    |
| ------- | ---------- | ----------------------------- |
| 3.0.0   | 2024-12-18 | Production-ready cleanup      |
| 2.0.0   | 2024-12-17 | Military-grade transformation |
| 1.5.0   | 2024-11-01 | Rust engine, GUI              |
| 1.0.0   | 2024-09-01 | Initial release               |
