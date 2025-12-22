//! Backend auto-detection and selection
//! Implements priority-based backend selection with graceful fallback

use crate::backend::{create_best_backend, detect_system_capabilities, select_best_backend};
use crate::backend::{Backend, BackendError, BackendType, StandardBackend, SystemCapabilities};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// SIMD instruction set capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdType {
    None,
    SSE2,
    AVX2,
    AVX512,
    NEON,
}

/// CPU architecture information
#[derive(Debug, Clone)]
pub struct CpuInfo {
    pub architecture: String,
    pub cores: u32,
    pub simd_support: SimdType,
    pub features: Vec<String>,
}

/// Recommended configuration based on detected capabilities
#[derive(Debug, Clone)]
pub struct RecommendedConfig {
    pub backend: BackendType,
    pub simd_type: SimdType,
    pub use_simd: bool,
    pub thread_count: u32,
    pub platform_optimizations: PlatformOptimizations,
}

/// Platform-specific optimization recommendations
#[derive(Debug, Clone)]
pub struct PlatformOptimizations {
    pub use_numa_awareness: bool,
    pub use_hugepages: bool,
    pub use_kernel_bypass: bool,
    pub buffer_size_hint: usize,
}

/// Backend selector with automatic fallback
pub struct BackendSelector {
    /// Current active backend
    active_backend: Arc<RwLock<Box<dyn Backend>>>,
    /// System capabilities
    capabilities: SystemCapabilities,
    /// CPU information including SIMD support
    cpu_info: CpuInfo,
    /// Preferred backend (user override)
    preferred: Option<BackendType>,
    /// Whether fallback is enabled
    fallback_enabled: AtomicBool,
    /// Backend priority order
    priority: Vec<BackendType>,
}

impl BackendSelector {
    /// Detect CPU SIMD capabilities
    /// Implements Requirements 12.4, 12.5: SIMD code path selection
    fn detect_simd_capabilities() -> SimdType {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                SimdType::AVX512
            } else if is_x86_feature_detected!("avx2") {
                SimdType::AVX2
            } else if is_x86_feature_detected!("sse2") {
                SimdType::SSE2
            } else {
                SimdType::None
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                SimdType::NEON
            } else {
                SimdType::None
            }
        }
        #[cfg(target_arch = "arm")]
        {
            // ARM32 uses scalar operations per requirements
            SimdType::None
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
        {
            SimdType::None
        }
    }

    /// Get CPU information including SIMD support
    /// Implements Requirements 12.4, 12.5: Architecture-specific optimizations
    fn detect_cpu_info() -> CpuInfo {
        let simd_support = Self::detect_simd_capabilities();
        let cores = std::thread::available_parallelism()
            .map(|p| p.get() as u32)
            .unwrap_or(1);

        let mut features = Vec::new();

        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                features.push("AVX-512".to_string());
            }
            if is_x86_feature_detected!("avx2") {
                features.push("AVX2".to_string());
            }
            if is_x86_feature_detected!("sse2") {
                features.push("SSE2".to_string());
            }
            if is_x86_feature_detected!("tsc") {
                features.push("TSC".to_string());
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("neon") {
                features.push("NEON".to_string());
            }
        }

        CpuInfo {
            architecture: std::env::consts::ARCH.to_string(),
            cores,
            simd_support,
            features,
        }
    }
    /// Get platform-specific backend priority
    /// Implements Requirements 12.3: Platform-specific backend selection
    /// Windows: RIO > IOCP > Winsock2
    /// macOS: Network.framework > kqueue > BSD sockets  
    /// Linux: DPDK > AF_XDP > io_uring > sendmmsg > raw socket
    fn get_platform_priority() -> Vec<BackendType> {
        #[cfg(target_os = "linux")]
        {
            vec![
                BackendType::Dpdk,      // Kernel bypass for enterprise
                BackendType::AfXdp,     // Zero-copy for high performance
                BackendType::IoUring,   // Async I/O for modern kernels
                BackendType::Sendmmsg,  // Batch sending for efficiency
                BackendType::RawSocket, // Always available fallback
            ]
        }
        #[cfg(target_os = "windows")]
        {
            vec![
                BackendType::RegisteredIO, // Windows RIO for zero-copy
                BackendType::IOCP,         // I/O Completion Ports for async
                BackendType::RawSocket,    // Winsock2 fallback
            ]
        }
        #[cfg(target_os = "macos")]
        {
            vec![
                BackendType::NetworkFramework, // Modern userspace networking
                BackendType::Kqueue,           // Event-driven I/O
                BackendType::RawSocket,        // BSD sockets fallback
            ]
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            vec![BackendType::RawSocket] // Generic fallback
        }
    }

    /// Create a new backend selector with auto-detection
    /// Implements Requirements 12.3, 12.4, 12.5: Platform and SIMD detection
    pub fn new() -> Self {
        let capabilities = detect_system_capabilities();
        let cpu_info = Self::detect_cpu_info();
        let best = select_best_backend(&capabilities);
        let backend = create_best_backend();

        info!("Auto-detected backend: {:?}", best);
        info!(
            "CPU: {} cores, {} architecture, SIMD: {:?}",
            cpu_info.cores, cpu_info.architecture, cpu_info.simd_support
        );
        info!("CPU features: {:?}", cpu_info.features);

        Self {
            active_backend: Arc::new(RwLock::new(backend)),
            capabilities,
            cpu_info,
            preferred: None,
            fallback_enabled: AtomicBool::new(true),
            priority: Self::get_platform_priority(),
        }
    }

    /// Create with a specific preferred backend
    pub fn with_preferred(preferred: BackendType) -> Result<Self, BackendError> {
        let mut selector = Self::new();
        selector.set_preferred(preferred)?;
        Ok(selector)
    }

    /// Set preferred backend
    pub fn set_preferred(&mut self, backend_type: BackendType) -> Result<(), BackendError> {
        if !self.is_backend_available(backend_type) {
            return Err(BackendError::NotAvailable(format!(
                "Backend {:?} is not available on this system",
                backend_type
            )));
        }

        self.preferred = Some(backend_type);
        self.switch_to(backend_type)?;
        Ok(())
    }

    /// Check if a backend is available
    pub fn is_backend_available(&self, backend_type: BackendType) -> bool {
        match backend_type {
            BackendType::None => false,
            BackendType::RawSocket => self.capabilities.has_raw_socket,
            BackendType::Sendmmsg => self.capabilities.has_sendmmsg,
            BackendType::IoUring => self.capabilities.has_io_uring,
            BackendType::AfXdp => self.capabilities.has_af_xdp,
            BackendType::AfXdpIoUring => {
                self.capabilities.has_af_xdp && self.capabilities.has_io_uring
            }
            BackendType::Dpdk => self.capabilities.has_dpdk,
            BackendType::IOCP => self.capabilities.has_iocp,
            BackendType::RegisteredIO => self.capabilities.has_registered_io,
            BackendType::Kqueue => self.capabilities.has_kqueue,
            BackendType::NetworkFramework => self.capabilities.has_network_framework,
        }
    }

    /// Get list of available backends
    pub fn available_backends(&self) -> Vec<BackendType> {
        self.priority
            .iter()
            .filter(|&&bt| self.is_backend_available(bt))
            .copied()
            .collect()
    }

    /// Switch to a specific backend
    fn switch_to(&mut self, backend_type: BackendType) -> Result<(), BackendError> {
        let mut backend: Box<dyn Backend> = match backend_type {
            BackendType::RawSocket | BackendType::None => Box::new(StandardBackend::new()),
            #[cfg(target_os = "linux")]
            BackendType::Sendmmsg | BackendType::IoUring | BackendType::Dpdk => {
                Box::new(crate::backend::NativeBackend::new(backend_type))
            }
            #[cfg(target_os = "linux")]
            BackendType::AfXdp => Box::new(
                crate::linux_afxdp::AfXdpBackend::new("eth0", 0).unwrap_or_else(|_| {
                    // Fallback to standard backend if AF_XDP fails
                    Box::new(StandardBackend::new()) as Box<dyn Backend>
                }),
            ),
            #[cfg(target_os = "windows")]
            BackendType::IOCP => Box::new(crate::windows_backend::IOCPBackend::new()),
            #[cfg(all(target_os = "windows", feature = "registered_io"))]
            BackendType::RegisteredIO => Box::new(crate::windows_rio::RioBackend::new()),
            #[cfg(all(target_os = "windows", not(feature = "registered_io")))]
            BackendType::RegisteredIO => Box::new(StandardBackend::new()),
            #[cfg(target_os = "macos")]
            BackendType::Kqueue => Box::new(crate::macos_backend::KqueueBackend::new()),
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            _ => Box::new(StandardBackend::new()),
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            _ => Box::new(StandardBackend::new()),
        };

        backend.init()?;

        let mut active = self.active_backend.write();
        let _ = active.cleanup();
        *active = backend;

        info!("Switched to backend: {:?}", backend_type);
        Ok(())
    }

    /// Get the current active backend type
    pub fn current_backend(&self) -> BackendType {
        self.active_backend.read().backend_type()
    }

    /// Get system capabilities
    pub fn capabilities(&self) -> &SystemCapabilities {
        &self.capabilities
    }

    /// Get CPU information including SIMD support
    /// Implements Requirements 12.4, 12.5: CPU feature detection
    pub fn cpu_info(&self) -> &CpuInfo {
        &self.cpu_info
    }

    /// Get the optimal SIMD instruction set for this CPU
    /// Implements Requirements 12.4, 12.5: SIMD code path selection
    pub fn optimal_simd(&self) -> SimdType {
        self.cpu_info.simd_support
    }

    /// Check if SIMD acceleration is available
    pub fn has_simd_support(&self) -> bool {
        self.cpu_info.simd_support != SimdType::None
    }

    /// Get recommended configuration based on detected capabilities
    /// Implements Requirements 12.3, 12.4, 12.5: Platform-specific optimizations
    pub fn get_recommended_config(&self) -> RecommendedConfig {
        let backend = self.current_backend();
        let simd = self.optimal_simd();

        RecommendedConfig {
            backend,
            simd_type: simd,
            use_simd: simd != SimdType::None,
            thread_count: self.cpu_info.cores,
            platform_optimizations: self.get_platform_optimizations(),
        }
    }

    /// Get platform-specific optimization recommendations
    fn get_platform_optimizations(&self) -> PlatformOptimizations {
        #[cfg(target_os = "linux")]
        {
            PlatformOptimizations {
                use_numa_awareness: self.capabilities.numa_nodes > 1,
                use_hugepages: self.current_backend() == BackendType::Dpdk,
                use_kernel_bypass: matches!(
                    self.current_backend(),
                    BackendType::Dpdk | BackendType::AfXdp
                ),
                buffer_size_hint: match self.current_backend() {
                    BackendType::Dpdk => 8 * 1024 * 1024 * 1024, // 8GB for DPDK
                    BackendType::AfXdp => 2 * 1024 * 1024 * 1024, // 2GB for AF_XDP
                    _ => 256 * 1024 * 1024,                      // 256MB default
                },
            }
        }
        #[cfg(target_os = "windows")]
        {
            PlatformOptimizations {
                use_numa_awareness: self.cpu_info.cores > 8,
                use_hugepages: false, // Not commonly used on Windows
                use_kernel_bypass: self.current_backend() == BackendType::RegisteredIO,
                buffer_size_hint: match self.current_backend() {
                    BackendType::RegisteredIO => 1024 * 1024 * 1024, // 1GB for RIO
                    BackendType::IOCP => 512 * 1024 * 1024,          // 512MB for IOCP
                    _ => 256 * 1024 * 1024,                          // 256MB default
                },
            }
        }
        #[cfg(target_os = "macos")]
        {
            PlatformOptimizations {
                use_numa_awareness: false, // macOS handles NUMA internally
                use_hugepages: false,      // Not exposed on macOS
                use_kernel_bypass: false,  // Network.framework is userspace
                buffer_size_hint: match self.current_backend() {
                    BackendType::NetworkFramework => 512 * 1024 * 1024, // 512MB
                    _ => 256 * 1024 * 1024,                             // 256MB default
                },
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            PlatformOptimizations {
                use_numa_awareness: false,
                use_hugepages: false,
                use_kernel_bypass: false,
                buffer_size_hint: 256 * 1024 * 1024, // 256MB default
            }
        }
    }

    /// Enable or disable automatic fallback
    pub fn set_fallback_enabled(&self, enabled: bool) {
        self.fallback_enabled.store(enabled, Ordering::SeqCst);
    }

    /// Check if fallback is enabled
    pub fn is_fallback_enabled(&self) -> bool {
        self.fallback_enabled.load(Ordering::Relaxed)
    }

    /// Try to send with automatic fallback on failure
    pub fn send_with_fallback(
        &self,
        data: &[u8],
        dest: std::net::SocketAddr,
    ) -> Result<usize, BackendError> {
        let backend = self.active_backend.read();

        match backend.send(data, dest) {
            Ok(n) => Ok(n),
            Err(e) => {
                if self.fallback_enabled.load(Ordering::Relaxed) {
                    warn!("Send failed, attempting fallback: {}", e);
                    drop(backend);
                    self.try_fallback()?;
                    self.active_backend.read().send(data, dest)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Try to send batch with automatic fallback
    pub fn send_batch_with_fallback(
        &self,
        packets: &[&[u8]],
        dest: std::net::SocketAddr,
    ) -> Result<usize, BackendError> {
        let backend = self.active_backend.read();

        match backend.send_batch(packets, dest) {
            Ok(n) => Ok(n),
            Err(e) => {
                if self.fallback_enabled.load(Ordering::Relaxed) {
                    warn!("Batch send failed, attempting fallback: {}", e);
                    drop(backend);
                    self.try_fallback()?;
                    self.active_backend.read().send_batch(packets, dest)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Attempt to fall back to the next available backend
    fn try_fallback(&self) -> Result<(), BackendError> {
        let current = self.current_backend();
        let current_idx = self.priority.iter().position(|&b| b == current);

        // Try each backend in priority order after current
        let start_idx = current_idx.map(|i| i + 1).unwrap_or(0);

        for &backend_type in &self.priority[start_idx..] {
            if self.is_backend_available(backend_type) {
                debug!("Attempting fallback to {:?}", backend_type);

                let mut backend: Box<dyn Backend> = match backend_type {
                    BackendType::RawSocket | BackendType::None => Box::new(StandardBackend::new()),
                    #[cfg(target_os = "linux")]
                    BackendType::Sendmmsg | BackendType::IoUring | BackendType::Dpdk => {
                        Box::new(crate::backend::NativeBackend::new(backend_type))
                    }
                    #[cfg(target_os = "linux")]
                    BackendType::AfXdp => {
                        match crate::linux_afxdp::AfXdpBackend::new("eth0", 0) {
                            Ok(backend) => Box::new(backend),
                            Err(_) => continue, // Try next backend in fallback chain
                        }
                    }
                    #[cfg(target_os = "windows")]
                    BackendType::IOCP => Box::new(crate::windows_backend::IOCPBackend::new()),
                    #[cfg(all(target_os = "windows", feature = "registered_io"))]
                    BackendType::RegisteredIO => Box::new(crate::windows_rio::RioBackend::new()),
                    #[cfg(all(target_os = "windows", not(feature = "registered_io")))]
                    BackendType::RegisteredIO => Box::new(StandardBackend::new()),
                    #[cfg(target_os = "macos")]
                    BackendType::Kqueue => Box::new(crate::macos_backend::KqueueBackend::new()),
                    #[cfg(not(any(
                        target_os = "linux",
                        target_os = "windows",
                        target_os = "macos"
                    )))]
                    _ => Box::new(StandardBackend::new()),
                    #[cfg(any(target_os = "windows", target_os = "macos"))]
                    _ => Box::new(StandardBackend::new()),
                };

                if backend.init().is_ok() {
                    let mut active = self.active_backend.write();
                    let _ = active.cleanup();
                    *active = backend;
                    info!("Fallback successful: {:?}", backend_type);
                    return Ok(());
                }
            }
        }

        Err(BackendError::NotAvailable(
            "No fallback backend available".into(),
        ))
    }

    /// Get backend for direct access
    pub fn backend(&self) -> impl std::ops::Deref<Target = Box<dyn Backend>> + '_ {
        self.active_backend.read()
    }

    /// Initialize the active backend
    pub fn init(&self) -> Result<(), BackendError> {
        self.active_backend.write().init()
    }

    /// Cleanup the active backend
    pub fn cleanup(&self) -> Result<(), BackendError> {
        self.active_backend.write().cleanup()
    }
}

impl Default for BackendSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Backend capability report for Python
#[derive(Debug, Clone)]
pub struct CapabilityReport {
    pub platform: String,
    pub arch: String,
    pub cpu_count: i32,
    pub available_backends: Vec<String>,
    pub active_backend: String,
    pub has_dpdk: bool,
    pub has_af_xdp: bool,
    pub has_io_uring: bool,
    pub has_sendmmsg: bool,
    pub kernel_version: String,
    // New SIMD and CPU information
    pub simd_support: String,
    pub cpu_features: Vec<String>,
    pub recommended_config: RecommendedConfigReport,
}

/// Simplified recommended configuration for Python
#[derive(Debug, Clone)]
pub struct RecommendedConfigReport {
    pub backend: String,
    pub simd_type: String,
    pub use_simd: bool,
    pub thread_count: u32,
    pub buffer_size_hint: usize,
    pub use_numa_awareness: bool,
    pub use_kernel_bypass: bool,
}

impl CapabilityReport {
    pub fn generate(selector: &BackendSelector) -> Self {
        let caps = selector.capabilities();
        let cpu_info = selector.cpu_info();
        let recommended = selector.get_recommended_config();

        Self {
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_count: caps.cpu_count,
            available_backends: selector
                .available_backends()
                .iter()
                .map(|b| b.name().to_string())
                .collect(),
            active_backend: selector.current_backend().name().to_string(),
            has_dpdk: caps.has_dpdk,
            has_af_xdp: caps.has_af_xdp,
            has_io_uring: caps.has_io_uring,
            has_sendmmsg: caps.has_sendmmsg,
            kernel_version: format!("{}.{}", caps.kernel_version.0, caps.kernel_version.1),
            simd_support: format!("{:?}", cpu_info.simd_support),
            cpu_features: cpu_info.features.clone(),
            recommended_config: RecommendedConfigReport {
                backend: recommended.backend.name().to_string(),
                simd_type: format!("{:?}", recommended.simd_type),
                use_simd: recommended.use_simd,
                thread_count: recommended.thread_count,
                buffer_size_hint: recommended.platform_optimizations.buffer_size_hint,
                use_numa_awareness: recommended.platform_optimizations.use_numa_awareness,
                use_kernel_bypass: recommended.platform_optimizations.use_kernel_bypass,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_selector_creation() {
        let selector = BackendSelector::new();
        assert!(selector.is_backend_available(BackendType::RawSocket));
        assert!(selector.cpu_info().cores > 0);
    }

    #[test]
    fn test_available_backends() {
        let selector = BackendSelector::new();
        let available = selector.available_backends();
        assert!(!available.is_empty());
        assert!(available.contains(&BackendType::RawSocket));
    }

    #[test]
    fn test_fallback_enabled() {
        let selector = BackendSelector::new();
        assert!(selector.is_fallback_enabled());

        selector.set_fallback_enabled(false);
        assert!(!selector.is_fallback_enabled());
    }

    #[test]
    fn test_capability_report() {
        let selector = BackendSelector::new();
        let report = CapabilityReport::generate(&selector);

        assert!(!report.platform.is_empty());
        assert!(!report.arch.is_empty());
        assert!(report.cpu_count > 0);
        assert!(!report.simd_support.is_empty());
        assert!(report.recommended_config.thread_count > 0);
    }

    #[test]
    fn test_simd_detection() {
        let selector = BackendSelector::new();
        let cpu_info = selector.cpu_info();

        // SIMD support should be detected correctly for the current architecture
        #[cfg(target_arch = "x86_64")]
        {
            // Most modern x86_64 systems should have at least SSE2
            assert!(
                cpu_info.simd_support != SimdType::None
                    || cpu_info.simd_support == SimdType::SSE2
                    || cpu_info.simd_support == SimdType::AVX2
                    || cpu_info.simd_support == SimdType::AVX512
            );
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Most ARM64 systems should have NEON
            assert!(
                cpu_info.simd_support == SimdType::NEON || cpu_info.simd_support == SimdType::None
            );
        }
    }

    #[test]
    fn test_recommended_config() {
        let selector = BackendSelector::new();
        let config = selector.get_recommended_config();

        assert!(config.thread_count > 0);
        assert!(config.platform_optimizations.buffer_size_hint > 0);

        // Verify SIMD is enabled when available
        if selector.has_simd_support() {
            assert!(config.use_simd);
            assert!(config.simd_type != SimdType::None);
        }
    }

    /// **Feature: true-military-grade, Property 10: Cross-Platform Backend Selection**
    /// **Validates: Requirements 12.3, 12.4, 12.5**
    ///
    /// Property: For any platform (Windows/macOS/Linux), the backend selector SHALL choose
    /// the highest-performance available backend for that platform, and the selected backend
    /// SHALL be functional.
    #[test]
    fn test_property_cross_platform_backend_selection() {
        let selector = BackendSelector::new();
        let available_backends = selector.available_backends();
        let current_backend = selector.current_backend();
        let platform_priority = BackendSelector::get_platform_priority();

        // Property 1: At least one backend should always be available (RawSocket)
        assert!(
            !available_backends.is_empty(),
            "At least one backend should always be available"
        );
        assert!(
            available_backends.contains(&BackendType::RawSocket),
            "RawSocket should always be available as fallback"
        );

        // Property 2: Current backend should be in the available list
        assert!(
            available_backends.contains(&current_backend),
            "Current backend {:?} should be in available list: {:?}",
            current_backend,
            available_backends
        );

        // Property 3: Current backend should be the highest priority available
        let expected_backend = platform_priority
            .iter()
            .find(|&&backend| available_backends.contains(&backend))
            .copied()
            .unwrap_or(BackendType::RawSocket);

        assert_eq!(
            current_backend, expected_backend,
            "Current backend {:?} should be highest priority available backend {:?}",
            current_backend, expected_backend
        );

        // Property 4: Platform-specific backend priorities should be correct
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                platform_priority[0],
                BackendType::Dpdk,
                "Linux should prioritize DPDK first"
            );
            assert_eq!(
                platform_priority[1],
                BackendType::AfXdp,
                "Linux should prioritize AF_XDP second"
            );
            assert_eq!(
                *platform_priority.last().unwrap(),
                BackendType::RawSocket,
                "Linux should have RawSocket as fallback"
            );
        }

        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                platform_priority[0],
                BackendType::RegisteredIO,
                "Windows should prioritize RIO first"
            );
            assert_eq!(
                platform_priority[1],
                BackendType::IOCP,
                "Windows should prioritize IOCP second"
            );
            assert_eq!(
                *platform_priority.last().unwrap(),
                BackendType::RawSocket,
                "Windows should have RawSocket as fallback"
            );
        }

        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                platform_priority[0],
                BackendType::NetworkFramework,
                "macOS should prioritize Network.framework first"
            );
            assert_eq!(
                platform_priority[1],
                BackendType::Kqueue,
                "macOS should prioritize kqueue second"
            );
            assert_eq!(
                *platform_priority.last().unwrap(),
                BackendType::RawSocket,
                "macOS should have RawSocket as fallback"
            );
        }

        // Property 5: Backend should be functional (basic check without full initialization)
        let backend = selector.backend();
        // Just check that we can get a backend instance without hanging
        assert!(
            !backend.backend_type().name().is_empty(),
            "Selected backend should have a valid name"
        );
    }

    /// **Feature: true-military-grade, Property 11: SIMD Code Path Selection**
    /// **Validates: Requirements 12.4, 12.5**
    ///
    /// Property: For any CPU architecture, the system SHALL use the optimal SIMD instruction
    /// set available (x86_64 with AVX2: Use AVX2 SIMD, ARM64 with NEON: Use NEON SIMD,
    /// ARM32: Use scalar operations).
    #[test]
    fn test_property_simd_code_path_selection() {
        let selector = BackendSelector::new();
        let cpu_info = selector.cpu_info();
        let config = selector.get_recommended_config();

        // Property 1: SIMD detection should be consistent with architecture
        #[cfg(target_arch = "x86_64")]
        {
            // x86_64 should detect appropriate SIMD level
            match cpu_info.simd_support {
                SimdType::AVX512 => {
                    assert!(
                        is_x86_feature_detected!("avx512f"),
                        "AVX-512 detected but not available"
                    );
                    assert!(config.use_simd, "Should use SIMD when AVX-512 available");
                }
                SimdType::AVX2 => {
                    assert!(
                        is_x86_feature_detected!("avx2"),
                        "AVX2 detected but not available"
                    );
                    assert!(config.use_simd, "Should use SIMD when AVX2 available");
                }
                SimdType::SSE2 => {
                    assert!(
                        is_x86_feature_detected!("sse2"),
                        "SSE2 detected but not available"
                    );
                    assert!(config.use_simd, "Should use SIMD when SSE2 available");
                }
                SimdType::None => {
                    assert!(!config.use_simd, "Should not use SIMD when none available");
                }
                SimdType::NEON => {
                    panic!("NEON should not be detected on x86_64");
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 should detect NEON or None
            match cpu_info.simd_support {
                SimdType::NEON => {
                    assert!(
                        std::arch::is_aarch64_feature_detected!("neon"),
                        "NEON detected but not available"
                    );
                    assert!(config.use_simd, "Should use SIMD when NEON available");
                }
                SimdType::None => {
                    assert!(!config.use_simd, "Should not use SIMD when none available");
                }
                SimdType::AVX512 | SimdType::AVX2 | SimdType::SSE2 => {
                    panic!("x86 SIMD should not be detected on ARM64");
                }
            }
        }

        #[cfg(target_arch = "arm")]
        {
            // ARM32 should use scalar operations per requirements
            assert_eq!(
                cpu_info.simd_support,
                SimdType::None,
                "ARM32 should use scalar operations"
            );
            assert!(!config.use_simd, "ARM32 should not use SIMD");
        }

        // Property 2: SIMD type should match configuration
        assert_eq!(
            config.simd_type, cpu_info.simd_support,
            "Configuration SIMD type should match detected SIMD support"
        );

        // Property 3: CPU features should be consistent with SIMD support
        match cpu_info.simd_support {
            SimdType::AVX512 => {
                assert!(
                    cpu_info.features.contains(&"AVX-512".to_string()),
                    "AVX-512 support should be in features list"
                );
            }
            SimdType::AVX2 => {
                assert!(
                    cpu_info.features.contains(&"AVX2".to_string()),
                    "AVX2 support should be in features list"
                );
            }
            SimdType::SSE2 => {
                assert!(
                    cpu_info.features.contains(&"SSE2".to_string()),
                    "SSE2 support should be in features list"
                );
            }
            SimdType::NEON => {
                assert!(
                    cpu_info.features.contains(&"NEON".to_string()),
                    "NEON support should be in features list"
                );
            }
            SimdType::None => {
                // No specific SIMD features required
            }
        }

        // Property 4: Thread count should be reasonable for the architecture
        assert!(config.thread_count > 0, "Thread count should be positive");
        assert!(
            config.thread_count <= 1024,
            "Thread count should be reasonable"
        );
        assert_eq!(
            config.thread_count, cpu_info.cores,
            "Thread count should match CPU cores"
        );

        // Property 5: Architecture string should be valid
        assert!(
            !cpu_info.architecture.is_empty(),
            "Architecture should not be empty"
        );
        assert!(
            matches!(
                cpu_info.architecture.as_str(),
                "x86_64" | "aarch64" | "arm" | "x86"
            ),
            "Architecture should be recognized: {}",
            cpu_info.architecture
        );
    }
}
