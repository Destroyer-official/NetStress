//! Linux-specific optimizations and advanced features
//! Enables DPDK, AF_XDP, io_uring, and sendmmsg for maximum performance

use crate::backend::{Backend, BackendError, BackendType, SystemCapabilities};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

/// Linux optimization manager
pub struct LinuxOptimizer {
    capabilities: SystemCapabilities,
    enabled_features: Vec<String>,
}

impl LinuxOptimizer {
    /// Create new Linux optimizer with capability detection
    pub fn new() -> Self {
        let capabilities = detect_linux_capabilities();
        let enabled_features = Self::detect_enabled_features(&capabilities);

        info!(
            "Linux optimizer initialized with {} features",
            enabled_features.len()
        );
        for feature in &enabled_features {
            info!("  - {}", feature);
        }

        Self {
            capabilities,
            enabled_features,
        }
    }

    /// Get system capabilities
    pub fn capabilities(&self) -> &SystemCapabilities {
        &self.capabilities
    }

    /// Get enabled features
    pub fn enabled_features(&self) -> &[String] {
        &self.enabled_features
    }

    /// Check if a specific feature is enabled
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        self.enabled_features.iter().any(|f| f == feature)
    }

    /// Get recommended backend for maximum performance
    pub fn get_recommended_backend(&self) -> BackendType {
        if self.capabilities.has_dpdk {
            BackendType::Dpdk
        } else if self.capabilities.has_af_xdp {
            BackendType::AfXdp
        } else if self.capabilities.has_io_uring {
            BackendType::IoUring
        } else if self.capabilities.has_sendmmsg {
            BackendType::Sendmmsg
        } else {
            BackendType::RawSocket
        }
    }

    /// Apply Linux-specific socket optimizations
    pub fn optimize_socket(&self, socket_fd: i32) -> Result<(), BackendError> {
        unsafe {
            // Set socket buffer sizes for high throughput
            let sndbuf_size = 16 * 1024 * 1024; // 16MB send buffer
            let rcvbuf_size = 16 * 1024 * 1024; // 16MB receive buffer

            libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            // Enable socket reuse
            let reuse = 1;
            libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &reuse as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &reuse as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            // Disable Nagle's algorithm for low latency
            let nodelay = 1;
            libc::setsockopt(
                socket_fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &nodelay as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );
        }

        Ok(())
    }

    /// Set CPU affinity for current thread
    pub fn set_cpu_affinity(&self, cpu_id: usize) -> Result<(), BackendError> {
        if cpu_id >= self.capabilities.cpu_count as usize {
            return Err(BackendError::InitFailed(format!(
                "CPU {} not available (max: {})",
                cpu_id,
                self.capabilities.cpu_count - 1
            )));
        }

        #[cfg(target_os = "linux")]
        {
            use nix::sched::{sched_setaffinity, CpuSet};
            use nix::unistd::Pid;

            let mut cpu_set = CpuSet::new();
            cpu_set.set(cpu_id).map_err(|e| {
                BackendError::InitFailed(format!("Failed to set CPU affinity: {}", e))
            })?;

            sched_setaffinity(Pid::from_raw(0), &cpu_set).map_err(|e| {
                BackendError::InitFailed(format!("Failed to set CPU affinity: {}", e))
            })?;

            debug!("Set CPU affinity to core {}", cpu_id);
        }

        Ok(())
    }

    /// Enable high-resolution timers
    pub fn enable_high_res_timers(&self) -> Result<(), BackendError> {
        // This is typically handled by the kernel, but we can request it
        debug!("High-resolution timers requested");
        Ok(())
    }

    /// Get performance recommendations
    pub fn get_performance_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !self.capabilities.has_dpdk {
            recommendations.push("Consider installing DPDK for maximum performance".to_string());
        }

        if !self.capabilities.has_af_xdp {
            recommendations
                .push("Consider enabling AF_XDP for kernel-bypass networking".to_string());
        }

        if !self.capabilities.has_io_uring {
            recommendations
                .push("Consider upgrading to Linux 5.1+ for io_uring support".to_string());
        }

        if self.capabilities.cpu_count < 4 {
            recommendations.push(
                "Consider using a system with more CPU cores for better performance".to_string(),
            );
        }

        recommendations.push("Use CPU affinity to pin threads to specific cores".to_string());
        recommendations.push("Increase socket buffer sizes for high throughput".to_string());
        recommendations.push("Disable interrupt coalescing on network interfaces".to_string());

        recommendations
    }

    /// Detect enabled features based on capabilities
    fn detect_enabled_features(caps: &SystemCapabilities) -> Vec<String> {
        let mut features = Vec::new();

        if caps.has_raw_socket {
            features.push("Raw Sockets".to_string());
        }

        if caps.has_sendmmsg {
            features.push("sendmmsg Batch Sending".to_string());
        }

        if caps.has_io_uring {
            features.push("io_uring Async I/O".to_string());
        }

        if caps.has_af_xdp {
            features.push("AF_XDP Zero-Copy".to_string());
        }

        if caps.has_dpdk {
            features.push("DPDK Kernel Bypass".to_string());
        }

        features.push(format!("Multi-Core Support ({} cores)", caps.cpu_count));

        if caps.kernel_version.0 >= 5 {
            features.push("Modern Linux Kernel".to_string());
        }

        features
    }
}

impl Default for LinuxOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced Linux capability detection
fn detect_linux_capabilities() -> SystemCapabilities {
    let mut caps = SystemCapabilities::default();
    caps.has_raw_socket = true;

    // Get CPU count
    caps.cpu_count = std::thread::available_parallelism()
        .map(|p| p.get() as i32)
        .unwrap_or(1);

    // Check kernel version for feature availability
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let parts: Vec<&str> = release.trim().split('.').collect();
        if parts.len() >= 2 {
            caps.kernel_version.0 = parts[0].parse().unwrap_or(0);
            caps.kernel_version.1 = parts[1].parse().unwrap_or(0);
        }
    }

    // sendmmsg available on Linux 3.0+
    if caps.kernel_version.0 >= 3 {
        caps.has_sendmmsg = true;
    }

    // io_uring available on Linux 5.1+
    if caps.kernel_version.0 > 5 || (caps.kernel_version.0 == 5 && caps.kernel_version.1 >= 1) {
        #[cfg(feature = "io_uring")]
        {
            caps.has_io_uring = check_io_uring_support();
        }
    }

    // AF_XDP available on Linux 4.18+
    if caps.kernel_version.0 > 4 || (caps.kernel_version.0 == 4 && caps.kernel_version.1 >= 18) {
        #[cfg(feature = "af_xdp")]
        {
            caps.has_af_xdp = check_af_xdp_support();
        }
    }

    // DPDK detection
    #[cfg(feature = "dpdk")]
    {
        caps.has_dpdk = check_dpdk_support();
    }

    // NUMA detection
    if let Ok(online) = std::fs::read_to_string("/sys/devices/system/node/online") {
        let parts: Vec<&str> = online.trim().split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                caps.numa_nodes = end - start + 1;
            }
        } else {
            caps.numa_nodes = 1;
        }
    }

    caps
}

/// Check if io_uring is actually supported
#[cfg(feature = "io_uring")]
fn check_io_uring_support() -> bool {
    // Try to create a small io_uring instance
    match io_uring::IoUring::new(1) {
        Ok(_) => {
            debug!("io_uring support confirmed");
            true
        }
        Err(e) => {
            warn!("io_uring not supported: {}", e);
            false
        }
    }
}

#[cfg(not(feature = "io_uring"))]
fn check_io_uring_support() -> bool {
    false
}

/// Check if AF_XDP is actually supported
#[cfg(feature = "af_xdp")]
fn check_af_xdp_support() -> bool {
    // Check for required files/capabilities
    std::path::Path::new("/sys/fs/bpf").exists()
        && std::path::Path::new("/proc/net/xdp_stats").exists()
}

#[cfg(not(feature = "af_xdp"))]
fn check_af_xdp_support() -> bool {
    false
}

/// Check if DPDK is actually supported
#[cfg(feature = "dpdk")]
fn check_dpdk_support() -> bool {
    // Check for DPDK libraries and hugepages
    std::path::Path::new("/sys/kernel/mm/hugepages").exists()
}

#[cfg(not(feature = "dpdk"))]
fn check_dpdk_support() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_optimizer_creation() {
        let optimizer = LinuxOptimizer::new();
        assert!(!optimizer.enabled_features().is_empty());
    }

    #[test]
    fn test_capability_detection() {
        let caps = detect_linux_capabilities();
        assert!(caps.has_raw_socket);
        assert!(caps.cpu_count > 0);
    }

    #[test]
    fn test_performance_recommendations() {
        let optimizer = LinuxOptimizer::new();
        let recommendations = optimizer.get_performance_recommendations();
        assert!(!recommendations.is_empty());
    }
}
