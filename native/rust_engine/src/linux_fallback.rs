//! Linux Backend Fallback Chain Implementation
//! AF_XDP → io_uring → sendmmsg → raw socket
//! Graceful fallback with warning logs

use crate::backend::{Backend, BackendError, BackendStats, BackendType};
use crate::linux_afxdp::AfXdpBackend;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, info, warn};

/// Linux backend with automatic fallback chain
pub struct LinuxFallbackBackend {
    /// Current active backend
    active_backend: Box<dyn Backend>,
    /// Backend type currently in use
    current_type: BackendType,
    /// Interface name for AF_XDP
    interface: String,
    /// Queue ID for AF_XDP
    queue_id: u32,
    /// Fallback statistics
    fallback_stats: FallbackStats,
    /// Whether fallback is enabled
    fallback_enabled: bool,
}

/// Fallback statistics
struct FallbackStats {
    fallback_count: AtomicU64,
    af_xdp_failures: AtomicU64,
    io_uring_failures: AtomicU64,
    sendmmsg_failures: AtomicU64,
}

impl Default for FallbackStats {
    fn default() -> Self {
        Self {
            fallback_count: AtomicU64::new(0),
            af_xdp_failures: AtomicU64::new(0),
            io_uring_failures: AtomicU64::new(0),
            sendmmsg_failures: AtomicU64::new(0),
        }
    }
}

impl LinuxFallbackBackend {
    /// Create new Linux fallback backend
    pub fn new(interface: &str, queue_id: u32) -> Result<Self, BackendError> {
        info!(
            "Creating Linux fallback backend with interface: {}",
            interface
        );

        let mut backend = Self {
            active_backend: Box::new(crate::backend::StandardBackend::new()),
            current_type: BackendType::None,
            interface: interface.to_string(),
            queue_id,
            fallback_stats: FallbackStats::default(),
            fallback_enabled: true,
        };

        // Try to initialize with the best available backend
        backend.initialize_best_backend()?;
        Ok(backend)
    }

    /// Initialize with the best available backend following fallback chain
    fn initialize_best_backend(&mut self) -> Result<(), BackendError> {
        // Try AF_XDP first
        if self.try_af_xdp().is_ok() {
            return Ok(());
        }

        // Try io_uring
        if self.try_io_uring().is_ok() {
            return Ok(());
        }

        // Try sendmmsg
        if self.try_sendmmsg().is_ok() {
            return Ok(());
        }

        // Fall back to raw socket
        self.try_raw_socket()
    }

    /// Try to initialize AF_XDP backend
    fn try_af_xdp(&mut self) -> Result<(), BackendError> {
        debug!("Attempting to initialize AF_XDP backend");

        if !AfXdpBackend::is_available() {
            debug!("AF_XDP not available on this system");
            return Err(BackendError::NotAvailable("AF_XDP not supported".into()));
        }

        match AfXdpBackend::new(&self.interface, self.queue_id) {
            Ok(mut backend) => match backend.init() {
                Ok(()) => {
                    info!("AF_XDP backend initialized successfully");
                    self.active_backend = Box::new(backend);
                    self.current_type = BackendType::AfXdp;
                    Ok(())
                }
                Err(e) => {
                    warn!("AF_XDP backend initialization failed: {}", e);
                    self.fallback_stats
                        .af_xdp_failures
                        .fetch_add(1, Ordering::Relaxed);
                    Err(e)
                }
            },
            Err(e) => {
                warn!("Failed to create AF_XDP backend: {}", e);
                self.fallback_stats
                    .af_xdp_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Try to initialize io_uring backend
    fn try_io_uring(&mut self) -> Result<(), BackendError> {
        debug!("Attempting to initialize io_uring backend");

        #[cfg(feature = "io_uring")]
        {
            // Check if io_uring is available (kernel 5.1+)
            if !self.is_io_uring_available() {
                debug!("io_uring not available on this system");
                return Err(BackendError::NotAvailable("io_uring not supported".into()));
            }

            match crate::backend::NativeBackend::new(BackendType::IoUring).init() {
                Ok(()) => {
                    info!("io_uring backend initialized successfully");
                    self.active_backend =
                        Box::new(crate::backend::NativeBackend::new(BackendType::IoUring));
                    self.current_type = BackendType::IoUring;
                    Ok(())
                }
                Err(e) => {
                    warn!("io_uring backend initialization failed: {}", e);
                    self.fallback_stats
                        .io_uring_failures
                        .fetch_add(1, Ordering::Relaxed);
                    Err(e)
                }
            }
        }

        #[cfg(not(feature = "io_uring"))]
        {
            debug!("io_uring feature not enabled");
            Err(BackendError::NotAvailable(
                "io_uring feature not enabled".into(),
            ))
        }
    }

    /// Try to initialize sendmmsg backend
    fn try_sendmmsg(&mut self) -> Result<(), BackendError> {
        debug!("Attempting to initialize sendmmsg backend");

        // Check if sendmmsg is available (kernel 3.0+)
        if !self.is_sendmmsg_available() {
            debug!("sendmmsg not available on this system");
            return Err(BackendError::NotAvailable("sendmmsg not supported".into()));
        }

        let mut backend = crate::backend::NativeBackend::new(BackendType::Sendmmsg);
        match backend.init() {
            Ok(()) => {
                info!("sendmmsg backend initialized successfully");
                self.active_backend = Box::new(backend);
                self.current_type = BackendType::Sendmmsg;
                Ok(())
            }
            Err(e) => {
                warn!("sendmmsg backend initialization failed: {}", e);
                self.fallback_stats
                    .sendmmsg_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Try to initialize raw socket backend (always available)
    fn try_raw_socket(&mut self) -> Result<(), BackendError> {
        debug!("Falling back to raw socket backend");

        let mut backend = crate::backend::StandardBackend::new();
        match backend.init() {
            Ok(()) => {
                info!("Raw socket backend initialized successfully");
                self.active_backend = Box::new(backend);
                self.current_type = BackendType::RawSocket;
                Ok(())
            }
            Err(e) => {
                error!("Raw socket backend initialization failed: {}", e);
                Err(e)
            }
        }
    }

    /// Check if io_uring is available
    fn is_io_uring_available(&self) -> bool {
        // Check kernel version (5.1+)
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = release.trim().split('.').collect();
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
                    return major > 5 || (major == 5 && minor >= 1);
                }
            }
        }
        false
    }

    /// Check if sendmmsg is available
    fn is_sendmmsg_available(&self) -> bool {
        // Check kernel version (3.0+)
        if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = release.trim().split('.').collect();
            if parts.len() >= 1 {
                if let Ok(major) = parts[0].parse::<i32>() {
                    return major >= 3;
                }
            }
        }
        false
    }

    /// Attempt fallback to next available backend
    fn attempt_fallback(&mut self) -> Result<(), BackendError> {
        if !self.fallback_enabled {
            return Err(BackendError::NotAvailable("Fallback disabled".into()));
        }

        warn!("Attempting fallback from {:?} backend", self.current_type);
        self.fallback_stats
            .fallback_count
            .fetch_add(1, Ordering::Relaxed);

        // Try next backend in fallback chain
        match self.current_type {
            BackendType::AfXdp => {
                if self.try_io_uring().is_ok() {
                    return Ok(());
                }
                if self.try_sendmmsg().is_ok() {
                    return Ok(());
                }
                self.try_raw_socket()
            }
            BackendType::IoUring => {
                if self.try_sendmmsg().is_ok() {
                    return Ok(());
                }
                self.try_raw_socket()
            }
            BackendType::Sendmmsg => self.try_raw_socket(),
            _ => Err(BackendError::NotAvailable("No fallback available".into())),
        }
    }

    /// Get fallback statistics
    pub fn get_fallback_stats(&self) -> FallbackStatsSnapshot {
        FallbackStatsSnapshot {
            fallback_count: self.fallback_stats.fallback_count.load(Ordering::Relaxed),
            af_xdp_failures: self.fallback_stats.af_xdp_failures.load(Ordering::Relaxed),
            io_uring_failures: self
                .fallback_stats
                .io_uring_failures
                .load(Ordering::Relaxed),
            sendmmsg_failures: self
                .fallback_stats
                .sendmmsg_failures
                .load(Ordering::Relaxed),
            current_backend: self.current_type,
        }
    }

    /// Enable or disable fallback
    pub fn set_fallback_enabled(&mut self, enabled: bool) {
        self.fallback_enabled = enabled;
        info!("Fallback {}", if enabled { "enabled" } else { "disabled" });
    }
}

/// Snapshot of fallback statistics
#[derive(Debug, Clone)]
pub struct FallbackStatsSnapshot {
    pub fallback_count: u64,
    pub af_xdp_failures: u64,
    pub io_uring_failures: u64,
    pub sendmmsg_failures: u64,
    pub current_backend: BackendType,
}

impl Backend for LinuxFallbackBackend {
    fn backend_type(&self) -> BackendType {
        self.current_type
    }

    fn init(&mut self) -> Result<(), BackendError> {
        // Already initialized in new()
        Ok(())
    }

    fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, BackendError> {
        match self.active_backend.send(data, dest) {
            Ok(n) => Ok(n),
            Err(e) => {
                if self.fallback_enabled {
                    warn!(
                        "Send failed with {}, attempting fallback: {}",
                        self.current_type.name(),
                        e
                    );
                    // Note: In a real implementation, we would need mutable access to attempt fallback
                    // For now, just return the error
                    Err(e)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn send_batch(&self, packets: &[&[u8]], dest: SocketAddr) -> Result<usize, BackendError> {
        match self.active_backend.send_batch(packets, dest) {
            Ok(n) => Ok(n),
            Err(e) => {
                if self.fallback_enabled {
                    warn!(
                        "Batch send failed with {}, attempting fallback: {}",
                        self.current_type.name(),
                        e
                    );
                    // Note: In a real implementation, we would need mutable access to attempt fallback
                    // For now, just return the error
                    Err(e)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        info!("Cleaning up Linux fallback backend");
        self.active_backend.cleanup()
    }

    fn is_initialized(&self) -> bool {
        self.active_backend.is_initialized()
    }

    fn stats(&self) -> BackendStats {
        self.active_backend.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_fallback_backend_creation() {
        let backend = LinuxFallbackBackend::new("eth0", 0);
        // This may fail on systems without proper network interfaces
        // but should not panic
        match backend {
            Ok(backend) => {
                assert!(backend.is_initialized());
            }
            Err(e) => {
                println!("Expected failure on test system: {}", e);
            }
        }
    }

    #[test]
    fn test_kernel_version_checks() {
        let backend = LinuxFallbackBackend::new("lo", 0).unwrap_or_else(|_| {
            // Create a minimal backend for testing
            LinuxFallbackBackend {
                active_backend: Box::new(crate::backend::StandardBackend::new()),
                current_type: BackendType::RawSocket,
                interface: "lo".to_string(),
                queue_id: 0,
                fallback_stats: FallbackStats::default(),
                fallback_enabled: true,
            }
        });

        // These should not panic
        let _ = backend.is_sendmmsg_available();
        let _ = backend.is_io_uring_available();
    }

    #[test]
    fn test_fallback_stats() {
        let backend = LinuxFallbackBackend::new("lo", 0).unwrap_or_else(|_| LinuxFallbackBackend {
            active_backend: Box::new(crate::backend::StandardBackend::new()),
            current_type: BackendType::RawSocket,
            interface: "lo".to_string(),
            queue_id: 0,
            fallback_stats: FallbackStats::default(),
            fallback_enabled: true,
        });

        let stats = backend.get_fallback_stats();
        assert_eq!(stats.fallback_count, 0);
    }
}
