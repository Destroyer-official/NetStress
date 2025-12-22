//! macOS-specific backend implementations
//! Uses kqueue for efficient event handling and BSD socket optimizations

use crate::backend::{Backend, BackendError, BackendStats, BackendType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// macOS capabilities detection
#[derive(Debug, Clone, Default)]
pub struct MacOSCapabilities {
    pub has_kqueue: bool,
    pub has_sendfile: bool,
    pub has_so_nosigpipe: bool,
    pub has_so_reuseport: bool,
    pub cpu_count: i32,
    pub darwin_version: (i32, i32),
}

/// Backend statistics with atomic counters
struct BackendStatsInner {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    batch_count: AtomicU64,
    events_processed: AtomicU64,
}

impl Default for BackendStatsInner {
    fn default() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            batch_count: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
        }
    }
}

/// kqueue-based backend for macOS
pub struct KqueueBackend {
    kqueue_fd: RawFd,
    socket_fd: RawFd,
    stats: BackendStatsInner,
    initialized: bool,
    event_buffer: Vec<libc::kevent>,
    socket_map: Arc<RwLock<HashMap<RawFd, std::net::UdpSocket>>>,
}

impl KqueueBackend {
    /// Create a new kqueue backend
    pub fn new() -> Self {
        Self {
            kqueue_fd: -1,
            socket_fd: -1,
            stats: BackendStatsInner::default(),
            initialized: false,
            event_buffer: Vec::with_capacity(1024),
            socket_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Setup BSD socket optimizations
    fn setup_bsd_socket_opts(&self, socket_fd: RawFd) -> Result<(), BackendError> {
        unsafe {
            // Enable SO_REUSEPORT for better load balancing
            let reuseport = 1i32;
            if libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &reuseport as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            ) != 0
            {
                warn!("Failed to set SO_REUSEPORT");
            }

            // Disable SIGPIPE on macOS
            let nosigpipe = 1i32;
            if libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &nosigpipe as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            ) != 0
            {
                warn!("Failed to set SO_NOSIGPIPE");
            }

            // Set socket buffer sizes for better performance
            let sndbuf = 1024 * 1024; // 1MB send buffer
            if libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            ) != 0
            {
                warn!("Failed to set SO_SNDBUF");
            }

            let rcvbuf = 1024 * 1024; // 1MB receive buffer
            if libc::setsockopt(
                socket_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            ) != 0
            {
                warn!("Failed to set SO_RCVBUF");
            }
        }

        Ok(())
    }

    /// Register socket with kqueue for write events
    fn register_socket_write(&self, socket_fd: RawFd) -> Result<(), BackendError> {
        let mut kevent = libc::kevent {
            ident: socket_fd as libc::uintptr_t,
            filter: libc::EVFILT_WRITE,
            flags: libc::EV_ADD | libc::EV_ENABLE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };

        let result = unsafe {
            libc::kevent(
                self.kqueue_fd,
                &mut kevent as *mut libc::kevent,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };

        if result == -1 {
            return Err(BackendError::InitFailed(
                "Failed to register socket with kqueue".into(),
            ));
        }

        debug!(
            "Registered socket {} with kqueue for write events",
            socket_fd
        );
        Ok(())
    }

    /// Wait for socket to be ready for writing
    fn wait_for_write_ready(&mut self, timeout_ms: i32) -> Result<bool, BackendError> {
        let timeout = if timeout_ms > 0 {
            libc::timespec {
                tv_sec: (timeout_ms / 1000) as libc::time_t,
                tv_nsec: ((timeout_ms % 1000) * 1_000_000) as libc::c_long,
            }
        } else {
            libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        };

        self.event_buffer.resize(64, unsafe { std::mem::zeroed() });

        let num_events = unsafe {
            libc::kevent(
                self.kqueue_fd,
                std::ptr::null(),
                0,
                self.event_buffer.as_mut_ptr(),
                self.event_buffer.len() as i32,
                if timeout_ms > 0 {
                    &timeout as *const libc::timespec
                } else {
                    std::ptr::null()
                },
            )
        };

        if num_events == -1 {
            let errno = unsafe { *libc::__error() };
            if errno == libc::EINTR {
                return Ok(false); // Interrupted, try again
            }
            return Err(BackendError::SendFailed(format!(
                "kqueue wait failed: errno {}",
                errno
            )));
        }

        self.stats
            .events_processed
            .fetch_add(num_events as u64, Ordering::Relaxed);

        // Check if any events are for our socket
        for i in 0..num_events as usize {
            let event = &self.event_buffer[i];
            if event.ident == self.socket_fd as libc::uintptr_t
                && event.filter == libc::EVFILT_WRITE
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Send batch using kqueue for event notification
    fn send_batch_kqueue(
        &mut self,
        packets: &[&[u8]],
        dest: SocketAddr,
    ) -> Result<usize, BackendError> {
        let addr = match dest {
            SocketAddr::V4(v4) => {
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::AF_INET as u16;
                addr.sin_port = v4.port().to_be();
                addr.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                addr
            }
            SocketAddr::V6(_) => {
                return Err(BackendError::SendFailed("IPv6 not supported yet".into()));
            }
        };

        let mut sent_count = 0;
        let mut total_bytes = 0;

        for packet in packets {
            // Wait for socket to be ready for writing (with short timeout)
            if !self.wait_for_write_ready(1)? {
                // Socket not ready, but don't fail the entire batch
                continue;
            }

            let sent = unsafe {
                libc::sendto(
                    self.socket_fd,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };

            if sent > 0 {
                sent_count += 1;
                total_bytes += sent as u64;
            } else {
                let errno = unsafe { *libc::__error() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    // Socket buffer full, continue with next packet
                    continue;
                } else {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        self.stats
            .packets_sent
            .fetch_add(sent_count, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(total_bytes, Ordering::Relaxed);
        self.stats.batch_count.fetch_add(1, Ordering::Relaxed);

        Ok(sent_count as usize)
    }
}

impl Backend for KqueueBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Kqueue
    }

    fn init(&mut self) -> Result<(), BackendError> {
        // Create kqueue
        self.kqueue_fd = unsafe { libc::kqueue() };
        if self.kqueue_fd == -1 {
            return Err(BackendError::InitFailed("Failed to create kqueue".into()));
        }

        // Create UDP socket
        self.socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if self.socket_fd == -1 {
            unsafe { libc::close(self.kqueue_fd) };
            return Err(BackendError::InitFailed("Failed to create socket".into()));
        }

        // Setup BSD socket optimizations
        self.setup_bsd_socket_opts(self.socket_fd)?;

        // Set socket to non-blocking for better kqueue integration
        let flags = unsafe { libc::fcntl(self.socket_fd, libc::F_GETFL, 0) };
        if flags != -1 {
            unsafe {
                libc::fcntl(self.socket_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        // Register socket with kqueue
        self.register_socket_write(self.socket_fd)?;

        self.initialized = true;
        info!("kqueue backend initialized successfully");
        Ok(())
    }

    fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        let addr = match dest {
            SocketAddr::V4(v4) => {
                let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                addr.sin_family = libc::AF_INET as u16;
                addr.sin_port = v4.port().to_be();
                addr.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                addr
            }
            SocketAddr::V6(_) => {
                return Err(BackendError::SendFailed("IPv6 not supported yet".into()));
            }
        };

        let sent = unsafe {
            libc::sendto(
                self.socket_fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if sent < 0 {
            let errno = unsafe { *libc::__error() };
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            Err(BackendError::SendFailed(format!(
                "sendto failed: errno {}",
                errno
            )))
        } else {
            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(sent as u64, Ordering::Relaxed);
            Ok(sent as usize)
        }
    }

    fn send_batch(&self, packets: &[&[u8]], dest: SocketAddr) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        // Use kqueue-optimized batch sending
        let mut backend = unsafe { &mut *(self as *const Self as *mut Self) };
        backend.send_batch_kqueue(packets, dest)
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        if self.socket_fd >= 0 {
            unsafe { libc::close(self.socket_fd) };
            self.socket_fd = -1;
        }

        if self.kqueue_fd >= 0 {
            unsafe { libc::close(self.kqueue_fd) };
            self.kqueue_fd = -1;
        }

        self.initialized = false;
        info!("kqueue backend cleaned up");
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn stats(&self) -> BackendStats {
        BackendStats {
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
            batch_count: self.stats.batch_count.load(Ordering::Relaxed),
        }
    }
}

impl Drop for KqueueBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// macOS optimizer for performance tuning
pub struct MacOSOptimizer {
    capabilities: MacOSCapabilities,
}

impl MacOSOptimizer {
    /// Create a new macOS optimizer
    pub fn new() -> Self {
        Self {
            capabilities: detect_macos_capabilities(),
        }
    }

    /// Get system capabilities
    pub fn capabilities(&self) -> &MacOSCapabilities {
        &self.capabilities
    }

    /// Get recommended backend for macOS
    pub fn get_recommended_backend(&self) -> BackendType {
        if self.capabilities.has_kqueue {
            BackendType::Kqueue
        } else {
            BackendType::RawSocket
        }
    }

    /// Get performance recommendations
    pub fn get_performance_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        if self.capabilities.has_kqueue {
            recommendations.push("Use kqueue backend for optimal performance".into());
        }

        if self.capabilities.has_so_reuseport {
            recommendations.push("SO_REUSEPORT available for load balancing".into());
        }

        if self.capabilities.has_sendfile {
            recommendations.push("sendfile() available for zero-copy transfers".into());
        }

        recommendations.push(format!(
            "Detected {} CPU cores for parallel processing",
            self.capabilities.cpu_count
        ));

        if self.capabilities.darwin_version.0 >= 20 {
            recommendations.push("Modern macOS version with optimized networking stack".into());
        }

        recommendations
    }

    /// Get enabled features
    pub fn enabled_features(&self) -> Vec<String> {
        let mut features = Vec::new();

        if self.capabilities.has_kqueue {
            features.push("kqueue".into());
        }
        if self.capabilities.has_sendfile {
            features.push("sendfile".into());
        }
        if self.capabilities.has_so_nosigpipe {
            features.push("SO_NOSIGPIPE".into());
        }
        if self.capabilities.has_so_reuseport {
            features.push("SO_REUSEPORT".into());
        }

        features
    }

    /// Get Darwin version
    pub fn get_darwin_version(&self) -> (i32, i32) {
        self.capabilities.darwin_version
    }

    /// Check if running on macOS Server
    pub fn is_macos_server(&self) -> bool {
        // Simple heuristic - check for server-specific paths
        std::path::Path::new("/System/Library/CoreServices/ServerVersion.plist").exists()
    }
}

/// Detect macOS system capabilities
pub fn detect_macos_capabilities() -> MacOSCapabilities {
    let mut caps = MacOSCapabilities::default();

    // Get CPU count
    caps.cpu_count = std::thread::available_parallelism()
        .map(|p| p.get() as i32)
        .unwrap_or(1);

    // Check kqueue availability
    let kqueue_fd = unsafe { libc::kqueue() };
    if kqueue_fd >= 0 {
        caps.has_kqueue = true;
        unsafe { libc::close(kqueue_fd) };
    }

    // Check sendfile availability
    caps.has_sendfile = true; // Available on all modern macOS versions

    // Check SO_NOSIGPIPE availability (macOS-specific)
    caps.has_so_nosigpipe = true;

    // Check SO_REUSEPORT availability
    caps.has_so_reuseport = true;

    // Get Darwin version
    if let Ok(version) = std::process::Command::new("uname").arg("-r").output() {
        if let Ok(version_str) = String::from_utf8(version.stdout) {
            let parts: Vec<&str> = version_str.trim().split('.').collect();
            if parts.len() >= 2 {
                caps.darwin_version.0 = parts[0].parse().unwrap_or(0);
                caps.darwin_version.1 = parts[1].parse().unwrap_or(0);
            }
        }
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_macos_capabilities() {
        let caps = detect_macos_capabilities();
        assert!(caps.cpu_count > 0);
        // On macOS, kqueue should always be available
        #[cfg(target_os = "macos")]
        assert!(caps.has_kqueue);
    }

    #[test]
    fn test_macos_optimizer() {
        let optimizer = MacOSOptimizer::new();
        let recommendations = optimizer.get_performance_recommendations();
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_kqueue_backend_creation() {
        let backend = KqueueBackend::new();
        assert_eq!(backend.backend_type(), BackendType::Kqueue);
        assert!(!backend.is_initialized());
    }
}
