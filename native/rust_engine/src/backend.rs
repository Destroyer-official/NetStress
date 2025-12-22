//! Backend abstraction layer
//! Provides unified interface for different packet sending backends

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

#[cfg(all(target_os = "linux", feature = "io_uring"))]
use io_uring::{opcode, types};

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("Backend not available: {0}")]
    NotAvailable(String),
    #[error("Initialization failed: {0}")]
    InitFailed(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Backend not initialized")]
    NotInitialized,
}

/// Backend type enumeration matching C driver
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BackendType {
    None = 0,
    RawSocket = 1,
    Sendmmsg = 2,
    IoUring = 3,
    AfXdp = 4,
    AfXdpIoUring = 5, // Combined AF_XDP + io_uring
    Dpdk = 6,
    IOCP = 7,              // Windows I/O Completion Ports
    RegisteredIO = 8,      // Windows Registered I/O
    Kqueue = 9,            // macOS kqueue
    NetworkFramework = 10, // macOS Network.framework
}

impl BackendType {
    pub fn name(&self) -> &'static str {
        match self {
            BackendType::None => "none",
            BackendType::RawSocket => "raw_socket",
            BackendType::Sendmmsg => "sendmmsg",
            BackendType::IoUring => "io_uring",
            BackendType::AfXdp => "af_xdp",
            BackendType::AfXdpIoUring => "af_xdp_io_uring",
            BackendType::Dpdk => "dpdk",
            BackendType::IOCP => "iocp",
            BackendType::RegisteredIO => "registered_io",
            BackendType::Kqueue => "kqueue",
            BackendType::NetworkFramework => "network_framework",
        }
    }

    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => BackendType::RawSocket,
            2 => BackendType::Sendmmsg,
            3 => BackendType::IoUring,
            4 => BackendType::AfXdp,
            5 => BackendType::AfXdpIoUring,
            6 => BackendType::Dpdk,
            7 => BackendType::IOCP,
            8 => BackendType::RegisteredIO,
            9 => BackendType::Kqueue,
            10 => BackendType::NetworkFramework,
            _ => BackendType::None,
        }
    }
}

/// System capabilities detected from C driver
#[derive(Debug, Clone, Default)]
pub struct SystemCapabilities {
    pub has_dpdk: bool,
    pub has_af_xdp: bool,
    pub has_io_uring: bool,
    pub has_af_xdp_io_uring: bool, // Combined AF_XDP + io_uring
    pub has_sendmmsg: bool,
    pub has_raw_socket: bool,
    pub has_iocp: bool,              // Windows IOCP
    pub has_registered_io: bool,     // Windows Registered I/O
    pub has_kqueue: bool,            // macOS kqueue
    pub has_network_framework: bool, // macOS Network.framework
    pub kernel_version: (i32, i32),
    pub cpu_count: i32,
    pub numa_nodes: i32,
}

/// Backend trait for pluggable packet sending
pub trait Backend: Send + Sync {
    /// Get backend type
    fn backend_type(&self) -> BackendType;

    /// Initialize the backend
    fn init(&mut self) -> Result<(), BackendError>;

    /// Send a single packet
    fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, BackendError>;

    /// Send a batch of packets (returns number sent)
    fn send_batch(&self, packets: &[&[u8]], dest: SocketAddr) -> Result<usize, BackendError>;

    /// Cleanup resources
    fn cleanup(&mut self) -> Result<(), BackendError>;

    /// Check if backend is initialized
    fn is_initialized(&self) -> bool;

    /// Get backend statistics
    fn stats(&self) -> BackendStats;
}

/// Backend statistics
#[derive(Debug, Clone, Default)]
pub struct BackendStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub batch_count: u64,
}

/// Standard socket backend (always available)
pub struct StandardBackend {
    socket: Option<std::net::UdpSocket>,
    stats: BackendStatsInner,
    initialized: bool,
}

struct BackendStatsInner {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    batch_count: AtomicU64,
}

impl Default for BackendStatsInner {
    fn default() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            batch_count: AtomicU64::new(0),
        }
    }
}

impl Default for StandardBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardBackend {
    pub fn new() -> Self {
        Self {
            socket: None,
            stats: BackendStatsInner::default(),
            initialized: false,
        }
    }
}

impl Backend for StandardBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::RawSocket
    }

    fn init(&mut self) -> Result<(), BackendError> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| BackendError::InitFailed(e.to_string()))?;

        // Set socket options for performance
        let _ = socket.set_nonblocking(false);

        self.socket = Some(socket);
        self.initialized = true;
        Ok(())
    }

    fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, BackendError> {
        let socket = self.socket.as_ref().ok_or(BackendError::NotInitialized)?;

        match socket.send_to(data, dest) {
            Ok(n) => {
                self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                Err(BackendError::SendFailed(e.to_string()))
            }
        }
    }

    fn send_batch(&self, packets: &[&[u8]], dest: SocketAddr) -> Result<usize, BackendError> {
        let socket = self.socket.as_ref().ok_or(BackendError::NotInitialized)?;

        let mut sent = 0;
        for packet in packets {
            match socket.send_to(packet, dest) {
                Ok(n) => {
                    self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    sent += 1;
                }
                Err(_) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        self.stats.batch_count.fetch_add(1, Ordering::Relaxed);
        Ok(sent)
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        self.socket = None;
        self.initialized = false;
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

/// Native backend using C driver (sendmmsg, io_uring, etc.)
#[cfg(target_os = "linux")]
pub struct NativeBackend {
    backend_type: BackendType,
    socket_fd: i32,
    stats: BackendStatsInner,
    initialized: bool,
    #[cfg(feature = "io_uring")]
    io_uring: Option<io_uring::IoUring>,
}

#[cfg(target_os = "linux")]
impl NativeBackend {
    pub fn new(backend_type: BackendType) -> Self {
        Self {
            backend_type,
            socket_fd: -1,
            stats: BackendStatsInner::default(),
            initialized: false,
            #[cfg(feature = "io_uring")]
            io_uring: None,
        }
    }

    /// Create with auto-detected best backend
    pub fn auto() -> Self {
        // Detect capabilities and select best backend
        let caps = detect_system_capabilities();
        let backend_type = select_best_backend(&caps);
        Self::new(backend_type)
    }
}

#[cfg(target_os = "linux")]
impl Backend for NativeBackend {
    fn backend_type(&self) -> BackendType {
        self.backend_type
    }

    fn init(&mut self) -> Result<(), BackendError> {
        match self.backend_type {
            #[cfg(feature = "io_uring")]
            BackendType::IoUring => {
                // Initialize io_uring
                let ring = io_uring::IoUring::new(256).map_err(|e| {
                    BackendError::InitFailed(format!("io_uring init failed: {}", e))
                })?;
                self.io_uring = Some(ring);

                // Still need a socket for io_uring operations
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                if fd < 0 {
                    return Err(BackendError::InitFailed("Failed to create socket".into()));
                }
                self.socket_fd = fd;
            }
            _ => {
                // Create raw socket for other backends
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                if fd < 0 {
                    return Err(BackendError::InitFailed("Failed to create socket".into()));
                }
                self.socket_fd = fd;
            }
        }

        self.initialized = true;
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
            _ => return Err(BackendError::SendFailed("IPv6 not supported".into())),
        };

        let sent = unsafe {
            libc::sendto(
                self.socket_fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };

        if sent < 0 {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            Err(BackendError::SendFailed("sendto failed".into()))
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

        match self.backend_type {
            BackendType::Sendmmsg => self.send_batch_sendmmsg(packets, dest),
            #[cfg(feature = "io_uring")]
            BackendType::IoUring => self.send_batch_io_uring(packets, dest),
            _ => {
                // Fallback to individual sends
                let mut sent = 0;
                for packet in packets {
                    if self.send(packet, dest).is_ok() {
                        sent += 1;
                    }
                }
                Ok(sent)
            }
        }
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        if self.socket_fd >= 0 {
            unsafe { libc::close(self.socket_fd) };
            self.socket_fd = -1;
        }
        self.initialized = false;
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

#[cfg(target_os = "linux")]
impl NativeBackend {
    fn send_batch_sendmmsg(
        &self,
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
            _ => return Err(BackendError::SendFailed("IPv6 not supported".into())),
        };

        let count = packets.len();
        let mut iovecs: Vec<libc::iovec> = packets
            .iter()
            .map(|p| libc::iovec {
                iov_base: p.as_ptr() as *mut libc::c_void,
                iov_len: p.len(),
            })
            .collect();

        let mut msgs: Vec<libc::mmsghdr> = (0..count)
            .map(|i| {
                let mut msg: libc::mmsghdr = unsafe { std::mem::zeroed() };
                msg.msg_hdr.msg_name = &addr as *const _ as *mut libc::c_void;
                msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
                msg.msg_hdr.msg_iov = &mut iovecs[i];
                msg.msg_hdr.msg_iovlen = 1;
                msg
            })
            .collect();

        let sent = unsafe { libc::sendmmsg(self.socket_fd, msgs.as_mut_ptr(), count as u32, 0) };

        if sent < 0 {
            self.stats.errors.fetch_add(count as u64, Ordering::Relaxed);
            Err(BackendError::SendFailed("sendmmsg failed".into()))
        } else {
            let sent_count = sent as usize;
            let bytes: u64 = packets[..sent_count].iter().map(|p| p.len() as u64).sum();
            self.stats
                .packets_sent
                .fetch_add(sent_count as u64, Ordering::Relaxed);
            self.stats.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            self.stats.batch_count.fetch_add(1, Ordering::Relaxed);
            Ok(sent_count)
        }
    }

    #[cfg(feature = "io_uring")]
    fn send_batch_io_uring(
        &self,
        packets: &[&[u8]],
        dest: SocketAddr,
    ) -> Result<usize, BackendError> {
        // For now, fall back to sendmmsg for io_uring until we can properly implement it
        // This ensures the feature works even if io_uring implementation needs refinement
        self.send_batch_sendmmsg(packets, dest)
    }
}

#[cfg(target_os = "linux")]
impl Drop for NativeBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Detect system capabilities
pub fn detect_system_capabilities() -> SystemCapabilities {
    let mut caps = SystemCapabilities::default();
    caps.has_raw_socket = true;

    #[cfg(target_os = "linux")]
    {
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
                caps.has_io_uring = true;
            }
        }

        // AF_XDP available on Linux 4.18+
        if caps.kernel_version.0 > 4 || (caps.kernel_version.0 == 4 && caps.kernel_version.1 >= 18)
        {
            #[cfg(feature = "af_xdp")]
            {
                caps.has_af_xdp = true;
            }
        }

        // Combined AF_XDP + io_uring available when both are supported
        caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;

        // DPDK detection
        #[cfg(feature = "dpdk")]
        {
            caps.has_dpdk = true;
        }
    }

    #[cfg(target_os = "windows")]
    {
        caps.cpu_count = std::thread::available_parallelism()
            .map(|p| p.get() as i32)
            .unwrap_or(1);

        // IOCP is available on all modern Windows versions
        caps.has_iocp = true;

        // Registered I/O is available on Windows Server 2012/Windows 8 and later
        caps.has_registered_io = true; // Assume available, handle errors gracefully
    }

    #[cfg(target_os = "macos")]
    {
        caps.cpu_count = std::thread::available_parallelism()
            .map(|p| p.get() as i32)
            .unwrap_or(1);

        // kqueue is available on all modern macOS versions
        let kqueue_fd = unsafe { libc::kqueue() };
        if kqueue_fd >= 0 {
            caps.has_kqueue = true;
            unsafe { libc::close(kqueue_fd) };
        }

        // Network.framework is available on macOS 10.14+
        caps.has_network_framework =
            crate::macos_network_framework::NetworkFrameworkBackend::is_available();
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        caps.cpu_count = std::thread::available_parallelism()
            .map(|p| p.get() as i32)
            .unwrap_or(1);
    }

    caps
}

/// Select best available backend
pub fn select_best_backend(caps: &SystemCapabilities) -> BackendType {
    if caps.has_dpdk {
        BackendType::Dpdk
    } else if caps.has_af_xdp_io_uring {
        BackendType::AfXdpIoUring // Prioritize combined backend
    } else if caps.has_af_xdp {
        BackendType::AfXdp
    } else if caps.has_io_uring {
        BackendType::IoUring
    } else if caps.has_sendmmsg {
        BackendType::Sendmmsg
    } else if caps.has_registered_io {
        BackendType::RegisteredIO
    } else if caps.has_iocp {
        BackendType::IOCP
    } else if caps.has_network_framework {
        BackendType::NetworkFramework
    } else if caps.has_kqueue {
        BackendType::Kqueue
    } else {
        BackendType::RawSocket
    }
}

/// Create the best available backend for the current system
pub fn create_best_backend() -> Box<dyn Backend> {
    let caps = detect_system_capabilities();
    let backend_type = select_best_backend(&caps);

    #[cfg(target_os = "linux")]
    {
        match backend_type {
            BackendType::AfXdpIoUring => {
                // Use combined AF_XDP + io_uring backend
                match crate::linux_afxdp_iouring::AfXdpIoUringBackend::new("eth0", 0) {
                    Ok(mut backend) => {
                        if backend.init().is_ok() {
                            return Box::new(backend);
                        }
                    }
                    Err(_) => {
                        // Fall back to regular AF_XDP
                        if caps.has_af_xdp {
                            return Box::new(NativeBackend::new(BackendType::AfXdp));
                        }
                    }
                }
            }
            _ => {
                if backend_type != BackendType::RawSocket {
                    return Box::new(NativeBackend::new(backend_type));
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        match backend_type {
            BackendType::IOCP => {
                return Box::new(crate::windows_backend::IOCPBackend::new());
            }
            BackendType::RegisteredIO => {
                return Box::new(crate::windows_backend::RegisteredIOBackend::new());
            }
            _ => {}
        }
    }

    #[cfg(target_os = "macos")]
    {
        match backend_type {
            BackendType::NetworkFramework => {
                match crate::macos_network_framework::NetworkFrameworkBackend::new() {
                    Ok(backend) => {
                        return Box::new(backend);
                    }
                    Err(e) => {
                        eprintln!("Warning: Network.framework initialization failed: {}. Falling back to kqueue.", e);
                        return Box::new(crate::macos_backend::KqueueBackend::new());
                    }
                }
            }
            BackendType::Kqueue => {
                return Box::new(crate::macos_backend::KqueueBackend::new());
            }
            _ => {}
        }
    }

    Box::new(StandardBackend::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_type_name() {
        assert_eq!(BackendType::Dpdk.name(), "dpdk");
        assert_eq!(BackendType::Sendmmsg.name(), "sendmmsg");
    }

    #[test]
    fn test_detect_capabilities() {
        let caps = detect_system_capabilities();
        assert!(caps.has_raw_socket);
        assert!(caps.cpu_count > 0);
    }

    #[test]
    fn test_standard_backend() {
        let mut backend = StandardBackend::new();
        assert!(!backend.is_initialized());

        backend.init().unwrap();
        assert!(backend.is_initialized());

        backend.cleanup().unwrap();
        assert!(!backend.is_initialized());
    }
}
