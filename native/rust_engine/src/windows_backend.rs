//! Windows-specific backend implementations
//! Provides IOCP (I/O Completion Ports) backend for high-performance async I/O on Windows

use crate::backend::{Backend, BackendError, BackendStats, BackendType};
use std::mem;
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

#[cfg(target_os = "windows")]
use winapi::ctypes::c_void;

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::{DWORD, TRUE};
#[cfg(target_os = "windows")]
use winapi::shared::winerror::ERROR_IO_PENDING;
#[cfg(target_os = "windows")]
use winapi::shared::ws2def::{AF_INET, SOCKADDR, SOCKADDR_IN, WSABUF};
#[cfg(target_os = "windows")]
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
#[cfg(target_os = "windows")]
use winapi::um::ioapiset::{CreateIoCompletionPort, GetQueuedCompletionStatus};
#[cfg(target_os = "windows")]
use winapi::um::minwinbase::LPOVERLAPPED;
#[cfg(target_os = "windows")]
use winapi::um::winbase::INFINITE;
#[cfg(target_os = "windows")]
use winapi::um::winnt::{OSVERSIONINFOEXW, OSVERSIONINFOW};
#[cfg(target_os = "windows")]
use winapi::um::winsock2::{
    closesocket, sendto, socket, WSACleanup, WSAGetLastError, WSASend, WSAStartup, INVALID_SOCKET,
    SOCKET, SOCK_DGRAM, WSADATA, WSAOVERLAPPED,
};

#[derive(Debug, Error)]
pub enum WindowsBackendError {
    #[error("WSA initialization failed: {0}")]
    WSAInitFailed(i32),
    #[error("Socket creation failed: {0}")]
    SocketCreationFailed(i32),
    #[error("IOCP creation failed: {0}")]
    IOCPCreationFailed(i32),
    #[error("Send operation failed: {0}")]
    SendFailed(i32),
    #[error("Completion port operation failed: {0}")]
    CompletionPortFailed(i32),
}

/// IOCP operation types
#[derive(Debug, Clone, Copy, PartialEq)]
enum IOCPOperation {
    Send,
    Shutdown,
}

/// IOCP operation context
#[repr(C)]
struct IOCPContext {
    overlapped: WSAOVERLAPPED,
    operation: IOCPOperation,
    buffer: Vec<u8>,
    bytes_transferred: DWORD,
}

impl IOCPContext {
    fn new(operation: IOCPOperation, buffer: Vec<u8>) -> Self {
        Self {
            overlapped: unsafe { mem::zeroed() },
            operation,
            buffer,
            bytes_transferred: 0,
        }
    }
}

/// Thread-safe wrapper for raw pointers
#[cfg(target_os = "windows")]
struct SafeHandle(*mut c_void);

#[cfg(target_os = "windows")]
unsafe impl Send for SafeHandle {}
#[cfg(target_os = "windows")]
unsafe impl Sync for SafeHandle {}

#[cfg(target_os = "windows")]
impl SafeHandle {
    fn new() -> Self {
        SafeHandle(ptr::null_mut())
    }

    fn set(&mut self, ptr: *mut c_void) {
        self.0 = ptr;
    }

    fn get(&self) -> *mut c_void {
        self.0
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

/// Windows IOCP backend for high-performance async I/O
#[cfg(target_os = "windows")]
pub struct IOCPBackend {
    socket: SOCKET,
    completion_port: SafeHandle,
    stats: BackendStatsInner,
    initialized: bool,
    wsa_initialized: bool,
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

#[cfg(target_os = "windows")]
impl IOCPBackend {
    pub fn new() -> Self {
        Self {
            socket: INVALID_SOCKET,
            completion_port: SafeHandle::new(),
            stats: BackendStatsInner::default(),
            initialized: false,
            wsa_initialized: false,
        }
    }

    /// Initialize WSA (Windows Sockets API)
    fn init_wsa(&mut self) -> Result<(), WindowsBackendError> {
        if self.wsa_initialized {
            return Ok(());
        }

        let mut wsa_data: WSADATA = unsafe { mem::zeroed() };
        let result = unsafe { WSAStartup(0x0202, &mut wsa_data) }; // Request Winsock 2.2

        if result != 0 {
            return Err(WindowsBackendError::WSAInitFailed(result));
        }

        self.wsa_initialized = true;
        Ok(())
    }

    /// Create UDP socket
    fn create_socket(&mut self) -> Result<(), WindowsBackendError> {
        let sock = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };

        if sock == INVALID_SOCKET {
            let error = unsafe { WSAGetLastError() };
            return Err(WindowsBackendError::SocketCreationFailed(error));
        }

        self.socket = sock;
        Ok(())
    }

    /// Create I/O Completion Port
    fn create_completion_port(&mut self) -> Result<(), WindowsBackendError> {
        // Create completion port
        let iocp = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                0,
                0, // Use default number of concurrent threads
            )
        };

        if iocp.is_null() {
            return Err(WindowsBackendError::IOCPCreationFailed(unsafe {
                winapi::um::errhandlingapi::GetLastError() as i32
            }));
        }

        // Associate socket with completion port
        let result = unsafe {
            CreateIoCompletionPort(
                self.socket as winapi::um::winnt::HANDLE,
                iocp,
                self.socket as usize,
                0,
            )
        };

        if result.is_null() {
            unsafe { CloseHandle(iocp) };
            return Err(WindowsBackendError::IOCPCreationFailed(unsafe {
                winapi::um::errhandlingapi::GetLastError() as i32
            }));
        }

        self.completion_port.set(iocp);
        Ok(())
    }

    /// Send data asynchronously using IOCP
    fn send_async(&self, data: &[u8], dest: SocketAddr) -> Result<usize, WindowsBackendError> {
        let sockaddr = match dest {
            SocketAddr::V4(v4) => {
                let mut addr: SOCKADDR_IN = unsafe { mem::zeroed() };
                addr.sin_family = AF_INET as u16;
                addr.sin_port = v4.port().to_be();
                unsafe { *addr.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes(v4.ip().octets()) };
                addr
            }
            _ => {
                return Err(WindowsBackendError::SendFailed(-1)); // IPv6 not supported yet
            }
        };

        // Create operation context
        let mut context = Box::new(IOCPContext::new(IOCPOperation::Send, data.to_vec()));
        let context_ptr = Box::into_raw(context);

        // Prepare WSABUF
        let mut wsabuf = WSABUF {
            len: data.len() as u32,
            buf: data.as_ptr() as *mut i8,
        };

        let mut bytes_sent: DWORD = 0;

        // Perform async send
        let result = unsafe {
            WSASend(
                self.socket,
                &mut wsabuf,
                1,
                &mut bytes_sent,
                0,
                &mut (*context_ptr).overlapped as *mut _ as LPOVERLAPPED,
                None,
            )
        };

        if result == 0 {
            // Operation completed immediately
            unsafe { Box::from_raw(context_ptr) }; // Clean up context
            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(bytes_sent as u64, Ordering::Relaxed);
            Ok(bytes_sent as usize)
        } else {
            let error = unsafe { WSAGetLastError() };
            if error == ERROR_IO_PENDING as i32 {
                // Operation is pending, will complete asynchronously
                // Note: In a real implementation, we'd need to handle completion
                // For now, we'll wait for completion synchronously
                self.wait_for_completion(context_ptr)
            } else {
                unsafe { Box::from_raw(context_ptr) }; // Clean up context
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                Err(WindowsBackendError::SendFailed(error))
            }
        }
    }

    /// Wait for IOCP completion (simplified synchronous version)
    fn wait_for_completion(
        &self,
        context_ptr: *mut IOCPContext,
    ) -> Result<usize, WindowsBackendError> {
        let mut bytes_transferred: DWORD = 0;
        let mut completion_key: usize = 0;
        let mut overlapped: LPOVERLAPPED = ptr::null_mut();

        let result = unsafe {
            GetQueuedCompletionStatus(
                self.completion_port.get(),
                &mut bytes_transferred,
                &mut completion_key,
                &mut overlapped,
                INFINITE, // Wait indefinitely
            )
        };

        // Clean up context
        let context = unsafe { Box::from_raw(context_ptr) };

        if result == TRUE {
            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(bytes_transferred as u64, Ordering::Relaxed);
            Ok(bytes_transferred as usize)
        } else {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(WindowsBackendError::CompletionPortFailed(error as i32))
        }
    }

    /// Send batch using multiple async operations
    fn send_batch_async(
        &self,
        packets: &[&[u8]],
        dest: SocketAddr,
    ) -> Result<usize, WindowsBackendError> {
        let mut sent_count = 0;

        for packet in packets {
            match self.send_async(packet, dest) {
                Ok(_) => sent_count += 1,
                Err(_) => break, // Stop on first error
            }
        }

        self.stats.batch_count.fetch_add(1, Ordering::Relaxed);
        Ok(sent_count)
    }
}

#[cfg(target_os = "windows")]
impl Backend for IOCPBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::RawSocket // We'll add IOCP as a new type later
    }

    fn init(&mut self) -> Result<(), BackendError> {
        self.init_wsa()
            .map_err(|e| BackendError::InitFailed(e.to_string()))?;

        self.create_socket()
            .map_err(|e| BackendError::InitFailed(e.to_string()))?;

        self.create_completion_port()
            .map_err(|e| BackendError::InitFailed(e.to_string()))?;

        self.initialized = true;
        Ok(())
    }

    fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        self.send_async(data, dest)
            .map_err(|e| BackendError::SendFailed(e.to_string()))
    }

    fn send_batch(&self, packets: &[&[u8]], dest: SocketAddr) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        self.send_batch_async(packets, dest)
            .map_err(|e| BackendError::SendFailed(e.to_string()))
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        if !self.completion_port.is_null() {
            unsafe { CloseHandle(self.completion_port.get()) };
            self.completion_port.set(ptr::null_mut());
        }

        if self.socket != INVALID_SOCKET {
            unsafe { closesocket(self.socket) };
            self.socket = INVALID_SOCKET;
        }

        if self.wsa_initialized {
            unsafe { WSACleanup() };
            self.wsa_initialized = false;
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

#[cfg(target_os = "windows")]
impl Drop for IOCPBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

// Stub implementation for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub struct IOCPBackend;

#[cfg(not(target_os = "windows"))]
impl IOCPBackend {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(target_os = "windows"))]
impl Backend for IOCPBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::None
    }

    fn init(&mut self) -> Result<(), BackendError> {
        Err(BackendError::NotAvailable(
            "IOCP not available on this platform".into(),
        ))
    }

    fn send(&self, _data: &[u8], _dest: SocketAddr) -> Result<usize, BackendError> {
        Err(BackendError::NotAvailable(
            "IOCP not available on this platform".into(),
        ))
    }

    fn send_batch(&self, _packets: &[&[u8]], _dest: SocketAddr) -> Result<usize, BackendError> {
        Err(BackendError::NotAvailable(
            "IOCP not available on this platform".into(),
        ))
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        false
    }

    fn stats(&self) -> BackendStats {
        BackendStats::default()
    }
}

/// Registered I/O backend for maximum performance on Windows
#[cfg(target_os = "windows")]
pub struct RegisteredIOBackend {
    socket: SOCKET,
    rio_cq: SafeHandle, // RIO_CQ handle
    rio_rq: SafeHandle, // RIO_RQ handle
    buffer_pool: Vec<Vec<u8>>,
    stats: BackendStatsInner,
    initialized: bool,
    wsa_initialized: bool,
}

#[cfg(target_os = "windows")]
impl RegisteredIOBackend {
    pub fn new() -> Self {
        Self {
            socket: INVALID_SOCKET,
            rio_cq: SafeHandle::new(),
            rio_rq: SafeHandle::new(),
            buffer_pool: Vec::new(),
            stats: BackendStatsInner::default(),
            initialized: false,
            wsa_initialized: false,
        }
    }

    /// Initialize Registered I/O
    fn init_registered_io(&mut self) -> Result<(), WindowsBackendError> {
        // Note: This is a simplified implementation
        // Real Registered I/O requires more complex setup with RIOCreateCompletionQueue,
        // RIOCreateRequestQueue, etc. For now, we'll fall back to IOCP behavior

        // Initialize WSA first
        self.init_wsa()?;
        self.create_socket()?;

        // Pre-allocate buffer pool for zero-copy operations
        self.buffer_pool.reserve(1024);
        for _ in 0..1024 {
            self.buffer_pool.push(vec![0u8; 1500]); // MTU-sized buffers
        }

        self.initialized = true;
        Ok(())
    }

    /// Initialize WSA (Windows Sockets API)
    fn init_wsa(&mut self) -> Result<(), WindowsBackendError> {
        if self.wsa_initialized {
            return Ok(());
        }

        let mut wsa_data: WSADATA = unsafe { mem::zeroed() };
        let result = unsafe { WSAStartup(0x0202, &mut wsa_data) }; // Request Winsock 2.2

        if result != 0 {
            return Err(WindowsBackendError::WSAInitFailed(result));
        }

        self.wsa_initialized = true;
        Ok(())
    }

    /// Create UDP socket with optimizations
    fn create_socket(&mut self) -> Result<(), WindowsBackendError> {
        let sock = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };

        if sock == INVALID_SOCKET {
            let error = unsafe { WSAGetLastError() };
            return Err(WindowsBackendError::SocketCreationFailed(error));
        }

        // Set socket options for performance
        self.set_socket_optimizations(sock)?;

        self.socket = sock;
        Ok(())
    }

    /// Set Windows-specific socket optimizations
    fn set_socket_optimizations(&self, sock: SOCKET) -> Result<(), WindowsBackendError> {
        use winapi::um::winsock2::{setsockopt, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};

        // Increase send buffer size
        let send_buf_size: i32 = 1024 * 1024; // 1MB
        let result = unsafe {
            setsockopt(
                sock,
                SOL_SOCKET,
                SO_SNDBUF,
                &send_buf_size as *const i32 as *const i8,
                mem::size_of::<i32>() as i32,
            )
        };

        if result != 0 {
            let error = unsafe { WSAGetLastError() };
            return Err(WindowsBackendError::SocketCreationFailed(error));
        }

        // Increase receive buffer size
        let recv_buf_size: i32 = 1024 * 1024; // 1MB
        let result = unsafe {
            setsockopt(
                sock,
                SOL_SOCKET,
                SO_RCVBUF,
                &recv_buf_size as *const i32 as *const i8,
                mem::size_of::<i32>() as i32,
            )
        };

        if result != 0 {
            let error = unsafe { WSAGetLastError() };
            return Err(WindowsBackendError::SocketCreationFailed(error));
        }

        Ok(())
    }

    /// Send using optimized path (falls back to standard send for now)
    fn send_optimized(&self, data: &[u8], dest: SocketAddr) -> Result<usize, WindowsBackendError> {
        // For now, use standard sendto with optimized socket
        let sockaddr = match dest {
            SocketAddr::V4(v4) => {
                let mut addr: SOCKADDR_IN = unsafe { mem::zeroed() };
                addr.sin_family = AF_INET as u16;
                addr.sin_port = v4.port().to_be();
                unsafe { *addr.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes(v4.ip().octets()) };
                addr
            }
            _ => {
                return Err(WindowsBackendError::SendFailed(-1)); // IPv6 not supported yet
            }
        };

        let sent = unsafe {
            sendto(
                self.socket,
                data.as_ptr() as *const i8,
                data.len() as i32,
                0,
                &sockaddr as *const SOCKADDR_IN as *const SOCKADDR,
                mem::size_of::<SOCKADDR_IN>() as i32,
            )
        };

        if sent == -1 {
            let error = unsafe { WSAGetLastError() };
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
            Err(WindowsBackendError::SendFailed(error))
        } else {
            self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_sent
                .fetch_add(sent as u64, Ordering::Relaxed);
            Ok(sent as usize)
        }
    }
}

#[cfg(target_os = "windows")]
impl Backend for RegisteredIOBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::RegisteredIO
    }

    fn init(&mut self) -> Result<(), BackendError> {
        self.init_registered_io()
            .map_err(|e| BackendError::InitFailed(e.to_string()))
    }

    fn send(&self, data: &[u8], dest: SocketAddr) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        self.send_optimized(data, dest)
            .map_err(|e| BackendError::SendFailed(e.to_string()))
    }

    fn send_batch(&self, packets: &[&[u8]], dest: SocketAddr) -> Result<usize, BackendError> {
        if !self.initialized {
            return Err(BackendError::NotInitialized);
        }

        let mut sent_count = 0;
        for packet in packets {
            match self.send_optimized(packet, dest) {
                Ok(_) => sent_count += 1,
                Err(_) => break,
            }
        }

        self.stats.batch_count.fetch_add(1, Ordering::Relaxed);
        Ok(sent_count)
    }

    fn cleanup(&mut self) -> Result<(), BackendError> {
        if self.socket != INVALID_SOCKET {
            unsafe { closesocket(self.socket) };
            self.socket = INVALID_SOCKET;
        }

        if self.wsa_initialized {
            unsafe { WSACleanup() };
            self.wsa_initialized = false;
        }

        self.buffer_pool.clear();
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

#[cfg(target_os = "windows")]
impl Drop for RegisteredIOBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Windows-specific optimizations and features
#[cfg(target_os = "windows")]
pub struct WindowsOptimizer {
    capabilities: WindowsCapabilities,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsCapabilities {
    pub has_iocp: bool,
    pub has_registered_io: bool,
    pub winsock_version: (u8, u8),
    pub cpu_count: i32,
}

#[cfg(target_os = "windows")]
impl WindowsOptimizer {
    pub fn new() -> Self {
        Self {
            capabilities: Self::detect_capabilities(),
        }
    }

    fn detect_capabilities() -> WindowsCapabilities {
        WindowsCapabilities {
            has_iocp: true, // IOCP is available on all modern Windows versions
            has_registered_io: Self::check_registered_io(),
            winsock_version: Self::get_winsock_version(),
            cpu_count: std::thread::available_parallelism()
                .map(|p| p.get() as i32)
                .unwrap_or(1),
        }
    }

    fn check_registered_io() -> bool {
        // Registered I/O is available on Windows Server 2012/Windows 8 and later
        // For now, we'll assume it's available and handle errors gracefully
        true
    }

    fn get_winsock_version() -> (u8, u8) {
        // Return Winsock 2.2 as the target version
        (2, 2)
    }

    pub fn capabilities(&self) -> &WindowsCapabilities {
        &self.capabilities
    }

    pub fn get_recommended_backend(&self) -> BackendType {
        if self.capabilities.has_registered_io {
            BackendType::RawSocket // We'll add RegisteredIO type later
        } else if self.capabilities.has_iocp {
            BackendType::RawSocket // We'll add IOCP type later
        } else {
            BackendType::RawSocket
        }
    }

    pub fn get_performance_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        if self.capabilities.has_registered_io {
            recommendations.push("Use Registered I/O for maximum performance".to_string());
            recommendations.push("Pre-allocate buffer pools for zero-copy operations".to_string());
        }

        if self.capabilities.has_iocp {
            recommendations.push("Use IOCP for high-concurrency scenarios".to_string());
            recommendations.push("Configure completion port with optimal thread count".to_string());
        }

        recommendations.push(format!(
            "Optimize for {} CPU cores",
            self.capabilities.cpu_count
        ));

        // Windows-specific socket optimizations
        recommendations.push("Increase socket buffer sizes (SO_SNDBUF/SO_RCVBUF)".to_string());
        recommendations.push("Use WSASend/WSARecv for async operations".to_string());
        recommendations.push("Consider TCP_NODELAY for low-latency scenarios".to_string());

        // Memory optimizations
        recommendations.push("Use large pages if available (requires privileges)".to_string());
        recommendations.push("Pin worker threads to specific CPU cores".to_string());

        recommendations
    }

    /// Apply Windows-specific system optimizations
    pub fn apply_system_optimizations(&self) -> Result<(), String> {
        // Note: These would require elevated privileges in a real implementation

        // Set process priority to high
        self.set_process_priority()?;

        // Configure network adapter settings (if possible)
        self.optimize_network_settings()?;

        Ok(())
    }

    fn set_process_priority(&self) -> Result<(), String> {
        use winapi::um::processthreadsapi::{GetCurrentProcess, SetPriorityClass};
        use winapi::um::winbase::HIGH_PRIORITY_CLASS;

        let result = unsafe { SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS) };

        if result == 0 {
            return Err("Failed to set process priority".to_string());
        }

        Ok(())
    }

    fn optimize_network_settings(&self) -> Result<(), String> {
        // In a real implementation, this would:
        // - Disable TCP chimney offload if problematic
        // - Configure RSS (Receive Side Scaling)
        // - Set interrupt moderation
        // - Configure NUMA node affinity

        // For now, just return success
        Ok(())
    }

    /// Get Windows version information
    pub fn get_windows_version(&self) -> (u32, u32) {
        use winapi::um::sysinfoapi::GetVersionExW;
        use winapi::um::winnt::OSVERSIONINFOW;

        let mut version_info: OSVERSIONINFOW = unsafe { mem::zeroed() };
        version_info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;

        let result = unsafe { GetVersionExW(&mut version_info) };

        if result != 0 {
            (version_info.dwMajorVersion, version_info.dwMinorVersion)
        } else {
            (0, 0) // Unknown version
        }
    }

    /// Check if running on Windows Server
    pub fn is_windows_server(&self) -> bool {
        use winapi::um::sysinfoapi::GetVersionExW;
        use winapi::um::winnt::{OSVERSIONINFOEXW, OSVERSIONINFOW, VER_NT_SERVER};

        let mut version_info: OSVERSIONINFOEXW = unsafe { mem::zeroed() };
        version_info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOEXW>() as u32;

        let result = unsafe { GetVersionExW(&mut version_info as *mut _ as *mut OSVERSIONINFOW) };

        if result != 0 {
            version_info.wProductType == VER_NT_SERVER
        } else {
            false
        }
    }
}

// Stub for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub struct WindowsOptimizer;

#[cfg(not(target_os = "windows"))]
impl WindowsOptimizer {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iocp_backend_creation() {
        let backend = IOCPBackend::new();
        assert!(!backend.is_initialized());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_optimizer() {
        let optimizer = WindowsOptimizer::new();
        let caps = optimizer.capabilities();
        assert!(caps.cpu_count > 0);
    }
}
