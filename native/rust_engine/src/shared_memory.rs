//! Shared Memory Bridge for Real-Time Telemetry
//!
//! Rust-side implementation of the shared memory bridge for writing engine statistics.
//! This module provides microsecond-level stats updates to shared memory that can be
//! read by Python without IPC overhead.
//!
//! Requirements:
//! - 8.1: Write stats to shared memory (mmap)
//! - 8.3: Microsecond-level update frequency

use memmap2::{MmapMut, MmapOptions};
use parking_lot::Mutex;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::mem;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur with shared memory operations
#[derive(Error, Debug)]
pub enum SharedMemoryError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid shared memory size: {0}")]
    InvalidSize(usize),
    #[error("Shared memory not initialized")]
    NotInitialized,
    #[error("Invalid magic number")]
    InvalidMagic,
    #[error("Version mismatch")]
    VersionMismatch,
}

/// Memory layout offsets matching Python implementation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatsLayout;

impl StatsLayout {
    // Header (32 bytes)
    pub const MAGIC: usize = 0; // 4 bytes: Magic number
    pub const VERSION: usize = 4; // 4 bytes: Structure version
    pub const TIMESTAMP_US: usize = 8; // 8 bytes: Last update timestamp (microseconds)
    pub const WRITER_PID: usize = 16; // 4 bytes: Writer process ID
    pub const SEQUENCE: usize = 20; // 8 bytes: Sequence number
    pub const RESERVED: usize = 28; // 4 bytes: Reserved

    // Stats data (64 bytes)
    pub const PACKETS_SENT: usize = 32; // 8 bytes: Total packets sent
    pub const BYTES_SENT: usize = 40; // 8 bytes: Total bytes sent
    pub const PPS: usize = 48; // 8 bytes: Packets per second (f64)
    pub const BPS: usize = 56; // 8 bytes: Bytes per second (f64)
    pub const ERRORS: usize = 64; // 8 bytes: Total errors
    pub const DURATION_US: usize = 72; // 8 bytes: Duration in microseconds
    pub const BACKEND_ID: usize = 80; // 4 bytes: Backend type ID
    pub const THREAD_COUNT: usize = 84; // 4 bytes: Active thread count

    // Backend-specific stats (32 bytes)
    pub const BACKEND_STAT1: usize = 88; // 8 bytes: Backend stat 1
    pub const BACKEND_STAT2: usize = 96; // 8 bytes: Backend stat 2
    pub const BACKEND_STAT3: usize = 104; // 8 bytes: Backend stat 3
    pub const BACKEND_STAT4: usize = 112; // 8 bytes: Backend stat 4

    // Total size
    pub const TOTAL_SIZE: usize = 128;
}

/// Backend type identifiers matching Python implementation
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    Unknown = 0,
    Python = 1,
    Rust = 2,
    Dpdk = 3,
    AfXdp = 4,
    IoUring = 5,
    Sendmmsg = 6,
    RawSocket = 7,
}

impl From<&str> for BackendType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "python" => BackendType::Python,
            "rust" => BackendType::Rust,
            "dpdk" => BackendType::Dpdk,
            "af_xdp" => BackendType::AfXdp,
            "io_uring" => BackendType::IoUring,
            "sendmmsg" => BackendType::Sendmmsg,
            "raw_socket" => BackendType::RawSocket,
            _ => BackendType::Unknown,
        }
    }
}

/// Statistics snapshot for writing to shared memory
#[derive(Debug, Clone)]
pub struct SharedStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub pps: f64,
    pub bps: f64,
    pub errors: u64,
    pub duration_us: u64,
    pub backend: BackendType,
    pub thread_count: u32,
    pub backend_stats: [f64; 4],
}

impl Default for SharedStatsSnapshot {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            bytes_sent: 0,
            pps: 0.0,
            bps: 0.0,
            errors: 0,
            duration_us: 0,
            backend: BackendType::Rust,
            thread_count: 1,
            backend_stats: [0.0; 4],
        }
    }
}

impl From<crate::stats::StatsSnapshot> for SharedStatsSnapshot {
    fn from(stats: crate::stats::StatsSnapshot) -> Self {
        Self {
            packets_sent: stats.packets_sent,
            bytes_sent: stats.bytes_sent,
            pps: stats.pps as f64,
            bps: stats.bps as f64,
            errors: stats.errors,
            duration_us: stats.duration.as_micros() as u64,
            backend: BackendType::Rust,
            thread_count: 1,
            backend_stats: [0.0; 4],
        }
    }
}

/// High-performance shared memory writer for engine statistics
pub struct SharedMemoryWriter {
    mmap: MmapMut,
    sequence: AtomicU64,
    start_time: SystemTime,
    _file: std::fs::File,
}

impl SharedMemoryWriter {
    /// Magic number for validation (same as Python: "NSTB")
    const MAGIC_NUMBER: u32 = 0x4E535442;
    const VERSION: u32 = 1;

    /// Create a new shared memory writer
    pub fn new(name: &str) -> Result<Self, SharedMemoryError> {
        let path = Self::get_shared_memory_path(name);

        // Create or open the shared memory file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        // Set the file size
        file.set_len(StatsLayout::TOTAL_SIZE as u64)?;

        // Memory map the file
        let mmap = unsafe {
            MmapOptions::new()
                .len(StatsLayout::TOTAL_SIZE)
                .map_mut(&file)?
        };

        let mut writer = Self {
            mmap,
            sequence: AtomicU64::new(0),
            start_time: SystemTime::now(),
            _file: file,
        };

        // Initialize the shared memory
        writer.initialize()?;

        Ok(writer)
    }

    /// Get platform-specific shared memory path
    fn get_shared_memory_path(name: &str) -> std::path::PathBuf {
        if cfg!(windows) {
            // On Windows, use temp directory
            std::env::temp_dir().join(format!("{}.shm", name))
        } else {
            // On Unix-like systems, use /dev/shm
            Path::new("/dev/shm").join(name)
        }
    }

    /// Initialize shared memory with header
    fn initialize(&mut self) -> Result<(), SharedMemoryError> {
        // Write header
        self.write_u32(StatsLayout::MAGIC, Self::MAGIC_NUMBER);
        self.write_u32(StatsLayout::VERSION, Self::VERSION);
        self.write_u64(StatsLayout::TIMESTAMP_US, self.current_time_us());
        self.write_u32(StatsLayout::WRITER_PID, std::process::id());
        self.write_u64(StatsLayout::SEQUENCE, 0);
        self.write_u32(StatsLayout::RESERVED, 0);

        // Initialize stats to zero
        self.write_u64(StatsLayout::PACKETS_SENT, 0);
        self.write_u64(StatsLayout::BYTES_SENT, 0);
        self.write_f64(StatsLayout::PPS, 0.0);
        self.write_f64(StatsLayout::BPS, 0.0);
        self.write_u64(StatsLayout::ERRORS, 0);
        self.write_u64(StatsLayout::DURATION_US, 0);
        self.write_u32(StatsLayout::BACKEND_ID, BackendType::Rust as u32);
        self.write_u32(StatsLayout::THREAD_COUNT, 1);

        // Initialize backend stats
        for i in 0..4 {
            self.write_f64(StatsLayout::BACKEND_STAT1 + i * 8, 0.0);
        }

        Ok(())
    }

    /// Write statistics to shared memory atomically
    pub fn write_stats(&mut self, stats: &SharedStatsSnapshot) -> Result<(), SharedMemoryError> {
        // Increment sequence number for atomic update
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;

        // Write sequence number to mark start of update
        self.write_u64(StatsLayout::SEQUENCE, sequence);

        // Write timestamp
        self.write_u64(StatsLayout::TIMESTAMP_US, self.current_time_us());

        // Write stats atomically
        self.write_u64(StatsLayout::PACKETS_SENT, stats.packets_sent);
        self.write_u64(StatsLayout::BYTES_SENT, stats.bytes_sent);
        self.write_f64(StatsLayout::PPS, stats.pps);
        self.write_f64(StatsLayout::BPS, stats.bps);
        self.write_u64(StatsLayout::ERRORS, stats.errors);
        self.write_u64(StatsLayout::DURATION_US, stats.duration_us);
        self.write_u32(StatsLayout::BACKEND_ID, stats.backend as u32);
        self.write_u32(StatsLayout::THREAD_COUNT, stats.thread_count);

        // Write backend-specific stats
        for (i, &stat) in stats.backend_stats.iter().enumerate() {
            self.write_f64(StatsLayout::BACKEND_STAT1 + i * 8, stat);
        }

        // Write sequence number again to mark end of update
        self.write_u64(StatsLayout::SEQUENCE, sequence);

        Ok(())
    }

    /// Update stats from engine stats snapshot
    pub fn update_from_engine_stats(
        &mut self,
        stats: &crate::stats::StatsSnapshot,
        backend: BackendType,
        thread_count: u32,
    ) -> Result<(), SharedMemoryError> {
        let shared_stats = SharedStatsSnapshot {
            packets_sent: stats.packets_sent,
            bytes_sent: stats.bytes_sent,
            pps: stats.pps as f64,
            bps: stats.bps as f64,
            errors: stats.errors,
            duration_us: stats.duration.as_micros() as u64,
            backend,
            thread_count,
            backend_stats: [0.0; 4], // Can be customized per backend
        };

        self.write_stats(&shared_stats)
    }

    /// Get current time in microseconds since Unix epoch
    fn current_time_us(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }

    /// Write 32-bit unsigned integer to shared memory
    fn write_u32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        self.mmap[offset..offset + 4].copy_from_slice(&bytes);
    }

    /// Write 64-bit unsigned integer to shared memory
    fn write_u64(&mut self, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        self.mmap[offset..offset + 8].copy_from_slice(&bytes);
    }

    /// Write 64-bit float to shared memory
    fn write_f64(&mut self, offset: usize, value: f64) {
        let bytes = value.to_le_bytes();
        self.mmap[offset..offset + 8].copy_from_slice(&bytes);
    }

    /// Read 32-bit unsigned integer from shared memory
    fn read_u32(&self, offset: usize) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.mmap[offset..offset + 4]);
        u32::from_le_bytes(bytes)
    }

    /// Read 64-bit unsigned integer from shared memory
    fn read_u64(&self, offset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.mmap[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    }

    /// Validate shared memory integrity
    pub fn is_valid(&self) -> bool {
        self.read_u32(StatsLayout::MAGIC) == Self::MAGIC_NUMBER
            && self.read_u32(StatsLayout::VERSION) == Self::VERSION
    }

    /// Get current sequence number
    pub fn get_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    /// Force sync to disk (for persistence)
    pub fn sync(&self) -> Result<(), SharedMemoryError> {
        self.mmap.flush()?;
        Ok(())
    }
}

/// Thread-safe shared memory writer with automatic updates
pub struct AutoUpdatingWriter {
    writer: Arc<Mutex<SharedMemoryWriter>>,
    update_interval_us: u64,
    running: Arc<AtomicU64>, // Using AtomicU64 as AtomicBool
}

impl AutoUpdatingWriter {
    /// Create a new auto-updating writer
    pub fn new(name: &str, update_interval_us: u64) -> Result<Self, SharedMemoryError> {
        let writer = SharedMemoryWriter::new(name)?;

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            update_interval_us,
            running: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Start automatic updates from stats
    pub fn start_auto_update(
        &self,
        stats: Arc<parking_lot::RwLock<crate::stats::Stats>>,
        backend: BackendType,
        thread_count: u32,
    ) {
        if self.running.swap(1, Ordering::SeqCst) == 1 {
            return; // Already running
        }

        let writer = Arc::clone(&self.writer);
        let running = Arc::clone(&self.running);
        let interval_us = self.update_interval_us;

        std::thread::spawn(move || {
            while running.load(Ordering::SeqCst) == 1 {
                let snapshot = stats.read().snapshot();

                if let Some(mut writer_guard) = writer.try_lock() {
                    let _ = writer_guard.update_from_engine_stats(&snapshot, backend, thread_count);
                }

                // Sleep for the specified interval
                std::thread::sleep(std::time::Duration::from_micros(interval_us));
            }
        });
    }

    /// Stop automatic updates
    pub fn stop_auto_update(&self) {
        self.running.store(0, Ordering::SeqCst);
    }

    /// Manually write stats
    pub fn write_stats(&self, stats: &SharedStatsSnapshot) -> Result<(), SharedMemoryError> {
        self.writer.lock().write_stats(stats)
    }

    /// Check if writer is valid
    pub fn is_valid(&self) -> bool {
        self.writer.lock().is_valid()
    }
}

impl Drop for AutoUpdatingWriter {
    fn drop(&mut self) {
        self.stop_auto_update();
    }
}

/// Convenience function to create a shared memory writer
pub fn create_writer(name: &str) -> Result<SharedMemoryWriter, SharedMemoryError> {
    SharedMemoryWriter::new(name)
}

/// Convenience function to create an auto-updating writer with microsecond updates
pub fn create_auto_writer(name: &str) -> Result<AutoUpdatingWriter, SharedMemoryError> {
    AutoUpdatingWriter::new(name, 1000) // 1000 microseconds = 1ms updates
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_shared_memory_writer_creation() {
        let writer = SharedMemoryWriter::new("test_writer").unwrap();
        assert!(writer.is_valid());
    }

    #[test]
    fn test_stats_write_read() {
        let mut writer = SharedMemoryWriter::new("test_stats").unwrap();

        let stats = SharedStatsSnapshot {
            packets_sent: 1000,
            bytes_sent: 64000,
            pps: 500.0,
            bps: 32000.0,
            errors: 1,
            duration_us: 2_000_000, // 2 seconds
            backend: BackendType::Rust,
            thread_count: 4,
            backend_stats: [1.0, 2.0, 3.0, 4.0],
        };

        writer.write_stats(&stats).unwrap();

        // Verify the data was written correctly by reading it back
        assert_eq!(writer.read_u64(StatsLayout::PACKETS_SENT), 1000);
        assert_eq!(writer.read_u64(StatsLayout::BYTES_SENT), 64000);
        assert_eq!(
            writer.read_u32(StatsLayout::BACKEND_ID),
            BackendType::Rust as u32
        );
        assert_eq!(writer.read_u32(StatsLayout::THREAD_COUNT), 4);
    }

    #[test]
    fn test_sequence_number_increment() {
        let mut writer = SharedMemoryWriter::new("test_sequence").unwrap();

        let stats = SharedStatsSnapshot::default();

        let seq1 = writer.get_sequence();
        writer.write_stats(&stats).unwrap();
        let seq2 = writer.get_sequence();

        assert!(seq2 > seq1);
    }

    #[test]
    fn test_backend_type_conversion() {
        assert_eq!(BackendType::from("rust"), BackendType::Rust);
        assert_eq!(BackendType::from("DPDK"), BackendType::Dpdk);
        assert_eq!(BackendType::from("af_xdp"), BackendType::AfXdp);
        assert_eq!(BackendType::from("unknown"), BackendType::Unknown);
    }
}
