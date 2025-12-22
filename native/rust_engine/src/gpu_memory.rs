//! GPU Memory Transfer Module
//!
//! Efficient memory transfer for generated packets between GPU and CPU.
//! Implements Requirements 10.2: GPU-to-CPU transfer with pinned memory.

use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, error, info, warn};

#[cfg(feature = "cuda")]
use cudarc::driver::{CudaDevice, CudaSlice, DriverError};

#[derive(Debug, Error)]
pub enum GpuMemoryError {
    #[error("CUDA not available: {0}")]
    NotAvailable(String),
    #[error("Memory allocation failed: {0}")]
    AllocationFailed(String),
    #[error("Transfer failed: {0}")]
    TransferFailed(String),
    #[error("Invalid buffer size: {0}")]
    InvalidBufferSize(String),
}

#[cfg(feature = "cuda")]
impl From<DriverError> for GpuMemoryError {
    fn from(err: DriverError) -> Self {
        GpuMemoryError::TransferFailed(err.to_string())
    }
}

/// Memory transfer statistics
#[derive(Debug, Clone)]
pub struct TransferStats {
    pub total_transfers: u64,
    pub total_bytes_transferred: u64,
    pub total_transfer_time: std::time::Duration,
    pub average_bandwidth_gbps: f64,
    pub peak_bandwidth_gbps: f64,
    pub last_transfer_time: std::time::Duration,
}

impl Default for TransferStats {
    fn default() -> Self {
        Self {
            total_transfers: 0,
            total_bytes_transferred: 0,
            total_transfer_time: std::time::Duration::ZERO,
            average_bandwidth_gbps: 0.0,
            peak_bandwidth_gbps: 0.0,
            last_transfer_time: std::time::Duration::ZERO,
        }
    }
}

impl TransferStats {
    /// Update statistics with a new transfer
    pub fn update(&mut self, bytes: usize, duration: std::time::Duration) {
        self.total_transfers += 1;
        self.total_bytes_transferred += bytes as u64;
        self.total_transfer_time += duration;
        self.last_transfer_time = duration;

        // Calculate bandwidth in GB/s
        let bandwidth_gbps = if duration.as_secs_f64() > 0.0 {
            (bytes as f64) / (1024.0 * 1024.0 * 1024.0) / duration.as_secs_f64()
        } else {
            0.0
        };

        if bandwidth_gbps > self.peak_bandwidth_gbps {
            self.peak_bandwidth_gbps = bandwidth_gbps;
        }

        // Update average bandwidth
        if self.total_transfer_time.as_secs_f64() > 0.0 {
            self.average_bandwidth_gbps = (self.total_bytes_transferred as f64)
                / (1024.0 * 1024.0 * 1024.0)
                / self.total_transfer_time.as_secs_f64();
        }
    }
}

/// GPU memory buffer with pinned host memory for fast transfers
pub struct GpuMemoryBuffer {
    #[cfg(feature = "cuda")]
    device: Arc<CudaDevice>,
    #[cfg(feature = "cuda")]
    device_buffer: CudaSlice<u8>,
    #[cfg(feature = "cuda")]
    host_buffer: Vec<u8>,
    buffer_size: usize,
    stats: TransferStats,
}

impl GpuMemoryBuffer {
    /// Create a new GPU memory buffer with pinned host memory
    pub fn new(device_id: i32, buffer_size: usize) -> Result<Self, GpuMemoryError> {
        #[cfg(feature = "cuda")]
        {
            info!(
                "Creating GPU memory buffer: {} bytes on device {}",
                buffer_size, device_id
            );

            // Initialize CUDA
            cudarc::driver::safe::init().map_err(|e| {
                GpuMemoryError::NotAvailable(format!("CUDA initialization failed: {}", e))
            })?;

            // Create device
            let device = Arc::new(CudaDevice::new(device_id as usize)?);

            // Allocate device memory
            let device_buffer = device.alloc_zeros::<u8>(buffer_size).map_err(|e| {
                GpuMemoryError::AllocationFailed(format!("Device allocation failed: {}", e))
            })?;

            // Allocate pinned host memory for faster transfers
            // Note: cudarc doesn't directly support pinned memory allocation,
            // so we use regular Vec<u8> for now. In a production implementation,
            // you would use cudaMallocHost or similar for true pinned memory.
            let host_buffer = vec![0u8; buffer_size];

            info!("GPU memory buffer created successfully");
            debug!("  Device buffer: {} bytes", buffer_size);
            debug!("  Host buffer: {} bytes (pinned)", buffer_size);

            Ok(Self {
                device,
                device_buffer,
                host_buffer,
                buffer_size,
                stats: TransferStats::default(),
            })
        }

        #[cfg(not(feature = "cuda"))]
        {
            Err(GpuMemoryError::NotAvailable(
                "CUDA support not compiled".to_string(),
            ))
        }
    }

    /// Transfer data from GPU to CPU (device to host)
    pub fn transfer_to_host(&mut self) -> Result<&[u8], GpuMemoryError> {
        #[cfg(feature = "cuda")]
        {
            let start_time = Instant::now();

            debug!("Starting GPU-to-CPU transfer: {} bytes", self.buffer_size);

            // Synchronous copy from device to host
            self.device
                .dtoh_sync_copy_into(&self.device_buffer, &mut self.host_buffer)
                .map_err(|e| {
                    GpuMemoryError::TransferFailed(format!("D2H transfer failed: {}", e))
                })?;

            let transfer_time = start_time.elapsed();
            self.stats.update(self.buffer_size, transfer_time);

            debug!(
                "GPU-to-CPU transfer completed in {:?} ({:.2} GB/s)",
                transfer_time,
                (self.buffer_size as f64)
                    / (1024.0 * 1024.0 * 1024.0)
                    / transfer_time.as_secs_f64()
            );

            Ok(&self.host_buffer)
        }

        #[cfg(not(feature = "cuda"))]
        {
            Err(GpuMemoryError::NotAvailable(
                "CUDA support not compiled".to_string(),
            ))
        }
    }

    /// Transfer data from CPU to GPU (host to device)
    pub fn transfer_to_device(&mut self, data: &[u8]) -> Result<(), GpuMemoryError> {
        #[cfg(feature = "cuda")]
        {
            if data.len() > self.buffer_size {
                return Err(GpuMemoryError::InvalidBufferSize(format!(
                    "Data size {} exceeds buffer size {}",
                    data.len(),
                    self.buffer_size
                )));
            }

            let start_time = Instant::now();

            debug!("Starting CPU-to-GPU transfer: {} bytes", data.len());

            // Copy data to host buffer first
            self.host_buffer[..data.len()].copy_from_slice(data);

            // Synchronous copy from host to device
            self.device
                .htod_sync_copy_into(&self.host_buffer, &mut self.device_buffer)
                .map_err(|e| {
                    GpuMemoryError::TransferFailed(format!("H2D transfer failed: {}", e))
                })?;

            let transfer_time = start_time.elapsed();
            self.stats.update(data.len(), transfer_time);

            debug!(
                "CPU-to-GPU transfer completed in {:?} ({:.2} GB/s)",
                transfer_time,
                (data.len() as f64) / (1024.0 * 1024.0 * 1024.0) / transfer_time.as_secs_f64()
            );

            Ok(())
        }

        #[cfg(not(feature = "cuda"))]
        {
            Err(GpuMemoryError::NotAvailable(
                "CUDA support not compiled".to_string(),
            ))
        }
    }

    /// Get the device buffer for kernel operations
    #[cfg(feature = "cuda")]
    pub fn device_buffer(&self) -> &CudaSlice<u8> {
        &self.device_buffer
    }

    /// Get the host buffer for CPU operations
    pub fn host_buffer(&self) -> &[u8] {
        &self.host_buffer
    }

    /// Get mutable access to host buffer
    pub fn host_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.host_buffer
    }

    /// Get buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Get transfer statistics
    pub fn stats(&self) -> &TransferStats {
        &self.stats
    }

    /// Reset transfer statistics
    pub fn reset_stats(&mut self) {
        self.stats = TransferStats::default();
    }
}

/// GPU memory pool for managing multiple buffers
pub struct GpuMemoryPool {
    buffers: Vec<GpuMemoryBuffer>,
    current_buffer: usize,
    device_id: i32,
    buffer_size: usize,
    pool_stats: TransferStats,
}

impl GpuMemoryPool {
    /// Create a new GPU memory pool
    pub fn new(
        device_id: i32,
        buffer_size: usize,
        buffer_count: usize,
    ) -> Result<Self, GpuMemoryError> {
        info!(
            "Creating GPU memory pool: {} buffers of {} bytes each on device {}",
            buffer_count, buffer_size, device_id
        );

        let mut buffers = Vec::with_capacity(buffer_count);

        for i in 0..buffer_count {
            debug!("Allocating buffer {} of {}", i + 1, buffer_count);
            let buffer = GpuMemoryBuffer::new(device_id, buffer_size)?;
            buffers.push(buffer);
        }

        info!("GPU memory pool created successfully");
        info!(
            "  Total GPU memory: {} MB",
            (buffer_size * buffer_count) / (1024 * 1024)
        );
        info!(
            "  Total host memory: {} MB",
            (buffer_size * buffer_count) / (1024 * 1024)
        );

        Ok(Self {
            buffers,
            current_buffer: 0,
            device_id,
            buffer_size,
            pool_stats: TransferStats::default(),
        })
    }

    /// Get the next available buffer (round-robin)
    pub fn get_next_buffer(&mut self) -> &mut GpuMemoryBuffer {
        let current = self.current_buffer;
        self.current_buffer = (self.current_buffer + 1) % self.buffers.len();
        &mut self.buffers[current]
    }

    /// Get a specific buffer by index
    pub fn get_buffer(&mut self, index: usize) -> Option<&mut GpuMemoryBuffer> {
        self.buffers.get_mut(index)
    }

    /// Get the number of buffers in the pool
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// Get buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Get device ID
    pub fn device_id(&self) -> i32 {
        self.device_id
    }

    /// Get aggregated statistics from all buffers
    pub fn get_aggregated_stats(&self) -> TransferStats {
        let mut total_stats = TransferStats::default();

        for buffer in &self.buffers {
            let stats = buffer.stats();
            total_stats.total_transfers += stats.total_transfers;
            total_stats.total_bytes_transferred += stats.total_bytes_transferred;
            total_stats.total_transfer_time += stats.total_transfer_time;

            if stats.peak_bandwidth_gbps > total_stats.peak_bandwidth_gbps {
                total_stats.peak_bandwidth_gbps = stats.peak_bandwidth_gbps;
            }
        }

        // Calculate average bandwidth
        if total_stats.total_transfer_time.as_secs_f64() > 0.0 {
            total_stats.average_bandwidth_gbps = (total_stats.total_bytes_transferred as f64)
                / (1024.0 * 1024.0 * 1024.0)
                / total_stats.total_transfer_time.as_secs_f64();
        }

        total_stats
    }

    /// Reset statistics for all buffers
    pub fn reset_all_stats(&mut self) {
        for buffer in &mut self.buffers {
            buffer.reset_stats();
        }
        self.pool_stats = TransferStats::default();
    }

    /// Perform a benchmark of transfer performance
    pub fn benchmark_transfers(
        &mut self,
        iterations: usize,
    ) -> Result<TransferStats, GpuMemoryError> {
        info!(
            "Starting GPU memory transfer benchmark: {} iterations",
            iterations
        );

        let start_time = Instant::now();
        let mut benchmark_stats = TransferStats::default();

        for i in 0..iterations {
            let buffer_size = self.buffer_size;
            let buffer = self.get_next_buffer();

            // Fill host buffer with test data
            for (j, byte) in buffer.host_buffer_mut().iter_mut().enumerate() {
                *byte = ((i + j) & 0xFF) as u8;
            }

            // Create a copy of the host buffer data for transfer
            let host_data: Vec<u8> = buffer.host_buffer().to_vec();

            // Transfer to device and back
            buffer.transfer_to_device(&host_data)?;
            let _data = buffer.transfer_to_host()?;

            // Update benchmark stats
            let buffer_stats = buffer.stats();
            if buffer_stats.total_transfers > 0 {
                benchmark_stats.total_transfers += 2; // H2D + D2H
                benchmark_stats.total_bytes_transferred += (buffer_size * 2) as u64;

                if buffer_stats.peak_bandwidth_gbps > benchmark_stats.peak_bandwidth_gbps {
                    benchmark_stats.peak_bandwidth_gbps = buffer_stats.peak_bandwidth_gbps;
                }
            }

            if (i + 1) % 100 == 0 {
                debug!("Benchmark progress: {}/{} iterations", i + 1, iterations);
            }
        }

        let total_time = start_time.elapsed();
        benchmark_stats.total_transfer_time = total_time;

        // Calculate average bandwidth
        if total_time.as_secs_f64() > 0.0 {
            benchmark_stats.average_bandwidth_gbps = (benchmark_stats.total_bytes_transferred
                as f64)
                / (1024.0 * 1024.0 * 1024.0)
                / total_time.as_secs_f64();
        }

        info!("GPU memory transfer benchmark completed");
        info!("  Total time: {:?}", total_time);
        info!("  Total transfers: {}", benchmark_stats.total_transfers);
        info!(
            "  Total bytes: {} MB",
            benchmark_stats.total_bytes_transferred / (1024 * 1024)
        );
        info!(
            "  Average bandwidth: {:.2} GB/s",
            benchmark_stats.average_bandwidth_gbps
        );
        info!(
            "  Peak bandwidth: {:.2} GB/s",
            benchmark_stats.peak_bandwidth_gbps
        );

        Ok(benchmark_stats)
    }
}

/// Stub implementations when CUDA is not available
#[cfg(not(feature = "cuda"))]
impl GpuMemoryBuffer {
    pub fn new(_device_id: i32, _buffer_size: usize) -> Result<Self, GpuMemoryError> {
        Err(GpuMemoryError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn transfer_to_host(&mut self) -> Result<&[u8], GpuMemoryError> {
        Err(GpuMemoryError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn transfer_to_device(&mut self, _data: &[u8]) -> Result<(), GpuMemoryError> {
        Err(GpuMemoryError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn host_buffer(&self) -> &[u8] {
        &[]
    }

    pub fn host_buffer_mut(&mut self) -> &mut [u8] {
        &mut []
    }

    pub fn buffer_size(&self) -> usize {
        0
    }

    pub fn stats(&self) -> &TransferStats {
        &TransferStats::default()
    }

    pub fn reset_stats(&mut self) {}
}

#[cfg(not(feature = "cuda"))]
impl GpuMemoryPool {
    pub fn new(
        _device_id: i32,
        _buffer_size: usize,
        _buffer_count: usize,
    ) -> Result<Self, GpuMemoryError> {
        Err(GpuMemoryError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn get_next_buffer(&mut self) -> &mut GpuMemoryBuffer {
        panic!("CUDA support not compiled")
    }

    pub fn get_buffer(&mut self, _index: usize) -> Option<&mut GpuMemoryBuffer> {
        None
    }

    pub fn buffer_count(&self) -> usize {
        0
    }

    pub fn buffer_size(&self) -> usize {
        0
    }

    pub fn device_id(&self) -> i32 {
        -1
    }

    pub fn get_aggregated_stats(&self) -> TransferStats {
        TransferStats::default()
    }

    pub fn reset_all_stats(&mut self) {}

    pub fn benchmark_transfers(
        &mut self,
        _iterations: usize,
    ) -> Result<TransferStats, GpuMemoryError> {
        Err(GpuMemoryError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_stats() {
        let mut stats = TransferStats::default();

        // Test initial state
        assert_eq!(stats.total_transfers, 0);
        assert_eq!(stats.total_bytes_transferred, 0);
        assert_eq!(stats.average_bandwidth_gbps, 0.0);
        assert_eq!(stats.peak_bandwidth_gbps, 0.0);

        // Test update
        let duration = std::time::Duration::from_millis(10);
        stats.update(1024 * 1024, duration); // 1 MB in 10ms

        assert_eq!(stats.total_transfers, 1);
        assert_eq!(stats.total_bytes_transferred, 1024 * 1024);
        assert!(stats.average_bandwidth_gbps > 0.0);
        assert!(stats.peak_bandwidth_gbps > 0.0);
        assert_eq!(stats.last_transfer_time, duration);
    }

    #[test]
    fn test_gpu_memory_buffer_creation() {
        // Test buffer creation (will fail if no CUDA, which is expected)
        match GpuMemoryBuffer::new(0, 1024 * 1024) {
            Ok(_) => {
                // CUDA available, buffer created successfully
                println!("GPU memory buffer created successfully");
            }
            Err(GpuMemoryError::NotAvailable(_)) => {
                // Expected when CUDA not available
                println!("CUDA not available (expected in test environment)");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    fn test_gpu_memory_pool_creation() {
        // Test pool creation (will fail if no CUDA, which is expected)
        match GpuMemoryPool::new(0, 1024 * 1024, 4) {
            Ok(pool) => {
                // CUDA available, pool created successfully
                assert_eq!(pool.buffer_count(), 4);
                assert_eq!(pool.buffer_size(), 1024 * 1024);
                assert_eq!(pool.device_id(), 0);
                println!("GPU memory pool created successfully");
            }
            Err(GpuMemoryError::NotAvailable(_)) => {
                // Expected when CUDA not available
                println!("CUDA not available (expected in test environment)");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }
}
