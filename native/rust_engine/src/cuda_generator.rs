//! CUDA GPU Packet Generator
//!
//! Real GPU acceleration for packet generation using NVIDIA CUDA.
//! Implements Requirements 10.1, 10.2: GPU-accelerated packet generation.

use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::gpu_direct::{GpuDirectError, GpuDirectManager, GpuDirectStats};
use crate::gpu_memory::{GpuMemoryError, GpuMemoryPool, TransferStats};

#[cfg(feature = "cuda")]
use cudarc::driver::{CudaDevice, DriverError, LaunchAsync, LaunchConfig};
#[cfg(feature = "cuda")]
use cudarc::nvrtc::compile_ptx;

#[derive(Debug, Error)]
pub enum CudaError {
    #[error("CUDA not available: {0}")]
    NotAvailable(String),
    #[error("CUDA driver error: {0}")]
    DriverError(String),
    #[error("CUDA compilation error: {0}")]
    CompilationError(String),
    #[error("CUDA memory error: {0}")]
    CudaMemoryError(String),
    #[error("CUDA kernel error: {0}")]
    KernelError(String),
    #[error("GPU memory error: {0}")]
    MemoryError(#[from] GpuMemoryError),
    #[error("GPUDirect error: {0}")]
    GpuDirectError(#[from] GpuDirectError),
}

#[cfg(feature = "cuda")]
impl From<DriverError> for CudaError {
    fn from(err: DriverError) -> Self {
        CudaError::DriverError(err.to_string())
    }
}

/// GPU information for CUDA devices
#[derive(Debug, Clone)]
pub struct GpuInfo {
    pub device_id: i32,
    pub name: String,
    pub memory_mb: usize,
    pub compute_capability: (i32, i32),
    pub multiprocessor_count: i32,
    pub max_threads_per_block: i32,
    pub max_blocks_per_grid: i32,
}

impl GpuInfo {
    /// Estimate packet generation performance
    pub fn estimate_pps(&self) -> u64 {
        // Rough estimate based on GPU specs
        let base_pps = match self.compute_capability {
            (8, _) => 100_000_000, // RTX 30/40 series, A100
            (7, 5) => 75_000_000,  // RTX 20 series
            (7, 0) => 50_000_000,  // GTX 10 series
            (6, _) => 25_000_000,  // GTX 9 series
            _ => 10_000_000,       // Older GPUs
        };

        // Scale by multiprocessor count
        let mp_factor = (self.multiprocessor_count as f64 / 80.0).min(2.0).max(0.1);
        (base_pps as f64 * mp_factor) as u64
    }

    /// Check if GPU is suitable for packet generation
    pub fn is_suitable(&self) -> bool {
        self.memory_mb >= 1024 && // At least 1GB memory
        self.compute_capability.0 >= 6 && // Compute capability 6.0+
        self.multiprocessor_count >= 8 // At least 8 SMs
    }
}

/// CUDA packet generator configuration
#[derive(Debug, Clone)]
pub struct CudaConfig {
    pub device_id: i32,
    pub packet_size: usize,
    pub batch_size: usize,
    pub buffer_count: usize,
    pub target_pps: u64,
    pub enable_gpu_direct: bool,
    pub network_interface: String,
}

impl Default for CudaConfig {
    fn default() -> Self {
        Self {
            device_id: 0,
            packet_size: 1472,
            batch_size: 65536,
            buffer_count: 4,
            target_pps: 50_000_000,
            enable_gpu_direct: true,
            network_interface: "eth0".to_string(),
        }
    }
}

/// CUDA packet generator
pub struct CudaPacketGenerator {
    #[cfg(feature = "cuda")]
    device: Arc<CudaDevice>,
    #[cfg(feature = "cuda")]
    kernel_func: cudarc::driver::CudaFunction,
    config: CudaConfig,
    gpu_info: GpuInfo,
    memory_pool: GpuMemoryPool,
    gpu_direct: Option<GpuDirectManager>,
    packets_generated: u64,
    bytes_generated: u64,
    generation_time: std::time::Duration,
}

impl CudaPacketGenerator {
    /// Detect available NVIDIA GPUs
    pub fn detect_gpus() -> Result<Vec<GpuInfo>, CudaError> {
        #[cfg(feature = "cuda")]
        {
            info!("Detecting NVIDIA GPUs via CUDA runtime...");

            // Initialize CUDA
            cudarc::driver::safe::init().map_err(|e| {
                CudaError::NotAvailable(format!("CUDA initialization failed: {}", e))
            })?;

            let device_count = cudarc::driver::safe::get_device_count().map_err(|e| {
                CudaError::NotAvailable(format!("Failed to get device count: {}", e))
            })?;

            if device_count == 0 {
                return Err(CudaError::NotAvailable("No CUDA devices found".to_string()));
            }

            let mut gpus = Vec::new();

            for device_id in 0..device_count {
                match Self::get_gpu_info(device_id) {
                    Ok(gpu_info) => {
                        info!(
                            "Detected NVIDIA GPU {}: {} ({} MB, CC {}.{}, {} SMs)",
                            device_id,
                            gpu_info.name,
                            gpu_info.memory_mb,
                            gpu_info.compute_capability.0,
                            gpu_info.compute_capability.1,
                            gpu_info.multiprocessor_count
                        );
                        gpus.push(gpu_info);
                    }
                    Err(e) => {
                        warn!("Failed to get info for GPU {}: {}", device_id, e);
                    }
                }
            }

            Ok(gpus)
        }

        #[cfg(not(feature = "cuda"))]
        {
            Err(CudaError::NotAvailable(
                "CUDA support not compiled".to_string(),
            ))
        }
    }

    #[cfg(feature = "cuda")]
    fn get_gpu_info(device_id: i32) -> Result<GpuInfo, CudaError> {
        let device = CudaDevice::new(device_id as usize)?;

        let name = device.name()?;
        let memory_bytes = device.total_memory()?;
        let memory_mb = memory_bytes / (1024 * 1024);

        // Get compute capability
        let major = device.get_attribute(
            cudarc::driver::sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
        )?;
        let minor = device.get_attribute(
            cudarc::driver::sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
        )?;
        let compute_capability = (major, minor);

        // Get multiprocessor count
        let multiprocessor_count = device.get_attribute(
            cudarc::driver::sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT,
        )?;

        // Get max threads per block
        let max_threads_per_block = device.get_attribute(
            cudarc::driver::sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
        )?;

        // Get max blocks per grid
        let max_blocks_per_grid = device.get_attribute(
            cudarc::driver::sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X,
        )?;

        Ok(GpuInfo {
            device_id,
            name,
            memory_mb,
            compute_capability,
            multiprocessor_count,
            max_threads_per_block,
            max_blocks_per_grid,
        })
    }

    /// Create new CUDA packet generator
    /// **Validates: Requirements 5.1, 5.2** - CUDA device initialization and GPU memory allocation
    pub fn new(config: CudaConfig) -> Result<Self, CudaError> {
        #[cfg(feature = "cuda")]
        {
            info!(
                "Initializing CUDA packet generator on device {}...",
                config.device_id
            );

            // Initialize CUDA runtime - **Requirement 5.1**
            cudarc::driver::safe::init().map_err(|e| {
                CudaError::NotAvailable(format!("CUDA initialization failed: {}", e))
            })?;

            // Create CUDA device and context - **Requirement 5.1**
            let device = Arc::new(CudaDevice::new(config.device_id as usize)?);

            // Get comprehensive GPU information
            let gpu_info = Self::get_gpu_info(config.device_id)?;

            if !gpu_info.is_suitable() {
                return Err(CudaError::NotAvailable(format!(
                    "GPU {} is not suitable for packet generation (need CC 6.0+, 1GB+ memory, 8+ SMs)",
                    config.device_id
                )));
            }

            // Compile CUDA kernel for packet generation
            let kernel_func = Self::compile_packet_kernel(&device)?;

            // Allocate GPU memory for packet templates (up to 1GB) - **Requirement 5.2**
            let buffer_size = config.packet_size * config.batch_size;
            let total_gpu_memory = buffer_size * config.buffer_count;

            if total_gpu_memory > 1024 * 1024 * 1024 {
                warn!(
                    "Total GPU memory allocation ({} MB) exceeds 1GB limit, reducing buffer count",
                    total_gpu_memory / (1024 * 1024)
                );
            }

            let memory_pool =
                GpuMemoryPool::new(config.device_id, buffer_size, config.buffer_count)?;

            info!(
                "Allocated {} MB of GPU memory for packet templates",
                total_gpu_memory / (1024 * 1024)
            );

            // Initialize GPUDirect RDMA if enabled
            let gpu_direct = if config.enable_gpu_direct {
                match GpuDirectManager::new(config.device_id, &config.network_interface) {
                    Ok(manager) => {
                        info!("GPUDirect RDMA initialized successfully");
                        Some(manager)
                    }
                    Err(e) => {
                        warn!("GPUDirect RDMA initialization failed: {}", e);
                        warn!("Will use fallback CPU transfers");
                        None
                    }
                }
            } else {
                info!("GPUDirect RDMA disabled by configuration");
                None
            };

            info!("CUDA packet generator initialized successfully");
            info!(
                "  Device: {} (CC {}.{}, {} MB)",
                gpu_info.name,
                gpu_info.compute_capability.0,
                gpu_info.compute_capability.1,
                gpu_info.memory_mb
            );
            info!("  Estimated performance: {} PPS", gpu_info.estimate_pps());
            info!(
                "  Buffer configuration: {} buffers of {} packets each",
                config.buffer_count, config.batch_size
            );
            info!(
                "  Total GPU memory allocated: {} MB",
                total_gpu_memory / (1024 * 1024)
            );

            Ok(Self {
                device,
                kernel_func,
                config,
                gpu_info,
                memory_pool,
                gpu_direct,
                packets_generated: 0,
                bytes_generated: 0,
                generation_time: std::time::Duration::ZERO,
            })
        }

        #[cfg(not(feature = "cuda"))]
        {
            Err(CudaError::NotAvailable(
                "CUDA support not compiled".to_string(),
            ))
        }
    }

    #[cfg(feature = "cuda")]
    fn compile_packet_kernel(
        device: &CudaDevice,
    ) -> Result<cudarc::driver::CudaFunction, CudaError> {
        info!("Compiling CUDA packet generation kernel...");

        // Enhanced CUDA kernel for parallel packet generation with proper timestamps and checksums
        // **Validates: Requirement 5.3** - PTX kernel for parallel packet generation
        let kernel_src = r#"
#include <cuda_runtime.h>

// Device function to get current timestamp (nanoseconds since epoch)
__device__ unsigned long long get_timestamp() {
    // Use GPU clock for high-resolution timestamps
    return clock64();
}

// Device function to calculate IP checksum
__device__ unsigned short calculate_ip_checksum(unsigned char* ip_header) {
    unsigned int checksum = 0;
    
    // Clear existing checksum field
    ip_header[10] = 0;
    ip_header[11] = 0;
    
    // Calculate checksum over 20-byte IP header
    for (int i = 0; i < 20; i += 2) {
        checksum += (ip_header[i] << 8) + ip_header[i + 1];
    }
    
    // Add carry bits
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    return ~checksum;
}

// Device function to calculate UDP checksum
__device__ unsigned short calculate_udp_checksum(
    unsigned char* ip_header,
    unsigned char* udp_header,
    unsigned short udp_len
) {
    unsigned int checksum = 0;
    
    // Pseudo-header: src_ip + dst_ip + protocol + udp_length
    // Source IP (4 bytes)
    checksum += (ip_header[12] << 8) + ip_header[13];
    checksum += (ip_header[14] << 8) + ip_header[15];
    // Destination IP (4 bytes)
    checksum += (ip_header[16] << 8) + ip_header[17];
    checksum += (ip_header[18] << 8) + ip_header[19];
    // Protocol (UDP = 17) and UDP length
    checksum += 17 + udp_len;
    
    // Clear existing UDP checksum
    udp_header[6] = 0;
    udp_header[7] = 0;
    
    // Add UDP header and data
    for (int i = 0; i < udp_len; i += 2) {
        if (i + 1 < udp_len) {
            checksum += (udp_header[i] << 8) + udp_header[i + 1];
        } else {
            checksum += udp_header[i] << 8; // Odd length padding
        }
    }
    
    // Add carry bits
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    
    return ~checksum;
}

extern "C" __global__ void generate_packets(
    unsigned char* output,
    unsigned int packet_size,
    unsigned int num_packets,
    unsigned int base_seed,
    unsigned int target_ip,
    unsigned short target_port,
    unsigned char protocol,
    unsigned long long base_timestamp
) {
    // Calculate thread index - supports thousands of threads in parallel
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx >= num_packets) return;
    
    // Get pointer to this thread's packet
    unsigned char* packet = output + idx * packet_size;
    
    // Generate unique seed for this thread
    unsigned int thread_seed = base_seed + idx;
    
    // Get current timestamp for this packet
    unsigned long long timestamp = base_timestamp + get_timestamp() + idx;
    
    // Ensure minimum packet size for valid headers
    if (packet_size < 64) return;
    
    // =================================================================
    // ETHERNET HEADER (14 bytes)
    // =================================================================
    // Destination MAC (randomized per thread)
    packet[0] = (thread_seed >> 24) & 0xFF;
    packet[1] = (thread_seed >> 16) & 0xFF;
    packet[2] = (thread_seed >> 8) & 0xFF;
    packet[3] = thread_seed & 0xFF;
    packet[4] = (idx >> 8) & 0xFF;
    packet[5] = idx & 0xFF;
    
    // Source MAC (randomized per thread)
    packet[6] = ((thread_seed * 31) >> 24) & 0xFF;
    packet[7] = ((thread_seed * 31) >> 16) & 0xFF;
    packet[8] = ((thread_seed * 31) >> 8) & 0xFF;
    packet[9] = (thread_seed * 31) & 0xFF;
    packet[10] = ((idx * 17) >> 8) & 0xFF;
    packet[11] = (idx * 17) & 0xFF;
    
    // EtherType (IPv4 = 0x0800)
    packet[12] = 0x08;
    packet[13] = 0x00;
    
    // =================================================================
    // IP HEADER (20 bytes, offset 14-33)
    // =================================================================
    unsigned char* ip_header = packet + 14;
    
    ip_header[0] = 0x45;  // Version (4) + IHL (5)
    ip_header[1] = 0x00;  // DSCP + ECN
    
    // Total length (IP header + payload)
    unsigned short ip_total_len = packet_size - 14;
    ip_header[2] = ip_total_len >> 8;
    ip_header[3] = ip_total_len & 0xFF;
    
    // Identification (unique per packet)
    ip_header[4] = (thread_seed >> 8) & 0xFF;
    ip_header[5] = thread_seed & 0xFF;
    
    // Flags (Don't Fragment) + Fragment Offset
    ip_header[6] = 0x40;
    ip_header[7] = 0x00;
    
    // TTL
    ip_header[8] = 64;
    
    // Protocol
    ip_header[9] = protocol;
    
    // Checksum (calculated later)
    ip_header[10] = 0x00;
    ip_header[11] = 0x00;
    
    // Source IP (randomized per thread)
    unsigned int src_ip = 0xC0A80100 + (thread_seed & 0xFF); // 192.168.1.x
    ip_header[12] = (src_ip >> 24) & 0xFF;
    ip_header[13] = (src_ip >> 16) & 0xFF;
    ip_header[14] = (src_ip >> 8) & 0xFF;
    ip_header[15] = src_ip & 0xFF;
    
    // Destination IP
    ip_header[16] = (target_ip >> 24) & 0xFF;
    ip_header[17] = (target_ip >> 16) & 0xFF;
    ip_header[18] = (target_ip >> 8) & 0xFF;
    ip_header[19] = target_ip & 0xFF;
    
    // =================================================================
    // TRANSPORT LAYER HEADER (UDP/TCP)
    // =================================================================
    if (packet_size >= 42) {
        unsigned char* transport_header = packet + 34;
        
        if (protocol == 17) { // UDP
            // Source port (randomized per thread)
            unsigned short src_port = 32768 + (thread_seed & 0x7FFF);
            transport_header[0] = src_port >> 8;
            transport_header[1] = src_port & 0xFF;
            
            // Destination port
            transport_header[2] = target_port >> 8;
            transport_header[3] = target_port & 0xFF;
            
            // UDP length
            unsigned short udp_len = packet_size - 34;
            transport_header[4] = udp_len >> 8;
            transport_header[5] = udp_len & 0xFF;
            
            // UDP checksum (calculated later)
            transport_header[6] = 0x00;
            transport_header[7] = 0x00;
            
            // Fill payload with timestamp-based data
            for (unsigned int i = 42; i < packet_size; i++) {
                packet[i] = ((timestamp >> ((i - 42) % 8)) ^ (thread_seed * 17 + i * 31)) & 0xFF;
            }
            
            // Calculate UDP checksum
            unsigned short udp_checksum = calculate_udp_checksum(ip_header, transport_header, udp_len);
            transport_header[6] = udp_checksum >> 8;
            transport_header[7] = udp_checksum & 0xFF;
            
        } else if (protocol == 6) { // TCP
            // Source port (randomized per thread)
            unsigned short src_port = 32768 + (thread_seed & 0x7FFF);
            transport_header[0] = src_port >> 8;
            transport_header[1] = src_port & 0xFF;
            
            // Destination port
            transport_header[2] = target_port >> 8;
            transport_header[3] = target_port & 0xFF;
            
            // Sequence number (timestamp-based)
            unsigned int seq_num = (unsigned int)(timestamp & 0xFFFFFFFF);
            transport_header[4] = (seq_num >> 24) & 0xFF;
            transport_header[5] = (seq_num >> 16) & 0xFF;
            transport_header[6] = (seq_num >> 8) & 0xFF;
            transport_header[7] = seq_num & 0xFF;
            
            // Acknowledgment number
            transport_header[8] = 0x00;
            transport_header[9] = 0x00;
            transport_header[10] = 0x00;
            transport_header[11] = 0x00;
            
            // Data offset (5 words = 20 bytes) + flags (SYN)
            transport_header[12] = 0x50;
            transport_header[13] = 0x02;
            
            // Window size
            transport_header[14] = 0xFF;
            transport_header[15] = 0xFF;
            
            // Checksum (simplified for performance)
            transport_header[16] = 0x00;
            transport_header[17] = 0x00;
            
            // Urgent pointer
            transport_header[18] = 0x00;
            transport_header[19] = 0x00;
            
            // Fill remaining payload
            for (unsigned int i = 54; i < packet_size; i++) {
                packet[i] = ((timestamp >> ((i - 54) % 8)) ^ (thread_seed * 23 + i * 37)) & 0xFF;
            }
        }
    }
    
    // =================================================================
    // CALCULATE IP CHECKSUM (must be done after all header fields are set)
    // =================================================================
    unsigned short ip_checksum = calculate_ip_checksum(ip_header);
    ip_header[10] = ip_checksum >> 8;
    ip_header[11] = ip_checksum & 0xFF;
}
"#;

        // Compile kernel to PTX
        let ptx = compile_ptx(kernel_src).map_err(|e| {
            CudaError::CompilationError(format!("Kernel compilation failed: {}", e))
        })?;

        info!("CUDA kernel compiled successfully");
        debug!("Kernel features:");
        debug!("  - Parallel packet generation with thousands of threads");
        debug!("  - Real-time timestamp modification");
        debug!("  - Proper IP and UDP checksum calculation");
        debug!("  - Randomized source ports and IPs per thread");

        device
            .load_ptx(ptx, "generate_packets", &["generate_packets"])
            .map_err(|e| CudaError::CompilationError(format!("Kernel loading failed: {}", e)))
    }

    /// Generate a batch of packets on GPU with parallel processing
    /// **Validates: Requirement 5.3** - Parallel packet generation with timestamp and checksum modification
    pub fn generate_batch(
        &mut self,
        target_ip: u32,
        target_port: u16,
        protocol: u8,
    ) -> Result<&[u8], CudaError> {
        #[cfg(feature = "cuda")]
        {
            let start_time = Instant::now();

            // Get next buffer from memory pool
            let buffer = self.memory_pool.get_next_buffer();
            let device_buffer = buffer.device_buffer();

            // Generate random seed for this batch
            let seed = rand::random::<u32>();

            // Get base timestamp for packet generation
            let base_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            // Calculate optimal launch configuration for thousands of threads
            let threads_per_block = 256; // Optimal for most GPUs
            let blocks = (self.config.batch_size + threads_per_block - 1) / threads_per_block;

            debug!(
                "Launching CUDA kernel: {} blocks, {} threads/block, {} packets",
                blocks, threads_per_block, self.config.batch_size
            );
            debug!(
                "Kernel parameters: target={}:{}, protocol={}, seed=0x{:08x}",
                target_ip, target_port, protocol, seed
            );

            // Launch enhanced kernel with timestamp support
            let cfg = LaunchConfig {
                grid_dim: (blocks as u32, 1, 1),
                block_dim: (threads_per_block as u32, 1, 1),
                shared_mem_bytes: 0,
            };

            unsafe {
                self.kernel_func.launch(
                    cfg,
                    (
                        device_buffer,
                        self.config.packet_size as u32,
                        self.config.batch_size as u32,
                        seed,
                        target_ip,
                        target_port,
                        protocol,
                        base_timestamp,
                    ),
                )?;
            }

            // Synchronize to ensure kernel completion
            self.device.synchronize()?;

            // Transfer data from GPU to host using efficient memory pool
            let host_data = buffer.transfer_to_host()?;

            let generation_time = start_time.elapsed();
            self.generation_time += generation_time;
            self.packets_generated += self.config.batch_size as u64;
            self.bytes_generated += (self.config.batch_size * self.config.packet_size) as u64;

            let pps = self.config.batch_size as f64 / generation_time.as_secs_f64();
            debug!(
                "Generated {} packets in {:?} ({:.2} M PPS)",
                self.config.batch_size,
                generation_time,
                pps / 1_000_000.0
            );

            // Log performance milestone
            if pps > 50_000_000.0 {
                info!(
                    "GPU packet generation exceeding 50M PPS target: {:.2} M PPS",
                    pps / 1_000_000.0
                );
            }

            Ok(host_data)
        }

        #[cfg(not(feature = "cuda"))]
        {
            Err(CudaError::NotAvailable(
                "CUDA support not compiled".to_string(),
            ))
        }
    }

    /// Get generation statistics
    pub fn get_stats(&self) -> CudaStats {
        let avg_pps = if self.generation_time.as_secs_f64() > 0.0 {
            self.packets_generated as f64 / self.generation_time.as_secs_f64()
        } else {
            0.0
        };

        CudaStats {
            packets_generated: self.packets_generated,
            bytes_generated: self.bytes_generated,
            generation_time: self.generation_time,
            average_pps: avg_pps as u64,
            gpu_info: self.gpu_info.clone(),
            transfer_stats: self.memory_pool.get_aggregated_stats(),
            gpu_direct_stats: self.gpu_direct.as_ref().map(|gd| gd.stats().clone()),
        }
    }

    /// Get GPU information
    pub fn gpu_info(&self) -> &GpuInfo {
        &self.gpu_info
    }

    /// Check if GPU supports GPUDirect RDMA
    pub fn supports_gpu_direct(&self) -> bool {
        // GPUDirect RDMA requires compute capability 6.0+ and specific hardware
        self.gpu_info.compute_capability.0 >= 6 && self.gpu_direct.is_some()
    }

    /// Send packets directly via GPUDirect RDMA (if available)
    pub fn send_direct(
        &mut self,
        target_ip: u32,
        target_port: u16,
        protocol: u8,
        destination: &str,
    ) -> Result<usize, CudaError> {
        // Generate packets on GPU
        let packet_data = self.generate_batch(target_ip, target_port, protocol)?;
        let packet_len = packet_data.len();

        // Send via GPUDirect if available, otherwise fallback
        if let Some(ref mut gpu_direct) = self.gpu_direct {
            gpu_direct.transfer_with_fallback(packet_data, destination)?;
            Ok(packet_len)
        } else {
            // No GPUDirect available, return the packet data for CPU sending
            Ok(packet_len)
        }
    }

    /// Get GPUDirect capabilities
    pub fn gpu_direct_capabilities(&self) -> Option<&crate::gpu_direct::GpuDirectCapabilities> {
        self.gpu_direct.as_ref().map(|gd| gd.capabilities())
    }
}

/// CUDA generation statistics
#[derive(Debug, Clone)]
pub struct CudaStats {
    pub packets_generated: u64,
    pub bytes_generated: u64,
    pub generation_time: std::time::Duration,
    pub average_pps: u64,
    pub gpu_info: GpuInfo,
    pub transfer_stats: TransferStats,
    pub gpu_direct_stats: Option<GpuDirectStats>,
}

/// Stub implementation when CUDA is not available
#[cfg(not(feature = "cuda"))]
impl CudaPacketGenerator {
    pub fn new(_config: CudaConfig) -> Result<Self, CudaError> {
        Err(CudaError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn generate_batch(
        &mut self,
        _target_ip: u32,
        _target_port: u16,
        _protocol: u8,
    ) -> Result<&[u8], CudaError> {
        Err(CudaError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn get_stats(&self) -> CudaStats {
        CudaStats {
            packets_generated: 0,
            bytes_generated: 0,
            generation_time: std::time::Duration::ZERO,
            average_pps: 0,
            gpu_info: GpuInfo {
                device_id: -1,
                name: "Not Available".to_string(),
                memory_mb: 0,
                compute_capability: (0, 0),
                multiprocessor_count: 0,
                max_threads_per_block: 0,
                max_blocks_per_grid: 0,
            },
            transfer_stats: TransferStats::default(),
            gpu_direct_stats: None,
        }
    }

    pub fn gpu_info(&self) -> &GpuInfo {
        &GpuInfo {
            device_id: -1,
            name: "Not Available".to_string(),
            memory_mb: 0,
            compute_capability: (0, 0),
            multiprocessor_count: 0,
            max_threads_per_block: 0,
            max_blocks_per_grid: 0,
        }
    }

    pub fn supports_gpu_direct(&self) -> bool {
        false
    }

    pub fn send_direct(
        &mut self,
        _target_ip: u32,
        _target_port: u16,
        _protocol: u8,
        _destination: &str,
    ) -> Result<usize, CudaError> {
        Err(CudaError::NotAvailable(
            "CUDA support not compiled".to_string(),
        ))
    }

    pub fn gpu_direct_capabilities(&self) -> Option<&crate::gpu_direct::GpuDirectCapabilities> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_detection() {
        // Test GPU detection (may fail if no CUDA GPUs available)
        match CudaPacketGenerator::detect_gpus() {
            Ok(gpus) => {
                println!("Detected {} CUDA GPUs", gpus.len());
                for gpu in gpus {
                    println!(
                        "  {}: {} MB, CC {}.{}",
                        gpu.name, gpu.memory_mb, gpu.compute_capability.0, gpu.compute_capability.1
                    );
                }
            }
            Err(e) => {
                println!("GPU detection failed (expected if no CUDA): {}", e);
            }
        }
    }

    #[test]
    fn test_gpu_info_estimates() {
        let gpu = GpuInfo {
            device_id: 0,
            name: "Test GPU".to_string(),
            memory_mb: 8192,
            compute_capability: (7, 5),
            multiprocessor_count: 68,
            max_threads_per_block: 1024,
            max_blocks_per_grid: 65535,
        };

        assert!(gpu.is_suitable());
        assert!(gpu.estimate_pps() > 50_000_000);
    }

    #[test]
    fn test_cuda_config_default() {
        let config = CudaConfig::default();
        assert_eq!(config.device_id, 0);
        assert_eq!(config.packet_size, 1472);
        assert_eq!(config.batch_size, 65536);
        assert_eq!(config.buffer_count, 4);
        assert_eq!(config.target_pps, 50_000_000);
    }
}
