// Real-Time Adaptive Scaling Module
// Implements Requirements 21.1, 21.2, 21.3, 21.4, 21.5
//
// This module provides real-time performance monitoring and adaptive scaling
// to automatically adjust system resources based on CPU usage, memory pressure,
// and packet loss rates.

use crate::engine::EngineConfig;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Performance metrics collected in real-time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// CPU usage percentage (0.0 to 100.0)
    pub cpu_usage: f32,
    /// Memory usage percentage (0.0 to 100.0)
    pub memory_usage: f32,
    /// Packet loss rate percentage (0.0 to 100.0)
    pub packet_loss: f32,
    /// Current packets per second
    pub current_pps: u64,
    /// Target packets per second
    pub target_pps: u64,
    /// Timestamp when metrics were collected (seconds since UNIX epoch)
    pub timestamp_secs: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            packet_loss: 0.0,
            current_pps: 0,
            target_pps: 0,
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Configuration adjustment recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAdjustment {
    /// New thread count (None = no change)
    pub thread_count: Option<u32>,
    /// New buffer size in bytes (None = no change)
    pub buffer_size: Option<usize>,
    /// New rate limit in PPS (None = no change)
    pub rate_limit: Option<u64>,
    /// New batch size (None = no change)
    pub batch_size: Option<u32>,
    /// Reason for adjustment
    pub reason: String,
}

impl ConfigAdjustment {
    pub fn new(reason: String) -> Self {
        Self {
            thread_count: None,
            buffer_size: None,
            rate_limit: None,
            batch_size: None,
            reason,
        }
    }
}

/// Real-time performance monitor
pub struct PerformanceMonitor {
    /// Current CPU usage (0-100)
    cpu_usage: Arc<AtomicU32>,
    /// Current memory usage in bytes
    memory_usage: Arc<AtomicU64>,
    /// Total system memory in bytes
    total_memory: u64,
    /// Packets sent counter
    packets_sent: Arc<AtomicU64>,
    /// Packets dropped counter
    packets_dropped: Arc<AtomicU64>,
    /// Last measurement timestamp
    last_measurement: Arc<AtomicU64>,
    /// Monitoring thread handle
    monitor_thread: Option<thread::JoinHandle<()>>,
    /// Stop monitoring flag
    stop_monitoring: Arc<AtomicBool>,
    /// Historical metrics for trend analysis
    metrics_history: Arc<std::sync::Mutex<VecDeque<PerformanceMetrics>>>,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new() -> Self {
        let total_memory = Self::get_total_memory();

        Self {
            cpu_usage: Arc::new(AtomicU32::new(0)),
            memory_usage: Arc::new(AtomicU64::new(0)),
            total_memory,
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_dropped: Arc::new(AtomicU64::new(0)),
            last_measurement: Arc::new(AtomicU64::new(0)),
            monitor_thread: None,
            stop_monitoring: Arc::new(AtomicBool::new(false)),
            metrics_history: Arc::new(std::sync::Mutex::new(VecDeque::with_capacity(60))), // 1 minute of history at 1Hz
        }
    }

    /// Start real-time monitoring
    /// Implements Requirement 21.1: Monitor CPU usage, memory pressure, and packet loss
    pub fn start_monitoring(&mut self) {
        if self.monitor_thread.is_some() {
            return; // Already monitoring
        }

        self.stop_monitoring.store(false, Ordering::Relaxed);

        let cpu_usage = Arc::clone(&self.cpu_usage);
        let memory_usage = Arc::clone(&self.memory_usage);
        let total_memory = self.total_memory;
        let packets_sent = Arc::clone(&self.packets_sent);
        let packets_dropped = Arc::clone(&self.packets_dropped);
        let last_measurement = Arc::clone(&self.last_measurement);
        let stop_monitoring = Arc::clone(&self.stop_monitoring);
        let metrics_history = Arc::clone(&self.metrics_history);

        let handle = thread::spawn(move || {
            let mut last_cpu_time = Self::get_cpu_time();
            let mut last_total_time = Self::get_total_cpu_time();

            while !stop_monitoring.load(Ordering::Relaxed) {
                // Measure CPU usage
                let current_cpu_time = Self::get_cpu_time();
                let current_total_time = Self::get_total_cpu_time();

                let cpu_delta = current_cpu_time.saturating_sub(last_cpu_time);
                let total_delta = current_total_time.saturating_sub(last_total_time);

                let cpu_percent = if total_delta > 0 {
                    ((cpu_delta as f64 / total_delta as f64) * 100.0).min(100.0) as u32
                } else {
                    0
                };

                cpu_usage.store(cpu_percent, Ordering::Relaxed);
                last_cpu_time = current_cpu_time;
                last_total_time = current_total_time;

                // Measure memory usage
                let current_memory = Self::get_memory_usage();
                memory_usage.store(current_memory, Ordering::Relaxed);

                // Calculate packet loss rate
                let sent = packets_sent.load(Ordering::Relaxed);
                let dropped = packets_dropped.load(Ordering::Relaxed);
                let total_packets = sent + dropped;

                let packet_loss_percent = if total_packets > 0 {
                    ((dropped as f64 / total_packets as f64) * 100.0) as f32
                } else {
                    0.0
                };

                // Store metrics in history
                let metrics = PerformanceMetrics {
                    cpu_usage: cpu_percent as f32,
                    memory_usage: if total_memory > 0 {
                        (current_memory as f64 / total_memory as f64 * 100.0) as f32
                    } else {
                        0.0
                    },
                    packet_loss: packet_loss_percent,
                    current_pps: sent, // This will be calculated properly by the caller
                    target_pps: 0,     // This will be set by the caller
                    timestamp_secs: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };

                if let Ok(mut history) = metrics_history.lock() {
                    history.push_back(metrics);
                    if history.len() > 60 {
                        history.pop_front();
                    }
                }

                // Update timestamp
                last_measurement.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                // Sleep for 1 second
                thread::sleep(Duration::from_secs(1));
            }
        });

        self.monitor_thread = Some(handle);
    }

    /// Stop monitoring
    pub fn stop_monitoring(&mut self) {
        self.stop_monitoring.store(true, Ordering::Relaxed);

        if let Some(handle) = self.monitor_thread.take() {
            let _ = handle.join();
        }
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        let cpu = self.cpu_usage.load(Ordering::Relaxed) as f32;
        let memory_bytes = self.memory_usage.load(Ordering::Relaxed);
        let memory_percent = if self.total_memory > 0 {
            (memory_bytes as f64 / self.total_memory as f64 * 100.0) as f32
        } else {
            0.0
        };

        let sent = self.packets_sent.load(Ordering::Relaxed);
        let dropped = self.packets_dropped.load(Ordering::Relaxed);
        let total_packets = sent + dropped;

        let packet_loss = if total_packets > 0 {
            (dropped as f64 / total_packets as f64 * 100.0) as f32
        } else {
            0.0
        };

        PerformanceMetrics {
            cpu_usage: cpu,
            memory_usage: memory_percent,
            packet_loss,
            current_pps: sent,
            target_pps: 0, // Will be set by caller
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Update packet counters
    pub fn update_packet_stats(&self, sent: u64, dropped: u64) {
        self.packets_sent.store(sent, Ordering::Relaxed);
        self.packets_dropped.store(dropped, Ordering::Relaxed);
    }

    /// Get metrics history for trend analysis
    pub fn get_metrics_history(&self) -> Vec<PerformanceMetrics> {
        if let Ok(history) = self.metrics_history.lock() {
            history.iter().cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Check if monitoring is active
    pub fn is_monitoring(&self) -> bool {
        self.monitor_thread.is_some() && !self.stop_monitoring.load(Ordering::Relaxed)
    }

    // Platform-specific implementations for system metrics

    #[cfg(target_os = "linux")]
    fn get_cpu_time() -> u64 {
        // Read from /proc/stat
        if let Ok(contents) = std::fs::read_to_string("/proc/stat") {
            if let Some(line) = contents.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 4 && parts[0] == "cpu" {
                    // user + nice + system + idle + iowait + irq + softirq
                    let user: u64 = parts[1].parse().unwrap_or(0);
                    let nice: u64 = parts[2].parse().unwrap_or(0);
                    let system: u64 = parts[3].parse().unwrap_or(0);
                    return user + nice + system;
                }
            }
        }
        0
    }

    #[cfg(target_os = "linux")]
    fn get_total_cpu_time() -> u64 {
        // Read from /proc/stat
        if let Ok(contents) = std::fs::read_to_string("/proc/stat") {
            if let Some(line) = contents.lines().next() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 7 && parts[0] == "cpu" {
                    // Sum all CPU time fields
                    let mut total = 0u64;
                    for i in 1..8 {
                        total += parts[i].parse().unwrap_or(0);
                    }
                    return total;
                }
            }
        }
        0
    }

    #[cfg(target_os = "linux")]
    fn get_memory_usage() -> u64 {
        // Read from /proc/meminfo
        if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;

            for line in contents.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        total = value.parse().unwrap_or(0) * 1024; // Convert KB to bytes
                    }
                } else if line.starts_with("MemAvailable:") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        available = value.parse().unwrap_or(0) * 1024; // Convert KB to bytes
                    }
                }
            }

            return total.saturating_sub(available);
        }
        0
    }

    #[cfg(target_os = "linux")]
    fn get_total_memory() -> u64 {
        // Read from /proc/meminfo
        if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
            for line in contents.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(value) = line.split_whitespace().nth(1) {
                        return value.parse().unwrap_or(0) * 1024; // Convert KB to bytes
                    }
                }
            }
        }
        0
    }

    // Windows implementations
    #[cfg(target_os = "windows")]
    fn get_cpu_time() -> u64 {
        // Use Windows API to get CPU time
        // This is a simplified implementation
        0
    }

    #[cfg(target_os = "windows")]
    fn get_total_cpu_time() -> u64 {
        // Use Windows API to get total CPU time
        // This is a simplified implementation
        100
    }

    #[cfg(target_os = "windows")]
    fn get_memory_usage() -> u64 {
        // Use Windows API to get memory usage
        // This is a simplified implementation
        0
    }

    #[cfg(target_os = "windows")]
    fn get_total_memory() -> u64 {
        // Use Windows API to get total memory
        // This is a simplified implementation
        8 * 1024 * 1024 * 1024 // 8GB default
    }

    // macOS implementations
    #[cfg(target_os = "macos")]
    fn get_cpu_time() -> u64 {
        // Use macOS system calls to get CPU time
        // This is a simplified implementation
        0
    }

    #[cfg(target_os = "macos")]
    fn get_total_cpu_time() -> u64 {
        // Use macOS system calls to get total CPU time
        // This is a simplified implementation
        100
    }

    #[cfg(target_os = "macos")]
    fn get_memory_usage() -> u64 {
        // Use macOS system calls to get memory usage
        // This is a simplified implementation
        0
    }

    #[cfg(target_os = "macos")]
    fn get_total_memory() -> u64 {
        // Use macOS system calls to get total memory
        // This is a simplified implementation
        8 * 1024 * 1024 * 1024 // 8GB default
    }
}

impl Drop for PerformanceMonitor {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_monitor_creation() {
        let monitor = PerformanceMonitor::new();
        assert!(!monitor.is_monitoring());
    }

    #[test]
    fn test_performance_monitor_start_stop() {
        let mut monitor = PerformanceMonitor::new();

        monitor.start_monitoring();
        assert!(monitor.is_monitoring());

        // Let it run for a short time
        thread::sleep(Duration::from_millis(100));

        monitor.stop_monitoring();
        assert!(!monitor.is_monitoring());
    }

    #[test]
    fn test_metrics_collection() {
        let monitor = PerformanceMonitor::new();
        let metrics = monitor.get_metrics();

        // Metrics should be initialized
        assert!(metrics.cpu_usage >= 0.0);
        assert!(metrics.memory_usage >= 0.0);
        assert!(metrics.packet_loss >= 0.0);
    }

    #[test]
    fn test_packet_stats_update() {
        let monitor = PerformanceMonitor::new();

        monitor.update_packet_stats(1000, 10);
        let metrics = monitor.get_metrics();

        assert_eq!(metrics.current_pps, 1000);
        assert_eq!(metrics.packet_loss, 1.0); // 10/1010 * 100 ≈ 1.0%
    }
}

/// Adaptive performance scaler
/// Implements Requirements 21.2, 21.3, 21.4, 21.5
pub struct AdaptiveScaler {
    /// Performance monitor
    monitor: PerformanceMonitor,
    /// Current engine configuration
    current_config: AdaptiveEngineConfig,
    /// Hardware profile for scaling decisions
    hardware_profile: HardwareProfile,
    /// Adjustment interval
    adjustment_interval: Duration,
    /// Last adjustment time
    last_adjustment: Instant,
    /// Scaling history for oscillation prevention
    adjustment_history: VecDeque<ConfigAdjustment>,
}

/// Engine configuration for adaptive scaling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveEngineConfig {
    /// Number of worker threads
    pub threads: u32,
    /// Buffer size in bytes
    pub buffer_size: usize,
    /// Rate limit in packets per second (0 = unlimited)
    pub rate_limit: u64,
    /// Batch size for packet operations
    pub batch_size: u32,
    /// Target packets per second
    pub target_pps: u64,
}

impl Default for AdaptiveEngineConfig {
    fn default() -> Self {
        Self {
            threads: 4,
            buffer_size: 64 * 1024 * 1024, // 64MB
            rate_limit: 0,
            batch_size: 64,
            target_pps: 100_000,
        }
    }
}

/// Hardware profile for scaling decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// Number of CPU cores
    pub cpu_cores: u32,
    /// Total RAM in bytes
    pub total_ram: u64,
    /// Network interface speed in Mbps
    pub nic_speed: u32,
    /// Device tier classification
    pub tier: DeviceTier,
}

/// Device tier classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DeviceTier {
    /// Low-end: 1-2 cores, <4GB RAM, ≤100Mbps NIC
    Low,
    /// Medium: 4-8 cores, 4-16GB RAM, 1Gbps NIC
    Medium,
    /// High: 8-32 cores, 16-64GB RAM, 10Gbps NIC
    High,
    /// Enterprise: 32+ cores, 64GB+ RAM, 25Gbps+ NIC
    Enterprise,
}

impl DeviceTier {
    /// Get default configuration for this tier
    pub fn get_default_config(&self) -> AdaptiveEngineConfig {
        match self {
            DeviceTier::Low => AdaptiveEngineConfig {
                threads: 1,
                buffer_size: 64 * 1024 * 1024, // 64MB
                rate_limit: 50_000,            // 50K PPS limit
                batch_size: 16,
                target_pps: 50_000,
            },
            DeviceTier::Medium => AdaptiveEngineConfig {
                threads: 4,
                buffer_size: 256 * 1024 * 1024, // 256MB
                rate_limit: 500_000,            // 500K PPS limit
                batch_size: 64,
                target_pps: 500_000,
            },
            DeviceTier::High => AdaptiveEngineConfig {
                threads: 16,
                buffer_size: 2 * 1024 * 1024 * 1024, // 2GB
                rate_limit: 10_000_000,              // 10M PPS limit
                batch_size: 256,
                target_pps: 10_000_000,
            },
            DeviceTier::Enterprise => AdaptiveEngineConfig {
                threads: 64,
                buffer_size: 8 * 1024 * 1024 * 1024, // 8GB
                rate_limit: 100_000_000,             // 100M PPS limit
                batch_size: 1024,
                target_pps: 100_000_000,
            },
        }
    }

    /// Get tier limits for scaling
    pub fn get_limits(&self) -> (u32, usize, u32) {
        match self {
            DeviceTier::Low => (2, 128 * 1024 * 1024, 32), // max threads, max buffer, max batch
            DeviceTier::Medium => (8, 512 * 1024 * 1024, 128),
            DeviceTier::High => (32, 4 * 1024 * 1024 * 1024, 512),
            DeviceTier::Enterprise => (128, 16 * 1024 * 1024 * 1024, 2048),
        }
    }
}

impl HardwareProfile {
    /// Detect hardware profile automatically
    pub fn detect() -> Self {
        let cpu_cores = num_cpus::get() as u32;
        let total_ram = Self::get_total_memory();
        let nic_speed = Self::detect_nic_speed();
        let tier = Self::classify_tier(cpu_cores, total_ram, nic_speed);

        Self {
            cpu_cores,
            total_ram,
            nic_speed,
            tier,
        }
    }

    /// Classify device tier based on hardware specs
    pub fn classify_tier(cpu_cores: u32, total_ram: u64, nic_speed: u32) -> DeviceTier {
        let ram_gb = total_ram / (1024 * 1024 * 1024);

        if cpu_cores >= 32 && ram_gb >= 64 && nic_speed >= 25000 {
            DeviceTier::Enterprise
        } else if cpu_cores >= 8 && ram_gb >= 16 && nic_speed >= 10000 {
            DeviceTier::High
        } else if cpu_cores >= 4 && ram_gb >= 4 && nic_speed >= 1000 {
            DeviceTier::Medium
        } else {
            DeviceTier::Low
        }
    }

    /// Get total system memory
    fn get_total_memory() -> u64 {
        PerformanceMonitor::get_total_memory()
    }

    /// Detect network interface speed (simplified)
    fn detect_nic_speed() -> u32 {
        // This is a simplified implementation
        // In a real implementation, this would query network interface capabilities
        1000 // Default to 1Gbps
    }
}

impl AdaptiveScaler {
    /// Create a new adaptive scaler
    pub fn new(hardware_profile: HardwareProfile) -> Self {
        let current_config = hardware_profile.tier.get_default_config();

        Self {
            monitor: PerformanceMonitor::new(),
            current_config,
            hardware_profile,
            adjustment_interval: Duration::from_secs(5), // Adjust every 5 seconds
            last_adjustment: Instant::now(),
            adjustment_history: VecDeque::with_capacity(10),
        }
    }

    /// Start adaptive scaling
    pub fn start(&mut self) {
        self.monitor.start_monitoring();
    }

    /// Stop adaptive scaling
    pub fn stop(&mut self) {
        self.monitor.stop_monitoring();
    }

    /// Get current configuration
    pub fn get_current_config(&self) -> &AdaptiveEngineConfig {
        &self.current_config
    }

    /// Update packet statistics for monitoring
    pub fn update_packet_stats(&self, sent: u64, dropped: u64) {
        self.monitor.update_packet_stats(sent, dropped);
    }

    /// Check if adjustment is needed and return configuration changes
    /// Implements Requirements 21.2, 21.3, 21.4, 21.5
    pub fn check_and_adjust(&mut self) -> Option<ConfigAdjustment> {
        // Only adjust at specified intervals to prevent oscillation
        if self.last_adjustment.elapsed() < self.adjustment_interval {
            return None;
        }

        let metrics = self.monitor.get_metrics();
        let mut adjustment = ConfigAdjustment::new("No adjustment needed".to_string());
        let mut needs_adjustment = false;

        // Requirement 21.2: Reduce threads when CPU >90%
        if metrics.cpu_usage > 90.0 {
            let new_threads = (self.current_config.threads.saturating_sub(1)).max(1);
            if new_threads != self.current_config.threads {
                adjustment.thread_count = Some(new_threads);
                adjustment.reason = format!(
                    "CPU usage high ({:.1}%), reducing threads from {} to {}",
                    metrics.cpu_usage, self.current_config.threads, new_threads
                );
                needs_adjustment = true;
            }
        }

        // Requirement 21.3: Reduce buffers when memory pressure detected
        if metrics.memory_usage > 85.0 {
            let new_buffer_size = (self.current_config.buffer_size * 3 / 4).max(32 * 1024 * 1024); // Min 32MB
            if new_buffer_size != self.current_config.buffer_size {
                adjustment.buffer_size = Some(new_buffer_size);
                adjustment.reason = format!(
                    "Memory pressure ({:.1}%), reducing buffer from {}MB to {}MB",
                    metrics.memory_usage,
                    self.current_config.buffer_size / (1024 * 1024),
                    new_buffer_size / (1024 * 1024)
                );
                needs_adjustment = true;
            }
        }

        // Requirement 21.4: Reduce rate when packet loss >1%
        if metrics.packet_loss > 1.0 {
            let new_rate = (self.current_config.rate_limit * 9 / 10).max(1000); // Reduce by 10%, min 1K PPS
            if new_rate != self.current_config.rate_limit && self.current_config.rate_limit > 0 {
                adjustment.rate_limit = Some(new_rate);
                adjustment.reason = format!(
                    "Packet loss high ({:.1}%), reducing rate from {} to {} PPS",
                    metrics.packet_loss, self.current_config.rate_limit, new_rate
                );
                needs_adjustment = true;
            }
        }

        // Requirement 21.5: Scale up when resources become available
        if !needs_adjustment && self.can_scale_up(&metrics) {
            if let Some(scale_up_adjustment) = self.scale_up(&metrics) {
                adjustment = scale_up_adjustment;
                needs_adjustment = true;
            }
        }

        if needs_adjustment {
            // Apply the adjustment
            self.apply_adjustment(&adjustment);
            self.last_adjustment = Instant::now();

            // Store in history to prevent oscillation
            self.adjustment_history.push_back(adjustment.clone());
            if self.adjustment_history.len() > 10 {
                self.adjustment_history.pop_front();
            }

            Some(adjustment)
        } else {
            None
        }
    }

    /// Check if system can scale up
    fn can_scale_up(&self, metrics: &PerformanceMetrics) -> bool {
        // Only scale up if system is not under stress
        metrics.cpu_usage < 70.0 && metrics.memory_usage < 70.0 && metrics.packet_loss < 0.5
    }

    /// Generate scale-up adjustment
    fn scale_up(&self, metrics: &PerformanceMetrics) -> Option<ConfigAdjustment> {
        let (max_threads, max_buffer, max_batch) = self.hardware_profile.tier.get_limits();
        let mut adjustment = ConfigAdjustment::new("Scaling up resources".to_string());
        let mut changed = false;

        // Increase threads if we have headroom
        if self.current_config.threads < max_threads
            && self.current_config.threads < self.hardware_profile.cpu_cores
        {
            let new_threads = (self.current_config.threads + 1).min(max_threads);
            adjustment.thread_count = Some(new_threads);
            adjustment.reason = format!(
                "System has headroom (CPU: {:.1}%), increasing threads from {} to {}",
                metrics.cpu_usage, self.current_config.threads, new_threads
            );
            changed = true;
        }

        // Increase buffer size if memory is available
        if self.current_config.buffer_size < max_buffer && metrics.memory_usage < 50.0 {
            let new_buffer_size = (self.current_config.buffer_size * 5 / 4).min(max_buffer);
            if new_buffer_size != self.current_config.buffer_size {
                adjustment.buffer_size = Some(new_buffer_size);
                adjustment.reason = format!(
                    "Memory available ({:.1}%), increasing buffer from {}MB to {}MB",
                    metrics.memory_usage,
                    self.current_config.buffer_size / (1024 * 1024),
                    new_buffer_size / (1024 * 1024)
                );
                changed = true;
            }
        }

        // Increase batch size for better efficiency
        if self.current_config.batch_size < max_batch {
            let new_batch_size = (self.current_config.batch_size * 3 / 2).min(max_batch);
            if new_batch_size != self.current_config.batch_size {
                adjustment.batch_size = Some(new_batch_size);
                changed = true;
            }
        }

        if changed {
            Some(adjustment)
        } else {
            None
        }
    }

    /// Apply configuration adjustment
    fn apply_adjustment(&mut self, adjustment: &ConfigAdjustment) {
        if let Some(threads) = adjustment.thread_count {
            self.current_config.threads = threads;
        }
        if let Some(buffer_size) = adjustment.buffer_size {
            self.current_config.buffer_size = buffer_size;
        }
        if let Some(rate_limit) = adjustment.rate_limit {
            self.current_config.rate_limit = rate_limit;
        }
        if let Some(batch_size) = adjustment.batch_size {
            self.current_config.batch_size = batch_size;
        }
    }

    /// Get performance metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        let mut metrics = self.monitor.get_metrics();
        metrics.target_pps = self.current_config.target_pps;
        metrics
    }

    /// Get adjustment history
    pub fn get_adjustment_history(&self) -> Vec<ConfigAdjustment> {
        self.adjustment_history.iter().cloned().collect()
    }

    /// Check if monitoring is active
    pub fn is_active(&self) -> bool {
        self.monitor.is_monitoring()
    }
}

#[cfg(test)]
mod adaptive_tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_device_tier_classification() {
        // Test Low tier
        let tier = HardwareProfile::classify_tier(2, 2 * 1024 * 1024 * 1024, 100);
        assert_eq!(tier, DeviceTier::Low);

        // Test Medium tier
        let tier = HardwareProfile::classify_tier(4, 8 * 1024 * 1024 * 1024, 1000);
        assert_eq!(tier, DeviceTier::Medium);

        // Test High tier
        let tier = HardwareProfile::classify_tier(16, 32 * 1024 * 1024 * 1024, 10000);
        assert_eq!(tier, DeviceTier::High);

        // Test Enterprise tier
        let tier = HardwareProfile::classify_tier(64, 128 * 1024 * 1024 * 1024, 25000);
        assert_eq!(tier, DeviceTier::Enterprise);
    }

    #[test]
    fn test_adaptive_scaler_creation() {
        let hardware = HardwareProfile {
            cpu_cores: 8,
            total_ram: 16 * 1024 * 1024 * 1024,
            nic_speed: 1000,
            tier: DeviceTier::Medium,
        };

        let scaler = AdaptiveScaler::new(hardware);
        assert_eq!(scaler.current_config.threads, 4);
        assert!(!scaler.is_active());
    }

    #[test]
    fn test_config_adjustment() {
        let hardware = HardwareProfile {
            cpu_cores: 8,
            total_ram: 16 * 1024 * 1024 * 1024,
            nic_speed: 1000,
            tier: DeviceTier::Medium,
        };

        let mut scaler = AdaptiveScaler::new(hardware);
        let initial_threads = scaler.current_config.threads;

        let adjustment = ConfigAdjustment {
            thread_count: Some(initial_threads + 1),
            buffer_size: None,
            rate_limit: None,
            batch_size: None,
            reason: "Test adjustment".to_string(),
        };

        scaler.apply_adjustment(&adjustment);
        assert_eq!(scaler.current_config.threads, initial_threads + 1);
    }

    // **Feature: true-military-grade, Property 9: Adaptive Scaling Response**
    // **Validates: Requirements 21.2, 21.3, 21.4, 21.5**
    proptest! {
        #[test]
        fn test_adaptive_scaling_response(
            cpu_usage in 0.0f32..100.0,
            memory_usage in 0.0f32..100.0,
            packet_loss in 0.0f32..10.0,
            cpu_cores in 1u32..128,
            total_ram in (1u64 * 1024 * 1024 * 1024)..(256u64 * 1024 * 1024 * 1024), // 1GB to 256GB
            nic_speed in 100u32..100000, // 100Mbps to 100Gbps
        ) {
            // Create hardware profile
            let tier = HardwareProfile::classify_tier(cpu_cores, total_ram, nic_speed);
            let hardware = HardwareProfile {
                cpu_cores,
                total_ram,
                nic_speed,
                tier,
            };

            let mut scaler = AdaptiveScaler::new(hardware);
            let initial_config = scaler.current_config.clone();

            // Create performance metrics
            let metrics = PerformanceMetrics {
                cpu_usage,
                memory_usage,
                packet_loss,
                current_pps: 100_000,
                target_pps: 100_000,
                timestamp_secs: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            };

            // Simulate the metrics in the monitor
            scaler.monitor.cpu_usage.store((cpu_usage as u32).min(100), std::sync::atomic::Ordering::Relaxed);
            scaler.monitor.memory_usage.store(
                ((memory_usage / 100.0) * total_ram as f32) as u64,
                std::sync::atomic::Ordering::Relaxed
            );

            // Calculate packet stats for the given loss rate
            let total_packets = 1000u64;
            let dropped_packets = ((packet_loss / 100.0) * total_packets as f32) as u64;
            let sent_packets = total_packets - dropped_packets;
            scaler.monitor.packets_sent.store(sent_packets, std::sync::atomic::Ordering::Relaxed);
            scaler.monitor.packets_dropped.store(dropped_packets, std::sync::atomic::Ordering::Relaxed);

            // Force adjustment interval to have passed
            scaler.last_adjustment = Instant::now() - Duration::from_secs(10);

            // Check for adjustment
            let adjustment = scaler.check_and_adjust();

            // Property: When metrics exceed thresholds, system should adjust to reduce the exceeded metric
            if cpu_usage > 90.0 {
                // Should reduce threads when CPU usage is high
                if let Some(adj) = &adjustment {
                    if let Some(new_threads) = adj.thread_count {
                        prop_assert!(new_threads <= initial_config.threads,
                            "CPU usage {:.1}% > 90%, threads should be reduced from {} to {}",
                            cpu_usage, initial_config.threads, new_threads);
                        prop_assert!(new_threads >= 1, "Thread count should never go below 1");
                    }
                }
            }

            if memory_usage > 85.0 {
                // Should reduce buffer size when memory usage is high
                if let Some(adj) = &adjustment {
                    if let Some(new_buffer) = adj.buffer_size {
                        prop_assert!(new_buffer <= initial_config.buffer_size,
                            "Memory usage {:.1}% > 85%, buffer should be reduced from {} to {}",
                            memory_usage, initial_config.buffer_size, new_buffer);
                        prop_assert!(new_buffer >= 32 * 1024 * 1024, "Buffer size should never go below 32MB");
                    }
                }
            }

            if packet_loss > 1.0 && initial_config.rate_limit > 0 {
                // Should reduce rate limit when packet loss is high
                if let Some(adj) = &adjustment {
                    if let Some(new_rate) = adj.rate_limit {
                        prop_assert!(new_rate <= initial_config.rate_limit,
                            "Packet loss {:.1}% > 1%, rate should be reduced from {} to {}",
                            packet_loss, initial_config.rate_limit, new_rate);
                        prop_assert!(new_rate >= 1000, "Rate limit should never go below 1000 PPS");
                    }
                }
            }

            // Property: When resources are available, system should scale up
            if cpu_usage < 70.0 && memory_usage < 70.0 && packet_loss < 0.5 {
                let (max_threads, max_buffer, max_batch) = tier.get_limits();

                if let Some(adj) = &adjustment {
                    // If scaling up threads
                    if let Some(new_threads) = adj.thread_count {
                        prop_assert!(new_threads >= initial_config.threads,
                            "With low resource usage, threads should not decrease");
                        prop_assert!(new_threads <= max_threads,
                            "Thread count should not exceed tier limit");
                        prop_assert!(new_threads <= cpu_cores,
                            "Thread count should not exceed CPU cores");
                    }

                    // If scaling up buffer
                    if let Some(new_buffer) = adj.buffer_size {
                        prop_assert!(new_buffer >= initial_config.buffer_size,
                            "With low memory usage, buffer should not decrease");
                        prop_assert!(new_buffer <= max_buffer,
                            "Buffer size should not exceed tier limit");
                    }

                    // If scaling up batch size
                    if let Some(new_batch) = adj.batch_size {
                        prop_assert!(new_batch >= initial_config.batch_size,
                            "With good performance, batch size should not decrease");
                        prop_assert!(new_batch <= max_batch,
                            "Batch size should not exceed tier limit");
                    }
                }
            }

            // Property: Configuration should always remain within tier limits
            let current_config = scaler.get_current_config();
            let (max_threads, max_buffer, max_batch) = tier.get_limits();

            prop_assert!(current_config.threads <= max_threads,
                "Thread count {} should not exceed tier limit {}",
                current_config.threads, max_threads);
            prop_assert!(current_config.buffer_size <= max_buffer,
                "Buffer size {} should not exceed tier limit {}",
                current_config.buffer_size, max_buffer);
            prop_assert!(current_config.batch_size <= max_batch,
                "Batch size {} should not exceed tier limit {}",
                current_config.batch_size, max_batch);

            // Property: Thread count should never exceed CPU cores
            prop_assert!(current_config.threads <= cpu_cores,
                "Thread count {} should not exceed CPU cores {}",
                current_config.threads, cpu_cores);
        }
    }
}
