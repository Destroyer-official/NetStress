//! Statistics tracking module
//! Thread-safe performance metrics collection

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Snapshot of current statistics
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub duration: Duration,
    pub pps: u64,  // packets per second
    pub bps: u64,  // bytes per second
}

impl StatsSnapshot {
    /// Get megabits per second
    pub fn mbps(&self) -> f64 {
        (self.bps as f64 * 8.0) / 1_000_000.0
    }

    /// Get gigabits per second
    pub fn gbps(&self) -> f64 {
        (self.bps as f64 * 8.0) / 1_000_000_000.0
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.packets_sent == 0 {
            0.0
        } else {
            let total = self.packets_sent + self.errors;
            (self.packets_sent as f64 / total as f64) * 100.0
        }
    }
}

/// Thread-safe statistics collector
pub struct Stats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    errors: AtomicU64,
    start_time: RwLock<Option<Instant>>,
    last_snapshot: RwLock<StatsSnapshot>,
    history: RwLock<Vec<StatsSnapshot>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            start_time: RwLock::new(None),
            last_snapshot: RwLock::new(StatsSnapshot::default()),
            history: RwLock::new(Vec::new()),
        }
    }

    /// Start tracking
    pub fn start(&self) {
        *self.start_time.write() = Some(Instant::now());
    }

    /// Stop tracking
    pub fn stop(&self) {
        let snapshot = self.snapshot();
        self.history.write().push(snapshot);
    }

    /// Reset all counters
    pub fn reset(&self) {
        self.packets_sent.store(0, Ordering::SeqCst);
        self.bytes_sent.store(0, Ordering::SeqCst);
        self.packets_received.store(0, Ordering::SeqCst);
        self.bytes_received.store(0, Ordering::SeqCst);
        self.errors.store(0, Ordering::SeqCst);
        *self.start_time.write() = None;
    }

    /// Record a sent packet
    #[inline]
    pub fn record_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a received packet
    #[inline]
    pub fn record_received(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record an error
    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record multiple sent packets (batch)
    #[inline]
    pub fn record_sent_batch(&self, count: u64, bytes: u64) {
        self.packets_sent.fetch_add(count, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current snapshot
    pub fn snapshot(&self) -> StatsSnapshot {
        let duration = self.start_time.read()
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);

        let packets = self.packets_sent.load(Ordering::Relaxed);
        let bytes = self.bytes_sent.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);

        let secs = duration.as_secs_f64().max(0.001);

        StatsSnapshot {
            packets_sent: packets,
            bytes_sent: bytes,
            errors,
            duration,
            pps: (packets as f64 / secs) as u64,
            bps: (bytes as f64 / secs) as u64,
        }
    }

    /// Get packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get error count
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Get elapsed duration
    pub fn elapsed(&self) -> Duration {
        self.start_time.read()
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Get history of snapshots
    pub fn get_history(&self) -> Vec<StatsSnapshot> {
        self.history.read().clone()
    }
}

/// Rate calculator for real-time PPS/BPS tracking
pub struct RateCalculator {
    window_size: usize,
    samples: RwLock<Vec<(Instant, u64, u64)>>,  // (time, packets, bytes)
}

impl RateCalculator {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            samples: RwLock::new(Vec::with_capacity(window_size)),
        }
    }

    /// Add a sample
    pub fn add_sample(&self, packets: u64, bytes: u64) {
        let mut samples = self.samples.write();
        samples.push((Instant::now(), packets, bytes));
        
        // Keep only recent samples
        if samples.len() > self.window_size {
            samples.remove(0);
        }
    }

    /// Calculate current rate
    pub fn calculate_rate(&self) -> (u64, u64) {
        let samples = self.samples.read();
        if samples.len() < 2 {
            return (0, 0);
        }

        let first = &samples[0];
        let last = &samples[samples.len() - 1];
        
        let duration = last.0.duration_since(first.0);
        let secs = duration.as_secs_f64().max(0.001);
        
        let packets_diff = last.1.saturating_sub(first.1);
        let bytes_diff = last.2.saturating_sub(first.2);

        let pps = (packets_diff as f64 / secs) as u64;
        let bps = (bytes_diff as f64 / secs) as u64;

        (pps, bps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_basic() {
        let stats = Stats::new();
        stats.start();
        
        stats.record_sent(100);
        stats.record_sent(100);
        stats.record_error();
        
        assert_eq!(stats.packets_sent(), 2);
        assert_eq!(stats.bytes_sent(), 200);
        assert_eq!(stats.errors(), 1);
    }

    #[test]
    fn test_snapshot() {
        let stats = Stats::new();
        stats.start();
        
        stats.record_sent_batch(1000, 100000);
        
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_sent, 1000);
        assert_eq!(snapshot.bytes_sent, 100000);
    }

    #[test]
    fn test_success_rate() {
        let snapshot = StatsSnapshot {
            packets_sent: 90,
            errors: 10,
            ..Default::default()
        };
        assert!((snapshot.success_rate() - 90.0).abs() < 0.01);
    }
}
