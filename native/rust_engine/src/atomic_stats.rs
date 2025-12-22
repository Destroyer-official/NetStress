//! Lock-free atomic statistics for real-time monitoring
//! Implements per-thread counters with efficient aggregation

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Atomic statistics counters (lock-free)
#[derive(Default)]
pub struct AtomicStats {
    /// Total packets sent
    pub packets_sent: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total errors
    pub errors: AtomicU64,
    /// Packets dropped (queue full, etc.)
    pub dropped: AtomicU64,
    /// Retransmissions
    pub retransmits: AtomicU64,
}

impl AtomicStats {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn record_sent(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_batch_sent(&self, packets: u64, bytes: u64) {
        self.packets_sent.fetch_add(packets, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            retransmits: self.retransmits.load(Ordering::Relaxed),
            ..Default::default()
        }
    }

    pub fn reset(&self) {
        self.packets_sent.store(0, Ordering::SeqCst);
        self.bytes_sent.store(0, Ordering::SeqCst);
        self.errors.store(0, Ordering::SeqCst);
        self.dropped.store(0, Ordering::SeqCst);
        self.retransmits.store(0, Ordering::SeqCst);
    }
}

/// Statistics snapshot for reporting
#[derive(Debug, Clone, Default)]
pub struct StatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub dropped: u64,
    pub retransmits: u64,
    pub duration: Duration,
    pub pps: f64,
    pub bps: f64,
    pub gbps: f64,
    pub error_rate: f64,
}

impl StatsSnapshot {
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        let secs = duration.as_secs_f64().max(0.001);
        self.pps = self.packets_sent as f64 / secs;
        self.bps = self.bytes_sent as f64 / secs;
        self.gbps = self.bps * 8.0 / 1_000_000_000.0;

        let total = self.packets_sent + self.errors;
        self.error_rate = if total > 0 {
            self.errors as f64 / total as f64 * 100.0
        } else {
            0.0
        };

        self
    }

    /// Convert to Prometheus format
    pub fn to_prometheus(&self, prefix: &str) -> String {
        format!(
            "# HELP {prefix}_packets_sent Total packets sent\n\
             # TYPE {prefix}_packets_sent counter\n\
             {prefix}_packets_sent {}\n\
             # HELP {prefix}_bytes_sent Total bytes sent\n\
             # TYPE {prefix}_bytes_sent counter\n\
             {prefix}_bytes_sent {}\n\
             # HELP {prefix}_errors Total errors\n\
             # TYPE {prefix}_errors counter\n\
             {prefix}_errors {}\n\
             # HELP {prefix}_pps Current packets per second\n\
             # TYPE {prefix}_pps gauge\n\
             {prefix}_pps {:.2}\n\
             # HELP {prefix}_gbps Current gigabits per second\n\
             # TYPE {prefix}_gbps gauge\n\
             {prefix}_gbps {:.4}\n",
            self.packets_sent,
            self.bytes_sent,
            self.errors,
            self.pps,
            self.gbps,
            prefix = prefix
        )
    }

    /// Convert to JSON format
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"packets_sent":{},"bytes_sent":{},"errors":{},"dropped":{},"duration_secs":{:.3},"pps":{:.2},"bps":{:.2},"gbps":{:.6},"error_rate":{:.4}}}"#,
            self.packets_sent,
            self.bytes_sent,
            self.errors,
            self.dropped,
            self.duration.as_secs_f64(),
            self.pps,
            self.bps,
            self.gbps,
            self.error_rate
        )
    }
}

/// Per-thread statistics for scalable counting
pub struct ThreadStats {
    /// Thread ID
    pub thread_id: usize,
    /// Local counters
    stats: AtomicStats,
    /// Last flush time
    last_flush: AtomicU64,
}

impl ThreadStats {
    pub fn new(thread_id: usize) -> Self {
        Self {
            thread_id,
            stats: AtomicStats::new(),
            last_flush: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_sent(&self, bytes: u64) {
        self.stats.record_sent(bytes);
    }

    #[inline]
    pub fn record_batch_sent(&self, packets: u64, bytes: u64) {
        self.stats.record_batch_sent(packets, bytes);
    }

    #[inline]
    pub fn record_error(&self) {
        self.stats.record_error();
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }
}

/// Aggregated statistics collector
pub struct StatsCollector {
    /// Global stats (aggregated)
    global: Arc<AtomicStats>,
    /// Per-thread stats
    thread_stats: RwLock<Vec<Arc<ThreadStats>>>,
    /// Start time
    start_time: Instant,
    /// Running flag
    running: AtomicBool,
    /// Update interval
    update_interval: Duration,
    /// History for rate calculation
    history: RwLock<Vec<(Instant, StatsSnapshot)>>,
}

impl StatsCollector {
    pub fn new() -> Self {
        Self {
            global: Arc::new(AtomicStats::new()),
            thread_stats: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            running: AtomicBool::new(false),
            update_interval: Duration::from_millis(100),
            history: RwLock::new(Vec::with_capacity(100)),
        }
    }

    /// Create thread-local stats
    pub fn create_thread_stats(&self, thread_id: usize) -> Arc<ThreadStats> {
        let stats = Arc::new(ThreadStats::new(thread_id));
        self.thread_stats.write().push(Arc::clone(&stats));
        stats
    }

    /// Start collecting
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// Stop collecting
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get aggregated snapshot
    pub fn snapshot(&self) -> StatsSnapshot {
        let mut total = StatsSnapshot::default();

        // Aggregate from all threads
        for thread_stats in self.thread_stats.read().iter() {
            let snap = thread_stats.snapshot();
            total.packets_sent += snap.packets_sent;
            total.bytes_sent += snap.bytes_sent;
            total.errors += snap.errors;
            total.dropped += snap.dropped;
        }

        // Add global stats
        let global = self.global.snapshot();
        total.packets_sent += global.packets_sent;
        total.bytes_sent += global.bytes_sent;
        total.errors += global.errors;

        total.with_duration(self.start_time.elapsed())
    }

    /// Get current rate (packets per second)
    pub fn current_pps(&self) -> f64 {
        let history = self.history.read();
        if history.len() < 2 {
            return self.snapshot().pps;
        }

        let (t1, s1) = &history[history.len() - 2];
        let (t2, s2) = &history[history.len() - 1];

        let dt = t2.duration_since(*t1).as_secs_f64();
        if dt > 0.0 {
            (s2.packets_sent - s1.packets_sent) as f64 / dt
        } else {
            0.0
        }
    }

    /// Record a snapshot to history
    pub fn record_history(&self) {
        let snap = self.snapshot();
        let mut history = self.history.write();
        history.push((Instant::now(), snap));

        // Keep last 100 entries
        if history.len() > 100 {
            history.remove(0);
        }
    }

    /// Get global stats for direct recording
    pub fn global(&self) -> &Arc<AtomicStats> {
        &self.global
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.global.reset();
        for thread_stats in self.thread_stats.read().iter() {
            thread_stats.stats.reset();
        }
        self.history.write().clear();
    }

    /// Get Prometheus metrics
    pub fn prometheus_metrics(&self) -> String {
        self.snapshot().to_prometheus("netstress")
    }

    /// Get JSON metrics
    pub fn json_metrics(&self) -> String {
        self.snapshot().to_json()
    }
}

impl Default for StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Real-time statistics reporter
pub struct StatsReporter {
    collector: Arc<StatsCollector>,
    interval: Duration,
    running: Arc<AtomicBool>,
}

impl StatsReporter {
    pub fn new(collector: Arc<StatsCollector>, interval: Duration) -> Self {
        Self {
            collector,
            interval,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start background reporting
    pub fn start(&self) -> std::thread::JoinHandle<()> {
        let collector = Arc::clone(&self.collector);
        let interval = self.interval;
        let running = Arc::clone(&self.running);

        running.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                collector.record_history();
                std::thread::sleep(interval);
            }
        })
    }

    /// Stop reporting
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_atomic_stats() {
        let stats = AtomicStats::new();

        stats.record_sent(100);
        stats.record_sent(200);
        stats.record_error();

        let snap = stats.snapshot();
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.bytes_sent, 300);
        assert_eq!(snap.errors, 1);
    }

    #[test]
    fn test_atomic_stats_batch() {
        let stats = AtomicStats::new();

        stats.record_batch_sent(10, 1000);
        stats.record_batch_sent(5, 500);

        let snap = stats.snapshot();
        assert_eq!(snap.packets_sent, 15);
        assert_eq!(snap.bytes_sent, 1500);
    }

    #[test]
    fn test_atomic_stats_reset() {
        let stats = AtomicStats::new();

        stats.record_sent(100);
        stats.record_error();

        let snap1 = stats.snapshot();
        assert_eq!(snap1.packets_sent, 1);
        assert_eq!(snap1.errors, 1);

        stats.reset();

        let snap2 = stats.snapshot();
        assert_eq!(snap2.packets_sent, 0);
        assert_eq!(snap2.errors, 0);
    }

    #[test]
    fn test_concurrent_stats() {
        let stats = Arc::new(AtomicStats::new());
        let mut handles = vec![];

        for _ in 0..4 {
            let s = Arc::clone(&stats);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    s.record_sent(100);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let snap = stats.snapshot();
        assert_eq!(snap.packets_sent, 4000);
        assert_eq!(snap.bytes_sent, 400000);
    }

    #[test]
    fn test_stats_collector() {
        let collector = StatsCollector::new();

        let t1 = collector.create_thread_stats(0);
        let t2 = collector.create_thread_stats(1);

        t1.record_sent(100);
        t2.record_sent(200);

        let snap = collector.snapshot();
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.bytes_sent, 300);
    }

    #[test]
    fn test_stats_collector_global() {
        let collector = StatsCollector::new();

        // Record to global stats
        collector.global().record_sent(500);

        // Record to thread stats
        let t1 = collector.create_thread_stats(0);
        t1.record_sent(100);

        let snap = collector.snapshot();
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.bytes_sent, 600);
    }

    #[test]
    fn test_stats_collector_reset() {
        let collector = StatsCollector::new();

        let t1 = collector.create_thread_stats(0);
        t1.record_sent(100);
        collector.global().record_sent(200);

        let snap1 = collector.snapshot();
        assert_eq!(snap1.packets_sent, 2);

        collector.reset();

        let snap2 = collector.snapshot();
        assert_eq!(snap2.packets_sent, 0);
    }

    #[test]
    fn test_stats_snapshot_with_duration() {
        let snap = StatsSnapshot {
            packets_sent: 1000,
            bytes_sent: 100000,
            errors: 10,
            ..Default::default()
        }
        .with_duration(Duration::from_secs(1));

        assert_eq!(snap.pps, 1000.0);
        assert_eq!(snap.bps, 100000.0);
        assert_eq!(snap.gbps, 0.0008);
        assert_eq!(snap.error_rate, 0.9900990099009901); // 10/(1000+10)*100
    }

    #[test]
    fn test_prometheus_format() {
        let snap = StatsSnapshot {
            packets_sent: 1000,
            bytes_sent: 100000,
            errors: 5,
            pps: 100.0,
            gbps: 0.0008,
            ..Default::default()
        };

        let prom = snap.to_prometheus("test");
        assert!(prom.contains("test_packets_sent 1000"));
        assert!(prom.contains("test_errors 5"));
        assert!(prom.contains("test_pps 100.00"));
        assert!(prom.contains("test_gbps 0.0008"));
    }

    #[test]
    fn test_json_format() {
        let snap = StatsSnapshot {
            packets_sent: 1000,
            bytes_sent: 100000,
            errors: 5,
            ..Default::default()
        };

        let json = snap.to_json();
        assert!(json.contains("\"packets_sent\":1000"));
        assert!(json.contains("\"errors\":5"));
        assert!(json.contains("\"bytes_sent\":100000"));
    }

    #[test]
    fn test_thread_stats() {
        let stats = ThreadStats::new(42);
        assert_eq!(stats.thread_id, 42);

        stats.record_sent(100);
        stats.record_error();

        let snap = stats.snapshot();
        assert_eq!(snap.packets_sent, 1);
        assert_eq!(snap.bytes_sent, 100);
        assert_eq!(snap.errors, 1);
    }

    #[test]
    fn test_stats_reporter() {
        let collector = Arc::new(StatsCollector::new());
        let reporter = StatsReporter::new(Arc::clone(&collector), Duration::from_millis(10));

        let handle = reporter.start();

        // Let it run briefly
        thread::sleep(Duration::from_millis(50));

        reporter.stop();
        handle.join().unwrap();

        // Should have recorded some history
        let history = collector.history.read();
        assert!(!history.is_empty());
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_atomic_stats_properties(
            packets in 0u64..1_000_000,
            bytes_per_packet in 1u64..10_000
        ) {
            let stats = AtomicStats::new();

            for _ in 0..packets {
                stats.record_sent(bytes_per_packet);
            }

            let snap = stats.snapshot();
            prop_assert_eq!(snap.packets_sent, packets);
            prop_assert_eq!(snap.bytes_sent, packets * bytes_per_packet);
        }

        #[test]
        fn test_batch_recording_properties(
            batch_count in 1u64..1000,
            packets_per_batch in 1u64..100,
            bytes_per_packet in 1u64..1500
        ) {
            let stats = AtomicStats::new();

            for _ in 0..batch_count {
                stats.record_batch_sent(packets_per_batch, packets_per_batch * bytes_per_packet);
            }

            let snap = stats.snapshot();
            prop_assert_eq!(snap.packets_sent, batch_count * packets_per_batch);
            prop_assert_eq!(snap.bytes_sent, batch_count * packets_per_batch * bytes_per_packet);
        }

        #[test]
        fn test_concurrent_stats_properties(
            thread_count in 1usize..8,
            operations_per_thread in 1usize..1000,
            bytes_per_op in 1u64..1000
        ) {
            let stats = Arc::new(AtomicStats::new());
            let mut handles = vec![];

            for _ in 0..thread_count {
                let s = Arc::clone(&stats);
                handles.push(thread::spawn(move || {
                    for _ in 0..operations_per_thread {
                        s.record_sent(bytes_per_op);
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }

            let snap = stats.snapshot();
            let expected_packets = (thread_count * operations_per_thread) as u64;
            let expected_bytes = expected_packets * bytes_per_op;

            prop_assert_eq!(snap.packets_sent, expected_packets);
            prop_assert_eq!(snap.bytes_sent, expected_bytes);
        }

        #[test]
        fn test_stats_snapshot_calculations(
            packets in 1u64..1_000_000,
            bytes in 1u64..1_000_000_000,
            duration_ms in 1u64..60_000
        ) {
            let duration = Duration::from_millis(duration_ms);
            let snap = StatsSnapshot {
                packets_sent: packets,
                bytes_sent: bytes,
                ..Default::default()
            }.with_duration(duration);

            let expected_pps = packets as f64 / duration.as_secs_f64();
            let expected_bps = bytes as f64 / duration.as_secs_f64();
            let expected_gbps = expected_bps * 8.0 / 1_000_000_000.0;

            // Allow small floating point differences
            prop_assert!((snap.pps - expected_pps).abs() < 0.1);
            prop_assert!((snap.bps - expected_bps).abs() < 0.1);
            prop_assert!((snap.gbps - expected_gbps).abs() < 0.000001);
        }
    }
}
