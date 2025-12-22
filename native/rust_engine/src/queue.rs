//! Lock-free queue implementations for high-performance packet handling
//! Uses crossbeam for MPMC queues with batch operations
//!
//! **Feature: military-grade-transformation, Property 1: Rust Engine Throughput**
//! **Validates: Requirements 1.2, 1.4** - Use crossbeam for lock-free communication

use crossbeam::queue::{ArrayQueue, SegQueue};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

/// Lock-free MPMC bounded queue with batch operations
pub struct PacketQueue<T> {
    queue: ArrayQueue<T>,
    enqueued: AtomicUsize,
    dequeued: AtomicUsize,
}

impl<T> PacketQueue<T> {
    /// Create a new packet queue with given capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: ArrayQueue::new(capacity),
            enqueued: AtomicUsize::new(0),
            dequeued: AtomicUsize::new(0),
        }
    }

    /// Push a single item (non-blocking)
    #[inline]
    pub fn push(&self, item: T) -> Result<(), T> {
        match self.queue.push(item) {
            Ok(()) => {
                self.enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(item) => Err(item),
        }
    }

    /// Pop a single item (non-blocking)
    #[inline]
    pub fn pop(&self) -> Option<T> {
        self.queue.pop().map(|item| {
            self.dequeued.fetch_add(1, Ordering::Relaxed);
            item
        })
    }

    /// Push multiple items in batch (returns number pushed)
    pub fn push_batch(&self, items: impl IntoIterator<Item = T>) -> usize {
        let mut count = 0;
        for item in items {
            if self.queue.push(item).is_ok() {
                count += 1;
            } else {
                break;
            }
        }
        self.enqueued.fetch_add(count, Ordering::Relaxed);
        count
    }

    /// Pop multiple items in batch
    pub fn pop_batch(&self, max: usize) -> Vec<T> {
        let mut items = Vec::with_capacity(max);
        for _ in 0..max {
            match self.queue.pop() {
                Some(item) => items.push(item),
                None => break,
            }
        }
        self.dequeued.fetch_add(items.len(), Ordering::Relaxed);
        items
    }

    /// Get current length (approximate)
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Check if full
    pub fn is_full(&self) -> bool {
        self.queue.is_full()
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }

    /// Get total enqueued count
    pub fn total_enqueued(&self) -> usize {
        self.enqueued.load(Ordering::Relaxed)
    }

    /// Get total dequeued count
    pub fn total_dequeued(&self) -> usize {
        self.dequeued.load(Ordering::Relaxed)
    }
}

/// Lock-free unbounded queue for variable workloads
pub struct UnboundedPacketQueue<T> {
    queue: SegQueue<T>,
    count: AtomicUsize,
}

impl<T> UnboundedPacketQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: SegQueue::new(),
            count: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn push(&self, item: T) {
        self.queue.push(item);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn pop(&self) -> Option<T> {
        self.queue.pop().map(|item| {
            self.count.fetch_sub(1, Ordering::Relaxed);
            item
        })
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl<T> Default for UnboundedPacketQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Work-stealing deque for load balancing across threads
pub struct WorkStealingQueue<T> {
    local: crossbeam::deque::Worker<T>,
    stealers: Vec<crossbeam::deque::Stealer<T>>,
}

impl<T> WorkStealingQueue<T> {
    pub fn new() -> (Self, crossbeam::deque::Stealer<T>) {
        let worker = crossbeam::deque::Worker::new_fifo();
        let stealer = worker.stealer();
        (
            Self {
                local: worker,
                stealers: Vec::new(),
            },
            stealer,
        )
    }

    pub fn add_stealer(&mut self, stealer: crossbeam::deque::Stealer<T>) {
        self.stealers.push(stealer);
    }

    #[inline]
    pub fn push(&self, item: T) {
        self.local.push(item);
    }

    #[inline]
    pub fn pop(&self) -> Option<T> {
        // Try local first
        if let Some(item) = self.local.pop() {
            return Some(item);
        }

        // Try stealing from others
        for stealer in &self.stealers {
            if let crossbeam::deque::Steal::Success(item) = stealer.steal() {
                return Some(item);
            }
        }

        None
    }

    pub fn is_empty(&self) -> bool {
        self.local.is_empty()
    }
}

/// High-performance worker pool for packet generation
///
/// Spawns threads equal to CPU cores and uses lock-free communication
/// for maximum throughput without contention.
///
/// **Validates: Requirements 1.2** - Spawn threads equal to CPU cores
/// **Validates: Requirements 1.4** - Achieve 1M+ PPS baseline
pub struct WorkerPool<T: Send + 'static> {
    workers: Vec<JoinHandle<()>>,
    task_queue: Arc<PacketQueue<T>>,
    running: Arc<AtomicBool>,
    worker_count: usize,
}

impl<T: Send + 'static> WorkerPool<T> {
    /// Create a new worker pool with the specified number of workers
    ///
    /// If `num_workers` is 0, defaults to the number of CPU cores.
    pub fn new(num_workers: usize, queue_capacity: usize) -> Self {
        let worker_count = if num_workers == 0 {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
        } else {
            num_workers
        };

        Self {
            workers: Vec::with_capacity(worker_count),
            task_queue: Arc::new(PacketQueue::new(queue_capacity)),
            running: Arc::new(AtomicBool::new(false)),
            worker_count,
        }
    }

    /// Start the worker pool with the given task handler
    pub fn start<F>(&mut self, handler: F)
    where
        F: Fn(T) + Send + Sync + Clone + 'static,
    {
        self.running.store(true, Ordering::SeqCst);

        for worker_id in 0..self.worker_count {
            let queue = Arc::clone(&self.task_queue);
            let running = Arc::clone(&self.running);
            let handler = handler.clone();

            let handle = thread::Builder::new()
                .name(format!("worker-pool-{}", worker_id))
                .spawn(move || {
                    while running.load(Ordering::Relaxed) {
                        if let Some(task) = queue.pop() {
                            handler(task);
                        } else {
                            // Brief yield to avoid busy-waiting when queue is empty
                            thread::yield_now();
                        }
                    }

                    // Drain remaining tasks
                    while let Some(task) = queue.pop() {
                        handler(task);
                    }
                })
                .expect("Failed to spawn worker thread");

            self.workers.push(handle);
        }
    }

    /// Submit a task to the worker pool
    #[inline]
    pub fn submit(&self, task: T) -> Result<(), T> {
        self.task_queue.push(task)
    }

    /// Submit multiple tasks in batch
    pub fn submit_batch(&self, tasks: impl IntoIterator<Item = T>) -> usize {
        self.task_queue.push_batch(tasks)
    }

    /// Stop the worker pool and wait for all workers to finish
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);

        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }

    /// Check if the worker pool is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get the number of workers
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Get the number of pending tasks
    pub fn pending_tasks(&self) -> usize {
        self.task_queue.len()
    }

    /// Get total tasks processed
    pub fn total_processed(&self) -> usize {
        self.task_queue.total_dequeued()
    }
}

impl<T: Send + 'static> Drop for WorkerPool<T> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::thread;

    #[test]
    fn test_packet_queue_basic() {
        let queue = PacketQueue::new(100);

        assert!(queue.push(1).is_ok());
        assert!(queue.push(2).is_ok());

        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_packet_queue_batch() {
        let queue = PacketQueue::new(100);

        let pushed = queue.push_batch(vec![1, 2, 3, 4, 5]);
        assert_eq!(pushed, 5);

        let popped = queue.pop_batch(3);
        assert_eq!(popped, vec![1, 2, 3]);
    }

    #[test]
    fn test_packet_queue_concurrent() {
        let queue = Arc::new(PacketQueue::new(1000));
        let mut handles = vec![];

        // Producers
        for i in 0..4 {
            let q = Arc::clone(&queue);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let _ = q.push(i * 100 + j);
                }
            }));
        }

        // Consumer
        let q = Arc::clone(&queue);
        handles.push(thread::spawn(move || {
            let mut count = 0;
            while count < 400 {
                if q.pop().is_some() {
                    count += 1;
                }
            }
        }));

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_unbounded_queue() {
        let queue = UnboundedPacketQueue::new();

        queue.push(1);
        queue.push(2);

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_worker_pool_basic() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);

        let mut pool: WorkerPool<u64> = WorkerPool::new(4, 1000);

        pool.start(move |value| {
            counter_clone.fetch_add(value, Ordering::Relaxed);
        });

        // Submit tasks
        for i in 1..=100 {
            let _ = pool.submit(i);
        }

        // Wait a bit for processing
        thread::sleep(std::time::Duration::from_millis(100));

        pool.stop();

        // Sum of 1..=100 = 5050
        assert_eq!(counter.load(Ordering::Relaxed), 5050);
    }

    #[test]
    fn test_worker_pool_batch_submit() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);

        let mut pool: WorkerPool<u64> = WorkerPool::new(2, 1000);

        pool.start(move |value| {
            counter_clone.fetch_add(value, Ordering::Relaxed);
        });

        // Submit batch
        let tasks: Vec<u64> = (1..=50).collect();
        let submitted = pool.submit_batch(tasks);
        assert_eq!(submitted, 50);

        // Wait for processing
        thread::sleep(std::time::Duration::from_millis(100));

        pool.stop();

        // Sum of 1..=50 = 1275
        assert_eq!(counter.load(Ordering::Relaxed), 1275);
    }

    #[test]
    fn test_worker_pool_default_workers() {
        let pool: WorkerPool<u64> = WorkerPool::new(0, 100);
        let cpu_count = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        assert_eq!(pool.worker_count(), cpu_count);
    }
}
