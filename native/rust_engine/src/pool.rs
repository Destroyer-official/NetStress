//! Packet pool module
//! Pre-allocated packet buffers for zero-allocation sending

use std::sync::Arc;
use parking_lot::Mutex;
use crossbeam::queue::ArrayQueue;

/// Pre-allocated packet buffer
#[derive(Clone)]
pub struct PacketBuffer {
    data: Vec<u8>,
    len: usize,
}

impl PacketBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            len: 0,
        }
    }

    pub fn with_data(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            len: data.len(),
        }
    }

    pub fn set_data(&mut self, data: &[u8]) {
        let copy_len = data.len().min(self.data.len());
        self.data[..copy_len].copy_from_slice(&data[..copy_len]);
        self.len = copy_len;
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}

/// Lock-free packet pool for high-performance allocation
pub struct PacketPool {
    pool: ArrayQueue<PacketBuffer>,
    packet_size: usize,
}

impl PacketPool {
    /// Create a new packet pool
    pub fn new(capacity: usize, packet_size: usize) -> Self {
        let pool = ArrayQueue::new(capacity);
        
        // Pre-allocate buffers
        for _ in 0..capacity {
            let _ = pool.push(PacketBuffer::new(packet_size));
        }

        Self { pool, packet_size }
    }

    /// Acquire a packet buffer from the pool
    pub fn acquire(&self) -> Option<PacketBuffer> {
        self.pool.pop()
    }

    /// Return a packet buffer to the pool
    pub fn release(&self, mut buffer: PacketBuffer) {
        buffer.clear();
        let _ = self.pool.push(buffer);
    }

    /// Get number of available buffers
    pub fn available(&self) -> usize {
        self.pool.len()
    }

    /// Get pool capacity
    pub fn capacity(&self) -> usize {
        self.pool.capacity()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }
}

/// Batch packet pool for sending multiple packets at once
pub struct BatchPool {
    batches: ArrayQueue<Vec<PacketBuffer>>,
    batch_size: usize,
    packet_size: usize,
}

impl BatchPool {
    pub fn new(num_batches: usize, batch_size: usize, packet_size: usize) -> Self {
        let batches = ArrayQueue::new(num_batches);
        
        for _ in 0..num_batches {
            let batch: Vec<PacketBuffer> = (0..batch_size)
                .map(|_| PacketBuffer::new(packet_size))
                .collect();
            let _ = batches.push(batch);
        }

        Self {
            batches,
            batch_size,
            packet_size,
        }
    }

    pub fn acquire_batch(&self) -> Option<Vec<PacketBuffer>> {
        self.batches.pop()
    }

    pub fn release_batch(&self, mut batch: Vec<PacketBuffer>) {
        for buf in &mut batch {
            buf.clear();
        }
        let _ = self.batches.push(batch);
    }

    pub fn available(&self) -> usize {
        self.batches.len()
    }
}

/// Ring buffer for packet data
pub struct RingBuffer {
    data: Vec<u8>,
    capacity: usize,
    read_pos: usize,
    write_pos: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            capacity,
            read_pos: 0,
            write_pos: 0,
        }
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        let available = self.capacity - self.len();
        let write_len = data.len().min(available);
        
        for i in 0..write_len {
            self.data[self.write_pos] = data[i];
            self.write_pos = (self.write_pos + 1) % self.capacity;
        }
        
        write_len
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let available = self.len();
        let read_len = buf.len().min(available);
        
        for i in 0..read_len {
            buf[i] = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.capacity;
        }
        
        read_len
    }

    pub fn len(&self) -> usize {
        if self.write_pos >= self.read_pos {
            self.write_pos - self.read_pos
        } else {
            self.capacity - self.read_pos + self.write_pos
        }
    }

    pub fn is_empty(&self) -> bool {
        self.read_pos == self.write_pos
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.capacity - 1
    }

    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_buffer() {
        let mut buf = PacketBuffer::new(1500);
        assert_eq!(buf.capacity(), 1500);
        assert!(buf.is_empty());
        
        buf.set_data(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_slice(), b"hello");
    }

    #[test]
    fn test_packet_pool() {
        let pool = PacketPool::new(10, 1500);
        assert_eq!(pool.available(), 10);
        
        let buf = pool.acquire().unwrap();
        assert_eq!(pool.available(), 9);
        
        pool.release(buf);
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn test_ring_buffer() {
        let mut ring = RingBuffer::new(16);
        assert!(ring.is_empty());
        
        let written = ring.write(b"hello");
        assert_eq!(written, 5);
        assert_eq!(ring.len(), 5);
        
        let mut buf = [0u8; 10];
        let read = ring.read(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");
    }
}
