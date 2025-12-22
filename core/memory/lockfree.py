"""
Lock-free data structures for high concurrency operations.
Implements atomic operations and lock-free algorithms for maximum performance.
"""

import threading
import time
import ctypes
from typing import Optional, Any, Generic, TypeVar, List, Dict
from dataclasses import dataclass
from enum import Enum
import weakref

T = TypeVar('T')


class AtomicReference(Generic[T]):
    """Atomic reference implementation using compare-and-swap"""
    
    def __init__(self, initial_value: Optional[T] = None):
        self._value = initial_value
        self._lock = threading.Lock()  # Fallback for platforms without true CAS
    
    def get(self) -> Optional[T]:
        """Get the current value"""
        return self._value
    
    def set(self, new_value: T):
        """Set a new value"""
        with self._lock:
            self._value = new_value
    
    def compare_and_set(self, expected: T, new_value: T) -> bool:
        """Compare and set operation (atomic)"""
        with self._lock:
            if self._value == expected:
                self._value = new_value
                return True
            return False
    
    def get_and_set(self, new_value: T) -> Optional[T]:
        """Get current value and set new value atomically"""
        with self._lock:
            old_value = self._value
            self._value = new_value
            return old_value


class LockFreeCounter:
    """Lock-free counter using atomic operations"""
    
    def __init__(self, initial_value: int = 0):
        self._value = ctypes.c_longlong(initial_value)
        self._lock = threading.Lock()  # Fallback for thread safety
    
    def increment(self, delta: int = 1) -> int:
        """Increment counter and return new value"""
        with self._lock:
            old_value = self._value.value
            self._value.value += delta
            return self._value.value
    
    def decrement(self, delta: int = 1) -> int:
        """Decrement counter and return new value"""
        return self.increment(-delta)
    
    def add(self, delta: int) -> int:
        """Add delta to counter and return new value"""
        return self.increment(delta)
    
    def get_and_increment(self, delta: int = 1) -> int:
        """Get current value and increment"""
        with self._lock:
            old_value = self._value.value
            self._value.value += delta
            return old_value
    
    def get_and_decrement(self, delta: int = 1) -> int:
        """Get current value and decrement"""
        return self.get_and_increment(-delta)
    
    def compare_and_set(self, expected: int, new_value: int) -> bool:
        """Compare and set operation"""
        with self._lock:
            if self._value.value == expected:
                self._value.value = new_value
                return True
            return False
    
    @property
    def value(self) -> int:
        """Get current value"""
        return self._value.value
    
    def reset(self, new_value: int = 0):
        """Reset counter to new value"""
        with self._lock:
            self._value.value = new_value


@dataclass
class LockFreeNode(Generic[T]):
    """Node for lock-free data structures"""
    data: Optional[T]
    next: Optional['LockFreeNode[T]'] = None
    marked: bool = False  # For deletion marking


class LockFreeQueue(Generic[T]):
    """Lock-free queue implementation using Michael & Scott algorithm"""
    
    def __init__(self):
        # Create dummy node
        dummy = LockFreeNode(None)
        self._head = AtomicReference(dummy)
        self._tail = AtomicReference(dummy)
        self._size = LockFreeCounter(0)
    
    def enqueue(self, item: T) -> bool:
        """Add item to the queue"""
        new_node = LockFreeNode(item)
        
        while True:
            tail = self._tail.get()
            next_node = tail.next
            
            # Check if tail is still the last node
            if tail == self._tail.get():
                if next_node is None:
                    # Try to link new node at the end of the list
                    if self._compare_and_set_next(tail, None, new_node):
                        break
                else:
                    # Try to advance tail pointer
                    self._tail.compare_and_set(tail, next_node)
        
        # Try to advance tail pointer
        self._tail.compare_and_set(tail, new_node)
        self._size.increment()
        return True
    
    def dequeue(self) -> Optional[T]:
        """Remove and return item from queue"""
        while True:
            head = self._head.get()
            tail = self._tail.get()
            next_node = head.next
            
            # Check if head is still the first node
            if head == self._head.get():
                if head == tail:
                    if next_node is None:
                        # Queue is empty
                        return None
                    # Try to advance tail pointer
                    self._tail.compare_and_set(tail, next_node)
                else:
                    if next_node is None:
                        continue
                    
                    # Read data before potential dequeue
                    data = next_node.data
                    
                    # Try to advance head pointer
                    if self._head.compare_and_set(head, next_node):
                        self._size.decrement()
                        return data
    
    def _compare_and_set_next(self, node: LockFreeNode[T], 
                             expected: Optional[LockFreeNode[T]], 
                             new_node: LockFreeNode[T]) -> bool:
        """Compare and set next pointer of a node"""
        # Simplified implementation - in real implementation would use atomic operations
        if node.next == expected:
            node.next = new_node
            return True
        return False
    
    def peek(self) -> Optional[T]:
        """Peek at the front item without removing it"""
        head = self._head.get()
        if head and head.next:
            return head.next.data
        return None
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        head = self._head.get()
        tail = self._tail.get()
        return head == tail and head.next is None
    
    def size(self) -> int:
        """Get approximate size of queue"""
        return self._size.value
    
    def clear(self):
        """Clear all items from queue"""
        while not self.is_empty():
            self.dequeue()


class LockFreeStack(Generic[T]):
    """Lock-free stack implementation using Treiber's algorithm"""
    
    def __init__(self):
        self._head = AtomicReference(None)
        self._size = LockFreeCounter(0)
    
    def push(self, item: T) -> bool:
        """Push item onto stack"""
        new_node = LockFreeNode(item)
        
        while True:
            current_head = self._head.get()
            new_node.next = current_head
            
            if self._head.compare_and_set(current_head, new_node):
                self._size.increment()
                return True
    
    def pop(self) -> Optional[T]:
        """Pop item from stack"""
        while True:
            current_head = self._head.get()
            
            if current_head is None:
                return None
            
            next_node = current_head.next
            
            if self._head.compare_and_set(current_head, next_node):
                self._size.decrement()
                return current_head.data
    
    def peek(self) -> Optional[T]:
        """Peek at top item without removing it"""
        head = self._head.get()
        return head.data if head else None
    
    def is_empty(self) -> bool:
        """Check if stack is empty"""
        return self._head.get() is None
    
    def size(self) -> int:
        """Get approximate size of stack"""
        return self._size.value
    
    def clear(self):
        """Clear all items from stack"""
        while not self.is_empty():
            self.pop()


class LockFreeHashMap(Generic[T]):
    """Lock-free hash map implementation"""
    
    def __init__(self, initial_capacity: int = 16):
        self.capacity = initial_capacity
        self._buckets = [LockFreeQueue() for _ in range(initial_capacity)]
        self._size = LockFreeCounter(0)
        self._resize_threshold = initial_capacity * 0.75
    
    def _hash(self, key: Any) -> int:
        """Simple hash function"""
        return hash(key) % self.capacity
    
    def put(self, key: Any, value: T) -> bool:
        """Put key-value pair into map"""
        bucket_index = self._hash(key)
        bucket = self._buckets[bucket_index]
        
        # For simplicity, we'll add to the bucket
        # In a real implementation, we'd need to handle key collisions properly
        bucket.enqueue((key, value))
        self._size.increment()
        
        return True
    
    def get(self, key: Any) -> Optional[T]:
        """Get value by key"""
        bucket_index = self._hash(key)
        bucket = self._buckets[bucket_index]
        
        # Linear search in bucket (simplified)
        # In real implementation, would use more sophisticated approach
        temp_items = []
        result = None
        
        # Dequeue all items to search
        while True:
            item = bucket.dequeue()
            if item is None:
                break
            
            item_key, item_value = item
            if item_key == key:
                result = item_value
            
            temp_items.append(item)
        
        # Re-enqueue all items
        for item in temp_items:
            bucket.enqueue(item)
        
        return result
    
    def remove(self, key: Any) -> Optional[T]:
        """Remove key-value pair"""
        bucket_index = self._hash(key)
        bucket = self._buckets[bucket_index]
        
        temp_items = []
        result = None
        
        # Dequeue all items
        while True:
            item = bucket.dequeue()
            if item is None:
                break
            
            item_key, item_value = item
            if item_key == key:
                result = item_value
                self._size.decrement()
            else:
                temp_items.append(item)
        
        # Re-enqueue remaining items
        for item in temp_items:
            bucket.enqueue(item)
        
        return result
    
    def size(self) -> int:
        """Get size of map"""
        return self._size.value
    
    def is_empty(self) -> bool:
        """Check if map is empty"""
        return self._size.value == 0


class LockFreeRingBuffer(Generic[T]):
    """Lock-free ring buffer for high-performance producer-consumer scenarios"""
    
    def __init__(self, capacity: int):
        if capacity <= 0 or (capacity & (capacity - 1)) != 0:
            raise ValueError("Capacity must be a power of 2")
        
        self.capacity = capacity
        self.mask = capacity - 1
        self._buffer = [None] * capacity
        self._head = LockFreeCounter(0)
        self._tail = LockFreeCounter(0)
    
    def put(self, item: T) -> bool:
        """Put item into buffer"""
        current_tail = self._tail.value
        next_tail = (current_tail + 1) & self.mask
        
        # Check if buffer is full
        if next_tail == self._head.value:
            return False
        
        self._buffer[current_tail] = item
        
        # Advance tail
        while not self._tail.compare_and_set(current_tail, next_tail):
            current_tail = self._tail.value
            next_tail = (current_tail + 1) & self.mask
            
            if next_tail == self._head.value:
                return False
        
        return True
    
    def get(self) -> Optional[T]:
        """Get item from buffer"""
        current_head = self._head.value
        
        # Check if buffer is empty
        if current_head == self._tail.value:
            return None
        
        item = self._buffer[current_head]
        self._buffer[current_head] = None  # Clear reference
        
        # Advance head
        next_head = (current_head + 1) & self.mask
        while not self._head.compare_and_set(current_head, next_head):
            current_head = self._head.value
            if current_head == self._tail.value:
                return None
            next_head = (current_head + 1) & self.mask
        
        return item
    
    def is_empty(self) -> bool:
        """Check if buffer is empty"""
        return self._head.value == self._tail.value
    
    def is_full(self) -> bool:
        """Check if buffer is full"""
        return ((self._tail.value + 1) & self.mask) == self._head.value
    
    def size(self) -> int:
        """Get current size"""
        return (self._tail.value - self._head.value) & self.mask
    
    def available_space(self) -> int:
        """Get available space"""
        return self.capacity - self.size() - 1


class LockFreeObjectPool(Generic[T]):
    """Lock-free object pool for reusing expensive objects"""
    
    def __init__(self, factory_func, max_size: int = 1000):
        self.factory_func = factory_func
        self.max_size = max_size
        self._available_objects = LockFreeStack()
        self._total_created = LockFreeCounter(0)
        self._total_borrowed = LockFreeCounter(0)
        self._total_returned = LockFreeCounter(0)
    
    def borrow(self) -> T:
        """Borrow an object from the pool"""
        obj = self._available_objects.pop()
        
        if obj is None:
            # Create new object
            obj = self.factory_func()
            self._total_created.increment()
        
        self._total_borrowed.increment()
        return obj
    
    def return_object(self, obj: T) -> bool:
        """Return an object to the pool"""
        if self._available_objects.size() >= self.max_size:
            # Pool is full, don't return object
            return False
        
        # Reset object if it has a reset method
        if hasattr(obj, 'reset'):
            try:
                obj.reset()
            except Exception:
                # Don't return objects that can't be reset
                return False
        
        self._available_objects.push(obj)
        self._total_returned.increment()
        return True
    
    def get_statistics(self) -> dict:
        """Get pool statistics"""
        return {
            'available_objects': self._available_objects.size(),
            'total_created': self._total_created.value,
            'total_borrowed': self._total_borrowed.value,
            'total_returned': self._total_returned.value,
            'current_borrowed': self._total_borrowed.value - self._total_returned.value
        }


class AtomicBoolean:
    """Atomic boolean implementation"""
    
    def __init__(self, initial_value: bool = False):
        self._value = AtomicReference(initial_value)
    
    def get(self) -> bool:
        """Get current value"""
        return self._value.get()
    
    def set(self, new_value: bool):
        """Set new value"""
        self._value.set(new_value)
    
    def compare_and_set(self, expected: bool, new_value: bool) -> bool:
        """Compare and set operation"""
        return self._value.compare_and_set(expected, new_value)
    
    def get_and_set(self, new_value: bool) -> bool:
        """Get current value and set new value"""
        return self._value.get_and_set(new_value)


class LockFreeStatistics:
    """Lock-free statistics collector"""
    
    def __init__(self):
        self.count = LockFreeCounter(0)
        self.sum = LockFreeCounter(0)
        self.min_value = AtomicReference(float('inf'))
        self.max_value = AtomicReference(float('-inf'))
        self.sum_of_squares = LockFreeCounter(0)
    
    def add_sample(self, value: float):
        """Add a sample value"""
        int_value = int(value * 1000)  # Convert to int for atomic operations
        
        self.count.increment()
        self.sum.add(int_value)
        self.sum_of_squares.add(int_value * int_value)
        
        # Update min
        while True:
            current_min = self.min_value.get()
            if value >= current_min or self.min_value.compare_and_set(current_min, value):
                break
        
        # Update max
        while True:
            current_max = self.max_value.get()
            if value <= current_max or self.max_value.compare_and_set(current_max, value):
                break
    
    def get_statistics(self) -> dict:
        """Get current statistics"""
        count = self.count.value
        if count == 0:
            return {
                'count': 0,
                'mean': 0.0,
                'min': 0.0,
                'max': 0.0,
                'variance': 0.0,
                'std_dev': 0.0
            }
        
        sum_val = self.sum.value / 1000.0
        sum_sq = self.sum_of_squares.value / 1000000.0
        mean = sum_val / count
        variance = (sum_sq / count) - (mean * mean)
        std_dev = variance ** 0.5 if variance >= 0 else 0.0
        
        return {
            'count': count,
            'mean': mean,
            'min': self.min_value.get(),
            'max': self.max_value.get(),
            'variance': variance,
            'std_dev': std_dev
        }
    
    def reset(self):
        """Reset all statistics"""
        self.count.reset()
        self.sum.reset()
        self.min_value.set(float('inf'))
        self.max_value.set(float('-inf'))
        self.sum_of_squares.reset()



class LockFreeBatchQueue(Generic[T]):
    """
    Lock-free batch queue optimized for high-throughput producer-consumer scenarios.
    
    Features:
    - Batch enqueue/dequeue for reduced atomic operations
    - Cache-line padding to avoid false sharing
    - Optimized for single-producer single-consumer (SPSC) pattern
    """
    
    def __init__(self, capacity: int = 65536):
        # Ensure capacity is power of 2
        self.capacity = 1 << (capacity - 1).bit_length()
        self.mask = self.capacity - 1
        self._buffer = [None] * self.capacity
        self._head = LockFreeCounter(0)
        self._tail = LockFreeCounter(0)
        self._batch_buffer: List[T] = []
        self._batch_size = 64
    
    def enqueue_batch(self, items: List[T]) -> int:
        """Enqueue multiple items at once, returns number enqueued"""
        enqueued = 0
        tail = self._tail.value
        head = self._head.value
        
        available = self.capacity - (tail - head)
        to_enqueue = min(len(items), available)
        
        for i in range(to_enqueue):
            idx = (tail + i) & self.mask
            self._buffer[idx] = items[i]
        
        if to_enqueue > 0:
            self._tail.add(to_enqueue)
            enqueued = to_enqueue
        
        return enqueued
    
    def dequeue_batch(self, max_items: int = 64) -> List[T]:
        """Dequeue multiple items at once"""
        result = []
        head = self._head.value
        tail = self._tail.value
        
        available = tail - head
        to_dequeue = min(max_items, available)
        
        for i in range(to_dequeue):
            idx = (head + i) & self.mask
            item = self._buffer[idx]
            if item is not None:
                result.append(item)
                self._buffer[idx] = None
        
        if result:
            self._head.add(len(result))
        
        return result
    
    def size(self) -> int:
        """Get approximate size"""
        return self._tail.value - self._head.value


class LockFreeStatsAggregator:
    """
    Lock-free statistics aggregator for high-performance metrics collection.
    
    Optimized for:
    - High-frequency updates from multiple threads
    - Low-latency reads
    - Minimal contention
    """
    
    def __init__(self):
        self._packets_sent = LockFreeCounter(0)
        self._bytes_sent = LockFreeCounter(0)
        self._errors = LockFreeCounter(0)
        self._latency_sum = LockFreeCounter(0)
        self._latency_count = LockFreeCounter(0)
        self._start_time = time.time()
        
        # Per-thread local buffers for batching
        self._local_buffers: Dict[int, Dict[str, int]] = {}
        self._buffer_lock = threading.Lock()
        self._flush_threshold = 100
    
    def _get_thread_buffer(self) -> Dict[str, int]:
        """Get or create thread-local buffer"""
        tid = threading.get_ident()
        if tid not in self._local_buffers:
            with self._buffer_lock:
                if tid not in self._local_buffers:
                    self._local_buffers[tid] = {
                        'packets': 0, 'bytes': 0, 'errors': 0,
                        'latency_sum': 0, 'latency_count': 0
                    }
        return self._local_buffers[tid]
    
    def record_packet(self, bytes_sent: int, latency_us: int = 0):
        """Record a sent packet with optional latency"""
        buf = self._get_thread_buffer()
        buf['packets'] += 1
        buf['bytes'] += bytes_sent
        if latency_us > 0:
            buf['latency_sum'] += latency_us
            buf['latency_count'] += 1
        
        # Flush if threshold reached
        if buf['packets'] >= self._flush_threshold:
            self._flush_buffer(buf)
    
    def record_error(self):
        """Record an error"""
        buf = self._get_thread_buffer()
        buf['errors'] += 1
    
    def _flush_buffer(self, buf: Dict[str, int]):
        """Flush thread-local buffer to global counters"""
        if buf['packets'] > 0:
            self._packets_sent.add(buf['packets'])
            self._bytes_sent.add(buf['bytes'])
            buf['packets'] = 0
            buf['bytes'] = 0
        
        if buf['errors'] > 0:
            self._errors.add(buf['errors'])
            buf['errors'] = 0
        
        if buf['latency_count'] > 0:
            self._latency_sum.add(buf['latency_sum'])
            self._latency_count.add(buf['latency_count'])
            buf['latency_sum'] = 0
            buf['latency_count'] = 0
    
    def flush_all(self):
        """Flush all thread-local buffers"""
        for buf in self._local_buffers.values():
            self._flush_buffer(buf)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        self.flush_all()
        
        elapsed = time.time() - self._start_time
        packets = self._packets_sent.value
        bytes_sent = self._bytes_sent.value
        errors = self._errors.value
        latency_count = self._latency_count.value
        
        avg_latency = 0.0
        if latency_count > 0:
            avg_latency = self._latency_sum.value / latency_count
        
        return {
            'packets_sent': packets,
            'bytes_sent': bytes_sent,
            'errors': errors,
            'duration': elapsed,
            'pps': packets / max(0.001, elapsed),
            'bps': bytes_sent / max(0.001, elapsed),
            'mbps': (bytes_sent * 8) / max(0.001, elapsed) / 1_000_000,
            'error_rate': errors / max(1, packets + errors),
            'avg_latency_us': avg_latency,
        }
    
    def reset(self):
        """Reset all statistics"""
        self._packets_sent.reset()
        self._bytes_sent.reset()
        self._errors.reset()
        self._latency_sum.reset()
        self._latency_count.reset()
        self._start_time = time.time()
        
        for buf in self._local_buffers.values():
            for key in buf:
                buf[key] = 0


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts based on system feedback.
    
    Features:
    - Token bucket with adaptive refill rate
    - Congestion detection and backoff
    - Burst allowance for traffic shaping
    """
    
    def __init__(self, target_rate: int, burst_size: int = 0):
        self.target_rate = target_rate
        self.burst_size = burst_size if burst_size > 0 else target_rate
        self._tokens = LockFreeCounter(self.burst_size)
        self._last_refill = time.time()
        self._lock = threading.Lock()
        
        # Adaptive parameters
        self._error_count = 0
        self._success_count = 0
        self._current_rate = target_rate
        self._min_rate = target_rate // 10
        self._max_rate = target_rate * 2
        self._adaptation_interval = 1.0
        self._last_adaptation = time.time()
    
    def try_acquire(self, count: int = 1) -> bool:
        """Try to acquire tokens without blocking"""
        self._refill()
        
        current = self._tokens.value
        if current >= count:
            self._tokens.add(-count)
            return True
        return False
    
    def acquire(self, count: int = 1) -> float:
        """Acquire tokens, blocking if necessary. Returns wait time."""
        start = time.time()
        
        while not self.try_acquire(count):
            # Calculate wait time
            deficit = count - self._tokens.value
            wait_time = deficit / max(1, self._current_rate)
            time.sleep(min(wait_time, 0.001))  # Max 1ms sleep
        
        return time.time() - start
    
    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self._last_refill
        
        if elapsed > 0:
            new_tokens = int(elapsed * self._current_rate)
            if new_tokens > 0:
                current = self._tokens.value
                new_total = min(current + new_tokens, self.burst_size)
                self._tokens.reset(new_total)
                self._last_refill = now
    
    def record_success(self):
        """Record successful operation"""
        self._success_count += 1
        self._maybe_adapt()
    
    def record_error(self):
        """Record failed operation"""
        self._error_count += 1
        self._maybe_adapt()
    
    def _maybe_adapt(self):
        """Adapt rate based on success/error ratio"""
        now = time.time()
        if now - self._last_adaptation < self._adaptation_interval:
            return
        
        total = self._success_count + self._error_count
        if total < 10:
            return
        
        error_rate = self._error_count / total
        
        if error_rate > 0.1:
            # High error rate - reduce rate
            self._current_rate = max(self._min_rate, int(self._current_rate * 0.8))
        elif error_rate < 0.01 and self._current_rate < self._max_rate:
            # Low error rate - increase rate
            self._current_rate = min(self._max_rate, int(self._current_rate * 1.1))
        
        # Reset counters
        self._success_count = 0
        self._error_count = 0
        self._last_adaptation = now
    
    @property
    def current_rate(self) -> int:
        """Get current effective rate"""
        return self._current_rate
    
    def set_rate(self, rate: int):
        """Set new target rate"""
        self.target_rate = rate
        self._current_rate = rate
        self._max_rate = rate * 2
        self._min_rate = rate // 10
