"""
Memory pool manager for packet buffers and high-performance memory allocation.
Implements specialized pools for different buffer types and sizes.
"""

import threading
import time
import weakref
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
import queue
import ctypes
import mmap
import os

from .lockfree import LockFreeQueue, LockFreeCounter, AtomicReference


class BufferSize(Enum):
    """Standard buffer sizes for different use cases"""
    TINY = 64        # Small control packets
    SMALL = 256      # Small packets
    MEDIUM = 512     # Medium packets
    STANDARD = 1024  # Standard packets
    LARGE = 1472     # Ethernet MTU
    JUMBO = 9000     # Jumbo frames
    HUGE = 65536     # Large buffers


@dataclass
class PoolStatistics:
    """Memory pool statistics"""
    total_allocated: int = 0
    total_freed: int = 0
    current_allocated: int = 0
    peak_allocated: int = 0
    allocation_failures: int = 0
    bytes_allocated: int = 0
    bytes_freed: int = 0
    hit_rate: float = 0.0
    miss_rate: float = 0.0


class PacketBuffer:
    """High-performance packet buffer with metadata"""
    
    def __init__(self, size: int, buffer_id: int):
        self.size = size
        self.buffer_id = buffer_id
        self.creation_time = time.time()
        self.last_used = time.time()
        self.use_count = 0
        self.is_locked = False
        
        # Create the actual buffer
        self._buffer = None
        self._memoryview = None
        self._create_buffer()
    
    def _create_buffer(self):
        """Create the underlying buffer"""
        try:
            # Try memory-mapped buffer for zero-copy operations
            self._buffer = mmap.mmap(-1, self.size)
            self._memoryview = memoryview(self._buffer)
        except (OSError, ValueError):
            # Fallback to ctypes buffer
            self._buffer = (ctypes.c_ubyte * self.size)()
            self._memoryview = memoryview(self._buffer)
    
    def get_buffer(self) -> memoryview:
        """Get buffer as memoryview"""
        self.last_used = time.time()
        self.use_count += 1
        return self._memoryview
    
    def write_data(self, data: bytes, offset: int = 0) -> int:
        """Write data to buffer"""
        if self.is_locked:
            raise RuntimeError("Buffer is locked")
        
        if offset + len(data) > self.size:
            raise ValueError("Data too large for buffer")
        
        self._memoryview[offset:offset + len(data)] = data
        self.last_used = time.time()
        self.use_count += 1
        
        return len(data)
    
    def read_data(self, length: int, offset: int = 0) -> bytes:
        """Read data from buffer"""
        if offset + length > self.size:
            length = self.size - offset
        
        data = bytes(self._memoryview[offset:offset + length])
        self.last_used = time.time()
        self.use_count += 1
        
        return data
    
    def clear(self):
        """Clear buffer contents"""
        if self.is_locked:
            return
        
        if hasattr(self._buffer, 'seek'):
            # Memory-mapped buffer
            self._buffer.seek(0)
            self._buffer.write(b'\x00' * self.size)
            self._buffer.seek(0)
        else:
            # ctypes buffer
            ctypes.memset(self._buffer, 0, self.size)
        
        self.last_used = time.time()
    
    def lock(self):
        """Lock buffer to prevent modifications"""
        self.is_locked = True
    
    def unlock(self):
        """Unlock buffer"""
        self.is_locked = False
    
    def close(self):
        """Close and cleanup buffer"""
        if hasattr(self._buffer, 'close'):
            try:
                self._buffer.close()
            except Exception:
                pass
        
        self._buffer = None
        self._memoryview = None
    
    @property
    def age(self) -> float:
        """Get buffer age in seconds"""
        return time.time() - self.creation_time
    
    @property
    def idle_time(self) -> float:
        """Get idle time since last use"""
        return time.time() - self.last_used
    
    def __len__(self) -> int:
        return self.size
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.close()
        except Exception:
            pass


class PacketBufferPool:
    """High-performance packet buffer pool with lock-free operations"""
    
    def __init__(self, buffer_size: int, initial_count: int = 100, 
                 max_count: int = 10000, enable_preallocation: bool = True):
        
        self.buffer_size = buffer_size
        self.initial_count = initial_count
        self.max_count = max_count
        self.enable_preallocation = enable_preallocation
        
        # Lock-free data structures
        self._available_buffers = LockFreeQueue()
        self._allocated_count = LockFreeCounter()
        self._total_allocated = LockFreeCounter()
        self._total_freed = LockFreeCounter()
        self._allocation_failures = LockFreeCounter()
        self._hits = LockFreeCounter()
        self._misses = LockFreeCounter()
        
        # Buffer tracking
        self._all_buffers: weakref.WeakSet = weakref.WeakSet()
        self._buffer_id_counter = LockFreeCounter()
        
        # Cleanup management
        self._last_cleanup = AtomicReference(time.time())
        self._cleanup_interval = 60.0  # Cleanup every minute
        
        # Pre-allocate buffers if enabled
        if self.enable_preallocation:
            self._preallocate_buffers()
    
    def _preallocate_buffers(self):
        """Pre-allocate initial set of buffers"""
        for _ in range(self.initial_count):
            try:
                buffer = self._create_buffer()
                if buffer:
                    self._available_buffers.enqueue(buffer)
                    self._all_buffers.add(buffer)
            except Exception:
                break
    
    def _create_buffer(self) -> Optional[PacketBuffer]:
        """Create a new packet buffer"""
        try:
            if self._allocated_count.value >= self.max_count:
                self._allocation_failures.increment()
                return None
            
            buffer_id = self._buffer_id_counter.increment()
            buffer = PacketBuffer(self.buffer_size, buffer_id)
            
            self._allocated_count.increment()
            self._total_allocated.increment()
            
            return buffer
            
        except Exception:
            self._allocation_failures.increment()
            return None
    
    def get_buffer(self) -> Optional[PacketBuffer]:
        """Get a buffer from the pool"""
        # Try to get from available buffers first
        buffer = self._available_buffers.dequeue()
        
        if buffer:
            self._hits.increment()
            return buffer
        
        # Pool is empty, create new buffer
        self._misses.increment()
        buffer = self._create_buffer()
        
        if buffer:
            self._all_buffers.add(buffer)
        
        return buffer
    
    def return_buffer(self, buffer: PacketBuffer):
        """Return a buffer to the pool"""
        if buffer.size != self.buffer_size:
            # Wrong size buffer, don't return to pool
            self._free_buffer(buffer)
            return
        
        # Clear buffer before returning
        buffer.clear()
        buffer.unlock()  # Ensure buffer is unlocked
        
        # Try to return to available pool
        if not self._available_buffers.enqueue(buffer):
            # Queue is full or failed, free the buffer
            self._free_buffer(buffer)
    
    def _free_buffer(self, buffer: PacketBuffer):
        """Free a buffer and update counters"""
        try:
            buffer.close()
            self._allocated_count.decrement()
            self._total_freed.increment()
        except Exception:
            pass
    
    def cleanup_old_buffers(self, max_idle_time: float = 300.0):
        """Cleanup old unused buffers"""
        current_time = time.time()
        
        # Check if cleanup is needed
        last_cleanup = self._last_cleanup.get()
        if current_time - last_cleanup < self._cleanup_interval:
            return
        
        # Update last cleanup time
        if not self._last_cleanup.compare_and_set(last_cleanup, current_time):
            # Another thread is doing cleanup
            return
        
        # Collect old buffers
        buffers_to_free = []
        temp_buffers = []
        
        # Process available buffers
        while True:
            buffer = self._available_buffers.dequeue()
            if buffer is None:
                break
            
            if buffer.idle_time > max_idle_time:
                buffers_to_free.append(buffer)
            else:
                temp_buffers.append(buffer)
        
        # Return non-old buffers
        for buffer in temp_buffers:
            self._available_buffers.enqueue(buffer)
        
        # Free old buffers
        for buffer in buffers_to_free:
            self._free_buffer(buffer)
    
    def get_statistics(self) -> PoolStatistics:
        """Get pool statistics"""
        total_requests = self._hits.value + self._misses.value
        
        return PoolStatistics(
            total_allocated=self._total_allocated.value,
            total_freed=self._total_freed.value,
            current_allocated=self._allocated_count.value,
            peak_allocated=max(self._total_allocated.value - self._total_freed.value, 0),
            allocation_failures=self._allocation_failures.value,
            bytes_allocated=self._total_allocated.value * self.buffer_size,
            bytes_freed=self._total_freed.value * self.buffer_size,
            hit_rate=self._hits.value / total_requests if total_requests > 0 else 0.0,
            miss_rate=self._misses.value / total_requests if total_requests > 0 else 0.0
        )
    
    def close_all(self):
        """Close all buffers in the pool"""
        # Free available buffers
        while True:
            buffer = self._available_buffers.dequeue()
            if buffer is None:
                break
            self._free_buffer(buffer)
        
        # Free all tracked buffers
        for buffer in list(self._all_buffers):
            try:
                self._free_buffer(buffer)
            except Exception:
                pass
    
    @property
    def available_count(self) -> int:
        """Get number of available buffers (approximate)"""
        return self._available_buffers.size()
    
    @property
    def allocated_count(self) -> int:
        """Get number of allocated buffers"""
        return self._allocated_count.value


class MemoryPoolManager:
    """Manager for multiple memory pools with different buffer sizes"""
    
    def __init__(self, custom_sizes: Optional[Dict[BufferSize, int]] = None):
        # Default buffer sizes
        self._buffer_sizes = custom_sizes or {
            BufferSize.TINY: 64,
            BufferSize.SMALL: 256,
            BufferSize.MEDIUM: 512,
            BufferSize.STANDARD: 1024,
            BufferSize.LARGE: 1472,
            BufferSize.JUMBO: 9000,
            BufferSize.HUGE: 65536
        }
        
        # Create pools for each buffer size
        self._pools: Dict[BufferSize, PacketBufferPool] = {}
        self._size_to_pool: Dict[int, PacketBufferPool] = {}
        
        # Global statistics
        self._global_hits = LockFreeCounter()
        self._global_misses = LockFreeCounter()
        self._global_allocations = LockFreeCounter()
        self._global_frees = LockFreeCounter()
        
        # Cleanup management
        self._cleanup_thread = None
        self._cleanup_interval = 120.0  # Cleanup every 2 minutes
        self._running = True
        
        # Initialize pools
        self._init_pools()
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _init_pools(self):
        """Initialize buffer pools"""
        for buffer_size_enum, size in self._buffer_sizes.items():
            try:
                # Adjust pool parameters based on buffer size
                if size <= 1024:
                    initial_count = 200
                    max_count = 20000
                elif size <= 9000:
                    initial_count = 100
                    max_count = 10000
                else:
                    initial_count = 50
                    max_count = 5000
                
                pool = PacketBufferPool(
                    buffer_size=size,
                    initial_count=initial_count,
                    max_count=max_count,
                    enable_preallocation=True
                )
                
                self._pools[buffer_size_enum] = pool
                self._size_to_pool[size] = pool
                
            except Exception:
                # Skip failed pool creation
                continue
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while self._running:
                try:
                    time.sleep(self._cleanup_interval)
                    if self._running:
                        self._cleanup_all_pools()
                except Exception:
                    pass
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_all_pools(self):
        """Cleanup old buffers in all pools"""
        for pool in self._pools.values():
            try:
                pool.cleanup_old_buffers()
            except Exception:
                pass
    
    def get_buffer(self, size: int) -> Optional[PacketBuffer]:
        """Get a buffer of specified size"""
        # Find the best matching pool
        pool = self._find_best_pool(size)
        
        if pool:
            buffer = pool.get_buffer()
            if buffer:
                self._global_hits.increment()
                return buffer
        
        # No suitable pool or pool failed, create custom buffer
        self._global_misses.increment()
        return self._create_custom_buffer(size)
    
    def _find_best_pool(self, size: int) -> Optional[PacketBufferPool]:
        """Find the best matching pool for the given size"""
        # Check for exact size match
        if size in self._size_to_pool:
            return self._size_to_pool[size]
        
        # Find smallest pool that can accommodate the size
        suitable_pools = [
            (pool_size, pool) for pool_size, pool in self._size_to_pool.items()
            if pool_size >= size
        ]
        
        if suitable_pools:
            # Return pool with smallest suitable size
            suitable_pools.sort(key=lambda x: x[0])
            return suitable_pools[0][1]
        
        return None
    
    def _create_custom_buffer(self, size: int) -> Optional[PacketBuffer]:
        """Create a custom buffer for non-standard sizes"""
        try:
            self._global_allocations.increment()
            return PacketBuffer(size, self._global_allocations.value)
        except Exception:
            return None
    
    def return_buffer(self, buffer: PacketBuffer):
        """Return a buffer to the appropriate pool"""
        # Find matching pool
        pool = self._size_to_pool.get(buffer.size)
        
        if pool:
            pool.return_buffer(buffer)
        else:
            # Custom buffer, just free it
            buffer.close()
            self._global_frees.increment()
    
    def get_buffer_by_type(self, buffer_type: BufferSize) -> Optional[PacketBuffer]:
        """Get buffer by predefined type"""
        pool = self._pools.get(buffer_type)
        if pool:
            buffer = pool.get_buffer()
            if buffer:
                self._global_hits.increment()
                return buffer
        
        self._global_misses.increment()
        return None
    
    def get_packet_buffer(self) -> Optional[PacketBuffer]:
        """Get standard packet buffer (1472 bytes)"""
        return self.get_buffer_by_type(BufferSize.LARGE)
    
    def get_small_buffer(self) -> Optional[PacketBuffer]:
        """Get small buffer (256 bytes)"""
        return self.get_buffer_by_type(BufferSize.SMALL)
    
    def get_large_buffer(self) -> Optional[PacketBuffer]:
        """Get large buffer (65536 bytes)"""
        return self.get_buffer_by_type(BufferSize.HUGE)
    
    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics for all pools"""
        stats = {
            'global': {
                'total_hits': self._global_hits.value,
                'total_misses': self._global_misses.value,
                'total_allocations': self._global_allocations.value,
                'total_frees': self._global_frees.value,
                'global_hit_rate': 0.0,
                'global_miss_rate': 0.0
            },
            'pools': {},
            'summary': {
                'total_pools': len(self._pools),
                'total_current_allocated': 0,
                'total_bytes_allocated': 0,
                'total_allocation_failures': 0
            }
        }
        
        # Calculate global rates
        total_requests = self._global_hits.value + self._global_misses.value
        if total_requests > 0:
            stats['global']['global_hit_rate'] = self._global_hits.value / total_requests
            stats['global']['global_miss_rate'] = self._global_misses.value / total_requests
        
        # Pool-specific statistics
        for buffer_type, pool in self._pools.items():
            pool_stats = pool.get_statistics()
            
            stats['pools'][buffer_type.name.lower()] = {
                'buffer_size': pool.buffer_size,
                'available_count': pool.available_count,
                'allocated_count': pool.allocated_count,
                'statistics': pool_stats
            }
            
            # Update summary
            stats['summary']['total_current_allocated'] += pool_stats.current_allocated
            stats['summary']['total_bytes_allocated'] += pool_stats.bytes_allocated
            stats['summary']['total_allocation_failures'] += pool_stats.allocation_failures
        
        return stats
    
    def optimize_pools(self):
        """Optimize pool configurations based on usage patterns"""
        stats = self.get_comprehensive_statistics()
        
        for buffer_type, pool_info in stats['pools'].items():
            pool_stats = pool_info['statistics']
            
            # If hit rate is low, consider increasing pool size
            if pool_stats.hit_rate < 0.8 and pool_stats.allocation_failures > 0:
                # Pool might be too small
                pass  # Could implement dynamic pool resizing
            
            # If allocation failures are high, log warning
            if pool_stats.allocation_failures > 100:
                pass  # Could log warning or alert
    
    def cleanup(self):
        """Cleanup all resources"""
        self._running = False
        
        # Wait for cleanup thread
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2.0)
        
        # Close all pools
        for pool in self._pools.values():
            try:
                pool.close_all()
            except Exception:
                pass
        
        self._pools.clear()
        self._size_to_pool.clear()
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except Exception:
            pass