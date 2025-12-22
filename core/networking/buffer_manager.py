"""
Zero-copy buffer management system for high-performance packet handling.
Implements memory pools and buffer recycling for optimal performance.
"""

import mmap
import threading
import time
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from enum import Enum
import queue
import weakref
import ctypes
import os


class BufferType(Enum):
    """Buffer types for different use cases"""
    PACKET = "packet"
    SEND = "send"
    RECEIVE = "receive"
    TEMPORARY = "temporary"


@dataclass
class BufferMetrics:
    """Buffer pool metrics"""
    total_allocated: int = 0
    total_freed: int = 0
    current_allocated: int = 0
    peak_allocated: int = 0
    allocation_failures: int = 0
    bytes_allocated: int = 0
    bytes_freed: int = 0


class ZeroCopyBuffer:
    """Zero-copy buffer implementation using memory mapping"""
    
    def __init__(self, size: int, buffer_type: BufferType = BufferType.PACKET):
        self._size = size
        self._buffer_type = buffer_type
        self._creation_time = time.time()
        self._last_used = time.time()
        self._use_count = 0
        self._lock = threading.Lock()
        
        # Create memory-mapped buffer
        self._mmap_buffer = None
        self._ctypes_buffer = None
        self._memoryview = None
        
        self._create_buffer()
    
    def _create_buffer(self):
        """Create the underlying buffer"""
        try:
            # Try to create memory-mapped buffer for zero-copy operations
            self._mmap_buffer = mmap.mmap(-1, self._size)
            self._memoryview = memoryview(self._mmap_buffer)
        except (OSError, ValueError):
            # Fallback to ctypes buffer
            self._ctypes_buffer = (ctypes.c_ubyte * self._size)()
            self._memoryview = memoryview(self._ctypes_buffer)
    
    def get_buffer(self) -> memoryview:
        """Get the buffer as a memoryview for zero-copy operations"""
        with self._lock:
            self._last_used = time.time()
            self._use_count += 1
            return self._memoryview
    
    def write(self, data: bytes, offset: int = 0) -> int:
        """Write data to buffer"""
        with self._lock:
            if offset + len(data) > self._size:
                raise ValueError("Data too large for buffer")
            
            self._memoryview[offset:offset + len(data)] = data
            self._last_used = time.time()
            self._use_count += 1
            
            return len(data)
    
    def write_data(self, data: bytes, offset: int = 0) -> int:
        """Write data to buffer (alias for write)"""
        return self.write(data, offset)
    
    def read_data(self, size: int, offset: int = 0) -> bytes:
        """Read data from buffer (alias for read)"""
        return self.read(size, offset)
    
    def read(self, size: int, offset: int = 0) -> bytes:
        """Read data from buffer"""
        with self._lock:
            if offset + size > self._size:
                size = self._size - offset
            
            data = bytes(self._memoryview[offset:offset + size])
            self._last_used = time.time()
            self._use_count += 1
            
            return data
    
    def clear(self):
        """Clear buffer contents"""
        with self._lock:
            if self._mmap_buffer:
                # Zero out memory-mapped buffer
                self._mmap_buffer.seek(0)
                self._mmap_buffer.write(b'\x00' * self._size)
                self._mmap_buffer.seek(0)
            elif self._ctypes_buffer:
                # Zero out ctypes buffer
                ctypes.memset(self._ctypes_buffer, 0, self._size)
            
            self._last_used = time.time()
    
    def resize(self, new_size: int) -> bool:
        """Resize buffer (creates new buffer)"""
        if new_size == self._size:
            return True
        
        with self._lock:
            try:
                # Close old buffer
                self._close_buffer()
                
                # Create new buffer
                self._size = new_size
                self._create_buffer()
                
                return True
            except Exception:
                return False
    
    def _close_buffer(self):
        """Close the underlying buffer"""
        if self._mmap_buffer:
            try:
                self._mmap_buffer.close()
            except Exception:
                pass
            self._mmap_buffer = None
        
        self._ctypes_buffer = None
        self._memoryview = None
    
    def close(self):
        """Close and cleanup buffer"""
        with self._lock:
            self._close_buffer()
    
    @property
    def size(self) -> int:
        """Get buffer size"""
        return self._size
    
    @property
    def buffer_type(self) -> BufferType:
        """Get buffer type"""
        return self._buffer_type
    
    @property
    def use_count(self) -> int:
        """Get usage count"""
        return self._use_count
    
    @property
    def last_used(self) -> float:
        """Get last used timestamp"""
        return self._last_used
    
    @property
    def age(self) -> float:
        """Get buffer age in seconds"""
        return time.time() - self._creation_time
    
    def __len__(self) -> int:
        return self._size
    
    def __getitem__(self, key):
        return self._memoryview[key]
    
    def __setitem__(self, key, value):
        self._memoryview[key] = value
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.close()
        except Exception:
            pass


class BufferPool:
    """Pool of reusable buffers for specific size and type"""
    
    def __init__(self, buffer_size: int, buffer_type: BufferType, 
                 initial_count: int = 10, max_count: int = 100):
        self._buffer_size = buffer_size
        self._buffer_type = buffer_type
        self._initial_count = initial_count
        self._max_count = max_count
        
        self._available_buffers = queue.Queue(maxsize=max_count)
        self._all_buffers: weakref.WeakSet = weakref.WeakSet()
        self._metrics = BufferMetrics()
        self._lock = threading.Lock()
        
        # Pre-allocate initial buffers
        self._preallocate_buffers()
    
    def _preallocate_buffers(self):
        """Pre-allocate initial set of buffers"""
        for _ in range(self._initial_count):
            try:
                buffer = ZeroCopyBuffer(self._buffer_size, self._buffer_type)
                self._available_buffers.put_nowait(buffer)
                self._all_buffers.add(buffer)
                
                with self._lock:
                    self._metrics.total_allocated += 1
                    self._metrics.current_allocated += 1
                    self._metrics.bytes_allocated += self._buffer_size
                    
            except Exception:
                # Skip failed allocations
                continue
    
    def get_buffer(self, timeout: Optional[float] = None) -> Optional[ZeroCopyBuffer]:
        """Get a buffer from the pool"""
        try:
            # Try to get from available buffers
            buffer = self._available_buffers.get(timeout=timeout)
            return buffer
            
        except queue.Empty:
            # Pool is empty, try to create new buffer
            return self._create_new_buffer()
    
    def return_buffer(self, buffer: ZeroCopyBuffer):
        """Return a buffer to the pool"""
        if buffer.buffer_type != self._buffer_type or buffer.size != self._buffer_size:
            # Wrong type or size, don't return to pool
            buffer.close()
            return
        
        try:
            # Clear buffer before returning
            buffer.clear()
            
            # Try to return to pool
            self._available_buffers.put_nowait(buffer)
            
        except queue.Full:
            # Pool is full, close the buffer
            buffer.close()
            with self._lock:
                self._metrics.current_allocated -= 1
                self._metrics.total_freed += 1
                self._metrics.bytes_freed += buffer.size
    
    def _create_new_buffer(self) -> Optional[ZeroCopyBuffer]:
        """Create a new buffer when pool is empty"""
        with self._lock:
            if self._metrics.current_allocated >= self._max_count:
                self._metrics.allocation_failures += 1
                return None
        
        try:
            buffer = ZeroCopyBuffer(self._buffer_size, self._buffer_type)
            self._all_buffers.add(buffer)
            
            with self._lock:
                self._metrics.total_allocated += 1
                self._metrics.current_allocated += 1
                self._metrics.peak_allocated = max(
                    self._metrics.peak_allocated, 
                    self._metrics.current_allocated
                )
                self._metrics.bytes_allocated += self._buffer_size
            
            return buffer
            
        except Exception:
            with self._lock:
                self._metrics.allocation_failures += 1
            return None
    
    def cleanup_old_buffers(self, max_age: float = 300.0):
        """Cleanup old unused buffers"""
        current_time = time.time()
        buffers_to_remove = []
        
        # Collect old buffers from available queue
        temp_buffers = []
        while not self._available_buffers.empty():
            try:
                buffer = self._available_buffers.get_nowait()
                if current_time - buffer.last_used > max_age:
                    buffers_to_remove.append(buffer)
                else:
                    temp_buffers.append(buffer)
            except queue.Empty:
                break
        
        # Return non-old buffers to queue
        for buffer in temp_buffers:
            try:
                self._available_buffers.put_nowait(buffer)
            except queue.Full:
                buffers_to_remove.append(buffer)
        
        # Close old buffers
        for buffer in buffers_to_remove:
            buffer.close()
            with self._lock:
                self._metrics.current_allocated -= 1
                self._metrics.total_freed += 1
                self._metrics.bytes_freed += buffer.size
    
    def get_metrics(self) -> BufferMetrics:
        """Get pool metrics"""
        with self._lock:
            return BufferMetrics(
                total_allocated=self._metrics.total_allocated,
                total_freed=self._metrics.total_freed,
                current_allocated=self._metrics.current_allocated,
                peak_allocated=self._metrics.peak_allocated,
                allocation_failures=self._metrics.allocation_failures,
                bytes_allocated=self._metrics.bytes_allocated,
                bytes_freed=self._metrics.bytes_freed
            )
    
    def close_all(self):
        """Close all buffers in the pool"""
        # Close available buffers
        while not self._available_buffers.empty():
            try:
                buffer = self._available_buffers.get_nowait()
                buffer.close()
            except queue.Empty:
                break
        
        # Close all tracked buffers
        for buffer in list(self._all_buffers):
            try:
                buffer.close()
            except Exception:
                pass
        
        with self._lock:
            self._metrics.current_allocated = 0
    
    @property
    def available_count(self) -> int:
        """Get number of available buffers"""
        return self._available_buffers.qsize()
    
    @property
    def buffer_size(self) -> int:
        """Get buffer size"""
        return self._buffer_size
    
    @property
    def buffer_type(self) -> BufferType:
        """Get buffer type"""
        return self._buffer_type


class ZeroCopyBufferManager:
    """Manager for zero-copy buffer pools"""
    
    # Standard buffer sizes for different use cases
    STANDARD_SIZES = {
        BufferType.PACKET: [64, 128, 256, 512, 1024, 1472, 1500, 4096, 8192],
        BufferType.SEND: [1024, 4096, 8192, 16384, 32768, 65536],
        BufferType.RECEIVE: [1024, 4096, 8192, 16384, 32768, 65536],
        BufferType.TEMPORARY: [256, 1024, 4096, 16384]
    }
    
    def __init__(self, custom_sizes: Optional[Dict[BufferType, List[int]]] = None):
        self._buffer_pools: Dict[Tuple[BufferType, int], BufferPool] = {}
        self._lock = threading.Lock()
        self._cleanup_thread = None
        self._cleanup_interval = 60.0  # Cleanup every minute
        self._running = True
        
        # Use custom sizes or defaults
        self._sizes = custom_sizes or self.STANDARD_SIZES
        
        # Initialize buffer pools
        self._init_buffer_pools()
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _init_buffer_pools(self):
        """Initialize buffer pools for standard sizes"""
        for buffer_type, sizes in self._sizes.items():
            for size in sizes:
                pool = BufferPool(
                    buffer_size=size,
                    buffer_type=buffer_type,
                    initial_count=5,
                    max_count=50
                )
                self._buffer_pools[(buffer_type, size)] = pool
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while self._running:
                try:
                    time.sleep(self._cleanup_interval)
                    if self._running:
                        self._cleanup_old_buffers()
                except Exception:
                    pass
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_old_buffers(self):
        """Cleanup old buffers in all pools"""
        with self._lock:
            for pool in self._buffer_pools.values():
                try:
                    pool.cleanup_old_buffers()
                except Exception:
                    pass
    
    def get_buffer(self, size: int, buffer_type: BufferType = BufferType.PACKET) -> Optional[ZeroCopyBuffer]:
        """Get a buffer of specified size and type"""
        # Find the best matching pool
        pool_key = self._find_best_pool(size, buffer_type)
        
        if pool_key:
            pool = self._buffer_pools[pool_key]
            buffer = pool.get_buffer(timeout=0.1)
            if buffer:
                return buffer
        
        # No suitable pool found or pool is empty, create custom buffer
        return self._create_custom_buffer(size, buffer_type)
    
    def _find_best_pool(self, size: int, buffer_type: BufferType) -> Optional[Tuple[BufferType, int]]:
        """Find the best matching buffer pool"""
        # Look for exact size match first
        exact_key = (buffer_type, size)
        if exact_key in self._buffer_pools:
            return exact_key
        
        # Find smallest buffer that can accommodate the size
        suitable_sizes = [
            pool_size for (pool_type, pool_size) in self._buffer_pools.keys()
            if pool_type == buffer_type and pool_size >= size
        ]
        
        if suitable_sizes:
            best_size = min(suitable_sizes)
            return (buffer_type, best_size)
        
        return None
    
    def _create_custom_buffer(self, size: int, buffer_type: BufferType) -> Optional[ZeroCopyBuffer]:
        """Create a custom buffer for non-standard sizes"""
        try:
            return ZeroCopyBuffer(size, buffer_type)
        except Exception:
            return None
    
    def return_buffer(self, buffer: ZeroCopyBuffer):
        """Return a buffer to the appropriate pool"""
        pool_key = (buffer.buffer_type, buffer.size)
        
        if pool_key in self._buffer_pools:
            self._buffer_pools[pool_key].return_buffer(buffer)
        else:
            # Custom buffer, just close it
            buffer.close()
    
    def get_packet_buffer(self, size: int = 1472) -> Optional[ZeroCopyBuffer]:
        """Get a packet buffer (convenience method)"""
        return self.get_buffer(size, BufferType.PACKET)
    
    def get_send_buffer(self, size: int = 8192) -> Optional[ZeroCopyBuffer]:
        """Get a send buffer (convenience method)"""
        return self.get_buffer(size, BufferType.SEND)
    
    def get_receive_buffer(self, size: int = 8192) -> Optional[ZeroCopyBuffer]:
        """Get a receive buffer (convenience method)"""
        return self.get_buffer(size, BufferType.RECEIVE)
    
    def get_temporary_buffer(self, size: int = 4096) -> Optional[ZeroCopyBuffer]:
        """Get a temporary buffer (convenience method)"""
        return self.get_buffer(size, BufferType.TEMPORARY)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive buffer statistics"""
        stats = {
            'pools': {},
            'total_metrics': BufferMetrics()
        }
        
        with self._lock:
            for (buffer_type, size), pool in self._buffer_pools.items():
                pool_metrics = pool.get_metrics()
                
                pool_key = f"{buffer_type.value}_{size}"
                stats['pools'][pool_key] = {
                    'buffer_type': buffer_type.value,
                    'buffer_size': size,
                    'available_count': pool.available_count,
                    'metrics': pool_metrics
                }
                
                # Aggregate metrics
                total = stats['total_metrics']
                total.total_allocated += pool_metrics.total_allocated
                total.total_freed += pool_metrics.total_freed
                total.current_allocated += pool_metrics.current_allocated
                total.peak_allocated += pool_metrics.peak_allocated
                total.allocation_failures += pool_metrics.allocation_failures
                total.bytes_allocated += pool_metrics.bytes_allocated
                total.bytes_freed += pool_metrics.bytes_freed
        
        return stats
    
    def cleanup(self):
        """Cleanup all resources"""
        self._running = False
        
        # Wait for cleanup thread to finish
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)
        
        # Close all buffer pools
        with self._lock:
            for pool in self._buffer_pools.values():
                try:
                    pool.close_all()
                except Exception:
                    pass
            
            self._buffer_pools.clear()
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except Exception:
            pass