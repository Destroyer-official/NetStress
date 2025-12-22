"""
NUMA-aware memory allocation and management system.
Provides optimized memory pools for high-performance packet processing.
"""

import threading
import time
import mmap
import ctypes
import os
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
import queue
import weakref

from ..platform.detection import PlatformType, PlatformDetector


class MemoryType(Enum):
    """Memory allocation types"""
    STANDARD = "standard"
    HUGE_PAGES = "huge_pages"
    LOCKED = "locked"
    NUMA_LOCAL = "numa_local"
    SHARED = "shared"


class MemoryAlignment(Enum):
    """Memory alignment options"""
    BYTE = 1
    WORD = 4
    DWORD = 8
    CACHE_LINE = 64
    PAGE = 4096


@dataclass
class MemoryBlock:
    """Represents a memory block"""
    address: int
    size: int
    memory_type: MemoryType
    alignment: MemoryAlignment
    numa_node: Optional[int]
    allocated_time: float
    last_accessed: float
    reference_count: int


@dataclass
class MemoryPoolStats:
    """Memory pool statistics"""
    total_allocated: int = 0
    total_freed: int = 0
    current_allocated: int = 0
    peak_allocated: int = 0
    allocation_failures: int = 0
    bytes_allocated: int = 0
    bytes_freed: int = 0
    fragmentation_ratio: float = 0.0


class NUMANode:
    """Represents a NUMA node with its memory and CPU information"""
    
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.cpu_cores: Set[int] = set()
        self.memory_size: int = 0
        self.available_memory: int = 0
        self.allocated_blocks: List[MemoryBlock] = []
        self.lock = threading.Lock()
    
    def add_cpu_core(self, core_id: int):
        """Add a CPU core to this NUMA node"""
        self.cpu_cores.add(core_id)
    
    def set_memory_info(self, total_memory: int, available_memory: int):
        """Set memory information for this NUMA node"""
        self.memory_size = total_memory
        self.available_memory = available_memory
    
    def allocate_memory(self, size: int) -> bool:
        """Check if memory can be allocated on this node"""
        with self.lock:
            if self.available_memory >= size:
                self.available_memory -= size
                return True
            return False
    
    def free_memory(self, size: int):
        """Free memory on this node"""
        with self.lock:
            self.available_memory += size
            if self.available_memory > self.memory_size:
                self.available_memory = self.memory_size


class NUMATopology:
    """NUMA topology detection and management"""
    
    def __init__(self):
        self.nodes: Dict[int, NUMANode] = {}
        self.current_cpu: Optional[int] = None
        self.platform_type = PlatformDetector.detect_platform()
        
        self._detect_topology()
    
    def _detect_topology(self):
        """Detect NUMA topology"""
        if self.platform_type == PlatformType.LINUX:
            self._detect_linux_topology()
        elif self.platform_type == PlatformType.WINDOWS:
            self._detect_windows_topology()
        elif self.platform_type == PlatformType.MACOS:
            self._detect_macos_topology()
        else:
            # Fallback: single node
            self._create_single_node()
    
    def _detect_linux_topology(self):
        """Detect NUMA topology on Linux"""
        try:
            # Read NUMA nodes
            numa_nodes_path = "/sys/devices/system/node"
            if os.path.exists(numa_nodes_path):
                for entry in os.listdir(numa_nodes_path):
                    if entry.startswith("node") and entry[4:].isdigit():
                        node_id = int(entry[4:])
                        node = NUMANode(node_id)
                        
                        # Read CPU cores for this node
                        cpulist_path = f"{numa_nodes_path}/{entry}/cpulist"
                        if os.path.exists(cpulist_path):
                            with open(cpulist_path, 'r') as f:
                                cpulist = f.read().strip()
                                for cpu_range in cpulist.split(','):
                                    if '-' in cpu_range:
                                        start, end = map(int, cpu_range.split('-'))
                                        for cpu in range(start, end + 1):
                                            node.add_cpu_core(cpu)
                                    else:
                                        node.add_cpu_core(int(cpu_range))
                        
                        # Read memory info
                        meminfo_path = f"{numa_nodes_path}/{entry}/meminfo"
                        if os.path.exists(meminfo_path):
                            with open(meminfo_path, 'r') as f:
                                for line in f:
                                    if "MemTotal:" in line:
                                        total_kb = int(line.split()[3])
                                        total_bytes = total_kb * 1024
                                        node.set_memory_info(total_bytes, total_bytes)
                                        break
                        
                        self.nodes[node_id] = node
            
            if not self.nodes:
                self._create_single_node()
                
        except Exception:
            self._create_single_node()
    
    def _detect_windows_topology(self):
        """Detect NUMA topology on Windows"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Try to get NUMA information using Windows API
            kernel32 = ctypes.windll.kernel32
            
            # Get number of NUMA nodes
            num_nodes = wintypes.ULONG()
            if kernel32.GetNumaHighestNodeNumber(ctypes.byref(num_nodes)):
                for node_id in range(num_nodes.value + 1):
                    node = NUMANode(node_id)
                    
                    # Get processor mask for this node
                    processor_mask = ctypes.c_ulonglong()
                    if kernel32.GetNumaNodeProcessorMask(node_id, ctypes.byref(processor_mask)):
                        # Extract CPU cores from processor mask
                        mask = processor_mask.value
                        cpu_id = 0
                        while mask:
                            if mask & 1:
                                node.add_cpu_core(cpu_id)
                            mask >>= 1
                            cpu_id += 1
                    
                    # Estimate memory (Windows doesn't provide easy NUMA memory info)
                    total_memory = PlatformDetector.get_memory_total()
                    node_memory = total_memory // (num_nodes.value + 1)
                    node.set_memory_info(node_memory, node_memory)
                    
                    self.nodes[node_id] = node
            
            if not self.nodes:
                self._create_single_node()
                
        except Exception:
            self._create_single_node()
    
    def _detect_macos_topology(self):
        """Detect NUMA topology on macOS (limited support)"""
        # macOS has limited NUMA support, create single node
        self._create_single_node()
    
    def _create_single_node(self):
        """Create a single NUMA node (fallback)"""
        node = NUMANode(0)
        
        # Add all CPU cores
        cpu_count = PlatformDetector.get_cpu_count()
        for cpu_id in range(cpu_count):
            node.add_cpu_core(cpu_id)
        
        # Set total memory
        total_memory = PlatformDetector.get_memory_total()
        node.set_memory_info(total_memory, total_memory)
        
        self.nodes[0] = node
    
    def get_current_numa_node(self) -> int:
        """Get the NUMA node for the current CPU"""
        try:
            if self.platform_type == PlatformType.LINUX:
                # Try to get current CPU
                with open('/proc/self/stat', 'r') as f:
                    fields = f.read().split()
                    if len(fields) > 38:
                        current_cpu = int(fields[38])
                        
                        # Find NUMA node for this CPU
                        for node_id, node in self.nodes.items():
                            if current_cpu in node.cpu_cores:
                                return node_id
            
            # Fallback to node 0
            return 0
            
        except Exception:
            return 0
    
    def get_best_numa_node(self, required_memory: int) -> int:
        """Get the best NUMA node for allocation"""
        best_node = 0
        best_available = 0
        
        for node_id, node in self.nodes.items():
            if node.available_memory >= required_memory:
                if node.available_memory > best_available:
                    best_available = node.available_memory
                    best_node = node_id
        
        return best_node
    
    def get_node_info(self, node_id: int) -> Optional[NUMANode]:
        """Get information about a NUMA node"""
        return self.nodes.get(node_id)
    
    def get_all_nodes(self) -> Dict[int, NUMANode]:
        """Get all NUMA nodes"""
        return self.nodes.copy()


class MemoryPool:
    """High-performance memory pool with NUMA awareness"""
    
    def __init__(self, block_size: int, initial_blocks: int = 10, 
                 max_blocks: int = 1000, memory_type: MemoryType = MemoryType.STANDARD,
                 alignment: MemoryAlignment = MemoryAlignment.CACHE_LINE,
                 numa_node: Optional[int] = None):
        
        self.block_size = block_size
        self.initial_blocks = initial_blocks
        self.max_blocks = max_blocks
        self.memory_type = memory_type
        self.alignment = alignment
        self.numa_node = numa_node
        
        self._available_blocks = queue.Queue(maxsize=max_blocks)
        self._allocated_blocks: Dict[int, MemoryBlock] = {}
        self._stats = MemoryPoolStats()
        self._lock = threading.Lock()
        
        # NUMA topology
        self._numa_topology = NUMATopology()
        
        # Pre-allocate initial blocks
        self._preallocate_blocks()
    
    def _preallocate_blocks(self):
        """Pre-allocate initial memory blocks"""
        for _ in range(self.initial_blocks):
            try:
                block = self._allocate_block()
                if block:
                    self._available_blocks.put_nowait(block)
            except Exception:
                break
    
    def _allocate_block(self) -> Optional[MemoryBlock]:
        """Allocate a single memory block"""
        try:
            # Determine NUMA node
            target_numa_node = self.numa_node
            if target_numa_node is None:
                target_numa_node = self._numa_topology.get_best_numa_node(self.block_size)
            
            # Allocate memory based on type
            if self.memory_type == MemoryType.HUGE_PAGES:
                address = self._allocate_huge_pages()
            elif self.memory_type == MemoryType.LOCKED:
                address = self._allocate_locked_memory()
            elif self.memory_type == MemoryType.SHARED:
                address = self._allocate_shared_memory()
            else:
                address = self._allocate_standard_memory()
            
            if address is None:
                return None
            
            # Create memory block
            block = MemoryBlock(
                address=address,
                size=self.block_size,
                memory_type=self.memory_type,
                alignment=self.alignment,
                numa_node=target_numa_node,
                allocated_time=time.time(),
                last_accessed=time.time(),
                reference_count=0
            )
            
            # Update NUMA node allocation
            numa_node_info = self._numa_topology.get_node_info(target_numa_node)
            if numa_node_info:
                numa_node_info.allocate_memory(self.block_size)
            
            # Update statistics
            with self._lock:
                self._stats.total_allocated += 1
                self._stats.current_allocated += 1
                self._stats.peak_allocated = max(self._stats.peak_allocated, self._stats.current_allocated)
                self._stats.bytes_allocated += self.block_size
            
            return block
            
        except Exception:
            with self._lock:
                self._stats.allocation_failures += 1
            return None
    
    def _allocate_standard_memory(self) -> Optional[int]:
        """Allocate standard memory"""
        try:
            # Use ctypes to allocate aligned memory
            size_with_alignment = self.block_size + self.alignment.value
            raw_ptr = ctypes.c_void_p()
            
            if hasattr(ctypes, 'pythonapi'):
                # Use Python's memory allocator
                ctypes.pythonapi.PyMem_Malloc.restype = ctypes.c_void_p
                ctypes.pythonapi.PyMem_Malloc.argtypes = [ctypes.c_size_t]
                raw_ptr = ctypes.pythonapi.PyMem_Malloc(size_with_alignment)
            else:
                # Fallback to libc malloc
                libc = ctypes.CDLL("libc.so.6" if os.name != 'nt' else "msvcrt.dll")
                libc.malloc.restype = ctypes.c_void_p
                libc.malloc.argtypes = [ctypes.c_size_t]
                raw_ptr = libc.malloc(size_with_alignment)
            
            if raw_ptr:
                # Align the pointer
                aligned_ptr = (raw_ptr + self.alignment.value - 1) & ~(self.alignment.value - 1)
                return aligned_ptr
            
            return None
            
        except Exception:
            return None
    
    def _allocate_huge_pages(self) -> Optional[int]:
        """Allocate memory using huge pages (Linux only)"""
        try:
            if self._numa_topology.platform_type != PlatformType.LINUX:
                return self._allocate_standard_memory()
            
            # Try to use huge pages
            flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
            
            # Check if huge pages are available
            try:
                flags |= mmap.MAP_HUGETLB
            except AttributeError:
                # MAP_HUGETLB not available, fallback to standard
                return self._allocate_standard_memory()
            
            # Allocate using mmap with huge pages
            mm = mmap.mmap(-1, self.block_size, flags=flags)
            return ctypes.addressof(ctypes.c_char.from_buffer(mm))
            
        except Exception:
            return self._allocate_standard_memory()
    
    def _allocate_locked_memory(self) -> Optional[int]:
        """Allocate locked memory (prevents swapping)"""
        try:
            # Allocate standard memory first
            address = self._allocate_standard_memory()
            if address is None:
                return None
            
            # Try to lock the memory
            if self._numa_topology.platform_type == PlatformType.LINUX:
                import ctypes
                libc = ctypes.CDLL("libc.so.6")
                libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.mlock.restype = ctypes.c_int
                
                result = libc.mlock(address, self.block_size)
                if result != 0:
                    # Lock failed, but still return the memory
                    pass
            
            return address
            
        except Exception:
            return self._allocate_standard_memory()
    
    def _allocate_shared_memory(self) -> Optional[int]:
        """Allocate shared memory"""
        try:
            # Create shared memory using mmap
            mm = mmap.mmap(-1, self.block_size, mmap.MAP_SHARED | mmap.MAP_ANONYMOUS)
            return ctypes.addressof(ctypes.c_char.from_buffer(mm))
            
        except Exception:
            return self._allocate_standard_memory()
    
    def get_block(self, timeout: Optional[float] = None) -> Optional[MemoryBlock]:
        """Get a memory block from the pool"""
        try:
            # Try to get from available blocks
            block = self._available_blocks.get(timeout=timeout)
            block.last_accessed = time.time()
            block.reference_count += 1
            
            with self._lock:
                self._allocated_blocks[block.address] = block
            
            return block
            
        except queue.Empty:
            # Pool is empty, try to allocate new block
            if self._stats.current_allocated < self.max_blocks:
                return self._allocate_block()
            else:
                with self._lock:
                    self._stats.allocation_failures += 1
                return None
    
    def return_block(self, block: MemoryBlock):
        """Return a memory block to the pool"""
        if block.address not in self._allocated_blocks:
            return
        
        with self._lock:
            del self._allocated_blocks[block.address]
        
        block.reference_count -= 1
        block.last_accessed = time.time()
        
        try:
            # Clear the memory block
            self._clear_block(block)
            
            # Return to available pool
            self._available_blocks.put_nowait(block)
            
        except queue.Full:
            # Pool is full, free the block
            self._free_block(block)
    
    def _clear_block(self, block: MemoryBlock):
        """Clear memory block contents"""
        try:
            ctypes.memset(block.address, 0, block.size)
        except Exception:
            pass
    
    def _free_block(self, block: MemoryBlock):
        """Free a memory block"""
        try:
            # Update NUMA node
            numa_node_info = self._numa_topology.get_node_info(block.numa_node or 0)
            if numa_node_info:
                numa_node_info.free_memory(block.size)
            
            # Free the memory based on type
            if block.memory_type == MemoryType.LOCKED:
                self._free_locked_memory(block)
            else:
                self._free_standard_memory(block)
            
            # Update statistics
            with self._lock:
                self._stats.current_allocated -= 1
                self._stats.total_freed += 1
                self._stats.bytes_freed += block.size
                
        except Exception:
            pass
    
    def _free_standard_memory(self, block: MemoryBlock):
        """Free standard memory"""
        try:
            if hasattr(ctypes, 'pythonapi'):
                ctypes.pythonapi.PyMem_Free.argtypes = [ctypes.c_void_p]
                ctypes.pythonapi.PyMem_Free(block.address)
            else:
                libc = ctypes.CDLL("libc.so.6" if os.name != 'nt' else "msvcrt.dll")
                libc.free.argtypes = [ctypes.c_void_p]
                libc.free(block.address)
        except Exception:
            pass
    
    def _free_locked_memory(self, block: MemoryBlock):
        """Free locked memory"""
        try:
            # Unlock memory first
            if self._numa_topology.platform_type == PlatformType.LINUX:
                libc = ctypes.CDLL("libc.so.6")
                libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.munlock(block.address, block.size)
            
            # Free the memory
            self._free_standard_memory(block)
            
        except Exception:
            self._free_standard_memory(block)
    
    def cleanup_old_blocks(self, max_age: float = 300.0):
        """Cleanup old unused blocks"""
        current_time = time.time()
        blocks_to_free = []
        
        # Check available blocks
        temp_blocks = []
        while not self._available_blocks.empty():
            try:
                block = self._available_blocks.get_nowait()
                if current_time - block.last_accessed > max_age:
                    blocks_to_free.append(block)
                else:
                    temp_blocks.append(block)
            except queue.Empty:
                break
        
        # Return non-old blocks
        for block in temp_blocks:
            try:
                self._available_blocks.put_nowait(block)
            except queue.Full:
                blocks_to_free.append(block)
        
        # Free old blocks
        for block in blocks_to_free:
            self._free_block(block)
    
    def get_statistics(self) -> MemoryPoolStats:
        """Get pool statistics"""
        with self._lock:
            stats = MemoryPoolStats(
                total_allocated=self._stats.total_allocated,
                total_freed=self._stats.total_freed,
                current_allocated=self._stats.current_allocated,
                peak_allocated=self._stats.peak_allocated,
                allocation_failures=self._stats.allocation_failures,
                bytes_allocated=self._stats.bytes_allocated,
                bytes_freed=self._stats.bytes_freed
            )
            
            # Calculate fragmentation ratio
            if self._stats.bytes_allocated > 0:
                used_bytes = (self._stats.current_allocated * self.block_size)
                stats.fragmentation_ratio = 1.0 - (used_bytes / self._stats.bytes_allocated)
            
            return stats
    
    def close_all(self):
        """Close and free all memory blocks"""
        # Free available blocks
        while not self._available_blocks.empty():
            try:
                block = self._available_blocks.get_nowait()
                self._free_block(block)
            except queue.Empty:
                break
        
        # Free allocated blocks
        with self._lock:
            for block in list(self._allocated_blocks.values()):
                self._free_block(block)
            self._allocated_blocks.clear()


class NUMAMemoryManager:
    """NUMA-aware memory manager for high-performance applications"""
    
    def __init__(self):
        self._memory_pools: Dict[Tuple[int, MemoryType], MemoryPool] = {}
        self._numa_topology = NUMATopology()
        self._lock = threading.Lock()
        self._cleanup_thread = None
        self._cleanup_interval = 120.0  # Cleanup every 2 minutes
        self._running = True
        
        # Standard pool sizes
        self._standard_sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        
        # Initialize standard pools
        self._init_standard_pools()
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _init_standard_pools(self):
        """Initialize standard memory pools"""
        for size in self._standard_sizes:
            for memory_type in [MemoryType.STANDARD, MemoryType.LOCKED]:
                try:
                    pool = MemoryPool(
                        block_size=size,
                        initial_blocks=5,
                        max_blocks=100,
                        memory_type=memory_type,
                        alignment=MemoryAlignment.CACHE_LINE
                    )
                    self._memory_pools[(size, memory_type)] = pool
                except Exception:
                    continue
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while self._running:
                try:
                    time.sleep(self._cleanup_interval)
                    if self._running:
                        self._cleanup_old_blocks()
                except Exception:
                    pass
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
    
    def _cleanup_old_blocks(self):
        """Cleanup old blocks in all pools"""
        with self._lock:
            for pool in self._memory_pools.values():
                try:
                    pool.cleanup_old_blocks()
                except Exception:
                    pass
    
    def allocate(self, size: int, memory_type: MemoryType = MemoryType.STANDARD,
                alignment: MemoryAlignment = MemoryAlignment.CACHE_LINE,
                numa_node: Optional[int] = None) -> Optional[MemoryBlock]:
        """Allocate memory block"""
        
        # Find best matching pool
        pool_key = self._find_best_pool(size, memory_type)
        
        if pool_key:
            pool = self._memory_pools[pool_key]
            block = pool.get_block(timeout=0.1)
            if block:
                return block
        
        # Create custom pool if needed
        return self._allocate_custom_block(size, memory_type, alignment, numa_node)
    
    def _find_best_pool(self, size: int, memory_type: MemoryType) -> Optional[Tuple[int, MemoryType]]:
        """Find the best matching memory pool"""
        # Look for exact size match
        exact_key = (size, memory_type)
        if exact_key in self._memory_pools:
            return exact_key
        
        # Find smallest pool that can accommodate the size
        suitable_sizes = [
            pool_size for (pool_size, pool_type) in self._memory_pools.keys()
            if pool_type == memory_type and pool_size >= size
        ]
        
        if suitable_sizes:
            best_size = min(suitable_sizes)
            return (best_size, memory_type)
        
        return None
    
    def _allocate_custom_block(self, size: int, memory_type: MemoryType,
                             alignment: MemoryAlignment, numa_node: Optional[int]) -> Optional[MemoryBlock]:
        """Allocate custom memory block"""
        try:
            pool = MemoryPool(
                block_size=size,
                initial_blocks=1,
                max_blocks=10,
                memory_type=memory_type,
                alignment=alignment,
                numa_node=numa_node
            )
            
            return pool.get_block()
            
        except Exception:
            return None
    
    def free(self, block: MemoryBlock):
        """Free memory block"""
        pool_key = (block.size, block.memory_type)
        
        if pool_key in self._memory_pools:
            self._memory_pools[pool_key].return_block(block)
        else:
            # Custom block, create temporary pool to free it
            try:
                temp_pool = MemoryPool(
                    block_size=block.size,
                    initial_blocks=0,
                    max_blocks=1,
                    memory_type=block.memory_type
                )
                temp_pool.return_block(block)
                temp_pool.close_all()
            except Exception:
                pass
    
    def allocate_packet_buffer(self, size: int = 1472) -> Optional[MemoryBlock]:
        """Allocate buffer for packet data"""
        return self.allocate(size, MemoryType.STANDARD, MemoryAlignment.CACHE_LINE)
    
    def allocate_locked_buffer(self, size: int) -> Optional[MemoryBlock]:
        """Allocate locked memory buffer"""
        return self.allocate(size, MemoryType.LOCKED, MemoryAlignment.CACHE_LINE)
    
    def allocate_numa_local_buffer(self, size: int, numa_node: int) -> Optional[MemoryBlock]:
        """Allocate NUMA-local buffer"""
        return self.allocate(size, MemoryType.NUMA_LOCAL, MemoryAlignment.CACHE_LINE, numa_node)
    
    def get_numa_topology(self) -> NUMATopology:
        """Get NUMA topology information"""
        return self._numa_topology
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive memory statistics"""
        stats = {
            'pools': {},
            'numa_topology': {},
            'total_stats': MemoryPoolStats()
        }
        
        # Pool statistics
        with self._lock:
            for (size, memory_type), pool in self._memory_pools.items():
                pool_stats = pool.get_statistics()
                
                pool_key = f"{memory_type.value}_{size}"
                stats['pools'][pool_key] = {
                    'size': size,
                    'memory_type': memory_type.value,
                    'stats': pool_stats
                }
                
                # Aggregate stats
                total = stats['total_stats']
                total.total_allocated += pool_stats.total_allocated
                total.total_freed += pool_stats.total_freed
                total.current_allocated += pool_stats.current_allocated
                total.peak_allocated += pool_stats.peak_allocated
                total.allocation_failures += pool_stats.allocation_failures
                total.bytes_allocated += pool_stats.bytes_allocated
                total.bytes_freed += pool_stats.bytes_freed
        
        # NUMA topology
        for node_id, node in self._numa_topology.get_all_nodes().items():
            stats['numa_topology'][f'node_{node_id}'] = {
                'cpu_cores': list(node.cpu_cores),
                'memory_size': node.memory_size,
                'available_memory': node.available_memory,
                'utilization': 1.0 - (node.available_memory / node.memory_size) if node.memory_size > 0 else 0.0
            }
        
        return stats
    
    def cleanup(self):
        """Cleanup all resources"""
        self._running = False
        
        # Wait for cleanup thread
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2.0)
        
        # Close all pools
        with self._lock:
            for pool in self._memory_pools.values():
                try:
                    pool.close_all()
                except Exception:
                    pass
            
            self._memory_pools.clear()
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.cleanup()
        except Exception:
            pass