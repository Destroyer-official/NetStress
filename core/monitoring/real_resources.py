"""Real resource monitoring using psutil and OS-level APIs."""

import logging
import platform
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

logger = logging.getLogger(__name__)


@dataclass
class ResourceUsage:
    """Real resource usage measurement."""
    timestamp: datetime
    cpu_percent: float
    cpu_per_core: List[float]
    memory_rss_mb: float
    memory_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    network_packets_sent: int
    network_packets_recv: int
    disk_read_mb: float
    disk_write_mb: float
    source: str


@dataclass
class ResourceLimits:
    """Resource usage limits for enforcement."""
    max_cpu_percent: Optional[float] = None
    max_memory_mb: Optional[float] = None
    max_network_mbps: Optional[float] = None
    max_disk_mbps: Optional[float] = None


class RealResourceMonitor:
    """Real resource monitoring using psutil and OS APIs."""

    def __init__(self, limits: Optional[ResourceLimits] = None, monitoring_interval: float = 1.0):
        if not PSUTIL_AVAILABLE:
            raise ImportError("psutil is required for resource monitoring")
        
        self.platform = platform.system()
        self.limits = limits or ResourceLimits()
        self.monitoring_interval = monitoring_interval
        self.process = psutil.Process()
        
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._limit_callbacks: List[Callable[[str, float], None]] = []
        self._log_counter = 0
        
        self._baseline_net = self._get_network_counters()
        self._baseline_disk = self._get_disk_counters()
        self._baseline_time = time.time()
        
        logger.info(f"RealResourceMonitor initialized on {self.platform}")

    def get_cpu_usage(self) -> Dict[str, float]:
        """Get real CPU usage using psutil."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'cpu_per_core': psutil.cpu_percent(interval=0.1, percpu=True),
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True)
            }
        except Exception as e:
            logger.error(f"Failed to get CPU usage: {e}")
            return {'cpu_percent': 0.0, 'cpu_per_core': [], 'cpu_count': 1, 'cpu_count_logical': 1}

    def get_memory_usage(self) -> Dict[str, float]:
        """Get real memory usage using RSS."""
        try:
            memory_info = self.process.memory_info()
            system_memory = psutil.virtual_memory()
            return {
                'rss_mb': memory_info.rss / (1024 * 1024),
                'vms_mb': memory_info.vms / (1024 * 1024),
                'memory_percent': self.process.memory_percent(),
                'system_total_mb': system_memory.total / (1024 * 1024),
                'system_available_mb': system_memory.available / (1024 * 1024),
                'system_used_percent': system_memory.percent
            }
        except Exception as e:
            logger.error(f"Failed to get memory usage: {e}")
            return {'rss_mb': 0.0, 'vms_mb': 0.0, 'memory_percent': 0.0,
                    'system_total_mb': 0.0, 'system_available_mb': 0.0, 'system_used_percent': 0.0}

    def _get_network_counters(self) -> Dict[str, int]:
        """Get current network I/O counters."""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except Exception:
            return {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0}

    def _get_disk_counters(self) -> Dict[str, int]:
        """Get current disk I/O counters."""
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                return {'read_bytes': disk_io.read_bytes, 'write_bytes': disk_io.write_bytes}
        except Exception:
            pass
        return {'read_bytes': 0, 'write_bytes': 0}

    def get_network_usage(self) -> Dict[str, Any]:
        """Get real network usage from OS interface statistics."""
        current_net = self._get_network_counters()
        time_delta = max(time.time() - self._baseline_time, 1.0)
        
        bytes_sent_delta = current_net['bytes_sent'] - self._baseline_net['bytes_sent']
        bytes_recv_delta = current_net['bytes_recv'] - self._baseline_net['bytes_recv']
        
        send_mbps = (bytes_sent_delta * 8) / (1_000_000 * time_delta)
        recv_mbps = (bytes_recv_delta * 8) / (1_000_000 * time_delta)
        
        return {
            'bytes_sent': current_net['bytes_sent'],
            'bytes_recv': current_net['bytes_recv'],
            'packets_sent': current_net['packets_sent'],
            'packets_recv': current_net['packets_recv'],
            'send_mbps': send_mbps,
            'recv_mbps': recv_mbps,
            'total_mbps': send_mbps + recv_mbps,
            'measurement_period_seconds': time_delta
        }

    def get_disk_usage(self) -> Dict[str, Any]:
        """Get real disk I/O usage."""
        current_disk = self._get_disk_counters()
        time_delta = max(time.time() - self._baseline_time, 1.0)
        
        read_delta = current_disk['read_bytes'] - self._baseline_disk['read_bytes']
        write_delta = current_disk['write_bytes'] - self._baseline_disk['write_bytes']
        
        return {
            'read_bytes': current_disk['read_bytes'],
            'write_bytes': current_disk['write_bytes'],
            'read_mbps': read_delta / (1_000_000 * time_delta),
            'write_mbps': write_delta / (1_000_000 * time_delta),
            'total_mbps': (read_delta + write_delta) / (1_000_000 * time_delta),
            'measurement_period_seconds': time_delta
        }

    def get_current_usage(self) -> ResourceUsage:
        """Get comprehensive current resource usage."""
        cpu_data = self.get_cpu_usage()
        memory_data = self.get_memory_usage()
        network_data = self.get_network_usage()
        disk_data = self.get_disk_usage()
        
        return ResourceUsage(
            timestamp=datetime.now(),
            cpu_percent=cpu_data['cpu_percent'],
            cpu_per_core=cpu_data['cpu_per_core'],
            memory_rss_mb=memory_data['rss_mb'],
            memory_percent=memory_data['memory_percent'],
            network_bytes_sent=network_data['bytes_sent'],
            network_bytes_recv=network_data['bytes_recv'],
            network_packets_sent=network_data['packets_sent'],
            network_packets_recv=network_data['packets_recv'],
            disk_read_mb=disk_data['read_bytes'] / (1024 * 1024),
            disk_write_mb=disk_data['write_bytes'] / (1024 * 1024),
            source='psutil'
        )

    def add_limit_callback(self, callback: Callable[[str, float], None]) -> None:
        """Add callback for when resource limits are exceeded."""
        self._limit_callbacks.append(callback)

    def _check_limits(self, usage: ResourceUsage) -> None:
        """Check if any resource limits are exceeded."""
        if not self.limits:
            return
        
        checks = [
            (self.limits.max_cpu_percent, usage.cpu_percent, 'cpu'),
            (self.limits.max_memory_mb, usage.memory_rss_mb, 'memory'),
        ]
        
        for limit, value, name in checks:
            if limit is not None and value > limit:
                logger.warning(f"{name.upper()} limit exceeded: {value:.1f} > {limit}")
                for callback in self._limit_callbacks:
                    try:
                        callback(name, value)
                    except Exception as e:
                        logger.error(f"Limit callback failed: {e}")
        
        if self.limits.max_network_mbps is not None:
            network_data = self.get_network_usage()
            if network_data['total_mbps'] > self.limits.max_network_mbps:
                logger.warning(f"Network limit exceeded: {network_data['total_mbps']:.1f}Mbps")
                for callback in self._limit_callbacks:
                    try:
                        callback('network', network_data['total_mbps'])
                    except Exception as e:
                        logger.error(f"Limit callback failed: {e}")

    def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._monitoring:
            try:
                usage = self.get_current_usage()
                self._check_limits(usage)
                self._log_counter += 1
                
                if self._log_counter % 10 == 0:
                    logger.debug(f"Resources: CPU={usage.cpu_percent:.1f}%, "
                               f"Memory={usage.memory_rss_mb:.1f}MB")
                
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.monitoring_interval)

    def start_monitoring(self) -> None:
        """Start background resource monitoring."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, name="ResourceMonitor", daemon=True)
        self._monitor_thread.start()
        logger.info("Started background resource monitoring")

    def stop_monitoring(self) -> None:
        """Stop background resource monitoring."""
        if not self._monitoring:
            return
        
        self._monitoring = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)
        logger.info("Stopped background resource monitoring")

    def reset_baseline(self) -> None:
        """Reset baseline measurements for rate calculations."""
        self._baseline_net = self._get_network_counters()
        self._baseline_disk = self._get_disk_counters()
        self._baseline_time = time.time()

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for context."""
        try:
            return {
                'platform': self.platform,
                'cpu_count': psutil.cpu_count(),
                'cpu_count_logical': psutil.cpu_count(logical=True),
                'memory_total_gb': psutil.virtual_memory().total / (1024**3),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()),
            }
        except Exception as e:
            return {'platform': self.platform, 'error': str(e)}
