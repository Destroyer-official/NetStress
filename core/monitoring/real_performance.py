"""Real performance monitoring using OS-level counters."""

import logging
import platform
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class PerformanceResult:
    """Real performance measurement result."""
    timestamp: datetime
    duration_seconds: float
    packets_sent: int
    bytes_sent: int
    packets_per_second: float
    megabits_per_second: float
    gigabits_per_second: float
    errors: int
    source: str
    interface: str
    methodology: str


class RealPerformanceMonitor:
    """Real performance monitoring using OS-level counters."""

    def __init__(self, interface: Optional[str] = None):
        self.platform = platform.system()
        self.start_time: Optional[float] = None
        self.start_counters: Optional[Dict[str, int]] = None
        self.interface = interface or self._get_default_interface()
        logger.info(f"RealPerformanceMonitor initialized for {self.interface}")

    def _get_default_interface(self) -> str:
        """Get the default network interface."""
        if self.platform == 'Linux':
            try:
                result = subprocess.run(
                    ['ip', 'route', 'get', '8.8.8.8'],
                    capture_output=True, text=True, timeout=5
                )
                parts = result.stdout.split()
                for i, part in enumerate(parts):
                    if part == 'dev' and i + 1 < len(parts):
                        return parts[i + 1]
            except Exception:
                pass
            return 'eth0'
        elif self.platform == 'Windows':
            return 'Ethernet'
        return 'en0'

    def get_interface_stats(self) -> Dict[str, int]:
        """Get real interface statistics from the OS."""
        if self.platform == 'Linux':
            return self._get_linux_interface_stats()
        return self._get_psutil_stats()

    def _get_linux_interface_stats(self) -> Dict[str, int]:
        """Read stats from /proc/net/dev."""
        stats = {'tx_packets': 0, 'tx_bytes': 0, 'rx_packets': 0, 
                 'rx_bytes': 0, 'tx_errors': 0, 'rx_errors': 0}
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if self.interface in line and ':' in line:
                        data_part = line.split(':', 1)[1].strip()
                        parts = data_part.split()
                        if len(parts) >= 16:
                            stats['rx_bytes'] = int(parts[0])
                            stats['rx_packets'] = int(parts[1])
                            stats['rx_errors'] = int(parts[2])
                            stats['tx_bytes'] = int(parts[8])
                            stats['tx_packets'] = int(parts[9])
                            stats['tx_errors'] = int(parts[10])
                        break
        except Exception as e:
            logger.error(f"Failed to read /proc/net/dev: {e}")
            return self._get_psutil_stats()
        return stats

    def _get_psutil_stats(self) -> Dict[str, int]:
        """Fallback using psutil."""
        stats = {'tx_packets': 0, 'tx_bytes': 0, 'rx_packets': 0,
                 'rx_bytes': 0, 'tx_errors': 0, 'rx_errors': 0}
        
        if not PSUTIL_AVAILABLE:
            return stats
        
        try:
            counters = psutil.net_io_counters(pernic=True)
            if self.interface in counters:
                c = counters[self.interface]
                stats.update({
                    'tx_packets': c.packets_sent,
                    'tx_bytes': c.bytes_sent,
                    'rx_packets': c.packets_recv,
                    'rx_bytes': c.bytes_recv,
                    'tx_errors': c.errout,
                    'rx_errors': c.errin
                })
            else:
                for iface_name, c in counters.items():
                    if c.bytes_sent > 0 or c.bytes_recv > 0:
                        self.interface = iface_name
                        stats.update({
                            'tx_packets': c.packets_sent,
                            'tx_bytes': c.bytes_sent,
                            'rx_packets': c.packets_recv,
                            'rx_bytes': c.bytes_recv,
                            'tx_errors': c.errout,
                            'rx_errors': c.errin
                        })
                        break
        except Exception as e:
            logger.error(f"psutil stats failed: {e}")
        return stats

    def start_measurement(self) -> None:
        """Start a measurement period."""
        self.start_time = time.perf_counter()
        self.start_counters = self.get_interface_stats()

    def get_measurement(self) -> PerformanceResult:
        """Get real performance metrics since start_measurement()."""
        if not self.start_time or not self.start_counters:
            raise ValueError("Must call start_measurement() first")

        elapsed = time.perf_counter() - self.start_time
        current = self.get_interface_stats()

        tx_packets = current['tx_packets'] - self.start_counters['tx_packets']
        tx_bytes = current['tx_bytes'] - self.start_counters['tx_bytes']
        tx_errors = current['tx_errors'] - self.start_counters['tx_errors']

        pps = tx_packets / elapsed if elapsed > 0 else 0
        mbps = (tx_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else 0
        gbps = (tx_bytes * 8 / 1_000_000_000) / elapsed if elapsed > 0 else 0

        return PerformanceResult(
            timestamp=datetime.now(),
            duration_seconds=elapsed,
            packets_sent=tx_packets,
            bytes_sent=tx_bytes,
            packets_per_second=pps,
            megabits_per_second=mbps,
            gigabits_per_second=gbps,
            errors=tx_errors,
            source='os_counters',
            interface=self.interface,
            methodology=f"OS counters from {self.platform} interface {self.interface}"
        )

    def get_current_stats(self) -> Dict[str, Any]:
        """Get current interface statistics."""
        return {
            'interface': self.interface,
            'platform': self.platform,
            'timestamp': datetime.now(),
            'counters': self.get_interface_stats(),
            'source': 'os_counters'
        }

    def reset_measurement(self) -> None:
        """Reset measurement period."""
        self.start_time = None
        self.start_counters = None
