#!/usr/bin/env python3
"""
Platform Abstraction Layer - Cross-platform compatibility and optimization
Provides unified interface for platform-specific operations and optimizations
"""

import asyncio
import logging
import platform
import os
import sys
import socket
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from .detection import PlatformDetector, PlatformType

logger = logging.getLogger(__name__)


# Platform Adapters for cross-platform compatibility
class PlatformAdapter(ABC):
    """Abstract base class for platform-specific adapters"""
    
    @abstractmethod
    def get_optimal_socket_options(self) -> Dict[str, Any]:
        """Get platform-optimized socket options"""
        pass
    
    @abstractmethod
    def get_max_connections(self) -> int:
        """Get maximum concurrent connections for this platform"""
        pass
    
    @abstractmethod
    def get_buffer_sizes(self) -> Dict[str, int]:
        """Get optimal buffer sizes"""
        pass
    
    @abstractmethod
    def apply_socket_optimizations(self, sock: socket.socket) -> None:
        """Apply platform-specific socket optimizations"""
        pass


class WindowsAdapter(PlatformAdapter):
    """Windows-specific platform adapter"""
    
    def get_optimal_socket_options(self) -> Dict[str, Any]:
        return {
            'SO_REUSEADDR': True,
            'TCP_NODELAY': True,
            'SO_KEEPALIVE': False,
            'SO_SNDBUF': 65536,
            'SO_RCVBUF': 65536,
        }
    
    def get_max_connections(self) -> int:
        return 16384  # Windows default limit
    
    def get_buffer_sizes(self) -> Dict[str, int]:
        return {
            'send_buffer': 65536,
            'recv_buffer': 65536,
            'packet_buffer': 8192,
        }
    
    def apply_socket_optimizations(self, sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        except Exception as e:
            logger.debug(f"Could not apply all socket optimizations: {e}")


class LinuxAdapter(PlatformAdapter):
    """Linux-specific platform adapter"""
    
    def get_optimal_socket_options(self) -> Dict[str, Any]:
        return {
            'SO_REUSEADDR': True,
            'SO_REUSEPORT': True,
            'TCP_NODELAY': True,
            'TCP_QUICKACK': True,
            'SO_KEEPALIVE': False,
            'SO_SNDBUF': 262144,
            'SO_RCVBUF': 262144,
        }
    
    def get_max_connections(self) -> int:
        try:
            with open('/proc/sys/net/core/somaxconn', 'r') as f:
                return int(f.read().strip())
        except:
            return 65535
    
    def get_buffer_sizes(self) -> Dict[str, int]:
        return {
            'send_buffer': 262144,
            'recv_buffer': 262144,
            'packet_buffer': 16384,
        }
    
    def apply_socket_optimizations(self, sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except Exception as e:
            logger.debug(f"Could not apply all socket optimizations: {e}")


class MacOSAdapter(PlatformAdapter):
    """macOS-specific platform adapter"""
    
    def get_optimal_socket_options(self) -> Dict[str, Any]:
        return {
            'SO_REUSEADDR': True,
            'SO_REUSEPORT': True,
            'TCP_NODELAY': True,
            'SO_KEEPALIVE': False,
            'SO_SNDBUF': 131072,
            'SO_RCVBUF': 131072,
        }
    
    def get_max_connections(self) -> int:
        return 32768
    
    def get_buffer_sizes(self) -> Dict[str, int]:
        return {
            'send_buffer': 131072,
            'recv_buffer': 131072,
            'packet_buffer': 8192,
        }
    
    def apply_socket_optimizations(self, sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        except Exception as e:
            logger.debug(f"Could not apply all socket optimizations: {e}")


@dataclass
class SocketConfig:
    """Socket configuration settings"""
    send_buffer_size: int = 65536
    recv_buffer_size: int = 65536
    tcp_nodelay: bool = True
    reuse_addr: bool = True
    reuse_port: bool = False
    keep_alive: bool = False
    timeout: float = 5.0


@dataclass
class SystemInfo:
    """System information container"""
    platform_type: str
    system: str
    release: str
    version: str
    machine: str
    processor: str
    cpu_count: int
    memory_total: int = 0


class PlatformEngine:
    """
    Main platform engine that provides cross-platform compatibility
    and platform-specific optimizations for network operations.
    """
    
    def __init__(self):
        self.detector = PlatformDetector()
        self.system_info = self._get_system_info()
        self.adapter = self._create_adapter()
        logger.info(f"PlatformEngine initialized for {self.system_info.system}")
    
    def _get_system_info(self) -> SystemInfo:
        """Get system information"""
        import multiprocessing
        
        system = platform.system()
        platform_type = system.lower()
        if platform_type == 'darwin':
            platform_type = 'macos'
        
        cpu_count = multiprocessing.cpu_count()
        
        # Get memory info
        memory_total = 0
        try:
            import psutil
            memory_total = psutil.virtual_memory().total
        except ImportError:
            pass
        
        return SystemInfo(
            platform_type=platform_type,
            system=system,
            release=platform.release(),
            version=platform.version(),
            machine=platform.machine(),
            processor=platform.processor(),
            cpu_count=cpu_count,
            memory_total=memory_total
        )
    
    def _create_adapter(self) -> PlatformAdapter:
        """Create platform-specific adapter"""
        system = platform.system().lower()
        
        if system == 'windows':
            return WindowsAdapter()
        elif system == 'linux':
            return LinuxAdapter()
        elif system == 'darwin':
            return MacOSAdapter()
        else:
            # Default to Linux adapter for unknown systems
            logger.warning(f"Unknown platform {system}, using Linux adapter")
            return LinuxAdapter()
    
    def get_optimal_socket_config(self, protocol: str = "TCP") -> SocketConfig:
        """Get optimal socket configuration for the current platform"""
        buffer_sizes = self.adapter.get_buffer_sizes()
        options = self.adapter.get_optimal_socket_options()
        
        return SocketConfig(
            send_buffer_size=buffer_sizes.get('send_buffer', 65536),
            recv_buffer_size=buffer_sizes.get('recv_buffer', 65536),
            tcp_nodelay=options.get('TCP_NODELAY', True),
            reuse_addr=options.get('SO_REUSEADDR', True),
            reuse_port=options.get('SO_REUSEPORT', False),
            keep_alive=options.get('SO_KEEPALIVE', False),
        )
    
    def get_max_performance_settings(self) -> Dict[str, Any]:
        """Get maximum performance settings for the platform"""
        return {
            'max_connections': self.adapter.get_max_connections(),
            'buffer_sizes': self.adapter.get_buffer_sizes(),
            'socket_options': self.adapter.get_optimal_socket_options(),
            'cpu_count': self.system_info.cpu_count,
            'recommended_workers': max(1, self.system_info.cpu_count - 1),
        }
    
    def get_network_capabilities(self) -> Dict[str, Any]:
        """Get network capabilities for the platform"""
        capabilities = {
            'raw_sockets': False,
            'high_performance_timer': hasattr(time, 'perf_counter'),
            'async_io': True,
            'multiprocessing': True,
            'max_connections': self.adapter.get_max_connections(),
        }
        
        # Check raw socket support
        if platform.system() == 'Windows':
            capabilities['raw_sockets'] = True  # With Npcap
        elif platform.system() in ['Linux', 'Darwin']:
            capabilities['raw_sockets'] = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        return capabilities
    
    def get_system_info(self) -> SystemInfo:
        """Get system information (returns cached system_info)"""
        return self.system_info
    
    def create_optimized_socket(self, 
                                socket_type: int = socket.SOCK_STREAM,
                                protocol: int = 0) -> socket.socket:
        """Create an optimized socket for the current platform"""
        sock = socket.socket(socket.AF_INET, socket_type, protocol)
        self.adapter.apply_socket_optimizations(sock)
        return sock
    
    def apply_optimizations(self, sock: socket.socket) -> None:
        """Apply platform-specific optimizations to an existing socket"""
        self.adapter.apply_socket_optimizations(sock)

class OptimizationType(Enum):
    MEMORY = "memory"
    CPU = "cpu"
    NETWORK = "network"
    IO = "io"
    KERNEL = "kernel"

@dataclass
class PlatformCapabilities:
    """Platform capabilities and features"""
    has_raw_sockets: bool = False
    has_high_resolution_timer: bool = False
    has_numa_support: bool = False
    has_cpu_affinity: bool = False
    has_memory_locking: bool = False
    has_kernel_bypass: bool = False
    max_file_descriptors: int = 1024
    max_threads: int = 1000
    page_size: int = 4096

class PlatformAbstraction:
    """Cross-platform abstraction layer"""
    
    def __init__(self):
        self.detector = PlatformDetector()
        self.platform_info = None
        self.capabilities = None
        self.optimizations = {}
        
        logger.info("Platform Abstraction Layer initialized")
    
    async def initialize(self):
        """Initialize platform abstraction"""
        try:
            # Detect platform - use get_system_info() for full SystemInfo object
            self.platform_info = self.detector.get_system_info()
            
            # Detect capabilities
            self.capabilities = await self._detect_capabilities()
            
            # Load platform-specific optimizations
            await self._load_optimizations()
            
            # Get system name from platform_type enum
            system_name = self.platform_info.platform_type.value if self.platform_info.platform_type else 'unknown'
            logger.info(f"Platform abstraction initialized for {system_name}")
            
        except Exception as e:
            logger.error(f"Platform abstraction initialization failed: {e}")
            raise
    
    @property
    def system(self) -> str:
        """Get the system name string"""
        if self.platform_info and self.platform_info.platform_type:
            return platform.system()  # Returns 'Windows', 'Linux', 'Darwin'
        return platform.system()
    
    async def _detect_capabilities(self) -> PlatformCapabilities:
        """Detect platform capabilities"""
        capabilities = PlatformCapabilities()
        system = platform.system()  # Get actual system name
        
        try:
            # Check raw socket support
            if system in ['Linux', 'Darwin']:
                capabilities.has_raw_sockets = os.geteuid() == 0  # Root required
            elif system == 'Windows':
                capabilities.has_raw_sockets = True  # With Npcap
            
            # Check high resolution timer
            capabilities.has_high_resolution_timer = hasattr(time, 'perf_counter')
            
            # Check CPU affinity support
            try:
                import psutil
                capabilities.has_cpu_affinity = hasattr(psutil.Process(), 'cpu_affinity')
            except ImportError:
                capabilities.has_cpu_affinity = False
            
            # Check NUMA support
            if system == 'Linux':
                capabilities.has_numa_support = os.path.exists('/sys/devices/system/node')
            
            # Check memory locking
            if system in ['Linux', 'Darwin']:
                try:
                    import mlock
                    capabilities.has_memory_locking = True
                except ImportError:
                    capabilities.has_memory_locking = False
            
            # Get system limits
            try:
                import resource
                capabilities.max_file_descriptors = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            except (ImportError, OSError):
                capabilities.max_file_descriptors = 1024
            
            # Get page size
            try:
                capabilities.page_size = os.sysconf('SC_PAGE_SIZE')
            except (AttributeError, OSError):
                capabilities.page_size = 4096
            
        except Exception as e:
            logger.error(f"Capability detection failed: {e}")
        
        return capabilities
    
    async def _load_optimizations(self):
        """Load platform-specific optimizations"""
        system = platform.system()  # Get actual system name
        if system == 'Linux':
            await self._load_linux_optimizations()
        elif system == 'Windows':
            await self._load_windows_optimizations()
        elif system == 'Darwin':
            await self._load_macos_optimizations()
    
    async def _load_linux_optimizations(self):
        """Load Linux-specific optimizations"""
        self.optimizations[OptimizationType.KERNEL] = {
            'tcp_congestion_control': 'bbr',
            'tcp_window_scaling': True,
            'tcp_timestamps': False,
            'tcp_sack': True,
            'tcp_fack': True,
            'ip_forward': False,
            'net_core_rmem_max': 268435456,
            'net_core_wmem_max': 268435456
        }
        
        self.optimizations[OptimizationType.MEMORY] = {
            'vm_swappiness': 1,
            'vm_dirty_ratio': 15,
            'vm_dirty_background_ratio': 5,
            'transparent_hugepages': 'madvise'
        }
        
        self.optimizations[OptimizationType.CPU] = {
            'cpu_governor': 'performance',
            'cpu_scaling_min_freq': 'max',
            'irq_balance': False
        }
    
    async def _load_windows_optimizations(self):
        """Load Windows-specific optimizations"""
        self.optimizations[OptimizationType.NETWORK] = {
            'tcp_chimney_offload': True,
            'tcp_window_auto_tuning': 'normal',
            'receive_side_scaling': True,
            'tcp_global_parameters': {
                'TcpTimedWaitDelay': 30,
                'MaxUserPort': 65534,
                'TcpNumConnections': 16777214
            }
        }
        
        self.optimizations[OptimizationType.MEMORY] = {
            'large_page_minimum': 2097152,  # 2MB
            'lock_pages_in_memory': True
        }
    
    async def _load_macos_optimizations(self):
        """Load macOS-specific optimizations"""
        self.optimizations[OptimizationType.NETWORK] = {
            'net_inet_tcp_sendspace': 131072,
            'net_inet_tcp_recvspace': 131072,
            'net_inet_tcp_mssdflt': 1460,
            'kern_ipc_maxsockbuf': 8388608
        }
        
        self.optimizations[OptimizationType.MEMORY] = {
            'vm_compressor_mode': 4,
            'vm_pressure_threshold': 0.85
        }
    
    def get_platform_info(self):
        """Get platform information"""
        return self.platform_info
    
    def get_capabilities(self) -> PlatformCapabilities:
        """Get platform capabilities"""
        return self.capabilities
    
    def get_available_optimizations(self) -> List[str]:
        """Get list of available optimizations"""
        optimizations = []
        for opt_type, opts in self.optimizations.items():
            optimizations.extend([f"{opt_type.value}_{key}" for key in opts.keys()])
        return optimizations
    
    async def apply_optimization(self, optimization_type: OptimizationType, 
                               optimization_name: str) -> bool:
        """Apply a specific optimization"""
        try:
            if optimization_type not in self.optimizations:
                logger.warning(f"No optimizations available for {optimization_type}")
                return False
            
            opts = self.optimizations[optimization_type]
            if optimization_name not in opts:
                logger.warning(f"Optimization {optimization_name} not found")
                return False
            
            value = opts[optimization_name]
            system = platform.system()  # Get actual system name
            
            if system == 'Linux':
                return await self._apply_linux_optimization(optimization_name, value)
            elif system == 'Windows':
                return await self._apply_windows_optimization(optimization_name, value)
            elif system == 'Darwin':
                return await self._apply_macos_optimization(optimization_name, value)
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to apply optimization {optimization_name}: {e}")
            return False
    
    async def _apply_linux_optimization(self, name: str, value: Any) -> bool:
        """Apply Linux-specific optimization"""
        try:
            if name.startswith('net_'):
                # Network optimization
                sysctl_name = name.replace('_', '.')
                cmd = f"sysctl -w {sysctl_name}={value}"
                result = os.system(cmd)
                return result == 0
            elif name.startswith('vm_'):
                # Memory optimization
                sysctl_name = name.replace('_', '.')
                cmd = f"sysctl -w {sysctl_name}={value}"
                result = os.system(cmd)
                return result == 0
            elif name == 'tcp_congestion_control':
                cmd = f"sysctl -w net.ipv4.tcp_congestion_control={value}"
                result = os.system(cmd)
                return result == 0
            
            return True
            
        except Exception as e:
            logger.error(f"Linux optimization failed: {e}")
            return False
    
    async def _apply_windows_optimization(self, name: str, value: Any) -> bool:
        """Apply Windows-specific optimization"""
        try:
            # Windows optimizations would require registry changes
            # For safety, we'll just log the optimization
            logger.info(f"Windows optimization: {name} = {value}")
            return True
            
        except Exception as e:
            logger.error(f"Windows optimization failed: {e}")
            return False
    
    async def _apply_macos_optimization(self, name: str, value: Any) -> bool:
        """Apply macOS-specific optimization"""
        try:
            if name.startswith('net_') or name.startswith('kern_'):
                cmd = f"sysctl -w {name}={value}"
                result = os.system(cmd)
                return result == 0
            
            return True
            
        except Exception as e:
            logger.error(f"macOS optimization failed: {e}")
            return False
    
    async def optimize_for_performance(self) -> Dict[str, bool]:
        """Apply all performance optimizations"""
        results = {}
        
        for opt_type, opts in self.optimizations.items():
            for opt_name in opts.keys():
                result = await self.apply_optimization(opt_type, opt_name)
                results[f"{opt_type.value}_{opt_name}"] = result
        
        return results
    
    def get_optimal_worker_count(self) -> int:
        """Get optimal number of worker processes"""
        try:
            import multiprocessing
            cpu_count = multiprocessing.cpu_count()
            system = platform.system()  # Get actual system name
            
            # Adjust based on platform and capabilities
            if system == 'Linux':
                # Linux can handle more workers
                return cpu_count * 2
            elif system == 'Windows':
                # Windows is more conservative
                return max(1, cpu_count - 1)
            else:
                # macOS and others
                return cpu_count
                
        except Exception:
            return 4  # Safe default
    
    def get_optimal_buffer_size(self) -> int:
        """Get optimal buffer size for the platform"""
        if self.capabilities:
            # Base on page size
            return self.capabilities.page_size * 64  # 64 pages
        else:
            return 262144  # 256KB default
    
    def supports_feature(self, feature: str) -> bool:
        """Check if platform supports a specific feature"""
        if not self.capabilities:
            return False
        
        feature_map = {
            'raw_sockets': self.capabilities.has_raw_sockets,
            'high_resolution_timer': self.capabilities.has_high_resolution_timer,
            'numa': self.capabilities.has_numa_support,
            'cpu_affinity': self.capabilities.has_cpu_affinity,
            'memory_locking': self.capabilities.has_memory_locking,
            'kernel_bypass': self.capabilities.has_kernel_bypass
        }
        
        return feature_map.get(feature, False)
    
    async def get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource information"""
        resources = {}
        
        try:
            import psutil
            
            # CPU information
            resources['cpu'] = {
                'count': psutil.cpu_count(),
                'usage': psutil.cpu_percent(interval=1),
                'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            resources['memory'] = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': memory.percent
            }
            
            # Disk information
            disk = psutil.disk_usage('/')
            resources['disk'] = {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': (disk.used / disk.total) * 100
            }
            
            # Network information
            network = psutil.net_io_counters()
            resources['network'] = {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            }
            
        except ImportError:
            logger.warning("psutil not available, limited resource information")
            resources = {
                'cpu': {'count': os.cpu_count() or 1},
                'memory': {'total': 0, 'available': 0},
                'disk': {'total': 0, 'free': 0},
                'network': {'bytes_sent': 0, 'bytes_recv': 0}
            }
        
        return resources