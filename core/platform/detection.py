"""
Platform detection logic for Windows, Linux, and macOS.
Provides comprehensive system information and capability detection.
"""

import platform
import sys
import os
import subprocess
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass


class PlatformType(Enum):
    """Supported platform types"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """System architectures"""
    X86_64 = "x86_64"
    ARM64 = "arm64"
    X86 = "x86"
    UNKNOWN = "unknown"


@dataclass
class SystemInfo:
    """Comprehensive system information"""
    platform_type: PlatformType
    architecture: Architecture
    kernel_version: str
    os_version: str
    cpu_count: int
    memory_total: int
    has_admin_privileges: bool
    supports_raw_sockets: bool
    network_interfaces: List[str]
    max_file_descriptors: int


class PlatformDetector:
    """Detects platform type and system capabilities"""
    
    @staticmethod
    def detect_platform() -> PlatformType:
        """Detect the current platform type"""
        system = platform.system().lower()
        
        if system == "windows":
            return PlatformType.WINDOWS
        elif system == "linux":
            return PlatformType.LINUX
        elif system == "darwin":
            return PlatformType.MACOS
        else:
            return PlatformType.UNKNOWN
    
    @staticmethod
    def detect_architecture() -> Architecture:
        """Detect system architecture"""
        machine = platform.machine().lower()
        
        if machine in ["x86_64", "amd64"]:
            return Architecture.X86_64
        elif machine in ["arm64", "aarch64"]:
            return Architecture.ARM64
        elif machine in ["i386", "i686", "x86"]:
            return Architecture.X86
        else:
            return Architecture.UNKNOWN
    
    @staticmethod
    def get_kernel_version() -> str:
        """Get kernel version string"""
        try:
            return platform.release()
        except Exception:
            return "unknown"
    
    @staticmethod
    def get_os_version() -> str:
        """Get detailed OS version"""
        try:
            return platform.version()
        except Exception:
            return "unknown"
    
    @staticmethod
    def get_cpu_count() -> int:
        """Get number of CPU cores"""
        try:
            return os.cpu_count() or 1
        except Exception:
            return 1
    
    def get_platform(self) -> str:
        """Get platform name as string"""
        return self.detect_platform().value
    
    @staticmethod
    def get_platform_info() -> dict:
        """Get comprehensive platform information"""
        return {
            'platform': PlatformDetector.detect_platform().value,
            'architecture': PlatformDetector.detect_architecture().value,
            'kernel_version': PlatformDetector.get_kernel_version(),
            'os_version': PlatformDetector.get_os_version(),
            'cpu_count': PlatformDetector.get_cpu_count(),
            'python_version': platform.python_version()
        }
    
    @staticmethod
    def get_memory_total() -> int:
        """Get total system memory in bytes"""
        try:
            if PlatformDetector.detect_platform() == PlatformType.LINUX:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            # Convert from KB to bytes
                            return int(line.split()[1]) * 1024
            elif PlatformDetector.detect_platform() == PlatformType.WINDOWS:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                c_ulong = ctypes.c_ulong
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', c_ulong),
                        ('dwMemoryLoad', c_ulong),
                        ('ullTotalPhys', ctypes.c_ulonglong),
                        ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong),
                        ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong),
                        ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                    ]
                memoryStatus = MEMORYSTATUSEX()
                memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))
                return memoryStatus.ullTotalPhys
            elif PlatformDetector.detect_platform() == PlatformType.MACOS:
                result = subprocess.run(['sysctl', '-n', 'hw.memsize'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return int(result.stdout.strip())
        except Exception:
            pass
        return 0
    
    @staticmethod
    def has_admin_privileges() -> bool:
        """Check if running with administrative privileges"""
        try:
            platform_type = PlatformDetector.detect_platform()
            
            if platform_type == PlatformType.WINDOWS:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False
    
    @staticmethod
    def supports_raw_sockets() -> bool:
        """Check if raw socket creation is supported"""
        try:
            import socket
            # Try to create a raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.close()
            return True
        except (OSError, PermissionError):
            return False
    
    @staticmethod
    def get_network_interfaces() -> List[str]:
        """Get list of available network interfaces"""
        interfaces = []
        try:
            platform_type = PlatformDetector.detect_platform()
            
            if platform_type == PlatformType.LINUX:
                # Read from /proc/net/dev
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()[2:]  # Skip header lines
                    for line in lines:
                        interface = line.split(':')[0].strip()
                        if interface and interface != 'lo':
                            interfaces.append(interface)
            elif platform_type == PlatformType.WINDOWS:
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[3:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == 'Enabled':
                            interface = ' '.join(parts[3:])
                            if interface and 'Loopback' not in interface:
                                interfaces.append(interface)
            elif platform_type == PlatformType.MACOS:
                result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    all_interfaces = result.stdout.strip().split()
                    interfaces = [iface for iface in all_interfaces if iface != 'lo0']
        except Exception:
            pass
        
        return interfaces
    
    @staticmethod
    def get_max_file_descriptors() -> int:
        """Get maximum number of file descriptors"""
        try:
            platform_type = PlatformDetector.detect_platform()
            
            if platform_type in [PlatformType.LINUX, PlatformType.MACOS]:
                import resource
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
                return hard
            elif platform_type == PlatformType.WINDOWS:
                # Windows doesn't have the same concept, return a reasonable default
                return 2048
        except Exception:
            pass
        return 1024
    
    @classmethod
    def get_system_info(cls) -> SystemInfo:
        """Get comprehensive system information"""
        return SystemInfo(
            platform_type=cls.detect_platform(),
            architecture=cls.detect_architecture(),
            kernel_version=cls.get_kernel_version(),
            os_version=cls.get_os_version(),
            cpu_count=cls.get_cpu_count(),
            memory_total=cls.get_memory_total(),
            has_admin_privileges=cls.has_admin_privileges(),
            supports_raw_sockets=cls.supports_raw_sockets(),
            network_interfaces=cls.get_network_interfaces(),
            max_file_descriptors=cls.get_max_file_descriptors()
        )