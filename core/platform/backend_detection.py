#!/usr/bin/env python3
"""
Backend Detection and Selection Module
Implements Requirements 4.4, 5.5: Backend capability detection and priority-based selection

This module provides Python interface to the C driver's backend detection functions.
It detects system capabilities for DPDK, AF_XDP, io_uring, sendmmsg, and raw sockets,
then selects the best available backend based on priority order.
"""

import os
import sys
import ctypes
import logging
import platform
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class BackendType(Enum):
    """Backend types in priority order (highest to lowest performance)"""
    NONE = 0
    RAW_SOCKET = 1
    SENDMMSG = 2
    IO_URING = 3
    AF_XDP = 4
    DPDK = 5


@dataclass
class SystemCapabilities:
    """System capabilities detected by C driver"""
    has_dpdk: bool = False
    has_af_xdp: bool = False
    has_io_uring: bool = False
    has_sendmmsg: bool = False
    has_raw_socket: bool = True  # Always available
    kernel_version_major: int = 0
    kernel_version_minor: int = 0
    cpu_count: int = 1
    numa_nodes: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for compatibility"""
        return {
            'dpdk': self.has_dpdk,
            'af_xdp': self.has_af_xdp,
            'io_uring': self.has_io_uring,
            'sendmmsg': self.has_sendmmsg,
            'raw_socket': self.has_raw_socket,
            'kernel_version': (self.kernel_version_major, self.kernel_version_minor),
            'cpu_count': self.cpu_count,
            'numa_nodes': self.numa_nodes,
        }


class CDriverCapabilities(ctypes.Structure):
    """C structure for system_capabilities_t"""
    _fields_ = [
        ("has_dpdk", ctypes.c_int),
        ("has_af_xdp", ctypes.c_int),
        ("has_io_uring", ctypes.c_int),
        ("has_sendmmsg", ctypes.c_int),
        ("has_raw_socket", ctypes.c_int),
        ("kernel_version_major", ctypes.c_int),
        ("kernel_version_minor", ctypes.c_int),
        ("cpu_count", ctypes.c_int),
        ("numa_nodes", ctypes.c_int),
    ]


class BackendDetector:
    """
    Backend detection and selection using C driver functions.
    
    This class provides Python interface to the C driver's capability detection
    and backend selection functions, implementing Requirements 4.4 and 5.5.
    """
    
    def __init__(self):
        self._c_driver = None
        self._capabilities = None
        self._load_c_driver()
    
    def _load_c_driver(self) -> None:
        """Load the C driver library"""
        try:
            # Try to load the C driver library
            if platform.system() == "Windows":
                lib_name = "driver_shim.dll"
            elif platform.system() == "Darwin":
                lib_name = "libdriver_shim.dylib"
            else:
                lib_name = "libdriver_shim.so"
            
            # Look for library in native/c_driver directory
            lib_paths = [
                os.path.join(os.path.dirname(__file__), "..", "..", "native", "c_driver", lib_name),
                os.path.join("native", "c_driver", lib_name),
                lib_name,  # System path
            ]
            
            for lib_path in lib_paths:
                if os.path.exists(lib_path):
                    try:
                        self._c_driver = ctypes.CDLL(lib_path)
                        logger.info(f"Loaded C driver from {lib_path}")
                        break
                    except OSError as e:
                        logger.debug(f"Failed to load {lib_path}: {e}")
                        continue
            
            if self._c_driver is None:
                logger.warning("C driver library not found, using fallback detection")
                return
            
            # Set up function signatures
            self._setup_function_signatures()
            
        except Exception as e:
            logger.warning(f"Failed to load C driver: {e}")
            self._c_driver = None
    
    def _setup_function_signatures(self) -> None:
        """Set up C function signatures"""
        if not self._c_driver:
            return
        
        try:
            # detect_capabilities function
            self._c_driver.detect_capabilities.argtypes = [ctypes.POINTER(CDriverCapabilities)]
            self._c_driver.detect_capabilities.restype = ctypes.c_int
            
            # select_best_backend function
            self._c_driver.select_best_backend.argtypes = [ctypes.POINTER(CDriverCapabilities)]
            self._c_driver.select_best_backend.restype = ctypes.c_int
            
            # backend_name function
            self._c_driver.backend_name.argtypes = [ctypes.c_int]
            self._c_driver.backend_name.restype = ctypes.c_char_p
            
            logger.debug("C driver function signatures set up successfully")
            
        except AttributeError as e:
            logger.warning(f"C driver missing expected functions: {e}")
            self._c_driver = None
    
    def detect_capabilities(self) -> SystemCapabilities:
        """
        Detect system capabilities using C driver.
        
        Implements Requirement 4.4: Check for DPDK libraries, kernel version for AF_XDP (4.18+),
        kernel version for io_uring (5.1+), and sendmmsg support.
        
        Returns:
            SystemCapabilities object with detected capabilities
        """
        if self._c_driver:
            try:
                # Use C driver for detection
                caps_struct = CDriverCapabilities()
                result = self._c_driver.detect_capabilities(ctypes.byref(caps_struct))
                
                if result == 0:
                    capabilities = SystemCapabilities(
                        has_dpdk=bool(caps_struct.has_dpdk),
                        has_af_xdp=bool(caps_struct.has_af_xdp),
                        has_io_uring=bool(caps_struct.has_io_uring),
                        has_sendmmsg=bool(caps_struct.has_sendmmsg),
                        has_raw_socket=bool(caps_struct.has_raw_socket),
                        kernel_version_major=caps_struct.kernel_version_major,
                        kernel_version_minor=caps_struct.kernel_version_minor,
                        cpu_count=caps_struct.cpu_count,
                        numa_nodes=caps_struct.numa_nodes,
                    )
                    
                    logger.info(f"Detected capabilities via C driver: "
                              f"DPDK={capabilities.has_dpdk}, "
                              f"AF_XDP={capabilities.has_af_xdp}, "
                              f"io_uring={capabilities.has_io_uring}, "
                              f"sendmmsg={capabilities.has_sendmmsg}, "
                              f"kernel={capabilities.kernel_version_major}.{capabilities.kernel_version_minor}")
                    
                    self._capabilities = capabilities
                    return capabilities
                else:
                    logger.warning(f"C driver detect_capabilities returned error: {result}")
            
            except Exception as e:
                logger.warning(f"C driver capability detection failed: {e}")
        
        # Fallback to Python-based detection
        return self._detect_capabilities_fallback()
    
    def _detect_capabilities_fallback(self) -> SystemCapabilities:
        """
        Fallback capability detection using pure Python.
        
        This implements the same logic as the C driver but in Python,
        for cases where the C driver is not available.
        """
        capabilities = SystemCapabilities()
        
        # Always have raw sockets
        capabilities.has_raw_socket = True
        
        # CPU count
        capabilities.cpu_count = os.cpu_count() or 1
        
        # Platform-specific detection
        system = platform.system()
        
        if system == "Linux":
            # Check kernel version
            try:
                release = platform.release()
                parts = release.split('.')
                if len(parts) >= 2:
                    capabilities.kernel_version_major = int(parts[0])
                    capabilities.kernel_version_minor = int(parts[1].split('-')[0])
            except (ValueError, IndexError):
                logger.warning("Could not parse kernel version")
            
            # sendmmsg available on Linux 3.0+
            if capabilities.kernel_version_major >= 3:
                capabilities.has_sendmmsg = True
            
            # io_uring available on Linux 5.1+
            if (capabilities.kernel_version_major > 5 or 
                (capabilities.kernel_version_major == 5 and capabilities.kernel_version_minor >= 1)):
                capabilities.has_io_uring = True
            
            # AF_XDP available on Linux 4.18+
            if (capabilities.kernel_version_major > 4 or 
                (capabilities.kernel_version_major == 4 and capabilities.kernel_version_minor >= 18)):
                capabilities.has_af_xdp = True
            
            # Check for DPDK libraries (basic check)
            dpdk_paths = [
                "/usr/lib/x86_64-linux-gnu/librte_eal.so",
                "/usr/local/lib/librte_eal.so",
                "/opt/dpdk/lib/librte_eal.so",
            ]
            capabilities.has_dpdk = any(os.path.exists(path) for path in dpdk_paths)
            
            # NUMA detection
            try:
                with open("/sys/devices/system/node/online", "r") as f:
                    content = f.read().strip()
                    if '-' in content:
                        start, end = content.split('-')
                        capabilities.numa_nodes = int(end) - int(start) + 1
                    else:
                        capabilities.numa_nodes = 1
            except (FileNotFoundError, ValueError):
                capabilities.numa_nodes = 1
        
        elif system == "Windows":
            # Windows doesn't have AF_XDP, io_uring, or sendmmsg
            capabilities.has_af_xdp = False
            capabilities.has_io_uring = False
            capabilities.has_sendmmsg = False
            
            # Check for DPDK on Windows (basic check)
            dpdk_paths = [
                "C:\\Program Files\\DPDK\\lib\\librte_eal.dll",
                "C:\\DPDK\\lib\\librte_eal.dll",
            ]
            capabilities.has_dpdk = any(os.path.exists(path) for path in dpdk_paths)
        
        elif system == "Darwin":
            # macOS doesn't have AF_XDP, io_uring, or sendmmsg
            capabilities.has_af_xdp = False
            capabilities.has_io_uring = False
            capabilities.has_sendmmsg = False
            capabilities.has_dpdk = False  # DPDK not commonly used on macOS
        
        logger.info(f"Detected capabilities via Python fallback: "
                   f"DPDK={capabilities.has_dpdk}, "
                   f"AF_XDP={capabilities.has_af_xdp}, "
                   f"io_uring={capabilities.has_io_uring}, "
                   f"sendmmsg={capabilities.has_sendmmsg}")
        
        self._capabilities = capabilities
        return capabilities
    
    def select_best_backend(self, capabilities: Optional[SystemCapabilities] = None) -> BackendType:
        """
        Select the best available backend based on capabilities.
        
        Implements Requirement 4.4, 5.5: Priority-based backend selection with automatic fallback.
        Priority order: DPDK > AF_XDP > io_uring > sendmmsg > raw socket
        
        Args:
            capabilities: System capabilities (if None, will detect automatically)
        
        Returns:
            Best available backend type
        """
        if capabilities is None:
            capabilities = self.detect_capabilities()
        
        if self._c_driver:
            try:
                # Use C driver for backend selection
                caps_struct = CDriverCapabilities(
                    has_dpdk=int(capabilities.has_dpdk),
                    has_af_xdp=int(capabilities.has_af_xdp),
                    has_io_uring=int(capabilities.has_io_uring),
                    has_sendmmsg=int(capabilities.has_sendmmsg),
                    has_raw_socket=int(capabilities.has_raw_socket),
                    kernel_version_major=capabilities.kernel_version_major,
                    kernel_version_minor=capabilities.kernel_version_minor,
                    cpu_count=capabilities.cpu_count,
                    numa_nodes=capabilities.numa_nodes,
                )
                
                backend_id = self._c_driver.select_best_backend(ctypes.byref(caps_struct))
                backend = BackendType(backend_id)
                
                logger.info(f"C driver selected backend: {backend.name}")
                return backend
                
            except Exception as e:
                logger.warning(f"C driver backend selection failed: {e}")
        
        # Fallback to Python-based selection
        return self._select_best_backend_fallback(capabilities)
    
    def _select_best_backend_fallback(self, capabilities: SystemCapabilities) -> BackendType:
        """
        Fallback backend selection using Python logic.
        
        Implements the same priority order as the C driver:
        DPDK > AF_XDP > io_uring > sendmmsg > raw socket
        """
        if capabilities.has_dpdk:
            logger.info("Selected backend: DPDK (highest performance)")
            return BackendType.DPDK
        
        if capabilities.has_af_xdp:
            logger.info("Selected backend: AF_XDP (zero-copy)")
            return BackendType.AF_XDP
        
        if capabilities.has_io_uring:
            logger.info("Selected backend: io_uring (async I/O)")
            return BackendType.IO_URING
        
        if capabilities.has_sendmmsg:
            logger.info("Selected backend: sendmmsg (batch sending)")
            return BackendType.SENDMMSG
        
        logger.info("Selected backend: raw_socket (fallback)")
        return BackendType.RAW_SOCKET
    
    def get_backend_name(self, backend: BackendType) -> str:
        """
        Get human-readable name for backend type.
        
        Args:
            backend: Backend type
        
        Returns:
            Human-readable backend name
        """
        if self._c_driver:
            try:
                name_ptr = self._c_driver.backend_name(backend.value)
                if name_ptr:
                    return name_ptr.decode('utf-8')
            except Exception as e:
                logger.debug(f"C driver backend_name failed: {e}")
        
        # Fallback mapping
        name_map = {
            BackendType.NONE: "none",
            BackendType.RAW_SOCKET: "raw_socket",
            BackendType.SENDMMSG: "sendmmsg",
            BackendType.IO_URING: "io_uring",
            BackendType.AF_XDP: "af_xdp",
            BackendType.DPDK: "dpdk",
        }
        return name_map.get(backend, "unknown")
    
    def get_available_backends(self, capabilities: Optional[SystemCapabilities] = None) -> List[BackendType]:
        """
        Get list of all available backends in priority order.
        
        Args:
            capabilities: System capabilities (if None, will detect automatically)
        
        Returns:
            List of available backend types in priority order
        """
        if capabilities is None:
            capabilities = self.detect_capabilities()
        
        available = []
        
        if capabilities.has_dpdk:
            available.append(BackendType.DPDK)
        if capabilities.has_af_xdp:
            available.append(BackendType.AF_XDP)
        if capabilities.has_io_uring:
            available.append(BackendType.IO_URING)
        if capabilities.has_sendmmsg:
            available.append(BackendType.SENDMMSG)
        if capabilities.has_raw_socket:
            available.append(BackendType.RAW_SOCKET)
        
        return available
    
    def get_capabilities(self) -> Optional[SystemCapabilities]:
        """Get cached capabilities (call detect_capabilities first)"""
        return self._capabilities


# Global detector instance
_detector = None


def get_detector() -> BackendDetector:
    """Get global backend detector instance"""
    global _detector
    if _detector is None:
        _detector = BackendDetector()
    return _detector


def detect_system_capabilities() -> SystemCapabilities:
    """
    Detect system capabilities for backend selection.
    
    This is the main entry point for capability detection.
    
    Returns:
        SystemCapabilities object with detected capabilities
    """
    return get_detector().detect_capabilities()


def select_optimal_backend(capabilities: Optional[SystemCapabilities] = None) -> BackendType:
    """
    Select the optimal backend based on system capabilities.
    
    Args:
        capabilities: System capabilities (if None, will detect automatically)
    
    Returns:
        Best available backend type
    """
    return get_detector().select_best_backend(capabilities)


def get_available_backends(capabilities: Optional[SystemCapabilities] = None) -> List[BackendType]:
    """
    Get list of available backends in priority order.
    
    Args:
        capabilities: System capabilities (if None, will detect automatically)
    
    Returns:
        List of available backend types
    """
    return get_detector().get_available_backends(capabilities)


def backend_name(backend: BackendType) -> str:
    """Get human-readable name for backend type"""
    return get_detector().get_backend_name(backend)


# Export public API
__all__ = [
    'BackendType',
    'SystemCapabilities',
    'BackendDetector',
    'detect_system_capabilities',
    'select_optimal_backend',
    'get_available_backends',
    'backend_name',
]