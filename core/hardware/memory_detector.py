"""
Memory Detection Module

Detects memory characteristics including total RAM, available RAM, memory speed,
and NUMA topology on multi-socket systems.

Implements Requirements 11.1: Memory detection for adaptive scaling.
"""

import os
import platform
import subprocess
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NumaNode:
    """NUMA node information"""
    node_id: int
    memory_mb: int
    cpu_list: List[int]
    distance_map: Dict[int, int]  # Distance to other NUMA nodes


@dataclass
class MemoryInfo:
    """Comprehensive memory information"""
    total_bytes: int
    available_bytes: int
    speed_mhz: int = 0
    type_ddr: str = "Unknown"  # DDR3, DDR4, DDR5, etc.
    channels: int = 0
    numa_nodes: List[NumaNode] = None
    hugepage_size_kb: int = 0
    hugepages_total: int = 0
    hugepages_free: int = 0
    
    @property
    def total_gb(self) -> float:
        """Total memory in GB"""
        return self.total_bytes / (1024**3)
    
    @property
    def available_gb(self) -> float:
        """Available memory in GB"""
        return self.available_bytes / (1024**3)
    
    @property
    def is_numa(self) -> bool:
        """Whether system has NUMA topology"""
        return self.numa_nodes is not None and len(self.numa_nodes) > 1


class MemoryDetector:
    """
    Memory detection and NUMA topology analysis.
    
    Provides comprehensive memory information for adaptive performance scaling.
    """
    
    @staticmethod
    def detect_total_memory() -> int:
        """
        Detect total system memory in bytes.
        
        Returns:
            Total memory in bytes
        """
        total_bytes = 0
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try /proc/meminfo first
                try:
                    with open('/proc/meminfo', 'r') as f:
                        for line in f:
                            if line.startswith('MemTotal:'):
                                # Convert from KB to bytes
                                kb = int(line.split()[1])
                                total_bytes = kb * 1024
                                break
                except FileNotFoundError:
                    logger.debug("/proc/meminfo not available")
                
                # Fallback to sysinfo
                if total_bytes == 0:
                    try:
                        import ctypes
                        import ctypes.util
                        
                        libc = ctypes.CDLL(ctypes.util.find_library("c"))
                        
                        class SysInfo(ctypes.Structure):
                            _fields_ = [
                                ("uptime", ctypes.c_long),
                                ("loads", ctypes.c_ulong * 3),
                                ("totalram", ctypes.c_ulong),
                                ("freeram", ctypes.c_ulong),
                                ("sharedram", ctypes.c_ulong),
                                ("bufferram", ctypes.c_ulong),
                                ("totalswap", ctypes.c_ulong),
                                ("freeswap", ctypes.c_ulong),
                                ("procs", ctypes.c_ushort),
                                ("pad", ctypes.c_ushort),
                                ("totalhigh", ctypes.c_ulong),
                                ("freehigh", ctypes.c_ulong),
                                ("mem_unit", ctypes.c_uint),
                            ]
                        
                        sysinfo = SysInfo()
                        if libc.sysinfo(ctypes.byref(sysinfo)) == 0:
                            total_bytes = sysinfo.totalram * sysinfo.mem_unit
                    
                    except (ImportError, OSError, AttributeError):
                        logger.debug("Could not use sysinfo")
            
            elif system == "Windows":
                try:
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
                    
                    if kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus)):
                        total_bytes = memoryStatus.ullTotalPhys
                
                except (ImportError, OSError, AttributeError):
                    logger.debug("Could not use Windows memory API")
            
            elif system == "Darwin":
                try:
                    result = subprocess.run(
                        ['sysctl', '-n', 'hw.memsize'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        total_bytes = int(result.stdout.strip())
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get memory size from sysctl")
        
        except Exception as e:
            logger.warning(f"Error detecting total memory: {e}")
        
        logger.info(f"Detected total memory: {total_bytes / (1024**3):.2f} GB")
        return total_bytes
    
    @staticmethod
    def detect_available_memory() -> int:
        """
        Detect currently available memory in bytes.
        
        Returns:
            Available memory in bytes
        """
        available_bytes = 0
        
        try:
            system = platform.system()
            
            if system == "Linux":
                try:
                    with open('/proc/meminfo', 'r') as f:
                        mem_available = 0
                        mem_free = 0
                        buffers = 0
                        cached = 0
                        
                        for line in f:
                            if line.startswith('MemAvailable:'):
                                # Preferred method (kernel 3.14+)
                                kb = int(line.split()[1])
                                available_bytes = kb * 1024
                                break
                            elif line.startswith('MemFree:'):
                                mem_free = int(line.split()[1]) * 1024
                            elif line.startswith('Buffers:'):
                                buffers = int(line.split()[1]) * 1024
                            elif line.startswith('Cached:'):
                                cached = int(line.split()[1]) * 1024
                        
                        # Fallback calculation if MemAvailable not present
                        if available_bytes == 0:
                            available_bytes = mem_free + buffers + cached
                
                except FileNotFoundError:
                    logger.debug("/proc/meminfo not available")
            
            elif system == "Windows":
                try:
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
                    
                    if kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus)):
                        available_bytes = memoryStatus.ullAvailPhys
                
                except (ImportError, OSError, AttributeError):
                    logger.debug("Could not use Windows memory API")
            
            elif system == "Darwin":
                try:
                    # Get VM statistics
                    result = subprocess.run(
                        ['vm_stat'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        page_size = 4096  # Default page size
                        free_pages = 0
                        inactive_pages = 0
                        
                        for line in lines:
                            if 'page size of' in line:
                                page_size = int(line.split()[-2])
                            elif line.startswith('Pages free:'):
                                free_pages = int(line.split()[2].rstrip('.'))
                            elif line.startswith('Pages inactive:'):
                                inactive_pages = int(line.split()[2].rstrip('.'))
                        
                        available_bytes = (free_pages + inactive_pages) * page_size
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get available memory from vm_stat")
        
        except Exception as e:
            logger.warning(f"Error detecting available memory: {e}")
        
        logger.info(f"Detected available memory: {available_bytes / (1024**3):.2f} GB")
        return available_bytes
    
    @staticmethod
    def detect_memory_speed_and_type() -> tuple[int, str]:
        """
        Detect memory speed in MHz and type (DDR3/DDR4/DDR5).
        
        Returns:
            Tuple of (speed_mhz, memory_type)
        """
        speed_mhz = 0
        memory_type = "Unknown"
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try dmidecode for detailed memory info
                try:
                    result = subprocess.run(
                        ['dmidecode', '-t', 'memory'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for i, line in enumerate(lines):
                            if 'Type:' in line and 'DDR' in line:
                                memory_type = line.split(':')[1].strip()
                            elif 'Speed:' in line and 'MHz' in line:
                                try:
                                    speed_str = line.split(':')[1].strip()
                                    speed_mhz = int(speed_str.split()[0])
                                except (ValueError, IndexError):
                                    pass
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                    logger.debug("dmidecode not available or failed")
                
                # Fallback: try /proc/meminfo for basic info
                if speed_mhz == 0:
                    try:
                        # Some systems expose memory frequency in sysfs
                        freq_paths = [
                            '/sys/devices/system/edac/mc/mc0/dimm0/dimm_mem_type',
                            '/sys/class/dmi/id/memory_speed',
                        ]
                        
                        for path in freq_paths:
                            try:
                                with open(path, 'r') as f:
                                    content = f.read().strip()
                                    if 'DDR' in content:
                                        memory_type = content
                                    elif content.isdigit():
                                        speed_mhz = int(content)
                            except FileNotFoundError:
                                continue
                    
                    except Exception:
                        logger.debug("Could not read memory info from sysfs")
            
            elif system == "Windows":
                try:
                    # Use WMI to get memory information
                    result = subprocess.run(
                        ['wmic', 'memorychip', 'get', 'Speed,MemoryType', '/format:value'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('Speed=') and line.split('=')[1].strip():
                                speed_mhz = int(line.split('=')[1].strip())
                            elif line.startswith('MemoryType='):
                                # Windows memory type codes: 20=DDR, 21=DDR2, 24=DDR3, 26=DDR4
                                mem_type_code = line.split('=')[1].strip()
                                if mem_type_code:
                                    type_map = {
                                        '20': 'DDR',
                                        '21': 'DDR2',
                                        '24': 'DDR3',
                                        '26': 'DDR4',
                                        '34': 'DDR5'
                                    }
                                    memory_type = type_map.get(mem_type_code, f"Type{mem_type_code}")
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get memory info from wmic")
            
            elif system == "Darwin":
                try:
                    # macOS doesn't easily expose memory speed/type
                    # Try system_profiler for detailed hardware info
                    result = subprocess.run(
                        ['system_profiler', 'SPMemoryDataType'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'Type:' in line and 'DDR' in line:
                                memory_type = line.split(':')[1].strip()
                            elif 'Speed:' in line and 'MHz' in line:
                                try:
                                    speed_str = line.split(':')[1].strip()
                                    speed_mhz = int(speed_str.split()[0])
                                except (ValueError, IndexError):
                                    pass
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not get memory info from system_profiler")
        
        except Exception as e:
            logger.warning(f"Error detecting memory speed/type: {e}")
        
        logger.info(f"Detected memory: {memory_type} @ {speed_mhz} MHz")
        return speed_mhz, memory_type
    
    @staticmethod
    def detect_numa_topology() -> Optional[List[NumaNode]]:
        """
        Detect NUMA topology on multi-socket systems.
        
        Returns:
            List of NUMA nodes, or None if not a NUMA system
        """
        numa_nodes = []
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Check if NUMA is available
                if not os.path.exists('/sys/devices/system/node'):
                    return None
                
                # Get list of NUMA nodes
                try:
                    with open('/sys/devices/system/node/online', 'r') as f:
                        online_nodes = f.read().strip()
                    
                    # Parse node range (e.g., "0-1" or "0,2,4")
                    node_ids = []
                    if '-' in online_nodes:
                        start, end = map(int, online_nodes.split('-'))
                        node_ids = list(range(start, end + 1))
                    else:
                        node_ids = [int(x) for x in online_nodes.split(',')]
                    
                    for node_id in node_ids:
                        node_path = f'/sys/devices/system/node/node{node_id}'
                        
                        # Get memory info for this node
                        memory_mb = 0
                        try:
                            with open(f'{node_path}/meminfo', 'r') as f:
                                for line in f:
                                    if line.startswith(f'Node {node_id} MemTotal:'):
                                        kb = int(line.split()[3])
                                        memory_mb = kb // 1024
                                        break
                        except FileNotFoundError:
                            pass
                        
                        # Get CPU list for this node
                        cpu_list = []
                        try:
                            with open(f'{node_path}/cpulist', 'r') as f:
                                cpulist_str = f.read().strip()
                                for cpu_range in cpulist_str.split(','):
                                    if '-' in cpu_range:
                                        start, end = map(int, cpu_range.split('-'))
                                        cpu_list.extend(range(start, end + 1))
                                    else:
                                        cpu_list.append(int(cpu_range))
                        except (FileNotFoundError, ValueError):
                            pass
                        
                        # Get distance map
                        distance_map = {}
                        try:
                            with open(f'{node_path}/distance', 'r') as f:
                                distances = list(map(int, f.read().strip().split()))
                                for i, distance in enumerate(distances):
                                    distance_map[i] = distance
                        except (FileNotFoundError, ValueError):
                            pass
                        
                        numa_node = NumaNode(
                            node_id=node_id,
                            memory_mb=memory_mb,
                            cpu_list=cpu_list,
                            distance_map=distance_map
                        )
                        numa_nodes.append(numa_node)
                
                except (FileNotFoundError, ValueError):
                    logger.debug("Could not parse NUMA topology")
            
            elif system in ["Windows", "Darwin"]:
                # NUMA detection on Windows/macOS is more complex and less standardized
                # For now, assume single NUMA node
                pass
        
        except Exception as e:
            logger.warning(f"Error detecting NUMA topology: {e}")
        
        if numa_nodes:
            logger.info(f"Detected NUMA topology: {len(numa_nodes)} nodes")
            for node in numa_nodes:
                logger.info(f"  Node {node.node_id}: {node.memory_mb}MB, "
                           f"CPUs {node.cpu_list}")
        else:
            logger.info("No NUMA topology detected (single node system)")
        
        return numa_nodes if numa_nodes else None
    
    @staticmethod
    def detect_hugepage_info() -> tuple[int, int, int]:
        """
        Detect hugepage configuration.
        
        Returns:
            Tuple of (hugepage_size_kb, total_hugepages, free_hugepages)
        """
        hugepage_size_kb = 0
        hugepages_total = 0
        hugepages_free = 0
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Check /proc/meminfo for hugepage info
                try:
                    with open('/proc/meminfo', 'r') as f:
                        for line in f:
                            if line.startswith('Hugepagesize:'):
                                hugepage_size_kb = int(line.split()[1])
                            elif line.startswith('HugePages_Total:'):
                                hugepages_total = int(line.split()[1])
                            elif line.startswith('HugePages_Free:'):
                                hugepages_free = int(line.split()[1])
                
                except FileNotFoundError:
                    logger.debug("/proc/meminfo not available")
                
                # Also check for transparent hugepages
                try:
                    with open('/sys/kernel/mm/transparent_hugepage/hpage_pmd_size', 'r') as f:
                        thp_size_bytes = int(f.read().strip())
                        if hugepage_size_kb == 0:
                            hugepage_size_kb = thp_size_bytes // 1024
                except FileNotFoundError:
                    pass
            
            # Windows and macOS don't have traditional hugepages like Linux
        
        except Exception as e:
            logger.warning(f"Error detecting hugepage info: {e}")
        
        if hugepage_size_kb > 0:
            logger.info(f"Detected hugepages: {hugepage_size_kb}KB size, "
                       f"{hugepages_total} total, {hugepages_free} free")
        
        return hugepage_size_kb, hugepages_total, hugepages_free
    
    @staticmethod
    def detect_memory_channels() -> int:
        """
        Detect number of memory channels.
        
        Returns:
            Number of memory channels, or 0 if unknown
        """
        channels = 0
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try dmidecode to count memory slots
                try:
                    result = subprocess.run(
                        ['dmidecode', '-t', 'memory'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        # Count populated memory slots
                        populated_slots = 0
                        lines = result.stdout.split('\n')
                        in_memory_device = False
                        
                        for line in lines:
                            if 'Memory Device' in line:
                                in_memory_device = True
                                slot_populated = False
                            elif in_memory_device and 'Size:' in line:
                                size_str = line.split(':')[1].strip()
                                if 'No Module Installed' not in size_str and size_str != '':
                                    populated_slots += 1
                                in_memory_device = False
                        
                        # Estimate channels based on populated slots
                        # This is a heuristic - actual channel detection is complex
                        if populated_slots >= 4:
                            channels = 4  # Quad channel
                        elif populated_slots >= 2:
                            channels = 2  # Dual channel
                        elif populated_slots == 1:
                            channels = 1  # Single channel
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                    logger.debug("dmidecode not available for memory channel detection")
            
            elif system == "Windows":
                try:
                    # Count memory slots via WMI
                    result = subprocess.run(
                        ['wmic', 'memorychip', 'get', 'DeviceLocator', '/format:value'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        slot_count = 0
                        for line in result.stdout.split('\n'):
                            if line.startswith('DeviceLocator=') and line.split('=')[1].strip():
                                slot_count += 1
                        
                        # Estimate channels
                        if slot_count >= 4:
                            channels = min(4, slot_count // 2)
                        elif slot_count >= 2:
                            channels = 2
                        else:
                            channels = 1
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not detect memory channels via wmic")
        
        except Exception as e:
            logger.warning(f"Error detecting memory channels: {e}")
        
        if channels > 0:
            logger.info(f"Detected memory channels: {channels}")
        
        return channels
    
    @classmethod
    def detect_memory_info(cls) -> MemoryInfo:
        """
        Detect comprehensive memory information.
        
        Returns:
            MemoryInfo object with all detected memory characteristics
        """
        logger.info("Starting memory detection...")
        
        total_bytes = cls.detect_total_memory()
        available_bytes = cls.detect_available_memory()
        speed_mhz, memory_type = cls.detect_memory_speed_and_type()
        numa_nodes = cls.detect_numa_topology()
        hugepage_size_kb, hugepages_total, hugepages_free = cls.detect_hugepage_info()
        channels = cls.detect_memory_channels()
        
        memory_info = MemoryInfo(
            total_bytes=total_bytes,
            available_bytes=available_bytes,
            speed_mhz=speed_mhz,
            type_ddr=memory_type,
            channels=channels,
            numa_nodes=numa_nodes,
            hugepage_size_kb=hugepage_size_kb,
            hugepages_total=hugepages_total,
            hugepages_free=hugepages_free
        )
        
        logger.info(f"Memory detection complete: {memory_info.total_gb:.2f}GB total, "
                   f"{memory_info.available_gb:.2f}GB available, {memory_type} @ {speed_mhz}MHz")
        
        return memory_info