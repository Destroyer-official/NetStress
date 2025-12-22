"""
CPU Detection Module

Detects CPU characteristics including core count, thread count, architecture,
CPU features (AVX2, AVX-512, NEON, TSC), and frequency.

Implements Requirements 11.1, 12.4, 12.5: CPU detection for adaptive scaling.
"""

import os
import platform
import subprocess
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """CPU architectures"""
    X86_64 = "x86_64"
    ARM64 = "arm64"
    ARM32 = "arm32"
    UNKNOWN = "unknown"


@dataclass
class CpuFeatures:
    """CPU feature flags"""
    avx2: bool = False
    avx512: bool = False
    neon: bool = False  # ARM SIMD
    tsc: bool = False   # Timestamp counter
    sse4_2: bool = False
    aes_ni: bool = False
    rdrand: bool = False


@dataclass
class CpuInfo:
    """Comprehensive CPU information"""
    cores: int
    threads: int
    architecture: Architecture
    features: CpuFeatures
    frequency_mhz: int
    model_name: str
    vendor: str
    cache_l1_kb: int = 0
    cache_l2_kb: int = 0
    cache_l3_kb: int = 0


class CpuDetector:
    """
    CPU detection and feature identification.
    
    Provides comprehensive CPU information for adaptive performance scaling.
    """
    
    @staticmethod
    def detect_architecture() -> Architecture:
        """
        Detect CPU architecture.
        
        Returns:
            Architecture enum value
        """
        machine = platform.machine().lower()
        
        if machine in ["x86_64", "amd64"]:
            return Architecture.X86_64
        elif machine in ["arm64", "aarch64"]:
            return Architecture.ARM64
        elif machine in ["arm", "armv7l", "armv6l"]:
            return Architecture.ARM32
        else:
            logger.warning(f"Unknown architecture: {machine}")
            return Architecture.UNKNOWN
    
    @staticmethod
    def detect_cores_and_threads() -> tuple[int, int]:
        """
        Detect physical CPU cores and logical threads.
        
        Returns:
            Tuple of (physical_cores, logical_threads)
        """
        logical_threads = os.cpu_count() or 1
        physical_cores = logical_threads  # Default assumption
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try to get physical cores from /proc/cpuinfo
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        content = f.read()
                    
                    # Count unique physical IDs
                    physical_ids = set()
                    cores_per_socket = 0
                    
                    for line in content.split('\n'):
                        if line.startswith('physical id'):
                            physical_ids.add(line.split(':')[1].strip())
                        elif line.startswith('cpu cores'):
                            cores_per_socket = int(line.split(':')[1].strip())
                    
                    if physical_ids and cores_per_socket:
                        physical_cores = len(physical_ids) * cores_per_socket
                    else:
                        # Fallback: count unique core IDs
                        core_ids = set()
                        for line in content.split('\n'):
                            if line.startswith('core id'):
                                core_ids.add(line.split(':')[1].strip())
                        if core_ids:
                            physical_cores = len(core_ids)
                
                except (FileNotFoundError, ValueError, IndexError):
                    logger.debug("Could not parse /proc/cpuinfo for core count")
            
            elif system == "Windows":
                try:
                    result = subprocess.run(
                        ['wmic', 'cpu', 'get', 'NumberOfCores', '/format:value'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('NumberOfCores='):
                                physical_cores = int(line.split('=')[1])
                                break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get core count from wmic")
            
            elif system == "Darwin":
                try:
                    result = subprocess.run(
                        ['sysctl', '-n', 'hw.physicalcpu'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        physical_cores = int(result.stdout.strip())
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get core count from sysctl")
        
        except Exception as e:
            logger.warning(f"Error detecting cores/threads: {e}")
        
        # Ensure physical cores doesn't exceed logical threads
        physical_cores = min(physical_cores, logical_threads)
        
        logger.info(f"Detected {physical_cores} physical cores, {logical_threads} logical threads")
        return physical_cores, logical_threads
    
    @staticmethod
    def detect_cpu_features() -> CpuFeatures:
        """
        Detect CPU feature flags.
        
        Returns:
            CpuFeatures object with detected capabilities
        """
        features = CpuFeatures()
        
        try:
            system = platform.system()
            arch = CpuDetector.detect_architecture()
            
            if system == "Linux":
                # Read from /proc/cpuinfo
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        content = f.read().lower()
                    
                    if arch == Architecture.X86_64:
                        features.avx2 = 'avx2' in content
                        features.avx512 = any(flag in content for flag in ['avx512f', 'avx512'])
                        features.sse4_2 = 'sse4_2' in content
                        features.aes_ni = 'aes' in content
                        features.rdrand = 'rdrand' in content
                        features.tsc = 'tsc' in content or 'rdtsc' in content
                    elif arch in [Architecture.ARM64, Architecture.ARM32]:
                        features.neon = 'neon' in content or 'asimd' in content
                        features.aes_ni = 'aes' in content
                
                except FileNotFoundError:
                    logger.debug("/proc/cpuinfo not available")
            
            elif system == "Windows":
                # Use CPUID instruction via ctypes (x86 only)
                if arch == Architecture.X86_64:
                    try:
                        import ctypes
                        
                        # Check for AVX2 (EAX=7, ECX=0, EBX bit 5)
                        # This is a simplified check - full CPUID would be more complex
                        features.tsc = True  # TSC is standard on modern x86
                        
                        # Try to detect features via registry or WMI
                        try:
                            result = subprocess.run(
                                ['wmic', 'cpu', 'get', 'Name', '/format:value'],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.returncode == 0:
                                cpu_name = result.stdout.lower()
                                # Heuristic detection based on CPU model
                                if 'intel' in cpu_name:
                                    # Most Intel CPUs from Haswell+ have AVX2
                                    features.avx2 = True
                                    features.sse4_2 = True
                                    features.aes_ni = True
                                elif 'amd' in cpu_name:
                                    # Most AMD CPUs from Excavator+ have AVX2
                                    features.avx2 = True
                                    features.sse4_2 = True
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                            pass
                    
                    except ImportError:
                        logger.debug("ctypes not available for CPUID")
            
            elif system == "Darwin":
                try:
                    # Check for AVX2 support
                    result = subprocess.run(
                        ['sysctl', '-n', 'hw.optional.avx2_0'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        features.avx2 = result.stdout.strip() == '1'
                    
                    # Check for other features
                    feature_checks = {
                        'hw.optional.sse4_2': 'sse4_2',
                        'hw.optional.aes': 'aes_ni',
                        'hw.optional.rdrand': 'rdrand',
                    }
                    
                    for sysctl_name, feature_name in feature_checks.items():
                        try:
                            result = subprocess.run(
                                ['sysctl', '-n', sysctl_name],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.returncode == 0:
                                setattr(features, feature_name, result.stdout.strip() == '1')
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                            continue
                    
                    # ARM Macs have NEON
                    if arch == Architecture.ARM64:
                        features.neon = True
                        features.aes_ni = True  # Apple Silicon has AES acceleration
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not detect CPU features via sysctl")
        
        except Exception as e:
            logger.warning(f"Error detecting CPU features: {e}")
        
        logger.info(f"Detected CPU features: AVX2={features.avx2}, AVX512={features.avx512}, "
                   f"NEON={features.neon}, TSC={features.tsc}, SSE4.2={features.sse4_2}")
        
        return features
    
    @staticmethod
    def detect_cpu_frequency() -> int:
        """
        Detect CPU base frequency in MHz.
        
        Returns:
            CPU frequency in MHz, or 0 if unknown
        """
        frequency_mhz = 0
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try multiple sources for CPU frequency
                sources = [
                    '/proc/cpuinfo',
                    '/sys/devices/system/cpu/cpu0/cpufreq/base_frequency',
                    '/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq'
                ]
                
                # Try /proc/cpuinfo first
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if line.startswith('cpu MHz'):
                                frequency_mhz = int(float(line.split(':')[1].strip()))
                                break
                            elif line.startswith('BogoMIPS'):
                                # Fallback for some ARM systems
                                bogomips = float(line.split(':')[1].strip())
                                frequency_mhz = int(bogomips / 2)  # Rough estimate
                                break
                except (FileNotFoundError, ValueError, IndexError):
                    pass
                
                # Try sysfs if /proc/cpuinfo didn't work
                if frequency_mhz == 0:
                    for source in sources[1:]:
                        try:
                            with open(source, 'r') as f:
                                freq_khz = int(f.read().strip())
                                frequency_mhz = freq_khz // 1000
                                break
                        except (FileNotFoundError, ValueError):
                            continue
            
            elif system == "Windows":
                try:
                    result = subprocess.run(
                        ['wmic', 'cpu', 'get', 'MaxClockSpeed', '/format:value'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('MaxClockSpeed='):
                                frequency_mhz = int(line.split('=')[1])
                                break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get CPU frequency from wmic")
            
            elif system == "Darwin":
                try:
                    result = subprocess.run(
                        ['sysctl', '-n', 'hw.cpufrequency_max'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        freq_hz = int(result.stdout.strip())
                        frequency_mhz = freq_hz // 1000000
                    else:
                        # Fallback for Apple Silicon
                        result = subprocess.run(
                            ['sysctl', '-n', 'hw.cpufrequency'],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            freq_hz = int(result.stdout.strip())
                            frequency_mhz = freq_hz // 1000000
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug("Could not get CPU frequency from sysctl")
        
        except Exception as e:
            logger.warning(f"Error detecting CPU frequency: {e}")
        
        logger.info(f"Detected CPU frequency: {frequency_mhz} MHz")
        return frequency_mhz
    
    @staticmethod
    def detect_cpu_model_and_vendor() -> tuple[str, str]:
        """
        Detect CPU model name and vendor.
        
        Returns:
            Tuple of (model_name, vendor)
        """
        model_name = "Unknown"
        vendor = "Unknown"
        
        try:
            system = platform.system()
            
            if system == "Linux":
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if line.startswith('model name'):
                                model_name = line.split(':', 1)[1].strip()
                            elif line.startswith('vendor_id'):
                                vendor = line.split(':', 1)[1].strip()
                            elif line.startswith('Hardware') and model_name == "Unknown":
                                # ARM systems often use Hardware field
                                model_name = line.split(':', 1)[1].strip()
                            
                            if model_name != "Unknown" and vendor != "Unknown":
                                break
                except FileNotFoundError:
                    logger.debug("/proc/cpuinfo not available")
            
            elif system == "Windows":
                try:
                    result = subprocess.run(
                        ['wmic', 'cpu', 'get', 'Name,Manufacturer', '/format:value'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('Manufacturer='):
                                vendor = line.split('=', 1)[1].strip()
                            elif line.startswith('Name='):
                                model_name = line.split('=', 1)[1].strip()
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not get CPU info from wmic")
            
            elif system == "Darwin":
                try:
                    result = subprocess.run(
                        ['sysctl', '-n', 'machdep.cpu.brand_string'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        model_name = result.stdout.strip()
                    
                    result = subprocess.run(
                        ['sysctl', '-n', 'machdep.cpu.vendor'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        vendor = result.stdout.strip()
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not get CPU info from sysctl")
        
        except Exception as e:
            logger.warning(f"Error detecting CPU model/vendor: {e}")
        
        logger.info(f"Detected CPU: {model_name} ({vendor})")
        return model_name, vendor
    
    @staticmethod
    def detect_cache_sizes() -> tuple[int, int, int]:
        """
        Detect CPU cache sizes in KB.
        
        Returns:
            Tuple of (L1_cache_kb, L2_cache_kb, L3_cache_kb)
        """
        l1_kb = l2_kb = l3_kb = 0
        
        try:
            system = platform.system()
            
            if system == "Linux":
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        for line in f:
                            if 'cache size' in line:
                                # This is usually L2 cache
                                cache_str = line.split(':')[1].strip()
                                if 'KB' in cache_str:
                                    l2_kb = int(cache_str.split()[0])
                                break
                    
                    # Try sysfs for more detailed cache info
                    cache_paths = {
                        'L1d': '/sys/devices/system/cpu/cpu0/cache/index0/size',
                        'L1i': '/sys/devices/system/cpu/cpu0/cache/index1/size',
                        'L2': '/sys/devices/system/cpu/cpu0/cache/index2/size',
                        'L3': '/sys/devices/system/cpu/cpu0/cache/index3/size',
                    }
                    
                    for cache_type, path in cache_paths.items():
                        try:
                            with open(path, 'r') as f:
                                size_str = f.read().strip()
                                if 'K' in size_str:
                                    size_kb = int(size_str.replace('K', ''))
                                    if cache_type == 'L1d':
                                        l1_kb = size_kb
                                    elif cache_type == 'L2':
                                        l2_kb = size_kb
                                    elif cache_type == 'L3':
                                        l3_kb = size_kb
                        except (FileNotFoundError, ValueError):
                            continue
                
                except FileNotFoundError:
                    logger.debug("Cache info not available in /proc/cpuinfo")
            
            elif system == "Darwin":
                try:
                    cache_sysctls = {
                        'hw.l1dcachesize': 'l1',
                        'hw.l2cachesize': 'l2',
                        'hw.l3cachesize': 'l3',
                    }
                    
                    for sysctl_name, cache_level in cache_sysctls.items():
                        try:
                            result = subprocess.run(
                                ['sysctl', '-n', sysctl_name],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.returncode == 0:
                                size_bytes = int(result.stdout.strip())
                                size_kb = size_bytes // 1024
                                if cache_level == 'l1':
                                    l1_kb = size_kb
                                elif cache_level == 'l2':
                                    l2_kb = size_kb
                                elif cache_level == 'l3':
                                    l3_kb = size_kb
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                            continue
                
                except Exception:
                    logger.debug("Could not get cache sizes from sysctl")
        
        except Exception as e:
            logger.warning(f"Error detecting cache sizes: {e}")
        
        logger.info(f"Detected cache sizes: L1={l1_kb}KB, L2={l2_kb}KB, L3={l3_kb}KB")
        return l1_kb, l2_kb, l3_kb
    
    @classmethod
    def detect_cpu_info(cls) -> CpuInfo:
        """
        Detect comprehensive CPU information.
        
        Returns:
            CpuInfo object with all detected CPU characteristics
        """
        logger.info("Starting CPU detection...")
        
        architecture = cls.detect_architecture()
        cores, threads = cls.detect_cores_and_threads()
        features = cls.detect_cpu_features()
        frequency_mhz = cls.detect_cpu_frequency()
        model_name, vendor = cls.detect_cpu_model_and_vendor()
        l1_kb, l2_kb, l3_kb = cls.detect_cache_sizes()
        
        cpu_info = CpuInfo(
            cores=cores,
            threads=threads,
            architecture=architecture,
            features=features,
            frequency_mhz=frequency_mhz,
            model_name=model_name,
            vendor=vendor,
            cache_l1_kb=l1_kb,
            cache_l2_kb=l2_kb,
            cache_l3_kb=l3_kb
        )
        
        logger.info(f"CPU detection complete: {cores}C/{threads}T {architecture.value} "
                   f"{frequency_mhz}MHz {model_name}")
        
        return cpu_info