"""
GPU Detection Module

Detects GPU characteristics including NVIDIA GPUs via CUDA, AMD GPUs via ROCm/OpenCL,
GPU memory, and compute capability.

Implements Requirements 11.1, 10.1: GPU detection for adaptive scaling and acceleration.
"""

import os
import platform
import subprocess
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class GpuType(Enum):
    """GPU types"""
    UNKNOWN = "unknown"
    NVIDIA_CUDA = "nvidia_cuda"
    AMD_ROCM = "amd_rocm"
    AMD_OPENCL = "amd_opencl"
    INTEL_OPENCL = "intel_opencl"
    APPLE_METAL = "apple_metal"


@dataclass
class GpuInfo:
    """GPU information"""
    name: str
    gpu_type: GpuType
    memory_mb: int
    compute_capability: str = ""
    driver_version: str = ""
    cuda_version: str = ""
    opencl_version: str = ""
    pci_id: str = ""
    power_limit_watts: int = 0
    temperature_celsius: int = 0
    utilization_percent: int = 0
    memory_utilization_percent: int = 0
    
    @property
    def memory_gb(self) -> float:
        """GPU memory in GB"""
        return self.memory_mb / 1024.0
    
    @property
    def is_high_end(self) -> bool:
        """Whether this is a high-end GPU (>= 8GB memory)"""
        return self.memory_mb >= 8192
    
    @property
    def supports_compute(self) -> bool:
        """Whether GPU supports compute workloads"""
        return self.gpu_type in [GpuType.NVIDIA_CUDA, GpuType.AMD_ROCM, 
                               GpuType.AMD_OPENCL, GpuType.INTEL_OPENCL]


class GpuDetector:
    """
    GPU detection and capability analysis.
    
    Provides comprehensive GPU information for adaptive performance scaling
    and hardware acceleration.
    """
    
    @staticmethod
    def detect_nvidia_gpus() -> List[GpuInfo]:
        """
        Detect NVIDIA GPUs via CUDA and nvidia-smi.
        
        Returns:
            List of detected NVIDIA GPUs
        """
        gpus = []
        
        try:
            # Try nvidia-smi first (most reliable)
            try:
                result = subprocess.run(
                    ['nvidia-smi', '--query-gpu=name,memory.total,driver_version,temperature.gpu,utilization.gpu,utilization.memory,power.draw,power.limit', 
                     '--format=csv,noheader,nounits'],
                    capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for i, line in enumerate(lines):
                        if line.strip():
                            parts = [p.strip() for p in line.split(',')]
                            if len(parts) >= 3:
                                name = parts[0]
                                memory_mb = int(parts[1]) if parts[1].isdigit() else 0
                                driver_version = parts[2]
                                temperature = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                                utilization = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
                                memory_util = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
                                power_draw = int(float(parts[6])) if len(parts) > 6 and parts[6].replace('.', '').isdigit() else 0
                                power_limit = int(float(parts[7])) if len(parts) > 7 and parts[7].replace('.', '').isdigit() else 0
                                
                                # Get compute capability
                                compute_capability = ""
                                try:
                                    cc_result = subprocess.run(
                                        ['nvidia-smi', '--query-gpu=compute_cap', '--format=csv,noheader,nounits', f'--id={i}'],
                                        capture_output=True, text=True, timeout=5
                                    )
                                    if cc_result.returncode == 0:
                                        compute_capability = cc_result.stdout.strip()
                                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                                    pass
                                
                                # Get CUDA version
                                cuda_version = ""
                                try:
                                    cuda_result = subprocess.run(
                                        ['nvidia-smi', '--query-gpu=cuda_version', '--format=csv,noheader,nounits'],
                                        capture_output=True, text=True, timeout=5
                                    )
                                    if cuda_result.returncode == 0:
                                        cuda_version = cuda_result.stdout.strip().split('\n')[0]
                                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                                    pass
                                
                                gpu = GpuInfo(
                                    name=name,
                                    gpu_type=GpuType.NVIDIA_CUDA,
                                    memory_mb=memory_mb,
                                    compute_capability=compute_capability,
                                    driver_version=driver_version,
                                    cuda_version=cuda_version,
                                    power_limit_watts=power_limit,
                                    temperature_celsius=temperature,
                                    utilization_percent=utilization,
                                    memory_utilization_percent=memory_util
                                )
                                gpus.append(gpu)
                                
                                logger.info(f"Detected NVIDIA GPU: {name} ({memory_mb}MB, "
                                           f"CC {compute_capability}, CUDA {cuda_version})")
            
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                logger.debug("nvidia-smi not available")
            
            # Fallback: try CUDA runtime detection
            if not gpus:
                try:
                    # Try to import pycuda or cupy for CUDA detection
                    cuda_available = False
                    
                    try:
                        import pycuda.driver as cuda
                        import pycuda.autoinit
                        cuda_available = True
                        
                        device_count = cuda.Device.count()
                        for i in range(device_count):
                            device = cuda.Device(i)
                            name = device.name()
                            memory_mb = device.total_memory() // (1024 * 1024)
                            compute_capability = f"{device.compute_capability()[0]}.{device.compute_capability()[1]}"
                            
                            gpu = GpuInfo(
                                name=name,
                                gpu_type=GpuType.NVIDIA_CUDA,
                                memory_mb=memory_mb,
                                compute_capability=compute_capability
                            )
                            gpus.append(gpu)
                            
                            logger.info(f"Detected NVIDIA GPU via PyCUDA: {name} ({memory_mb}MB)")
                    
                    except ImportError:
                        try:
                            import cupy
                            cuda_available = True
                            
                            device_count = cupy.cuda.runtime.getDeviceCount()
                            for i in range(device_count):
                                with cupy.cuda.Device(i):
                                    props = cupy.cuda.runtime.getDeviceProperties(i)
                                    name = props['name'].decode('utf-8')
                                    memory_mb = props['totalGlobalMem'] // (1024 * 1024)
                                    compute_capability = f"{props['major']}.{props['minor']}"
                                    
                                    gpu = GpuInfo(
                                        name=name,
                                        gpu_type=GpuType.NVIDIA_CUDA,
                                        memory_mb=memory_mb,
                                        compute_capability=compute_capability
                                    )
                                    gpus.append(gpu)
                                    
                                    logger.info(f"Detected NVIDIA GPU via CuPy: {name} ({memory_mb}MB)")
                        
                        except ImportError:
                            logger.debug("No CUDA Python libraries available")
                
                except Exception as e:
                    logger.debug(f"CUDA runtime detection failed: {e}")
        
        except Exception as e:
            logger.warning(f"Error detecting NVIDIA GPUs: {e}")
        
        return gpus
    
    @staticmethod
    def detect_amd_gpus() -> List[GpuInfo]:
        """
        Detect AMD GPUs via ROCm and OpenCL.
        
        Returns:
            List of detected AMD GPUs
        """
        gpus = []
        
        try:
            # Try ROCm first
            try:
                result = subprocess.run(
                    ['rocm-smi', '--showproductname', '--showmeminfo', 'vram', '--showdriverversion'],
                    capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_gpu = None
                    
                    for line in lines:
                        line = line.strip()
                        if 'GPU[' in line and 'Product Name:' in line:
                            name = line.split('Product Name:')[1].strip()
                            current_gpu = GpuInfo(
                                name=name,
                                gpu_type=GpuType.AMD_ROCM,
                                memory_mb=0
                            )
                        elif current_gpu and 'GPU Memory Total:' in line:
                            try:
                                memory_str = line.split('GPU Memory Total:')[1].strip()
                                if 'MB' in memory_str:
                                    memory_mb = int(memory_str.split('MB')[0].strip())
                                elif 'GB' in memory_str:
                                    memory_gb = float(memory_str.split('GB')[0].strip())
                                    memory_mb = int(memory_gb * 1024)
                                else:
                                    memory_mb = 0
                                current_gpu.memory_mb = memory_mb
                                gpus.append(current_gpu)
                                
                                logger.info(f"Detected AMD GPU via ROCm: {current_gpu.name} ({memory_mb}MB)")
                                current_gpu = None
                            except (ValueError, IndexError):
                                pass
            
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                logger.debug("rocm-smi not available")
            
            # Fallback: try OpenCL detection for AMD GPUs
            if not gpus:
                try:
                    import pyopencl as cl
                    
                    platforms = cl.get_platforms()
                    for platform in platforms:
                        if 'amd' in platform.name.lower() or 'advanced micro devices' in platform.name.lower():
                            devices = platform.get_devices(device_type=cl.device_type.GPU)
                            
                            for device in devices:
                                name = device.name
                                memory_mb = device.global_mem_size // (1024 * 1024)
                                opencl_version = device.opencl_c_version
                                
                                gpu = GpuInfo(
                                    name=name,
                                    gpu_type=GpuType.AMD_OPENCL,
                                    memory_mb=memory_mb,
                                    opencl_version=opencl_version
                                )
                                gpus.append(gpu)
                                
                                logger.info(f"Detected AMD GPU via OpenCL: {name} ({memory_mb}MB)")
                
                except ImportError:
                    logger.debug("PyOpenCL not available")
                except Exception as e:
                    logger.debug(f"OpenCL AMD detection failed: {e}")
        
        except Exception as e:
            logger.warning(f"Error detecting AMD GPUs: {e}")
        
        return gpus
    
    @staticmethod
    def detect_intel_gpus() -> List[GpuInfo]:
        """
        Detect Intel GPUs via OpenCL.
        
        Returns:
            List of detected Intel GPUs
        """
        gpus = []
        
        try:
            # Intel GPU detection via OpenCL
            try:
                import pyopencl as cl
                
                platforms = cl.get_platforms()
                for platform in platforms:
                    if 'intel' in platform.name.lower():
                        devices = platform.get_devices(device_type=cl.device_type.GPU)
                        
                        for device in devices:
                            name = device.name
                            memory_mb = device.global_mem_size // (1024 * 1024)
                            opencl_version = device.opencl_c_version
                            
                            gpu = GpuInfo(
                                name=name,
                                gpu_type=GpuType.INTEL_OPENCL,
                                memory_mb=memory_mb,
                                opencl_version=opencl_version
                            )
                            gpus.append(gpu)
                            
                            logger.info(f"Detected Intel GPU via OpenCL: {name} ({memory_mb}MB)")
            
            except ImportError:
                logger.debug("PyOpenCL not available for Intel GPU detection")
            except Exception as e:
                logger.debug(f"OpenCL Intel detection failed: {e}")
        
        except Exception as e:
            logger.warning(f"Error detecting Intel GPUs: {e}")
        
        return gpus
    
    @staticmethod
    def detect_apple_gpus() -> List[GpuInfo]:
        """
        Detect Apple GPUs (Apple Silicon) via Metal.
        
        Returns:
            List of detected Apple GPUs
        """
        gpus = []
        
        try:
            system = platform.system()
            
            if system == "Darwin":
                # Check if running on Apple Silicon
                try:
                    result = subprocess.run(
                        ['sysctl', '-n', 'hw.optional.arm64'],
                        capture_output=True, text=True, timeout=5
                    )
                    
                    if result.returncode == 0 and result.stdout.strip() == '1':
                        # This is Apple Silicon, get GPU info
                        try:
                            result = subprocess.run(
                                ['system_profiler', 'SPDisplaysDataType'],
                                capture_output=True, text=True, timeout=10
                            )
                            
                            if result.returncode == 0:
                                lines = result.stdout.split('\n')
                                current_gpu = None
                                
                                for line in lines:
                                    line = line.strip()
                                    if 'Chipset Model:' in line:
                                        name = line.split('Chipset Model:')[1].strip()
                                        current_gpu = GpuInfo(
                                            name=name,
                                            gpu_type=GpuType.APPLE_METAL,
                                            memory_mb=0
                                        )
                                    elif current_gpu and 'VRAM (Total):' in line:
                                        try:
                                            memory_str = line.split('VRAM (Total):')[1].strip()
                                            if 'MB' in memory_str:
                                                memory_mb = int(memory_str.split('MB')[0].strip())
                                            elif 'GB' in memory_str:
                                                memory_gb = float(memory_str.split('GB')[0].strip())
                                                memory_mb = int(memory_gb * 1024)
                                            else:
                                                # Apple Silicon uses unified memory
                                                # Estimate GPU memory as portion of system memory
                                                total_result = subprocess.run(
                                                    ['sysctl', '-n', 'hw.memsize'],
                                                    capture_output=True, text=True, timeout=5
                                                )
                                                if total_result.returncode == 0:
                                                    total_bytes = int(total_result.stdout.strip())
                                                    # Assume 1/4 of system memory available for GPU
                                                    memory_mb = (total_bytes // 4) // (1024 * 1024)
                                            
                                            current_gpu.memory_mb = memory_mb
                                            gpus.append(current_gpu)
                                            
                                            logger.info(f"Detected Apple GPU: {current_gpu.name} ({memory_mb}MB)")
                                            current_gpu = None
                                        
                                        except (ValueError, IndexError):
                                            pass
                        
                        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                            logger.debug("Could not get Apple GPU info via system_profiler")
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not detect Apple Silicon")
        
        except Exception as e:
            logger.warning(f"Error detecting Apple GPUs: {e}")
        
        return gpus
    
    @staticmethod
    def detect_generic_opencl_gpus() -> List[GpuInfo]:
        """
        Detect any remaining GPUs via generic OpenCL.
        
        Returns:
            List of detected GPUs via OpenCL
        """
        gpus = []
        
        try:
            import pyopencl as cl
            
            platforms = cl.get_platforms()
            for platform in platforms:
                # Skip platforms we've already handled specifically
                platform_name = platform.name.lower()
                if any(vendor in platform_name for vendor in ['nvidia', 'amd', 'advanced micro devices', 'intel']):
                    continue
                
                try:
                    devices = platform.get_devices(device_type=cl.device_type.GPU)
                    
                    for device in devices:
                        name = device.name
                        memory_mb = device.global_mem_size // (1024 * 1024)
                        opencl_version = device.opencl_c_version
                        
                        gpu = GpuInfo(
                            name=name,
                            gpu_type=GpuType.UNKNOWN,
                            memory_mb=memory_mb,
                            opencl_version=opencl_version
                        )
                        gpus.append(gpu)
                        
                        logger.info(f"Detected generic GPU via OpenCL: {name} ({memory_mb}MB)")
                
                except cl.LogicError:
                    # No GPU devices on this platform
                    continue
        
        except ImportError:
            logger.debug("PyOpenCL not available for generic GPU detection")
        except Exception as e:
            logger.debug(f"Generic OpenCL detection failed: {e}")
        
        return gpus
    
    @staticmethod
    def detect_gpu_via_system_info() -> List[GpuInfo]:
        """
        Detect GPUs via system information (fallback method).
        
        Returns:
            List of detected GPUs via system info
        """
        gpus = []
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try lspci
                try:
                    result = subprocess.run(
                        ['lspci', '-nn'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            line_lower = line.lower()
                            if 'vga' in line_lower or 'display' in line_lower or '3d' in line_lower:
                                # Extract GPU name
                                if ':' in line:
                                    name = line.split(':', 1)[1].strip()
                                    # Remove PCI IDs in brackets
                                    if '[' in name and ']' in name:
                                        name = name.split('[')[0].strip()
                                    
                                    gpu_type = GpuType.UNKNOWN
                                    if 'nvidia' in line_lower:
                                        gpu_type = GpuType.NVIDIA_CUDA
                                    elif 'amd' in line_lower or 'ati' in line_lower:
                                        gpu_type = GpuType.AMD_OPENCL
                                    elif 'intel' in line_lower:
                                        gpu_type = GpuType.INTEL_OPENCL
                                    
                                    gpu = GpuInfo(
                                        name=name,
                                        gpu_type=gpu_type,
                                        memory_mb=0  # Can't determine memory from lspci
                                    )
                                    gpus.append(gpu)
                                    
                                    logger.info(f"Detected GPU via lspci: {name}")
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                    logger.debug("lspci not available")
            
            elif system == "Windows":
                # Try WMI
                try:
                    result = subprocess.run(
                        ['wmic', 'path', 'win32_VideoController', 'get', 'Name,AdapterRAM', '/format:value'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        name = ""
                        memory_bytes = 0
                        
                        for line in result.stdout.split('\n'):
                            if line.startswith('Name='):
                                name = line.split('=', 1)[1].strip()
                            elif line.startswith('AdapterRAM=') and line.split('=')[1].strip():
                                try:
                                    memory_bytes = int(line.split('=')[1].strip())
                                except ValueError:
                                    memory_bytes = 0
                            
                            if name and line.strip() == '':
                                # End of this GPU entry
                                memory_mb = memory_bytes // (1024 * 1024) if memory_bytes > 0 else 0
                                
                                gpu_type = GpuType.UNKNOWN
                                name_lower = name.lower()
                                if 'nvidia' in name_lower or 'geforce' in name_lower or 'quadro' in name_lower:
                                    gpu_type = GpuType.NVIDIA_CUDA
                                elif 'amd' in name_lower or 'radeon' in name_lower:
                                    gpu_type = GpuType.AMD_OPENCL
                                elif 'intel' in name_lower:
                                    gpu_type = GpuType.INTEL_OPENCL
                                
                                gpu = GpuInfo(
                                    name=name,
                                    gpu_type=gpu_type,
                                    memory_mb=memory_mb
                                )
                                gpus.append(gpu)
                                
                                logger.info(f"Detected GPU via WMI: {name} ({memory_mb}MB)")
                                
                                name = ""
                                memory_bytes = 0
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("WMI GPU detection failed")
        
        except Exception as e:
            logger.warning(f"Error detecting GPUs via system info: {e}")
        
        return gpus
    
    @classmethod
    def detect_all_gpus(cls) -> List[GpuInfo]:
        """
        Detect all available GPUs using multiple methods.
        
        Returns:
            List of all detected GPUs
        """
        logger.info("Starting GPU detection...")
        
        all_gpus = []
        
        # Try each detection method
        nvidia_gpus = cls.detect_nvidia_gpus()
        amd_gpus = cls.detect_amd_gpus()
        intel_gpus = cls.detect_intel_gpus()
        apple_gpus = cls.detect_apple_gpus()
        opencl_gpus = cls.detect_generic_opencl_gpus()
        
        # Combine results, avoiding duplicates
        all_gpus.extend(nvidia_gpus)
        all_gpus.extend(amd_gpus)
        all_gpus.extend(intel_gpus)
        all_gpus.extend(apple_gpus)
        
        # Add OpenCL GPUs that aren't already detected
        for opencl_gpu in opencl_gpus:
            if not any(gpu.name == opencl_gpu.name for gpu in all_gpus):
                all_gpus.append(opencl_gpu)
        
        # If no GPUs detected via specific methods, try system info
        if not all_gpus:
            system_gpus = cls.detect_gpu_via_system_info()
            all_gpus.extend(system_gpus)
        
        # Remove duplicates based on name
        unique_gpus = []
        seen_names = set()
        for gpu in all_gpus:
            if gpu.name not in seen_names:
                unique_gpus.append(gpu)
                seen_names.add(gpu.name)
        
        logger.info(f"GPU detection complete: found {len(unique_gpus)} GPUs")
        for gpu in unique_gpus:
            logger.info(f"  {gpu.name} ({gpu.gpu_type.value}, {gpu.memory_gb:.1f}GB)")
        
        return unique_gpus
    
    @classmethod
    def get_best_compute_gpu(cls, gpus: List[GpuInfo]) -> Optional[GpuInfo]:
        """
        Get the best GPU for compute workloads.
        
        Args:
            gpus: List of available GPUs
        
        Returns:
            Best compute GPU, or None if no suitable GPU found
        """
        compute_gpus = [gpu for gpu in gpus if gpu.supports_compute]
        
        if not compute_gpus:
            return None
        
        # Prioritize by type and memory
        def gpu_score(gpu: GpuInfo) -> tuple:
            type_score = {
                GpuType.NVIDIA_CUDA: 4,
                GpuType.AMD_ROCM: 3,
                GpuType.AMD_OPENCL: 2,
                GpuType.INTEL_OPENCL: 1,
                GpuType.UNKNOWN: 0
            }.get(gpu.gpu_type, 0)
            
            return (type_score, gpu.memory_mb)
        
        best_gpu = max(compute_gpus, key=gpu_score)
        logger.info(f"Best compute GPU: {best_gpu.name} ({best_gpu.memory_gb:.1f}GB)")
        
        return best_gpu
    
    @classmethod
    def estimate_compute_performance(cls, gpu: GpuInfo) -> Dict[str, Any]:
        """
        Estimate compute performance metrics for a GPU.
        
        Args:
            gpu: GPU to analyze
        
        Returns:
            Dictionary with performance estimates
        """
        performance = {
            'packet_generation_pps': 0,
            'memory_bandwidth_gbps': 0,
            'compute_score': 0,
            'suitability': 'none'
        }
        
        if not gpu.supports_compute:
            return performance
        
        # Rough performance estimates based on GPU type and memory
        if gpu.gpu_type == GpuType.NVIDIA_CUDA:
            # NVIDIA GPUs generally have good compute performance
            if gpu.memory_mb >= 24576:  # 24GB+ (RTX 4090, A100, etc.)
                performance['packet_generation_pps'] = 100_000_000  # 100M PPS
                performance['memory_bandwidth_gbps'] = 1000
                performance['compute_score'] = 10
                performance['suitability'] = 'excellent'
            elif gpu.memory_mb >= 16384:  # 16GB+ (RTX 4080, etc.)
                performance['packet_generation_pps'] = 75_000_000   # 75M PPS
                performance['memory_bandwidth_gbps'] = 750
                performance['compute_score'] = 8
                performance['suitability'] = 'very_good'
            elif gpu.memory_mb >= 8192:   # 8GB+ (RTX 3070, etc.)
                performance['packet_generation_pps'] = 50_000_000   # 50M PPS
                performance['memory_bandwidth_gbps'] = 500
                performance['compute_score'] = 6
                performance['suitability'] = 'good'
            elif gpu.memory_mb >= 4096:   # 4GB+ (GTX 1650, etc.)
                performance['packet_generation_pps'] = 25_000_000   # 25M PPS
                performance['memory_bandwidth_gbps'] = 250
                performance['compute_score'] = 4
                performance['suitability'] = 'fair'
            else:
                performance['packet_generation_pps'] = 10_000_000   # 10M PPS
                performance['memory_bandwidth_gbps'] = 100
                performance['compute_score'] = 2
                performance['suitability'] = 'limited'
        
        elif gpu.gpu_type == GpuType.AMD_ROCM:
            # AMD ROCm GPUs (professional)
            if gpu.memory_mb >= 16384:
                performance['packet_generation_pps'] = 60_000_000   # 60M PPS
                performance['memory_bandwidth_gbps'] = 600
                performance['compute_score'] = 7
                performance['suitability'] = 'very_good'
            elif gpu.memory_mb >= 8192:
                performance['packet_generation_pps'] = 40_000_000   # 40M PPS
                performance['memory_bandwidth_gbps'] = 400
                performance['compute_score'] = 5
                performance['suitability'] = 'good'
            else:
                performance['packet_generation_pps'] = 20_000_000   # 20M PPS
                performance['memory_bandwidth_gbps'] = 200
                performance['compute_score'] = 3
                performance['suitability'] = 'fair'
        
        elif gpu.gpu_type in [GpuType.AMD_OPENCL, GpuType.INTEL_OPENCL]:
            # Consumer GPUs via OpenCL (limited performance)
            if gpu.memory_mb >= 8192:
                performance['packet_generation_pps'] = 20_000_000   # 20M PPS
                performance['memory_bandwidth_gbps'] = 200
                performance['compute_score'] = 3
                performance['suitability'] = 'fair'
            else:
                performance['packet_generation_pps'] = 10_000_000   # 10M PPS
                performance['memory_bandwidth_gbps'] = 100
                performance['compute_score'] = 2
                performance['suitability'] = 'limited'
        
        return performance