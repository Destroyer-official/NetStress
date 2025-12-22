"""
Hardware Profile Module

Combines all hardware detection modules to create comprehensive hardware profiles
and device tier classifications for adaptive performance scaling.

Implements Requirements 11.1, 11.2, 11.3, 11.4, 11.5: Hardware profiling and adaptive configuration.
"""

import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

from .cpu_detector import CpuDetector, CpuInfo
from .memory_detector import MemoryDetector, MemoryInfo
from .network_detector import NetworkDetector, NetworkInfo
from .gpu_detector import GpuDetector, GpuInfo

logger = logging.getLogger(__name__)


class DeviceTier(Enum):
    """Device performance tiers"""
    LOW = "low"           # 1-2 cores, <4GB RAM, ≤100Mbps NIC
    MEDIUM = "medium"     # 4-8 cores, 4-16GB RAM, 1Gbps NIC
    HIGH = "high"         # 8-32 cores, 16-64GB RAM, 10Gbps NIC
    ENTERPRISE = "enterprise"  # 32+ cores, 64GB+ RAM, 25Gbps+ NIC


@dataclass
class TierConfig:
    """Configuration parameters for each device tier"""
    threads: int
    buffer_size_mb: int
    batch_size: int
    target_pps: int
    memory_limit_mb: int
    enable_gpu: bool = False
    enable_numa: bool = False
    enable_hugepages: bool = False
    
    @property
    def buffer_size_bytes(self) -> int:
        """Buffer size in bytes"""
        return self.buffer_size_mb * 1024 * 1024


@dataclass
class HardwareProfile:
    """Comprehensive hardware profile"""
    cpu: CpuInfo
    memory: MemoryInfo
    network: NetworkInfo
    gpus: list[GpuInfo]
    tier: DeviceTier
    config: TierConfig
    
    @property
    def best_gpu(self) -> Optional[GpuInfo]:
        """Best GPU for compute workloads"""
        return GpuDetector.get_best_compute_gpu(self.gpus) if self.gpus else None
    
    @property
    def has_high_speed_network(self) -> bool:
        """Whether system has high-speed networking (>=10Gbps)"""
        return self.network.has_high_speed_nic
    
    @property
    def supports_numa(self) -> bool:
        """Whether system supports NUMA"""
        return self.memory.is_numa
    
    @property
    def supports_gpu_acceleration(self) -> bool:
        """Whether system supports GPU acceleration"""
        return self.best_gpu is not None
    
    @property
    def total_compute_score(self) -> int:
        """Overall compute capability score (0-100)"""
        cpu_score = min(self.cpu.cores * 2, 40)  # Max 40 points for CPU
        memory_score = min(int(self.memory.total_gb * 2), 30)  # Max 30 points for memory
        network_score = min(int(self.network.total_bandwidth_gbps), 20)  # Max 20 points for network
        gpu_score = 0
        
        if self.best_gpu:
            gpu_perf = GpuDetector.estimate_compute_performance(self.best_gpu)
            gpu_score = min(gpu_perf['compute_score'], 10)  # Max 10 points for GPU
        
        return cpu_score + memory_score + network_score + gpu_score


class HardwareProfiler:
    """
    Hardware profiling and device tier classification.
    
    Combines all hardware detection modules to create comprehensive profiles
    and adaptive configurations.
    """
    
    # Device tier thresholds
    TIER_THRESHOLDS = {
        DeviceTier.LOW: {
            'max_cores': 2,
            'max_memory_gb': 4,
            'max_network_mbps': 100
        },
        DeviceTier.MEDIUM: {
            'max_cores': 8,
            'max_memory_gb': 16,
            'max_network_mbps': 1000
        },
        DeviceTier.HIGH: {
            'max_cores': 32,
            'max_memory_gb': 64,
            'max_network_mbps': 10000
        },
        DeviceTier.ENTERPRISE: {
            'max_cores': float('inf'),
            'max_memory_gb': float('inf'),
            'max_network_mbps': float('inf')
        }
    }
    
    # Tier configurations
    TIER_CONFIGS = {
        DeviceTier.LOW: TierConfig(
            threads=1,
            buffer_size_mb=64,
            batch_size=16,
            target_pps=50_000,
            memory_limit_mb=512,
            enable_gpu=False,
            enable_numa=False,
            enable_hugepages=False
        ),
        DeviceTier.MEDIUM: TierConfig(
            threads=4,
            buffer_size_mb=256,
            batch_size=64,
            target_pps=500_000,
            memory_limit_mb=2048,
            enable_gpu=True,
            enable_numa=False,
            enable_hugepages=False
        ),
        DeviceTier.HIGH: TierConfig(
            threads=16,
            buffer_size_mb=2048,
            batch_size=256,
            target_pps=10_000_000,
            memory_limit_mb=8192,
            enable_gpu=True,
            enable_numa=True,
            enable_hugepages=True
        ),
        DeviceTier.ENTERPRISE: TierConfig(
            threads=64,
            buffer_size_mb=8192,
            batch_size=1024,
            target_pps=100_000_000,
            memory_limit_mb=32768,
            enable_gpu=True,
            enable_numa=True,
            enable_hugepages=True
        )
    }
    
    @classmethod
    def classify_device_tier(cls, cpu: CpuInfo, memory: MemoryInfo, network: NetworkInfo) -> DeviceTier:
        """
        Classify device into performance tier based on hardware characteristics.
        
        Args:
            cpu: CPU information
            memory: Memory information
            network: Network information
        
        Returns:
            Device tier classification
        """
        cores = cpu.cores
        memory_gb = memory.total_gb
        network_mbps = network.total_bandwidth_mbps
        
        # Check each tier from lowest to highest
        for tier in [DeviceTier.LOW, DeviceTier.MEDIUM, DeviceTier.HIGH, DeviceTier.ENTERPRISE]:
            thresholds = cls.TIER_THRESHOLDS[tier]
            
            if (cores <= thresholds['max_cores'] and 
                memory_gb <= thresholds['max_memory_gb'] and 
                network_mbps <= thresholds['max_network_mbps']):
                
                logger.info(f"Classified device as {tier.value}: "
                           f"{cores}C, {memory_gb:.1f}GB, {network_mbps}Mbps")
                return tier
        
        # Fallback to enterprise if all thresholds exceeded
        logger.info(f"Classified device as {DeviceTier.ENTERPRISE.value}: "
                   f"{cores}C, {memory_gb:.1f}GB, {network_mbps}Mbps")
        return DeviceTier.ENTERPRISE
    
    @classmethod
    def create_adaptive_config(cls, tier: DeviceTier, cpu: CpuInfo, memory: MemoryInfo, 
                             network: NetworkInfo, gpus: list[GpuInfo]) -> TierConfig:
        """
        Create adaptive configuration based on tier and actual hardware.
        
        Args:
            tier: Device tier
            cpu: CPU information
            memory: Memory information
            network: Network information
            gpus: Available GPUs
        
        Returns:
            Adaptive configuration for the device
        """
        base_config = cls.TIER_CONFIGS[tier]
        
        # Create adaptive copy
        config = TierConfig(
            threads=base_config.threads,
            buffer_size_mb=base_config.buffer_size_mb,
            batch_size=base_config.batch_size,
            target_pps=base_config.target_pps,
            memory_limit_mb=base_config.memory_limit_mb,
            enable_gpu=base_config.enable_gpu,
            enable_numa=base_config.enable_numa,
            enable_hugepages=base_config.enable_hugepages
        )
        
        # Adapt thread count to actual CPU cores
        if tier == DeviceTier.LOW:
            config.threads = min(cpu.threads, 2)
        elif tier == DeviceTier.MEDIUM:
            config.threads = min(max(cpu.threads - 1, 1), 8)  # Leave one core for system, but at least 1 thread
        elif tier == DeviceTier.HIGH:
            config.threads = min(max(cpu.threads - 2, 1), 32)  # Leave two cores for system, but at least 1 thread
        else:  # ENTERPRISE
            config.threads = min(max(cpu.threads - 4, 1), 128)  # Leave four cores for system, but at least 1 thread
        
        # Adapt buffer size to available memory
        max_buffer_mb = int(memory.available_gb * 1024 * 0.25)  # Use max 25% of available memory
        config.buffer_size_mb = min(config.buffer_size_mb, max_buffer_mb)
        
        # Adapt memory limit
        max_memory_mb = int(memory.available_gb * 1024 * 0.5)  # Use max 50% of available memory
        config.memory_limit_mb = min(config.memory_limit_mb, max_memory_mb)
        
        # Adapt target PPS to network bandwidth
        if network.fastest_interface and network.fastest_interface.speed_mbps > 0:
            # Estimate packets per second based on network speed
            # Assume average packet size of 1000 bytes
            max_pps_by_network = (network.fastest_interface.speed_mbps * 1_000_000) // (1000 * 8)
            config.target_pps = min(config.target_pps, max_pps_by_network)
        elif config.target_pps == 0:
            # Fallback if no network speed detected - use tier default
            config.target_pps = base_config.target_pps
        
        # Disable features not supported by hardware
        if not memory.is_numa:
            config.enable_numa = False
        
        if memory.hugepage_size_kb == 0:
            config.enable_hugepages = False
        
        if not gpus or not GpuDetector.get_best_compute_gpu(gpus):
            config.enable_gpu = False
        
        logger.info(f"Created adaptive config for {tier.value}: "
                   f"{config.threads} threads, {config.buffer_size_mb}MB buffer, "
                   f"{config.target_pps} PPS target")
        
        return config
    
    @classmethod
    def detect_hardware_profile(cls) -> HardwareProfile:
        """
        Detect comprehensive hardware profile with adaptive configuration.
        
        Returns:
            Complete hardware profile with tier classification and config
        """
        logger.info("Starting comprehensive hardware detection...")
        
        # Detect all hardware components
        cpu = CpuDetector.detect_cpu_info()
        memory = MemoryDetector.detect_memory_info()
        network = NetworkDetector.detect_network_info()
        gpus = GpuDetector.detect_all_gpus()
        
        # Classify device tier
        tier = cls.classify_device_tier(cpu, memory, network)
        
        # Create adaptive configuration
        config = cls.create_adaptive_config(tier, cpu, memory, network, gpus)
        
        # Create hardware profile
        profile = HardwareProfile(
            cpu=cpu,
            memory=memory,
            network=network,
            gpus=gpus,
            tier=tier,
            config=config
        )
        
        logger.info(f"Hardware profile complete: {tier.value} tier, "
                   f"score {profile.total_compute_score}/100")
        
        # Log summary
        cls._log_profile_summary(profile)
        
        return profile
    
    @classmethod
    def _log_profile_summary(cls, profile: HardwareProfile) -> None:
        """Log hardware profile summary"""
        logger.info("=== Hardware Profile Summary ===")
        logger.info(f"Device Tier: {profile.tier.value.upper()}")
        logger.info(f"CPU: {profile.cpu.cores}C/{profile.cpu.threads}T "
                   f"{profile.cpu.architecture.value} @ {profile.cpu.frequency_mhz}MHz")
        logger.info(f"Memory: {profile.memory.total_gb:.1f}GB total, "
                   f"{profile.memory.available_gb:.1f}GB available")
        logger.info(f"Network: {len(profile.network.interfaces)} interfaces, "
                   f"{profile.network.total_bandwidth_gbps:.1f}Gbps total")
        
        if profile.gpus:
            logger.info(f"GPUs: {len(profile.gpus)} detected")
            for gpu in profile.gpus:
                logger.info(f"  - {gpu.name} ({gpu.memory_gb:.1f}GB)")
        else:
            logger.info("GPUs: None detected")
        
        logger.info(f"Configuration: {profile.config.threads} threads, "
                   f"{profile.config.buffer_size_mb}MB buffer, "
                   f"{profile.config.target_pps:,} PPS target")
        logger.info(f"Compute Score: {profile.total_compute_score}/100")
        logger.info("================================")
    
    @classmethod
    def get_optimization_recommendations(cls, profile: HardwareProfile) -> list[str]:
        """
        Get optimization recommendations based on hardware profile.
        
        Args:
            profile: Hardware profile
        
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        
        # CPU optimizations
        if profile.cpu.features.avx2:
            recommendations.append("Enable AVX2 SIMD acceleration for packet processing")
        if profile.cpu.features.avx512:
            recommendations.append("Enable AVX-512 SIMD for maximum vectorization")
        if profile.cpu.features.neon:
            recommendations.append("Enable ARM NEON SIMD acceleration")
        
        # Memory optimizations
        if profile.memory.is_numa:
            recommendations.append("Use NUMA-aware memory allocation and thread pinning")
        if profile.memory.hugepages_total > 0:
            recommendations.append("Enable hugepages for better memory performance")
        if profile.memory.speed_mhz > 3000:
            recommendations.append("High-speed memory detected - optimize for bandwidth")
        
        # Network optimizations
        if profile.network.has_high_speed_nic:
            recommendations.append("Enable zero-copy networking for high-speed NICs")
        if len(profile.network.bondable_interfaces) > 1:
            recommendations.append("Consider NIC bonding for increased bandwidth")
        if profile.network.supports_kernel_bypass:
            recommendations.append("Enable kernel bypass (DPDK/AF_XDP) for maximum performance")
        
        # GPU optimizations
        if profile.best_gpu:
            gpu_perf = GpuDetector.estimate_compute_performance(profile.best_gpu)
            if gpu_perf['suitability'] in ['excellent', 'very_good']:
                recommendations.append("Enable GPU acceleration for packet generation")
            recommendations.append(f"GPU can generate ~{gpu_perf['packet_generation_pps']:,} PPS")
        
        # Tier-specific recommendations
        if profile.tier == DeviceTier.LOW:
            recommendations.append("Use single-threaded mode to minimize overhead")
            recommendations.append("Limit buffer sizes to conserve memory")
        elif profile.tier == DeviceTier.ENTERPRISE:
            recommendations.append("Enable all performance features for maximum throughput")
            recommendations.append("Use per-core packet queues with RSS")
        
        return recommendations
    
    @classmethod
    def estimate_performance_capacity(cls, profile: HardwareProfile) -> Dict[str, Any]:
        """
        Estimate performance capacity based on hardware profile.
        
        Args:
            profile: Hardware profile
        
        Returns:
            Dictionary with performance estimates
        """
        base_pps = profile.config.target_pps
        
        # Ensure we have a minimum baseline PPS
        if base_pps == 0:
            base_pps = cls.TIER_CONFIGS[profile.tier].target_pps
        
        # Apply hardware-specific multipliers
        cpu_multiplier = 1.0
        if profile.cpu.features.avx2:
            cpu_multiplier *= 1.2
        if profile.cpu.features.avx512:
            cpu_multiplier *= 1.5
        if profile.cpu.features.neon:
            cpu_multiplier *= 1.1
        
        memory_multiplier = 1.0
        if profile.memory.speed_mhz > 3000:
            memory_multiplier *= 1.1
        if profile.memory.is_numa and profile.config.enable_numa:
            memory_multiplier *= 1.15
        
        network_multiplier = 1.0
        if profile.network.has_high_speed_nic:
            network_multiplier *= 1.3
        if profile.network.supports_kernel_bypass:
            network_multiplier *= 1.5
        
        gpu_multiplier = 1.0
        if profile.best_gpu and profile.config.enable_gpu:
            gpu_perf = GpuDetector.estimate_compute_performance(profile.best_gpu)
            if gpu_perf['suitability'] == 'excellent':
                gpu_multiplier *= 2.0
            elif gpu_perf['suitability'] == 'very_good':
                gpu_multiplier *= 1.5
            elif gpu_perf['suitability'] == 'good':
                gpu_multiplier *= 1.2
        
        # Calculate final estimates
        estimated_pps = int(base_pps * cpu_multiplier * memory_multiplier * 
                           network_multiplier * gpu_multiplier)
        
        # Bandwidth estimate (assuming 1KB average packet size)
        estimated_bandwidth_mbps = (estimated_pps * 1024 * 8) // 1_000_000
        
        return {
            'estimated_pps': estimated_pps,
            'estimated_bandwidth_mbps': estimated_bandwidth_mbps,
            'estimated_bandwidth_gbps': estimated_bandwidth_mbps / 1000.0,
            'cpu_multiplier': cpu_multiplier,
            'memory_multiplier': memory_multiplier,
            'network_multiplier': network_multiplier,
            'gpu_multiplier': gpu_multiplier,
            'confidence': 'high' if profile.tier in [DeviceTier.HIGH, DeviceTier.ENTERPRISE] else 'medium'
        }