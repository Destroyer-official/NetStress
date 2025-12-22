"""
Platform capability mapping and feature detection.
Provides comprehensive capability assessment for optimization decisions.
"""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from .detection import PlatformType, Architecture, SystemInfo


class NetworkCapability(Enum):
    """Network-related capabilities"""
    RAW_SOCKETS = "raw_sockets"
    PACKET_CAPTURE = "packet_capture"
    KERNEL_BYPASS = "kernel_bypass"
    ZERO_COPY = "zero_copy"
    MULTICAST = "multicast"
    IPV6 = "ipv6"
    JUMBO_FRAMES = "jumbo_frames"
    XDP = "xdp"
    EBPF = "ebpf"
    DPDK = "dpdk"
    NETMAP = "netmap"


class PerformanceCapability(Enum):
    """Performance-related capabilities"""
    HIGH_RESOLUTION_TIMER = "high_resolution_timer"
    CPU_AFFINITY = "cpu_affinity"
    NUMA_AWARENESS = "numa_awareness"
    HUGE_PAGES = "huge_pages"
    MEMORY_LOCKING = "memory_locking"
    REAL_TIME_SCHEDULING = "real_time_scheduling"
    VECTORIZED_OPERATIONS = "vectorized_operations"
    HARDWARE_ACCELERATION = "hardware_acceleration"


class SecurityCapability(Enum):
    """Security-related capabilities"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SANDBOX_ESCAPE = "sandbox_escape"
    FIREWALL_BYPASS = "firewall_bypass"
    ANTI_FORENSICS = "anti_forensics"


@dataclass
class CapabilityProfile:
    """Comprehensive capability profile for a platform"""
    network_capabilities: Set[NetworkCapability]
    performance_capabilities: Set[PerformanceCapability]
    security_capabilities: Set[SecurityCapability]
    max_packet_rate: int
    max_bandwidth_gbps: float
    max_concurrent_connections: int
    memory_efficiency_score: float
    cpu_efficiency_score: float


class CapabilityMapper:
    """Maps platform capabilities and provides optimization recommendations"""
    
    # Platform capability matrices
    NETWORK_CAPABILITY_MATRIX = {
        PlatformType.LINUX: {
            NetworkCapability.RAW_SOCKETS,
            NetworkCapability.PACKET_CAPTURE,
            NetworkCapability.KERNEL_BYPASS,
            NetworkCapability.ZERO_COPY,
            NetworkCapability.MULTICAST,
            NetworkCapability.IPV6,
            NetworkCapability.JUMBO_FRAMES,
            NetworkCapability.XDP,
            NetworkCapability.EBPF,
            NetworkCapability.DPDK,
            NetworkCapability.NETMAP
        },
        PlatformType.WINDOWS: {
            NetworkCapability.RAW_SOCKETS,
            NetworkCapability.PACKET_CAPTURE,
            NetworkCapability.MULTICAST,
            NetworkCapability.IPV6,
            NetworkCapability.JUMBO_FRAMES
        },
        PlatformType.MACOS: {
            NetworkCapability.RAW_SOCKETS,
            NetworkCapability.PACKET_CAPTURE,
            NetworkCapability.MULTICAST,
            NetworkCapability.IPV6,
            NetworkCapability.JUMBO_FRAMES
        }
    }
    
    PERFORMANCE_CAPABILITY_MATRIX = {
        PlatformType.LINUX: {
            PerformanceCapability.HIGH_RESOLUTION_TIMER,
            PerformanceCapability.CPU_AFFINITY,
            PerformanceCapability.NUMA_AWARENESS,
            PerformanceCapability.HUGE_PAGES,
            PerformanceCapability.MEMORY_LOCKING,
            PerformanceCapability.REAL_TIME_SCHEDULING,
            PerformanceCapability.VECTORIZED_OPERATIONS,
            PerformanceCapability.HARDWARE_ACCELERATION
        },
        PlatformType.WINDOWS: {
            PerformanceCapability.HIGH_RESOLUTION_TIMER,
            PerformanceCapability.CPU_AFFINITY,
            PerformanceCapability.NUMA_AWARENESS,
            PerformanceCapability.VECTORIZED_OPERATIONS,
            PerformanceCapability.HARDWARE_ACCELERATION
        },
        PlatformType.MACOS: {
            PerformanceCapability.HIGH_RESOLUTION_TIMER,
            PerformanceCapability.VECTORIZED_OPERATIONS,
            PerformanceCapability.HARDWARE_ACCELERATION
        }
    }
    
    # Performance baselines by platform and architecture
    PERFORMANCE_BASELINES = {
        (PlatformType.LINUX, Architecture.X86_64): {
            'max_packet_rate': 10000000,  # 10M pps
            'max_bandwidth_gbps': 100.0,
            'max_concurrent_connections': 1000000,
            'memory_efficiency_score': 0.95,
            'cpu_efficiency_score': 0.90
        },
        (PlatformType.WINDOWS, Architecture.X86_64): {
            'max_packet_rate': 5000000,   # 5M pps
            'max_bandwidth_gbps': 50.0,
            'max_concurrent_connections': 100000,
            'memory_efficiency_score': 0.80,
            'cpu_efficiency_score': 0.75
        },
        (PlatformType.MACOS, Architecture.X86_64): {
            'max_packet_rate': 3000000,   # 3M pps
            'max_bandwidth_gbps': 40.0,
            'max_concurrent_connections': 50000,
            'memory_efficiency_score': 0.85,
            'cpu_efficiency_score': 0.80
        },
        (PlatformType.LINUX, Architecture.ARM64): {
            'max_packet_rate': 8000000,   # 8M pps
            'max_bandwidth_gbps': 80.0,
            'max_concurrent_connections': 800000,
            'memory_efficiency_score': 0.90,
            'cpu_efficiency_score': 0.85
        }
    }
    
    @classmethod
    def get_network_capabilities(cls, platform_type: PlatformType, 
                                system_info: SystemInfo) -> Set[NetworkCapability]:
        """Get network capabilities for a platform"""
        base_capabilities = cls.NETWORK_CAPABILITY_MATRIX.get(platform_type, set())
        
        # Filter based on actual system capabilities
        filtered_capabilities = set()
        
        for capability in base_capabilities:
            if capability == NetworkCapability.RAW_SOCKETS:
                if system_info.supports_raw_sockets:
                    filtered_capabilities.add(capability)
            elif capability == NetworkCapability.XDP:
                # XDP requires Linux kernel 4.8+
                if platform_type == PlatformType.LINUX:
                    try:
                        kernel_version = system_info.kernel_version
                        major, minor = map(int, kernel_version.split('.')[:2])
                        if major > 4 or (major == 4 and minor >= 8):
                            filtered_capabilities.add(capability)
                    except (ValueError, AttributeError):
                        pass
            elif capability == NetworkCapability.EBPF:
                # eBPF requires Linux kernel 3.18+
                if platform_type == PlatformType.LINUX:
                    try:
                        kernel_version = system_info.kernel_version
                        major, minor = map(int, kernel_version.split('.')[:2])
                        if major > 3 or (major == 3 and minor >= 18):
                            filtered_capabilities.add(capability)
                    except (ValueError, AttributeError):
                        pass
            else:
                filtered_capabilities.add(capability)
        
        return filtered_capabilities
    
    @classmethod
    def get_performance_capabilities(cls, platform_type: PlatformType,
                                   system_info: SystemInfo) -> Set[PerformanceCapability]:
        """Get performance capabilities for a platform"""
        base_capabilities = cls.PERFORMANCE_CAPABILITY_MATRIX.get(platform_type, set())
        
        # Filter based on system requirements
        filtered_capabilities = set()
        
        for capability in base_capabilities:
            if capability == PerformanceCapability.NUMA_AWARENESS:
                # NUMA awareness requires multiple CPU sockets
                if system_info.cpu_count >= 8:  # Heuristic for NUMA systems
                    filtered_capabilities.add(capability)
            elif capability == PerformanceCapability.HUGE_PAGES:
                # Check if huge pages are available (Linux-specific)
                if platform_type == PlatformType.LINUX:
                    try:
                        with open('/proc/meminfo', 'r') as f:
                            content = f.read()
                            if 'HugePages_Total:' in content:
                                filtered_capabilities.add(capability)
                    except (IOError, OSError):
                        pass
            elif capability == PerformanceCapability.MEMORY_LOCKING:
                # Memory locking requires sufficient privileges
                if system_info.has_admin_privileges:
                    filtered_capabilities.add(capability)
            else:
                filtered_capabilities.add(capability)
        
        return filtered_capabilities
    
    @classmethod
    def get_security_capabilities(cls, platform_type: PlatformType,
                                system_info: SystemInfo) -> Set[SecurityCapability]:
        """Get security capabilities for a platform"""
        capabilities = set()
        
        if system_info.has_admin_privileges:
            capabilities.add(SecurityCapability.PRIVILEGE_ESCALATION)
            capabilities.add(SecurityCapability.FIREWALL_BYPASS)
            capabilities.add(SecurityCapability.ANTI_FORENSICS)
        
        # Platform-specific security capabilities
        if platform_type == PlatformType.LINUX:
            capabilities.add(SecurityCapability.SANDBOX_ESCAPE)
        
        return capabilities
    
    @classmethod
    def get_performance_baseline(cls, platform_type: PlatformType,
                               architecture: Architecture) -> Dict[str, float]:
        """Get performance baseline for platform/architecture combination"""
        key = (platform_type, architecture)
        baseline = cls.PERFORMANCE_BASELINES.get(key)
        
        if baseline is None:
            # Fallback to x86_64 baseline with reduced performance
            fallback_key = (platform_type, Architecture.X86_64)
            baseline = cls.PERFORMANCE_BASELINES.get(fallback_key, {
                'max_packet_rate': 1000000,
                'max_bandwidth_gbps': 10.0,
                'max_concurrent_connections': 10000,
                'memory_efficiency_score': 0.70,
                'cpu_efficiency_score': 0.65
            })
            
            # Reduce performance for unknown architectures
            baseline = {k: v * 0.7 if isinstance(v, (int, float)) else v 
                       for k, v in baseline.items()}
        
        return baseline
    
    @classmethod
    def create_capability_profile(cls, system_info: SystemInfo) -> CapabilityProfile:
        """Create comprehensive capability profile"""
        platform_type = system_info.platform_type
        architecture = system_info.architecture
        
        network_caps = cls.get_network_capabilities(platform_type, system_info)
        performance_caps = cls.get_performance_capabilities(platform_type, system_info)
        security_caps = cls.get_security_capabilities(platform_type, system_info)
        
        baseline = cls.get_performance_baseline(platform_type, architecture)
        
        # Adjust baseline based on system resources
        cpu_factor = min(system_info.cpu_count / 8.0, 2.0)  # Scale up to 2x for high core count
        memory_factor = min(system_info.memory_total / (16 * 1024**3), 2.0)  # Scale up to 2x for 16GB+
        
        return CapabilityProfile(
            network_capabilities=network_caps,
            performance_capabilities=performance_caps,
            security_capabilities=security_caps,
            max_packet_rate=int(baseline['max_packet_rate'] * cpu_factor),
            max_bandwidth_gbps=baseline['max_bandwidth_gbps'] * cpu_factor,
            max_concurrent_connections=int(baseline['max_concurrent_connections'] * memory_factor),
            memory_efficiency_score=baseline['memory_efficiency_score'],
            cpu_efficiency_score=baseline['cpu_efficiency_score']
        )
    
    @classmethod
    def get_optimization_recommendations(cls, profile: CapabilityProfile) -> List[str]:
        """Get optimization recommendations based on capability profile"""
        recommendations = []
        
        # Network optimizations
        if NetworkCapability.KERNEL_BYPASS in profile.network_capabilities:
            recommendations.append("Enable kernel bypass (DPDK/XDP) for maximum packet rate")
        
        if NetworkCapability.ZERO_COPY in profile.network_capabilities:
            recommendations.append("Use zero-copy networking to reduce CPU overhead")
        
        if NetworkCapability.EBPF in profile.network_capabilities:
            recommendations.append("Implement eBPF filters for efficient packet processing")
        
        # Performance optimizations
        if PerformanceCapability.CPU_AFFINITY in profile.performance_capabilities:
            recommendations.append("Set CPU affinity to isolate attack processes")
        
        if PerformanceCapability.NUMA_AWARENESS in profile.performance_capabilities:
            recommendations.append("Use NUMA-aware memory allocation")
        
        if PerformanceCapability.HUGE_PAGES in profile.performance_capabilities:
            recommendations.append("Enable huge pages for better memory performance")
        
        if PerformanceCapability.REAL_TIME_SCHEDULING in profile.performance_capabilities:
            recommendations.append("Use real-time scheduling for time-critical operations")
        
        # Security recommendations
        if SecurityCapability.PRIVILEGE_ESCALATION in profile.security_capabilities:
            recommendations.append("Leverage elevated privileges for raw socket access")
        
        if SecurityCapability.FIREWALL_BYPASS in profile.security_capabilities:
            recommendations.append("Implement firewall evasion techniques")
        
        return recommendations
    
    @classmethod
    def estimate_attack_capacity(cls, profile: CapabilityProfile, 
                               attack_type: str) -> Dict[str, float]:
        """Estimate attack capacity based on capability profile"""
        base_pps = profile.max_packet_rate
        base_bandwidth = profile.max_bandwidth_gbps
        
        # Adjust based on attack type
        if attack_type.upper() == 'TCP':
            # TCP requires more overhead
            pps_factor = 0.6
            bandwidth_factor = 0.7
        elif attack_type.upper() == 'UDP':
            # UDP is more efficient
            pps_factor = 0.9
            bandwidth_factor = 0.95
        elif attack_type.upper() == 'HTTP':
            # HTTP has significant overhead
            pps_factor = 0.3
            bandwidth_factor = 0.5
        else:
            # Default factors
            pps_factor = 0.7
            bandwidth_factor = 0.8
        
        # Apply capability bonuses
        if NetworkCapability.KERNEL_BYPASS in profile.network_capabilities:
            pps_factor *= 1.5
            bandwidth_factor *= 1.3
        
        if NetworkCapability.ZERO_COPY in profile.network_capabilities:
            pps_factor *= 1.2
            bandwidth_factor *= 1.1
        
        if PerformanceCapability.CPU_AFFINITY in profile.performance_capabilities:
            pps_factor *= 1.1
        
        return {
            'estimated_pps': int(base_pps * pps_factor),
            'estimated_bandwidth_gbps': base_bandwidth * bandwidth_factor,
            'efficiency_score': (profile.cpu_efficiency_score + profile.memory_efficiency_score) / 2
        }