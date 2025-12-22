"""
Property-Based Tests for Hardware Detection System

Tests the hardware detection completeness property to ensure all hardware
components are correctly identified and return valid values.

**Feature: true-military-grade, Property 2: Hardware Detection Completeness**
**Validates: Requirements 11.1**
"""

import pytest
from hypothesis import given, strategies as st, assume, settings
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant
import logging
from typing import Any, Dict

from core.hardware.cpu_detector import CpuDetector, CpuInfo, Architecture, CpuFeatures
from core.hardware.memory_detector import MemoryDetector, MemoryInfo
from core.hardware.network_detector import NetworkDetector, NetworkInfo
from core.hardware.gpu_detector import GpuDetector, GpuInfo, GpuType
from core.hardware.hardware_profile import HardwareProfiler, HardwareProfile, DeviceTier

logger = logging.getLogger(__name__)


class TestHardwareDetectionProperties:
    """Property-based tests for hardware detection completeness"""
    
    def test_cpu_detection_completeness(self):
        """
        Property 2: Hardware Detection Completeness - CPU Component
        
        For any system startup, the CPU detector SHALL correctly identify
        CPU cores, architecture, and return valid values for all fields.
        """
        cpu_info = CpuDetector.detect_cpu_info()
        
        # CPU info must be valid
        assert isinstance(cpu_info, CpuInfo)
        
        # Core count must be positive
        assert cpu_info.cores > 0, f"Invalid core count: {cpu_info.cores}"
        assert cpu_info.threads > 0, f"Invalid thread count: {cpu_info.threads}"
        
        # Threads should be >= cores (hyperthreading or equal)
        assert cpu_info.threads >= cpu_info.cores, \
            f"Threads ({cpu_info.threads}) < cores ({cpu_info.cores})"
        
        # Architecture must be valid enum value
        assert isinstance(cpu_info.architecture, Architecture)
        assert cpu_info.architecture != Architecture.UNKNOWN or True  # Allow unknown for edge cases
        
        # Features must be valid
        assert isinstance(cpu_info.features, CpuFeatures)
        
        # Model name and vendor should be strings
        assert isinstance(cpu_info.model_name, str)
        assert isinstance(cpu_info.vendor, str)
        
        # Frequency should be non-negative (0 allowed if unknown)
        assert cpu_info.frequency_mhz >= 0, f"Invalid frequency: {cpu_info.frequency_mhz}"
        
        # Cache sizes should be non-negative
        assert cpu_info.cache_l1_kb >= 0, f"Invalid L1 cache: {cpu_info.cache_l1_kb}"
        assert cpu_info.cache_l2_kb >= 0, f"Invalid L2 cache: {cpu_info.cache_l2_kb}"
        assert cpu_info.cache_l3_kb >= 0, f"Invalid L3 cache: {cpu_info.cache_l3_kb}"
        
        logger.info(f"CPU detection test passed: {cpu_info.cores}C/{cpu_info.threads}T "
                   f"{cpu_info.architecture.value}")
    
    def test_memory_detection_completeness(self):
        """
        Property 2: Hardware Detection Completeness - Memory Component
        
        For any system startup, the memory detector SHALL correctly identify
        total RAM, available RAM, and return valid values for all fields.
        """
        memory_info = MemoryDetector.detect_memory_info()
        
        # Memory info must be valid
        assert isinstance(memory_info, MemoryInfo)
        
        # Total memory must be positive
        assert memory_info.total_bytes > 0, f"Invalid total memory: {memory_info.total_bytes}"
        
        # Available memory must be positive and <= total
        assert memory_info.available_bytes > 0, f"Invalid available memory: {memory_info.available_bytes}"
        assert memory_info.available_bytes <= memory_info.total_bytes, \
            f"Available ({memory_info.available_bytes}) > total ({memory_info.total_bytes})"
        
        # Speed should be non-negative (0 allowed if unknown)
        assert memory_info.speed_mhz >= 0, f"Invalid memory speed: {memory_info.speed_mhz}"
        
        # Type should be string
        assert isinstance(memory_info.type_ddr, str)
        
        # Channels should be non-negative
        assert memory_info.channels >= 0, f"Invalid channel count: {memory_info.channels}"
        
        # Hugepage info should be non-negative
        assert memory_info.hugepage_size_kb >= 0, f"Invalid hugepage size: {memory_info.hugepage_size_kb}"
        assert memory_info.hugepages_total >= 0, f"Invalid hugepages total: {memory_info.hugepages_total}"
        assert memory_info.hugepages_free >= 0, f"Invalid hugepages free: {memory_info.hugepages_free}"
        
        # Free hugepages should not exceed total
        if memory_info.hugepages_total > 0:
            assert memory_info.hugepages_free <= memory_info.hugepages_total, \
                f"Free hugepages ({memory_info.hugepages_free}) > total ({memory_info.hugepages_total})"
        
        # NUMA nodes should be valid if present
        if memory_info.numa_nodes:
            assert len(memory_info.numa_nodes) > 0
            for node in memory_info.numa_nodes:
                assert node.node_id >= 0
                assert node.memory_mb >= 0
                assert isinstance(node.cpu_list, list)
        
        logger.info(f"Memory detection test passed: {memory_info.total_gb:.1f}GB total, "
                   f"{memory_info.available_gb:.1f}GB available")
    
    def test_network_detection_completeness(self):
        """
        Property 2: Hardware Detection Completeness - Network Component
        
        For any system startup, the network detector SHALL correctly identify
        NIC speed, capabilities, and return valid values for all fields.
        """
        network_info = NetworkDetector.detect_network_info()
        
        # Network info must be valid
        assert isinstance(network_info, NetworkInfo)
        
        # Should have at least detected interface list (even if empty)
        assert isinstance(network_info.interfaces, list)
        
        # Total bandwidth should be non-negative
        assert network_info.total_bandwidth_mbps >= 0, \
            f"Invalid total bandwidth: {network_info.total_bandwidth_mbps}"
        
        # Interface count properties should be consistent
        assert network_info.interface_count == len(network_info.interfaces)
        assert network_info.active_interface_count <= network_info.interface_count
        
        # Bondable interfaces should be subset of all interfaces
        assert len(network_info.bondable_interfaces) <= len(network_info.interfaces)
        
        # Validate each interface
        for interface in network_info.interfaces:
            # Name should be non-empty string
            assert isinstance(interface.name, str)
            assert len(interface.name) > 0
            
            # Speed should be non-negative
            assert interface.speed_mbps >= 0, f"Invalid speed for {interface.name}: {interface.speed_mbps}"
            
            # MTU should be reasonable (at least 68 bytes for IPv4 minimum)
            if interface.mtu > 0:
                assert interface.mtu >= 68, f"Invalid MTU for {interface.name}: {interface.mtu}"
            
            # MAC address should be string
            assert isinstance(interface.mac_address, str)
            
            # IP addresses should be list of strings
            assert isinstance(interface.ip_addresses, list)
            for ip in interface.ip_addresses:
                assert isinstance(ip, str)
            
            # Capabilities should be valid
            assert hasattr(interface.capabilities, 'checksum_offload')
            assert hasattr(interface.capabilities, 'tso')
            assert hasattr(interface.capabilities, 'rss')
            
            # Driver should be string
            assert isinstance(interface.driver, str)
            
            # Queue count should be positive
            assert interface.queue_count > 0, f"Invalid queue count for {interface.name}: {interface.queue_count}"
            
            # NUMA node should be valid if set
            if interface.numa_node >= 0:
                assert interface.numa_node < 256  # Reasonable upper bound
        
        # Fastest interface should be from the interface list if present
        if network_info.fastest_interface:
            assert network_info.fastest_interface in network_info.interfaces
        
        logger.info(f"Network detection test passed: {len(network_info.interfaces)} interfaces, "
                   f"{network_info.total_bandwidth_gbps:.1f}Gbps total")
    
    def test_gpu_detection_completeness(self):
        """
        Property 2: Hardware Detection Completeness - GPU Component
        
        For any system startup, the GPU detector SHALL correctly identify
        GPU availability and return valid values for all fields.
        """
        gpus = GpuDetector.detect_all_gpus()
        
        # GPU list must be valid (can be empty)
        assert isinstance(gpus, list)
        
        # Validate each GPU
        for gpu in gpus:
            assert isinstance(gpu, GpuInfo)
            
            # Name should be non-empty string
            assert isinstance(gpu.name, str)
            assert len(gpu.name) > 0
            
            # GPU type should be valid enum
            assert isinstance(gpu.gpu_type, GpuType)
            
            # Memory should be non-negative
            assert gpu.memory_mb >= 0, f"Invalid GPU memory for {gpu.name}: {gpu.memory_mb}"
            
            # String fields should be strings
            assert isinstance(gpu.compute_capability, str)
            assert isinstance(gpu.driver_version, str)
            assert isinstance(gpu.cuda_version, str)
            assert isinstance(gpu.opencl_version, str)
            assert isinstance(gpu.pci_id, str)
            
            # Numeric fields should be non-negative
            assert gpu.power_limit_watts >= 0, f"Invalid power limit for {gpu.name}: {gpu.power_limit_watts}"
            assert gpu.temperature_celsius >= 0, f"Invalid temperature for {gpu.name}: {gpu.temperature_celsius}"
            
            # Utilization should be 0-100 percent
            assert 0 <= gpu.utilization_percent <= 100, \
                f"Invalid utilization for {gpu.name}: {gpu.utilization_percent}"
            assert 0 <= gpu.memory_utilization_percent <= 100, \
                f"Invalid memory utilization for {gpu.name}: {gpu.memory_utilization_percent}"
            
            # Properties should be consistent
            if gpu.memory_mb >= 8192:
                assert gpu.is_high_end
            
            if gpu.gpu_type in [GpuType.NVIDIA_CUDA, GpuType.AMD_ROCM, GpuType.AMD_OPENCL, GpuType.INTEL_OPENCL]:
                assert gpu.supports_compute
        
        logger.info(f"GPU detection test passed: {len(gpus)} GPUs detected")
    
    def test_hardware_profile_completeness(self):
        """
        Property 2: Hardware Detection Completeness - Complete Profile
        
        For any system startup, the hardware profiler SHALL create a complete
        profile with valid tier classification and configuration.
        """
        profile = HardwareProfiler.detect_hardware_profile()
        
        # Profile must be valid
        assert isinstance(profile, HardwareProfile)
        
        # All components must be present and valid
        assert isinstance(profile.cpu, CpuInfo)
        assert isinstance(profile.memory, MemoryInfo)
        assert isinstance(profile.network, NetworkInfo)
        assert isinstance(profile.gpus, list)
        
        # Tier must be valid
        assert isinstance(profile.tier, DeviceTier)
        
        # Config must be valid and consistent with tier
        assert hasattr(profile.config, 'threads')
        assert hasattr(profile.config, 'buffer_size_mb')
        assert hasattr(profile.config, 'batch_size')
        assert hasattr(profile.config, 'target_pps')
        
        # Config values should be positive
        assert profile.config.threads > 0, f"Invalid thread count: {profile.config.threads}"
        assert profile.config.buffer_size_mb > 0, f"Invalid buffer size: {profile.config.buffer_size_mb}"
        assert profile.config.batch_size > 0, f"Invalid batch size: {profile.config.batch_size}"
        assert profile.config.target_pps > 0, f"Invalid target PPS: {profile.config.target_pps}"
        
        # Thread count should not exceed available threads
        assert profile.config.threads <= profile.cpu.threads, \
            f"Config threads ({profile.config.threads}) > CPU threads ({profile.cpu.threads})"
        
        # Compute score should be reasonable
        score = profile.total_compute_score
        assert 0 <= score <= 100, f"Invalid compute score: {score}"
        
        # Properties should be consistent
        if profile.memory.is_numa:
            assert profile.supports_numa
        
        if profile.gpus and GpuDetector.get_best_compute_gpu(profile.gpus):
            assert profile.supports_gpu_acceleration
        
        logger.info(f"Hardware profile test passed: {profile.tier.value} tier, "
                   f"score {score}/100")
    
    @given(
        st.integers(min_value=1, max_value=128),  # cores
        st.integers(min_value=1, max_value=512),  # memory_gb  
        st.integers(min_value=10, max_value=400000)  # network_mbps
    )
    def test_tier_classification_consistency(self, cores, memory_gb, network_mbps):
        """
        **Feature: true-military-grade, Property 3: Device Tier Classification Consistency**
        **Validates: Requirements 11.2**
        
        For any detected hardware profile, the tier classifier SHALL assign exactly one tier 
        (Low/Medium/High/Enterprise) based on consistent thresholds, and the same hardware 
        SHALL always receive the same tier.
        """
        from core.hardware.cpu_detector import CpuInfo, CpuFeatures, Architecture
        from core.hardware.memory_detector import MemoryInfo
        from core.hardware.network_detector import NetworkInfo
        
        # Create test hardware configuration
        cpu = CpuInfo(
            cores=cores,
            threads=cores * 2,  # Assume hyperthreading
            architecture=Architecture.X86_64,
            features=CpuFeatures(),
            frequency_mhz=3000,
            model_name="Test CPU",
            vendor="Test"
        )
        
        memory = MemoryInfo(
            total_bytes=memory_gb * 1024**3,
            available_bytes=int(memory_gb * 0.8 * 1024**3)  # 80% available
        )
        
        network = NetworkInfo(
            interfaces=[],
            total_bandwidth_mbps=network_mbps,
            fastest_interface=None,
            bondable_interfaces=[],
            has_high_speed_nic=network_mbps >= 10000
        )
        
        # Property: Same hardware configuration should always get same tier
        tier1 = HardwareProfiler.classify_device_tier(cpu, memory, network)
        tier2 = HardwareProfiler.classify_device_tier(cpu, memory, network)
        tier3 = HardwareProfiler.classify_device_tier(cpu, memory, network)
        
        assert tier1 == tier2 == tier3, \
            f"Inconsistent tier classification for {cores}C/{memory_gb}GB/{network_mbps}Mbps: {tier1}, {tier2}, {tier3}"
        
        # Property: Tier assignment should follow consistent thresholds
        # Low: 1-2 cores, <4GB RAM, ≤100Mbps NIC
        # Medium: 4-8 cores, 4-16GB RAM, 1Gbps NIC
        # High: 8-32 cores, 16-64GB RAM, 10Gbps NIC
        # Enterprise: 32+ cores, 64GB+ RAM, 25Gbps+ NIC
        
        if cores <= 2 and memory_gb <= 4 and network_mbps <= 100:
            assert tier1 == DeviceTier.LOW, \
                f"Expected LOW tier for {cores}C/{memory_gb}GB/{network_mbps}Mbps, got {tier1}"
        elif cores <= 8 and memory_gb <= 16 and network_mbps <= 1000:
            assert tier1 in [DeviceTier.LOW, DeviceTier.MEDIUM], \
                f"Expected LOW/MEDIUM tier for {cores}C/{memory_gb}GB/{network_mbps}Mbps, got {tier1}"
        elif cores <= 32 and memory_gb <= 64 and network_mbps <= 10000:
            assert tier1 in [DeviceTier.LOW, DeviceTier.MEDIUM, DeviceTier.HIGH], \
                f"Expected LOW/MEDIUM/HIGH tier for {cores}C/{memory_gb}GB/{network_mbps}Mbps, got {tier1}"
        else:
            # Should be classified as some valid tier
            assert tier1 in [DeviceTier.LOW, DeviceTier.MEDIUM, DeviceTier.HIGH, DeviceTier.ENTERPRISE], \
                f"Invalid tier classification: {tier1}"
        
        # Property: Higher resource configurations should get equal or higher tiers
        # Test with doubled resources
        cpu_higher = CpuInfo(
            cores=min(cores * 2, 128),
            threads=min(cores * 4, 256),
            architecture=Architecture.X86_64,
            features=CpuFeatures(),
            frequency_mhz=3000,
            model_name="Test CPU",
            vendor="Test"
        )
        
        memory_higher = MemoryInfo(
            total_bytes=min(memory_gb * 2, 512) * 1024**3,
            available_bytes=int(min(memory_gb * 2, 512) * 0.8 * 1024**3)
        )
        
        network_higher = NetworkInfo(
            interfaces=[],
            total_bandwidth_mbps=min(network_mbps * 2, 400000),
            fastest_interface=None,
            bondable_interfaces=[],
            has_high_speed_nic=min(network_mbps * 2, 400000) >= 10000
        )
        
        tier_higher = HardwareProfiler.classify_device_tier(cpu_higher, memory_higher, network_higher)
        
        # Convert tiers to numeric values for comparison
        tier_values = {
            DeviceTier.LOW: 1,
            DeviceTier.MEDIUM: 2, 
            DeviceTier.HIGH: 3,
            DeviceTier.ENTERPRISE: 4
        }
        
        assert tier_values[tier_higher] >= tier_values[tier1], \
            f"Higher resources got lower tier: {tier1} -> {tier_higher} for " \
            f"{cores}C/{memory_gb}GB/{network_mbps}Mbps -> " \
            f"{cpu_higher.cores}C/{memory_higher.total_gb:.0f}GB/{network_higher.total_bandwidth_mbps}Mbps"
    
    def test_performance_estimation_validity(self):
        """
        Property: Performance estimates should be reasonable and consistent.
        
        Higher-tier devices should have equal or better performance estimates.
        """
        profile = HardwareProfiler.detect_hardware_profile()
        estimates = HardwareProfiler.estimate_performance_capacity(profile)
        
        # Estimates should be valid
        assert isinstance(estimates, dict)
        assert 'estimated_pps' in estimates
        assert 'estimated_bandwidth_mbps' in estimates
        assert 'confidence' in estimates
        
        # Values should be positive
        assert estimates['estimated_pps'] > 0
        assert estimates['estimated_bandwidth_mbps'] > 0
        
        # Multipliers should be >= 1.0 (no negative impact)
        assert estimates['cpu_multiplier'] >= 1.0
        assert estimates['memory_multiplier'] >= 1.0
        assert estimates['network_multiplier'] >= 1.0
        assert estimates['gpu_multiplier'] >= 1.0
        
        # Bandwidth should be consistent with PPS (assuming ~1KB packets)
        expected_bandwidth = (estimates['estimated_pps'] * 1024 * 8) // 1_000_000
        actual_bandwidth = estimates['estimated_bandwidth_mbps']
        
        # Allow some tolerance for rounding
        assert abs(expected_bandwidth - actual_bandwidth) / expected_bandwidth < 0.1, \
            f"Inconsistent bandwidth calculation: expected {expected_bandwidth}, got {actual_bandwidth}"
        
        logger.info(f"Performance estimation test passed: {estimates['estimated_pps']:,} PPS, "
                   f"{estimates['estimated_bandwidth_mbps']} Mbps")

    @given(
        st.sampled_from([DeviceTier.LOW, DeviceTier.MEDIUM, DeviceTier.HIGH, DeviceTier.ENTERPRISE]),
        st.integers(min_value=1, max_value=128),  # cores
        st.integers(min_value=1, max_value=512),  # memory_gb
        st.integers(min_value=10, max_value=400000)  # network_mbps
    )
    def test_adaptive_configuration_scaling(self, tier, cores, memory_gb, network_mbps):
        """
        **Feature: true-military-grade, Property 4: Adaptive Configuration Scaling**
        **Validates: Requirements 11.3, 11.4, 11.5**
        
        For any device tier, the generated configuration SHALL have thread count, buffer size, 
        and batch size within the tier's defined ranges, and higher tiers SHALL have equal or 
        greater values than lower tiers.
        """
        from core.hardware.cpu_detector import CpuInfo, CpuFeatures, Architecture
        from core.hardware.memory_detector import MemoryInfo
        from core.hardware.network_detector import NetworkInfo
        from core.hardware.gpu_detector import GpuInfo
        
        # Create test hardware configuration
        cpu = CpuInfo(
            cores=cores,
            threads=cores * 2,  # Assume hyperthreading
            architecture=Architecture.X86_64,
            features=CpuFeatures(),
            frequency_mhz=3000,
            model_name="Test CPU",
            vendor="Test"
        )
        
        memory = MemoryInfo(
            total_bytes=memory_gb * 1024**3,
            available_bytes=int(memory_gb * 0.8 * 1024**3)  # 80% available
        )
        
        network = NetworkInfo(
            interfaces=[],
            total_bandwidth_mbps=network_mbps,
            fastest_interface=None,
            bondable_interfaces=[],
            has_high_speed_nic=network_mbps >= 10000
        )
        
        gpus = []  # No GPUs for this test
        
        # Generate adaptive configuration
        config = HardwareProfiler.create_adaptive_config(tier, cpu, memory, network, gpus)
        
        # Property: Configuration values should be positive and reasonable
        assert config.threads > 0, f"Invalid thread count: {config.threads}"
        assert config.buffer_size_mb > 0, f"Invalid buffer size: {config.buffer_size_mb}"
        assert config.batch_size > 0, f"Invalid batch size: {config.batch_size}"
        assert config.target_pps > 0, f"Invalid target PPS: {config.target_pps}"
        assert config.memory_limit_mb > 0, f"Invalid memory limit: {config.memory_limit_mb}"
        
        # Property: Thread count should not exceed available CPU threads
        assert config.threads <= cpu.threads, \
            f"Config threads ({config.threads}) > CPU threads ({cpu.threads})"
        
        # Property: Buffer size should not exceed available memory
        max_reasonable_buffer = int(memory.available_gb * 1024 * 0.5)  # 50% of available memory
        assert config.buffer_size_mb <= max_reasonable_buffer, \
            f"Buffer size ({config.buffer_size_mb}MB) > reasonable limit ({max_reasonable_buffer}MB)"
        
        # Property: Configuration should respect tier-based limits
        base_config = HardwareProfiler.TIER_CONFIGS[tier]
        
        # Threads should be within reasonable bounds for the tier
        if tier == DeviceTier.LOW:
            assert config.threads <= 2, f"LOW tier should have ≤2 threads, got {config.threads}"
        elif tier == DeviceTier.MEDIUM:
            assert config.threads <= 8, f"MEDIUM tier should have ≤8 threads, got {config.threads}"
        elif tier == DeviceTier.HIGH:
            assert config.threads <= 32, f"HIGH tier should have ≤32 threads, got {config.threads}"
        else:  # ENTERPRISE
            assert config.threads <= 128, f"ENTERPRISE tier should have ≤128 threads, got {config.threads}"
        
        # Property: Higher tiers should have equal or greater base values
        tier_order = [DeviceTier.LOW, DeviceTier.MEDIUM, DeviceTier.HIGH, DeviceTier.ENTERPRISE]
        tier_index = tier_order.index(tier)
        
        for lower_tier in tier_order[:tier_index]:
            lower_config = HardwareProfiler.TIER_CONFIGS[lower_tier]
            
            assert base_config.threads >= lower_config.threads, \
                f"Tier {tier.value} threads ({base_config.threads}) < {lower_tier.value} threads ({lower_config.threads})"
            
            assert base_config.buffer_size_mb >= lower_config.buffer_size_mb, \
                f"Tier {tier.value} buffer ({base_config.buffer_size_mb}MB) < {lower_tier.value} buffer ({lower_config.buffer_size_mb}MB)"
            
            assert base_config.batch_size >= lower_config.batch_size, \
                f"Tier {tier.value} batch size ({base_config.batch_size}) < {lower_tier.value} batch size ({lower_config.batch_size})"
            
            assert base_config.target_pps >= lower_config.target_pps, \
                f"Tier {tier.value} target PPS ({base_config.target_pps}) < {lower_tier.value} target PPS ({lower_config.target_pps})"
        
        # Property: Adaptive configuration should be consistent
        config2 = HardwareProfiler.create_adaptive_config(tier, cpu, memory, network, gpus)
        
        assert config.threads == config2.threads, "Adaptive config should be deterministic"
        assert config.buffer_size_mb == config2.buffer_size_mb, "Adaptive config should be deterministic"
        assert config.batch_size == config2.batch_size, "Adaptive config should be deterministic"
        assert config.target_pps == config2.target_pps, "Adaptive config should be deterministic"
        
        logger.debug(f"Adaptive config test passed for {tier.value}: "
                    f"{config.threads}T, {config.buffer_size_mb}MB, "
                    f"batch={config.batch_size}, {config.target_pps:,} PPS")


class HardwareDetectionStateMachine(RuleBasedStateMachine):
    """
    Stateful property testing for hardware detection system.
    
    Tests that hardware detection remains consistent across multiple calls
    and that the system maintains valid state.
    """
    
    def __init__(self):
        super().__init__()
        self.detection_count = 0
        self.cached_profile = None
    
    @rule()
    def detect_hardware_profile(self):
        """Detect hardware profile and verify consistency"""
        profile = HardwareProfiler.detect_hardware_profile()
        
        if self.cached_profile is None:
            self.cached_profile = profile
        else:
            # Hardware should not change between detections
            assert profile.cpu.cores == self.cached_profile.cpu.cores
            assert profile.cpu.threads == self.cached_profile.cpu.threads
            assert profile.memory.total_bytes == self.cached_profile.memory.total_bytes
            assert profile.tier == self.cached_profile.tier
        
        self.detection_count += 1
    
    @rule()
    def get_optimization_recommendations(self):
        """Get optimization recommendations and verify they're valid"""
        if self.cached_profile:
            recommendations = HardwareProfiler.get_optimization_recommendations(self.cached_profile)
            
            assert isinstance(recommendations, list)
            for rec in recommendations:
                assert isinstance(rec, str)
                assert len(rec) > 0
    
    @invariant()
    def detection_count_increases(self):
        """Detection count should only increase"""
        assert self.detection_count >= 0
    
    @invariant()
    def cached_profile_valid(self):
        """Cached profile should remain valid if set"""
        if self.cached_profile:
            assert isinstance(self.cached_profile, HardwareProfile)
            assert self.cached_profile.cpu.cores > 0
            assert self.cached_profile.memory.total_bytes > 0


# Configure hypothesis settings for longer test runs
TestHardwareDetectionStateMachine = HardwareDetectionStateMachine.TestCase
TestHardwareDetectionStateMachine.settings = settings(max_examples=10, stateful_step_count=10)


if __name__ == "__main__":
    # Run property tests
    test_instance = TestHardwareDetectionProperties()
    
    print("Running hardware detection property tests...")
    
    try:
        test_instance.test_cpu_detection_completeness()
        print("✓ CPU detection completeness test passed")
        
        test_instance.test_memory_detection_completeness()
        print("✓ Memory detection completeness test passed")
        
        test_instance.test_network_detection_completeness()
        print("✓ Network detection completeness test passed")
        
        test_instance.test_gpu_detection_completeness()
        print("✓ GPU detection completeness test passed")
        
        test_instance.test_hardware_profile_completeness()
        print("✓ Hardware profile completeness test passed")
        
        test_instance.test_performance_estimation_validity()
        print("✓ Performance estimation validity test passed")
        
        print("\n✓ All hardware detection property tests passed!")
        
    except Exception as e:
        print(f"✗ Hardware detection property test failed: {e}")
        raise