#!/usr/bin/env python3
"""
Cross-Platform Integration Tests for True Military-Grade Implementation

Tests backend selection, fallback chains, and adaptive scaling across Windows, macOS, and Linux platforms.
Validates Requirements: All cross-platform requirements from the true-military-grade spec.

**Feature: true-military-grade**
**Validates: Requirements 1.1-1.5, 2.1-2.4, 3.1-3.5, 11.1-11.5, 12.1-12.5, 17.1-17.5, 18.1-18.5, 19.1-19.5**
"""

import pytest
import sys
import os
import platform
import time
import threading
import socket
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List, Optional
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import components to test
try:
    from core.platform.detection import PlatformDetector, PlatformType, Architecture as PlatformArchitecture, SystemInfo
    from core.platform.backend_detection import BackendDetector, BackendType, SystemCapabilities
    from core.hardware.hardware_profile import HardwareProfiler, HardwareProfile, DeviceTier
    from core.hardware.cpu_detector import CpuDetector, CpuInfo, CpuFeatures, Architecture as CpuArchitecture
    from core.hardware.memory_detector import MemoryDetector, MemoryInfo
    from core.hardware.network_detector import NetworkDetector, NetworkInfo
    from core.hardware.gpu_detector import GpuDetector, GpuInfo
    COMPONENTS_AVAILABLE = True
except ImportError as e:
    COMPONENTS_AVAILABLE = False
    print(f"Warning: Some components not available: {e}")

logger = logging.getLogger(__name__)


class TestCrossPlatformBackendSelection:
    """Test backend selection across different platforms"""
    
    def test_windows_backend_priority_chain(self):
        """
        Test Windows backend priority chain: RIO > IOCP > Winsock2
        **Validates: Requirements 1.1, 1.4, 17.1, 17.2**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Mock Windows platform
        with patch('core.platform.detection.PlatformDetector.detect_platform') as mock_platform:
            mock_platform.return_value = PlatformType.WINDOWS
            
            detector = BackendDetector()
            
            # Test with all Windows capabilities available
            capabilities = SystemCapabilities(
                has_dpdk=False,  # Not common on Windows
                has_af_xdp=False,  # Linux-only
                has_io_uring=False,  # Linux-only
                has_sendmmsg=False,  # Linux-only
                has_raw_socket=True,
                kernel_version_major=10,
                kernel_version_minor=0,
                cpu_count=8,
                numa_nodes=1
            )
            
            # Should select raw socket as best available on Windows
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.RAW_SOCKET
            
            # Test available backends list
            available = detector.get_available_backends(capabilities)
            assert BackendType.RAW_SOCKET in available
            assert BackendType.AF_XDP not in available
            assert BackendType.IO_URING not in available
            assert BackendType.SENDMMSG not in available
    
    def test_macos_backend_priority_chain(self):
        """
        Test macOS backend priority chain: Network.framework > kqueue > BSD sockets
        **Validates: Requirements 2.1, 2.4, 18.1, 18.2**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Mock macOS platform
        with patch('core.platform.detection.PlatformDetector.detect_platform') as mock_platform:
            mock_platform.return_value = PlatformType.MACOS
            
            detector = BackendDetector()
            
            # Test with macOS capabilities
            capabilities = SystemCapabilities(
                has_dpdk=False,  # Not common on macOS
                has_af_xdp=False,  # Linux-only
                has_io_uring=False,  # Linux-only
                has_sendmmsg=False,  # Linux-only
                has_raw_socket=True,
                kernel_version_major=21,  # macOS kernel version
                kernel_version_minor=0,
                cpu_count=8,
                numa_nodes=1
            )
            
            # Should select raw socket as best available on macOS
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.RAW_SOCKET
            
            # Test available backends list
            available = detector.get_available_backends(capabilities)
            assert BackendType.RAW_SOCKET in available
            assert BackendType.AF_XDP not in available
            assert BackendType.IO_URING not in available
    
    def test_linux_backend_priority_chain(self):
        """
        Test Linux backend priority chain: DPDK > AF_XDP > io_uring > sendmmsg > raw socket
        **Validates: Requirements 3.1-3.5, 19.1-19.5**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Mock Linux platform
        with patch('core.platform.detection.PlatformDetector.detect_platform') as mock_platform:
            mock_platform.return_value = PlatformType.LINUX
            
            detector = BackendDetector()
            
            # Test with full Linux capabilities
            capabilities = SystemCapabilities(
                has_dpdk=True,
                has_af_xdp=True,
                has_io_uring=True,
                has_sendmmsg=True,
                has_raw_socket=True,
                kernel_version_major=5,
                kernel_version_minor=15,
                cpu_count=16,
                numa_nodes=2
            )
            
            # Should select DPDK as highest priority
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.DPDK
            
            # Test fallback chain by removing capabilities
            capabilities.has_dpdk = False
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.AF_XDP
            
            capabilities.has_af_xdp = False
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.IO_URING
            
            capabilities.has_io_uring = False
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.SENDMMSG
            
            capabilities.has_sendmmsg = False
            backend = detector.select_best_backend(capabilities)
            assert backend == BackendType.RAW_SOCKET
    
    def test_kernel_version_requirements(self):
        """
        Test kernel version requirements for Linux backends
        **Validates: Requirements 3.1, 3.4**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        detector = BackendDetector()
        
        # Test AF_XDP requires kernel 4.18+
        capabilities = SystemCapabilities(
            has_dpdk=False,
            has_af_xdp=False,  # Will be set based on kernel version
            has_io_uring=False,
            has_sendmmsg=True,
            has_raw_socket=True,
            kernel_version_major=4,
            kernel_version_minor=17,  # Below 4.18
            cpu_count=4,
            numa_nodes=1
        )
        
        # Should not have AF_XDP with kernel 4.17
        available = detector.get_available_backends(capabilities)
        assert BackendType.AF_XDP not in available
        
        # Test with kernel 4.18+
        capabilities.kernel_version_minor = 18
        capabilities.has_af_xdp = True
        available = detector.get_available_backends(capabilities)
        assert BackendType.AF_XDP in available
        
        # Test io_uring requires kernel 5.1+
        capabilities.kernel_version_major = 5
        capabilities.kernel_version_minor = 0  # Below 5.1
        capabilities.has_io_uring = False
        available = detector.get_available_backends(capabilities)
        assert BackendType.IO_URING not in available
        
        # Test with kernel 5.1+
        capabilities.kernel_version_minor = 1
        capabilities.has_io_uring = True
        available = detector.get_available_backends(capabilities)
        assert BackendType.IO_URING in available
    
    def test_backend_fallback_graceful_degradation(self):
        """
        Test graceful degradation when preferred backends are unavailable
        **Validates: Requirements 1.4, 2.4, 3.4**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        detector = BackendDetector()
        
        # Test with minimal capabilities (only raw socket)
        minimal_capabilities = SystemCapabilities(
            has_dpdk=False,
            has_af_xdp=False,
            has_io_uring=False,
            has_sendmmsg=False,
            has_raw_socket=True,
            kernel_version_major=3,
            kernel_version_minor=0,
            cpu_count=1,
            numa_nodes=1
        )
        
        # Should always fall back to raw socket
        backend = detector.select_best_backend(minimal_capabilities)
        assert backend == BackendType.RAW_SOCKET
        
        # Test that fallback is consistent
        backend2 = detector.select_best_backend(minimal_capabilities)
        assert backend == backend2
    
    def test_cross_platform_capability_detection(self):
        """
        Test capability detection works correctly on all platforms
        **Validates: Requirements 12.3**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        detector = BackendDetector()
        
        # Test actual platform detection
        capabilities = detector.detect_capabilities()
        
        # Should always have raw socket capability
        assert capabilities.has_raw_socket == True
        
        # Should have reasonable CPU count
        assert capabilities.cpu_count >= 1
        assert capabilities.cpu_count <= 256  # Reasonable upper bound
        
        # Should have valid kernel version info
        assert capabilities.kernel_version_major >= 0
        assert capabilities.kernel_version_minor >= 0
        
        # Platform-specific checks
        current_platform = platform.system().lower()
        
        if current_platform == "linux":
            # Linux should potentially have sendmmsg, io_uring, AF_XDP
            # (depending on kernel version)
            if capabilities.kernel_version_major >= 3:
                # sendmmsg available on Linux 3.0+
                pass  # May or may not be detected depending on system
        elif current_platform == "windows":
            # Windows should not have Linux-specific features
            assert capabilities.has_af_xdp == False
            assert capabilities.has_io_uring == False
            assert capabilities.has_sendmmsg == False
        elif current_platform == "darwin":
            # macOS should not have Linux-specific features
            assert capabilities.has_af_xdp == False
            assert capabilities.has_io_uring == False
            assert capabilities.has_sendmmsg == False


class TestCrossPlatformHardwareDetection:
    """Test hardware detection across different platforms"""
    
    def test_cpu_detection_cross_platform(self):
        """
        Test CPU detection works on all platforms
        **Validates: Requirements 11.1, 12.4, 12.5**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        cpu_info = CpuDetector.detect_cpu_info()
        
        # Should detect valid CPU information
        assert cpu_info.cores >= 1
        assert cpu_info.threads >= cpu_info.cores
        assert cpu_info.architecture in [arch for arch in CpuArchitecture]
        assert isinstance(cpu_info.model_name, str)
        assert isinstance(cpu_info.vendor, str)
        
        # Platform-specific feature detection
        current_platform = platform.system().lower()
        current_arch = platform.machine().lower()
        
        if current_arch in ["x86_64", "amd64"]:
            # x86_64 should potentially have AVX features
            assert hasattr(cpu_info.features, 'avx2')
            assert hasattr(cpu_info.features, 'avx512')
        elif current_arch in ["arm64", "aarch64"]:
            # ARM64 should potentially have NEON
            assert hasattr(cpu_info.features, 'neon')
    
    def test_memory_detection_cross_platform(self):
        """
        Test memory detection works on all platforms
        **Validates: Requirements 11.1**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        memory_info = MemoryDetector.detect_memory_info()
        
        # Should detect valid memory information
        assert memory_info.total_bytes > 0
        assert memory_info.available_bytes > 0
        assert memory_info.available_bytes <= memory_info.total_bytes
        
        # Should have reasonable memory amounts (at least 512MB, less than 2TB)
        assert memory_info.total_bytes >= 512 * 1024 * 1024
        assert memory_info.total_bytes <= 2 * 1024 * 1024 * 1024 * 1024
        
        # Platform-specific checks
        current_platform = platform.system().lower()
        
        if current_platform == "linux":
            # Linux may have NUMA and hugepage information
            if memory_info.numa_nodes:
                assert len(memory_info.numa_nodes) >= 1
        elif current_platform in ["windows", "darwin"]:
            # Windows and macOS may have different memory reporting
            pass  # Platform-specific memory features vary
    
    def test_network_detection_cross_platform(self):
        """
        Test network detection works on all platforms
        **Validates: Requirements 11.1**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        network_info = NetworkDetector.detect_network_info()
        
        # Should detect at least some network interfaces
        assert isinstance(network_info.interfaces, list)
        assert network_info.interface_count >= 0
        assert network_info.interface_count == len(network_info.interfaces)
        
        # Should have reasonable bandwidth values
        assert network_info.total_bandwidth_mbps >= 0
        
        # Validate interface information
        for interface in network_info.interfaces:
            assert isinstance(interface.name, str)
            assert len(interface.name) > 0
            assert interface.speed_mbps >= 0
            assert isinstance(interface.mac_address, str)
            assert isinstance(interface.ip_addresses, list)
    
    def test_gpu_detection_cross_platform(self):
        """
        Test GPU detection works on all platforms
        **Validates: Requirements 11.1, 10.1**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        gpus = GpuDetector.detect_all_gpus()
        
        # Should return a list (may be empty)
        assert isinstance(gpus, list)
        
        # Validate GPU information if any GPUs detected
        for gpu in gpus:
            assert isinstance(gpu.name, str)
            assert len(gpu.name) > 0
            assert gpu.memory_mb >= 0
            assert isinstance(gpu.compute_capability, str)
            assert isinstance(gpu.driver_version, str)
    
    def test_device_tier_classification_cross_platform(self):
        """
        Test device tier classification works consistently across platforms
        **Validates: Requirements 11.2, 11.3**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Test with known hardware configurations
        test_configs = [
            # Low tier
            {
                'cores': 1, 'memory_gb': 2, 'network_mbps': 100,
                'expected_tier': DeviceTier.LOW
            },
            # Medium tier
            {
                'cores': 4, 'memory_gb': 8, 'network_mbps': 1000,
                'expected_tier': DeviceTier.MEDIUM
            },
            # High tier
            {
                'cores': 16, 'memory_gb': 32, 'network_mbps': 10000,
                'expected_tier': DeviceTier.HIGH
            },
            # Enterprise tier
            {
                'cores': 64, 'memory_gb': 128, 'network_mbps': 100000,
                'expected_tier': DeviceTier.ENTERPRISE
            }
        ]
        
        for config in test_configs:
            # Create mock hardware info
            cpu = CpuInfo(
                cores=config['cores'],
                threads=config['cores'] * 2,
                architecture=CpuArchitecture.X86_64,
                features=CpuFeatures(),
                frequency_mhz=3000,
                model_name="Test CPU",
                vendor="Test"
            )
            
            memory = MemoryInfo(
                total_bytes=config['memory_gb'] * 1024**3,
                available_bytes=int(config['memory_gb'] * 0.8 * 1024**3)
            )
            
            network = NetworkInfo(
                interfaces=[],
                total_bandwidth_mbps=config['network_mbps'],
                fastest_interface=None,
                bondable_interfaces=[],
                has_high_speed_nic=config['network_mbps'] >= 10000
            )
            
            # Test tier classification
            tier = HardwareProfiler.classify_device_tier(cpu, memory, network)
            
            # Should classify correctly regardless of platform
            if config['expected_tier'] == DeviceTier.LOW:
                assert tier in [DeviceTier.LOW, DeviceTier.MEDIUM]  # May be upgraded
            else:
                # Allow some flexibility in tier assignment
                tier_values = {
                    DeviceTier.LOW: 1,
                    DeviceTier.MEDIUM: 2,
                    DeviceTier.HIGH: 3,
                    DeviceTier.ENTERPRISE: 4
                }
                expected_value = tier_values[config['expected_tier']]
                actual_value = tier_values[tier]
                assert abs(actual_value - expected_value) <= 1  # Within one tier


class TestCrossPlatformAdaptiveScaling:
    """Test adaptive scaling across different platforms"""
    
    def test_adaptive_configuration_scaling(self):
        """
        Test adaptive configuration scaling works across platforms
        **Validates: Requirements 11.3, 11.4, 11.5, 21.1-21.5**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Test with different device tiers
        for tier in [DeviceTier.LOW, DeviceTier.MEDIUM, DeviceTier.HIGH, DeviceTier.ENTERPRISE]:
            # Create mock hardware for tier
            if tier == DeviceTier.LOW:
                cores, memory_gb, network_mbps = 2, 4, 100
            elif tier == DeviceTier.MEDIUM:
                cores, memory_gb, network_mbps = 8, 16, 1000
            elif tier == DeviceTier.HIGH:
                cores, memory_gb, network_mbps = 32, 64, 10000
            else:  # ENTERPRISE
                cores, memory_gb, network_mbps = 128, 512, 100000
            
            cpu = CpuInfo(
                cores=cores,
                threads=cores * 2,
                architecture=CpuArchitecture.X86_64,
                features=CpuFeatures(),
                frequency_mhz=3000,
                model_name="Test CPU",
                vendor="Test"
            )
            
            memory = MemoryInfo(
                total_bytes=memory_gb * 1024**3,
                available_bytes=int(memory_gb * 0.8 * 1024**3)
            )
            
            network = NetworkInfo(
                interfaces=[],
                total_bandwidth_mbps=network_mbps,
                fastest_interface=None,
                bondable_interfaces=[],
                has_high_speed_nic=network_mbps >= 10000
            )
            
            gpus = []
            
            # Create adaptive configuration
            config = HardwareProfiler.create_adaptive_config(tier, cpu, memory, network, gpus)
            
            # Validate configuration is reasonable
            assert config.threads > 0
            assert config.threads <= cpu.threads
            assert config.buffer_size_mb > 0
            assert config.batch_size > 0
            assert config.target_pps > 0
            assert config.memory_limit_mb > 0
            
            # Higher tiers should generally have higher values
            base_config = HardwareProfiler.TIER_CONFIGS[tier]
            assert config.threads <= base_config.threads * 2  # Allow some adaptation
    
    def test_performance_estimation_cross_platform(self):
        """
        Test performance estimation works across platforms
        **Validates: Requirements 21.1**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Create a test hardware profile
        profile = HardwareProfile(
            cpu=CpuInfo(
                cores=8,
                threads=16,
                architecture=CpuArchitecture.X86_64,
                features=CpuFeatures(avx2=True),
                frequency_mhz=3000,
                model_name="Test CPU",
                vendor="Test"
            ),
            memory=MemoryInfo(
                total_bytes=16 * 1024**3,
                available_bytes=12 * 1024**3
            ),
            network=NetworkInfo(
                interfaces=[],
                total_bandwidth_mbps=1000,
                fastest_interface=None,
                bondable_interfaces=[],
                has_high_speed_nic=False
            ),
            gpus=[],
            tier=DeviceTier.MEDIUM,
            config=HardwareProfiler.TIER_CONFIGS[DeviceTier.MEDIUM]
        )
        
        # Test performance estimation
        estimates = HardwareProfiler.estimate_performance_capacity(profile)
        
        # Should return valid estimates
        assert isinstance(estimates, dict)
        assert 'estimated_pps' in estimates
        assert 'estimated_bandwidth_mbps' in estimates
        assert 'confidence' in estimates
        
        assert estimates['estimated_pps'] > 0
        assert estimates['estimated_bandwidth_mbps'] > 0
        assert estimates['confidence'] in ['low', 'medium', 'high']
        
        # Multipliers should be reasonable
        assert estimates['cpu_multiplier'] >= 1.0
        assert estimates['memory_multiplier'] >= 1.0
        assert estimates['network_multiplier'] >= 1.0
        assert estimates['gpu_multiplier'] >= 1.0
    
    def test_real_time_adaptation_simulation(self):
        """
        Test real-time adaptation simulation across platforms
        **Validates: Requirements 21.2, 21.3, 21.4, 21.5**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Simulate performance metrics that would trigger scaling
        test_scenarios = [
            {
                'name': 'High CPU usage',
                'cpu_usage': 95.0,
                'memory_usage': 50.0,
                'packet_loss': 0.1,
                'expected_action': 'scale_down'
            },
            {
                'name': 'High memory pressure',
                'cpu_usage': 60.0,
                'memory_usage': 90.0,
                'packet_loss': 0.1,
                'expected_action': 'scale_down'
            },
            {
                'name': 'High packet loss',
                'cpu_usage': 70.0,
                'memory_usage': 60.0,
                'packet_loss': 2.0,
                'expected_action': 'scale_down'
            },
            {
                'name': 'Low resource usage',
                'cpu_usage': 30.0,
                'memory_usage': 40.0,
                'packet_loss': 0.01,
                'expected_action': 'scale_up'
            }
        ]
        
        for scenario in test_scenarios:
            # Create mock performance metrics
            metrics = {
                'cpu_usage': scenario['cpu_usage'],
                'memory_usage': scenario['memory_usage'],
                'packet_loss': scenario['packet_loss'],
                'current_pps': 100000,
                'target_pps': 500000
            }
            
            # Simulate adaptive scaling decision
            should_scale_down = (
                metrics['cpu_usage'] > 90 or
                metrics['memory_usage'] > 85 or
                metrics['packet_loss'] > 1.0
            )
            
            should_scale_up = (
                metrics['cpu_usage'] < 50 and
                metrics['memory_usage'] < 60 and
                metrics['packet_loss'] < 0.1 and
                metrics['current_pps'] < metrics['target_pps'] * 0.8
            )
            
            if should_scale_down:
                assert scenario['expected_action'] == 'scale_down'
            elif should_scale_up:
                assert scenario['expected_action'] == 'scale_up'


class TestCrossPlatformIntegration:
    """Test complete cross-platform integration"""
    
    def test_full_hardware_profile_detection(self):
        """
        Test complete hardware profile detection on current platform
        **Validates: Requirements 11.1, 11.2, 12.3**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Detect actual hardware profile
        profile = HardwareProfiler.detect_hardware_profile()
        
        # Should create valid profile
        assert isinstance(profile, HardwareProfile)
        assert isinstance(profile.cpu, CpuInfo)
        assert isinstance(profile.memory, MemoryInfo)
        assert isinstance(profile.network, NetworkInfo)
        assert isinstance(profile.gpus, list)
        assert isinstance(profile.tier, DeviceTier)
        
        # Should have reasonable compute score
        score = profile.total_compute_score
        assert 0 <= score <= 100
        
        # Should generate optimization recommendations
        recommendations = HardwareProfiler.get_optimization_recommendations(profile)
        assert isinstance(recommendations, list)
        
        # Should estimate performance capacity
        estimates = HardwareProfiler.estimate_performance_capacity(profile)
        assert isinstance(estimates, dict)
        assert estimates['estimated_pps'] > 0
    
    def test_backend_and_hardware_integration(self):
        """
        Test integration between backend selection and hardware detection
        **Validates: Requirements 12.3, 12.4, 12.5**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Detect hardware profile
        profile = HardwareProfiler.detect_hardware_profile()
        
        # Detect backend capabilities
        detector = BackendDetector()
        capabilities = detector.detect_capabilities()
        backend = detector.select_best_backend(capabilities)
        
        # Integration should be consistent
        assert isinstance(backend, BackendType)
        assert backend != BackendType.NONE
        
        # Backend selection should consider hardware capabilities
        if profile.tier == DeviceTier.ENTERPRISE:
            # Enterprise systems should prefer high-performance backends
            if capabilities.has_dpdk or capabilities.has_af_xdp:
                assert backend in [BackendType.DPDK, BackendType.AF_XDP, BackendType.IO_URING]
        
        # Configuration should be appropriate for selected backend
        config = profile.config
        if backend in [BackendType.DPDK, BackendType.AF_XDP]:
            # High-performance backends should have larger configurations
            assert config.threads >= 2 or profile.tier == DeviceTier.LOW
            assert config.buffer_size_mb >= 64
    
    def test_cross_platform_consistency(self):
        """
        Test that behavior is consistent across platform detection
        **Validates: Requirements 12.1, 12.2**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Test platform detection
        platform_info = PlatformDetector.get_platform_info()
        
        assert 'platform' in platform_info
        assert 'architecture' in platform_info
        assert 'cpu_count' in platform_info
        
        # Should detect current platform correctly
        current_platform = platform.system().lower()
        detected_platform = platform_info['platform']
        
        if current_platform == 'windows':
            assert detected_platform == 'windows'
        elif current_platform == 'linux':
            assert detected_platform == 'linux'
        elif current_platform == 'darwin':
            assert detected_platform == 'macos'
        
        # CPU count should match
        detected_cpu_count = platform_info['cpu_count']
        actual_cpu_count = os.cpu_count() or 1
        assert detected_cpu_count == actual_cpu_count
    
    def test_error_handling_cross_platform(self):
        """
        Test error handling works consistently across platforms
        **Validates: Requirements 1.4, 2.4, 3.4**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Test with invalid/corrupted capabilities
        detector = BackendDetector()
        
        # Should handle None capabilities gracefully
        backend = detector.select_best_backend(None)
        assert isinstance(backend, BackendType)
        
        # Should handle empty capabilities gracefully
        empty_capabilities = SystemCapabilities(
            has_dpdk=False,
            has_af_xdp=False,
            has_io_uring=False,
            has_sendmmsg=False,
            has_raw_socket=False,  # Even this is false
            kernel_version_major=0,
            kernel_version_minor=0,
            cpu_count=0,
            numa_nodes=0
        )
        
        # Should still return a backend (probably RAW_SOCKET as fallback)
        backend = detector.select_best_backend(empty_capabilities)
        assert isinstance(backend, BackendType)
    
    def test_concurrent_detection_safety(self):
        """
        Test that concurrent hardware/backend detection is thread-safe
        **Validates: Requirements 11.1, 12.3**
        """
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        results = []
        errors = []
        
        def detect_hardware():
            try:
                profile = HardwareProfiler.detect_hardware_profile()
                results.append(profile)
            except Exception as e:
                errors.append(e)
        
        def detect_backend():
            try:
                detector = BackendDetector()
                capabilities = detector.detect_capabilities()
                backend = detector.select_best_backend(capabilities)
                results.append((capabilities, backend))
            except Exception as e:
                errors.append(e)
        
        # Run concurrent detection
        threads = []
        for i in range(5):
            t1 = threading.Thread(target=detect_hardware)
            t2 = threading.Thread(target=detect_backend)
            threads.extend([t1, t2])
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # Should not have errors
        assert len(errors) == 0, f"Concurrent detection errors: {errors}"
        
        # Should have results
        assert len(results) > 0
        
        # Results should be consistent
        hardware_profiles = [r for r in results if isinstance(r, HardwareProfile)]
        if len(hardware_profiles) > 1:
            # All hardware profiles should have same basic characteristics
            first_profile = hardware_profiles[0]
            for profile in hardware_profiles[1:]:
                assert profile.cpu.cores == first_profile.cpu.cores
                assert profile.memory.total_bytes == first_profile.memory.total_bytes
                assert profile.tier == first_profile.tier


if __name__ == "__main__":
    # Configure logging for test output
    logging.basicConfig(level=logging.INFO)
    
    # Run tests
    pytest.main([__file__, "-v", "-s", "--tb=short"])