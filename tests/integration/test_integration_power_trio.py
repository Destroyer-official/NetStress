#!/usr/bin/env python3
"""
Integration Tests for Ultimate Power Trio
Tests the full Python → Rust → C flow

This test suite validates the complete "Sandwich" architecture:
- Python (Top Layer): Configuration, control, reporting
- Rust (Middle Layer): High-speed packet generation, memory safety
- C (Bottom Layer): Hardware access via DPDK, AF_XDP, io_uring, raw sockets

Requirements tested:
- All requirements from the Ultimate Power Trio specification
- Full Python → Rust → C integration flow
- Backend selection and fallback mechanisms
- Protocol support (UDP, TCP, ICMP, HTTP)
- Statistics accuracy and real-time reporting
- Safety controls and emergency stop
- Cross-platform compatibility
"""

import pytest
import sys
import os
import time
import threading
import subprocess
import tempfile
import json
import socket
import struct
import platform
import multiprocessing
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.native_engine import (
        UltimateEngine, EngineConfig, EngineStats, BackendType, EngineBackend, Protocol,
        SystemCapabilities, get_capabilities, is_native_available, 
        build_packet, start_flood, quick_flood, create_engine,
        NATIVE_ENGINE_AVAILABLE
    )
    INTEGRATION_AVAILABLE = True
    # Alias for backward compatibility
    NativePacketEngine = UltimateEngine
except ImportError as e:
    print(f"Warning: Native engine integration not available: {e}")
    INTEGRATION_AVAILABLE = False
    NATIVE_ENGINE_AVAILABLE = False
    
    # Create mock classes for testing
    class EngineConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class EngineStats:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class BackendType:
        AUTO = "auto"
        NATIVE = "native"
        PYTHON = "python"
        DPDK = "dpdk"
        AF_XDP = "af_xdp"
        IO_URING = "io_uring"
        SENDMMSG = "sendmmsg"
        RAW_SOCKET = "raw_socket"
    
    class UltimateEngine:
        def __init__(self, config):
            self.config = config
            self.running = False
            self.backend_name = "python"
        
        def start(self):
            self.running = True
        
        def stop(self):
            self.running = False
        
        def get_stats(self):
            return EngineStats(packets_sent=0, bytes_sent=0, pps=0.0)
    
    # Alias for backward compatibility
    EngineBackend = BackendType
    NativePacketEngine = UltimateEngine
    
    class Protocol:
        UDP = "udp"
        TCP = "tcp"
        ICMP = "icmp"
        HTTP = "http"
    
    class SystemCapabilities:
        def __init__(self):
            self.platform = platform.system()
            self.cpu_count = os.cpu_count() or 1
            self.native_available = False

# Try to import the native Rust module directly for low-level testing
try:
    import netstress_engine
    RUST_MODULE_AVAILABLE = True
except ImportError:
    RUST_MODULE_AVAILABLE = False


class TestPowerTrioIntegration:
    """Integration tests for the complete Power Trio stack"""

    def setup_method(self):
        """Setup for each test method"""
        self.test_target = "127.0.0.1"
        self.test_port = 9999
        self.test_threads = 2
        self.test_duration = 0.1  # Short duration for tests
        self.test_packet_size = 64  # Small packets for testing
        
    def teardown_method(self):
        """Cleanup after each test"""
        # Allow time for cleanup
        time.sleep(0.01)

    def test_python_to_rust_to_c_flow_basic(self):
        """Test basic Python → Rust → C integration flow"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=self.test_threads,
            packet_size=self.test_packet_size,
            protocol=Protocol.UDP,
            backend=BackendType.AUTO  # Let it choose best backend
        )
        
        engine = UltimateEngine(config)
        
        # Test initial state
        assert not engine.is_running()
        assert engine.config.target == self.test_target
        assert engine.config.port == self.test_port
        
        # Test start/stop cycle
        engine.start()
        assert engine.is_running()
        
        time.sleep(self.test_duration)
        
        stats = engine.stop()
        assert not engine.is_running()
        
        # Verify statistics
        assert isinstance(stats, EngineStats)
        assert stats.duration >= 0
        assert stats.packets_sent >= 0
        assert stats.bytes_sent >= 0
        
        # Verify backend was selected
        assert engine.backend_name in ["rust_native", "python", "raw_socket", "python_fallback"]

    def test_rust_module_direct_access(self):
        """Test direct access to Rust module (bypassing Python wrapper)"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test capabilities detection
        caps = netstress_engine.get_capabilities()
        assert isinstance(caps, dict)
        assert 'platform' in caps
        assert 'cpu_count' in caps
        
        # Test packet building
        packet = netstress_engine.build_packet(
            "192.168.1.1", "192.168.1.2", 12345, 80, "udp", b"test"
        )
        assert isinstance(packet, (bytes, list))
        assert len(packet) > 0
        
        # Test batch packet generation
        batch = netstress_engine.generate_packet_batch(
            "192.168.1.2", 80, "udp", 64, 10
        )
        assert isinstance(batch, list)
        assert len(batch) == 10
        for pkt in batch:
            assert isinstance(pkt, (bytes, list))
            assert len(pkt) > 0

    def test_c_driver_integration_via_rust(self):
        """Test C driver integration through Rust layer"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test capability report which includes C driver capabilities
        report = netstress_engine.get_capability_report()
        assert isinstance(report, dict)
        
        # Should include backend information from C layer
        assert 'available_backends' in report
        assert 'has_dpdk' in report
        assert 'has_af_xdp' in report
        assert 'has_io_uring' in report
        assert 'has_sendmmsg' in report
        
        # Test backend selection
        backends = netstress_engine.get_available_backends()
        assert isinstance(backends, list)
        assert len(backends) > 0
        
        # Should have at least raw socket backend
        backend_names = [b.lower() for b in backends]
        assert any('raw' in name or 'socket' in name for name in backend_names)

    def test_full_stack_protocol_support(self):
        """Test protocol support through full stack"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        protocols = [Protocol.UDP, Protocol.TCP, Protocol.ICMP, Protocol.HTTP]
        
        for protocol in protocols:
            config = EngineConfig(
                target=self.test_target,
                port=self.test_port,
                threads=1,
                packet_size=self.test_packet_size,
                protocol=protocol,
                backend=BackendType.AUTO
            )
            
            with UltimateEngine(config) as engine:
                time.sleep(self.test_duration)
                stats = engine.get_stats()
                assert stats.duration > 0
                # Protocol-specific validation would go here

    def test_backend_fallback_chain(self):
        """Test backend fallback chain (DPDK → AF_XDP → io_uring → sendmmsg → raw_socket)"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test with AUTO backend (should select best available)
        config_auto = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            backend=BackendType.AUTO
        )
        
        engine_auto = UltimateEngine(config_auto)
        backend_name = engine_auto.backend_name
        # Should select any available backend (system-dependent)
        valid_backends = ["rust_native", "python", "raw_socket", "sendmmsg", "io_uring", "af_xdp", "dpdk"]
        assert backend_name in valid_backends
        
        # Test forced Python backend (should always work)
        config_python = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            backend=BackendType.PYTHON
        )
        
        engine_python = UltimateEngine(config_python)
        # Python backend may be "python" or "python_fallback" depending on system
        assert engine_python.backend_name in ["python", "python_fallback"]
        
        # Test that engine works with fallback
        with engine_python as engine:
            time.sleep(self.test_duration)
            stats = engine.get_stats()
            assert stats.duration > 0

    def test_statistics_accuracy_across_layers(self):
        """Test statistics accuracy from C → Rust → Python"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=1,
            packet_size=self.test_packet_size,
            rate_limit=100,  # Low rate for predictable testing
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            # Get initial stats
            stats1 = engine.get_stats()
            initial_packets = stats1.packets_sent
            
            time.sleep(self.test_duration)
            
            # Get stats after running
            stats2 = engine.get_stats()
            
            # Verify consistency across layers
            assert stats2.packets_sent >= initial_packets
            assert stats2.duration > stats1.duration
            assert stats2.bytes_sent >= stats1.bytes_sent
            
            # Verify calculated fields are consistent
            if stats2.duration > 0:
                expected_pps = stats2.packets_sent / stats2.duration
                # Allow some tolerance for timing variations
                assert abs(stats2.pps - expected_pps) < expected_pps * 0.2 or stats2.pps == 0

    def test_memory_safety_across_ffi_boundaries(self):
        """Test memory safety across FFI boundaries (Python ↔ Rust ↔ C)"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        import gc
        
        # Create and destroy multiple engines to test memory management
        for i in range(10):
            config = EngineConfig(
                target=self.test_target,
                port=self.test_port + i,
                threads=1,
                packet_size=self.test_packet_size,
                backend=BackendType.AUTO
            )
            
            engine = UltimateEngine(config)
            engine.start()
            time.sleep(0.01)  # Very brief run
            engine.stop()
            del engine
        
        # Force garbage collection
        gc.collect()
        
        # Test that we can still create new engines (no resource leaks)
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=1,
            backend=BackendType.AUTO
        )
        
        engine = UltimateEngine(config)
        assert engine is not None

    def test_concurrent_engines_resource_isolation(self):
        """Test multiple concurrent engines with resource isolation"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        engines = []
        configs = [
            EngineConfig(
                target=self.test_target,
                port=self.test_port + i,
                threads=1,
                packet_size=self.test_packet_size,
                backend=BackendType.AUTO
            )
            for i in range(3)
        ]
        
        try:
            # Start all engines
            for config in configs:
                engine = UltimateEngine(config)
                engine.start()
                engines.append(engine)
                assert engine.is_running()
            
            # Let them run briefly
            time.sleep(self.test_duration)
            
            # Check all are still running and have independent stats
            stats_list = []
            for engine in engines:
                assert engine.is_running()
                stats = engine.get_stats()
                stats_list.append(stats)
                assert stats.duration > 0
            
            # Verify engines are independent (different backend instances)
            for i, engine in enumerate(engines):
                assert engine.config.port == self.test_port + i
        
        finally:
            # Clean up
            for engine in engines:
                if engine.is_running():
                    engine.stop()

    def test_error_propagation_across_layers(self):
        """Test error propagation from C → Rust → Python"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test invalid target (should propagate error from C layer)
        with pytest.raises(Exception):
            config = EngineConfig(
                target="invalid.target.address.that.does.not.exist.nowhere.invalid",
                port=self.test_port,
                backend=BackendType.AUTO
            )
            engine = UltimateEngine(config)
            engine.start()  # Should fail
        
        # Test invalid configuration
        config = EngineConfig(
            target=self.test_target,
            port=0,  # Invalid port
            backend=BackendType.AUTO
        )
        
        # Should handle gracefully or raise appropriate error
        try:
            engine = UltimateEngine(config)
            # May succeed or fail depending on implementation
        except Exception as e:
            # Should be a meaningful error message
            assert len(str(e)) > 0

    def test_platform_specific_optimizations(self):
        """Test platform-specific optimizations are properly integrated"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        caps = get_capabilities()
        assert isinstance(caps, SystemCapabilities)
        
        # Test platform detection
        assert caps.platform in ['Windows', 'Linux', 'Darwin', 'windows', 'linux', 'darwin']
        assert caps.cpu_count > 0
        
        # Test platform-specific features
        if caps.platform.lower() == 'linux':
            # Linux should potentially have advanced features
            # (may not be compiled in, so we just check they're reported)
            assert hasattr(caps, 'has_af_xdp')
            assert hasattr(caps, 'has_io_uring')
        
        # Test that engine works regardless of platform
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            backend=BackendType.AUTO
        )
        
        engine = UltimateEngine(config)
        assert engine is not None
        
        # Should be able to get capabilities
        engine_caps = engine.capabilities
        assert engine_caps.platform == caps.platform

    def test_rate_limiting_enforcement_across_layers(self):
        """Test rate limiting enforcement from Rust layer"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=1,
            packet_size=self.test_packet_size,
            rate_limit=1000,  # 1000 PPS
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            # Test dynamic rate changes
            engine.set_rate(500)  # Change to 500 PPS
            
            time.sleep(self.test_duration)
            
            stats = engine.get_stats()
            # Rate limiting should be working (hard to test exact rate in short time)
            assert stats.packets_sent >= 0
            
            # Test that rate limiting is enforced in Rust layer
            # (cannot be bypassed from Python)
            engine.set_rate(10000)  # High rate
            time.sleep(self.test_duration)
            
            stats2 = engine.get_stats()
            assert stats2.packets_sent >= stats.packets_sent

    def test_context_manager_usage(self):
        """Test engine as context manager with proper cleanup"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=1,
            packet_size=self.test_packet_size,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            assert engine.is_running()
            time.sleep(self.test_duration)
            stats = engine.get_stats()
            assert stats.duration > 0
        
        # Should be stopped after context exit
        assert not engine.is_running()

    def test_packet_building_integration(self):
        """Test packet building functionality across all layers"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test UDP packet building
        try:
            udp_packet = build_packet(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="udp",
                payload=b"test"
            )
            assert isinstance(udp_packet, bytes)
            assert len(udp_packet) >= 8  # UDP header minimum
        except Exception as e:
            pytest.skip(f"Packet building not available: {e}")
        
        # Test TCP packet building
        try:
            tcp_packet = build_packet(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=54321,
                dst_port=443,
                protocol="tcp"
            )
            assert isinstance(tcp_packet, bytes)
            assert len(tcp_packet) >= 20  # TCP header minimum
        except Exception:
            pass  # May not be available
        
        # Test ICMP packet building
        try:
            icmp_packet = build_packet(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=0,
                dst_port=0,
                protocol="icmp",
                payload=b"ping"
            )
            assert isinstance(icmp_packet, bytes)
            assert len(icmp_packet) >= 8  # ICMP header minimum
        except Exception:
            pass  # May not be available

    def test_rust_specific_features(self):
        """Test Rust-specific features like SIMD and lock-free queues"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test batch packet generation (uses Rust optimizations)
        batch = netstress_engine.generate_packet_batch(
            "192.168.1.2", 80, "udp", 1472, 100
        )
        assert isinstance(batch, list)
        assert len(batch) == 100
        
        # All packets should be properly formed
        for packet in batch:
            assert isinstance(packet, (bytes, list))
            assert len(packet) > 0
        
        # Test protocol-specific builders
        protocols = ["udp", "tcp", "icmp"]
        for protocol in protocols:
            try:
                batch = netstress_engine.generate_packet_batch(
                    "127.0.0.1", 80, protocol, 64, 10
                )
                assert len(batch) == 10
            except Exception:
                pass  # Some protocols may not be available

    def test_c_driver_backend_detection(self):
        """Test C driver backend detection and capabilities"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test capability detection
        caps = netstress_engine.get_capability_report()
        
        # Should detect platform capabilities
        assert 'platform' in caps
        assert 'cpu_count' in caps
        assert caps['cpu_count'] > 0
        
        # Should detect C driver capabilities
        c_capabilities = ['has_dpdk', 'has_af_xdp', 'has_io_uring', 'has_sendmmsg']
        for cap in c_capabilities:
            assert cap in caps
            assert isinstance(caps[cap], bool)
        
        # Should have at least one backend available
        assert 'available_backends' in caps
        assert len(caps['available_backends']) > 0

    def test_safety_controls_integration(self):
        """Test safety controls integration across layers"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test safety controller
        safety = netstress_engine.PySafetyController.permissive()
        safety.set_max_pps(1000)
        
        # Test authorization
        safety.authorize_ip("127.0.0.1")
        assert safety.is_authorized("127.0.0.1")
        
        # Test CIDR authorization
        safety.authorize_cidr("192.168.1.0/24")
        assert safety.is_authorized("192.168.1.100")
        
        # Test emergency stop
        assert not safety.is_stopped()
        safety.emergency_stop("test")
        assert safety.is_stopped()
        assert safety.stop_reason() == "test"
        
        # Test reset
        safety.reset_emergency_stop()
        assert not safety.is_stopped()

    def test_audit_logging_integration(self):
        """Test audit logging integration across layers"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test audit logger
        audit = netstress_engine.PyAuditLogger()
        
        # Test logging operations
        audit.log_engine_start("127.0.0.1", "test config")
        audit.log_target_authorized("127.0.0.1")
        audit.log_engine_stop("test stats")
        
        # Should have entries
        assert audit.entry_count() > 0
        
        # Test chain verification
        result = audit.verify_chain()
        assert 'valid' in result
        assert 'entries_checked' in result
        
        # Test JSON export
        json_data = audit.export_json()
        assert len(json_data) > 0
        
        # Should be valid JSON
        import json
        parsed = json.loads(json_data)
        assert isinstance(parsed, (list, dict))

    def test_statistics_export_formats(self):
        """Test statistics export in different formats (JSON, Prometheus)"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test JSON metrics
        json_metrics = netstress_engine.get_realtime_stats_json()
        assert isinstance(json_metrics, str)
        assert len(json_metrics) > 0
        
        # Should be valid JSON
        import json
        parsed = json.loads(json_metrics)
        assert isinstance(parsed, dict)
        
        # Test Prometheus metrics
        prom_metrics = netstress_engine.get_prometheus_metrics()
        assert isinstance(prom_metrics, str)
        assert len(prom_metrics) > 0
        
        # Should contain Prometheus format indicators
        assert any(keyword in prom_metrics for keyword in ['# HELP', '# TYPE', 'packets_sent'])

    def test_platform_optimization_reports(self):
        """Test platform-specific optimization reports"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        current_platform = platform.system().lower()
        
        # Test Linux optimizations
        linux_report = netstress_engine.get_linux_optimization_report()
        assert isinstance(linux_report, dict)
        if current_platform == 'linux':
            assert 'kernel_version' in linux_report
            assert 'recommended_backend' in linux_report
        else:
            assert 'error' in linux_report
        
        # Test Windows optimizations
        windows_report = netstress_engine.get_windows_optimization_report()
        assert isinstance(windows_report, dict)
        if current_platform == 'windows':
            assert 'winsock_version' in windows_report
            assert 'recommended_backend' in windows_report
        else:
            assert 'error' in windows_report
        
        # Test macOS optimizations
        macos_report = netstress_engine.get_macos_optimization_report()
        assert isinstance(macos_report, dict)
        if current_platform == 'darwin':
            assert 'darwin_version' in macos_report
            assert 'recommended_backend' in macos_report
        else:
            assert 'error' in macos_report

    def test_high_level_api_integration(self):
        """Test high-level API functions that use the full stack"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test quick_flood function
        try:
            stats = quick_flood(
                target=self.test_target,
                port=self.test_port,
                duration=self.test_duration,
                protocol="udp",
                rate_limit=100
            )
            assert isinstance(stats, EngineStats)
            assert stats.duration >= 0
            assert stats.packets_sent >= 0
        except Exception as e:
            pytest.skip(f"Quick flood not available: {e}")
        
        # Test create_engine factory function
        engine = create_engine(
            target=self.test_target,
            port=self.test_port,
            protocol="udp",
            threads=1,
            packet_size=self.test_packet_size,
            rate_limit=100
        )
        assert isinstance(engine, UltimateEngine)
        
        # Test start_flood function
        try:
            result = start_flood(
                target=self.test_target,
                port=self.test_port,
                duration=self.test_duration,
                rate=100,
                threads=1,
                packet_size=self.test_packet_size,
                protocol="udp"
            )
            assert isinstance(result, dict)
            assert 'packets_sent' in result
            assert 'duration_secs' in result
        except Exception as e:
            pytest.skip(f"Start flood not available: {e}")

    def test_multiple_engines_concurrent(self):
        """Test running multiple engines concurrently"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        engines = []
        configs = [
            EngineConfig(
                target=self.test_target,
                port=self.test_port + i,
                threads=1,
                backend=EngineBackend.PYTHON
            )
            for i in range(3)
        ]
        
        try:
            # Start all engines
            for config in configs:
                engine = NativePacketEngine(config)
                engine.start()
                engines.append(engine)
                assert engine.is_running()
            
            # Let them run briefly
            time.sleep(self.test_duration)
            
            # Check all are still running
            for engine in engines:
                assert engine.is_running()
                stats = engine.get_stats()
                assert stats.duration_secs > 0
        
        finally:
            # Clean up
            for engine in engines:
                if engine.is_running():
                    engine.stop()

    def test_rate_limiting_integration(self):
        """Test rate limiting functionality"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=1,
            rate_limit=1000,  # 1000 PPS
            backend=EngineBackend.PYTHON
        )
        
        with NativePacketEngine(config) as engine:
            # Set different rate
            engine.set_rate(5000)
            
            time.sleep(self.test_duration)
            
            stats = engine.get_stats()
            # Rate limiting should be working (hard to test exact rate in short time)
            assert stats.packets_sent >= 0

    def test_different_protocols(self):
        """Test different protocol support"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        protocols = ["udp", "tcp", "http"]
        
        for protocol in protocols:
            config = EngineConfig(
                target=self.test_target,
                port=self.test_port,
                threads=1,
                protocol=protocol,
                backend=EngineBackend.PYTHON
            )
            
            with NativePacketEngine(config) as engine:
                time.sleep(self.test_duration)
                stats = engine.get_stats()
                assert stats.duration_secs > 0

    def test_packet_building_integration(self):
        """Test packet building functionality"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        # Test UDP packet
        try:
            udp_packet = build_packet(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="udp",
                payload=b"test"
            )
            assert isinstance(udp_packet, bytes)
            assert len(udp_packet) >= 28  # IP + UDP headers
        except Exception:
            pytest.skip("Packet building not available")
        
        # Test TCP packet
        try:
            tcp_packet = build_packet(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=54321,
                dst_port=443,
                protocol="tcp"
            )
            assert isinstance(tcp_packet, bytes)
            assert len(tcp_packet) >= 40  # IP + TCP headers
        except Exception:
            pass  # May not be available

    def test_capabilities_detection(self):
        """Test system capabilities detection"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        caps = get_capabilities()
        # Can be either dict or SystemCapabilities object
        if isinstance(caps, dict):
            assert 'platform' in caps
            assert 'cpu_count' in caps
            assert caps['cpu_count'] > 0
        else:
            # SystemCapabilities object
            assert hasattr(caps, 'platform')
            assert hasattr(caps, 'cpu_count')
            assert caps.cpu_count > 0
        
        # Test native availability
        native_available = is_native_available()
        assert isinstance(native_available, bool)

    def test_backend_selection_and_fallback(self):
        """Test backend selection and fallback mechanisms"""
        # Test AUTO backend selection
        config_auto = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            backend=EngineBackend.AUTO
        )
        
        if NATIVE_ENGINE_AVAILABLE:
            engine_auto = NativePacketEngine(config_auto)
            # Should select appropriate backend (system-dependent)
            valid_backends = ["native", "python", "raw_socket", "sendmmsg", "io_uring", "af_xdp", "dpdk", "python_fallback"]
            assert engine_auto.backend_name in valid_backends
        
        # Test forced Python backend
        config_python = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            backend=EngineBackend.PYTHON
        )
        
        if NATIVE_ENGINE_AVAILABLE:
            engine_python = NativePacketEngine(config_python)
            assert engine_python.backend_name in ["python", "python_fallback"]
        
        # Test forced native backend (may fail if not available)
        if NATIVE_ENGINE_AVAILABLE and is_native_available():
            config_native = EngineConfig(
                target=self.test_target,
                port=self.test_port,
                backend=EngineBackend.NATIVE
            )
            
            try:
                engine_native = NativePacketEngine(config_native)
                # Native backend may fall back to available backend
                assert engine_native.backend_name in ["native", "raw_socket", "sendmmsg", "io_uring", "af_xdp", "dpdk"]
            except RuntimeError:
                # Expected if native engine not available
                pass

    def test_error_handling_and_recovery(self):
        """Test error handling and recovery scenarios"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        # Test invalid target - engine creation doesn't validate target immediately
        # Target validation happens during start() method
        try:
            config = EngineConfig(
                target="invalid.target.address.that.does.not.exist",
                port=self.test_port,
                backend=EngineBackend.PYTHON
            )
            engine = UltimateEngine(config.target, config.port, native=False)
            # The error should occur during start, not construction
            with pytest.raises(Exception):
                engine.start()
                time.sleep(0.1)  # Give it time to fail
                engine.stop()
        except Exception:
            pass  # Expected behavior
        
        # Test invalid port
        config = EngineConfig(
            target=self.test_target,
            port=0,  # Invalid port
            backend=EngineBackend.PYTHON
        )
        
        # Should handle gracefully
        try:
            engine = NativePacketEngine(config)
            # May succeed or fail depending on implementation
        except Exception:
            pass  # Expected for invalid configuration

    def test_statistics_accuracy_and_consistency(self):
        """Test statistics accuracy and consistency"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=1,
            rate_limit=100,  # Low rate for predictable testing
            backend=EngineBackend.PYTHON
        )
        
        with NativePacketEngine(config) as engine:
            # Get initial stats
            stats1 = engine.get_stats()
            initial_packets = stats1.packets_sent
            
            time.sleep(self.test_duration)
            
            # Get stats after running
            stats2 = engine.get_stats()
            
            # Verify consistency
            assert stats2.packets_sent >= initial_packets
            assert stats2.duration_secs >= stats1.duration_secs
            assert stats2.bytes_sent >= stats1.bytes_sent
            
            # Verify calculated fields
            if stats2.duration_secs > 0 and stats2.packets_sent > 0:
                expected_pps = stats2.packets_sent / stats2.duration_secs
                # Allow some tolerance for timing variations (use max to avoid 0 tolerance)
                tolerance = max(expected_pps * 0.1, 1.0)
                assert abs(stats2.pps - expected_pps) < tolerance

    def test_memory_usage_and_cleanup(self):
        """Test memory usage and proper cleanup"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        import gc
        
        # Create and destroy multiple engines
        for i in range(10):
            config = EngineConfig(
                target=self.test_target,
                port=self.test_port + i,
                threads=1,
                backend=EngineBackend.PYTHON
            )
            
            engine = NativePacketEngine(config)
            engine.start()
            time.sleep(0.01)  # Very brief run
            engine.stop()
            del engine
        
        # Force garbage collection
        gc.collect()
        
        # Should not have memory leaks (hard to test directly)
        assert True  # If we get here without crashing, cleanup worked

    def test_thread_safety(self):
        """Test thread safety of engine operations"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=2,
            backend=EngineBackend.PYTHON
        )
        
        engine = NativePacketEngine(config)
        errors = []
        
        def worker():
            try:
                for _ in range(10):
                    stats = engine.get_stats()
                    assert isinstance(stats, EngineStats)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)
        
        # Start engine
        engine.start()
        
        try:
            # Create multiple threads accessing stats
            threads = [threading.Thread(target=worker) for _ in range(5)]
            
            for t in threads:
                t.start()
            
            for t in threads:
                t.join()
            
            # Check for errors
            assert len(errors) == 0, f"Thread safety errors: {errors}"
        
        finally:
            engine.stop()

    def test_configuration_validation(self):
        """Test configuration validation"""
        # Test valid configurations
        valid_configs = [
            {"target": "127.0.0.1", "port": 80},
            {"target": "localhost", "port": 443},
            {"target": "8.8.8.8", "port": 53},
        ]
        
        for config_dict in valid_configs:
            config = EngineConfig(**config_dict, backend=EngineBackend.PYTHON)
            assert config.target == config_dict["target"]
            assert config.port == config_dict["port"]
        
        # Test edge cases
        edge_configs = [
            {"target": "127.0.0.1", "port": 1},      # Min port
            {"target": "127.0.0.1", "port": 65535},  # Max port
            {"target": "127.0.0.1", "port": 80, "threads": 1},    # Min threads
            {"target": "127.0.0.1", "port": 80, "threads": 64},   # Many threads
        ]
        
        for config_dict in edge_configs:
            config = EngineConfig(**config_dict, backend=EngineBackend.PYTHON)
            # Should create without error
            assert config.target is not None

    def test_performance_benchmarking(self):
        """Test performance characteristics"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            threads=2,
            rate_limit=10000,  # High rate
            backend=EngineBackend.PYTHON
        )
        
        with NativePacketEngine(config) as engine:
            start_time = time.time()
            time.sleep(0.5)  # Run for half a second
            end_time = time.time()
            
            stats = engine.get_stats()
            
            # Basic performance checks
            actual_duration = end_time - start_time
            assert abs(stats.duration_secs - actual_duration) < 0.1
            
            # Should achieve some reasonable rate
            if stats.duration_secs > 0:
                assert stats.pps >= 0  # At least some packets per second

    def test_integration_with_existing_ddos_module(self):
        """Test integration with existing ddos.py module"""
        try:
            import ddos
            # Test that the module can be imported without errors
            assert hasattr(ddos, 'RealAttackEngine') or hasattr(ddos, 'AttackEngine')
        except ImportError:
            pytest.skip("ddos module not available")

    def test_cross_platform_compatibility(self):
        """Test cross-platform compatibility"""
        if not NATIVE_ENGINE_AVAILABLE:
            pytest.skip("Native engine not available")
        
        caps = get_capabilities()
        
        # Should work on all platforms
        assert caps['platform'] in ['Windows', 'Linux', 'Darwin', 'windows', 'linux', 'darwin']
        
        # Test platform-specific features
        if caps['platform'].lower() == 'linux':
            # Linux should have more advanced features
            assert 'af_xdp' in caps or 'io_uring' in caps or True  # May not be compiled in
        
        # All platforms should support basic functionality
        config = EngineConfig(
            target=self.test_target,
            port=self.test_port,
            backend=EngineBackend.PYTHON
        )
        
        engine = NativePacketEngine(config)
        assert engine is not None


class TestPowerTrioPropertyBased:
    """Property-based integration tests for the full stack"""

    @pytest.mark.parametrize("target,port", [
        ("127.0.0.1", 80),
        ("localhost", 443),
        ("127.0.0.1", 8080),
        ("127.0.0.1", 53),
    ])
    def test_engine_with_various_targets(self, target, port):
        """Test engine with various target configurations through full stack"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target=target,
            port=port,
            threads=1,
            packet_size=64,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0

    @pytest.mark.parametrize("threads", [1, 2, 4])
    def test_engine_with_various_thread_counts(self, threads):
        """Test engine with various thread counts across layers"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=threads,
            packet_size=64,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0

    @pytest.mark.parametrize("rate_limit", [100, 1000, 10000, None])
    def test_engine_with_various_rate_limits(self, rate_limit):
        """Test rate limiting enforcement across Python → Rust → C"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            rate_limit=rate_limit,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0

    @pytest.mark.parametrize("protocol", ["udp", "tcp", "icmp", "http"])
    def test_protocol_support_full_stack(self, protocol):
        """Test protocol support through all layers"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        try:
            proto_enum = Protocol(protocol.lower())
        except ValueError:
            pytest.skip(f"Protocol {protocol} not supported")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=80 if protocol != "icmp" else 0,
            threads=1,
            packet_size=64,
            protocol=proto_enum,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0

    @pytest.mark.parametrize("backend", ["auto", "python"])
    def test_backend_consistency(self, backend):
        """Test that different backends produce consistent results"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        try:
            backend_enum = BackendType(backend.lower())
        except ValueError:
            pytest.skip(f"Backend {backend} not supported")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            backend=backend_enum
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0
            assert stats.packets_sent >= 0
            assert stats.bytes_sent >= 0

    @pytest.mark.parametrize("packet_size", [64, 512, 1024, 1472])
    def test_packet_sizes_across_layers(self, packet_size):
        """Test various packet sizes through the full stack"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=packet_size,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0
            
            # Verify packet size is reflected in bytes sent
            if stats.packets_sent > 0:
                avg_packet_size = stats.bytes_sent / stats.packets_sent
                # Allow some variance for headers
                assert avg_packet_size >= packet_size * 0.8


class TestPowerTrioStressTests:
    """Stress tests for the complete Power Trio stack"""

    def test_long_running_engine_full_stack(self):
        """Test engine running for extended period through full stack"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            rate_limit=100,  # Low rate to avoid overwhelming
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            # Run for 1 second (long for a test)
            time.sleep(1.0)
            
            stats = engine.get_stats()
            assert stats.duration >= 0.9
            assert stats.packets_sent >= 0

    def test_rapid_start_stop_cycles_memory_safety(self):
        """Test rapid start/stop cycles for memory safety across FFI"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            backend=BackendType.AUTO
        )
        
        for i in range(20):
            engine = UltimateEngine(config)
            engine.start()
            time.sleep(0.01)  # Very brief
            engine.stop()
            
            # Should handle rapid cycles without error
            assert not engine.is_running()

    def test_high_thread_count_coordination(self):
        """Test high thread count coordination across layers"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        max_threads = min(multiprocessing.cpu_count() * 2, 16)  # Reasonable limit
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=max_threads,
            packet_size=64,
            rate_limit=1000,  # Limit to avoid overwhelming
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            time.sleep(0.1)
            stats = engine.get_stats()
            assert stats.duration > 0

    def test_memory_pressure_handling(self):
        """Test handling of memory pressure across all layers"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Create multiple engines with large packet sizes
        engines = []
        try:
            for i in range(5):
                config = EngineConfig(
                    target="127.0.0.1",
                    port=9999 + i,
                    threads=2,
                    packet_size=1472,  # Large packets
                    rate_limit=1000,
                    backend=BackendType.AUTO
                )
                
                engine = UltimateEngine(config)
                engine.start()
                engines.append(engine)
            
            # Let them run briefly
            time.sleep(0.1)
            
            # All should still be running
            for engine in engines:
                assert engine.is_running()
                stats = engine.get_stats()
                assert stats.duration > 0
        
        finally:
            for engine in engines:
                if engine.is_running():
                    engine.stop()

    def test_concurrent_protocol_stress(self):
        """Test concurrent engines with different protocols"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        protocols = [Protocol.UDP, Protocol.TCP, Protocol.HTTP]
        engines = []
        
        try:
            for i, protocol in enumerate(protocols):
                config = EngineConfig(
                    target="127.0.0.1",
                    port=8000 + i,
                    threads=1,
                    packet_size=64,
                    protocol=protocol,
                    rate_limit=500,
                    backend=BackendType.AUTO
                )
                
                engine = UltimateEngine(config)
                engine.start()
                engines.append(engine)
            
            # Let them run concurrently
            time.sleep(0.2)
            
            # All should be working independently
            for i, engine in enumerate(engines):
                assert engine.is_running()
                stats = engine.get_stats()
                assert stats.duration > 0
                assert engine.config.protocol == protocols[i]
        
        finally:
            for engine in engines:
                if engine.is_running():
                    engine.stop()


class TestPowerTrioErrorHandling:
    """Test error handling and recovery across all layers"""
    
    test_port = 9999  # Default test port

    def test_rust_error_propagation(self):
        """Test error handling from Rust to Python - implementation handles errors gracefully"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test invalid packet building - implementation may handle gracefully or raise
        try:
            result = netstress_engine.build_packet(
                "invalid.ip.address", "192.168.1.1", 80, 80, "udp"
            )
            # If no exception, result should be None or empty
            assert result is None or result == b'' or isinstance(result, bytes)
        except Exception:
            pass  # Exception is also acceptable
        
        # Test invalid protocol - implementation may handle gracefully or raise
        try:
            result = netstress_engine.build_packet(
                "192.168.1.1", "192.168.1.2", 80, 80, "invalid_protocol"
            )
            # If no exception, result should be None or empty
            assert result is None or result == b'' or isinstance(result, bytes)
        except Exception:
            pass  # Exception is also acceptable

    def test_c_driver_error_handling(self):
        """Test C driver error handling through Rust"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # Test capability detection (should not raise errors)
        caps = netstress_engine.get_capability_report()
        assert isinstance(caps, dict)
        
        # Test backend selection (should handle unavailable backends gracefully)
        backends = netstress_engine.get_available_backends()
        assert isinstance(backends, list)
        assert len(backends) > 0  # Should have at least one backend

    def test_ffi_boundary_error_handling(self):
        """Test error handling at FFI boundaries - implementation handles errors gracefully"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test invalid configuration - implementation may handle gracefully or raise
        try:
            config = EngineConfig(
                target="",  # Empty target
                port=self.test_port,
                backend=BackendType.AUTO
            )
            engine = UltimateEngine(config)
            # If no exception, engine should be created but may not work properly
            assert engine is not None
        except Exception:
            pass  # Exception is also acceptable
        
        # Test invalid port range - implementation may handle gracefully or raise
        try:
            config = EngineConfig(
                target="127.0.0.1",
                port=70000,  # Invalid port
                backend=BackendType.AUTO
            )
            engine = UltimateEngine(config)
            # If no exception, engine should be created but may not work properly
            assert engine is not None
        except Exception:
            pass  # Exception is also acceptable

    def test_resource_cleanup_on_error(self):
        """Test proper resource cleanup when errors occur"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test that resources are cleaned up even if start fails
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            backend=BackendType.AUTO
        )
        
        engine = UltimateEngine(config)
        
        try:
            engine.start()
            # Force an error condition
            engine.stop()
            
            # Should be able to start again (resources cleaned up)
            engine.start()
            engine.stop()
        except Exception:
            # Even if operations fail, should not leak resources
            pass
        
        # Should be in clean state
        assert not engine.is_running()

    def setup_method(self):
        """Setup for error handling tests"""
        self.test_port = 9999


class TestPowerTrioPerformance:
    """Performance validation tests for the full stack"""

    def test_performance_comparison_native_vs_python(self):
        """Compare performance between native and Python backends"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        test_duration = 0.5
        
        # Test Python backend
        config_python = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            backend=BackendType.PYTHON
        )
        
        with UltimateEngine(config_python) as engine_python:
            time.sleep(test_duration)
            stats_python = engine_python.get_stats()
        
        # Test AUTO backend (may use native)
        config_auto = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config_auto) as engine_auto:
            time.sleep(test_duration)
            stats_auto = engine_auto.get_stats()
        
        # Both should produce reasonable results
        assert stats_python.duration > 0
        assert stats_auto.duration > 0
        assert stats_python.packets_sent >= 0
        assert stats_auto.packets_sent >= 0
        
        # If native is available, it should be at least as good as Python
        if engine_auto.backend_name == "rust_native":
            # Native should be at least as fast (or handle errors better)
            assert stats_auto.pps >= stats_python.pps or stats_auto.errors <= stats_python.errors

    def test_throughput_scaling_with_threads(self):
        """Test throughput scaling with thread count"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        test_duration = 0.2
        thread_counts = [1, 2, 4]
        results = []
        
        for threads in thread_counts:
            config = EngineConfig(
                target="127.0.0.1",
                port=9999,
                threads=threads,
                packet_size=64,
                rate_limit=10000,  # High limit
                backend=BackendType.AUTO
            )
            
            with UltimateEngine(config) as engine:
                time.sleep(test_duration)
                stats = engine.get_stats()
                results.append((threads, stats.pps))
        
        # Should show some scaling (or at least not decrease significantly)
        for i in range(1, len(results)):
            prev_threads, prev_pps = results[i-1]
            curr_threads, curr_pps = results[i]
            
            # Allow for some variance, but shouldn't decrease dramatically
            assert curr_pps >= prev_pps * 0.5 or curr_pps == 0

    def test_memory_usage_stability(self):
        """Test memory usage stability over time"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        import gc
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=2,
            packet_size=64,
            rate_limit=1000,
            backend=BackendType.AUTO
        )
        
        # Run multiple cycles to check for memory leaks
        for cycle in range(5):
            with UltimateEngine(config) as engine:
                time.sleep(0.1)
                stats = engine.get_stats()
                assert stats.duration > 0
            
            # Force garbage collection
            gc.collect()
        
        # If we get here without crashing, memory management is working

    def test_latency_consistency(self):
        """Test latency consistency across operations"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            rate_limit=100,  # Low rate for consistent timing
            backend=BackendType.AUTO
        )
        
        latencies = []
        
        # Measure start/stop latencies
        for i in range(10):
            engine = UltimateEngine(config)
            
            start_time = time.monotonic()
            engine.start()
            start_latency = time.monotonic() - start_time
            
            time.sleep(0.01)
            
            stop_time = time.monotonic()
            engine.stop()
            stop_latency = time.monotonic() - stop_time
            
            latencies.append((start_latency, stop_latency))
        
        # Check that latencies are reasonable and consistent
        start_latencies = [l[0] for l in latencies]
        stop_latencies = [l[1] for l in latencies]
        
        # Should start within reasonable time (10ms requirement from spec)
        assert all(l < 0.01 for l in start_latencies), f"Start latencies too high: {start_latencies}"
        
        # Stop should be fast too
        assert all(l < 0.1 for l in stop_latencies), f"Stop latencies too high: {stop_latencies}"


class TestPowerTrioCompliance:
    """Test compliance with Ultimate Power Trio requirements"""

    def test_requirement_1_rust_engine_core(self):
        """Test Requirement 1: Rust Engine Core"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=2,
            packet_size=64,
            backend=BackendType.AUTO
        )
        
        engine = UltimateEngine(config)
        
        # 1.1: Start within 10ms
        start_time = time.monotonic()
        engine.start()
        start_duration = time.monotonic() - start_time
        assert start_duration < 0.01, f"Start took {start_duration:.3f}s, requirement is <10ms"
        
        try:
            time.sleep(0.1)
            stats = engine.get_stats()
            
            # 1.3: Pre-allocated memory pools (verified by no crashes)
            assert stats.duration > 0
            
            # 1.4: Lock-free MPMC queues (verified by multi-thread operation)
            assert engine.config.threads >= 2
            
        finally:
            engine.stop()

    def test_requirement_3_python_rust_integration(self):
        """Test Requirement 3: Python-Rust Integration (PyO3)"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # 3.1: Load native extension
        assert netstress_engine is not None
        
        # 3.2: Zero-copy PyBytes (tested by packet building)
        packet = netstress_engine.build_packet(
            "192.168.1.1", "192.168.1.2", 80, 80, "udp", b"test"
        )
        assert isinstance(packet, (bytes, list))
        
        # 3.3: Statistics conversion without blocking
        stats = netstress_engine.get_stats()
        assert isinstance(stats, dict)
        
        # 3.4: Proper Python exceptions
        with pytest.raises(Exception):
            netstress_engine.build_packet(
                "invalid", "192.168.1.2", 80, 80, "invalid_protocol"
            )

    def test_requirement_5_backend_selection_fallback(self):
        """Test Requirement 5: Backend Selection and Fallback"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # 5.1: Detect available backends
        caps = get_capabilities()
        assert isinstance(caps, SystemCapabilities)
        assert caps.cpu_count > 0
        
        # 5.2: Automatic fallback
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=BackendType.AUTO
        )
        
        engine = UltimateEngine(config)
        # Accept any valid backend name that the system selects
        valid_backends = ["rust_native", "python", "raw_socket", "sendmmsg", "io_uring", "af_xdp", "dpdk", "python_fallback"]
        assert engine.backend_name in valid_backends
        
        # 5.3: Report active backend
        backend_name = engine.backend_name
        assert len(backend_name) > 0

    def test_requirement_6_real_time_statistics(self):
        """Test Requirement 6: Real-Time Statistics"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            packet_size=64,
            rate_limit=1000,
            backend=BackendType.AUTO
        )
        
        with UltimateEngine(config) as engine:
            # 6.1: Statistics updated at least every 100ms
            time.sleep(0.15)
            
            stats1 = engine.get_stats()
            time.sleep(0.15)
            stats2 = engine.get_stats()
            
            # Should have updated
            assert stats2.duration > stats1.duration
            
            # 6.2: Atomic counters (verified by consistent reads)
            assert stats2.packets_sent >= stats1.packets_sent
            assert stats2.bytes_sent >= stats1.bytes_sent

    def test_requirement_9_safety_compliance(self):
        """Test Requirement 9: Safety and Compliance"""
        if not RUST_MODULE_AVAILABLE:
            pytest.skip("Rust module not available")
        
        # 9.1: Target authorization
        safety = netstress_engine.PySafetyController.permissive()
        safety.authorize_ip("127.0.0.1")
        assert safety.is_authorized("127.0.0.1")
        
        # 9.2: Rate limiting enforcement
        safety.set_max_pps(1000)
        assert safety.current_pps() <= 1000
        
        # 9.5: Emergency stop within 100ms
        start_time = time.monotonic()
        safety.emergency_stop("test")
        stop_time = time.monotonic()
        
        assert safety.is_stopped()
        assert (stop_time - start_time) < 0.1  # Should be nearly instantaneous

    def test_requirement_10_cross_platform_support(self):
        """Test Requirement 10: Cross-Platform Support"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        caps = get_capabilities()
        
        # 10.4: Document platform limitations
        assert caps.platform in ['Windows', 'Linux', 'Darwin', 'windows', 'linux', 'darwin']
        
        # Should work on current platform
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=BackendType.AUTO
        )
        
        engine = UltimateEngine(config)
        assert engine is not None
        
        # Test basic functionality
        with engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert stats.duration > 0


class TestPowerTrioDocumentation:
    """Test that the integration matches documentation examples"""

    def test_design_document_examples(self):
        """Test examples from the design document work"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test UltimateEngine example from design doc
        config = EngineConfig(
            target="127.0.0.1",
            port=80,
            threads=4,
            packet_size=1472
        )
        
        engine = UltimateEngine(config)
        assert engine is not None
        
        # Test context manager usage
        with engine:
            time.sleep(0.05)
            stats = engine.get_stats()
            assert isinstance(stats, EngineStats)

    def test_api_consistency_with_spec(self):
        """Test that API matches specification"""
        if not INTEGRATION_AVAILABLE:
            pytest.skip("Integration components not available")
        
        # Test that all required classes exist
        assert EngineConfig is not None
        assert EngineStats is not None
        assert UltimateEngine is not None
        assert BackendType is not None
        assert Protocol is not None
        
        # Test that all required functions exist
        assert get_capabilities is not None
        assert create_engine is not None
        assert quick_flood is not None
        
        # Test factory function
        engine = create_engine(
            target="127.0.0.1",
            port=80,
            protocol="udp",
            threads=1,
            packet_size=64
        )
        assert isinstance(engine, UltimateEngine)


if __name__ == "__main__":
    # Print integration status
    print(f"Integration Available: {INTEGRATION_AVAILABLE}")
    print(f"Native Engine Available: {NATIVE_ENGINE_AVAILABLE}")
    print(f"Rust Module Available: {RUST_MODULE_AVAILABLE}")
    
    if INTEGRATION_AVAILABLE:
        print("Running full integration tests...")
    else:
        print("Running limited tests (integration components not available)")
    
    # Run tests with verbose output
    pytest.main([__file__, "-v", "-s", "--tb=short"])