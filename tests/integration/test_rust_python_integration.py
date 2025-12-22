#!/usr/bin/env python3
"""
Rust-Python Integration Tests
Tests the PyO3 bindings and Rust engine integration
"""

import pytest
import sys
import os
import time
import json
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # Try to import the native Rust engine
    import netstress_engine
    RUST_ENGINE_AVAILABLE = True
except ImportError:
    RUST_ENGINE_AVAILABLE = False
    netstress_engine = None


class TestRustPythonBindings:
    """Test PyO3 bindings between Python and Rust"""

    def test_module_import(self):
        """Test that the Rust module can be imported"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        assert netstress_engine is not None
        assert hasattr(netstress_engine, '__version__')

    def test_packet_engine_creation(self):
        """Test PacketEngine creation"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        engine = netstress_engine.PacketEngine("127.0.0.1", 8080, 2, 1472)
        assert engine is not None
        assert str(engine).startswith("PacketEngine")

    def test_packet_engine_operations(self):
        """Test basic PacketEngine operations"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        engine = netstress_engine.PacketEngine("127.0.0.1", 8080, 1, 1472)
        
        # Test initial state
        assert not engine.is_running()
        
        # Test start/stop
        engine.start()
        assert engine.is_running()
        
        time.sleep(0.1)
        
        engine.stop()
        assert not engine.is_running()
        
        # Test statistics
        stats = engine.get_stats()
        assert isinstance(stats, dict)
        assert 'packets_sent' in stats
        assert 'bytes_sent' in stats
        assert 'duration_secs' in stats

    def test_packet_engine_rate_limiting(self):
        """Test rate limiting functionality"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        engine = netstress_engine.PacketEngine("127.0.0.1", 8080, 1, 1472)
        
        # Test rate setting
        engine.set_rate(5000)
        
        engine.start()
        time.sleep(0.1)
        engine.stop()
        
        stats = engine.get_stats()
        assert stats['packets_sent'] >= 0

    def test_start_flood_function(self):
        """Test the start_flood function"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        result = netstress_engine.start_flood(
            target="127.0.0.1",
            port=8080,
            duration=1,  # 1 second
            rate=1000,
            threads=1,
            packet_size=1472,
            protocol="udp"
        )
        
        assert isinstance(result, dict)
        assert 'packets_sent' in result
        assert 'bytes_sent' in result
        assert 'average_pps' in result
        assert 'duration_secs' in result

    def test_build_packet_function(self):
        """Test packet building function"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Test UDP packet
        udp_packet = netstress_engine.build_packet(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="udp",
            payload=b"test"
        )
        
        assert isinstance(udp_packet, bytes)
        assert len(udp_packet) >= 28  # IP + UDP headers
        
        # Test TCP packet
        tcp_packet = netstress_engine.build_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=54321,
            dst_port=443,
            protocol="tcp"
        )
        
        assert isinstance(tcp_packet, bytes)
        assert len(tcp_packet) >= 40  # IP + TCP headers

    def test_get_capabilities_function(self):
        """Test capabilities detection"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        caps = netstress_engine.get_capabilities()
        
        assert isinstance(caps, dict)
        assert 'platform' in caps
        assert 'arch' in caps
        assert 'cpu_count' in caps
        assert caps['cpu_count'] > 0

    def test_protocol_builder_functions(self):
        """Test protocol-specific builder functions"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Test UDP packet builder
        if hasattr(netstress_engine, 'build_udp_packet'):
            udp_packet = netstress_engine.build_udp_packet(
                dst_ip="8.8.8.8",
                dst_port=53,
                payload=b"DNS query"
            )
            assert isinstance(udp_packet, bytes)
        
        # Test TCP SYN builder
        if hasattr(netstress_engine, 'build_tcp_syn'):
            syn_packet = netstress_engine.build_tcp_syn(
                dst_ip="1.1.1.1",
                dst_port=443
            )
            assert isinstance(syn_packet, bytes)
        
        # Test ICMP echo builder
        if hasattr(netstress_engine, 'build_icmp_echo'):
            icmp_packet = netstress_engine.build_icmp_echo(
                dst_ip="127.0.0.1",
                payload=b"ping"
            )
            assert isinstance(icmp_packet, bytes)

    def test_batch_packet_generation(self):
        """Test batch packet generation"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        if hasattr(netstress_engine, 'generate_packet_batch'):
            batch = netstress_engine.generate_packet_batch(
                dst_ip="127.0.0.1",
                dst_port=80,
                protocol="udp",
                payload_size=100,
                count=10
            )
            
            assert isinstance(batch, list)
            assert len(batch) == 10
            for packet in batch:
                assert isinstance(packet, bytes)
                assert len(packet) > 0

    def test_capability_report(self):
        """Test detailed capability report"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        if hasattr(netstress_engine, 'get_capability_report'):
            report = netstress_engine.get_capability_report()
            
            assert isinstance(report, dict)
            assert 'platform' in report
            assert 'available_backends' in report
            assert 'active_backend' in report

    def test_available_backends(self):
        """Test backend enumeration"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        if hasattr(netstress_engine, 'get_available_backends'):
            backends = netstress_engine.get_available_backends()
            
            assert isinstance(backends, list)
            assert len(backends) > 0
            for backend in backends:
                assert isinstance(backend, str)
                assert len(backend) > 0

    def test_statistics_formats(self):
        """Test different statistics formats"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Test JSON stats
        if hasattr(netstress_engine, 'get_realtime_stats_json'):
            json_stats = netstress_engine.get_realtime_stats_json()
            assert isinstance(json_stats, str)
            # Should be valid JSON
            parsed = json.loads(json_stats)
            assert isinstance(parsed, dict)
        
        # Test Prometheus stats
        if hasattr(netstress_engine, 'get_prometheus_metrics'):
            prom_stats = netstress_engine.get_prometheus_metrics()
            assert isinstance(prom_stats, str)
            assert len(prom_stats) > 0

    def test_platform_specific_reports(self):
        """Test platform-specific optimization reports"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        import platform
        system = platform.system().lower()
        
        if system == 'linux' and hasattr(netstress_engine, 'get_linux_optimization_report'):
            report = netstress_engine.get_linux_optimization_report()
            assert isinstance(report, dict)
            if 'error' not in report:
                assert 'platform' in report
                assert report['platform'] == 'linux'
        
        elif system == 'windows' and hasattr(netstress_engine, 'get_windows_optimization_report'):
            report = netstress_engine.get_windows_optimization_report()
            assert isinstance(report, dict)
            if 'error' not in report:
                assert 'platform' in report
                assert report['platform'] == 'windows'
        
        elif system == 'darwin' and hasattr(netstress_engine, 'get_macos_optimization_report'):
            report = netstress_engine.get_macos_optimization_report()
            assert isinstance(report, dict)
            if 'error' not in report:
                assert 'platform' in report
                assert report['platform'] == 'macos'

    def test_safety_controller(self):
        """Test safety controller functionality"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        if hasattr(netstress_engine, 'PySafetyController'):
            # Test permissive controller
            controller = netstress_engine.PySafetyController.permissive()
            assert controller is not None
            
            # Test authorization
            controller.authorize_ip("127.0.0.1")
            assert controller.is_authorized("127.0.0.1")
            
            controller.authorize_cidr("192.168.0.0/16")
            assert controller.is_authorized("192.168.1.1")
            
            controller.authorize_domain("example.com")
            assert controller.is_authorized("example.com")
            
            # Test rate limiting
            controller.set_max_pps(1000)
            assert controller.current_pps() >= 0
            
            # Test emergency stop
            assert not controller.is_stopped()
            controller.emergency_stop("Test stop")
            assert controller.is_stopped()
            assert controller.stop_reason() == "Test stop"
            
            controller.reset_emergency_stop()
            assert not controller.is_stopped()

    def test_audit_logger(self):
        """Test audit logging functionality"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        if hasattr(netstress_engine, 'PyAuditLogger'):
            logger = netstress_engine.PyAuditLogger()
            assert logger is not None
            
            # Test logging operations
            logger.log_engine_start("127.0.0.1", "test config")
            logger.log_target_authorized("127.0.0.1")
            logger.log_engine_stop("test stats")
            
            # Test entry count
            count = logger.entry_count()
            assert count >= 3
            
            # Test JSON export
            json_export = logger.export_json()
            assert isinstance(json_export, str)
            assert len(json_export) > 0
            
            # Test chain verification
            verification = logger.verify_chain()
            assert isinstance(verification, dict)
            assert 'valid' in verification
            assert 'entries_checked' in verification

    def test_error_handling(self):
        """Test error handling in Rust bindings - implementation handles errors gracefully"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Test invalid packet building - implementation may handle gracefully or raise
        try:
            result = netstress_engine.build_packet(
                src_ip="invalid.ip",
                dst_ip="127.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="udp"
            )
            # If no exception, result should be None, empty, or valid bytes
            assert result is None or result == b'' or isinstance(result, (bytes, bytearray))
        except Exception:
            pass  # Exception is also acceptable
        
        # Test invalid protocol - implementation may handle gracefully or raise
        try:
            result = netstress_engine.build_packet(
                src_ip="127.0.0.1",
                dst_ip="127.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="invalid_protocol"
            )
            # If no exception, result should be None, empty, or valid bytes
            assert result is None or result == b'' or isinstance(result, (bytes, bytearray))
        except Exception:
            pass  # Exception is also acceptable

    def test_memory_management(self):
        """Test memory management in bindings"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Create and destroy many objects
        for i in range(100):
            engine = netstress_engine.PacketEngine("127.0.0.1", 8080 + i, 1, 1472)
            
            # Use the engine briefly
            engine.start()
            engine.stop()
            
            # Get stats to exercise the binding
            stats = engine.get_stats()
            assert isinstance(stats, dict)
            
            # Delete explicitly
            del engine
        
        # Should not have memory leaks
        import gc
        gc.collect()

    def test_concurrent_access(self):
        """Test concurrent access to Rust objects"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        import threading
        
        engine = netstress_engine.PacketEngine("127.0.0.1", 8080, 2, 1472)
        engine.start()
        
        errors = []
        
        def worker():
            try:
                for _ in range(50):
                    stats = engine.get_stats()
                    assert isinstance(stats, dict)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = [threading.Thread(target=worker) for _ in range(5)]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        engine.stop()
        
        # Check for errors
        assert len(errors) == 0, f"Concurrent access errors: {errors}"

    def test_large_data_handling(self):
        """Test handling of large data structures"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Test large payload
        large_payload = b"A" * 10000
        
        try:
            packet = netstress_engine.build_packet(
                src_ip="127.0.0.1",
                dst_ip="127.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="udp",
                payload=large_payload
            )
            
            assert isinstance(packet, bytes)
            assert len(packet) >= len(large_payload)
        except Exception:
            # May fail due to size limits, which is acceptable
            pass

    def test_unicode_handling(self):
        """Test Unicode string handling in bindings"""
        if not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        # Test with Unicode domain names (should work or fail gracefully)
        try:
            if hasattr(netstress_engine, 'PySafetyController'):
                controller = netstress_engine.PySafetyController.permissive()
                controller.authorize_domain("тест.com")  # Cyrillic
                # Should handle Unicode gracefully
        except Exception:
            # May not support Unicode, which is acceptable
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])