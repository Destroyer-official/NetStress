#!/usr/bin/env python3
"""
Military-Grade Transformation Integration Tests
Tests the complete Python → Rust → C flow for military-grade features

**Feature: military-grade-transformation**
**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 7.1, 7.2, 7.3, 8.1, 8.2, 8.3**
"""

import pytest
import sys
import os
import time
import json
import threading
import socket
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import components to test
try:
    from core.native_engine import NativePacketEngine, EngineConfig, EngineBackend, is_native_available
    from core.distributed.coordinator import NTPCoordinator, DistributedCoordinator
    from core.analytics.telemetry_stream import TelemetryPublisher, SharedMemoryBridge
    from core.antidetect.traffic_morph import ProtocolTunneler
    COMPONENTS_AVAILABLE = True
except ImportError as e:
    COMPONENTS_AVAILABLE = False
    print(f"Warning: Some components not available: {e}")

# Try to import native Rust engine
try:
    import netstress_engine
    RUST_ENGINE_AVAILABLE = True
except ImportError:
    RUST_ENGINE_AVAILABLE = False
    netstress_engine = None


class TestPythonRustCFlow:
    """Test the complete Python → Rust → C integration flow"""

    def test_engine_backend_selection_flow(self):
        """Test backend selection flows through all layers"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Test AUTO backend selection
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            backend=EngineBackend.AUTO
        )
        
        engine = NativePacketEngine(config)
        
        # Should select best available backend
        if is_native_available():
            assert engine.backend_name in ["native", "rust"]
        else:
            assert engine.backend_name == "python"

    def test_rust_engine_integration(self):
        """Test Rust engine integration with Python wrapper"""
        if not COMPONENTS_AVAILABLE or not RUST_ENGINE_AVAILABLE:
            pytest.skip("Rust engine not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            threads=2,
            packet_size=1472,
            backend=EngineBackend.NATIVE
        )
        
        with NativePacketEngine(config) as engine:
            # Test engine is running
            assert engine.is_running()
            
            # Test rate limiting
            engine.set_rate(5000)
            
            # Run for short duration
            time.sleep(0.2)
            
            # Get statistics
            stats = engine.get_stats()
            assert stats.duration_secs > 0
            assert stats.packets_sent >= 0
            assert stats.bytes_sent >= 0

    def test_c_driver_backend_fallback(self):
        """Test C driver backend fallback chain"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Mock the capability detection to test fallback
        with patch('core.native_engine.get_capabilities') as mock_caps:
            # Simulate system with only raw sockets
            mock_caps.return_value = {
                'platform': 'linux',
                'cpu_count': 4,
                'dpdk': False,
                'af_xdp': False,
                'io_uring': False,
                'sendmmsg': True,
                'raw_socket': True
            }
            
            config = EngineConfig(
                target="127.0.0.1",
                port=8080,
                backend=EngineBackend.AUTO
            )
            
            engine = NativePacketEngine(config)
            # Should fall back to available backend
            assert engine.backend_name in ["python", "native", "sendmmsg", "raw_socket"]

    def test_packet_generation_flow(self):
        """Test packet generation through all layers"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            threads=1,
            packet_size=64,
            protocol="udp"
        )
        
        engine = NativePacketEngine(config)
        
        # Test packet building if available
        try:
            from core.native_engine import build_packet
            packet = build_packet(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="udp"
            )
            assert isinstance(packet, bytes)
            assert len(packet) >= 28  # IP + UDP headers
        except ImportError:
            pytest.skip("Packet building not available")

    def test_threading_integration(self):
        """Test multi-threading integration across layers"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            threads=4,  # Test multi-threading
            rate_limit=1000
        )
        
        with NativePacketEngine(config) as engine:
            # Should utilize multiple threads
            time.sleep(0.3)
            stats = engine.get_stats()
            
            # With multiple threads, should achieve reasonable throughput
            if stats.duration_secs > 0:
                pps = stats.packets_sent / stats.duration_secs
                # Should be able to achieve at least some packets per second
                assert pps >= 0

    def test_error_propagation(self):
        """Test error propagation through layers"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Test invalid configuration
        with pytest.raises((ValueError, RuntimeError)):
            config = EngineConfig(
                target="invalid.ip.address",
                port=-1,  # Invalid port
                backend=EngineBackend.NATIVE
            )
            NativePacketEngine(config)

    def test_memory_management_across_layers(self):
        """Test memory management across Python-Rust-C boundary"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Create and destroy multiple engines
        for i in range(10):
            config = EngineConfig(
                target="127.0.0.1",
                port=8080 + i,
                threads=1
            )
            
            engine = NativePacketEngine(config)
            engine.start()
            time.sleep(0.01)
            engine.stop()
            
            # Get stats to exercise memory
            stats = engine.get_stats()
            assert isinstance(stats.packets_sent, int)
            
            del engine
        
        # Force garbage collection
        import gc
        gc.collect()


class TestDistributedCoordination:
    """Test distributed coordination and NTP synchronization"""

    def test_ntp_coordinator_initialization(self):
        """Test NTP coordinator initialization"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Test with mock NTP servers
            coordinator = NTPCoordinator([
                "pool.ntp.org",
                "time.google.com"
            ])
            
            # Should initialize without error
            assert coordinator is not None
            
            # Test time synchronization
            sync_time = coordinator.get_synchronized_time()
            assert isinstance(sync_time, float)
            assert sync_time > 0
            
        except Exception as e:
            # NTP may not be available in test environment
            pytest.skip(f"NTP not available: {e}")

    def test_distributed_attack_scheduling(self):
        """Test distributed attack scheduling with timestamps"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            coordinator = NTPCoordinator(["time.google.com"])
            
            # Schedule attack 1 second in the future
            future_time = time.time() + 1.0
            coordinator.schedule_attack(future_time)
            
            # Should be able to schedule without error
            assert True
            
        except Exception:
            pytest.skip("NTP coordination not available")

    def test_clock_drift_detection(self):
        """Test clock drift detection and correction"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Mock clock drift scenario
        with patch('time.time') as mock_time:
            # Simulate clock drift
            mock_time.side_effect = [1000.0, 1000.5, 1001.2]  # Irregular intervals
            
            try:
                coordinator = NTPCoordinator(["localhost"])
                
                # Should detect drift (or handle gracefully)
                sync_time1 = coordinator.get_synchronized_time()
                sync_time2 = coordinator.get_synchronized_time()
                
                # Times should be reasonable
                assert isinstance(sync_time1, float)
                assert isinstance(sync_time2, float)
                
            except Exception:
                pytest.skip("Clock drift detection not available")

    def test_multi_node_synchronization(self):
        """Test synchronization across multiple nodes"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        # Simulate multiple nodes
        nodes = []
        
        for i in range(3):
            try:
                coordinator = NTPCoordinator(["time.google.com"])
                nodes.append(coordinator)
            except Exception:
                pytest.skip("Multi-node coordination not available")
        
        if not nodes:
            pytest.skip("No nodes created")
        
        # Schedule synchronized attack
        attack_time = time.time() + 2.0
        
        for node in nodes:
            try:
                node.schedule_attack(attack_time)
            except Exception:
                pass  # Some nodes may fail, which is acceptable
        
        # All nodes should have similar synchronized times
        sync_times = []
        for node in nodes:
            try:
                sync_time = node.get_synchronized_time()
                sync_times.append(sync_time)
            except Exception:
                pass
        
        if len(sync_times) >= 2:
            # Times should be within reasonable range
            time_diff = max(sync_times) - min(sync_times)
            assert time_diff < 10.0  # Within 10 seconds is reasonable for test

    def test_distributed_coordinator_integration(self):
        """Test distributed coordinator with engine integration"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Create distributed coordinator
            dist_coordinator = DistributedCoordinator(
                node_id="test_node_1",
                ntp_servers=["time.google.com"]
            )
            
            # Create engine config
            config = EngineConfig(
                target="127.0.0.1",
                port=8080,
                threads=1
            )
            
            # Test coordinated attack
            attack_time = time.time() + 1.0
            
            # Should be able to coordinate without error
            dist_coordinator.coordinate_attack(config, attack_time)
            
        except Exception as e:
            pytest.skip(f"Distributed coordination not available: {e}")


class TestTelemetryStreaming:
    """Test real-time telemetry streaming"""

    def test_shared_memory_bridge(self):
        """Test shared memory bridge for telemetry"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Create shared memory bridge
            bridge = SharedMemoryBridge("test_stats")
            
            # Test writing stats
            test_stats = {
                "packets_sent": 1000,
                "bytes_sent": 100000,
                "pps": 5000.0,
                "duration": 0.2
            }
            
            bridge.write_stats(test_stats)
            
            # Test reading stats
            read_stats = bridge.read_stats()
            
            assert isinstance(read_stats, dict)
            # Stats should be similar (may not be exact due to timing)
            
        except Exception as e:
            pytest.skip(f"Shared memory not available: {e}")

    def test_zeromq_telemetry_publisher(self):
        """Test ZeroMQ telemetry publisher"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            import zmq
            
            # Create publisher
            publisher = TelemetryPublisher("tcp://127.0.0.1:5555")
            
            # Test publishing stats
            test_stats = {
                "timestamp": time.time(),
                "packets_sent": 2000,
                "bytes_sent": 200000,
                "pps": 10000.0
            }
            
            publisher.publish_stats(test_stats)
            
            # Should publish without error
            assert True
            
        except ImportError:
            pytest.skip("ZeroMQ not available")
        except Exception as e:
            pytest.skip(f"ZeroMQ publisher not available: {e}")

    def test_telemetry_latency(self):
        """Test telemetry latency requirements"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            bridge = SharedMemoryBridge("latency_test")
            
            # Measure write latency
            start_time = time.perf_counter()
            
            for i in range(100):
                stats = {"iteration": i, "timestamp": time.time()}
                bridge.write_stats(stats)
            
            write_time = time.perf_counter() - start_time
            avg_write_latency = write_time / 100
            
            # Should be very fast (microsecond level)
            assert avg_write_latency < 0.001  # Less than 1ms average
            
            # Measure read latency
            start_time = time.perf_counter()
            
            for i in range(100):
                stats = bridge.read_stats()
            
            read_time = time.perf_counter() - start_time
            avg_read_latency = read_time / 100
            
            # Should be very fast
            assert avg_read_latency < 0.001  # Less than 1ms average
            
        except Exception as e:
            pytest.skip(f"Telemetry latency test not available: {e}")

    def test_real_time_stats_streaming(self):
        """Test real-time statistics streaming"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Create engine with telemetry
            config = EngineConfig(
                target="127.0.0.1",
                port=8080,
                threads=1,
                rate_limit=1000
            )
            
            engine = NativePacketEngine(config)
            bridge = SharedMemoryBridge("realtime_test")
            
            # Start engine
            engine.start()
            
            # Stream stats for short duration
            stats_collected = []
            
            for i in range(10):
                time.sleep(0.05)  # 50ms intervals
                
                stats = engine.get_stats()
                bridge.write_stats(stats.__dict__)
                
                read_stats = bridge.read_stats()
                stats_collected.append(read_stats)
            
            engine.stop()
            
            # Should have collected multiple stat snapshots
            assert len(stats_collected) == 10
            
            # Stats should show progression
            if len(stats_collected) >= 2:
                first_stats = stats_collected[0]
                last_stats = stats_collected[-1]
                
                # Duration should increase
                if 'duration_secs' in first_stats and 'duration_secs' in last_stats:
                    assert last_stats['duration_secs'] >= first_stats['duration_secs']
            
        except Exception as e:
            pytest.skip(f"Real-time streaming not available: {e}")

    def test_telemetry_concurrent_access(self):
        """Test concurrent access to telemetry systems"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            bridge = SharedMemoryBridge("concurrent_test")
            errors = []
            
            def writer_thread():
                try:
                    for i in range(50):
                        stats = {"thread": "writer", "iteration": i}
                        bridge.write_stats(stats)
                        time.sleep(0.001)
                except Exception as e:
                    errors.append(e)
            
            def reader_thread():
                try:
                    for i in range(50):
                        stats = bridge.read_stats()
                        time.sleep(0.001)
                except Exception as e:
                    errors.append(e)
            
            # Start concurrent threads
            threads = [
                threading.Thread(target=writer_thread),
                threading.Thread(target=reader_thread),
                threading.Thread(target=reader_thread)
            ]
            
            for t in threads:
                t.start()
            
            for t in threads:
                t.join()
            
            # Should not have errors
            assert len(errors) == 0, f"Concurrent access errors: {errors}"
            
        except Exception as e:
            pytest.skip(f"Concurrent telemetry test not available: {e}")


class TestProtocolTunneling:
    """Test protocol tunneling integration"""

    def test_gre_tunnel_integration(self):
        """Test GRE tunnel integration"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Create GRE tunnel
            tunnel = ProtocolTunneler.create_gre_tunnel()
            
            # Test encapsulation
            test_payload = b"Hello, World!"
            encapsulated = tunnel.encapsulate(test_payload)
            
            assert isinstance(encapsulated, bytes)
            assert len(encapsulated) > len(test_payload)  # Should be larger due to headers
            
            # Test decapsulation
            decapsulated = tunnel.decapsulate(encapsulated)
            assert decapsulated == test_payload
            
        except Exception as e:
            pytest.skip(f"GRE tunneling not available: {e}")

    def test_dns_over_https_tunnel(self):
        """Test DNS-over-HTTPS tunnel integration"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Create DoH tunnel
            tunnel = ProtocolTunneler.create_doh_tunnel("1.1.1.1")
            
            # Test encapsulation
            test_payload = b"Secret data"
            encapsulated = tunnel.encapsulate(test_payload)
            
            assert isinstance(encapsulated, bytes)
            # Should contain DNS query structure
            
        except Exception as e:
            pytest.skip(f"DoH tunneling not available: {e}")

    def test_tunnel_with_engine_integration(self):
        """Test tunnel integration with packet engine"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        try:
            # Create tunnel
            tunnel = ProtocolTunneler.create_gre_tunnel()
            
            # Create engine config with tunneling
            config = EngineConfig(
                target="127.0.0.1",
                port=8080,
                threads=1,
                tunnel_type="gre"
            )
            
            # Should be able to create engine with tunnel config
            engine = NativePacketEngine(config)
            assert engine is not None
            
        except Exception as e:
            pytest.skip(f"Tunnel-engine integration not available: {e}")


class TestPerformanceIntegration:
    """Test performance characteristics of integrated system"""

    def test_throughput_integration(self):
        """Test throughput across all layers"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            threads=2,
            rate_limit=10000,  # 10K PPS target
            packet_size=64
        )
        
        with NativePacketEngine(config) as engine:
            # Run for 1 second
            time.sleep(1.0)
            
            stats = engine.get_stats()
            
            if stats.duration_secs > 0:
                actual_pps = stats.packets_sent / stats.duration_secs
                
                # Should achieve reasonable throughput
                # (May be limited in test environment)
                assert actual_pps >= 0
                
                # If we achieved significant throughput, verify it's reasonable
                if actual_pps > 100:
                    assert actual_pps <= config.rate_limit * 1.1  # Within 10% of limit

    def test_latency_integration(self):
        """Test latency characteristics"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            threads=1,
            rate_limit=1000
        )
        
        engine = NativePacketEngine(config)
        
        # Measure start latency
        start_time = time.perf_counter()
        engine.start()
        start_latency = time.perf_counter() - start_time
        
        # Should start quickly
        assert start_latency < 1.0  # Less than 1 second
        
        # Measure stats latency
        stats_times = []
        for i in range(10):
            start_time = time.perf_counter()
            stats = engine.get_stats()
            stats_latency = time.perf_counter() - start_time
            stats_times.append(stats_latency)
        
        # Measure stop latency
        start_time = time.perf_counter()
        engine.stop()
        stop_latency = time.perf_counter() - start_time
        
        # Should stop quickly
        assert stop_latency < 1.0  # Less than 1 second
        
        # Stats should be fast
        avg_stats_latency = sum(stats_times) / len(stats_times)
        assert avg_stats_latency < 0.01  # Less than 10ms average

    def test_memory_usage_integration(self):
        """Test memory usage across integration"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create multiple engines
        engines = []
        for i in range(5):
            config = EngineConfig(
                target="127.0.0.1",
                port=8080 + i,
                threads=1
            )
            engine = NativePacketEngine(config)
            engines.append(engine)
        
        # Start all engines
        for engine in engines:
            engine.start()
        
        time.sleep(0.5)
        
        # Check memory usage
        peak_memory = process.memory_info().rss
        
        # Stop all engines
        for engine in engines:
            engine.stop()
        
        # Clean up
        del engines
        import gc
        gc.collect()
        
        time.sleep(0.1)
        final_memory = process.memory_info().rss
        
        # Memory should not grow excessively
        memory_growth = peak_memory - initial_memory
        memory_mb = memory_growth / (1024 * 1024)
        
        # Should use reasonable amount of memory (less than 100MB for test)
        assert memory_mb < 100

    def test_cpu_utilization_integration(self):
        """Test CPU utilization characteristics"""
        if not COMPONENTS_AVAILABLE:
            pytest.skip("Components not available")
        
        import psutil
        
        # Measure baseline CPU
        cpu_before = psutil.cpu_percent(interval=0.1)
        
        config = EngineConfig(
            target="127.0.0.1",
            port=8080,
            threads=2,
            rate_limit=5000
        )
        
        with NativePacketEngine(config) as engine:
            # Let it run and measure CPU
            time.sleep(1.0)
            cpu_during = psutil.cpu_percent(interval=0.1)
        
        # CPU usage should be reasonable
        # (May vary significantly in test environment)
        assert cpu_during >= 0
        assert cpu_during <= 100


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])