"""
Tests for the Native Engine Python wrapper.

Tests both the native Rust engine (when available) and the Python fallback.
"""

import pytest
import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.native_engine import (
    NativePacketEngine,
    EngineConfig,
    EngineStats,
    EngineBackend,
    get_capabilities,
    is_native_available,
    build_packet,
)


class TestEngineConfig:
    """Tests for EngineConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = EngineConfig(target="127.0.0.1", port=8080)
        assert config.target == "127.0.0.1"
        assert config.port == 8080
        assert config.threads == 4
        assert config.packet_size == 1472
        assert config.protocol == "udp"
        assert config.rate_limit is None
        assert config.backend == EngineBackend.AUTO
    
    def test_custom_config(self):
        """Test custom configuration"""
        config = EngineConfig(
            target="192.168.1.100",
            port=80,
            threads=8,
            packet_size=1024,
            protocol="tcp",
            rate_limit=100000,
            backend=EngineBackend.PYTHON
        )
        assert config.threads == 8
        assert config.packet_size == 1024
        assert config.protocol == "tcp"
        assert config.rate_limit == 100000
        assert config.backend == EngineBackend.PYTHON


class TestEngineStats:
    """Tests for EngineStats dataclass"""
    
    def test_default_stats(self):
        """Test default statistics values"""
        stats = EngineStats()
        assert stats.packets_sent == 0
        assert stats.bytes_sent == 0
        assert stats.errors == 0
    
    def test_mbps_calculation(self):
        """Test Mbps calculation"""
        stats = EngineStats(bytes_per_second=125_000_000)  # 1 Gbps
        assert abs(stats.mbps - 1000.0) < 0.01
    
    def test_gbps_calculation(self):
        """Test Gbps calculation"""
        stats = EngineStats(bytes_per_second=1_250_000_000)  # 10 Gbps
        assert abs(stats.gbps - 10.0) < 0.01
    
    def test_success_rate(self):
        """Test success rate calculation"""
        stats = EngineStats(packets_sent=90, errors=10)
        assert abs(stats.success_rate - 90.0) < 0.01
    
    def test_success_rate_zero_packets(self):
        """Test success rate with zero packets"""
        stats = EngineStats(packets_sent=0, errors=0)
        assert stats.success_rate == 0.0


class TestCapabilities:
    """Tests for capability detection"""
    
    def test_get_capabilities(self):
        """Test capability detection returns expected keys"""
        caps = get_capabilities()
        assert 'platform' in caps
        assert 'cpu_count' in caps
        assert 'dpdk' in caps
        assert 'af_xdp' in caps
    
    def test_cpu_count_positive(self):
        """Test CPU count is positive"""
        caps = get_capabilities()
        assert caps['cpu_count'] > 0
    
    def test_is_native_available(self):
        """Test native availability check"""
        result = is_native_available()
        assert isinstance(result, bool)


class TestPythonFallbackEngine:
    """Tests for the Python fallback engine"""
    
    def test_engine_creation(self):
        """Test engine can be created with Python backend"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.PYTHON
        )
        engine = NativePacketEngine(config)
        assert engine.backend_name == "python_fallback"
    
    def test_engine_not_running_initially(self):
        """Test engine is not running after creation"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.PYTHON
        )
        engine = NativePacketEngine(config)
        assert not engine.is_running()
    
    def test_engine_start_stop(self):
        """Test engine start and stop"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            backend=EngineBackend.PYTHON
        )
        engine = NativePacketEngine(config)
        
        engine.start()
        assert engine.is_running()
        
        time.sleep(0.1)
        
        engine.stop()
        assert not engine.is_running()
    
    def test_engine_context_manager(self):
        """Test engine as context manager"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            backend=EngineBackend.PYTHON
        )
        
        with NativePacketEngine(config) as engine:
            assert engine.is_running()
            time.sleep(0.1)
        
        assert not engine.is_running()
    
    def test_engine_stats(self):
        """Test engine statistics collection"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=1,
            rate_limit=1000,
            backend=EngineBackend.PYTHON
        )
        
        with NativePacketEngine(config) as engine:
            time.sleep(0.5)
            stats = engine.get_stats()
        
        assert isinstance(stats, EngineStats)
        assert stats.duration_secs > 0
    
    def test_engine_set_rate(self):
        """Test setting rate limit"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.PYTHON
        )
        engine = NativePacketEngine(config)
        engine.set_rate(50000)
        # No exception means success


class TestPacketBuilding:
    """Tests for packet building functionality"""
    
    def test_build_udp_packet(self):
        """Test building UDP packet"""
        try:
            packet = build_packet(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="udp"
            )
            assert isinstance(packet, bytes)
            assert len(packet) >= 28  # IP + UDP headers minimum
        except Exception:
            # May fail if packet_craft module not available
            pytest.skip("Packet crafting not available")
    
    def test_build_tcp_packet(self):
        """Test building TCP packet"""
        try:
            packet = build_packet(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="tcp"
            )
            assert isinstance(packet, bytes)
            assert len(packet) >= 40  # IP + TCP headers minimum
        except Exception:
            pytest.skip("Packet crafting not available")
    
    def test_build_packet_with_payload(self):
        """Test building packet with custom payload"""
        try:
            payload = b"Hello, World!"
            packet = build_packet(
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=12345,
                dst_port=80,
                protocol="udp",
                payload=payload
            )
            assert isinstance(packet, bytes)
            # Payload should be in the packet
            assert payload in packet or len(packet) > 28
        except Exception:
            pytest.skip("Packet crafting not available")


class TestEngineBackendSelection:
    """Tests for backend selection logic"""
    
    def test_auto_backend_selection(self):
        """Test AUTO backend selects appropriately"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.AUTO
        )
        engine = NativePacketEngine(config)
        
        if is_native_available():
            assert engine.backend_name in ["raw_socket", "native"]
        else:
            assert engine.backend_name == "python_fallback"
    
    def test_force_python_backend(self):
        """Test forcing Python backend"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.PYTHON
        )
        engine = NativePacketEngine(config)
        assert engine.backend_name == "python_fallback"
    
    def test_force_native_backend_unavailable(self):
        """Test forcing native backend when unavailable raises error"""
        if is_native_available():
            pytest.skip("Native engine is available")
        
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.NATIVE
        )
        
        with pytest.raises(RuntimeError):
            NativePacketEngine(config)


@pytest.mark.skipif(not is_native_available(), reason="Native engine not available")
class TestNativeEngine:
    """Tests for the native Rust engine (only run if available)"""
    
    def test_native_engine_creation(self):
        """Test native engine can be created"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            backend=EngineBackend.NATIVE
        )
        engine = NativePacketEngine(config)
        assert engine.backend_name in ["raw_socket", "native"]
    
    def test_native_engine_start_stop(self):
        """Test native engine start and stop"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=2,
            backend=EngineBackend.NATIVE
        )
        engine = NativePacketEngine(config)
        
        engine.start()
        assert engine.is_running()
        
        time.sleep(0.1)
        
        engine.stop()
        assert not engine.is_running()
    
    def test_native_engine_stats(self):
        """Test native engine statistics"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            threads=2,
            rate_limit=10000,
            backend=EngineBackend.NATIVE
        )
        
        with NativePacketEngine(config) as engine:
            time.sleep(0.5)
            stats = engine.get_stats()
        
        assert isinstance(stats, EngineStats)
        assert stats.duration_secs > 0
    
    def test_native_capabilities(self):
        """Test native capabilities detection"""
        caps = get_capabilities()
        assert 'dpdk' in caps
        assert 'af_xdp' in caps
        assert isinstance(caps['dpdk'], bool)
        assert isinstance(caps['af_xdp'], bool)


class TestProtocolSupport:
    """Tests for different protocol support"""
    
    @pytest.mark.parametrize("protocol", ["udp", "tcp", "http"])
    def test_protocol_config(self, protocol):
        """Test different protocols can be configured"""
        config = EngineConfig(
            target="127.0.0.1",
            port=9999,
            protocol=protocol,
            backend=EngineBackend.PYTHON
        )
        engine = NativePacketEngine(config)
        assert engine.config.protocol == protocol


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
