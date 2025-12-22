"""
Test Layer 4 Attack Vectors

Tests for UDP flood, TCP flag attacks, and ICMP flood implementations.
"""

import pytest
import asyncio
import socket
from unittest.mock import patch, MagicMock

from core.attacks.layer4 import (
    Layer4Config, PayloadGenerator, IPSpoofing,
    UDPFlood, TCPFlagAttack, ICMPFlood, TCPConnectionExhaustion,
    create_udp_flood, create_syn_flood, create_ping_flood
)


class TestPayloadGenerator:
    """Test payload generation functionality"""
    
    def test_random_payload(self):
        """Test random payload generation"""
        payload = PayloadGenerator.generate_payload(100, 'random')
        assert len(payload) == 100
        assert isinstance(payload, bytes)
    
    def test_zeros_payload(self):
        """Test zeros payload generation"""
        payload = PayloadGenerator.generate_payload(50, 'zeros')
        assert len(payload) == 50
        assert payload == b'\x00' * 50
    
    def test_ones_payload(self):
        """Test ones payload generation"""
        payload = PayloadGenerator.generate_payload(30, 'ones')
        assert len(payload) == 30
        assert payload == b'\xff' * 30
    
    def test_sequence_payload(self):
        """Test sequence payload generation"""
        payload = PayloadGenerator.generate_payload(10, 'sequence')
        assert len(payload) == 10
        assert payload == bytes(range(10))
    
    def test_custom_payload(self):
        """Test custom payload generation"""
        custom = b'ABCD'
        payload = PayloadGenerator.generate_payload(10, 'custom', custom)
        assert len(payload) == 10
        assert payload == b'ABCDABCDAB'
    
    def test_malformed_payload(self):
        """Test malformed payload generation"""
        payload = PayloadGenerator.generate_malformed_payload(1000)
        assert len(payload) == 1000
        assert isinstance(payload, bytes)


class TestIPSpoofing:
    """Test IP spoofing functionality"""
    
    def test_generate_random_ip(self):
        """Test random IP generation"""
        ip = IPSpoofing.generate_random_ip()
        parts = ip.split('.')
        assert len(parts) == 4
        for part in parts:
            assert 0 <= int(part) <= 255
    
    def test_generate_ip_from_range(self):
        """Test IP generation from range"""
        ip = IPSpoofing.generate_ip_from_range('192.168.1.1', '192.168.1.254')
        parts = ip.split('.')
        assert parts[:3] == ['192', '168', '1']
        assert 1 <= int(parts[3]) <= 254


class TestLayer4Config:
    """Test Layer 4 configuration"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = Layer4Config(target='127.0.0.1', port=80)
        assert config.target == '127.0.0.1'
        assert config.port == 80
        assert config.duration == 60
        assert config.rate_limit == 10000
        assert config.payload_size == 1024
        assert config.payload_pattern == 'random'
        assert config.spoof_source is False


class TestUDPFlood:
    """Test UDP flood attack"""
    
    def test_udp_flood_creation(self):
        """Test UDP flood attack creation"""
        config = Layer4Config(target='127.0.0.1', port=80, duration=1)
        attack = UDPFlood(config)
        assert attack.config.target == '127.0.0.1'
        assert attack.config.port == 80
    
    @pytest.mark.asyncio
    @patch('socket.socket')
    async def test_udp_flood_socket_worker(self, mock_socket):
        """Test UDP flood socket worker"""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.sendto.return_value = 1024
        
        config = Layer4Config(target='127.0.0.1', port=80, duration=0.1, rate_limit=10)
        attack = UDPFlood(config)
        
        # Start attack for short duration
        await attack.start()
        
        # Verify socket operations were called
        mock_socket.assert_called()
        mock_sock.sendto.assert_called()
        assert attack.stats.packets_sent > 0
    
    def test_create_udp_flood_factory(self):
        """Test UDP flood factory function"""
        attack = create_udp_flood('127.0.0.1', 80, payload_size=512)
        assert isinstance(attack, UDPFlood)
        assert attack.config.target == '127.0.0.1'
        assert attack.config.port == 80
        assert attack.config.payload_size == 512


class TestTCPFlagAttack:
    """Test TCP flag attacks"""
    
    def test_tcp_flag_parsing(self):
        """Test TCP flag parsing"""
        config = Layer4Config(target='127.0.0.1', port=80)
        
        # Test single flag
        attack = TCPFlagAttack(config, 'SYN')
        assert attack.tcp_flags == 0x02
        
        # Test multiple flags
        attack = TCPFlagAttack(config, ['SYN', 'ACK'])
        assert attack.tcp_flags == 0x12  # SYN (0x02) | ACK (0x10)
        
        # Test integer flag
        attack = TCPFlagAttack(config, 0x04)
        assert attack.tcp_flags == 0x04
    
    def test_create_syn_flood_factory(self):
        """Test SYN flood factory function"""
        attack = create_syn_flood('127.0.0.1', 80)
        assert isinstance(attack, TCPFlagAttack)
        assert attack.tcp_flags == 0x02  # SYN flag


class TestICMPFlood:
    """Test ICMP flood attack"""
    
    def test_icmp_flood_creation(self):
        """Test ICMP flood attack creation"""
        config = Layer4Config(target='127.0.0.1', port=0)
        attack = ICMPFlood(config, 'ECHO_REQUEST')
        assert attack.icmp_type == 8  # ECHO_REQUEST
        assert attack.icmp_code == 0
    
    def test_icmp_types(self):
        """Test ICMP type mapping"""
        config = Layer4Config(target='127.0.0.1', port=0)
        
        attack = ICMPFlood(config, 'ECHO_REPLY')
        assert attack.icmp_type == 0
        
        attack = ICMPFlood(config, 'DEST_UNREACHABLE', 1)
        assert attack.icmp_type == 3
        assert attack.icmp_code == 1
    
    def test_create_ping_flood_factory(self):
        """Test ping flood factory function"""
        attack = create_ping_flood('127.0.0.1')
        assert isinstance(attack, ICMPFlood)
        assert attack.icmp_type == 8  # ECHO_REQUEST


class TestTCPConnectionExhaustion:
    """Test TCP connection exhaustion attack"""
    
    def test_connection_exhaustion_creation(self):
        """Test connection exhaustion attack creation"""
        config = Layer4Config(target='127.0.0.1', port=80)
        attack = TCPConnectionExhaustion(config, hold_time=10.0, max_connections=100)
        assert attack.hold_time == 10.0
        assert attack.max_connections == 100


class TestAttackStats:
    """Test attack statistics"""
    
    def test_stats_calculation(self):
        """Test statistics calculations"""
        config = Layer4Config(target='127.0.0.1', port=80)
        attack = UDPFlood(config)
        
        # Simulate some activity
        attack.stats.packets_sent = 1000
        attack.stats.bytes_sent = 1024000
        attack.stats.start_time = attack.stats.start_time - 1.0  # 1 second ago
        
        stats = attack.get_stats()
        assert stats['packets_sent'] == 1000
        assert stats['bytes_sent'] == 1024000
        assert stats['pps'] > 0
        assert stats['mbps'] > 0


@pytest.mark.asyncio
async def test_attack_lifecycle():
    """Test complete attack lifecycle"""
    config = Layer4Config(target='127.0.0.1', port=80, duration=0.1, rate_limit=10)
    attack = UDPFlood(config)
    
    # Test start and stop
    assert not attack._running
    
    # Start attack (will timeout after 0.1 seconds)
    await attack.start()
    
    assert not attack._running  # Should be stopped after timeout
    assert attack.stats.start_time > 0


if __name__ == '__main__':
    pytest.main([__file__])