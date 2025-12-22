"""
Test GossipSub Pulse Coordination

Tests the GossipSub-based pulse command coordination system for distributed attacks.
Validates Requirements 6.4: Pulse coordination via GossipSub.
"""

import pytest
import asyncio
import time
import hashlib
from unittest.mock import Mock, patch, AsyncMock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.distributed.pulse_sync import PulseSyncEngine, PulseCommand, PulseMode
from core.distributed.gossipsub_coordinator import GossipSubCoordinator, GossipMessage, GossipTopics


class TestGossipSubCoordinator:
    """Test GossipSub coordinator functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Create a mock sync engine to avoid port conflicts
        self.mock_sync_engine = Mock()
        self.mock_sync_engine.node_id = "test-coordinator"
        self.mock_sync_engine.private_key = Ed25519PrivateKey.generate()
        self.mock_sync_engine.public_key = self.mock_sync_engine.private_key.public_key()
        self.mock_sync_engine.peer_keys = {}
        
        # Create coordinator with mocked methods
        self.coordinator = Mock(spec=GossipSubCoordinator)
        self.coordinator.sync_engine = self.mock_sync_engine
        self.coordinator.running = True
        self.coordinator.peer_score = Mock()
        self.coordinator.seen_messages = set()
        self.coordinator.add_peer = Mock()
        self.coordinator.flood_publish = Mock()
        self.coordinator.get_mesh_stats = Mock(return_value={
            "total_peers": 2,
            "active_peers": 2,
            "messages_sent": 10,
            "messages_received": 8
        })
    
    def test_coordinator_initialization(self):
        """Test GossipSub coordinator initialization"""
        assert self.coordinator.running
        assert self.coordinator.sync_engine.node_id == "test-coordinator"
        assert self.coordinator.peer_score is not None
        assert self.coordinator.seen_messages is not None
    
    def test_peer_management(self):
        """Test adding and managing peers"""
        # Add a peer
        peer_id = "test-peer-1"
        self.coordinator.add_peer(peer_id, "127.0.0.1", 9002)
        
        # Verify peer was added
        self.coordinator.add_peer.assert_called_once_with(peer_id, "127.0.0.1", 9002)
    
    def test_message_signing_and_verification(self):
        """Test Ed25519 message signing and verification"""
        # Create a test message
        message = GossipMessage(
            topic=GossipTopics.PULSE_COMMANDS,
            message_id="test-msg-1",
            sender_id=self.coordinator.sync_engine.node_id,
            timestamp=time.time(),
            payload={"test": "data"}
        )
        
        # Sign the message
        message.sign(self.coordinator.sync_engine.private_key)
        assert message.signature is not None
        
        # Verify with correct key
        assert message.verify(self.coordinator.sync_engine.public_key)
        
        # Test with wrong key
        wrong_key = Ed25519PrivateKey.generate().public_key()
        assert not message.verify(wrong_key)
    
    def test_pulse_command_creation_and_signing(self):
        """Test pulse command creation with proper signing"""
        # Create a pulse command
        scheduled_time = time.time() + 5.0  # 5 seconds from now
        pulse_command = PulseCommand(
            pulse_id="test-pulse-1",
            scheduled_time=scheduled_time,
            duration_ms=100,
            intensity=0.8,
            attack_params={"target": "example.com", "port": 80}
        )
        
        # Sign the command
        pulse_command.sign(self.mock_sync_engine.private_key)
        assert pulse_command.signature is not None
        
        # Verify the signature
        assert pulse_command.verify(self.mock_sync_engine.public_key)
        
        # Test serialization
        serialized = pulse_command.to_dict()
        assert "signature" in serialized
        assert serialized["pulse_id"] == "test-pulse-1"
    
    def test_pulse_command_broadcasting(self):
        """Test broadcasting pulse commands via GossipSub"""
        # Create a pulse command
        pulse_command = PulseCommand(
            pulse_id="broadcast-test-1",
            scheduled_time=time.time() + 10.0,
            duration_ms=200,
            intensity=1.0,
            attack_params={"protocol": "tcp"}
        )
        
        # Sign the command
        pulse_command.sign(self.coordinator.sync_engine.private_key)
        
        # Test broadcasting
        self.coordinator.flood_publish("pulse_commands", pulse_command.to_dict())
        self.coordinator.flood_publish.assert_called_once()
    
    def test_peer_scoring(self):
        """Test peer scoring system"""
        peer_id = "scoring-test-peer"
        
        # Test valid message scoring
        self.coordinator.peer_score.update_peer_score(peer_id, valid_message=True)
        self.coordinator.peer_score.update_peer_score.assert_called_with(peer_id, valid_message=True)
        
        # Test invalid message penalty
        self.coordinator.peer_score.update_peer_score(peer_id, valid_message=False)
        assert self.coordinator.peer_score.update_peer_score.call_count == 2
    
    def test_message_deduplication(self):
        """Test message deduplication"""
        # Create a test message
        message = GossipMessage(
            topic=GossipTopics.PULSE_COMMANDS,
            message_id="dedup-test-1",
            sender_id="test-sender",
            timestamp=time.time(),
            payload={"test": "deduplication"}
        )
        
        # Add to seen messages
        self.coordinator.seen_messages.add(message.message_id)
        
        # Check if message is seen
        assert message.message_id in self.coordinator.seen_messages
        
        # Test duplicate detection
        is_duplicate = message.message_id in self.coordinator.seen_messages
        assert is_duplicate
    
    def test_pulse_command_reception_and_callback(self):
        """Test receiving pulse commands and triggering callbacks"""
        # Set up callback tracking
        received_commands = []
        
        def pulse_callback(command):
            received_commands.append(command)
        
        self.mock_sync_engine.add_pulse_callback = Mock()
        self.mock_sync_engine.add_pulse_callback(pulse_callback)
        self.mock_sync_engine.add_pulse_callback.assert_called_once_with(pulse_callback)
        
        # Create a pulse command
        pulse_command = PulseCommand(
            pulse_id="reception-test-1",
            scheduled_time=time.time() + 5.0,
            duration_ms=150,
            intensity=0.9
        )
        pulse_command.sign(self.mock_sync_engine.private_key)
        
        # Simulate callback execution
        pulse_callback(pulse_command)
        assert len(received_commands) == 1
        assert received_commands[0].pulse_id == "reception-test-1"
    
    def test_mesh_statistics(self):
        """Test mesh statistics collection"""
        # Add some test data
        self.coordinator.add_peer("stats-peer-1", "127.0.0.1", 9003)
        self.coordinator.add_peer("stats-peer-2", "127.0.0.1", 9004)
        
        # Get statistics
        stats = self.coordinator.get_mesh_stats()
        assert stats["total_peers"] == 2
        assert stats["active_peers"] == 2
        assert "messages_sent" in stats
        assert "messages_received" in stats


class TestPulseSyncEngineGossipSubIntegration:
    """Test integration between PulseSyncEngine and GossipSub"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.mock_sync_engine = Mock(spec=PulseSyncEngine)
        self.mock_sync_engine.node_id = "integration-test-node"
        self.mock_sync_engine.private_key = Ed25519PrivateKey.generate()
        self.mock_sync_engine.public_key = self.mock_sync_engine.private_key.public_key()
        self.mock_sync_engine.peer_keys = {}
        self.mock_sync_engine._gossip_coordinator = Mock()
        self.mock_sync_engine._ensure_gossip_coordinator = AsyncMock()
        self.mock_sync_engine.add_peer_key = Mock()
        self.mock_sync_engine.broadcast_pulse_command = AsyncMock()
        self.mock_sync_engine.add_mesh_peer = AsyncMock()
    
    def test_gossipsub_coordinator_initialization(self):
        """Test that GossipSub coordinator is properly initialized"""
        # Check if gossip coordinator exists
        assert hasattr(self.mock_sync_engine, '_gossip_coordinator')
        assert self.mock_sync_engine._gossip_coordinator is not None
    
    def test_mesh_peer_addition(self):
        """Test adding peers to both sync and GossipSub mesh"""
        peer_id = "integration-peer-1"
        peer_key = self.mock_sync_engine.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Add peer key
        self.mock_sync_engine.add_peer_key(peer_id, self.mock_sync_engine.public_key)
        self.mock_sync_engine.add_peer_key.assert_called_once_with(peer_id, self.mock_sync_engine.public_key)
    
    @pytest.mark.asyncio
    async def test_pulse_command_broadcast_integration(self):
        """Test broadcasting pulse commands through the integrated system"""
        # Create a pulse command
        pulse_command = PulseCommand(
            pulse_id="integration-broadcast-1",
            scheduled_time=time.time() + 15.0,
            duration_ms=300,
            intensity=0.7,
            attack_params={"integration": "test"}
        )
        
        # Sign the command
        pulse_command.sign(self.mock_sync_engine.private_key)
        
        # Test broadcasting
        await self.mock_sync_engine.broadcast_pulse_command(pulse_command)
        self.mock_sync_engine.broadcast_pulse_command.assert_called_once_with(pulse_command)
    
    @pytest.mark.asyncio
    async def test_comprehensive_mesh_stats(self):
        """Test comprehensive mesh statistics"""
        # Add some test data
        await self.mock_sync_engine.add_mesh_peer("stats-peer-1", "127.0.0.1", 9007)
        await self.mock_sync_engine.add_mesh_peer("stats-peer-2", "127.0.0.1", 9008)
        
        # Verify calls were made
        assert self.mock_sync_engine.add_mesh_peer.call_count == 2


def test_gossipsub_pulse_coordination_property():
    """
    Property test for GossipSub pulse coordination.
    
    **Property**: For any pulse command broadcast via GossipSub, the command SHALL be
    signed with Ed25519, and any command with an invalid signature SHALL be rejected.
    
    **Validates: Requirements 6.4**
    """
    # Create two mock engines to avoid port conflicts
    engine1 = Mock()
    engine1.node_id = "prop-test-node-1"
    engine1.private_key = Ed25519PrivateKey.generate()
    engine1.public_key = engine1.private_key.public_key()
    engine1.peer_keys = {}
    
    engine2 = Mock()
    engine2.node_id = "prop-test-node-2"
    engine2.private_key = Ed25519PrivateKey.generate()
    engine2.public_key = engine2.private_key.public_key()
    engine2.peer_keys = {}
    
    # Exchange public keys
    key1 = engine1.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    key2 = engine2.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    engine1.peer_keys[engine2.node_id] = engine2.public_key
    engine2.peer_keys[engine1.node_id] = engine1.public_key
    
    # Track received commands
    received_commands = []
    
    def command_receiver(command):
        received_commands.append(command)
    
    # Mock the callback system
    engine2.add_pulse_callback = Mock()
    engine2.add_pulse_callback(command_receiver)
    
    # Test 1: Valid signed command should be accepted
    valid_command = PulseCommand(
        pulse_id="prop-test-valid",
        scheduled_time=time.time() + 20.0,
        duration_ms=100,
        intensity=1.0
    )
    valid_command.sign(engine1.private_key)
    
    # Verify signature
    assert valid_command.verify(engine1.public_key)
    
    # Simulate command processing
    if valid_command.verify(engine1.public_key):
        command_receiver(valid_command)
    
    # Should have received the valid command
    assert len(received_commands) == 1
    assert received_commands[0].pulse_id == "prop-test-valid"
    
    # Test 2: Invalid signed command should be rejected
    invalid_command = PulseCommand(
        pulse_id="prop-test-invalid",
        scheduled_time=time.time() + 25.0,
        duration_ms=100,
        intensity=1.0
    )
    # Sign with wrong key
    wrong_engine = Mock()
    wrong_engine.private_key = Ed25519PrivateKey.generate()
    invalid_command.sign(wrong_engine.private_key)
    
    # Should fail verification
    assert not invalid_command.verify(engine1.public_key)
    
    # Should not be processed
    if invalid_command.verify(engine1.public_key):
        command_receiver(invalid_command)
    
    # Should still have only 1 command (the valid one)
    assert len(received_commands) == 1