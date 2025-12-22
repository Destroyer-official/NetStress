#!/usr/bin/env python3
"""
Basic test for GossipSub pulse coordination functionality
"""

import asyncio
import time
from core.distributed.pulse_sync import PulseSyncEngine, PulseCommand
from core.distributed.gossipsub_coordinator import GossipSubCoordinator, GossipMessage, GossipTopics


async def test_basic_gossipsub_functionality():
    """Test basic GossipSub functionality"""
    print("=== Testing GossipSub Pulse Coordination ===")
    
    # Create sync engine
    print("1. Creating PulseSyncEngine...")
    engine = PulseSyncEngine("test-node-1", sync_port=8765, gossip_port=9000)
    
    try:
        # Start the engine
        print("2. Starting sync engine...")
        await engine.start()
        
        # Check that GossipSub coordinator was initialized
        print("3. Checking GossipSub coordinator...")
        assert engine._gossip_coordinator is not None
        assert engine.gossip_coordinator.running
        print("   ✅ GossipSub coordinator initialized and running")
        
        # Test pulse command creation and signing
        print("4. Testing pulse command creation...")
        pulse_command = PulseCommand(
            pulse_id="test-pulse-1",
            scheduled_time=time.time() + 10.0,
            duration_ms=100,
            intensity=0.8,
            attack_params={"target": "example.com"}
        )
        
        # Sign the command
        pulse_command.sign(engine.private_key)
        assert pulse_command.signature is not None
        print("   ✅ Pulse command created and signed")
        
        # Verify signature
        assert pulse_command.verify(engine.public_key)
        print("   ✅ Pulse command signature verified")
        
        # Test message creation
        print("5. Testing GossipSub message creation...")
        message = GossipMessage(
            topic=GossipTopics.PULSE_COMMANDS,
            message_id="test-msg-1",
            sender_id=engine.node_id,
            timestamp=time.time(),
            payload=pulse_command.to_dict()
        )
        
        # Sign the message
        message.sign(engine.private_key)
        assert message.signature is not None
        print("   ✅ GossipSub message created and signed")
        
        # Verify message signature
        assert message.verify(engine.public_key)
        print("   ✅ GossipSub message signature verified")
        
        # Test peer scoring
        print("6. Testing peer scoring...")
        coordinator = engine.gossip_coordinator
        peer_id = "test-peer-1"
        
        # Test valid message scoring
        coordinator.peer_score.update_peer_score(peer_id, valid_message=True)
        assert coordinator.peer_score.scores[peer_id] > 0
        assert coordinator.peer_score.can_gossip_to_peer(peer_id)
        print("   ✅ Peer scoring works for valid messages")
        
        # Test invalid message penalty
        for _ in range(10):
            coordinator.peer_score.update_peer_score(peer_id, valid_message=False)
        
        assert coordinator.peer_score.scores[peer_id] < -50
        assert not coordinator.peer_score.can_publish_to_peer(peer_id)
        print("   ✅ Peer scoring penalizes invalid messages")
        
        # Test mesh statistics
        print("7. Testing mesh statistics...")
        stats = engine.get_mesh_stats()
        assert 'sync_engine' in stats
        assert 'gossipsub' in stats
        assert stats['sync_engine']['node_id'] == engine.node_id
        print("   ✅ Mesh statistics collection works")
        
        print("\n🎉 All basic GossipSub tests PASSED!")
        
    finally:
        # Clean up
        print("8. Cleaning up...")
        await engine.stop()
        print("   ✅ Engine stopped")


async def test_pulse_command_property():
    """
    Property test: Pulse commands must be properly signed and verified
    """
    print("\n=== Property Test: Pulse Command Signing ===")
    
    engine1 = PulseSyncEngine("prop-test-1", sync_port=8766, gossip_port=9001)
    engine2 = PulseSyncEngine("prop-test-2", sync_port=8767, gossip_port=9002)
    
    try:
        await engine1.start()
        await engine2.start()
        
        # Exchange public keys
        key1 = engine1.get_public_key_bytes()
        key2 = engine2.get_public_key_bytes()
        
        engine1.add_peer_key(engine2.node_id, key2)
        engine2.add_peer_key(engine1.node_id, key1)
        
        # Test 1: Valid signed command
        print("1. Testing valid signed command...")
        valid_command = PulseCommand(
            pulse_id="prop-valid",
            scheduled_time=time.time() + 5.0,
            duration_ms=100,
            intensity=1.0
        )
        valid_command.sign(engine1.private_key)
        
        # Should verify with correct key
        assert valid_command.verify(engine1.public_key)
        print("   ✅ Valid command verifies with correct key")
        
        # Should NOT verify with wrong key
        assert not valid_command.verify(engine2.public_key)
        print("   ✅ Valid command rejects wrong key")
        
        # Test 2: Tampered command
        print("2. Testing tampered command...")
        tampered_command = PulseCommand(
            pulse_id="prop-tampered",
            scheduled_time=time.time() + 5.0,
            duration_ms=100,
            intensity=1.0
        )
        tampered_command.sign(engine1.private_key)
        
        # Tamper with the command after signing
        tampered_command.intensity = 0.5  # Change intensity
        
        # Should NOT verify after tampering
        assert not tampered_command.verify(engine1.public_key)
        print("   ✅ Tampered command fails verification")
        
        print("\n🎉 Property test PASSED!")
        
    finally:
        await engine1.stop()
        await engine2.stop()


if __name__ == "__main__":
    async def main():
        await test_basic_gossipsub_functionality()
        await test_pulse_command_property()
        print("\n✅ All GossipSub pulse coordination tests completed successfully!")
    
    asyncio.run(main())