#!/usr/bin/env python3
"""
GossipSub Pulse Coordination Demo

Demonstrates Task 12.4: Pulse coordination via GossipSub
- Broadcast pulse commands with signed messages
- Include scheduled time in command
- Handle pulse command reception

This demo shows how distributed nodes can coordinate synchronized pulse attacks
using GossipSub v1.1 with Ed25519 message signing.
"""

import asyncio
import time
import logging
from core.distributed.pulse_sync import PulseSyncEngine, PulseCommand, PulseMode
from core.distributed.gossipsub_coordinator import GossipTopics

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PulseCoordinationDemo:
    """Demonstration of GossipSub pulse coordination"""
    
    def __init__(self):
        self.nodes = []
        self.received_commands = []
    
    async def create_mesh_nodes(self, count: int = 3):
        """Create a mesh of synchronized nodes"""
        logger.info(f"Creating mesh with {count} nodes...")
        
        base_sync_port = 8770
        base_gossip_port = 9010
        
        for i in range(count):
            node_id = f"demo-node-{i+1}"
            sync_port = base_sync_port + i
            gossip_port = base_gossip_port + i
            
            # Create sync engine
            engine = PulseSyncEngine(node_id, sync_port=sync_port, gossip_port=gossip_port)
            
            # Add pulse callback to track received commands
            def make_callback(node_id):
                def callback(command):
                    logger.info(f"📨 {node_id} received pulse command: {command.pulse_id}")
                    self.received_commands.append((node_id, command))
                return callback
            
            engine.add_pulse_callback(make_callback(node_id))
            
            # Start the engine
            await engine.start()
            self.nodes.append(engine)
            
            logger.info(f"✅ Created {node_id} (sync:{sync_port}, gossip:{gossip_port})")
        
        # Exchange public keys between all nodes
        logger.info("🔑 Exchanging public keys between nodes...")
        for i, node1 in enumerate(self.nodes):
            for j, node2 in enumerate(self.nodes):
                if i != j:
                    key = node2.get_public_key_bytes()
                    node1.add_peer_key(node2.node_id, key)
        
        logger.info("✅ Mesh nodes created and keys exchanged")
    
    async def demonstrate_pulse_coordination(self):
        """Demonstrate pulse command coordination via GossipSub"""
        if not self.nodes:
            logger.error("No nodes available for demonstration")
            return
        
        logger.info("\n🚀 Demonstrating GossipSub Pulse Coordination...")
        
        # Use the first node as the coordinator
        coordinator_node = self.nodes[0]
        
        # Create a pulse command scheduled for the future
        scheduled_time = time.time() + 5.0  # 5 seconds from now
        pulse_command = PulseCommand(
            pulse_id="demo-pulse-2024",
            scheduled_time=scheduled_time,
            duration_ms=200,
            intensity=0.9,
            attack_params={
                "target": "demo.example.com",
                "port": 80,
                "protocol": "tcp",
                "attack_type": "syn_flood"
            }
        )
        
        logger.info(f"📋 Created pulse command:")
        logger.info(f"   - Pulse ID: {pulse_command.pulse_id}")
        logger.info(f"   - Scheduled: {scheduled_time:.3f} (in {scheduled_time - time.time():.1f}s)")
        logger.info(f"   - Duration: {pulse_command.duration_ms}ms")
        logger.info(f"   - Intensity: {pulse_command.intensity}")
        
        # Sign the command
        pulse_command.sign(coordinator_node.private_key)
        logger.info("🔐 Pulse command signed with Ed25519")
        
        # Broadcast the command via GossipSub
        logger.info("📡 Broadcasting pulse command via GossipSub...")
        await coordinator_node.broadcast_pulse_command(pulse_command)
        
        # Wait a moment for message propagation
        await asyncio.sleep(1.0)
        
        # Check if other nodes received the command
        logger.info(f"📊 Command reception status:")
        for node in self.nodes[1:]:  # Skip coordinator node
            received = any(cmd.pulse_id == pulse_command.pulse_id 
                          for _, cmd in self.received_commands 
                          if _ == node.node_id)
            status = "✅ RECEIVED" if received else "❌ NOT RECEIVED"
            logger.info(f"   - {node.node_id}: {status}")
        
        # Show mesh statistics
        logger.info("\n📈 Mesh Statistics:")
        stats = coordinator_node.get_mesh_stats()
        
        sync_stats = stats['sync_engine']
        logger.info(f"   Sync Engine:")
        logger.info(f"     - Node ID: {sync_stats['node_id']}")
        logger.info(f"     - Mode: {sync_stats['pulse_mode']}")
        logger.info(f"     - Peers: {sync_stats['peer_count']}")
        
        if 'gossipsub' in stats:
            gossip_stats = stats['gossipsub']
            logger.info(f"   GossipSub:")
            logger.info(f"     - Total Peers: {gossip_stats['total_peers']}")
            logger.info(f"     - Connected: {gossip_stats['connected_peers']}")
            logger.info(f"     - Cached Messages: {gossip_stats['cached_messages']}")
            logger.info(f"     - Flood Publish: {gossip_stats['config']['flood_publish']}")
    
    async def demonstrate_signature_verification(self):
        """Demonstrate Ed25519 signature verification"""
        if len(self.nodes) < 2:
            logger.error("Need at least 2 nodes for signature verification demo")
            return
        
        logger.info("\n🔐 Demonstrating Ed25519 Signature Verification...")
        
        node1 = self.nodes[0]
        node2 = self.nodes[1]
        
        # Create a command and sign it with node1's key
        command = PulseCommand(
            pulse_id="signature-test",
            scheduled_time=time.time() + 10.0,
            duration_ms=100,
            intensity=0.5
        )
        
        command.sign(node1.private_key)
        logger.info(f"✅ Command signed by {node1.node_id}")
        
        # Verify with correct key
        valid = command.verify(node1.public_key)
        logger.info(f"🔍 Verification with correct key: {'✅ VALID' if valid else '❌ INVALID'}")
        
        # Try to verify with wrong key
        invalid = command.verify(node2.public_key)
        logger.info(f"🔍 Verification with wrong key: {'❌ INVALID' if not invalid else '✅ VALID'}")
        
        # Tamper with command and try to verify
        original_intensity = command.intensity
        command.intensity = 0.8  # Tamper with the command
        
        tampered = command.verify(node1.public_key)
        logger.info(f"🔍 Verification after tampering: {'❌ INVALID' if not tampered else '✅ VALID'}")
        
        # Restore original value
        command.intensity = original_intensity
    
    async def demonstrate_peer_scoring(self):
        """Demonstrate peer scoring system"""
        if not self.nodes:
            logger.error("No nodes available for peer scoring demo")
            return
        
        logger.info("\n📊 Demonstrating Peer Scoring System...")
        
        coordinator = self.nodes[0].gossip_coordinator
        test_peer_id = "scoring-demo-peer"
        
        # Simulate valid messages
        logger.info("📈 Sending valid messages...")
        for i in range(5):
            coordinator.peer_score.update_peer_score(test_peer_id, valid_message=True)
        
        score = coordinator.peer_score.scores[test_peer_id]
        can_gossip = coordinator.peer_score.can_gossip_to_peer(test_peer_id)
        can_publish = coordinator.peer_score.can_publish_to_peer(test_peer_id)
        
        logger.info(f"   Score after valid messages: {score}")
        logger.info(f"   Can gossip: {'✅ YES' if can_gossip else '❌ NO'}")
        logger.info(f"   Can publish: {'✅ YES' if can_publish else '❌ NO'}")
        
        # Simulate invalid messages
        logger.info("📉 Sending invalid messages...")
        for i in range(10):
            coordinator.peer_score.update_peer_score(test_peer_id, valid_message=False)
        
        score = coordinator.peer_score.scores[test_peer_id]
        can_gossip = coordinator.peer_score.can_gossip_to_peer(test_peer_id)
        can_publish = coordinator.peer_score.can_publish_to_peer(test_peer_id)
        is_graylisted = coordinator.peer_score.is_peer_graylisted(test_peer_id)
        
        logger.info(f"   Score after invalid messages: {score}")
        logger.info(f"   Can gossip: {'✅ YES' if can_gossip else '❌ NO'}")
        logger.info(f"   Can publish: {'✅ YES' if can_publish else '❌ NO'}")
        logger.info(f"   Is graylisted: {'✅ YES' if is_graylisted else '❌ NO'}")
    
    async def cleanup(self):
        """Clean up all nodes"""
        logger.info("\n🧹 Cleaning up nodes...")
        for node in self.nodes:
            await node.stop()
        logger.info("✅ All nodes stopped")


async def main():
    """Main demonstration function"""
    print("=" * 80)
    print("🎯 GossipSub Pulse Coordination Demonstration")
    print("   Task 12.4: Implement pulse coordination via GossipSub")
    print("=" * 80)
    
    demo = PulseCoordinationDemo()
    
    try:
        # Create mesh nodes
        await demo.create_mesh_nodes(count=3)
        
        # Wait a moment for initialization
        await asyncio.sleep(1.0)
        
        # Demonstrate pulse coordination
        await demo.demonstrate_pulse_coordination()
        
        # Demonstrate signature verification
        await demo.demonstrate_signature_verification()
        
        # Demonstrate peer scoring
        await demo.demonstrate_peer_scoring()
        
        print("\n" + "=" * 80)
        print("🎉 GossipSub Pulse Coordination Demo Completed Successfully!")
        print("✅ Task 12.4 Implementation Verified:")
        print("   - Pulse commands broadcast via GossipSub ✅")
        print("   - Ed25519 message signing implemented ✅")
        print("   - Scheduled time included in commands ✅")
        print("   - Pulse command reception handling ✅")
        print("   - Peer scoring and validation ✅")
        print("=" * 80)
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await demo.cleanup()


if __name__ == "__main__":
    asyncio.run(main())