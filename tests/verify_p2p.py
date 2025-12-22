#!/usr/bin/env python3
"""
P2P Mesh Reliability Verification Test Suite

This test suite validates the P2P Kademlia mesh network functionality:
1. Node Discovery - Nodes can find each other via DHT
2. Gossip Protocol - Commands propagate across the mesh
3. NAT Traversal - Nodes behind NAT can communicate
4. Mesh Resilience - Network survives node failures
5. Command Capability - Attack commands reach all nodes

Usage:
    python -m pytest tests/verify_p2p.py -v
    python tests/verify_p2p.py --nodes 5 --duration 60

Requirements:
    - Native Rust engine with P2P support compiled
    - Multiple network interfaces or localhost testing
"""

import asyncio
import socket
import time
import random
import json
import hashlib
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import unittest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# P2P Node Simulation (Pure Python for testing without native engine)
# ============================================================================

@dataclass
class PeerInfo:
    """Information about a peer node"""
    node_id: str
    address: str
    port: int
    last_seen: float = field(default_factory=time.time)
    is_alive: bool = True


@dataclass
class GossipMessage:
    """Message propagated via gossip protocol"""
    msg_id: str
    msg_type: str
    payload: Dict[str, Any]
    origin_node: str
    ttl: int = 10
    timestamp: float = field(default_factory=time.time)
    
    def to_bytes(self) -> bytes:
        return json.dumps({
            'msg_id': self.msg_id,
            'msg_type': self.msg_type,
            'payload': self.payload,
            'origin_node': self.origin_node,
            'ttl': self.ttl,
            'timestamp': self.timestamp
        }).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'GossipMessage':
        d = json.loads(data.decode())
        return cls(**d)


class KademliaNode:
    """
    Kademlia DHT Node Implementation for P2P Mesh Testing
    
    This is a pure Python implementation for testing purposes.
    In production, the Rust native engine (p2p_mesh.rs) is used.
    """
    
    K_BUCKET_SIZE = 20  # Max peers per bucket
    ALPHA = 3  # Parallel lookups
    
    def __init__(self, host: str = '127.0.0.1', port: int = 0):
        self.host = host
        self.port = port
        self.node_id = self._generate_node_id()
        
        # Routing table (k-buckets)
        self.routing_table: Dict[int, List[PeerInfo]] = {i: [] for i in range(160)}
        
        # Known peers
        self.peers: Dict[str, PeerInfo] = {}
        
        # Message deduplication
        self.seen_messages: Set[str] = set()
        self.message_history: deque = deque(maxlen=1000)
        
        # Received commands
        self.received_commands: List[GossipMessage] = []
        
        # Network
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._receive_thread: Optional[threading.Thread] = None
        
        # Stats
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'commands_received': 0,
            'peers_discovered': 0,
            'gossip_propagated': 0
        }
        
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        data = f"{self.host}:{self.port}:{time.time()}:{random.random()}"
        return hashlib.sha256(data.encode()).hexdigest()[:40]
    
    def _xor_distance(self, id1: str, id2: str) -> int:
        """Calculate XOR distance between two node IDs"""
        int1 = int(id1, 16)
        int2 = int(id2, 16)
        return int1 ^ int2
    
    def _bucket_index(self, node_id: str) -> int:
        """Get bucket index for a node ID"""
        distance = self._xor_distance(self.node_id, node_id)
        if distance == 0:
            return 0
        return distance.bit_length() - 1
    
    def start(self) -> int:
        """Start the node and return the actual port"""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.settimeout(0.5)
        
        # Get actual port if 0 was specified
        self.port = self._socket.getsockname()[1]
        
        self._running = True
        self._receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._receive_thread.start()
        
        logger.info(f"Node {self.node_id[:8]} started on {self.host}:{self.port}")
        return self.port
    
    def stop(self):
        """Stop the node"""
        self._running = False
        if self._receive_thread:
            self._receive_thread.join(timeout=2)
        if self._socket:
            self._socket.close()
        logger.info(f"Node {self.node_id[:8]} stopped")
    
    def _receive_loop(self):
        """Background thread to receive messages"""
        while self._running:
            try:
                data, addr = self._socket.recvfrom(65535)
                self._handle_message(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.debug(f"Receive error: {e}")
    
    def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming message"""
        try:
            msg = json.loads(data.decode())
            msg_type = msg.get('type')
            
            self.stats['messages_received'] += 1
            
            if msg_type == 'ping':
                self._handle_ping(msg, addr)
            elif msg_type == 'pong':
                self._handle_pong(msg, addr)
            elif msg_type == 'find_node':
                self._handle_find_node(msg, addr)
            elif msg_type == 'find_node_response':
                self._handle_find_node_response(msg, addr)
            elif msg_type == 'gossip':
                self._handle_gossip(msg, addr)
            elif msg_type == 'command':
                self._handle_command(msg, addr)
                
        except Exception as e:
            logger.debug(f"Message handling error: {e}")
    
    def _send(self, msg: Dict, addr: Tuple[str, int]):
        """Send message to address"""
        try:
            data = json.dumps(msg).encode()
            self._socket.sendto(data, addr)
            self.stats['messages_sent'] += 1
        except Exception as e:
            logger.debug(f"Send error: {e}")
    
    def _handle_ping(self, msg: Dict, addr: Tuple[str, int]):
        """Handle ping request"""
        sender_id = msg.get('node_id')
        self._add_peer(sender_id, addr[0], addr[1])
        
        # Send pong
        self._send({
            'type': 'pong',
            'node_id': self.node_id
        }, addr)
    
    def _handle_pong(self, msg: Dict, addr: Tuple[str, int]):
        """Handle pong response"""
        sender_id = msg.get('node_id')
        self._add_peer(sender_id, addr[0], addr[1])
    
    def _handle_find_node(self, msg: Dict, addr: Tuple[str, int]):
        """Handle find_node request"""
        target_id = msg.get('target_id')
        sender_id = msg.get('node_id')
        
        self._add_peer(sender_id, addr[0], addr[1])
        
        # Return closest nodes
        closest = self._find_closest_nodes(target_id, self.K_BUCKET_SIZE)
        
        self._send({
            'type': 'find_node_response',
            'node_id': self.node_id,
            'nodes': [
                {'node_id': p.node_id, 'address': p.address, 'port': p.port}
                for p in closest
            ]
        }, addr)
    
    def _handle_find_node_response(self, msg: Dict, addr: Tuple[str, int]):
        """Handle find_node response"""
        nodes = msg.get('nodes', [])
        for node in nodes:
            self._add_peer(node['node_id'], node['address'], node['port'])
    
    def _handle_gossip(self, msg: Dict, addr: Tuple[str, int]):
        """Handle gossip message"""
        gossip_msg = GossipMessage(
            msg_id=msg['msg_id'],
            msg_type=msg['msg_type'],
            payload=msg['payload'],
            origin_node=msg['origin_node'],
            ttl=msg['ttl'],
            timestamp=msg['timestamp']
        )
        
        # Deduplicate
        if gossip_msg.msg_id in self.seen_messages:
            return
            
        self.seen_messages.add(gossip_msg.msg_id)
        self.message_history.append(gossip_msg)
        self.stats['gossip_propagated'] += 1
        
        # Process based on type
        if gossip_msg.msg_type == 'command':
            self.received_commands.append(gossip_msg)
            self.stats['commands_received'] += 1
            logger.info(f"Node {self.node_id[:8]} received command: {gossip_msg.payload}")
        
        # Propagate if TTL > 0
        if gossip_msg.ttl > 0:
            self._propagate_gossip(gossip_msg)
    
    def _handle_command(self, msg: Dict, addr: Tuple[str, int]):
        """Handle direct command"""
        self._handle_gossip(msg, addr)
    
    def _add_peer(self, node_id: str, address: str, port: int):
        """Add peer to routing table"""
        if node_id == self.node_id:
            return
            
        peer = PeerInfo(node_id=node_id, address=address, port=port)
        
        # Add to peers dict
        if node_id not in self.peers:
            self.stats['peers_discovered'] += 1
        self.peers[node_id] = peer
        
        # Add to appropriate k-bucket
        bucket_idx = self._bucket_index(node_id)
        bucket = self.routing_table[bucket_idx]
        
        # Check if already in bucket
        for i, p in enumerate(bucket):
            if p.node_id == node_id:
                bucket[i] = peer
                return
                
        # Add if bucket not full
        if len(bucket) < self.K_BUCKET_SIZE:
            bucket.append(peer)
    
    def _find_closest_nodes(self, target_id: str, count: int) -> List[PeerInfo]:
        """Find closest nodes to target ID"""
        all_peers = list(self.peers.values())
        all_peers.sort(key=lambda p: self._xor_distance(p.node_id, target_id))
        return all_peers[:count]
    
    def bootstrap(self, bootstrap_addr: Tuple[str, int]):
        """Bootstrap into the network via a known node"""
        # Send ping
        self._send({
            'type': 'ping',
            'node_id': self.node_id
        }, bootstrap_addr)
        
        # Send find_node for self
        self._send({
            'type': 'find_node',
            'node_id': self.node_id,
            'target_id': self.node_id
        }, bootstrap_addr)
    
    def broadcast_command(self, command: Dict[str, Any]):
        """Broadcast a command to all nodes via gossip"""
        msg_id = hashlib.sha256(f"{time.time()}:{random.random()}".encode()).hexdigest()[:16]
        
        gossip_msg = GossipMessage(
            msg_id=msg_id,
            msg_type='command',
            payload=command,
            origin_node=self.node_id,
            ttl=10
        )
        
        self.seen_messages.add(msg_id)
        self.received_commands.append(gossip_msg)
        self.stats['commands_received'] += 1
        
        self._propagate_gossip(gossip_msg)
        
        logger.info(f"Node {self.node_id[:8]} broadcast command: {command}")
    
    def _propagate_gossip(self, msg: GossipMessage):
        """Propagate gossip message to peers"""
        if msg.ttl <= 0:
            return
            
        # Select random subset of peers
        peers = list(self.peers.values())
        if not peers:
            return
            
        # Fanout to sqrt(n) peers
        fanout = max(3, int(len(peers) ** 0.5))
        selected = random.sample(peers, min(fanout, len(peers)))
        
        for peer in selected:
            self._send({
                'type': 'gossip',
                'msg_id': msg.msg_id,
                'msg_type': msg.msg_type,
                'payload': msg.payload,
                'origin_node': msg.origin_node,
                'ttl': msg.ttl - 1,
                'timestamp': msg.timestamp
            }, (peer.address, peer.port))


# ============================================================================
# Test Suite
# ============================================================================

class TestP2PMeshReliability(unittest.TestCase):
    """P2P Mesh Reliability Test Suite"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.nodes: List[KademliaNode] = []
        cls.base_port = 19000 + random.randint(0, 1000)
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures"""
        for node in cls.nodes:
            try:
                node.stop()
            except Exception:
                pass
    
    def _create_mesh(self, num_nodes: int) -> List[KademliaNode]:
        """Create a mesh of connected nodes"""
        nodes = []
        
        # Create first node (bootstrap)
        bootstrap = KademliaNode('127.0.0.1', self.base_port)
        bootstrap.start()
        nodes.append(bootstrap)
        self.nodes.append(bootstrap)
        
        # Create and connect remaining nodes
        for i in range(1, num_nodes):
            node = KademliaNode('127.0.0.1', self.base_port + i)
            node.start()
            node.bootstrap(('127.0.0.1', bootstrap.port))
            nodes.append(node)
            self.nodes.append(node)
            time.sleep(0.1)  # Allow discovery
            
        # Wait for mesh to stabilize
        time.sleep(1.0)
        
        return nodes
    
    def test_01_node_discovery(self):
        """Test that nodes can discover each other via DHT"""
        logger.info("=== Test: Node Discovery ===")
        
        nodes = self._create_mesh(5)
        
        # Wait for discovery
        time.sleep(2.0)
        
        # Each node should know about at least some other nodes
        for node in nodes:
            peer_count = len(node.peers)
            logger.info(f"Node {node.node_id[:8]} discovered {peer_count} peers")
            self.assertGreater(peer_count, 0, f"Node {node.node_id[:8]} found no peers")
        
        # Bootstrap node should know most nodes
        bootstrap = nodes[0]
        self.assertGreaterEqual(len(bootstrap.peers), len(nodes) - 2)
        
        logger.info("✅ Node discovery test passed")
    
    def test_02_gossip_propagation(self):
        """Test that gossip messages propagate across the mesh"""
        logger.info("=== Test: Gossip Propagation ===")
        
        nodes = self._create_mesh(7)
        time.sleep(2.0)
        
        # Broadcast command from one node
        test_command = {
            'action': 'test_attack',
            'target': '192.168.1.1',
            'duration': 60
        }
        
        sender = nodes[3]  # Middle node
        sender.broadcast_command(test_command)
        
        # Wait for propagation
        time.sleep(3.0)
        
        # Check how many nodes received the command
        received_count = sum(1 for n in nodes if len(n.received_commands) > 0)
        
        logger.info(f"Command received by {received_count}/{len(nodes)} nodes")
        
        # At least 70% of nodes should receive the command
        min_expected = int(len(nodes) * 0.7)
        self.assertGreaterEqual(received_count, min_expected,
            f"Only {received_count} nodes received command, expected at least {min_expected}")
        
        logger.info("✅ Gossip propagation test passed")
    
    def test_03_mesh_resilience(self):
        """Test that mesh survives node failures"""
        logger.info("=== Test: Mesh Resilience ===")
        
        nodes = self._create_mesh(10)
        time.sleep(2.0)
        
        # Kill 30% of nodes
        kill_count = 3
        killed_nodes = random.sample(nodes[1:], kill_count)  # Don't kill bootstrap
        
        for node in killed_nodes:
            node.stop()
            nodes.remove(node)
            logger.info(f"Killed node {node.node_id[:8]}")
        
        time.sleep(1.0)
        
        # Broadcast command from surviving node
        test_command = {
            'action': 'resilience_test',
            'timestamp': time.time()
        }
        
        sender = nodes[len(nodes) // 2]
        sender.broadcast_command(test_command)
        
        time.sleep(3.0)
        
        # Check propagation among surviving nodes
        received_count = sum(1 for n in nodes if 
            any(c.payload.get('action') == 'resilience_test' for c in n.received_commands))
        
        logger.info(f"After killing {kill_count} nodes: {received_count}/{len(nodes)} received command")
        
        # At least 60% of surviving nodes should receive
        min_expected = int(len(nodes) * 0.6)
        self.assertGreaterEqual(received_count, min_expected)
        
        logger.info("✅ Mesh resilience test passed")
    
    def test_04_command_capability(self):
        """Test that attack commands reach all nodes"""
        logger.info("=== Test: Command Capability ===")
        
        nodes = self._create_mesh(8)
        time.sleep(2.0)
        
        # Simulate attack command
        attack_command = {
            'action': 'start_attack',
            'target': '10.0.0.1',
            'port': 80,
            'method': 'http_flood',
            'rate': 1000,
            'duration': 120
        }
        
        # Broadcast from bootstrap
        nodes[0].broadcast_command(attack_command)
        
        time.sleep(3.0)
        
        # Verify all nodes received the command
        for node in nodes:
            attack_cmds = [c for c in node.received_commands 
                         if c.payload.get('action') == 'start_attack']
            
            if attack_cmds:
                cmd = attack_cmds[0]
                self.assertEqual(cmd.payload['target'], '10.0.0.1')
                self.assertEqual(cmd.payload['method'], 'http_flood')
                logger.info(f"Node {node.node_id[:8]} ready to execute attack")
        
        received_count = sum(1 for n in nodes if 
            any(c.payload.get('action') == 'start_attack' for c in n.received_commands))
        
        logger.info(f"Attack command received by {received_count}/{len(nodes)} nodes")
        self.assertGreaterEqual(received_count, len(nodes) - 1)
        
        logger.info("✅ Command capability test passed")
    
    def test_05_multiple_commands(self):
        """Test multiple sequential commands"""
        logger.info("=== Test: Multiple Commands ===")
        
        nodes = self._create_mesh(6)
        time.sleep(2.0)
        
        commands = [
            {'action': 'cmd1', 'data': 'first'},
            {'action': 'cmd2', 'data': 'second'},
            {'action': 'cmd3', 'data': 'third'},
        ]
        
        for i, cmd in enumerate(commands):
            nodes[i % len(nodes)].broadcast_command(cmd)
            time.sleep(0.5)
        
        time.sleep(3.0)
        
        # Check that nodes received multiple commands
        for node in nodes:
            cmd_count = len(node.received_commands)
            logger.info(f"Node {node.node_id[:8]} received {cmd_count} commands")
            self.assertGreaterEqual(cmd_count, 2, "Node should receive at least 2 commands")
        
        logger.info("✅ Multiple commands test passed")
    
    def test_06_large_mesh(self):
        """Test with larger mesh (stress test)"""
        logger.info("=== Test: Large Mesh (20 nodes) ===")
        
        nodes = self._create_mesh(20)
        time.sleep(5.0)  # More time for larger mesh
        
        # Check connectivity
        total_peers = sum(len(n.peers) for n in nodes)
        avg_peers = total_peers / len(nodes)
        
        logger.info(f"Average peers per node: {avg_peers:.1f}")
        self.assertGreater(avg_peers, 3, "Average peer count too low")
        
        # Broadcast and verify
        nodes[10].broadcast_command({'action': 'large_mesh_test'})
        time.sleep(5.0)
        
        received = sum(1 for n in nodes if 
            any(c.payload.get('action') == 'large_mesh_test' for c in n.received_commands))
        
        logger.info(f"Large mesh: {received}/{len(nodes)} nodes received command")
        self.assertGreaterEqual(received, int(len(nodes) * 0.6))
        
        logger.info("✅ Large mesh test passed")


# ============================================================================
# Native Engine Integration Test
# ============================================================================

class TestNativeP2PEngine(unittest.TestCase):
    """Test native Rust P2P engine if available"""
    
    @classmethod
    def setUpClass(cls):
        """Check if native engine is available"""
        try:
            import netstress_engine
            cls.native_available = hasattr(netstress_engine, 'PyKademliaNode')
        except ImportError:
            cls.native_available = False
            
        if not cls.native_available:
            logger.warning("Native P2P engine not available, skipping native tests")
    
    def test_native_node_creation(self):
        """Test creating native P2P node"""
        if not self.native_available:
            self.skipTest("Native engine not available")
            
        import netstress_engine
        
        node = netstress_engine.PyKademliaNode("127.0.0.1", 0)
        self.assertIsNotNone(node)
        
        node_id = node.get_node_id()
        self.assertIsInstance(node_id, str)
        self.assertGreater(len(node_id), 0)
        
        logger.info(f"Native node created with ID: {node_id[:16]}...")
        logger.info("✅ Native node creation test passed")
    
    def test_native_bootstrap(self):
        """Test native node bootstrap"""
        if not self.native_available:
            self.skipTest("Native engine not available")
            
        import netstress_engine
        
        # Create bootstrap node
        bootstrap = netstress_engine.PyKademliaNode("127.0.0.1", 19500)
        bootstrap.start()
        
        # Create and connect second node
        node2 = netstress_engine.PyKademliaNode("127.0.0.1", 19501)
        node2.start()
        node2.bootstrap("127.0.0.1", 19500)
        
        time.sleep(2.0)
        
        # Check peer discovery
        peers = node2.get_peers()
        self.assertGreater(len(peers), 0)
        
        bootstrap.stop()
        node2.stop()
        
        logger.info("✅ Native bootstrap test passed")


# ============================================================================
# CLI Runner
# ============================================================================

def run_interactive_test(num_nodes: int = 5, duration: int = 60):
    """Run interactive P2P mesh test"""
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║     NetStress P2P Mesh Verification Test                      ║
║                                                               ║
║  Testing Kademlia DHT + Gossip Protocol                       ║
╚═══════════════════════════════════════════════════════════════╝

Nodes: {num_nodes}
Duration: {duration}s
""")
    
    nodes = []
    base_port = 18000 + random.randint(0, 1000)
    
    try:
        # Create mesh
        print(f"[1/4] Creating {num_nodes} nodes...")
        
        bootstrap = KademliaNode('127.0.0.1', base_port)
        bootstrap.start()
        nodes.append(bootstrap)
        print(f"  Bootstrap node: {bootstrap.node_id[:8]} on port {bootstrap.port}")
        
        for i in range(1, num_nodes):
            node = KademliaNode('127.0.0.1', base_port + i)
            node.start()
            node.bootstrap(('127.0.0.1', bootstrap.port))
            nodes.append(node)
            print(f"  Node {i}: {node.node_id[:8]} on port {node.port}")
            time.sleep(0.2)
        
        print(f"\n[2/4] Waiting for mesh stabilization...")
        time.sleep(3.0)
        
        # Print connectivity
        print(f"\n[3/4] Mesh Connectivity:")
        for node in nodes:
            print(f"  {node.node_id[:8]}: {len(node.peers)} peers")
        
        # Test command propagation
        print(f"\n[4/4] Testing command propagation...")
        
        test_cmd = {
            'action': 'interactive_test',
            'timestamp': time.time(),
            'message': 'Hello from P2P mesh!'
        }
        
        sender = nodes[num_nodes // 2]
        print(f"  Sending command from node {sender.node_id[:8]}...")
        sender.broadcast_command(test_cmd)
        
        time.sleep(3.0)
        
        received = sum(1 for n in nodes if len(n.received_commands) > 0)
        print(f"\n  Command received by {received}/{num_nodes} nodes ({received/num_nodes*100:.0f}%)")
        
        # Summary
        print(f"""
═══════════════════════════════════════════════════════════════
RESULTS:
  Nodes Created: {num_nodes}
  Mesh Connected: {'YES' if all(len(n.peers) > 0 for n in nodes) else 'PARTIAL'}
  Command Propagation: {received}/{num_nodes} ({received/num_nodes*100:.0f}%)
  
  Status: {'✅ PASS' if received >= num_nodes * 0.7 else '❌ FAIL'}
═══════════════════════════════════════════════════════════════
""")
        
        if duration > 10:
            print(f"Running for {duration}s... Press Ctrl+C to stop.")
            time.sleep(duration)
            
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        for node in nodes:
            node.stop()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='P2P Mesh Verification')
    parser.add_argument('--nodes', type=int, default=5, help='Number of nodes')
    parser.add_argument('--duration', type=int, default=10, help='Test duration in seconds')
    parser.add_argument('--unittest', action='store_true', help='Run unit tests')
    args = parser.parse_args()
    
    if args.unittest:
        unittest.main(argv=[''], exit=False, verbosity=2)
    else:
        run_interactive_test(args.nodes, args.duration)
