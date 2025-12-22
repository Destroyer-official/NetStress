"""
Kademlia DHT P2P Coordination Module

This module provides a Python interface to the Rust-based Kademlia DHT implementation
for peer-to-peer coordination in distributed NetStress attacks.

**Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5** - P2P mesh networking with Kademlia DHT
"""

import asyncio
import hashlib
import json
import logging
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

try:
    from netstress_engine import PyKademliaNode
except ImportError:
    # Fallback for development/testing
    PyKademliaNode = None

logger = logging.getLogger(__name__)


@dataclass
class PeerInfo:
    """Information about a peer in the network"""
    node_id: str  # Hex-encoded node ID
    address: str  # IP:port
    last_seen: float  # Timestamp


@dataclass
class AttackConfig:
    """Configuration for a distributed attack"""
    target: str
    port: int
    protocol: str
    duration: int
    rate: int
    swarm_id: str  # Hex-encoded swarm ID


class KademliaError(Exception):
    """Kademlia-specific errors"""
    pass


class KademliaNode:
    """
    Python wrapper for the Rust Kademlia DHT implementation
    
    Provides P2P coordination for distributed NetStress attacks without
    requiring a central server.
    """
    
    def __init__(self, bind_addr: str = "0.0.0.0:0"):
        """
        Initialize a new Kademlia node
        
        Args:
            bind_addr: Address to bind to (IP:port). Use "0.0.0.0:0" for auto-assignment
        """
        if PyKademliaNode is None:
            raise KademliaError("Rust engine not available - Kademlia functionality disabled")
        
        self.bind_addr = bind_addr
        self._node = None
        self._running = False
        self._thread = None
        
        # Parse bind address
        if bind_addr == "0.0.0.0:0":
            # Auto-assign port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', 0))
            port = sock.getsockname()[1]
            sock.close()
            self.bind_addr = f"0.0.0.0:{port}"
        
        try:
            self._node = PyKademliaNode(self.bind_addr)
            logger.info(f"Created Kademlia node bound to {self.bind_addr}")
        except Exception as e:
            raise KademliaError(f"Failed to create Kademlia node: {e}")
    
    @property
    def node_id(self) -> str:
        """Get the node ID as a hex string"""
        if self._node is None:
            raise KademliaError("Node not initialized")
        return self._node.node_id()
    
    @property
    def address(self) -> str:
        """Get the bind address"""
        if self._node is None:
            raise KademliaError("Node not initialized")
        return self._node.bind_addr()
    
    def bootstrap(self, seed_nodes: List[str]) -> None:
        """
        Bootstrap the node by connecting to seed nodes
        
        Args:
            seed_nodes: List of seed node addresses (IP:port format)
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        if not seed_nodes:
            raise KademliaError("At least one seed node is required")
        
        try:
            self._node.bootstrap(seed_nodes)
            logger.info(f"Bootstrapped with {len(seed_nodes)} seed nodes")
        except Exception as e:
            raise KademliaError(f"Bootstrap failed: {e}")
    
    def ping(self, addr: str) -> bool:
        """
        Ping a node to check if it's alive
        
        Args:
            addr: Node address (IP:port format)
            
        Returns:
            True if ping successful, False otherwise
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        try:
            self._node.ping_node(addr)
            return True
        except Exception as e:
            logger.debug(f"Ping to {addr} failed: {e}")
            return False
    
    def find_peers(self, target_id: Optional[str] = None) -> List[PeerInfo]:
        """
        Find peers closest to a target node ID
        
        Args:
            target_id: Target node ID as hex string. If None, uses random ID
            
        Returns:
            List of peer information
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        if target_id is None:
            # Generate random target
            target_id = hashlib.sha1(str(time.time()).encode()).hexdigest()
        
        try:
            peers_data = self._node.find_node(target_id)
            peers = []
            for peer_dict in peers_data:
                peers.append(PeerInfo(
                    node_id=peer_dict['node_id'],
                    address=peer_dict['address'],
                    last_seen=time.time()
                ))
            return peers
        except Exception as e:
            raise KademliaError(f"Find peers failed: {e}")
    
    def store_value(self, key: str, value: bytes) -> None:
        """
        Store a value in the DHT
        
        Args:
            key: Key as hex string (must be 40 hex chars = 160 bits)
            value: Value to store
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        if len(key) != 40:
            raise KademliaError("Key must be 40 hex characters (160 bits)")
        
        try:
            self._node.store(key, value)
            logger.debug(f"Stored value with key {key[:8]}...")
        except Exception as e:
            raise KademliaError(f"Store failed: {e}")
    
    def find_value(self, key: str) -> Optional[bytes]:
        """
        Find a value in the DHT
        
        Args:
            key: Key as hex string (must be 40 hex chars = 160 bits)
            
        Returns:
            Value if found, None otherwise
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        if len(key) != 40:
            raise KademliaError("Key must be 40 hex characters (160 bits)")
        
        try:
            return self._node.find_value(key)
        except Exception as e:
            raise KademliaError(f"Find value failed: {e}")
    
    def join_swarm(self, swarm_name: str) -> str:
        """
        Join a named swarm for coordinated attacks
        
        Args:
            swarm_name: Human-readable swarm name
            
        Returns:
            Swarm ID as hex string
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        # Generate swarm ID from name
        swarm_id = hashlib.sha1(swarm_name.encode()).digest()
        swarm_id_hex = swarm_id.hex()
        
        try:
            self._node.join_swarm(swarm_id)
            logger.info(f"Joined swarm '{swarm_name}' (ID: {swarm_id_hex[:8]}...)")
            return swarm_id_hex
        except Exception as e:
            raise KademliaError(f"Join swarm failed: {e}")
    
    def find_swarm_peers(self, swarm_name: str) -> List[PeerInfo]:
        """
        Find other peers in a swarm
        
        Args:
            swarm_name: Human-readable swarm name
            
        Returns:
            List of peers in the swarm
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        # Generate swarm ID from name
        swarm_id = hashlib.sha1(swarm_name.encode()).digest()
        
        try:
            peers_data = self._node.find_swarm_peers(swarm_id)
            peers = []
            for peer_dict in peers_data:
                peers.append(PeerInfo(
                    node_id=peer_dict['node_id'],
                    address=peer_dict['address'],
                    last_seen=time.time()
                ))
            return peers
        except Exception as e:
            raise KademliaError(f"Find swarm peers failed: {e}")
    
    def broadcast_attack(self, config: AttackConfig) -> None:
        """
        Broadcast an attack configuration to all known peers
        
        Args:
            config: Attack configuration
        """
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        # Convert swarm name to ID if needed
        if len(config.swarm_id) != 40:
            swarm_id_hex = hashlib.sha1(config.swarm_id.encode()).hexdigest()
        else:
            swarm_id_hex = config.swarm_id
        
        config_dict = {
            'target': config.target,
            'port': config.port,
            'protocol': config.protocol,
            'duration': config.duration,
            'rate': config.rate,
            'swarm_id': swarm_id_hex
        }
        
        try:
            self._node.broadcast_attack(config_dict)
            logger.info(f"Broadcasted attack config to swarm {swarm_id_hex[:8]}...")
        except Exception as e:
            raise KademliaError(f"Broadcast attack failed: {e}")
    
    def start(self) -> None:
        """Start the node's message handling loop"""
        if self._node is None:
            raise KademliaError("Node not initialized")
        
        if self._running:
            return
        
        try:
            self._node.start()
            self._running = True
            logger.info("Kademlia node started")
        except Exception as e:
            raise KademliaError(f"Failed to start node: {e}")
    
    def stop(self) -> None:
        """Stop the node"""
        if self._running:
            self._running = False
            logger.info("Kademlia node stopped")
    
    def is_running(self) -> bool:
        """Check if the node is running"""
        return self._running
    
    def get_stats(self) -> Dict[str, Any]:
        """Get node statistics"""
        return {
            'node_id': self.node_id,
            'address': self.address,
            'running': self.is_running(),
            'peers_count': len(self.find_peers()),
        }


class P2PCoordinator:
    """
    High-level coordinator for P2P distributed attacks
    
    Manages multiple Kademlia nodes and provides simplified interface
    for distributed attack coordination.
    """
    
    def __init__(self, bind_port: int = 0):
        """
        Initialize P2P coordinator
        
        Args:
            bind_port: Port to bind to (0 for auto-assignment)
        """
        self.bind_addr = f"0.0.0.0:{bind_port}"
        self.node = None
        self.swarms = {}  # swarm_name -> swarm_id mapping
        self.attack_handlers = []  # List of attack handler callbacks
        
    def start(self, seed_nodes: Optional[List[str]] = None) -> None:
        """
        Start the P2P coordinator
        
        Args:
            seed_nodes: List of seed node addresses for bootstrapping
        """
        try:
            self.node = KademliaNode(self.bind_addr)
            self.node.start()
            
            if seed_nodes:
                self.node.bootstrap(seed_nodes)
                
            logger.info(f"P2P Coordinator started on {self.node.address}")
            logger.info(f"Node ID: {self.node.node_id}")
            
        except Exception as e:
            raise KademliaError(f"Failed to start P2P coordinator: {e}")
    
    def stop(self) -> None:
        """Stop the P2P coordinator"""
        if self.node:
            self.node.stop()
            self.node = None
        logger.info("P2P Coordinator stopped")
    
    def create_swarm(self, swarm_name: str) -> str:
        """
        Create or join a swarm
        
        Args:
            swarm_name: Human-readable swarm name
            
        Returns:
            Swarm ID as hex string
        """
        if not self.node:
            raise KademliaError("Coordinator not started")
        
        swarm_id = self.node.join_swarm(swarm_name)
        self.swarms[swarm_name] = swarm_id
        return swarm_id
    
    def get_swarm_peers(self, swarm_name: str) -> List[PeerInfo]:
        """
        Get peers in a swarm
        
        Args:
            swarm_name: Swarm name
            
        Returns:
            List of peers in the swarm
        """
        if not self.node:
            raise KademliaError("Coordinator not started")
        
        return self.node.find_swarm_peers(swarm_name)
    
    def coordinate_attack(self, swarm_name: str, target: str, port: int, 
                         protocol: str = "udp", duration: int = 60, 
                         rate: int = 100000) -> None:
        """
        Coordinate a distributed attack across a swarm
        
        Args:
            swarm_name: Name of the swarm to coordinate
            target: Target IP or hostname
            port: Target port
            protocol: Protocol to use (udp, tcp, http)
            duration: Attack duration in seconds
            rate: Packets per second per node
        """
        if not self.node:
            raise KademliaError("Coordinator not started")
        
        if swarm_name not in self.swarms:
            self.create_swarm(swarm_name)
        
        config = AttackConfig(
            target=target,
            port=port,
            protocol=protocol,
            duration=duration,
            rate=rate,
            swarm_id=swarm_name
        )
        
        self.node.broadcast_attack(config)
        logger.info(f"Coordinated attack on {target}:{port} across swarm '{swarm_name}'")
    
    def add_attack_handler(self, handler) -> None:
        """
        Add a callback to handle incoming attack commands
        
        Args:
            handler: Callable that takes an AttackConfig and executes the attack
        """
        self.attack_handlers.append(handler)
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        if not self.node:
            return {'status': 'stopped'}
        
        stats = self.node.get_stats()
        stats['swarms'] = list(self.swarms.keys())
        stats['swarm_count'] = len(self.swarms)
        
        return stats


# Utility functions for P2P coordination

def generate_node_id() -> str:
    """Generate a random 160-bit node ID"""
    import os
    return os.urandom(20).hex()


def calculate_swarm_id(swarm_name: str) -> str:
    """Calculate swarm ID from name"""
    return hashlib.sha1(swarm_name.encode()).hexdigest()


def discover_local_peers(port_range: Tuple[int, int] = (8000, 8100)) -> List[str]:
    """
    Discover peers on the local network by scanning common ports
    
    Args:
        port_range: Range of ports to scan (start, end)
        
    Returns:
        List of discovered peer addresses
    """
    import socket
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    def check_port(host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            # Try to connect - if it fails, port might be open for UDP
            result = sock.connect_ex((host, port))
            sock.close()
            return f"{host}:{port}" if result == 0 else None
        except:
            return None
    
    # Get local network range
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    network_base = '.'.join(local_ip.split('.')[:-1]) + '.'
    
    peers = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        
        # Scan local network
        for i in range(1, 255):
            host = network_base + str(i)
            for port in range(port_range[0], port_range[1]):
                futures.append(executor.submit(check_port, host, port))
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                peers.append(result)
    
    return peers


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example: Create a simple P2P network
    coordinator = P2PCoordinator()
    
    try:
        # Start coordinator
        coordinator.start()
        
        # Create a test swarm
        swarm_id = coordinator.create_swarm("test-swarm")
        print(f"Created swarm: {swarm_id}")
        
        # Wait a bit for network to stabilize
        time.sleep(2)
        
        # Get network stats
        stats = coordinator.get_network_stats()
        print(f"Network stats: {json.dumps(stats, indent=2)}")
        
        # Keep running for a bit
        time.sleep(10)
        
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        coordinator.stop()