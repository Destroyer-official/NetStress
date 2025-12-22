"""
GossipSub Pulse Coordination

Implements pulse command coordination via GossipSub v1.1 with Ed25519 message signing
for distributed synchronized attacks.
"""

import asyncio
import json
import logging
import time
import hashlib
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import socket
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .pulse_sync import PulseCommand, PulseSyncEngine

logger = logging.getLogger(__name__)


class GossipTopics:
    """GossipSub topic names for different message types"""
    PULSE_COMMANDS = "netstress.pulse.commands"
    TIME_SYNC = "netstress.time.sync"
    MESH_CONTROL = "netstress.mesh.control"


@dataclass
class GossipMessage:
    """GossipSub message wrapper"""
    topic: str
    message_id: str
    sender_id: str
    timestamp: float
    payload: Dict[str, Any]
    signature: Optional[bytes] = None
    ttl: int = 5
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'topic': self.topic,
            'message_id': self.message_id,
            'sender_id': self.sender_id,
            'timestamp': self.timestamp,
            'payload': self.payload,
            'signature': self.signature.hex() if self.signature else None,
            'ttl': self.ttl
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GossipMessage':
        """Create from dictionary"""
        signature = None
        if data.get('signature'):
            signature = bytes.fromhex(data['signature'])
        
        return cls(
            topic=data['topic'],
            message_id=data['message_id'],
            sender_id=data['sender_id'],
            timestamp=data['timestamp'],
            payload=data['payload'],
            signature=signature,
            ttl=data.get('ttl', 5)
        )
    
    def sign(self, private_key: Ed25519PrivateKey):
        """Sign the message with Ed25519"""
        # Create message to sign (exclude signature field)
        message_data = {
            'topic': self.topic,
            'message_id': self.message_id,
            'sender_id': self.sender_id,
            'timestamp': self.timestamp,
            'payload': self.payload,
            'ttl': self.ttl
        }
        message = json.dumps(message_data, sort_keys=True).encode('utf-8')
        self.signature = private_key.sign(message)
    
    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Verify message signature"""
        if not self.signature:
            return False
        
        try:
            # Recreate message without signature
            message_data = {
                'topic': self.topic,
                'message_id': self.message_id,
                'sender_id': self.sender_id,
                'timestamp': self.timestamp,
                'payload': self.payload,
                'ttl': self.ttl
            }
            message = json.dumps(message_data, sort_keys=True).encode('utf-8')
            public_key.verify(self.signature, message)
            return True
        except Exception as e:
            logger.warning(f"Message signature verification failed: {e}")
            return False


class PeerScore:
    """Peer scoring for GossipSub mesh quality"""
    
    def __init__(self):
        self.scores: Dict[str, float] = {}
        self.message_counts: Dict[str, int] = {}
        self.invalid_messages: Dict[str, int] = {}
        self.last_seen: Dict[str, float] = {}
        
        # Score thresholds
        self.gossip_threshold = -10.0
        self.publish_threshold = -50.0
        self.graylist_threshold = -80.0
    
    def update_peer_score(self, peer_id: str, valid_message: bool = True):
        """Update peer score based on message validity"""
        current_time = time.time()
        
        # Initialize if new peer
        if peer_id not in self.scores:
            self.scores[peer_id] = 0.0
            self.message_counts[peer_id] = 0
            self.invalid_messages[peer_id] = 0
        
        self.last_seen[peer_id] = current_time
        self.message_counts[peer_id] += 1
        
        if valid_message:
            # Reward valid messages
            self.scores[peer_id] += 1.0
        else:
            # Penalize invalid messages heavily
            self.scores[peer_id] -= 10.0
            self.invalid_messages[peer_id] += 1
        
        # Apply time decay (scores decay over time)
        self._apply_time_decay(peer_id, current_time)
    
    def _apply_time_decay(self, peer_id: str, current_time: float):
        """Apply time-based score decay"""
        if peer_id not in self.last_seen:
            return
        
        time_since_last = current_time - self.last_seen[peer_id]
        if time_since_last > 300:  # 5 minutes
            # Decay score towards zero
            decay_factor = 0.95
            self.scores[peer_id] *= decay_factor
    
    def can_gossip_to_peer(self, peer_id: str) -> bool:
        """Check if peer score allows gossiping"""
        return self.scores.get(peer_id, 0.0) > self.gossip_threshold
    
    def can_publish_to_peer(self, peer_id: str) -> bool:
        """Check if peer score allows publishing"""
        return self.scores.get(peer_id, 0.0) > self.publish_threshold
    
    def is_peer_graylisted(self, peer_id: str) -> bool:
        """Check if peer is graylisted (very low score)"""
        return self.scores.get(peer_id, 0.0) <= self.graylist_threshold
    
    def get_peer_stats(self) -> Dict[str, Any]:
        """Get peer scoring statistics"""
        return {
            'total_peers': len(self.scores),
            'average_score': sum(self.scores.values()) / len(self.scores) if self.scores else 0.0,
            'graylisted_peers': sum(1 for score in self.scores.values() if score <= self.graylist_threshold),
            'total_messages': sum(self.message_counts.values()),
            'total_invalid': sum(self.invalid_messages.values())
        }


class GossipSubCoordinator:
    """
    GossipSub-based pulse coordination for distributed attacks.
    
    Implements GossipSub v1.1 with Ed25519 message signing, peer scoring,
    and flood publishing for time-critical pulse commands.
    """
    
    def __init__(self, sync_engine: PulseSyncEngine, listen_port: int = 9000):
        self.sync_engine = sync_engine
        self.listen_port = listen_port
        self.node_id = sync_engine.node_id
        
        # GossipSub state
        self.peers: Dict[str, Dict[str, Any]] = {}  # peer_id -> peer_info
        self.subscriptions: Dict[str, Set[str]] = {}  # topic -> set of peer_ids
        self.message_cache: Dict[str, GossipMessage] = {}  # message_id -> message
        self.seen_messages: Set[str] = set()
        
        # Peer scoring
        self.peer_score = PeerScore()
        
        # Message handlers
        self.message_handlers: Dict[str, List[Callable[[GossipMessage], None]]] = {}
        
        # Cryptographic keys (use same as sync engine)
        self.private_key = sync_engine.private_key
        self.public_key = sync_engine.public_key
        self.peer_keys = sync_engine.peer_keys
        
        # Network
        self.server: Optional[asyncio.Server] = None
        self.running = False
        
        # GossipSub v1.1 configuration with strict validation
        self.config = {
            'heartbeat_interval': 0.7,  # 700ms heartbeat
            'fanout_ttl': 60.0,         # 60s fanout TTL
            'gossip_factor': 0.25,      # 25% of peers for gossip
            'mesh_n': 6,                # Target mesh size
            'mesh_n_low': 4,            # Low watermark
            'mesh_n_high': 12,          # High watermark
            'flood_publish': True,      # Flood for time-critical messages
            'history_length': 5,        # Message history length
            'history_gossip': 3,        # Gossip history length
            'validation_mode': 'strict', # Strict message validation
            'message_signing': True,    # Enable Ed25519 message signing
            'duplicate_cache_time': 60.0, # 60s duplicate cache
            'max_transmit_size': 65536, # Max message size
        }
        
        # Tasks
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.maintenance_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start the GossipSub coordinator"""
        # Start TCP server for peer connections
        self.server = await asyncio.start_server(
            self._handle_peer_connection, '0.0.0.0', self.listen_port
        )
        
        self.running = True
        
        # Start background tasks
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self.maintenance_task = asyncio.create_task(self._maintenance_loop())
        
        # Subscribe to pulse command topic
        self.subscribe(GossipTopics.PULSE_COMMANDS, self._handle_pulse_command)
        
        logger.info(f"GossipSub coordinator started on port {self.listen_port}")
    
    async def stop(self):
        """Stop the GossipSub coordinator"""
        self.running = False
        
        # Cancel background tasks
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        if self.maintenance_task:
            self.maintenance_task.cancel()
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("GossipSub coordinator stopped")
    
    def subscribe(self, topic: str, handler: Callable[[GossipMessage], None]):
        """Subscribe to a topic with message handler"""
        if topic not in self.message_handlers:
            self.message_handlers[topic] = []
        
        self.message_handlers[topic].append(handler)
        logger.info(f"Subscribed to topic: {topic}")
    
    def add_peer(self, peer_id: str, address: str, port: int, public_key: Optional[bytes] = None):
        """Add a peer to the mesh"""
        self.peers[peer_id] = {
            'address': address,
            'port': port,
            'connected': False,
            'last_heartbeat': 0.0,
            'subscriptions': set()
        }
        
        if public_key:
            self.sync_engine.add_peer_key(peer_id, public_key)
        
        logger.info(f"Added peer {peer_id} at {address}:{port}")
    
    async def connect_to_peer(self, peer_id: str) -> bool:
        """Connect to a peer"""
        if peer_id not in self.peers:
            logger.error(f"Unknown peer: {peer_id}")
            return False
        
        peer_info = self.peers[peer_id]
        try:
            reader, writer = await asyncio.open_connection(
                peer_info['address'], peer_info['port']
            )
            
            # Send handshake
            handshake = {
                'type': 'handshake',
                'node_id': self.node_id,
                'public_key': self.sync_engine.get_public_key_bytes().hex(),
                'subscriptions': list(self.message_handlers.keys())
            }
            
            await self._send_message(writer, handshake)
            peer_info['connected'] = True
            peer_info['writer'] = writer
            
            # Start reading messages from this peer
            asyncio.create_task(self._read_peer_messages(peer_id, reader))
            
            logger.info(f"Connected to peer {peer_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            return False
    
    def generate_message_id(self, message: GossipMessage) -> str:
        """
        Generate unique message ID based on content hash.
        
        GossipSub v1.1 compliant message ID function that creates
        deterministic IDs based on message content and sender.
        """
        # Create deterministic message ID from content
        id_data = {
            'topic': message.topic,
            'sender_id': message.sender_id,
            'timestamp': message.timestamp,
            'payload': message.payload
        }
        
        # Use SHA-256 hash for message ID
        content = json.dumps(id_data, sort_keys=True).encode('utf-8')
        hash_digest = hashlib.sha256(content).hexdigest()
        
        # Return first 16 characters for compact ID
        return hash_digest[:16]
    async def publish_pulse_command(self, pulse_command: PulseCommand):
        """
        Publish a pulse command via GossipSub with flood publishing.
        
        Args:
            pulse_command: The pulse command to broadcast
        """
        # Create GossipSub message
        gossip_msg = GossipMessage(
            topic=GossipTopics.PULSE_COMMANDS,
            message_id="",  # Will be set by generate_message_id
            sender_id=self.node_id,
            timestamp=time.time(),
            payload=pulse_command.to_dict()
        )
        
        # Generate deterministic message ID
        gossip_msg.message_id = self.generate_message_id(gossip_msg)
        
        # Sign the message with Ed25519
        gossip_msg.sign(self.private_key)
        
        # Add to seen messages to avoid processing our own message
        self.seen_messages.add(gossip_msg.message_id)
        
        # Store in message cache
        self.message_cache[gossip_msg.message_id] = gossip_msg
        
        # Flood publish to all connected peers (time-critical)
        if self.config['flood_publish']:
            await self._flood_publish(gossip_msg)
        else:
            await self._gossip_publish(gossip_msg)
        
        logger.info(f"Published pulse command {pulse_command.pulse_id} to mesh with message ID {gossip_msg.message_id}")
    
    async def _flood_publish(self, message: GossipMessage):
        """Flood publish message to all connected peers"""
        published_count = 0
        
        for peer_id, peer_info in self.peers.items():
            if not peer_info.get('connected'):
                continue
            
            if self.peer_score.can_publish_to_peer(peer_id):
                try:
                    await self._send_gossip_message(peer_id, message)
                    published_count += 1
                except Exception as e:
                    logger.warning(f"Failed to flood publish to {peer_id}: {e}")
        
        logger.debug(f"Flood published to {published_count} peers")
    
    async def _gossip_publish(self, message: GossipMessage):
        """Gossip publish message to subset of peers"""
        # Select subset of peers based on gossip factor
        connected_peers = [
            peer_id for peer_id, info in self.peers.items()
            if info.get('connected') and self.peer_score.can_gossip_to_peer(peer_id)
        ]
        
        if not connected_peers:
            logger.warning("No connected peers for gossip publishing")
            return
        
        # Select gossip_factor percentage of peers
        import random
        gossip_count = max(1, int(len(connected_peers) * self.config['gossip_factor']))
        selected_peers = random.sample(connected_peers, min(gossip_count, len(connected_peers)))
        
        published_count = 0
        for peer_id in selected_peers:
            try:
                await self._send_gossip_message(peer_id, message)
                published_count += 1
            except Exception as e:
                logger.warning(f"Failed to gossip publish to {peer_id}: {e}")
        
        logger.debug(f"Gossip published to {published_count} peers")
    
    async def _send_gossip_message(self, peer_id: str, message: GossipMessage):
        """Send gossip message to specific peer"""
        peer_info = self.peers.get(peer_id)
        if not peer_info or not peer_info.get('connected'):
            return
        
        writer = peer_info.get('writer')
        if not writer:
            return
        
        gossip_data = {
            'type': 'gossip',
            'message': message.to_dict()
        }
        
        await self._send_message(writer, gossip_data)
    
    async def _handle_peer_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming peer connection"""
        peer_addr = writer.get_extra_info('peername')
        logger.info(f"New peer connection from {peer_addr}")
        
        try:
            while True:
                # Read message
                message = await self._read_message(reader)
                if not message:
                    break
                
                await self._process_peer_message(message, writer)
                
        except Exception as e:
            logger.error(f"Error handling peer connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _read_peer_messages(self, peer_id: str, reader: asyncio.StreamReader):
        """Read messages from a connected peer"""
        try:
            while self.running:
                message = await self._read_message(reader)
                if not message:
                    break
                
                await self._process_peer_message(message, None, peer_id)
                
        except Exception as e:
            logger.error(f"Error reading from peer {peer_id}: {e}")
        finally:
            # Mark peer as disconnected
            if peer_id in self.peers:
                self.peers[peer_id]['connected'] = False
    
    async def _process_peer_message(self, message: Dict[str, Any], writer: Optional[asyncio.StreamWriter], peer_id: Optional[str] = None):
        """Process message from peer"""
        msg_type = message.get('type')
        
        if msg_type == 'handshake':
            await self._handle_handshake(message, writer)
        elif msg_type == 'gossip':
            await self._handle_gossip_message(message, peer_id)
        elif msg_type == 'heartbeat':
            await self._handle_heartbeat(message, peer_id)
        else:
            logger.warning(f"Unknown message type: {msg_type}")
    
    async def _handle_handshake(self, message: Dict[str, Any], writer: asyncio.StreamWriter):
        """Handle peer handshake"""
        peer_node_id = message.get('node_id')
        public_key_hex = message.get('public_key')
        subscriptions = message.get('subscriptions', [])
        
        if not peer_node_id:
            logger.warning("Handshake missing node_id")
            return
        
        # Add peer key if provided
        if public_key_hex:
            try:
                public_key_bytes = bytes.fromhex(public_key_hex)
                self.sync_engine.add_peer_key(peer_node_id, public_key_bytes)
            except Exception as e:
                logger.warning(f"Invalid public key in handshake: {e}")
        
        # Update peer info
        if peer_node_id not in self.peers:
            peer_addr = writer.get_extra_info('peername')
            self.peers[peer_node_id] = {
                'address': peer_addr[0],
                'port': peer_addr[1],
                'connected': True,
                'last_heartbeat': time.time(),
                'subscriptions': set(subscriptions),
                'writer': writer
            }
        else:
            self.peers[peer_node_id]['connected'] = True
            self.peers[peer_node_id]['subscriptions'] = set(subscriptions)
            self.peers[peer_node_id]['writer'] = writer
        
        logger.info(f"Handshake completed with peer {peer_node_id}")
    
    async def _handle_gossip_message(self, message: Dict[str, Any], peer_id: Optional[str]):
        """Handle incoming gossip message"""
        try:
            gossip_data = message.get('message')
            if not gossip_data:
                return
            
            gossip_msg = GossipMessage.from_dict(gossip_data)
            
            # Check if we've already seen this message
            if gossip_msg.message_id in self.seen_messages:
                return
            
            # Verify signature if we have the sender's public key
            sender_key = self.peer_keys.get(gossip_msg.sender_id)
            valid_signature = True
            
            if sender_key and gossip_msg.signature:
                valid_signature = gossip_msg.verify(sender_key)
                if not valid_signature:
                    logger.warning(f"Invalid signature from {gossip_msg.sender_id}")
            
            # Update peer score
            if peer_id:
                self.peer_score.update_peer_score(peer_id, valid_signature)
            
            # Reject messages with invalid signatures
            if not valid_signature and sender_key:
                return
            
            # Mark as seen
            self.seen_messages.add(gossip_msg.message_id)
            
            # Store in cache
            self.message_cache[gossip_msg.message_id] = gossip_msg
            
            # Process message based on topic
            handlers = self.message_handlers.get(gossip_msg.topic, [])
            for handler in handlers:
                try:
                    handler(gossip_msg)
                except Exception as e:
                    logger.error(f"Message handler error: {e}")
            
            # Propagate message if TTL > 0
            if gossip_msg.ttl > 0:
                gossip_msg.ttl -= 1
                await self._gossip_publish(gossip_msg)
            
        except Exception as e:
            logger.error(f"Error handling gossip message: {e}")
    
    async def _handle_heartbeat(self, message: Dict[str, Any], peer_id: Optional[str]):
        """Handle peer heartbeat"""
        if peer_id and peer_id in self.peers:
            self.peers[peer_id]['last_heartbeat'] = time.time()
    
    def _handle_pulse_command(self, message: GossipMessage):
        """Handle received pulse command"""
        try:
            # Parse pulse command from message payload
            pulse_command = PulseCommand.from_dict(message.payload)
            
            # Verify command signature if we have sender's key
            sender_key = self.peer_keys.get(message.sender_id)
            if sender_key and not pulse_command.verify(sender_key):
                logger.warning(f"Invalid pulse command signature from {message.sender_id}")
                return
            
            # Check if command is for future execution
            current_time = self.sync_engine.get_synchronized_time()
            if pulse_command.scheduled_time > current_time:
                # Schedule for synchronized execution
                logger.info(f"Received pulse command {pulse_command.pulse_id} "
                           f"scheduled for {pulse_command.scheduled_time - current_time:.3f}s from now")
                
                # Execute the synchronized burst in a separate task
                asyncio.create_task(self.sync_engine.execute_synchronized_burst(pulse_command))
            else:
                logger.warning(f"Received pulse command {pulse_command.pulse_id} "
                              f"scheduled for the past ({current_time - pulse_command.scheduled_time:.3f}s ago)")
        
        except Exception as e:
            logger.error(f"Error processing pulse command: {e}")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to peers"""
        while self.running:
            try:
                heartbeat_msg = {
                    'type': 'heartbeat',
                    'node_id': self.node_id,
                    'timestamp': time.time()
                }
                
                # Send to all connected peers
                for peer_id, peer_info in self.peers.items():
                    if peer_info.get('connected') and peer_info.get('writer'):
                        try:
                            await self._send_message(peer_info['writer'], heartbeat_msg)
                        except Exception as e:
                            logger.warning(f"Failed to send heartbeat to {peer_id}: {e}")
                            peer_info['connected'] = False
                
                await asyncio.sleep(self.config['heartbeat_interval'])
                
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}")
                await asyncio.sleep(1.0)
    
    async def _maintenance_loop(self):
        """Perform periodic maintenance tasks"""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean up old messages from cache
                old_messages = [
                    msg_id for msg_id, msg in self.message_cache.items()
                    if current_time - msg.timestamp > 300  # 5 minutes
                ]
                for msg_id in old_messages:
                    del self.message_cache[msg_id]
                
                # Clean up seen messages set
                if len(self.seen_messages) > 10000:
                    # Keep only recent message IDs
                    recent_messages = {
                        msg_id for msg_id, msg in self.message_cache.items()
                        if current_time - msg.timestamp < 60  # 1 minute
                    }
                    self.seen_messages = recent_messages
                
                # Check for disconnected peers
                disconnected_peers = []
                for peer_id, peer_info in self.peers.items():
                    if (peer_info.get('connected') and 
                        current_time - peer_info.get('last_heartbeat', 0) > 30):  # 30s timeout
                        peer_info['connected'] = False
                        disconnected_peers.append(peer_id)
                
                if disconnected_peers:
                    logger.info(f"Marked {len(disconnected_peers)} peers as disconnected")
                
                await asyncio.sleep(30)  # Run every 30 seconds
                
            except Exception as e:
                logger.error(f"Maintenance loop error: {e}")
                await asyncio.sleep(5.0)
    
    async def _send_message(self, writer: asyncio.StreamWriter, message: Dict[str, Any]):
        """Send message to peer"""
        data = json.dumps(message).encode('utf-8')
        length = len(data)
        
        # Send length-prefixed message
        writer.write(length.to_bytes(4, 'big'))
        writer.write(data)
        await writer.drain()
    
    async def _read_message(self, reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
        """Read message from peer"""
        try:
            # Read length
            length_data = await reader.read(4)
            if len(length_data) != 4:
                return None
            
            length = int.from_bytes(length_data, 'big')
            
            # Read message data
            data = await reader.read(length)
            if len(data) != length:
                return None
            
            return json.loads(data.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error reading message: {e}")
            return None
    
    def get_mesh_stats(self) -> Dict[str, Any]:
        """Get mesh statistics"""
        connected_peers = sum(1 for info in self.peers.values() if info.get('connected'))
        
        return {
            'total_peers': len(self.peers),
            'connected_peers': connected_peers,
            'cached_messages': len(self.message_cache),
            'seen_messages': len(self.seen_messages),
            'subscriptions': len(self.message_handlers),
            'peer_scores': self.peer_score.get_peer_stats(),
            'config': self.config
        }