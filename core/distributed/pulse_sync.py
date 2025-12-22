"""
PTP-like Pulse Synchronization Engine

Implements precision time protocol-like synchronization for distributed attacks
with sub-10ms accuracy and coordinated pulse bursts via GossipSub.
"""

import asyncio
import time
import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Tuple
from enum import Enum
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

logger = logging.getLogger(__name__)


class PulseMode(Enum):
    """Attack mode enumeration"""
    CONTINUOUS = "continuous"
    PULSE = "pulse"


@dataclass
class SyncRequest:
    """PTP-like synchronization request"""
    request_id: str
    sender_id: str
    t1_timestamp: float  # Client transmit time
    sequence: int = 0
    
    def to_bytes(self) -> bytes:
        """Serialize sync request"""
        data = {
            'request_id': self.request_id,
            'sender_id': self.sender_id,
            't1_timestamp': self.t1_timestamp,
            'sequence': self.sequence
        }
        return json.dumps(data).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SyncRequest':
        """Deserialize sync request"""
        parsed = json.loads(data.decode('utf-8'))
        return cls(**parsed)


@dataclass
class SyncResponse:
    """PTP-like synchronization response"""
    request_id: str
    responder_id: str
    t1_timestamp: float  # Original client transmit time
    t2_timestamp: float  # Server receive time
    t3_timestamp: float  # Server transmit time
    sequence: int = 0
    
    def to_bytes(self) -> bytes:
        """Serialize sync response"""
        data = {
            'request_id': self.request_id,
            'responder_id': self.responder_id,
            't1_timestamp': self.t1_timestamp,
            't2_timestamp': self.t2_timestamp,
            't3_timestamp': self.t3_timestamp,
            'sequence': self.sequence
        }
        return json.dumps(data).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SyncResponse':
        """Deserialize sync response"""
        parsed = json.loads(data.decode('utf-8'))
        return cls(**parsed)


@dataclass
class SyncResult:
    """Result of time synchronization"""
    peer_id: str
    offset: float  # Clock offset in seconds (positive = local ahead)
    delay: float   # Round-trip delay in seconds
    accuracy: float  # Estimated accuracy in seconds
    timestamp: float  # When sync was performed
    
    @property
    def synchronized_time(self) -> float:
        """Get current synchronized time"""
        return time.time() - self.offset


@dataclass
class PulseCommand:
    """Coordinated pulse command"""
    pulse_id: str
    scheduled_time: float  # Unix timestamp in nanoseconds
    duration_ms: int       # Pulse duration in milliseconds
    intensity: float       # 0.0 - 1.0
    attack_params: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'pulse_id': self.pulse_id,
            'scheduled_time': self.scheduled_time,
            'duration_ms': self.duration_ms,
            'intensity': self.intensity,
            'attack_params': self.attack_params,
            'signature': self.signature.hex() if self.signature else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PulseCommand':
        """Create from dictionary"""
        signature = None
        if data.get('signature'):
            signature = bytes.fromhex(data['signature'])
        
        return cls(
            pulse_id=data['pulse_id'],
            scheduled_time=data['scheduled_time'],
            duration_ms=data['duration_ms'],
            intensity=data['intensity'],
            attack_params=data.get('attack_params', {}),
            signature=signature
        )
    
    def sign(self, private_key: Ed25519PrivateKey):
        """Sign the pulse command"""
        # Create message to sign (exclude signature field)
        message_data = {
            'pulse_id': self.pulse_id,
            'scheduled_time': self.scheduled_time,
            'duration_ms': self.duration_ms,
            'intensity': self.intensity,
            'attack_params': self.attack_params
        }
        message = json.dumps(message_data, sort_keys=True).encode('utf-8')
        self.signature = private_key.sign(message)
    
    def verify(self, public_key: Ed25519PublicKey) -> bool:
        """Verify pulse command signature"""
        if not self.signature:
            return False
        
        try:
            # Recreate message without signature
            message_data = {
                'pulse_id': self.pulse_id,
                'scheduled_time': self.scheduled_time,
                'duration_ms': self.duration_ms,
                'intensity': self.intensity,
                'attack_params': self.attack_params
            }
            message = json.dumps(message_data, sort_keys=True).encode('utf-8')
            public_key.verify(self.signature, message)
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False


class PTPSyncProtocol:
    """
    PTP-like time synchronization protocol implementation.
    
    Implements the core synchronization algorithm:
    1. Send sync request with local timestamp (t1)
    2. Peer records receive time (t2) and send time (t3)
    3. Calculate round-trip time and clock offset using PTP formula
    """
    
    def __init__(self, node_id: str, port: int = 8765):
        self.node_id = node_id
        self.port = port
        self.server = None
        self.running = False
        self.sync_handlers: List[Callable[[SyncRequest], SyncResponse]] = []
        
    async def start_server(self):
        """Start the sync protocol server"""
        self.server = await asyncio.start_server(
            self._handle_client, '0.0.0.0', self.port
        )
        self.running = True
        logger.info(f"PTP sync server started on port {self.port}")
        
    async def stop_server(self):
        """Stop the sync protocol server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.running = False
        logger.info("PTP sync server stopped")
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming sync requests"""
        try:
            # Read request length
            length_data = await reader.read(4)
            if len(length_data) != 4:
                return
            
            length = struct.unpack('!I', length_data)[0]
            
            # Read request data
            request_data = await reader.read(length)
            if len(request_data) != length:
                return
            
            # Parse request
            request = SyncRequest.from_bytes(request_data)
            
            # Record receive time (t2)
            t2 = time.time()
            
            # Process request and create response
            t3 = time.time()  # Send time
            response = SyncResponse(
                request_id=request.request_id,
                responder_id=self.node_id,
                t1_timestamp=request.t1_timestamp,
                t2_timestamp=t2,
                t3_timestamp=t3,
                sequence=request.sequence
            )
            
            # Send response
            response_data = response.to_bytes()
            writer.write(struct.pack('!I', len(response_data)))
            writer.write(response_data)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Error handling sync request: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def sync_with_peer(self, peer_host: str, peer_port: int) -> SyncResult:
        """
        Perform PTP-like synchronization with a peer.
        
        Args:
            peer_host: Peer hostname/IP
            peer_port: Peer port
            
        Returns:
            SyncResult with calculated offset and delay
        """
        try:
            # Connect to peer
            reader, writer = await asyncio.open_connection(peer_host, peer_port)
            
            # Create sync request
            request_id = hashlib.sha256(f"{self.node_id}:{time.time()}".encode()).hexdigest()[:16]
            t1 = time.time()  # Client transmit time
            
            request = SyncRequest(
                request_id=request_id,
                sender_id=self.node_id,
                t1_timestamp=t1
            )
            
            # Send request
            request_data = request.to_bytes()
            writer.write(struct.pack('!I', len(request_data)))
            writer.write(request_data)
            await writer.drain()
            
            # Read response
            length_data = await reader.read(4)
            length = struct.unpack('!I', length_data)[0]
            response_data = await reader.read(length)
            
            t4 = time.time()  # Client receive time
            
            # Parse response
            response = SyncResponse.from_bytes(response_data)
            
            # Calculate offset and delay using PTP algorithm
            # t1 = client transmit time
            # t2 = server receive time
            # t3 = server transmit time
            # t4 = client receive time
            
            # Offset = ((t2 - t1) + (t3 - t4)) / 2
            offset = ((response.t2_timestamp - t1) + (response.t3_timestamp - t4)) / 2
            
            # Delay = (t4 - t1) - (t3 - t2)
            delay = (t4 - t1) - (response.t3_timestamp - response.t2_timestamp)
            
            # Estimate accuracy based on delay variation
            accuracy = delay / 2  # Conservative estimate
            
            writer.close()
            await writer.wait_closed()
            
            return SyncResult(
                peer_id=response.responder_id,
                offset=offset,
                delay=delay,
                accuracy=accuracy,
                timestamp=t4
            )
            
        except Exception as e:
            logger.error(f"Sync with {peer_host}:{peer_port} failed: {e}")
            raise


class PulseSyncEngine:
    """
    Main pulse synchronization engine that coordinates PTP-like time sync
    and pulse command distribution via GossipSub.
    """
    
    def __init__(self, node_id: str, sync_port: int = 8765, gossip_port: int = 9000):
        self.node_id = node_id
        self.sync_protocol = PTPSyncProtocol(node_id, sync_port)
        
        # Time synchronization state
        self.peer_offsets: Dict[str, SyncResult] = {}
        self.local_offset: float = 0.0  # Offset from reference time
        self.reference_peer: Optional[str] = None
        
        # Pulse coordination
        self.pulse_mode = PulseMode.CONTINUOUS
        self.pulse_interval_ms: int = 1000  # Default 1 second
        self.pulse_callbacks: List[Callable[[PulseCommand], None]] = []
        self.pulse_history: List[Tuple[float, PulseCommand]] = []  # Execution history
        
        # Cryptographic keys for message signing
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.peer_keys: Dict[str, Ed25519PublicKey] = {}
        
        # GossipSub coordinator (lazy initialization)
        self._gossip_coordinator = None
        self.gossip_port = gossip_port
        
        # Running state
        self.running = False
        self.sync_task: Optional[asyncio.Task] = None
        self.burst_executor_task: Optional[asyncio.Task] = None
        
    async def start(self):
        """Start the pulse sync engine"""
        await self.sync_protocol.start_server()
        self.running = True
        
        # Start periodic sync task
        self.sync_task = asyncio.create_task(self._periodic_sync())
        
        # Start synchronized burst executor
        await self.start_burst_executor()
        
        # Initialize and start GossipSub coordinator
        await self._ensure_gossip_coordinator()
        if self._gossip_coordinator:
            await self._gossip_coordinator.start()
        
        logger.info(f"Pulse sync engine started for node {self.node_id}")
    
    async def stop(self):
        """Stop the pulse sync engine"""
        self.running = False
        
        if self.sync_task:
            self.sync_task.cancel()
            try:
                await self.sync_task
            except asyncio.CancelledError:
                pass
        
        # Stop synchronized burst executor
        await self.stop_burst_executor()
        
        # Stop GossipSub coordinator
        if self._gossip_coordinator:
            await self._gossip_coordinator.stop()
        
        await self.sync_protocol.stop_server()
        logger.info("Pulse sync engine stopped")
    
    async def _ensure_gossip_coordinator(self):
        """Ensure GossipSub coordinator is initialized"""
        if self._gossip_coordinator is None:
            try:
                from .gossipsub_coordinator import GossipSubCoordinator
                self._gossip_coordinator = GossipSubCoordinator(self, self.gossip_port)
            except ImportError as e:
                logger.warning(f"GossipSub coordinator not available: {e}")
    
    @property
    def gossip_coordinator(self):
        """Get GossipSub coordinator (may be None if not available)"""
        return self._gossip_coordinator
    
    async def _periodic_sync(self):
        """Periodically sync with peers to maintain accuracy"""
        while self.running:
            try:
                # Sync with all known peers
                for peer_id in list(self.peer_offsets.keys()):
                    # In a real implementation, you'd have peer addresses
                    # For now, we'll skip the actual sync
                    pass
                
                await asyncio.sleep(30)  # Sync every 30 seconds
                
            except Exception as e:
                logger.error(f"Periodic sync error: {e}")
                await asyncio.sleep(5)
    
    def get_synchronized_time(self) -> float:
        """Get current synchronized time"""
        return time.time() - self.local_offset
    
    def add_pulse_callback(self, callback: Callable[[PulseCommand], None]):
        """Add callback for pulse command execution"""
        self.pulse_callbacks.append(callback)
    
    def set_pulse_mode(self, mode: PulseMode):
        """
        Set attack mode (continuous or pulse) with runtime switching support.
        
        Args:
            mode: PulseMode.CONTINUOUS for constant traffic or PulseMode.PULSE for synchronized bursts
            
        Note:
            Mode can be changed at runtime. The change takes effect immediately.
            In CONTINUOUS mode, traffic flows constantly without synchronization.
            In PULSE mode, traffic is sent in synchronized bursts at configured intervals.
        """
        old_mode = self.pulse_mode
        self.pulse_mode = mode
        
        if old_mode != mode:
            logger.info(f"Pulse mode switched from {old_mode.value} to {mode.value}")
            
            # Notify all pulse callbacks about mode change
            for callback in self.pulse_callbacks:
                try:
                    # Create a special mode change command
                    mode_change_command = PulseCommand(
                        pulse_id=f"mode_change_{time.time()}",
                        scheduled_time=self.get_synchronized_time(),
                        duration_ms=0,
                        intensity=0.0,
                        attack_params={'mode_change': True, 'new_mode': mode.value}
                    )
                    callback(mode_change_command)
                except Exception as e:
                    logger.error(f"Mode change callback error: {e}")
        else:
            logger.info(f"Pulse mode set to {mode.value}")
    
    def set_pulse_interval(self, interval_ms: int):
        """Set pulse interval in milliseconds"""
        if interval_ms < 10:
            raise ValueError("Pulse interval must be at least 10ms")
        self.pulse_interval_ms = interval_ms
        logger.info(f"Pulse interval set to {interval_ms}ms")
    
    def is_continuous_mode(self) -> bool:
        """Check if engine is in continuous mode"""
        return self.pulse_mode == PulseMode.CONTINUOUS
    
    def is_pulse_mode(self) -> bool:
        """Check if engine is in pulse mode"""
        return self.pulse_mode == PulseMode.PULSE
    
    def switch_to_continuous_mode(self):
        """Switch to continuous mode for constant traffic flow"""
        self.set_pulse_mode(PulseMode.CONTINUOUS)
    
    def switch_to_pulse_mode(self, interval_ms: Optional[int] = None):
        """
        Switch to pulse mode for synchronized bursts.
        
        Args:
            interval_ms: Optional pulse interval in milliseconds. If not provided, uses current setting.
        """
        if interval_ms is not None:
            self.set_pulse_interval(interval_ms)
        self.set_pulse_mode(PulseMode.PULSE)
    
    def create_continuous_command(self, intensity: float = 1.0, 
                                attack_params: Optional[Dict[str, Any]] = None) -> PulseCommand:
        """
        Create a command for continuous mode traffic.
        
        Args:
            intensity: Traffic intensity (0.0 - 1.0)
            attack_params: Additional attack parameters
            
        Returns:
            PulseCommand configured for continuous traffic
        """
        command = PulseCommand(
            pulse_id=f"continuous_{time.time()}_{self.node_id}",
            scheduled_time=self.get_synchronized_time(),
            duration_ms=0,  # Continuous mode has no specific duration
            intensity=intensity,
            attack_params=attack_params or {}
        )
        
        # Mark as continuous mode command
        command.attack_params['continuous_mode'] = True
        command.attack_params['mode'] = 'continuous'
        
        # Sign the command
        command.sign(self.private_key)
        
        return command
    
    def execute_continuous_traffic(self, intensity: float = 1.0, 
                                 attack_params: Optional[Dict[str, Any]] = None):
        """
        Execute continuous traffic generation.
        
        Args:
            intensity: Traffic intensity (0.0 - 1.0)
            attack_params: Additional attack parameters
        """
        if not self.is_continuous_mode():
            logger.warning("execute_continuous_traffic called but not in continuous mode")
            return
        
        # Create continuous command
        command = self.create_continuous_command(intensity, attack_params)
        
        logger.info(f"Executing continuous traffic with intensity {intensity}")
        
        # Notify all pulse callbacks to start continuous traffic
        for callback in self.pulse_callbacks:
            try:
                callback(command)
            except Exception as e:
                logger.error(f"Continuous traffic callback error: {e}")
    
    def stop_continuous_traffic(self):
        """Stop continuous traffic generation"""
        # Create stop command
        stop_command = PulseCommand(
            pulse_id=f"stop_continuous_{time.time()}_{self.node_id}",
            scheduled_time=self.get_synchronized_time(),
            duration_ms=0,
            intensity=0.0,
            attack_params={'stop_continuous': True, 'mode': 'continuous'}
        )
        
        # Sign the command
        stop_command.sign(self.private_key)
        
        logger.info("Stopping continuous traffic")
        
        # Notify all pulse callbacks to stop continuous traffic
        for callback in self.pulse_callbacks:
            try:
                callback(stop_command)
            except Exception as e:
                logger.error(f"Stop continuous traffic callback error: {e}")
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key for sharing with peers"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def add_peer_key(self, peer_id: str, public_key_bytes: bytes):
        """Add a peer's public key for signature verification"""
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        self.peer_keys[peer_id] = public_key
        logger.info(f"Added public key for peer {peer_id}")
    async def high_precision_sync_with_peer(self, peer_host: str, peer_port: int, 
                                           rounds: int = 8) -> SyncResult:
        """
        Perform high-precision synchronization with multiple round-trips.
        
        Args:
            peer_host: Peer hostname/IP
            peer_port: Peer port
            rounds: Number of sync rounds for accuracy (default 8)
            
        Returns:
            SyncResult with median offset for robustness
        """
        results = []
        
        for round_num in range(rounds):
            try:
                result = await self.sync_protocol.sync_with_peer(peer_host, peer_port)
                results.append(result)
                
                # Small delay between rounds to avoid overwhelming
                if round_num < rounds - 1:
                    await asyncio.sleep(0.01)  # 10ms delay
                    
            except Exception as e:
                logger.warning(f"Sync round {round_num + 1} failed: {e}")
        
        if not results:
            raise RuntimeError("All sync rounds failed")
        
        # Use median offset for robustness against outliers
        offsets = [r.offset for r in results]
        delays = [r.delay for r in results]
        
        offsets.sort()
        delays.sort()
        
        median_offset = offsets[len(offsets) // 2]
        median_delay = delays[len(delays) // 2]
        
        # Calculate accuracy as standard deviation of offsets
        mean_offset = sum(offsets) / len(offsets)
        variance = sum((o - mean_offset) ** 2 for o in offsets) / len(offsets)
        accuracy = variance ** 0.5
        
        # Ensure sub-10ms accuracy requirement
        if accuracy > 0.010:  # 10ms
            logger.warning(f"Sync accuracy {accuracy*1000:.2f}ms exceeds 10ms target")
        
        result = SyncResult(
            peer_id=results[0].peer_id,
            offset=median_offset,
            delay=median_delay,
            accuracy=accuracy,
            timestamp=time.time()
        )
        
        # Store result
        self.peer_offsets[result.peer_id] = result
        
        # Update local offset if this is the reference peer
        if self.reference_peer == result.peer_id or self.reference_peer is None:
            self.local_offset = median_offset
            self.reference_peer = result.peer_id
        
        logger.info(f"High-precision sync with {result.peer_id}: "
                   f"offset={median_offset*1000:.3f}ms, "
                   f"accuracy={accuracy*1000:.3f}ms, "
                   f"delay={median_delay*1000:.3f}ms")
        
        return result
    
    async def sync_with_mesh_peers(self, peer_addresses: List[Tuple[str, int]]) -> Dict[str, SyncResult]:
        """
        Synchronize with multiple mesh peers for distributed coordination.
        
        Args:
            peer_addresses: List of (host, port) tuples for peers
            
        Returns:
            Dictionary of peer_id -> SyncResult
        """
        sync_tasks = []
        
        for host, port in peer_addresses:
            task = asyncio.create_task(
                self.high_precision_sync_with_peer(host, port)
            )
            sync_tasks.append(task)
        
        # Wait for all sync operations to complete
        results = await asyncio.gather(*sync_tasks, return_exceptions=True)
        
        sync_results = {}
        successful_syncs = 0
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                host, port = peer_addresses[i]
                logger.error(f"Sync with {host}:{port} failed: {result}")
            else:
                sync_results[result.peer_id] = result
                successful_syncs += 1
        
        if successful_syncs == 0:
            raise RuntimeError("Failed to sync with any peers")
        
        # Calculate mesh-wide synchronization quality
        if len(sync_results) > 1:
            offsets = [r.offset for r in sync_results.values()]
            mesh_accuracy = max(offsets) - min(offsets)
            logger.info(f"Mesh sync complete: {successful_syncs} peers, "
                       f"mesh accuracy: {mesh_accuracy*1000:.3f}ms")
        
        return sync_results
    
    def calculate_mesh_offset_consensus(self) -> float:
        """
        Calculate consensus offset from multiple peer synchronizations.
        Uses weighted average based on sync accuracy.
        
        Returns:
            Consensus offset in seconds
        """
        if not self.peer_offsets:
            return 0.0
        
        # Weight by inverse of accuracy (more accurate = higher weight)
        total_weight = 0.0
        weighted_sum = 0.0
        
        for result in self.peer_offsets.values():
            # Avoid division by zero, minimum accuracy of 1ms
            accuracy = max(result.accuracy, 0.001)
            weight = 1.0 / accuracy
            
            weighted_sum += result.offset * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        consensus_offset = weighted_sum / total_weight
        
        # Update local offset to consensus
        self.local_offset = consensus_offset
        
        logger.info(f"Mesh consensus offset: {consensus_offset*1000:.3f}ms")
        return consensus_offset
    
    async def add_mesh_peer(self, peer_id: str, address: str, port: int, 
                           sync_port: Optional[int] = None, public_key: Optional[bytes] = None):
        """
        Add a peer to both sync and GossipSub mesh.
        
        Args:
            peer_id: Unique peer identifier
            address: Peer IP address
            port: Peer GossipSub port
            sync_port: Peer sync port (defaults to port + 1000)
            public_key: Peer's Ed25519 public key bytes
        """
        # Add to GossipSub mesh
        await self._ensure_gossip_coordinator()
        if self._gossip_coordinator:
            self._gossip_coordinator.add_peer(peer_id, address, port, public_key)
            
            # Try to connect to peer
            connected = await self._gossip_coordinator.connect_to_peer(peer_id)
            if connected:
                logger.info(f"Connected to mesh peer {peer_id}")
        
        # Add public key for sync verification
        if public_key:
            self.add_peer_key(peer_id, public_key)
        
        # Optionally perform time sync with this peer
        if sync_port:
            try:
                sync_result = await self.high_precision_sync_with_peer(address, sync_port)
                logger.info(f"Synchronized with peer {peer_id}: offset={sync_result.offset*1000:.3f}ms")
            except Exception as e:
                logger.warning(f"Failed to sync with peer {peer_id}: {e}")
    
    async def broadcast_pulse_command(self, pulse_command: PulseCommand):
        """
        Broadcast a pulse command to the mesh via GossipSub.
        
        Args:
            pulse_command: The pulse command to broadcast
        """
        await self._ensure_gossip_coordinator()
        if self._gossip_coordinator:
            await self._gossip_coordinator.publish_pulse_command(pulse_command)
            logger.info(f"Broadcast pulse command {pulse_command.pulse_id} to mesh")
        else:
            logger.warning("GossipSub coordinator not available for pulse broadcasting")
    
    def high_precision_sleep(self, duration_seconds: float):
        """
        High-precision sleep using busy-wait for sub-millisecond accuracy.
        
        Args:
            duration_seconds: Sleep duration in seconds
        """
        if duration_seconds <= 0:
            return
        
        # For very short durations (< 1ms), use busy-wait for precision
        if duration_seconds < 0.001:
            end_time = time.perf_counter() + duration_seconds
            while time.perf_counter() < end_time:
                pass  # Busy-wait for maximum precision
        else:
            # For longer durations, sleep most of the time and busy-wait the remainder
            sleep_time = duration_seconds - 0.001  # Sleep all but last 1ms
            if sleep_time > 0:
                time.sleep(sleep_time)
            
            # Busy-wait for the remaining time for precision
            end_time = time.perf_counter() + 0.001
            while time.perf_counter() < end_time:
                pass
    
    async def wait_for_pulse_command(self) -> Optional[PulseCommand]:
        """
        Wait for the next pulse command to be received via GossipSub.
        
        Returns:
            The next pulse command to execute, or None if stopped
        """
        # This would typically be implemented with a queue that gets populated
        # by the GossipSub coordinator when pulse commands are received
        await self._ensure_gossip_coordinator()
        if not self._gossip_coordinator:
            logger.warning("GossipSub coordinator not available")
            return None
        
        # For now, we'll implement a simple polling mechanism
        # In a production system, this would use proper async queues
        while self.running:
            try:
                await asyncio.sleep(0.001)  # Check every 1ms
                # The actual pulse command would come from GossipSub coordinator
                # This is a placeholder implementation
            except asyncio.CancelledError:
                break
        
        return None
    
    async def execute_synchronized_burst(self, pulse_command: PulseCommand):
        """
        Execute a synchronized burst at the exact scheduled time.
        
        Args:
            pulse_command: The pulse command to execute
        """
        current_time = self.get_synchronized_time()
        
        # Calculate wait time until scheduled execution
        wait_time = pulse_command.scheduled_time - current_time
        
        if wait_time > 0:
            logger.info(f"Waiting {wait_time:.6f}s for pulse {pulse_command.pulse_id}")
            
            # Use high-precision sleep for accurate timing
            if wait_time > 0.1:  # If more than 100ms, use async sleep for most of it
                async_wait = wait_time - 0.01  # Leave 10ms for high-precision timing
                await asyncio.sleep(async_wait)
                wait_time = 0.01
            
            # Final high-precision wait using busy-wait
            self.high_precision_sleep(wait_time)
        
        # Execute the burst
        execution_start = time.perf_counter()
        logger.info(f"Executing synchronized burst {pulse_command.pulse_id} "
                   f"at {execution_start:.6f} (intensity: {pulse_command.intensity})")
        
        # Notify all pulse callbacks to execute the burst
        for callback in self.pulse_callbacks:
            try:
                callback(pulse_command)
            except Exception as e:
                logger.error(f"Pulse execution callback error: {e}")
        
        execution_end = time.perf_counter()
        execution_duration = (execution_end - execution_start) * 1000  # Convert to ms
        
        logger.info(f"Burst {pulse_command.pulse_id} executed in {execution_duration:.3f}ms")
        
        # Store execution record for statistics
        self.pulse_history.append((execution_start, pulse_command))
        
        # Keep history limited to last 1000 pulses
        if len(self.pulse_history) > 1000:
            self.pulse_history = self.pulse_history[-1000:]
    
    async def start_burst_executor(self):
        """
        Start the synchronized burst executor that waits for and executes pulse commands.
        """
        if not hasattr(self, 'burst_executor_task') or self.burst_executor_task is None:
            self.burst_executor_task = asyncio.create_task(self._burst_executor_loop())
            logger.info("Synchronized burst executor started")
    
    async def stop_burst_executor(self):
        """
        Stop the synchronized burst executor.
        """
        if hasattr(self, 'burst_executor_task') and self.burst_executor_task:
            self.burst_executor_task.cancel()
            try:
                await self.burst_executor_task
            except asyncio.CancelledError:
                pass
            self.burst_executor_task = None
            logger.info("Synchronized burst executor stopped")
    
    async def _burst_executor_loop(self):
        """
        Main loop for the synchronized burst executor.
        Handles both continuous and pulse modes with runtime switching.
        """
        logger.info("Burst executor loop started")
        
        continuous_task = None
        
        while self.running:
            try:
                current_mode = self.pulse_mode
                
                if current_mode == PulseMode.CONTINUOUS:
                    # In continuous mode, maintain constant traffic
                    if continuous_task is None or continuous_task.done():
                        # Start continuous traffic task
                        continuous_task = asyncio.create_task(self._continuous_traffic_loop())
                        logger.info("Started continuous traffic loop")
                    
                    # Check for mode changes every 100ms
                    await asyncio.sleep(0.1)
                    
                elif current_mode == PulseMode.PULSE:
                    # In pulse mode, stop continuous traffic if running
                    if continuous_task and not continuous_task.done():
                        continuous_task.cancel()
                        try:
                            await continuous_task
                        except asyncio.CancelledError:
                            pass
                        continuous_task = None
                        logger.info("Stopped continuous traffic for pulse mode")
                    
                    # Wait for pulse commands from GossipSub or scheduler
                    pulse_command = await self._wait_for_next_pulse()
                    if pulse_command:
                        await self.execute_synchronized_burst(pulse_command)
                else:
                    # Unknown mode, wait briefly
                    await asyncio.sleep(0.1)
                    
            except asyncio.CancelledError:
                logger.info("Burst executor loop cancelled")
                break
            except Exception as e:
                logger.error(f"Burst executor loop error: {e}")
                await asyncio.sleep(0.1)  # Brief pause on error
        
        # Clean up continuous task if running
        if continuous_task and not continuous_task.done():
            continuous_task.cancel()
            try:
                await continuous_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Burst executor loop stopped")
    
    async def _continuous_traffic_loop(self):
        """
        Loop for generating continuous traffic.
        Runs until cancelled or mode changes.
        """
        logger.info("Continuous traffic loop started")
        
        try:
            while self.running and self.pulse_mode == PulseMode.CONTINUOUS:
                # Generate continuous traffic command
                self.execute_continuous_traffic(intensity=1.0)
                
                # Small delay to prevent overwhelming the system
                # In a real implementation, this would be coordinated with the actual traffic generator
                await asyncio.sleep(0.01)  # 10ms intervals for continuous traffic
                
        except asyncio.CancelledError:
            logger.info("Continuous traffic loop cancelled")
            # Send stop command to callbacks
            self.stop_continuous_traffic()
        except Exception as e:
            logger.error(f"Continuous traffic loop error: {e}")
        
        logger.info("Continuous traffic loop stopped")
    
    async def _wait_for_next_pulse(self) -> Optional[PulseCommand]:
        """
        Wait for the next pulse command in pulse mode.
        
        Returns:
            The next pulse command to execute, or None if mode changed or stopped
        """
        # In a real implementation, this would receive commands from GossipSub
        # For now, we'll implement a simple timeout-based approach
        
        try:
            # Wait for a short time and check if we're still in pulse mode
            await asyncio.sleep(0.001)  # 1ms check interval
            
            if self.pulse_mode != PulseMode.PULSE or not self.running:
                return None
            
            # In a production system, this would integrate with the GossipSub coordinator
            # to receive actual pulse commands from the mesh
            # For now, return None to prevent busy waiting
            return None
            
        except asyncio.CancelledError:
            return None
    
    def get_burst_execution_stats(self) -> Dict[str, Any]:
        """
        Get statistics about burst execution performance.
        
        Returns:
            Dictionary with execution statistics
        """
        if not hasattr(self, 'pulse_history'):
            self.pulse_history = []
        
        if not self.pulse_history:
            return {
                'total_bursts_executed': 0,
                'average_execution_time_ms': 0.0,
                'timing_accuracy_ms': 0.0,
                'last_execution': None
            }
        
        # Calculate timing accuracy by comparing scheduled vs actual execution times
        # Note: We need to be careful about time base differences
        timing_errors = []
        
        for execution_time, pulse_command in self.pulse_history[-100:]:  # Last 100 executions
            # Convert scheduled time to same time base as execution_time (perf_counter)
            # This is an approximation since we don't store the exact conversion
            # In practice, for short intervals, the error should be minimal
            current_sync_time = self.get_synchronized_time()
            current_perf_time = time.perf_counter()
            
            # Estimate the perf_counter equivalent of the scheduled time
            time_diff = pulse_command.scheduled_time - current_sync_time
            estimated_perf_scheduled = current_perf_time + time_diff
            
            timing_error = abs(execution_time - estimated_perf_scheduled) * 1000  # Convert to ms
            
            # Only include reasonable timing errors (< 1 second) to filter out time base issues
            if timing_error < 1000:
                timing_errors.append(timing_error)
        
        avg_timing_error = sum(timing_errors) / len(timing_errors) if timing_errors else 0.0
        
        return {
            'total_bursts_executed': len(self.pulse_history),
            'timing_accuracy_ms': avg_timing_error,
            'last_execution': self.pulse_history[-1][0] if self.pulse_history else None,
            'recent_executions': len([t for t, _ in self.pulse_history if time.time() - t < 60])  # Last minute
        }
    
    def get_mesh_stats(self) -> Dict[str, Any]:
        """Get comprehensive mesh statistics"""
        stats = {
            'sync_engine': {
                'node_id': self.node_id,
                'running': self.running,
                'pulse_mode': self.pulse_mode.value,
                'supports_runtime_switching': True,
                'supported_modes': ['continuous', 'pulse'],
                'local_offset_ms': self.local_offset * 1000,
                'reference_peer': self.reference_peer,
                'peer_count': len(self.peer_offsets),
                'pulse_interval_ms': self.pulse_interval_ms,
                'peer_offsets': {
                    peer_id: {
                        'offset_ms': result.offset * 1000,
                        'delay_ms': result.delay * 1000,
                        'accuracy_ms': result.accuracy * 1000,
                        'timestamp': result.timestamp
                    }
                    for peer_id, result in self.peer_offsets.items()
                }
            },
            'burst_execution': self.get_burst_execution_stats()
        }
        
        # Add GossipSub stats if available
        if self._gossip_coordinator:
            stats['gossipsub'] = self._gossip_coordinator.get_mesh_stats()
        
        return stats
    
    def get_current_mode(self) -> str:
        """Get the current pulse mode as a string"""
        return self.pulse_mode.value
    
    def get_supported_modes(self) -> List[str]:
        """Get list of supported pulse modes"""
        return ['continuous', 'pulse']
    
    def can_switch_mode_runtime(self) -> bool:
        """Check if runtime mode switching is supported"""
        return True
class PulseInterval(Enum):
    """Predefined pulse intervals"""
    FAST = 10      # 10ms - Ultra-fast bursts
    MEDIUM = 100   # 100ms - Medium bursts  
    SLOW = 1000    # 1s - Slow bursts
    CUSTOM = -1    # Custom interval


@dataclass
class PulseConfig:
    """Pulse configuration settings"""
    interval_ms: int = 1000
    duration_ms: int = 100
    intensity: float = 1.0
    jitter_ms: int = 0  # Random jitter to add
    burst_count: int = 1  # Number of bursts per pulse
    burst_spacing_ms: int = 10  # Spacing between bursts
    
    def validate(self):
        """Validate pulse configuration"""
        if self.interval_ms < 10:
            raise ValueError("Pulse interval must be at least 10ms")
        if self.duration_ms < 1:
            raise ValueError("Pulse duration must be at least 1ms")
        if self.duration_ms > self.interval_ms:
            raise ValueError("Pulse duration cannot exceed interval")
        if not 0.0 <= self.intensity <= 1.0:
            raise ValueError("Pulse intensity must be between 0.0 and 1.0")
        if self.jitter_ms < 0:
            raise ValueError("Jitter cannot be negative")
        if self.burst_count < 1:
            raise ValueError("Burst count must be at least 1")


class PulseScheduler:
    """
    Advanced pulse scheduling with configurable intervals and patterns.
    """
    
    def __init__(self, sync_engine: 'PulseSyncEngine'):
        self.sync_engine = sync_engine
        self.config = PulseConfig()
        self.scheduled_pulses: List[PulseCommand] = []
        self.pulse_history: List[Tuple[float, PulseCommand]] = []
        self.scheduler_task: Optional[asyncio.Task] = None
        self.running = False
        
    def set_interval(self, interval: PulseInterval, custom_ms: Optional[int] = None):
        """
        Set pulse interval using predefined or custom values.
        
        Args:
            interval: Predefined interval or CUSTOM
            custom_ms: Custom interval in milliseconds (required if interval is CUSTOM)
        """
        if interval == PulseInterval.CUSTOM:
            if custom_ms is None:
                raise ValueError("Custom interval value required")
            if custom_ms < 10:
                raise ValueError("Custom interval must be at least 10ms")
            self.config.interval_ms = custom_ms
        else:
            self.config.interval_ms = interval.value
        
        logger.info(f"Pulse interval set to {self.config.interval_ms}ms")
    
    def configure_pulse(self, 
                       duration_ms: Optional[int] = None,
                       intensity: Optional[float] = None,
                       jitter_ms: Optional[int] = None,
                       burst_count: Optional[int] = None,
                       burst_spacing_ms: Optional[int] = None):
        """
        Configure pulse parameters.
        
        Args:
            duration_ms: Pulse duration in milliseconds
            intensity: Pulse intensity (0.0 - 1.0)
            jitter_ms: Random jitter to add to timing
            burst_count: Number of bursts per pulse
            burst_spacing_ms: Spacing between bursts in milliseconds
        """
        if duration_ms is not None:
            self.config.duration_ms = duration_ms
        if intensity is not None:
            self.config.intensity = intensity
        if jitter_ms is not None:
            self.config.jitter_ms = jitter_ms
        if burst_count is not None:
            self.config.burst_count = burst_count
        if burst_spacing_ms is not None:
            self.config.burst_spacing_ms = burst_spacing_ms
        
        # Validate configuration
        self.config.validate()
        
        logger.info(f"Pulse config updated: duration={self.config.duration_ms}ms, "
                   f"intensity={self.config.intensity}, jitter={self.config.jitter_ms}ms")
    
    def get_supported_intervals(self) -> List[int]:
        """Get list of supported pulse intervals in milliseconds"""
        return [
            PulseInterval.FAST.value,      # 10ms
            PulseInterval.MEDIUM.value,    # 100ms
            PulseInterval.SLOW.value,      # 1000ms
        ]
    
    def calculate_next_pulse_time(self, base_time: Optional[float] = None) -> float:
        """
        Calculate the next pulse time with optional jitter.
        
        Args:
            base_time: Base time to calculate from (default: current sync time)
            
        Returns:
            Next pulse time in synchronized time
        """
        if base_time is None:
            base_time = self.sync_engine.get_synchronized_time()
        
        # Calculate next interval boundary
        interval_sec = self.config.interval_ms / 1000.0
        next_boundary = (int(base_time / interval_sec) + 1) * interval_sec
        
        # Add jitter if configured
        if self.config.jitter_ms > 0:
            import random
            jitter_sec = random.uniform(0, self.config.jitter_ms / 1000.0)
            next_boundary += jitter_sec
        
        return next_boundary
    
    def create_pulse_command(self, scheduled_time: float, 
                           attack_params: Optional[Dict[str, Any]] = None) -> PulseCommand:
        """
        Create a pulse command with current configuration.
        
        Args:
            scheduled_time: When to execute the pulse (synchronized time)
            attack_params: Additional attack parameters
            
        Returns:
            Configured PulseCommand
        """
        pulse_id = hashlib.sha256(
            f"{self.sync_engine.node_id}:{scheduled_time}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        command = PulseCommand(
            pulse_id=pulse_id,
            scheduled_time=scheduled_time,
            duration_ms=self.config.duration_ms,
            intensity=self.config.intensity,
            attack_params=attack_params or {}
        )
        
        # Add burst configuration to attack params
        command.attack_params.update({
            'burst_count': self.config.burst_count,
            'burst_spacing_ms': self.config.burst_spacing_ms,
            'jitter_ms': self.config.jitter_ms
        })
        
        # Sign the command
        command.sign(self.sync_engine.private_key)
        
        return command
    
    async def start_scheduler(self):
        """Start the pulse scheduler"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Pulse scheduler started")
    
    async def stop_scheduler(self):
        """Stop the pulse scheduler"""
        self.running = False
        
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Pulse scheduler stopped")
    
    async def _scheduler_loop(self):
        """
        Main scheduler loop for automatic pulse generation.
        Handles both continuous and pulse modes with runtime switching.
        """
        while self.running:
            try:
                current_mode = self.sync_engine.pulse_mode
                
                if current_mode == PulseMode.PULSE:
                    # In pulse mode, generate scheduled pulse commands
                    next_pulse = self.calculate_next_pulse_time()
                    
                    # Create and schedule pulse command
                    command = self.create_pulse_command(next_pulse)
                    self.scheduled_pulses.append(command)
                    
                    logger.debug(f"Scheduled pulse {command.pulse_id} for {next_pulse}")
                    
                    # Notify callbacks about the scheduled pulse
                    for callback in self.sync_engine.pulse_callbacks:
                        try:
                            callback(command)
                        except Exception as e:
                            logger.error(f"Pulse callback error: {e}")
                    
                    # Wait until next interval
                    sleep_time = self.config.interval_ms / 1000.0
                    await asyncio.sleep(sleep_time)
                    
                elif current_mode == PulseMode.CONTINUOUS:
                    # In continuous mode, the burst executor handles traffic generation
                    # The scheduler just waits and monitors for mode changes
                    logger.debug("Scheduler in continuous mode - waiting for mode change")
                    await asyncio.sleep(1.0)  # Check every second for mode changes
                else:
                    # Unknown mode, wait briefly
                    await asyncio.sleep(1.0)
                    
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(1.0)
    
    def get_pulse_stats(self) -> Dict[str, Any]:
        """Get pulse scheduling statistics"""
        return {
            'config': {
                'interval_ms': self.config.interval_ms,
                'duration_ms': self.config.duration_ms,
                'intensity': self.config.intensity,
                'jitter_ms': self.config.jitter_ms,
                'burst_count': self.config.burst_count,
                'burst_spacing_ms': self.config.burst_spacing_ms
            },
            'scheduled_count': len(self.scheduled_pulses),
            'history_count': len(self.pulse_history),
            'mode': self.sync_engine.pulse_mode.value,
            'running': self.running,
            'supports_runtime_switching': True,  # Indicate runtime mode switching capability
            'supported_modes': ['continuous', 'pulse']
        }
    
    def apply_attack_config(self, attack_config: 'AttackConfig'):
        """
        Apply pulse configuration from AttackConfig.
        
        Args:
            attack_config: AttackConfig with pulse settings
        """
        from core.distributed.protocol import AttackConfig
        
        # Validate pulse configuration
        attack_config.validate_pulse_config()
        
        # Set pulse mode
        if attack_config.pulse_mode == "pulse":
            self.sync_engine.set_pulse_mode(PulseMode.PULSE)
        else:
            self.sync_engine.set_pulse_mode(PulseMode.CONTINUOUS)
        
        # Set interval first (check if it's a standard interval or custom)
        if attack_config.pulse_interval_ms in [10, 100, 1000]:
            # Use predefined interval
            interval_map = {
                10: PulseInterval.FAST,
                100: PulseInterval.MEDIUM,
                1000: PulseInterval.SLOW
            }
            self.set_interval(interval_map[attack_config.pulse_interval_ms])
        else:
            # Use custom interval
            self.set_interval(PulseInterval.CUSTOM, custom_ms=attack_config.pulse_interval_ms)
        
        # Configure pulse parameters after setting interval
        self.configure_pulse(
            duration_ms=attack_config.pulse_duration_ms,
            intensity=attack_config.pulse_intensity,
            jitter_ms=attack_config.pulse_jitter_ms
        )
        
        logger.info(f"Applied attack config: mode={attack_config.pulse_mode}, "
                   f"interval={attack_config.pulse_interval_ms}ms, "
                   f"duration={attack_config.pulse_duration_ms}ms, "
                   f"intensity={attack_config.pulse_intensity}")