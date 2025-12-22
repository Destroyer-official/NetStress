"""
Distributed Controller

Central controller for coordinating distributed stress tests.
Manages multiple agents and synchronizes attacks.

Enhanced with:
- NTP-based time synchronization (Requirement 7.2)
- Real-time statistics aggregation (Requirement 7.3)
- Load redistribution on agent failure (Requirement 7.4)
"""

import asyncio
import socket
import ssl
import time
import uuid
import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from collections import defaultdict
import logging

from .protocol import (
    ControlMessage, MessageType, AgentStatus, AgentInfo,
    AttackConfig, MessageBuilder
)
from .time_sync import ControllerTimeSync, TimeSyncResult
from .certificates import CertificateManager, create_ssl_context_server

logger = logging.getLogger(__name__)


@dataclass
class ControllerConfig:
    """Configuration for the distributed controller"""
    bind_address: str = "0.0.0.0"
    bind_port: int = 9999
    secret_key: bytes = b""  # Shared secret for authentication
    heartbeat_interval: float = 5.0
    heartbeat_timeout: float = 15.0
    max_agents: int = 100
    use_ssl: bool = False
    ssl_cert: str = ""
    ssl_key: str = ""
    # TLS mutual authentication settings (Requirement 7.5)
    use_mutual_tls: bool = True
    cert_dir: str = ".netstress/certs"
    auto_generate_certs: bool = True
    ca_cert_path: str = ""
    # Time synchronization settings
    enable_ntp_sync: bool = True
    ntp_sync_interval: float = 300.0  # Re-sync every 5 minutes
    sync_tolerance_ms: float = 100.0  # Target sync accuracy
    # Real-time stats settings
    stats_update_interval: float = 0.1  # 100ms stats updates
    stats_history_size: int = 1000  # Keep last 1000 samples
    # Load redistribution settings
    enable_load_redistribution: bool = True
    redistribution_threshold: float = 0.8  # Redistribute if agent at 80% capacity


class DistributedController:
    """
    Central controller for distributed stress testing.
    
    Features:
    - Agent registration and management
    - Synchronized attack coordination
    - Real-time statistics aggregation
    - Fault tolerance with agent failover
    """
    
    def __init__(self, config: Optional[ControllerConfig] = None):
        self.config = config or ControllerConfig()
        self.controller_id = f"controller-{uuid.uuid4().hex[:8]}"
        self.msg_builder = MessageBuilder(self.controller_id)
        
        # Certificate management (Requirement 7.5)
        self.cert_manager: Optional[CertificateManager] = None
        if self.config.use_mutual_tls:
            try:
                self.cert_manager = CertificateManager(self.config.cert_dir)
                logger.info("TLS mutual authentication enabled")
            except Exception as e:
                logger.error(f"Failed to initialize certificate manager: {e}")
                if self.config.auto_generate_certs:
                    logger.error("Auto-generate certificates disabled due to error")
                    self.config.use_mutual_tls = False
        
        # Agent management
        self.agents: Dict[str, AgentInfo] = {}
        self.agent_connections: Dict[str, asyncio.StreamWriter] = {}
        self._agent_readers: Dict[str, asyncio.StreamReader] = {}
        
        # Attack state
        self.current_attack: Optional[AttackConfig] = None
        self.attack_active = False
        self.attack_start_time = 0.0
        
        # Statistics
        self.aggregated_stats: Dict[str, Any] = defaultdict(int)
        self._stats_callbacks: List[Callable] = []
        
        # Server state
        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        
        # Time synchronization (Requirement 7.2)
        self._time_sync = ControllerTimeSync(sync_interval=self.config.ntp_sync_interval)
        self._agent_heartbeat_times: Dict[str, float] = {}  # Track RTT for time sync
        
        # Real-time stats aggregation (Requirement 7.3)
        self._stats_stream_task: Optional[asyncio.Task] = None
        self._stats_history: List[Dict[str, Any]] = []
        self._stats_lock = asyncio.Lock()
        
        # Load redistribution (Requirement 7.4)
        self._agent_loads: Dict[str, float] = {}  # agent_id -> load percentage
        self._redistribution_task: Optional[asyncio.Task] = None
        self._failed_agents: List[str] = []  # Recently failed agents
        
    async def start(self):
        """Start the controller server"""
        logger.info(f"Starting controller on {self.config.bind_address}:{self.config.bind_port}")
        
        # Start time synchronization (Requirement 7.2)
        if self.config.enable_ntp_sync:
            await self._time_sync.start()
            logger.info("NTP time synchronization enabled")
        
        # Create SSL context (Requirement 7.5)
        ssl_context = None
        if self.config.use_mutual_tls and self.cert_manager:
            try:
                # Generate/ensure controller certificate
                bind_addresses = [self.config.bind_address]
                if self.config.bind_address == "0.0.0.0":
                    bind_addresses.extend(["localhost", "127.0.0.1"])
                
                controller_cert, controller_key = self.cert_manager.ensure_controller_certificate(
                    self.controller_id, bind_addresses
                )
                ca_cert = self.cert_manager.get_ca_certificate_path()
                
                # Create SSL context with mutual authentication
                ssl_context = create_ssl_context_server(controller_cert, controller_key, ca_cert)
                logger.info("TLS mutual authentication configured")
                
            except Exception as e:
                logger.error(f"Failed to configure TLS: {e}")
                if not self.config.use_ssl:
                    # Fall back to no SSL if mutual TLS fails and regular SSL not configured
                    logger.warning("Falling back to unencrypted communication")
                    ssl_context = None
        elif self.config.use_ssl and self.config.ssl_cert and self.config.ssl_key:
            # Legacy SSL configuration
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.config.ssl_cert, self.config.ssl_key)
            logger.info("Legacy SSL configured (no mutual authentication)")
        
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.config.bind_address,
            self.config.bind_port,
            ssl=ssl_context
        )
        
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
        
        # Start real-time stats streaming (Requirement 7.3)
        self._stats_stream_task = asyncio.create_task(self._stats_stream_loop())
        
        # Start load redistribution monitor (Requirement 7.4)
        if self.config.enable_load_redistribution:
            self._redistribution_task = asyncio.create_task(self._load_redistribution_monitor())
        
        logger.info(f"Controller started with ID: {self.controller_id}")
        
    async def stop(self):
        """Stop the controller server"""
        logger.info("Stopping controller...")
        self._running = False
        
        # Send shutdown to all agents
        await self.broadcast(self.msg_builder.stop_attack())
        
        # Cancel all background tasks
        tasks_to_cancel = [
            self._heartbeat_task,
            self._stats_stream_task,
            self._redistribution_task,
        ]
        for task in tasks_to_cancel:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Stop time sync
        await self._time_sync.stop()
        
        # Close all agent connections
        for writer in self.agent_connections.values():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        
        # Stop server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            
        logger.info("Controller stopped")
        
    async def _handle_connection(self, reader: asyncio.StreamReader, 
                                  writer: asyncio.StreamWriter):
        """Handle incoming agent connection"""
        peer = writer.get_extra_info('peername')
        logger.info(f"New connection from {peer}")
        
        agent_id = None
        
        try:
            while self._running:
                # Read message length
                length_data = await reader.read(4)
                if not length_data:
                    break
                    
                import struct
                length = struct.unpack('>I', length_data)[0]
                
                # Read message body
                data = await reader.read(length)
                if not data:
                    break
                
                # Parse message
                try:
                    msg = ControlMessage.from_bytes(
                        length_data + data,
                        self.config.secret_key if self.config.secret_key else None
                    )
                except Exception as e:
                    logger.error(f"Failed to parse message: {e}")
                    continue
                
                # Handle message
                response = await self._handle_message(msg, reader, writer)
                
                if response:
                    await self._send_message(writer, response)
                    
                # Track agent ID for cleanup
                if msg.msg_type == MessageType.REGISTER:
                    agent_id = msg.sender_id
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            # Cleanup
            if agent_id and agent_id in self.agents:
                self.agents[agent_id].status = AgentStatus.OFFLINE
                if agent_id in self.agent_connections:
                    del self.agent_connections[agent_id]
                if agent_id in self._agent_readers:
                    del self._agent_readers[agent_id]
                    
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
                
            logger.info(f"Connection closed: {peer}")
            
    async def _handle_message(self, msg: ControlMessage, 
                              reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> Optional[ControlMessage]:
        """Handle incoming control message"""
        
        if msg.msg_type == MessageType.REGISTER:
            return await self._handle_register(msg, reader, writer)
            
        elif msg.msg_type == MessageType.HEARTBEAT:
            return await self._handle_heartbeat(msg)
            
        elif msg.msg_type == MessageType.STATUS_REPORT:
            return await self._handle_status_report(msg)
            
        elif msg.msg_type == MessageType.STATS_REPORT:
            return await self._handle_stats_report(msg)
            
        elif msg.msg_type == MessageType.READY_ACK:
            return await self._handle_ready_ack(msg)
            
        elif msg.msg_type == MessageType.ERROR_REPORT:
            return await self._handle_error_report(msg)
            
        else:
            logger.warning(f"Unknown message type: {msg.msg_type}")
            return None
            
    async def _handle_register(self, msg: ControlMessage,
                               reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter) -> ControlMessage:
        """Handle agent registration with certificate generation (Requirement 7.5)"""
        agent_id = msg.sender_id
        payload = msg.payload
        
        peer = writer.get_extra_info('peername')
        
        # Create agent info
        agent = AgentInfo(
            agent_id=agent_id,
            hostname=payload.get('hostname', 'unknown'),
            ip_address=peer[0] if peer else 'unknown',
            port=peer[1] if peer else 0,
            status=AgentStatus.IDLE,
            capabilities=payload.get('capabilities', {}),
            registered_at=time.time(),
            last_heartbeat=time.time(),
        )
        
        # Check max agents
        if len(self.agents) >= self.config.max_agents:
            logger.warning(f"Max agents reached, rejecting {agent_id}")
            return ControlMessage(
                msg_type=MessageType.REGISTER_ACK,
                sender_id=self.controller_id,
                payload={'accepted': False, 'reason': 'max_agents_reached'}
            )
        
        # Generate agent certificate if using mutual TLS (Requirement 7.5)
        agent_cert_info = {}
        if self.config.use_mutual_tls and self.cert_manager:
            try:
                agent_cert_path, agent_key_path = self.cert_manager.generate_agent_certificate(
                    agent_id, agent.hostname
                )
                
                # Read certificate content to send to agent
                with open(agent_cert_path, 'r') as f:
                    agent_cert_pem = f.read()
                with open(agent_key_path, 'r') as f:
                    agent_key_pem = f.read()
                
                ca_cert_path = self.cert_manager.get_ca_certificate_path()
                with open(ca_cert_path, 'r') as f:
                    ca_cert_pem = f.read()
                
                agent_cert_info = {
                    'certificate': agent_cert_pem,
                    'private_key': agent_key_pem,
                    'ca_certificate': ca_cert_pem,
                }
                
                logger.info(f"Generated certificate for agent: {agent_id}")
                
            except Exception as e:
                logger.error(f"Failed to generate certificate for {agent_id}: {e}")
                return ControlMessage(
                    msg_type=MessageType.REGISTER_ACK,
                    sender_id=self.controller_id,
                    payload={'accepted': False, 'reason': 'certificate_generation_failed'}
                )
        
        # Register agent
        self.agents[agent_id] = agent
        self.agent_connections[agent_id] = writer
        self._agent_readers[agent_id] = reader
        
        logger.info(f"Agent registered: {agent_id} ({agent.hostname})")
        
        response_payload = {
            'accepted': True,
            'controller_id': self.controller_id,
            'heartbeat_interval': self.config.heartbeat_interval,
            'use_mutual_tls': self.config.use_mutual_tls,
        }
        
        # Include certificate information if using mutual TLS
        if agent_cert_info:
            response_payload['tls_config'] = agent_cert_info
        
        return ControlMessage(
            msg_type=MessageType.REGISTER_ACK,
            sender_id=self.controller_id,
            payload=response_payload
        )
        
    async def _handle_heartbeat(self, msg: ControlMessage) -> ControlMessage:
        """Handle agent heartbeat with NTP-based time sync (Requirement 7.2)"""
        agent_id = msg.sender_id
        now = time.time()
        
        if agent_id in self.agents:
            self.agents[agent_id].last_heartbeat = now
            self.agents[agent_id].status = AgentStatus(msg.payload.get('status', 'idle'))
            
            if 'stats' in msg.payload:
                self.agents[agent_id].current_stats = msg.payload['stats']
                # Update agent load for redistribution (Requirement 7.4)
                self._update_agent_load(agent_id, msg.payload['stats'])
            
            # Calculate time offset for this agent (Requirement 7.2)
            if 'agent_time' in msg.payload:
                agent_time = msg.payload['agent_time']
                # Calculate round-trip time
                if agent_id in self._agent_heartbeat_times:
                    rtt = now - self._agent_heartbeat_times[agent_id]
                    self._time_sync.calculate_agent_offset(agent_id, agent_time, rtt)
        
        # Record when we're sending the response for RTT calculation
        self._agent_heartbeat_times[agent_id] = now
        
        # Include synchronized time in response (Requirement 7.2)
        return ControlMessage(
            msg_type=MessageType.HEARTBEAT_ACK,
            sender_id=self.controller_id,
            payload={
                'server_time': now,
                'sync_time': self._time_sync.get_controller_time(),
                'ntp_synced': self._time_sync.ntp_client.last_result is not None,
            }
        )
        
    async def _handle_status_report(self, msg: ControlMessage) -> None:
        """Handle status report from agent"""
        agent_id = msg.sender_id
        
        if agent_id in self.agents:
            self.agents[agent_id].status = AgentStatus(msg.payload.get('status', 'idle'))
            self.agents[agent_id].current_stats = msg.payload.get('stats', {})
            
        # Aggregate stats
        self._aggregate_stats()
        
        return None
        
    async def _handle_stats_report(self, msg: ControlMessage) -> None:
        """Handle statistics report from agent"""
        agent_id = msg.sender_id
        
        if agent_id in self.agents:
            self.agents[agent_id].current_stats = msg.payload.get('stats', {})
            
        # Aggregate stats
        self._aggregate_stats()
        
        # Notify callbacks
        for callback in self._stats_callbacks:
            try:
                callback(self.aggregated_stats)
            except Exception as e:
                logger.error(f"Stats callback error: {e}")
                
        return None
        
    async def _handle_ready_ack(self, msg: ControlMessage) -> None:
        """Handle ready acknowledgment"""
        agent_id = msg.sender_id
        
        if agent_id in self.agents and msg.payload.get('ready'):
            self.agents[agent_id].status = AgentStatus.READY
            
        return None
        
    async def _handle_error_report(self, msg: ControlMessage) -> None:
        """Handle error report from agent"""
        agent_id = msg.sender_id
        error = msg.payload.get('error', 'Unknown error')
        
        logger.error(f"Agent {agent_id} error: {error}")
        
        if agent_id in self.agents:
            self.agents[agent_id].status = AgentStatus.ERROR
            
        return None
        
    async def _send_message(self, writer: asyncio.StreamWriter, msg: ControlMessage):
        """Send message to agent"""
        data = msg.to_bytes(self.config.secret_key if self.config.secret_key else None)
        writer.write(data)
        await writer.drain()
        
    async def broadcast(self, msg: ControlMessage):
        """Broadcast message to all connected agents"""
        for agent_id, writer in list(self.agent_connections.items()):
            try:
                await self._send_message(writer, msg)
            except Exception as e:
                logger.error(f"Failed to send to {agent_id}: {e}")
                
    async def send_to_agent(self, agent_id: str, msg: ControlMessage) -> bool:
        """Send message to specific agent"""
        if agent_id not in self.agent_connections:
            return False
            
        try:
            await self._send_message(self.agent_connections[agent_id], msg)
            return True
        except Exception as e:
            logger.error(f"Failed to send to {agent_id}: {e}")
            return False
            
    async def _heartbeat_monitor(self):
        """Monitor agent heartbeats and remove dead agents"""
        while self._running:
            await asyncio.sleep(self.config.heartbeat_interval)
            
            now = time.time()
            dead_agents = []
            
            for agent_id, agent in self.agents.items():
                if now - agent.last_heartbeat > self.config.heartbeat_timeout:
                    logger.warning(f"Agent {agent_id} heartbeat timeout")
                    dead_agents.append(agent_id)
                    
            for agent_id in dead_agents:
                self.agents[agent_id].status = AgentStatus.OFFLINE
                if agent_id in self.agent_connections:
                    try:
                        self.agent_connections[agent_id].close()
                    except Exception:
                        pass
                    del self.agent_connections[agent_id]
                    
    def _aggregate_stats(self):
        """Aggregate statistics from all agents"""
        self.aggregated_stats = defaultdict(int)
        
        for agent in self.agents.values():
            stats = agent.current_stats
            for key, value in stats.items():
                if isinstance(value, (int, float)):
                    self.aggregated_stats[key] += value
                    
        self.aggregated_stats['active_agents'] = sum(
            1 for a in self.agents.values() 
            if a.status in [AgentStatus.ATTACKING, AgentStatus.READY]
        )
        self.aggregated_stats['total_agents'] = len(self.agents)
        self.aggregated_stats['timestamp'] = time.time()
        self.aggregated_stats['sync_time'] = self._time_sync.get_controller_time()
    
    # Real-time stats streaming (Requirement 7.3)
    
    async def _stats_stream_loop(self):
        """Stream real-time statistics at configured interval"""
        while self._running:
            try:
                await asyncio.sleep(self.config.stats_update_interval)
                
                if not self.attack_active:
                    continue
                
                # Aggregate current stats
                self._aggregate_stats()
                
                # Store in history
                async with self._stats_lock:
                    self._stats_history.append(dict(self.aggregated_stats))
                    # Trim history to configured size
                    if len(self._stats_history) > self.config.stats_history_size:
                        self._stats_history = self._stats_history[-self.config.stats_history_size:]
                
                # Notify callbacks
                for callback in self._stats_callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(self.aggregated_stats)
                        else:
                            callback(self.aggregated_stats)
                    except Exception as e:
                        logger.error(f"Stats callback error: {e}")
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stats stream error: {e}")
    
    async def get_stats_stream(self) -> Dict[str, Any]:
        """Get current aggregated stats (for real-time streaming)"""
        self._aggregate_stats()
        return dict(self.aggregated_stats)
    
    async def get_stats_history(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent stats history for analysis"""
        async with self._stats_lock:
            return self._stats_history[-count:]
    
    # Load redistribution (Requirement 7.4)
    
    def _update_agent_load(self, agent_id: str, stats: Dict[str, Any]):
        """Update agent load tracking for redistribution"""
        # Calculate load based on PPS vs max capacity
        if agent_id in self.agents:
            capabilities = self.agents[agent_id].capabilities
            max_pps = capabilities.get('max_pps', 1000000)
            current_pps = stats.get('pps', 0)
            
            if max_pps > 0:
                self._agent_loads[agent_id] = current_pps / max_pps
            else:
                self._agent_loads[agent_id] = 0.0
    
    async def _load_redistribution_monitor(self):
        """Monitor for agent failures and redistribute load (Requirement 7.4)"""
        while self._running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                
                if not self.attack_active or not self.current_attack:
                    continue
                
                # Check for failed agents
                failed = self._detect_failed_agents()
                
                if failed:
                    logger.warning(f"Detected {len(failed)} failed agent(s): {failed}")
                    await self._redistribute_load(failed)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Load redistribution error: {e}")
    
    def _detect_failed_agents(self) -> List[str]:
        """Detect agents that have failed during an attack"""
        failed = []
        now = time.time()
        
        for agent_id, agent in self.agents.items():
            # Check if agent was attacking but is now offline/error
            if agent.status in [AgentStatus.OFFLINE, AgentStatus.ERROR]:
                if agent_id not in self._failed_agents:
                    failed.append(agent_id)
            # Check for heartbeat timeout during attack
            elif agent.status == AgentStatus.ATTACKING:
                if now - agent.last_heartbeat > self.config.heartbeat_timeout:
                    if agent_id not in self._failed_agents:
                        failed.append(agent_id)
        
        return failed
    
    async def _redistribute_load(self, failed_agents: List[str]):
        """Redistribute load from failed agents to remaining agents"""
        if not self.current_attack:
            return
        
        # Mark agents as failed
        self._failed_agents.extend(failed_agents)
        
        # Get active agents
        active_agents = [
            a for a in self.agents.values()
            if a.status == AgentStatus.ATTACKING and a.agent_id not in self._failed_agents
        ]
        
        if not active_agents:
            logger.error("No active agents remaining for redistribution")
            return
        
        # Calculate new rate per agent
        total_rate = self.current_attack.rate_limit
        if total_rate == 0:
            # Unlimited rate, no redistribution needed
            return
        
        # Calculate rate that was being handled by failed agents
        failed_rate = 0
        for agent_id in failed_agents:
            if agent_id in self._agent_loads:
                agent_rate = self._agent_loads[agent_id] * self.agents[agent_id].capabilities.get('max_pps', 0)
                failed_rate += agent_rate
        
        # Distribute failed rate among remaining agents
        rate_increase_per_agent = failed_rate / len(active_agents)
        
        logger.info(f"Redistributing {failed_rate:.0f} PPS from {len(failed_agents)} failed agent(s) "
                   f"to {len(active_agents)} active agent(s) (+{rate_increase_per_agent:.0f} PPS each)")
        
        # Send updated config to active agents
        for agent in active_agents:
            current_rate = self.current_attack.rate_limit // (len(active_agents) + len(failed_agents))
            new_rate = int(current_rate + rate_increase_per_agent)
            
            # Create updated config
            updated_config = AttackConfig(
                target=self.current_attack.target,
                port=self.current_attack.port,
                protocol=self.current_attack.protocol,
                duration=self.current_attack.duration,
                rate_limit=new_rate,
                use_evasion=self.current_attack.use_evasion,
                shaping_profile=self.current_attack.shaping_profile,
                obfuscation_method=self.current_attack.obfuscation_method,
                timing_pattern=self.current_attack.timing_pattern,
                sync_start=False,  # Don't re-sync, just update rate
            )
            
            # Send config update
            msg = ControlMessage(
                msg_type=MessageType.UPDATE_CONFIG,
                sender_id=self.controller_id,
                payload={'config': updated_config.to_dict()}
            )
            
            await self.send_to_agent(agent.agent_id, msg)
            logger.info(f"Updated agent {agent.agent_id} rate to {new_rate} PPS")
    
    def get_agent_time_offsets(self) -> Dict[str, float]:
        """Get time offsets for all agents (for debugging/monitoring)"""
        offsets = {}
        for agent_id in self.agents:
            offsets[agent_id] = self._time_sync.get_agent_offset(agent_id)
        return offsets
        
    # Public API
    
    async def start_attack(self, config: AttackConfig, sync: bool = True) -> bool:
        """
        Start distributed attack across all agents.
        
        Uses NTP-based time synchronization for coordinated start (Requirement 7.2).
        
        Args:
            config: Attack configuration
            sync: Wait for all agents to be ready before starting
            
        Returns:
            True if attack started successfully
        """
        if not self.agents:
            logger.error("No agents connected")
            return False
        
        # Reset failed agents list for new attack
        self._failed_agents = []
            
        self.current_attack = config
        
        # If sync start, wait for all agents ready
        if sync and config.sync_start:
            # Send ready check
            await self.broadcast(ControlMessage(
                msg_type=MessageType.READY_CHECK,
                sender_id=self.controller_id,
            ))
            
            # Wait for ready acknowledgments (with timeout)
            timeout = 10.0
            start = time.time()
            while time.time() - start < timeout:
                ready_count = sum(
                    1 for a in self.agents.values() 
                    if a.status == AgentStatus.READY
                )
                if ready_count == len(self.agents):
                    break
                await asyncio.sleep(0.1)
            else:
                logger.warning("Not all agents ready, proceeding anyway")
        
        # Set synchronized start time using NTP-based sync (Requirement 7.2)
        if config.start_time == 0 and sync:
            # Use synchronized time for coordinated start
            sync_start_time = self._time_sync.calculate_sync_start_time(delay=2.0)
            config.start_time = sync_start_time
            logger.info(f"Synchronized start time: {sync_start_time:.6f} "
                       f"(in {sync_start_time - self._time_sync.get_controller_time():.2f}s)")
        
        # Send start command with per-agent adjusted times (Requirement 7.2)
        for agent_id, agent in self.agents.items():
            if agent.status in [AgentStatus.READY, AgentStatus.IDLE]:
                # Adjust start time for agent's clock offset
                agent_start_time = self._time_sync.get_agent_start_time(
                    agent_id, config.start_time
                )
                
                # Create agent-specific config with adjusted time
                agent_config = AttackConfig(
                    target=config.target,
                    port=config.port,
                    protocol=config.protocol,
                    duration=config.duration,
                    threads=config.threads,
                    packet_size=config.packet_size,
                    rate_limit=config.rate_limit,
                    use_evasion=config.use_evasion,
                    shaping_profile=config.shaping_profile,
                    obfuscation_method=config.obfuscation_method,
                    timing_pattern=config.timing_pattern,
                    start_time=agent_start_time,
                    sync_start=config.sync_start,
                )
                
                msg = self.msg_builder.start_attack(agent_config)
                await self.send_to_agent(agent_id, msg)
                
                offset = self._time_sync.get_agent_offset(agent_id)
                logger.debug(f"Agent {agent_id}: start_time={agent_start_time:.6f}, offset={offset:.6f}s")
        
        self.attack_active = True
        self.attack_start_time = config.start_time or self._time_sync.get_controller_time()
        
        logger.info(f"Attack started: {config.target}:{config.port} ({config.protocol})")
        logger.info(f"Synchronized {len(self.agents)} agents within {self.config.sync_tolerance_ms}ms target")
        return True
        
    async def stop_attack(self):
        """Stop the distributed attack"""
        msg = self.msg_builder.stop_attack()
        await self.broadcast(msg)
        
        self.attack_active = False
        self.current_attack = None
        
        logger.info("Attack stopped")
        
    def get_agents(self) -> List[AgentInfo]:
        """Get list of all agents"""
        return list(self.agents.values())
        
    def get_active_agents(self) -> List[AgentInfo]:
        """Get list of active agents"""
        return [a for a in self.agents.values() 
                if a.status in [AgentStatus.ATTACKING, AgentStatus.READY, AgentStatus.IDLE]]
        
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregated statistics"""
        self._aggregate_stats()
        return dict(self.aggregated_stats)
        
    def on_stats_update(self, callback: Callable):
        """Register callback for stats updates"""
        self._stats_callbacks.append(callback)
    
    # Certificate management methods (Requirement 7.5)
    
    def list_agent_certificates(self) -> List[Dict[str, Any]]:
        """List all agent certificates"""
        if not self.cert_manager:
            return []
        
        return self.cert_manager.list_agent_certificates()
    
    def revoke_agent_certificate(self, agent_id: str) -> bool:
        """Revoke agent certificate"""
        if not self.cert_manager:
            return False
        
        success = self.cert_manager.revoke_agent_certificate(agent_id)
        
        # Disconnect agent if currently connected
        if success and agent_id in self.agent_connections:
            try:
                self.agent_connections[agent_id].close()
                del self.agent_connections[agent_id]
                if agent_id in self.agents:
                    self.agents[agent_id].status = AgentStatus.OFFLINE
                logger.info(f"Disconnected agent with revoked certificate: {agent_id}")
            except Exception as e:
                logger.error(f"Error disconnecting agent {agent_id}: {e}")
        
        return success
    
    def cleanup_expired_certificates(self) -> int:
        """Clean up expired agent certificates"""
        if not self.cert_manager:
            return 0
        
        return self.cert_manager.cleanup_expired_certificates()
    
    def get_tls_status(self) -> Dict[str, Any]:
        """Get TLS configuration status"""
        return {
            'mutual_tls_enabled': self.config.use_mutual_tls,
            'cert_manager_available': self.cert_manager is not None,
            'ca_certificate_path': self.cert_manager.get_ca_certificate_path() if self.cert_manager else None,
            'controller_certificate_valid': self._verify_controller_certificate(),
            'agent_certificates': len(self.list_agent_certificates()),
        }
    
    def _verify_controller_certificate(self) -> bool:
        """Verify controller certificate is valid"""
        if not self.cert_manager:
            return False
        
        try:
            return self.cert_manager._verify_certificate(self.cert_manager.controller_cert_path)
        except Exception:
            return False
