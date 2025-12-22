"""
NTP-Based Time Synchronization

Provides precise time synchronization between controller and agents
for coordinated distributed attacks with sub-100ms accuracy.
"""

import asyncio
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)

# NTP constants
NTP_DELTA = 2208988800  # Seconds between 1900 and 1970
NTP_PORT = 123
NTP_VERSION = 3
NTP_MODE_CLIENT = 3
NTP_MODE_SERVER = 4


@dataclass
class TimeSyncResult:
    """Result of a time synchronization operation"""
    offset: float = 0.0  # Clock offset in seconds (positive = local ahead)
    delay: float = 0.0   # Round-trip delay in seconds
    stratum: int = 16    # NTP stratum (1 = primary, 16 = unsynchronized)
    precision: float = 0.0  # Estimated precision in seconds
    synced: bool = False
    sync_time: float = 0.0  # When sync was performed
    
    @property
    def adjusted_time(self) -> float:
        """Get current time adjusted for offset"""
        return time.time() - self.offset


@dataclass
class NTPPacket:
    """NTP packet structure"""
    leap: int = 0
    version: int = NTP_VERSION
    mode: int = NTP_MODE_CLIENT
    stratum: int = 0
    poll: int = 0
    precision: int = 0
    root_delay: float = 0.0
    root_dispersion: float = 0.0
    ref_id: bytes = b'\x00\x00\x00\x00'
    ref_timestamp: float = 0.0
    orig_timestamp: float = 0.0
    recv_timestamp: float = 0.0
    tx_timestamp: float = 0.0
    
    def to_bytes(self) -> bytes:
        """Serialize NTP packet to bytes"""
        # First byte: LI (2 bits) | VN (3 bits) | Mode (3 bits)
        first_byte = (self.leap << 6) | (self.version << 3) | self.mode
        
        # Convert timestamps to NTP format (64-bit: 32 seconds + 32 fraction)
        def to_ntp_time(t: float) -> Tuple[int, int]:
            if t == 0:
                return 0, 0
            ntp_time = t + NTP_DELTA
            seconds = int(ntp_time)
            fraction = int((ntp_time - seconds) * (2**32))
            return seconds, fraction
        
        ref_s, ref_f = to_ntp_time(self.ref_timestamp)
        orig_s, orig_f = to_ntp_time(self.orig_timestamp)
        recv_s, recv_f = to_ntp_time(self.recv_timestamp)
        tx_s, tx_f = to_ntp_time(self.tx_timestamp)
        
        return struct.pack(
            '!BBBbII4sIIIIIIII',
            first_byte,
            self.stratum,
            self.poll,
            self.precision,
            int(self.root_delay * 65536),
            int(self.root_dispersion * 65536),
            self.ref_id,
            ref_s, ref_f,
            orig_s, orig_f,
            recv_s, recv_f,
            tx_s, tx_f
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'NTPPacket':
        """Deserialize NTP packet from bytes"""
        if len(data) < 48:
            raise ValueError(f"NTP packet too short: {len(data)} bytes")
        
        unpacked = struct.unpack('!BBBbII4sIIIIIIII', data[:48])
        
        first_byte = unpacked[0]
        leap = (first_byte >> 6) & 0x3
        version = (first_byte >> 3) & 0x7
        mode = first_byte & 0x7
        
        def from_ntp_time(seconds: int, fraction: int) -> float:
            if seconds == 0 and fraction == 0:
                return 0.0
            return seconds - NTP_DELTA + fraction / (2**32)
        
        return cls(
            leap=leap,
            version=version,
            mode=mode,
            stratum=unpacked[1],
            poll=unpacked[2],
            precision=unpacked[3],
            root_delay=unpacked[4] / 65536,
            root_dispersion=unpacked[5] / 65536,
            ref_id=unpacked[6],  # Already bytes from 4s format
            ref_timestamp=from_ntp_time(unpacked[7], unpacked[8]),
            orig_timestamp=from_ntp_time(unpacked[9], unpacked[10]),
            recv_timestamp=from_ntp_time(unpacked[11], unpacked[12]),
            tx_timestamp=from_ntp_time(unpacked[13], unpacked[14]),
        )


class NTPClient:
    """Simple NTP client for time synchronization"""
    
    def __init__(self, servers: Optional[List[str]] = None, timeout: float = 2.0):
        self.servers = servers or [
            'pool.ntp.org',
            'time.google.com',
            'time.cloudflare.com',
            'time.windows.com',
        ]
        self.timeout = timeout
        self._last_result: Optional[TimeSyncResult] = None
    
    async def sync(self) -> TimeSyncResult:
        """Synchronize time with NTP servers"""
        results = []
        
        for server in self.servers:
            try:
                result = await self._query_server(server)
                if result.synced:
                    results.append(result)
                    logger.debug(f"NTP sync with {server}: offset={result.offset:.6f}s")
            except Exception as e:
                logger.debug(f"NTP query to {server} failed: {e}")
        
        if not results:
            logger.warning("Failed to sync with any NTP server")
            return TimeSyncResult(synced=False)
        
        # Use median offset for robustness
        results.sort(key=lambda r: r.offset)
        median_result = results[len(results) // 2]
        
        self._last_result = median_result
        logger.info(f"NTP sync complete: offset={median_result.offset:.6f}s, "
                   f"delay={median_result.delay:.6f}s")
        
        return median_result
    
    async def _query_server(self, server: str) -> TimeSyncResult:
        """Query a single NTP server"""
        loop = asyncio.get_event_loop()
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(self.timeout)
        
        try:
            # Resolve server address
            addr = await loop.run_in_executor(None, socket.gethostbyname, server)
            
            # Build request packet
            t1 = time.time()  # Client transmit time
            request = NTPPacket(tx_timestamp=t1)
            
            # Send request
            await loop.sock_sendto(sock, request.to_bytes(), (addr, NTP_PORT))
            
            # Receive response
            data, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 48),
                timeout=self.timeout
            )
            t4 = time.time()  # Client receive time
            
            # Parse response
            response = NTPPacket.from_bytes(data)
            
            # Calculate offset and delay using NTP algorithm
            # t1 = client transmit time
            # t2 = server receive time (recv_timestamp)
            # t3 = server transmit time (tx_timestamp)
            # t4 = client receive time
            t2 = response.recv_timestamp
            t3 = response.tx_timestamp
            
            # Offset = ((t2 - t1) + (t3 - t4)) / 2
            offset = ((t2 - t1) + (t3 - t4)) / 2
            
            # Delay = (t4 - t1) - (t3 - t2)
            delay = (t4 - t1) - (t3 - t2)
            
            return TimeSyncResult(
                offset=offset,
                delay=delay,
                stratum=response.stratum,
                precision=2 ** response.precision,
                synced=True,
                sync_time=t4,
            )
            
        finally:
            sock.close()
    
    @property
    def last_result(self) -> Optional[TimeSyncResult]:
        """Get the last sync result"""
        return self._last_result
    
    def get_adjusted_time(self) -> float:
        """Get current time adjusted for NTP offset"""
        if self._last_result and self._last_result.synced:
            return time.time() - self._last_result.offset
        return time.time()


class ControllerTimeSync:
    """
    Time synchronization manager for the distributed controller.
    
    Provides:
    - NTP-based time synchronization
    - Controller-agent time offset calculation
    - Synchronized start time coordination
    """
    
    def __init__(self, sync_interval: float = 300.0):
        self.sync_interval = sync_interval  # Re-sync every 5 minutes
        self.ntp_client = NTPClient()
        self._agent_offsets: dict = {}  # agent_id -> offset from controller
        self._running = False
        self._sync_task: Optional[asyncio.Task] = None
        self._controller_offset: float = 0.0  # Controller's offset from NTP
    
    async def start(self):
        """Start the time sync manager"""
        self._running = True
        
        # Initial NTP sync
        result = await self.ntp_client.sync()
        if result.synced:
            self._controller_offset = result.offset
        
        # Start periodic sync task
        self._sync_task = asyncio.create_task(self._periodic_sync())
        
        logger.info("Time sync manager started")
    
    async def stop(self):
        """Stop the time sync manager"""
        self._running = False
        
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Time sync manager stopped")
    
    async def _periodic_sync(self):
        """Periodically sync with NTP servers"""
        while self._running:
            await asyncio.sleep(self.sync_interval)
            
            try:
                result = await self.ntp_client.sync()
                if result.synced:
                    self._controller_offset = result.offset
            except Exception as e:
                logger.error(f"Periodic NTP sync failed: {e}")
    
    def get_controller_time(self) -> float:
        """Get the controller's synchronized time"""
        return time.time() - self._controller_offset
    
    def calculate_agent_offset(self, agent_id: str, 
                               agent_time: float, 
                               round_trip: float) -> float:
        """
        Calculate and store the time offset for an agent.
        
        Args:
            agent_id: Agent identifier
            agent_time: Time reported by agent
            round_trip: Round-trip time of the message
            
        Returns:
            Calculated offset (positive = agent ahead of controller)
        """
        controller_time = self.get_controller_time()
        
        # Estimate one-way delay as half of round-trip
        one_way_delay = round_trip / 2
        
        # Agent's time when it sent the message
        agent_send_time = agent_time
        
        # Controller's time when agent sent (estimated)
        controller_at_send = controller_time - one_way_delay
        
        # Offset = agent_time - controller_time (at same instant)
        offset = agent_send_time - controller_at_send
        
        self._agent_offsets[agent_id] = offset
        
        logger.debug(f"Agent {agent_id} time offset: {offset:.6f}s")
        
        return offset
    
    def get_agent_offset(self, agent_id: str) -> float:
        """Get the stored offset for an agent"""
        return self._agent_offsets.get(agent_id, 0.0)
    
    def calculate_sync_start_time(self, delay: float = 2.0) -> float:
        """
        Calculate a synchronized start time for all agents.
        
        Args:
            delay: Seconds from now to start
            
        Returns:
            Synchronized start time in controller's time reference
        """
        return self.get_controller_time() + delay
    
    def get_agent_start_time(self, agent_id: str, sync_time: float) -> float:
        """
        Convert controller sync time to agent's local time.
        
        Args:
            agent_id: Agent identifier
            sync_time: Start time in controller's reference
            
        Returns:
            Start time in agent's local time reference
        """
        offset = self.get_agent_offset(agent_id)
        return sync_time + offset
    
    def remove_agent(self, agent_id: str):
        """Remove an agent's time offset data"""
        self._agent_offsets.pop(agent_id, None)


class AgentTimeSync:
    """
    Time synchronization for distributed agents.
    
    Maintains sync with both NTP and the controller.
    """
    
    def __init__(self):
        self.ntp_client = NTPClient()
        self._controller_offset: float = 0.0  # Offset from controller
        self._ntp_offset: float = 0.0  # Offset from NTP
        self._last_sync: float = 0.0
    
    async def sync_with_ntp(self) -> TimeSyncResult:
        """Sync with NTP servers"""
        result = await self.ntp_client.sync()
        if result.synced:
            self._ntp_offset = result.offset
        return result
    
    def update_controller_offset(self, controller_time: float, 
                                  local_time: float,
                                  round_trip: float):
        """
        Update offset from controller based on heartbeat response.
        
        Args:
            controller_time: Time reported by controller
            local_time: Local time when response received
            round_trip: Round-trip time of the heartbeat
        """
        # Estimate controller's time when it sent the response
        one_way_delay = round_trip / 2
        controller_at_send = controller_time
        local_at_send = local_time - one_way_delay
        
        # Offset = controller_time - local_time (at same instant)
        self._controller_offset = controller_at_send - local_at_send
        self._last_sync = local_time
        
        logger.debug(f"Controller offset updated: {self._controller_offset:.6f}s")
    
    def get_controller_time(self) -> float:
        """Get estimated current controller time"""
        return time.time() + self._controller_offset
    
    def local_to_controller(self, local_time: float) -> float:
        """Convert local time to controller's time reference"""
        return local_time + self._controller_offset
    
    def controller_to_local(self, controller_time: float) -> float:
        """Convert controller time to local time reference"""
        return controller_time - self._controller_offset
    
    @property
    def offset(self) -> float:
        """Get current offset from controller"""
        return self._controller_offset
    
    @property
    def last_sync_age(self) -> float:
        """Get seconds since last sync"""
        if self._last_sync == 0:
            return float('inf')
        return time.time() - self._last_sync
