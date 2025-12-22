"""
Advanced Packet Crafting Module

Provides low-level packet manipulation:
- IP header crafting
- TCP/UDP header crafting
- ICMP packet crafting
- Checksum calculation
- Fragmentation
"""

import socket
import struct
import random
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class IPProtocol(Enum):
    """IP protocol numbers"""
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50
    AH = 51


class TCPFlags(Enum):
    """TCP flags"""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


@dataclass
class IPHeader:
    """IPv4 header"""
    version: int = 4
    ihl: int = 5  # Header length in 32-bit words
    tos: int = 0
    total_length: int = 0
    identification: int = field(default_factory=lambda: random.randint(0, 65535))
    flags: int = 0
    fragment_offset: int = 0
    ttl: int = 64
    protocol: int = IPProtocol.TCP.value
    checksum: int = 0
    src_addr: str = "0.0.0.0"
    dst_addr: str = "0.0.0.0"
    
    def pack(self) -> bytes:
        """Pack IP header into bytes"""
        version_ihl = (self.version << 4) + self.ihl
        flags_fragment = (self.flags << 13) + self.fragment_offset
        
        header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            flags_fragment,
            self.ttl,
            self.protocol,
            0,  # Checksum placeholder
            socket.inet_aton(self.src_addr),
            socket.inet_aton(self.dst_addr)
        )
        
        # Calculate checksum
        checksum = self._calculate_checksum(header)
        
        # Repack with checksum
        header = struct.pack(
            '!BBHHHBBH4s4s',
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            flags_fragment,
            self.ttl,
            self.protocol,
            checksum,
            socket.inet_aton(self.src_addr),
            socket.inet_aton(self.dst_addr)
        )
        
        return header
        
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate IP checksum"""
        if len(data) % 2:
            data += b'\x00'
            
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
            
        return ~total & 0xffff


@dataclass
class TCPHeader:
    """TCP header"""
    src_port: int = 0
    dst_port: int = 0
    seq_num: int = field(default_factory=lambda: random.randint(0, 2**32 - 1))
    ack_num: int = 0
    data_offset: int = 5  # Header length in 32-bit words
    reserved: int = 0
    flags: int = TCPFlags.SYN.value
    window: int = 65535
    checksum: int = 0
    urgent_ptr: int = 0
    options: bytes = b''
    
    def pack(self, src_addr: str, dst_addr: str, payload: bytes = b'') -> bytes:
        """Pack TCP header with pseudo-header checksum"""
        offset_reserved = (self.data_offset << 4) + self.reserved
        
        header = struct.pack(
            '!HHLLBBHHH',
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_reserved,
            self.flags,
            self.window,
            0,  # Checksum placeholder
            self.urgent_ptr
        )
        
        # Add options if any
        if self.options:
            header += self.options
            # Pad to 32-bit boundary
            padding = (4 - len(self.options) % 4) % 4
            header += b'\x00' * padding
            
        # Calculate checksum with pseudo-header
        checksum = self._calculate_tcp_checksum(src_addr, dst_addr, header + payload)
        
        # Repack with checksum
        header = struct.pack(
            '!HHLLBBHHH',
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_reserved,
            self.flags,
            self.window,
            checksum,
            self.urgent_ptr
        )
        
        if self.options:
            header += self.options
            header += b'\x00' * padding
            
        return header
        
    def _calculate_tcp_checksum(self, src_addr: str, dst_addr: str, tcp_segment: bytes) -> int:
        """Calculate TCP checksum with pseudo-header"""
        # Pseudo-header
        pseudo = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(src_addr),
            socket.inet_aton(dst_addr),
            0,
            IPProtocol.TCP.value,
            len(tcp_segment)
        )
        
        data = pseudo + tcp_segment
        
        if len(data) % 2:
            data += b'\x00'
            
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
            
        return ~total & 0xffff


@dataclass
class UDPHeader:
    """UDP header"""
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    checksum: int = 0
    
    def pack(self, src_addr: str, dst_addr: str, payload: bytes = b'') -> bytes:
        """Pack UDP header"""
        self.length = 8 + len(payload)
        
        header = struct.pack(
            '!HHHH',
            self.src_port,
            self.dst_port,
            self.length,
            0  # Checksum (optional for IPv4)
        )
        
        # Calculate checksum
        checksum = self._calculate_udp_checksum(src_addr, dst_addr, header + payload)
        
        header = struct.pack(
            '!HHHH',
            self.src_port,
            self.dst_port,
            self.length,
            checksum
        )
        
        return header
        
    def _calculate_udp_checksum(self, src_addr: str, dst_addr: str, udp_segment: bytes) -> int:
        """Calculate UDP checksum"""
        pseudo = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(src_addr),
            socket.inet_aton(dst_addr),
            0,
            IPProtocol.UDP.value,
            len(udp_segment)
        )
        
        data = pseudo + udp_segment
        
        if len(data) % 2:
            data += b'\x00'
            
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
            
        result = ~total & 0xffff
        return result if result else 0xffff


@dataclass
class ICMPHeader:
    """ICMP header"""
    type: int = 8  # Echo request
    code: int = 0
    checksum: int = 0
    identifier: int = field(default_factory=lambda: random.randint(0, 65535))
    sequence: int = 0
    
    def pack(self, payload: bytes = b'') -> bytes:
        """Pack ICMP header"""
        header = struct.pack(
            '!BBHHH',
            self.type,
            self.code,
            0,  # Checksum placeholder
            self.identifier,
            self.sequence
        )
        
        # Calculate checksum
        data = header + payload
        checksum = self._calculate_checksum(data)
        
        header = struct.pack(
            '!BBHHH',
            self.type,
            self.code,
            checksum,
            self.identifier,
            self.sequence
        )
        
        return header
        
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
            
        total = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            total += word
            
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
            
        return ~total & 0xffff


class PacketCrafter:
    """
    Advanced Packet Crafter
    
    Creates custom packets for various attack types.
    """
    
    def __init__(self):
        self._raw_socket = None
        self._raw_available = self._check_raw_sockets()
        
    def _check_raw_sockets(self) -> bool:
        """Check if raw sockets are available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.close()
            return True
        except (PermissionError, OSError):
            return False
            
    @property
    def raw_available(self) -> bool:
        return self._raw_available
        
    def craft_tcp_syn(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """Craft TCP SYN packet"""
        ip = IPHeader(
            protocol=IPProtocol.TCP.value,
            src_addr=src_ip,
            dst_addr=dst_ip
        )
        
        tcp = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            flags=TCPFlags.SYN.value
        )
        
        tcp_segment = tcp.pack(src_ip, dst_ip)
        ip.total_length = 20 + len(tcp_segment)
        
        return ip.pack() + tcp_segment
        
    def craft_tcp_ack(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int = None, ack: int = None) -> bytes:
        """Craft TCP ACK packet"""
        ip = IPHeader(
            protocol=IPProtocol.TCP.value,
            src_addr=src_ip,
            dst_addr=dst_ip
        )
        
        tcp = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq or random.randint(0, 2**32 - 1),
            ack_num=ack or random.randint(0, 2**32 - 1),
            flags=TCPFlags.ACK.value
        )
        
        tcp_segment = tcp.pack(src_ip, dst_ip)
        ip.total_length = 20 + len(tcp_segment)
        
        return ip.pack() + tcp_segment
        
    def craft_tcp_rst(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int = None) -> bytes:
        """Craft TCP RST packet"""
        ip = IPHeader(
            protocol=IPProtocol.TCP.value,
            src_addr=src_ip,
            dst_addr=dst_ip
        )
        
        tcp = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq or random.randint(0, 2**32 - 1),
            flags=TCPFlags.RST.value
        )
        
        tcp_segment = tcp.pack(src_ip, dst_ip)
        ip.total_length = 20 + len(tcp_segment)
        
        return ip.pack() + tcp_segment
        
    def craft_udp(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                  payload: bytes = b'') -> bytes:
        """Craft UDP packet"""
        ip = IPHeader(
            protocol=IPProtocol.UDP.value,
            src_addr=src_ip,
            dst_addr=dst_ip
        )
        
        udp = UDPHeader(
            src_port=src_port,
            dst_port=dst_port
        )
        
        udp_segment = udp.pack(src_ip, dst_ip, payload) + payload
        ip.total_length = 20 + len(udp_segment)
        
        return ip.pack() + udp_segment
        
    def craft_icmp_echo(self, src_ip: str, dst_ip: str, payload: bytes = b'') -> bytes:
        """Craft ICMP echo request"""
        ip = IPHeader(
            protocol=IPProtocol.ICMP.value,
            src_addr=src_ip,
            dst_addr=dst_ip
        )
        
        icmp = ICMPHeader(type=8, code=0)
        icmp_packet = icmp.pack(payload) + payload
        
        ip.total_length = 20 + len(icmp_packet)
        
        return ip.pack() + icmp_packet
        
    def craft_fragmented(self, src_ip: str, dst_ip: str, payload: bytes,
                         fragment_size: int = 8) -> List[bytes]:
        """Craft fragmented IP packets"""
        fragments = []
        offset = 0
        
        while offset < len(payload):
            # Get fragment data
            frag_data = payload[offset:offset + fragment_size]
            more_fragments = offset + fragment_size < len(payload)
            
            ip = IPHeader(
                protocol=IPProtocol.UDP.value,
                src_addr=src_ip,
                dst_addr=dst_ip,
                flags=1 if more_fragments else 0,  # MF flag
                fragment_offset=offset // 8
            )
            
            ip.total_length = 20 + len(frag_data)
            fragments.append(ip.pack() + frag_data)
            
            offset += fragment_size
            
        return fragments
        
    def send_raw(self, packet: bytes, dst_ip: str) -> bool:
        """Send raw packet"""
        if not self._raw_available:
            logger.warning("Raw sockets not available")
            return False
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(packet, (dst_ip, 0))
            sock.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send raw packet: {e}")
            return False


class IPSpoofHelper:
    """Helper for IP spoofing operations"""
    
    @staticmethod
    def random_ip() -> str:
        """Generate random IP address"""
        return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
    @staticmethod
    def random_private_ip() -> str:
        """Generate random private IP"""
        ranges = [
            (10, 0, 0, 0, 10, 255, 255, 255),
            (172, 16, 0, 0, 172, 31, 255, 255),
            (192, 168, 0, 0, 192, 168, 255, 255),
        ]
        
        r = random.choice(ranges)
        return f"{random.randint(r[0], r[4])}.{random.randint(r[1], r[5])}.{random.randint(r[2], r[6])}.{random.randint(max(1, r[3]), min(254, r[7]))}"
        
    @staticmethod
    def random_ip_in_range(network: str) -> str:
        """Generate random IP in network range"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            if hosts:
                return str(random.choice(hosts))
        except ValueError:
            pass
        return IPSpoofHelper.random_ip()
        
    @staticmethod
    def generate_spoofed_ips(count: int, exclude: List[str] = None) -> List[str]:
        """Generate list of spoofed IPs"""
        exclude = set(exclude or [])
        ips = set()
        
        while len(ips) < count:
            ip = IPSpoofHelper.random_ip()
            if ip not in exclude:
                ips.add(ip)
                
        return list(ips)


class PortHelper:
    """Helper for port operations"""
    
    WELL_KNOWN_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
        993: 'imaps', 995: 'pop3s', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 6379: 'redis', 8080: 'http-alt',
    }
    
    @staticmethod
    def random_port() -> int:
        """Generate random port"""
        return random.randint(1024, 65535)
        
    @staticmethod
    def random_ephemeral_port() -> int:
        """Generate random ephemeral port"""
        return random.randint(49152, 65535)
        
    @staticmethod
    def random_well_known_port() -> int:
        """Generate random well-known port"""
        return random.choice(list(PortHelper.WELL_KNOWN_PORTS.keys()))
        
    @staticmethod
    def generate_port_range(start: int, end: int) -> List[int]:
        """Generate port range"""
        return list(range(start, end + 1))
