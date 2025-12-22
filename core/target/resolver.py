"""
Advanced Target Resolution Engine

Implements URL to IP resolution with IPv4/IPv6 support, DNS resolution with caching
and optimization, and service discovery with port scanning capabilities.
"""

import asyncio
import socket
import time
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Union
from urllib.parse import urlparse
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)

@dataclass
class ServiceInfo:
    """Information about a discovered service"""
    port: int
    protocol: str  # TCP, UDP
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    state: str = "open"  # open, closed, filtered
    response_time: float = 0.0

@dataclass
class NetworkInfo:
    """Network topology and path information"""
    mtu: int = 1500
    hop_count: int = 0
    latency: float = 0.0
    jitter: float = 0.0
    packet_loss: float = 0.0
    bandwidth_estimate: float = 0.0
    path_mtu: int = 1500

@dataclass
class TargetInfo:
    """Comprehensive target information"""
    original_target: str
    ip_addresses: List[str] = field(default_factory=list)
    hostname: Optional[str] = None
    ports: List[ServiceInfo] = field(default_factory=list)
    network_info: NetworkInfo = field(default_factory=NetworkInfo)
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    resolution_time: float = 0.0
    last_updated: float = field(default_factory=time.time)

class DNSCache:
    """High-performance DNS cache with TTL support"""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self.cache: Dict[str, Tuple[List[str], float]] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._lock = asyncio.Lock()
    
    async def get(self, hostname: str) -> Optional[List[str]]:
        """Get cached DNS resolution"""
        async with self._lock:
            if hostname in self.cache:
                addresses, expiry = self.cache[hostname]
                if time.time() < expiry:
                    return addresses
                else:
                    del self.cache[hostname]
            return None
    
    async def set(self, hostname: str, addresses: List[str], ttl: Optional[int] = None):
        """Cache DNS resolution with TTL"""
        async with self._lock:
            if len(self.cache) >= self.max_size:
                # Remove oldest entry
                oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
                del self.cache[oldest_key]
            
            expiry = time.time() + (ttl or self.default_ttl)
            self.cache[hostname] = (addresses, expiry)

class PortScanner:
    """High-performance asynchronous port scanner"""
    
    def __init__(self, timeout: float = 1.0, max_concurrent: int = 1000):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_port(self, target: str, port: int, protocol: str = "TCP") -> ServiceInfo:
        """Scan a single port"""
        async with self.semaphore:
            start_time = time.time()
            
            try:
                if protocol.upper() == "TCP":
                    return await self._scan_tcp_port(target, port, start_time)
                elif protocol.upper() == "UDP":
                    return await self._scan_udp_port(target, port, start_time)
                else:
                    raise ValueError(f"Unsupported protocol: {protocol}")
            except Exception as e:
                logger.debug(f"Port scan error {target}:{port}/{protocol}: {e}")
                return ServiceInfo(
                    port=port,
                    protocol=protocol,
                    state="closed",
                    response_time=time.time() - start_time
                )
    
    async def _scan_tcp_port(self, target: str, port: int, start_time: float) -> ServiceInfo:
        """Scan TCP port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )
            
            response_time = time.time() - start_time
            
            # Try to grab banner
            banner = None
            try:
                writer.write(b"\r\n")
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            # Identify service
            service_name = self._identify_service(port, banner)
            
            return ServiceInfo(
                port=port,
                protocol="TCP",
                service_name=service_name,
                banner=banner,
                state="open",
                response_time=response_time
            )
            
        except asyncio.TimeoutError:
            return ServiceInfo(
                port=port,
                protocol="TCP",
                state="filtered",
                response_time=self.timeout
            )
        except ConnectionRefusedError:
            return ServiceInfo(
                port=port,
                protocol="TCP",
                state="closed",
                response_time=time.time() - start_time
            )
    
    async def _scan_udp_port(self, target: str, port: int, start_time: float) -> ServiceInfo:
        """Scan UDP port (basic implementation)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send a generic UDP probe
            sock.sendto(b"\x00" * 4, (target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                response_time = time.time() - start_time
                service_name = self._identify_service(port, None)
                
                return ServiceInfo(
                    port=port,
                    protocol="UDP",
                    service_name=service_name,
                    state="open",
                    response_time=response_time
                )
            except socket.timeout:
                # UDP is tricky - no response might mean open or filtered
                return ServiceInfo(
                    port=port,
                    protocol="UDP",
                    state="open|filtered",
                    response_time=self.timeout
                )
        except Exception:
            return ServiceInfo(
                port=port,
                protocol="UDP",
                state="closed",
                response_time=time.time() - start_time
            )
        finally:
            sock.close()
    
    def _identify_service(self, port: int, banner: Optional[str]) -> Optional[str]:
        """Identify service based on port and banner"""
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 3389: "rdp", 5432: "postgresql", 3306: "mysql",
            6379: "redis", 27017: "mongodb", 8080: "http-alt", 8443: "https-alt"
        }
        
        service = common_ports.get(port)
        
        # Enhance identification with banner analysis
        if banner and service:
            banner_lower = banner.lower()
            if "ssh" in banner_lower:
                service = "ssh"
            elif "http" in banner_lower:
                service = "http"
            elif "ftp" in banner_lower:
                service = "ftp"
            elif "smtp" in banner_lower:
                service = "smtp"
        
        return service
    
    async def scan_ports(self, target: str, ports: List[int], 
                        protocols: List[str] = None) -> List[ServiceInfo]:
        """Scan multiple ports concurrently"""
        if protocols is None:
            protocols = ["TCP"]
        
        tasks = []
        for port in ports:
            for protocol in protocols:
                tasks.append(self.scan_port(target, port, protocol))
        
        return await asyncio.gather(*tasks)

class TargetResolver:
    """Advanced target resolution engine with caching and optimization"""
    
    def __init__(self, dns_servers: List[str] = None, cache_size: int = 10000):
        self.dns_cache = DNSCache(max_size=cache_size)
        self.port_scanner = PortScanner()
        self.dns_servers = dns_servers or ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.dns_servers
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
    
    async def resolve_target(self, target: str) -> TargetInfo:
        """
        Resolve target to comprehensive target information
        Supports URLs, domain names, and IP addresses
        """
        start_time = time.time()
        
        # Parse target
        parsed_target = self._parse_target(target)
        hostname = parsed_target['hostname']
        
        target_info = TargetInfo(original_target=target, hostname=hostname)
        
        # Resolve IP addresses
        if self._is_ip_address(hostname):
            # Target is already an IP address
            if self._is_ipv4(hostname):
                target_info.ipv4_addresses = [hostname]
            else:
                target_info.ipv6_addresses = [hostname]
            target_info.ip_addresses = [hostname]
        else:
            # Resolve hostname to IP addresses
            await self._resolve_hostname(hostname, target_info)
        
        # Perform service discovery on primary IP
        if target_info.ip_addresses:
            primary_ip = target_info.ip_addresses[0]
            await self._discover_services(primary_ip, target_info, parsed_target.get('port'))
            await self._analyze_network_path(primary_ip, target_info)
        
        target_info.resolution_time = time.time() - start_time
        target_info.last_updated = time.time()
        
        return target_info
    
    def _parse_target(self, target: str) -> Dict[str, Union[str, int]]:
        """Parse target URL/hostname/IP and extract components"""
        # Handle URLs
        if '://' in target:
            parsed = urlparse(target)
            hostname = parsed.hostname or parsed.netloc.split(':')[0]
            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == 'https' else 80
        else:
            # Handle hostname:port or IP:port
            if ':' in target and not self._is_ipv6(target):
                hostname, port_str = target.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    hostname = target
                    port = None
            else:
                hostname = target
                port = None
        
        return {'hostname': hostname, 'port': port}
    
    def _is_ip_address(self, addr: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False
    
    def _is_ipv4(self, addr: str) -> bool:
        """Check if string is IPv4 address"""
        try:
            ipaddress.IPv4Address(addr)
            return True
        except ValueError:
            return False
    
    def _is_ipv6(self, addr: str) -> bool:
        """Check if string is IPv6 address"""
        try:
            ipaddress.IPv6Address(addr)
            return True
        except ValueError:
            return False
    
    async def _resolve_hostname(self, hostname: str, target_info: TargetInfo):
        """Resolve hostname to IP addresses with caching"""
        # Check cache first
        cached_addresses = await self.dns_cache.get(hostname)
        if cached_addresses:
            target_info.ip_addresses = cached_addresses
            self._categorize_ip_addresses(target_info)
            return
        
        # Perform DNS resolution
        addresses = []
        dns_records = {}
        
        try:
            # Resolve A records (IPv4)
            loop = asyncio.get_event_loop()
            a_records = await loop.run_in_executor(
                self.executor, self._resolve_dns_record, hostname, 'A'
            )
            if a_records:
                addresses.extend(a_records)
                dns_records['A'] = a_records
            
            # Resolve AAAA records (IPv6)
            aaaa_records = await loop.run_in_executor(
                self.executor, self._resolve_dns_record, hostname, 'AAAA'
            )
            if aaaa_records:
                addresses.extend(aaaa_records)
                dns_records['AAAA'] = aaaa_records
            
            # Resolve other useful records
            for record_type in ['CNAME', 'MX', 'TXT']:
                records = await loop.run_in_executor(
                    self.executor, self._resolve_dns_record, hostname, record_type
                )
                if records:
                    dns_records[record_type] = records
            
        except Exception as e:
            logger.error(f"DNS resolution failed for {hostname}: {e}")
            # Fallback to system resolver
            try:
                addr_info = await loop.run_in_executor(
                    self.executor, socket.getaddrinfo, hostname, None
                )
                addresses = list(set([info[4][0] for info in addr_info]))
            except Exception as fallback_error:
                logger.error(f"Fallback DNS resolution failed: {fallback_error}")
        
        if addresses:
            target_info.ip_addresses = addresses
            target_info.dns_records = dns_records
            self._categorize_ip_addresses(target_info)
            
            # Cache the results
            await self.dns_cache.set(hostname, addresses)
    
    def _resolve_dns_record(self, hostname: str, record_type: str) -> List[str]:
        """Resolve specific DNS record type (synchronous)"""
        try:
            answers = self.resolver.resolve(hostname, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception as e:
            logger.debug(f"DNS {record_type} resolution error for {hostname}: {e}")
            return []
    
    def _categorize_ip_addresses(self, target_info: TargetInfo):
        """Categorize IP addresses into IPv4 and IPv6"""
        for addr in target_info.ip_addresses:
            if self._is_ipv4(addr):
                target_info.ipv4_addresses.append(addr)
            elif self._is_ipv6(addr):
                target_info.ipv6_addresses.append(addr)
    
    async def _discover_services(self, ip: str, target_info: TargetInfo, 
                               hint_port: Optional[int] = None):
        """Discover services through port scanning"""
        # Define port ranges to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                       3389, 5432, 3306, 6379, 27017, 8080, 8443]
        
        # Add hint port if provided
        if hint_port and hint_port not in common_ports:
            common_ports.append(hint_port)
        
        # Scan ports
        services = await self.port_scanner.scan_ports(ip, common_ports, ["TCP"])
        
        # Filter to only open ports
        open_services = [svc for svc in services if svc.state == "open"]
        target_info.ports = open_services
        
        logger.info(f"Discovered {len(open_services)} open services on {ip}")
    
    async def _analyze_network_path(self, ip: str, target_info: TargetInfo):
        """Analyze network path characteristics"""
        network_info = NetworkInfo()
        
        try:
            # Measure latency with ping
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            
            try:
                sock.connect((ip, 80))  # Try HTTP port for connectivity test
                network_info.latency = (time.time() - start_time) * 1000  # Convert to ms
            except:
                # Try ICMP ping as fallback (requires raw socket privileges)
                pass
            finally:
                sock.close()
            
            # Estimate MTU (simplified)
            network_info.mtu = 1500  # Default Ethernet MTU
            network_info.path_mtu = 1500
            
        except Exception as e:
            logger.debug(f"Network path analysis error for {ip}: {e}")
        
        target_info.network_info = network_info
    
    async def probe_services(self, ip: str, ports: List[int] = None) -> List[ServiceInfo]:
        """Probe specific services on target"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                    3389, 5432, 3306, 6379, 27017, 8080, 8443]
        
        return await self.port_scanner.scan_ports(ip, ports, ["TCP", "UDP"])
    
    async def analyze_network_path(self, target: str) -> NetworkInfo:
        """Analyze network topology to target"""
        network_info = NetworkInfo()
        
        # Parse target to get IP
        if self._is_ip_address(target):
            ip = target
        else:
            target_info = await self.resolve_target(target)
            if not target_info.ip_addresses:
                raise ValueError(f"Could not resolve target: {target}")
            ip = target_info.ip_addresses[0]
        
        await self._analyze_network_path(ip, type('obj', (object,), {'network_info': network_info})())
        return network_info