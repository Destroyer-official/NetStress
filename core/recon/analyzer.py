"""
Target Analysis Module

Provides comprehensive target analysis:
- Network mapping
- Host discovery
- Vulnerability scanning
- Attack surface analysis
"""

import asyncio
import socket
import struct
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Set
from enum import Enum
import logging

logger = logging.getLogger(__name__)

# Import COMMON_PORTS from scanner module
try:
    from .scanner import COMMON_PORTS
except ImportError:
    # Fallback if import fails
    COMMON_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 443: 'https', 445: 'microsoft-ds',
        3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
        6379: 'redis', 8080: 'http-proxy', 27017: 'mongodb',
    }


@dataclass
class HostInfo:
    """Information about a discovered host"""
    ip: str
    hostname: Optional[str] = None
    is_alive: bool = False
    open_ports: List[int] = field(default_factory=list)
    os_guess: Optional[str] = None
    services: Dict[int, str] = field(default_factory=dict)
    response_time: float = 0.0


class HostDiscovery:
    """
    Host Discovery
    
    Discovers live hosts on a network using:
    - ICMP ping
    - TCP SYN ping
    - ARP scan (local network)
    """
    
    def __init__(self, timeout: float = 2.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._results: Dict[str, HostInfo] = {}
        
    async def discover(self, network: str) -> Dict[str, HostInfo]:
        """Discover hosts in network"""
        self._results = {}
        
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.error(f"Invalid network: {e}")
            return {}
            
        hosts = list(net.hosts())
        logger.info(f"Scanning {len(hosts)} hosts in {network}")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_host(ip: str):
            async with semaphore:
                info = await self._check_host(ip)
                if info.is_alive:
                    self._results[ip] = info
                    
        tasks = [check_host(str(ip)) for ip in hosts]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"Found {len(self._results)} live hosts")
        return self._results
        
    async def _check_host(self, ip: str) -> HostInfo:
        """Check if host is alive"""
        info = HostInfo(ip=ip)
        start = time.monotonic()
        
        # Try TCP connect to common ports
        common_ports = [80, 443, 22, 445, 139, 21, 23, 25, 3389]
        
        for port in common_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                
                info.is_alive = True
                info.open_ports.append(port)
                info.response_time = time.monotonic() - start
                break
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue
                
        # Try hostname resolution
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            info.hostname = hostname
        except socket.herror:
            pass
            
        return info
        
    def get_live_hosts(self) -> List[str]:
        """Get list of live host IPs"""
        return list(self._results.keys())


class NetworkMapper:
    """
    Network Mapping
    
    Maps network topology and relationships.
    """
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.topology: Dict[str, Any] = {}
        
    async def map_network(self, target: str) -> Dict[str, Any]:
        """Map network around target"""
        self.topology = {
            'target': target,
            'hops': [],
            'neighbors': [],
        }
        
        # Traceroute
        hops = await self._traceroute(target)
        self.topology['hops'] = hops
        
        return self.topology
        
    async def _traceroute(self, target: str, max_hops: int = 30) -> List[Dict]:
        """Perform traceroute"""
        hops = []
        
        try:
            dest_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return hops
            
        for ttl in range(1, max_hops + 1):
            hop_info = await self._probe_hop(dest_ip, ttl)
            hops.append(hop_info)
            
            if hop_info.get('ip') == dest_ip:
                break
                
        return hops
        
    async def _probe_hop(self, dest: str, ttl: int) -> Dict[str, Any]:
        """Probe a single hop"""
        result = {'ttl': ttl, 'ip': None, 'rtt': None}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.settimeout(self.timeout)
            
            port = 33434 + ttl
            start = time.monotonic()
            
            sock.sendto(b'', (dest, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                result['ip'] = addr[0]
                result['rtt'] = (time.monotonic() - start) * 1000
            except socket.timeout:
                result['ip'] = '*'
                
        except Exception as e:
            logger.debug(f"Traceroute error at TTL {ttl}: {e}")
        finally:
            sock.close()
            
        return result


class VulnerabilityScanner:
    """
    Basic Vulnerability Scanner
    
    Checks for common vulnerabilities:
    - Default credentials
    - Known CVEs
    - Misconfigurations
    """
    
    # Common default credentials
    DEFAULT_CREDS = {
        'ssh': [('root', 'root'), ('admin', 'admin'), ('root', 'toor')],
        'ftp': [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')],
        'mysql': [('root', ''), ('root', 'root'), ('mysql', 'mysql')],
        'redis': [(None, None)],  # No auth
    }
    
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        self.vulnerabilities: List[Dict] = []
        
    async def scan(self, ports: List[int]) -> List[Dict]:
        """Scan for vulnerabilities"""
        self.vulnerabilities = []
        
        for port in ports:
            vulns = await self._check_port(port)
            self.vulnerabilities.extend(vulns)
            
        return self.vulnerabilities
        
    async def _check_port(self, port: int) -> List[Dict]:
        """Check port for vulnerabilities"""
        vulns = []
        
        # Service-specific checks
        service_checks = {
            22: self._check_ssh,
            21: self._check_ftp,
            80: self._check_http,
            443: self._check_https,
            3306: self._check_mysql,
            6379: self._check_redis,
        }
        
        if port in service_checks:
            result = await service_checks[port]()
            if result:
                vulns.extend(result)
                
        return vulns

    async def _check_ssh(self) -> List[Dict]:
        """Check SSH for vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 22),
                timeout=self.timeout
            )
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            banner_str = banner.decode('utf-8', errors='ignore')
            
            writer.close()
            
            # Check for old SSH versions
            if 'SSH-1' in banner_str:
                vulns.append({
                    'port': 22,
                    'severity': 'high',
                    'title': 'SSH Protocol v1 Enabled',
                    'description': 'SSH v1 has known vulnerabilities',
                })
                
            # Check for vulnerable versions
            if 'OpenSSH_4' in banner_str or 'OpenSSH_5' in banner_str:
                vulns.append({
                    'port': 22,
                    'severity': 'medium',
                    'title': 'Outdated OpenSSH Version',
                    'description': f'Old SSH version detected: {banner_str.strip()}',
                })
                
        except Exception:
            pass
            
        return vulns
        
    async def _check_ftp(self) -> List[Dict]:
        """Check FTP for vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 21),
                timeout=self.timeout
            )
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            
            # Try anonymous login
            writer.write(b'USER anonymous\r\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2)
            
            if b'331' in response:
                writer.write(b'PASS anonymous@\r\n')
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=2)
                
                if b'230' in response:
                    vulns.append({
                        'port': 21,
                        'severity': 'high',
                        'title': 'Anonymous FTP Login Allowed',
                        'description': 'FTP server allows anonymous access',
                    })
                    
            writer.close()
            
        except Exception:
            pass
            
        return vulns
        
    async def _check_http(self) -> List[Dict]:
        """Check HTTP for vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 80),
                timeout=self.timeout
            )
            
            request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            response_str = response.decode('utf-8', errors='ignore')
            
            writer.close()
            
            # Check for missing security headers
            if 'X-Frame-Options' not in response_str:
                vulns.append({
                    'port': 80,
                    'severity': 'low',
                    'title': 'Missing X-Frame-Options Header',
                    'description': 'Site may be vulnerable to clickjacking',
                })
                
            if 'X-Content-Type-Options' not in response_str:
                vulns.append({
                    'port': 80,
                    'severity': 'low',
                    'title': 'Missing X-Content-Type-Options Header',
                    'description': 'Site may be vulnerable to MIME sniffing',
                })
                
            # Check for server version disclosure
            if 'Server:' in response_str:
                import re
                match = re.search(r'Server:\s*(.+)', response_str)
                if match and any(v in match.group(1) for v in ['Apache/2.2', 'nginx/1.0', 'IIS/6']):
                    vulns.append({
                        'port': 80,
                        'severity': 'medium',
                        'title': 'Outdated Web Server',
                        'description': f'Old server version: {match.group(1)}',
                    })
                    
        except Exception:
            pass
            
        return vulns
        
    async def _check_https(self) -> List[Dict]:
        """Check HTTPS for vulnerabilities"""
        import ssl
        vulns = []
        
        # Check for weak TLS versions
        weak_versions = [
            (ssl.TLSVersion.TLSv1, 'TLSv1.0'),
            (ssl.TLSVersion.TLSv1_1, 'TLSv1.1'),
        ]
        
        for version, name in weak_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, 443, ssl=ctx),
                    timeout=self.timeout
                )
                writer.close()
                
                vulns.append({
                    'port': 443,
                    'severity': 'medium',
                    'title': f'Weak TLS Version Supported: {name}',
                    'description': f'Server supports deprecated {name}',
                })
                
            except Exception:
                pass
                
        return vulns
        
    async def _check_mysql(self) -> List[Dict]:
        """Check MySQL for vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 3306),
                timeout=self.timeout
            )
            
            # Read greeting
            greeting = await asyncio.wait_for(reader.read(1024), timeout=2)
            
            if greeting:
                # Check for old MySQL versions
                if b'5.0' in greeting or b'5.1' in greeting:
                    vulns.append({
                        'port': 3306,
                        'severity': 'high',
                        'title': 'Outdated MySQL Version',
                        'description': 'MySQL 5.0/5.1 has known vulnerabilities',
                    })
                    
            writer.close()
            
        except Exception:
            pass
            
        return vulns
        
    async def _check_redis(self) -> List[Dict]:
        """Check Redis for vulnerabilities"""
        vulns = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, 6379),
                timeout=self.timeout
            )
            
            # Try INFO command without auth
            writer.write(b'INFO\r\n')
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=2)
            
            if b'redis_version' in response:
                vulns.append({
                    'port': 6379,
                    'severity': 'critical',
                    'title': 'Redis No Authentication',
                    'description': 'Redis server has no authentication',
                })
                
            writer.close()
            
        except Exception:
            pass
            
        return vulns


@dataclass
class TargetProfile:
    """
    Comprehensive target profile.
    
    Requirements: 21.1 - Aggregate scan results, identify vulnerable services, generate target profile
    """
    target: str
    timestamp: float
    
    # Network information
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    is_alive: bool = False
    
    # Port information
    open_ports: List[int] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    
    # Service information
    services: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    
    # OS information
    os_type: Optional[str] = None
    os_confidence: float = 0.0
    
    # Web information
    web_server: Optional[str] = None
    web_framework: Optional[str] = None
    web_cms: Optional[str] = None
    web_technologies: List[str] = field(default_factory=list)
    
    # TLS information
    tls_protocols: List[str] = field(default_factory=list)
    tls_cipher: Optional[str] = None
    certificate_info: Dict[str, Any] = field(default_factory=dict)
    
    # Vulnerability information
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    vulnerability_count: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    
    # Attack surface
    attack_vectors: List[str] = field(default_factory=list)
    recommended_attacks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Risk assessment
    risk_score: float = 0.0
    risk_level: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary"""
        return {
            'target': self.target,
            'timestamp': self.timestamp,
            'network': {
                'ip_address': self.ip_address,
                'hostname': self.hostname,
                'is_alive': self.is_alive,
            },
            'ports': {
                'open': self.open_ports,
                'filtered': self.filtered_ports,
                'closed': self.closed_ports,
                'total_open': len(self.open_ports),
            },
            'services': self.services,
            'os': {
                'type': self.os_type,
                'confidence': self.os_confidence,
            },
            'web': {
                'server': self.web_server,
                'framework': self.web_framework,
                'cms': self.web_cms,
                'technologies': self.web_technologies,
            },
            'tls': {
                'protocols': self.tls_protocols,
                'cipher': self.tls_cipher,
                'certificate': self.certificate_info,
            },
            'vulnerabilities': {
                'total': self.vulnerability_count,
                'critical': self.critical_vulns,
                'high': self.high_vulns,
                'medium': self.medium_vulns,
                'low': self.low_vulns,
                'details': self.vulnerabilities,
            },
            'attack_surface': {
                'vectors': self.attack_vectors,
                'recommended_attacks': self.recommended_attacks,
            },
            'risk': {
                'score': self.risk_score,
                'level': self.risk_level,
            }
        }


class TargetProfiler:
    """
    Target Profiling Engine
    
    Aggregates reconnaissance data and generates comprehensive target profiles.
    
    Requirements: 21.1 - Aggregate scan results, identify vulnerable services, generate target profile
    """
    
    def __init__(self, target: str):
        self.target = target
        self.profile: Optional[TargetProfile] = None
        
    async def create_profile(self, full_scan: bool = False, 
                           detect_versions: bool = True,
                           scan_vulnerabilities: bool = True) -> TargetProfile:
        """
        Create comprehensive target profile.
        
        Requirements: 21.1 - Aggregate scan results, identify vulnerable services
        
        Args:
            full_scan: Perform full port scan (1-65535) vs common ports
            detect_versions: Enable service version detection
            scan_vulnerabilities: Enable vulnerability scanning
            
        Returns:
            TargetProfile with aggregated reconnaissance data
        """
        from .scanner import SYNScanner, ScanConfig, BannerGrabber, PortState
        from .fingerprint import OSFingerprint, WebFingerprint, TLSFingerprint
        
        logger.info(f"Creating target profile for {self.target}")
        
        # Initialize profile
        self.profile = TargetProfile(
            target=self.target,
            timestamp=time.time()
        )
        
        # Resolve hostname/IP
        try:
            self.profile.ip_address = socket.gethostbyname(self.target)
            try:
                self.profile.hostname = socket.gethostbyaddr(self.profile.ip_address)[0]
            except socket.herror:
                self.profile.hostname = self.target
        except socket.gaierror:
            logger.error(f"Cannot resolve target: {self.target}")
            return self.profile
        
        # Port scan
        ports = list(range(1, 65536)) if full_scan else list(COMMON_PORTS.keys())
        logger.info(f"Scanning {len(ports)} ports...")
        
        scanner = SYNScanner(
            ScanConfig(target=self.target, ports=ports, timeout=2.0, max_concurrent=100),
            detect_versions=detect_versions
        )
        scan_results = await scanner.scan()
        
        # Categorize ports
        for port, result in scan_results.items():
            if result.state == PortState.OPEN:
                self.profile.open_ports.append(port)
                self.profile.services[port] = {
                    'service': result.service,
                    'version': result.version,
                    'banner': result.banner,
                    'response_time': result.response_time,
                }
            elif result.state == PortState.FILTERED:
                self.profile.filtered_ports.append(port)
            elif result.state == PortState.CLOSED:
                self.profile.closed_ports.append(port)
        
        self.profile.is_alive = len(self.profile.open_ports) > 0
        
        if not self.profile.is_alive:
            logger.warning(f"No open ports found on {self.target}")
            return self.profile
        
        logger.info(f"Found {len(self.profile.open_ports)} open ports")
        
        # Banner grabbing for open ports
        if detect_versions:
            logger.info("Grabbing banners...")
            banner_grabber = BannerGrabber(self.target)
            banners = await banner_grabber.grab_multiple(self.profile.open_ports)
            
            for port, banner_info in banners.items():
                if port in self.profile.services:
                    self.profile.services[port].update({
                        'banner': banner_info.get('banner'),
                        'server_header': banner_info.get('server_header'),
                        'tls_info': banner_info.get('tls_info'),
                    })
        
        # OS fingerprinting
        logger.info("Fingerprinting OS...")
        os_fp = OSFingerprint(self.target)
        os_result = await os_fp.fingerprint(self.profile.open_ports[0] if self.profile.open_ports else 80)
        self.profile.os_type = os_result.os_name
        self.profile.os_confidence = os_result.confidence
        
        # Web fingerprinting
        if 80 in self.profile.open_ports or 443 in self.profile.open_ports:
            logger.info("Fingerprinting web application...")
            port = 443 if 443 in self.profile.open_ports else 80
            use_ssl = port == 443
            
            web_fp = WebFingerprint(self.target, port, use_ssl)
            web_result = await web_fp.fingerprint()
            
            self.profile.web_server = web_result.server
            self.profile.web_framework = web_result.framework
            self.profile.web_cms = web_result.cms
            self.profile.web_technologies = web_result.technologies
        
        # TLS fingerprinting
        if 443 in self.profile.open_ports:
            logger.info("Analyzing TLS configuration...")
            tls_fp = TLSFingerprint(self.target)
            tls_result = await tls_fp.fingerprint()
            
            self.profile.tls_protocols = tls_result.get('protocols', [])
            self.profile.tls_cipher = tls_result.get('cipher')
            self.profile.certificate_info = tls_result.get('certificate', {})
        
        # Vulnerability scanning
        if scan_vulnerabilities:
            logger.info("Scanning for vulnerabilities...")
            vuln_scanner = VulnerabilityScanner(self.target)
            self.profile.vulnerabilities = await vuln_scanner.scan(self.profile.open_ports)
            
            # Count vulnerabilities by severity
            for vuln in self.profile.vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity == 'critical':
                    self.profile.critical_vulns += 1
                elif severity == 'high':
                    self.profile.high_vulns += 1
                elif severity == 'medium':
                    self.profile.medium_vulns += 1
                else:
                    self.profile.low_vulns += 1
            
            self.profile.vulnerability_count = len(self.profile.vulnerabilities)
        
        # Identify attack vectors
        self._identify_attack_vectors()
        
        # Calculate risk score
        self._calculate_risk_score()
        
        logger.info(f"Profile complete. Risk level: {self.profile.risk_level}")
        
        return self.profile
    
    def _identify_attack_vectors(self):
        """
        Identify potential attack vectors based on open services.
        
        Requirements: 21.1 - Identify vulnerable services
        """
        if not self.profile:
            return
        
        vectors = []
        recommendations = []
        
        # Web services
        if 80 in self.profile.open_ports or 443 in self.profile.open_ports:
            vectors.append('http_flood')
            vectors.append('slowloris')
            recommendations.append({
                'vector': 'HTTP Flood',
                'description': 'High-volume HTTP request flood',
                'ports': [p for p in [80, 443] if p in self.profile.open_ports],
                'effectiveness': 'high' if self.profile.web_server else 'medium'
            })
            
            if self.profile.web_server:
                if 'nginx' in self.profile.web_server.lower():
                    recommendations.append({
                        'vector': 'Slowloris',
                        'description': 'Slow HTTP headers attack (effective against Nginx)',
                        'ports': [80, 443],
                        'effectiveness': 'high'
                    })
                elif 'apache' in self.profile.web_server.lower():
                    recommendations.append({
                        'vector': 'Slow POST (RUDY)',
                        'description': 'Slow POST body attack (effective against Apache)',
                        'ports': [80, 443],
                        'effectiveness': 'high'
                    })
        
        # DNS services
        if 53 in self.profile.open_ports:
            vectors.append('dns_amplification')
            recommendations.append({
                'vector': 'DNS Amplification',
                'description': 'DNS query amplification attack',
                'ports': [53],
                'effectiveness': 'high'
            })
        
        # Database services
        db_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis'}
        for port, db_name in db_ports.items():
            if port in self.profile.open_ports:
                vectors.append(f'{db_name.lower()}_flood')
                recommendations.append({
                    'vector': f'{db_name} Connection Flood',
                    'description': f'Exhaust {db_name} connection pool',
                    'ports': [port],
                    'effectiveness': 'medium'
                })
        
        # SSH brute force
        if 22 in self.profile.open_ports:
            vectors.append('ssh_brute_force')
            recommendations.append({
                'vector': 'SSH Brute Force',
                'description': 'SSH authentication brute force',
                'ports': [22],
                'effectiveness': 'low'
            })
        
        # Generic TCP/UDP floods
        vectors.extend(['tcp_syn_flood', 'udp_flood', 'icmp_flood'])
        recommendations.append({
            'vector': 'TCP SYN Flood',
            'description': 'Generic TCP SYN flood attack',
            'ports': self.profile.open_ports[:10],  # Top 10 ports
            'effectiveness': 'medium'
        })
        
        self.profile.attack_vectors = list(set(vectors))
        self.profile.recommended_attacks = recommendations
    
    def _calculate_risk_score(self):
        """Calculate overall risk score for target"""
        if not self.profile:
            return
        
        score = 0.0
        
        # Open ports contribute to risk
        score += min(len(self.profile.open_ports) * 2, 30)
        
        # Vulnerabilities contribute heavily
        score += self.profile.critical_vulns * 20
        score += self.profile.high_vulns * 10
        score += self.profile.medium_vulns * 5
        score += self.profile.low_vulns * 1
        
        # Exposed services
        if 22 in self.profile.open_ports:  # SSH
            score += 5
        if 3389 in self.profile.open_ports:  # RDP
            score += 10
        if 21 in self.profile.open_ports:  # FTP
            score += 8
        
        # Web services with known tech
        if self.profile.web_server:
            score += 5
        if self.profile.web_cms:
            score += 10  # CMS often have vulnerabilities
        
        # Weak TLS
        if 'TLSv1.0' in self.profile.tls_protocols or 'TLSv1.1' in self.profile.tls_protocols:
            score += 15
        
        # Normalize to 0-100
        self.profile.risk_score = min(score, 100.0)
        
        # Determine risk level
        if self.profile.risk_score >= 80:
            self.profile.risk_level = "critical"
        elif self.profile.risk_score >= 60:
            self.profile.risk_level = "high"
        elif self.profile.risk_score >= 40:
            self.profile.risk_level = "medium"
        elif self.profile.risk_score >= 20:
            self.profile.risk_level = "low"
        else:
            self.profile.risk_level = "minimal"
    
    def get_profile(self) -> Optional[TargetProfile]:
        """Get the current profile"""
        return self.profile
    
    def export_profile(self, format: str = 'dict') -> Any:
        """
        Export profile in various formats.
        
        Args:
            format: Export format ('dict', 'json')
            
        Returns:
            Profile in requested format
        """
        if not self.profile:
            return None
        
        if format == 'dict':
            return self.profile.to_dict()
        elif format == 'json':
            import json
            return json.dumps(self.profile.to_dict(), indent=2)
        else:
            return self.profile


class TargetAnalyzer:
    """
    Comprehensive Target Analyzer
    
    Combines all reconnaissance capabilities.
    """
    
    def __init__(self, target: str):
        self.target = target
        self.results: Dict[str, Any] = {}
        
    async def analyze(self, full_scan: bool = False) -> Dict[str, Any]:
        """Perform comprehensive analysis"""
        from .scanner import TCPScanner, ScanConfig
        from .fingerprint import OSFingerprint, WebFingerprint, TLSFingerprint
        
        self.results = {
            'target': self.target,
            'timestamp': time.time(),
            'ports': {},
            'os': None,
            'web': None,
            'tls': None,
            'vulnerabilities': [],
        }
        
        # Port scan
        ports = list(range(1, 1025)) if full_scan else [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
        scanner = TCPScanner(ScanConfig(target=self.target, ports=ports))
        scan_results = await scanner.scan()
        
        self.results['ports'] = {
            'open': scanner.get_open_ports(),
            'details': {p: r.__dict__ for p, r in scan_results.items() if r.state.value == 'open'}
        }
        
        # OS fingerprint
        os_fp = OSFingerprint(self.target)
        self.results['os'] = (await os_fp.fingerprint()).__dict__
        
        # Web fingerprint if port 80/443 open
        if 80 in self.results['ports']['open']:
            web_fp = WebFingerprint(self.target, 80, False)
            self.results['web'] = (await web_fp.fingerprint()).__dict__
        elif 443 in self.results['ports']['open']:
            web_fp = WebFingerprint(self.target, 443, True)
            self.results['web'] = (await web_fp.fingerprint()).__dict__
            
        # TLS fingerprint if 443 open
        if 443 in self.results['ports']['open']:
            tls_fp = TLSFingerprint(self.target)
            self.results['tls'] = await tls_fp.fingerprint()
            
        # Vulnerability scan
        vuln_scanner = VulnerabilityScanner(self.target)
        self.results['vulnerabilities'] = await vuln_scanner.scan(self.results['ports']['open'])
        
        return self.results
