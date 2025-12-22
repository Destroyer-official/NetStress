"""
Target Profiling and Analysis System

Implements network topology discovery, service fingerprinting, and defense
mechanism detection for comprehensive target analysis.
"""

import asyncio
import time
import socket
import struct
import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
import logging
import re
from concurrent.futures import ThreadPoolExecutor

from .resolver import TargetInfo, ServiceInfo, NetworkInfo

logger = logging.getLogger(__name__)

class DefenseType(Enum):
    """Types of defense mechanisms"""
    RATE_LIMITING = "rate_limiting"
    DPI_FILTERING = "dpi_filtering"
    GEO_BLOCKING = "geo_blocking"
    CAPTCHA = "captcha"
    WAF = "waf"
    DDOS_PROTECTION = "ddos_protection"
    FIREWALL = "firewall"
    IPS = "ips"
    LOAD_BALANCER = "load_balancer"

@dataclass
class DefenseIndicator:
    """Indicator of a defense mechanism"""
    defense_type: DefenseType
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)
    bypass_techniques: List[str] = field(default_factory=list)

@dataclass
class DefenseProfile:
    """Profile of target defense mechanisms"""
    indicators: List[DefenseIndicator] = field(default_factory=list)
    overall_strength: float = 0.0  # 0.0 to 1.0
    recommended_evasion: List[str] = field(default_factory=list)
    analysis_time: float = field(default_factory=time.time)

@dataclass
class PerformanceProfile:
    """Target performance characteristics"""
    response_times: Dict[str, float] = field(default_factory=dict)
    throughput_estimate: float = 0.0
    connection_limits: Optional[int] = None
    resource_constraints: Dict[str, Any] = field(default_factory=dict)
    optimal_attack_params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ServiceFingerprint:
    """Detailed service fingerprint"""
    service_name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    os_hints: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    fingerprint_confidence: float = 0.0

class NetworkTopologyMapper:
    """Maps network topology and infrastructure"""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    async def discover_topology(self, target_info: TargetInfo) -> Dict[str, Any]:
        """Discover network topology around target"""
        topology = {
            'hops': [],
            'infrastructure': {},
            'cdn_detection': {},
            'load_balancer_detection': {}
        }
        
        if not target_info.ip_addresses:
            return topology
        
        primary_ip = target_info.ip_addresses[0]
        
        # Perform traceroute analysis
        topology['hops'] = await self._traceroute_analysis(primary_ip)
        
        # Detect CDN and load balancers
        topology['cdn_detection'] = await self._detect_cdn(target_info)
        topology['load_balancer_detection'] = await self._detect_load_balancer(target_info)
        
        # Analyze infrastructure
        topology['infrastructure'] = await self._analyze_infrastructure(target_info)
        
        return topology
    
    async def _traceroute_analysis(self, target_ip: str) -> List[Dict[str, Any]]:
        """Perform traceroute analysis to map network path"""
        hops = []
        
        try:
            # Simplified traceroute implementation
            for ttl in range(1, 31):  # Max 30 hops
                hop_info = await self._probe_hop(target_ip, ttl)
                if hop_info:
                    hops.append(hop_info)
                    if hop_info.get('reached_target'):
                        break
        except Exception as e:
            logger.debug(f"Traceroute analysis error: {e}")
        
        return hops
    
    async def _probe_hop(self, target_ip: str, ttl: int) -> Optional[Dict[str, Any]]:
        """Probe a single hop in traceroute"""
        try:
            # Create raw socket for ICMP (requires privileges)
            # Fallback to TCP-based traceroute
            start_time = time.time()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            
            # Set TTL
            if hasattr(socket, 'IP_TTL'):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            
            try:
                sock.connect((target_ip, 80))
                rtt = (time.time() - start_time) * 1000
                return {
                    'hop': ttl,
                    'ip': target_ip,
                    'rtt': rtt,
                    'reached_target': True
                }
            except socket.timeout:
                return {
                    'hop': ttl,
                    'ip': '*',
                    'rtt': 3000,
                    'reached_target': False
                }
            except Exception:
                return None
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"Hop probe error for TTL {ttl}: {e}")
            return None
    
    async def _detect_cdn(self, target_info: TargetInfo) -> Dict[str, Any]:
        """Detect CDN usage"""
        cdn_indicators = {
            'detected': False,
            'provider': None,
            'evidence': []
        }
        
        # Check DNS records for CDN indicators
        dns_records = target_info.dns_records
        
        # Common CDN CNAME patterns
        cdn_patterns = {
            'cloudflare': [r'\.cloudflare\.', r'\.cf-ipv6\.'],
            'akamai': [r'\.akamai\.', r'\.edgesuite\.', r'\.edgekey\.'],
            'fastly': [r'\.fastly\.', r'\.fastlylb\.'],
            'amazon': [r'\.cloudfront\.', r'\.amazonaws\.'],
            'google': [r'\.googleusercontent\.', r'\.ghs\.'],
            'microsoft': [r'\.azureedge\.', r'\.trafficmanager\.']
        }
        
        if 'CNAME' in dns_records:
            for cname in dns_records['CNAME']:
                for provider, patterns in cdn_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, cname, re.IGNORECASE):
                            cdn_indicators['detected'] = True
                            cdn_indicators['provider'] = provider
                            cdn_indicators['evidence'].append(f"CNAME: {cname}")
        
        # Check for multiple IP addresses (CDN characteristic)
        if len(target_info.ip_addresses) > 3:
            cdn_indicators['evidence'].append("Multiple IP addresses detected")
        
        return cdn_indicators
    
    async def _detect_load_balancer(self, target_info: TargetInfo) -> Dict[str, Any]:
        """Detect load balancer presence"""
        lb_indicators = {
            'detected': False,
            'type': None,
            'evidence': []
        }
        
        # Multiple IPs often indicate load balancing
        if len(target_info.ip_addresses) > 1:
            lb_indicators['detected'] = True
            lb_indicators['evidence'].append(f"Multiple IPs: {len(target_info.ip_addresses)}")
        
        # Check for load balancer headers (would need HTTP probing)
        # This is a simplified detection
        
        return lb_indicators
    
    async def _analyze_infrastructure(self, target_info: TargetInfo) -> Dict[str, Any]:
        """Analyze target infrastructure"""
        infrastructure = {
            'hosting_provider': None,
            'cloud_platform': None,
            'server_technology': [],
            'estimated_capacity': None
        }
        
        # Analyze IP ranges for hosting provider detection
        if target_info.ip_addresses:
            primary_ip = target_info.ip_addresses[0]
            infrastructure['hosting_provider'] = await self._identify_hosting_provider(primary_ip)
        
        return infrastructure
    
    async def _identify_hosting_provider(self, ip: str) -> Optional[str]:
        """Identify hosting provider from IP address"""
        # This would typically use WHOIS or IP geolocation services
        # Simplified implementation
        
        ip_ranges = {
            'aws': ['54.', '52.', '18.', '3.'],
            'google': ['35.', '34.', '130.'],
            'azure': ['40.', '52.', '13.', '104.'],
            'digitalocean': ['159.', '167.', '178.'],
            'cloudflare': ['104.', '172.']
        }
        
        for provider, prefixes in ip_ranges.items():
            for prefix in prefixes:
                if ip.startswith(prefix):
                    return provider
        
        return None

class ServiceFingerprinter:
    """Advanced service fingerprinting and identification"""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    async def fingerprint_services(self, target_info: TargetInfo) -> List[ServiceFingerprint]:
        """Fingerprint all discovered services"""
        fingerprints = []
        
        for service in target_info.ports:
            if service.state == "open":
                fingerprint = await self.fingerprint_service(
                    target_info.ip_addresses[0], service
                )
                if fingerprint:
                    fingerprints.append(fingerprint)
        
        return fingerprints
    
    async def fingerprint_service(self, ip: str, service: ServiceInfo) -> Optional[ServiceFingerprint]:
        """Fingerprint a specific service"""
        try:
            if service.protocol.upper() == "TCP":
                return await self._fingerprint_tcp_service(ip, service)
            elif service.protocol.upper() == "UDP":
                return await self._fingerprint_udp_service(ip, service)
        except Exception as e:
            logger.debug(f"Service fingerprinting error {ip}:{service.port}: {e}")
        
        return None
    
    async def _fingerprint_tcp_service(self, ip: str, service: ServiceInfo) -> Optional[ServiceFingerprint]:
        """Fingerprint TCP service"""
        fingerprint = ServiceFingerprint(service_name=service.service_name or "unknown")
        
        try:
            # Connect and grab banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, service.port),
                timeout=5.0
            )
            
            # Send service-specific probes
            if service.port == 80 or service.port == 8080:
                await self._probe_http_service(reader, writer, fingerprint)
            elif service.port == 443 or service.port == 8443:
                await self._probe_https_service(reader, writer, fingerprint)
            elif service.port == 22:
                await self._probe_ssh_service(reader, writer, fingerprint)
            elif service.port == 21:
                await self._probe_ftp_service(reader, writer, fingerprint)
            else:
                await self._probe_generic_service(reader, writer, fingerprint)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"TCP fingerprinting error for {ip}:{service.port}: {e}")
        
        return fingerprint
    
    async def _probe_http_service(self, reader, writer, fingerprint: ServiceFingerprint):
        """Probe HTTP service for detailed information"""
        try:
            # Send HTTP request
            request = b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            writer.write(request)
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            response_str = response.decode('utf-8', errors='ignore')
            
            # Parse HTTP headers
            headers = self._parse_http_headers(response_str)
            
            # Extract server information
            if 'server' in headers:
                server_header = headers['server']
                fingerprint.vendor, fingerprint.version = self._parse_server_header(server_header)
                fingerprint.configuration['server_header'] = server_header
            
            # Detect web application framework
            fingerprint.configuration['framework'] = self._detect_web_framework(headers, response_str)
            
            fingerprint.service_name = "http"
            fingerprint.fingerprint_confidence = 0.9
            
        except Exception as e:
            logger.debug(f"HTTP probing error: {e}")
    
    async def _probe_https_service(self, reader, writer, fingerprint: ServiceFingerprint):
        """Probe HTTPS service"""
        # For HTTPS, we'd need SSL/TLS handshake analysis
        # Simplified implementation
        fingerprint.service_name = "https"
        fingerprint.configuration['ssl_enabled'] = True
    
    async def _probe_ssh_service(self, reader, writer, fingerprint: ServiceFingerprint):
        """Probe SSH service"""
        try:
            # Read SSH banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            # Parse SSH version
            if banner_str.startswith('SSH-'):
                parts = banner_str.split()
                if len(parts) > 0:
                    version_info = parts[0].split('-')
                    if len(version_info) >= 3:
                        fingerprint.version = version_info[1]
                        fingerprint.vendor = version_info[2] if len(version_info) > 2 else "unknown"
            
            fingerprint.service_name = "ssh"
            fingerprint.configuration['banner'] = banner_str
            fingerprint.fingerprint_confidence = 0.95
            
        except Exception as e:
            logger.debug(f"SSH probing error: {e}")
    
    async def _probe_ftp_service(self, reader, writer, fingerprint: ServiceFingerprint):
        """Probe FTP service"""
        try:
            # Read FTP banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            fingerprint.service_name = "ftp"
            fingerprint.configuration['banner'] = banner_str
            
            # Extract version information from banner
            if 'vsftpd' in banner_str.lower():
                fingerprint.vendor = "vsftpd"
            elif 'proftpd' in banner_str.lower():
                fingerprint.vendor = "proftpd"
            elif 'filezilla' in banner_str.lower():
                fingerprint.vendor = "filezilla"
            
            fingerprint.fingerprint_confidence = 0.8
            
        except Exception as e:
            logger.debug(f"FTP probing error: {e}")
    
    async def _probe_generic_service(self, reader, writer, fingerprint: ServiceFingerprint):
        """Probe generic service"""
        try:
            # Try to read any banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if banner:
                banner_str = banner.decode('utf-8', errors='ignore').strip()
                fingerprint.configuration['banner'] = banner_str
                fingerprint.fingerprint_confidence = 0.5
        except:
            pass
    
    async def _fingerprint_udp_service(self, ip: str, service: ServiceInfo) -> Optional[ServiceFingerprint]:
        """Fingerprint UDP service"""
        fingerprint = ServiceFingerprint(service_name=service.service_name or "unknown")
        
        # UDP fingerprinting is more challenging
        # Implement service-specific probes
        if service.port == 53:
            fingerprint.service_name = "dns"
            fingerprint.fingerprint_confidence = 0.9
        elif service.port == 123:
            fingerprint.service_name = "ntp"
            fingerprint.fingerprint_confidence = 0.8
        
        return fingerprint
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """Parse HTTP response headers"""
        headers = {}
        lines = response.split('\r\n')
        
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return headers
    
    def _parse_server_header(self, server_header: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse server header for vendor and version"""
        # Common server header patterns
        patterns = [
            (r'Apache/([0-9.]+)', 'Apache'),
            (r'nginx/([0-9.]+)', 'nginx'),
            (r'Microsoft-IIS/([0-9.]+)', 'IIS'),
            (r'lighttpd/([0-9.]+)', 'lighttpd')
        ]
        
        for pattern, vendor in patterns:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                return vendor, match.group(1)
        
        return None, None
    
    def _detect_web_framework(self, headers: Dict[str, str], response: str) -> Optional[str]:
        """Detect web application framework"""
        # Check headers for framework indicators
        framework_headers = {
            'x-powered-by': {
                'ASP.NET': 'asp.net',
                'PHP': 'php',
                'Express': 'express'
            },
            'server': {
                'Kestrel': 'asp.net-core'
            }
        }
        
        for header, indicators in framework_headers.items():
            if header in headers:
                header_value = headers[header]
                for indicator, framework in indicators.items():
                    if indicator.lower() in header_value.lower():
                        return framework
        
        # Check response body for framework indicators
        body_indicators = {
            'django': r'csrfmiddlewaretoken',
            'rails': r'authenticity_token',
            'laravel': r'laravel_session',
            'wordpress': r'wp-content'
        }
        
        for framework, pattern in body_indicators.items():
            if re.search(pattern, response, re.IGNORECASE):
                return framework
        
        return None

class DefenseAnalyzer:
    """Analyzes target defense mechanisms"""
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    async def analyze_defenses(self, target_info: TargetInfo) -> DefenseProfile:
        """Analyze target defense mechanisms"""
        profile = DefenseProfile()
        
        if not target_info.ip_addresses:
            return profile
        
        primary_ip = target_info.ip_addresses[0]
        
        # Analyze different types of defenses
        await self._detect_rate_limiting(primary_ip, target_info.ports, profile)
        await self._detect_waf(primary_ip, target_info.ports, profile)
        await self._detect_ddos_protection(primary_ip, profile)
        await self._detect_firewall(primary_ip, target_info.ports, profile)
        
        # Calculate overall defense strength
        profile.overall_strength = self._calculate_defense_strength(profile)
        
        # Generate evasion recommendations
        profile.recommended_evasion = self._generate_evasion_recommendations(profile)
        
        return profile
    
    async def _detect_rate_limiting(self, ip: str, services: List[ServiceInfo], 
                                  profile: DefenseProfile):
        """Detect rate limiting mechanisms"""
        # Test for rate limiting by sending rapid requests
        http_services = [s for s in services if s.service_name in ['http', 'https']]
        
        for service in http_services:
            try:
                # Send rapid requests to detect rate limiting
                response_times = []
                for i in range(10):
                    start_time = time.time()
                    
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, service.port),
                            timeout=2.0
                        )
                        
                        request = b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"
                        writer.write(request)
                        await writer.drain()
                        
                        response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        response_time = time.time() - start_time
                        response_times.append(response_time)
                        
                        writer.close()
                        await writer.wait_closed()
                        
                        # Check for rate limiting indicators in response
                        if b'429' in response or b'rate limit' in response.lower():
                            indicator = DefenseIndicator(
                                defense_type=DefenseType.RATE_LIMITING,
                                confidence=0.9,
                                evidence=["HTTP 429 response detected"],
                                bypass_techniques=["IP rotation", "Request spacing", "User-Agent rotation"]
                            )
                            profile.indicators.append(indicator)
                            return
                        
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.1)  # Small delay between requests
                
                # Analyze response time patterns
                if len(response_times) > 5:
                    avg_time = sum(response_times) / len(response_times)
                    later_avg = sum(response_times[-3:]) / 3
                    
                    if later_avg > avg_time * 2:  # Significant slowdown
                        indicator = DefenseIndicator(
                            defense_type=DefenseType.RATE_LIMITING,
                            confidence=0.7,
                            evidence=["Response time degradation detected"],
                            bypass_techniques=["Request spacing", "Connection pooling"]
                        )
                        profile.indicators.append(indicator)
                
            except Exception as e:
                logger.debug(f"Rate limiting detection error: {e}")
    
    async def _detect_waf(self, ip: str, services: List[ServiceInfo], profile: DefenseProfile):
        """Detect Web Application Firewall"""
        http_services = [s for s in services if s.service_name in ['http', 'https']]
        
        for service in http_services:
            try:
                # Send requests with common attack patterns
                attack_payloads = [
                    "GET /?id=1' OR '1'='1 HTTP/1.1\r\n",
                    "GET /?q=<script>alert(1)</script> HTTP/1.1\r\n",
                    "GET /../../../etc/passwd HTTP/1.1\r\n"
                ]
                
                for payload in attack_payloads:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, service.port),
                            timeout=3.0
                        )
                        
                        request = payload.encode() + b"Host: target\r\n\r\n"
                        writer.write(request)
                        await writer.drain()
                        
                        response = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                        response_str = response.decode('utf-8', errors='ignore')
                        
                        writer.close()
                        await writer.wait_closed()
                        
                        # Check for WAF indicators
                        waf_indicators = [
                            'cloudflare', 'incapsula', 'sucuri', 'barracuda',
                            'f5 big-ip', 'fortinet', 'imperva', 'akamai',
                            'blocked', 'forbidden', 'security'
                        ]
                        
                        for indicator in waf_indicators:
                            if indicator in response_str.lower():
                                waf_indicator = DefenseIndicator(
                                    defense_type=DefenseType.WAF,
                                    confidence=0.8,
                                    evidence=[f"WAF signature detected: {indicator}"],
                                    bypass_techniques=["Payload encoding", "Request fragmentation", "IP rotation"]
                                )
                                profile.indicators.append(waf_indicator)
                                return
                        
                        # Check for generic blocking responses
                        if any(code in response_str for code in ['403', '406', '501', '503']):
                            waf_indicator = DefenseIndicator(
                                defense_type=DefenseType.WAF,
                                confidence=0.6,
                                evidence=["Suspicious HTTP error codes for attack payloads"],
                                bypass_techniques=["Payload obfuscation", "Protocol switching"]
                            )
                            profile.indicators.append(waf_indicator)
                            return
                        
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"WAF detection error: {e}")
    
    async def _detect_ddos_protection(self, ip: str, profile: DefenseProfile):
        """Detect DDoS protection services"""
        # This would typically involve analyzing response patterns,
        # checking for known DDoS protection providers, etc.
        
        # Simplified implementation - check for common DDoS protection indicators
        try:
            # Multiple rapid connections test
            connection_results = []
            
            for i in range(20):
                try:
                    start_time = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((ip, 80))
                    connection_time = time.time() - start_time
                    connection_results.append(connection_time)
                    sock.close()
                except Exception:
                    connection_results.append(None)
                
                await asyncio.sleep(0.05)  # 50ms between connections
            
            # Analyze connection patterns
            successful_connections = [t for t in connection_results if t is not None]
            failed_connections = len([t for t in connection_results if t is None])
            
            if failed_connections > len(connection_results) * 0.3:  # >30% failures
                ddos_indicator = DefenseIndicator(
                    defense_type=DefenseType.DDOS_PROTECTION,
                    confidence=0.7,
                    evidence=["High connection failure rate under load"],
                    bypass_techniques=["Connection rate limiting", "IP rotation", "Distributed sources"]
                )
                profile.indicators.append(ddos_indicator)
            
        except Exception as e:
            logger.debug(f"DDoS protection detection error: {e}")
    
    async def _detect_firewall(self, ip: str, services: List[ServiceInfo], profile: DefenseProfile):
        """Detect firewall presence"""
        # Analyze port scan results for firewall indicators
        
        # Check for filtered ports (indicates firewall)
        filtered_ports = [s for s in services if s.state == "filtered"]
        
        if len(filtered_ports) > 0:
            firewall_indicator = DefenseIndicator(
                defense_type=DefenseType.FIREWALL,
                confidence=0.8,
                evidence=[f"Filtered ports detected: {len(filtered_ports)}"],
                bypass_techniques=["Port hopping", "Protocol tunneling", "Fragmentation"]
            )
            profile.indicators.append(firewall_indicator)
        
        # Check for consistent port blocking patterns
        common_ports = [21, 22, 23, 25, 135, 139, 445, 1433, 3389]
        blocked_common = [p for p in common_ports if not any(s.port == p and s.state == "open" for s in services)]
        
        if len(blocked_common) > len(common_ports) * 0.7:  # >70% of common ports blocked
            firewall_indicator = DefenseIndicator(
                defense_type=DefenseType.FIREWALL,
                confidence=0.9,
                evidence=["Common administrative ports blocked"],
                bypass_techniques=["Alternative ports", "Protocol switching"]
            )
            profile.indicators.append(firewall_indicator)
    
    def _calculate_defense_strength(self, profile: DefenseProfile) -> float:
        """Calculate overall defense strength score"""
        if not profile.indicators:
            return 0.0
        
        # Weight different defense types
        weights = {
            DefenseType.DDOS_PROTECTION: 0.3,
            DefenseType.WAF: 0.25,
            DefenseType.RATE_LIMITING: 0.2,
            DefenseType.FIREWALL: 0.15,
            DefenseType.IPS: 0.1
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for indicator in profile.indicators:
            weight = weights.get(indicator.defense_type, 0.05)
            total_score += indicator.confidence * weight
            total_weight += weight
        
        return min(1.0, total_score / max(total_weight, 0.1))
    
    def _generate_evasion_recommendations(self, profile: DefenseProfile) -> List[str]:
        """Generate evasion technique recommendations"""
        recommendations = set()
        
        for indicator in profile.indicators:
            recommendations.update(indicator.bypass_techniques)
        
        # Add general recommendations based on defense strength
        if profile.overall_strength > 0.7:
            recommendations.update([
                "Multi-vector attack coordination",
                "Advanced payload obfuscation",
                "Distributed attack sources"
            ])
        elif profile.overall_strength > 0.4:
            recommendations.update([
                "Protocol switching",
                "Request timing variation",
                "User-Agent rotation"
            ])
        
        return list(recommendations)

class TargetProfiler:
    """Main target profiling orchestrator"""
    
    def __init__(self):
        self.topology_mapper = NetworkTopologyMapper()
        self.service_fingerprinter = ServiceFingerprinter()
        self.defense_analyzer = DefenseAnalyzer()
    
    async def profile_target(self, target_info: TargetInfo) -> Tuple[Dict[str, Any], List[ServiceFingerprint], DefenseProfile]:
        """Perform comprehensive target profiling"""
        
        # Discover network topology
        topology = await self.topology_mapper.discover_topology(target_info)
        
        # Fingerprint services
        service_fingerprints = await self.service_fingerprinter.fingerprint_services(target_info)
        
        # Analyze defenses
        defense_profile = await self.defense_analyzer.analyze_defenses(target_info)
        
        return topology, service_fingerprints, defense_profile
    
    async def generate_performance_profile(self, target_info: TargetInfo) -> PerformanceProfile:
        """Generate performance profile for attack optimization"""
        profile = PerformanceProfile()
        
        if not target_info.ip_addresses:
            return profile
        
        primary_ip = target_info.ip_addresses[0]
        
        # Measure response times for different protocols
        for service in target_info.ports:
            if service.state == "open":
                response_time = await self._measure_service_response_time(primary_ip, service)
                profile.response_times[f"{service.protocol}:{service.port}"] = response_time
        
        # Estimate optimal attack parameters
        profile.optimal_attack_params = self._calculate_optimal_params(target_info, profile)
        
        return profile
    
    async def _measure_service_response_time(self, ip: str, service: ServiceInfo) -> float:
        """Measure service response time"""
        try:
            start_time = time.time()
            
            if service.protocol.upper() == "TCP":
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, service.port),
                    timeout=5.0
                )
                writer.close()
                await writer.wait_closed()
            else:
                # UDP response time measurement is more complex
                return 0.0
            
            return time.time() - start_time
            
        except Exception:
            return float('inf')  # Service unreachable
    
    def _calculate_optimal_params(self, target_info: TargetInfo, 
                                performance_profile: PerformanceProfile) -> Dict[str, Any]:
        """Calculate optimal attack parameters"""
        params = {
            'packet_size': 1460,  # Default MSS
            'connection_rate': 1000,
            'protocol_distribution': {'TCP': 0.4, 'UDP': 0.6}
        }
        
        # Adjust based on response times
        avg_response_time = 0.0
        if performance_profile.response_times:
            avg_response_time = sum(performance_profile.response_times.values()) / len(performance_profile.response_times)
        
        if avg_response_time > 1.0:  # Slow target
            params['connection_rate'] = 500
            params['packet_size'] = 1024
        elif avg_response_time < 0.1:  # Fast target
            params['connection_rate'] = 2000
            params['packet_size'] = 1460
        
        # Adjust based on available services
        tcp_services = len([s for s in target_info.ports if s.protocol.upper() == "TCP"])
        udp_services = len([s for s in target_info.ports if s.protocol.upper() == "UDP"])
        
        if tcp_services > udp_services:
            params['protocol_distribution'] = {'TCP': 0.7, 'UDP': 0.3}
        elif udp_services > tcp_services:
            params['protocol_distribution'] = {'TCP': 0.3, 'UDP': 0.7}
        
        return params