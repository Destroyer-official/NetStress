"""
Fingerprinting Module

Implements various fingerprinting techniques:
- OS fingerprinting
- Web application fingerprinting
- Service version detection
- TLS/SSL fingerprinting
"""

import asyncio
import socket
import ssl
import struct
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class OSType(Enum):
    """Operating system types"""
    WINDOWS = "windows"
    LINUX = "linux"
    BSD = "bsd"
    MACOS = "macos"
    SOLARIS = "solaris"
    UNKNOWN = "unknown"


@dataclass
class OSFingerprintResult:
    """OS fingerprint result"""
    os_type: OSType
    os_name: str
    confidence: float
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebFingerprintResult:
    """Web application fingerprint result"""
    server: Optional[str] = None
    framework: Optional[str] = None
    cms: Optional[str] = None
    language: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    confidence: float = 0.0


class OSFingerprint:
    """
    OS Fingerprinting
    
    Identifies target operating system using:
    - TTL analysis
    - TCP window size
    - TCP options
    - ICMP responses
    """
    
    # TTL to OS mapping
    TTL_MAP = {
        (60, 64): OSType.LINUX,
        (64, 64): OSType.LINUX,
        (128, 128): OSType.WINDOWS,
        (255, 255): OSType.SOLARIS,
        (64, 65): OSType.MACOS,
    }
    
    # Window size patterns
    WINDOW_PATTERNS = {
        65535: [OSType.WINDOWS, OSType.BSD],
        5840: [OSType.LINUX],
        14600: [OSType.LINUX],
        29200: [OSType.LINUX],
        32120: [OSType.LINUX],
    }
    
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        
    async def fingerprint(self, port: int = 80) -> OSFingerprintResult:
        """Perform OS fingerprinting"""
        results = {
            'ttl': None,
            'window': None,
            'os_hints': []
        }
        
        # TCP fingerprint
        tcp_result = await self._tcp_fingerprint(port)
        results.update(tcp_result)
        
        # Determine OS
        os_type, confidence = self._analyze_results(results)
        
        return OSFingerprintResult(
            os_type=os_type,
            os_name=os_type.value,
            confidence=confidence,
            ttl=results.get('ttl'),
            window_size=results.get('window'),
            details=results
        )

    async def _tcp_fingerprint(self, port: int) -> Dict[str, Any]:
        """Get TCP fingerprint"""
        result = {}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Get TTL from socket options (platform dependent)
            try:
                ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                result['ttl'] = ttl
            except Exception:
                pass
                
            sock.close()
            
        except Exception as e:
            logger.debug(f"TCP fingerprint error: {e}")
            
        return result
        
    def _analyze_results(self, results: Dict) -> Tuple[OSType, float]:
        """Analyze fingerprint results"""
        scores = {os: 0.0 for os in OSType}
        
        ttl = results.get('ttl')
        if ttl:
            if ttl <= 64:
                scores[OSType.LINUX] += 0.4
                scores[OSType.MACOS] += 0.3
            elif ttl <= 128:
                scores[OSType.WINDOWS] += 0.5
            else:
                scores[OSType.SOLARIS] += 0.3
                
        window = results.get('window')
        if window:
            for size, os_list in self.WINDOW_PATTERNS.items():
                if abs(window - size) < 1000:
                    for os in os_list:
                        scores[os] += 0.3
                        
        # Find best match
        best_os = max(scores, key=scores.get)
        confidence = scores[best_os]
        
        if confidence < 0.2:
            return OSType.UNKNOWN, 0.0
            
        return best_os, min(confidence, 1.0)


class WebFingerprint:
    """
    Web Application Fingerprinting
    
    Identifies web technologies using:
    - HTTP headers
    - HTML content analysis
    - Cookie patterns
    - JavaScript libraries
    """
    
    # Server signatures
    SERVER_SIGNATURES = {
        'nginx': r'nginx/?(\d+\.[\d.]+)?',
        'apache': r'Apache/?(\d+\.[\d.]+)?',
        'iis': r'Microsoft-IIS/?(\d+\.[\d.]+)?',
        'lighttpd': r'lighttpd/?(\d+\.[\d.]+)?',
        'cloudflare': r'cloudflare',
        'gunicorn': r'gunicorn/?(\d+\.[\d.]+)?',
    }
    
    # Framework signatures
    FRAMEWORK_SIGNATURES = {
        'django': [r'csrfmiddlewaretoken', r'django'],
        'rails': [r'_rails', r'X-Rails'],
        'laravel': [r'laravel_session', r'XSRF-TOKEN'],
        'express': [r'X-Powered-By:\s*Express'],
        'flask': [r'Werkzeug'],
        'spring': [r'JSESSIONID', r'X-Application-Context'],
        'asp.net': [r'ASP\.NET', r'__VIEWSTATE'],
    }
    
    # CMS signatures
    CMS_SIGNATURES = {
        'wordpress': [r'/wp-content/', r'/wp-includes/', r'WordPress'],
        'drupal': [r'Drupal', r'/sites/default/'],
        'joomla': [r'Joomla', r'/components/com_'],
        'magento': [r'Magento', r'/skin/frontend/'],
        'shopify': [r'Shopify', r'cdn.shopify.com'],
    }
    
    def __init__(self, target: str, port: int = 80, ssl: bool = False):
        self.target = target
        self.port = port
        self.use_ssl = ssl
        
    async def fingerprint(self) -> WebFingerprintResult:
        """Perform web fingerprinting"""
        result = WebFingerprintResult()
        
        try:
            # Fetch page
            response = await self._fetch_page()
            if not response:
                return result
                
            headers, body = response
            result.headers = headers
            
            # Analyze server
            server = headers.get('server', '')
            result.server = server
            
            # Detect framework
            result.framework = self._detect_framework(headers, body)
            
            # Detect CMS
            result.cms = self._detect_cms(body)
            
            # Detect language
            result.language = self._detect_language(headers, body)
            
            # Collect technologies
            result.technologies = self._collect_technologies(headers, body)
            
            result.confidence = 0.8 if result.server else 0.5
            
        except Exception as e:
            logger.debug(f"Web fingerprint error: {e}")
            
        return result

    async def _fetch_page(self) -> Optional[Tuple[Dict[str, str], str]]:
        """Fetch web page"""
        try:
            if self.use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(
                    self.target, self.port, ssl=ssl_ctx
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.target, self.port
                )
                
            # Send request
            request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(65536), timeout=10)
            writer.close()
            
            # Parse response
            response_str = response.decode('utf-8', errors='ignore')
            parts = response_str.split('\r\n\r\n', 1)
            
            headers = {}
            for line in parts[0].split('\r\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.lower().strip()] = value.strip()
                    
            body = parts[1] if len(parts) > 1 else ''
            
            return headers, body
            
        except Exception as e:
            logger.debug(f"Fetch error: {e}")
            return None
            
    def _detect_framework(self, headers: Dict, body: str) -> Optional[str]:
        """Detect web framework"""
        combined = str(headers) + body
        
        for framework, patterns in self.FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return framework
        return None
        
    def _detect_cms(self, body: str) -> Optional[str]:
        """Detect CMS"""
        for cms, patterns in self.CMS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return cms
        return None
        
    def _detect_language(self, headers: Dict, body: str) -> Optional[str]:
        """Detect programming language"""
        powered_by = headers.get('x-powered-by', '').lower()
        
        if 'php' in powered_by:
            return 'php'
        elif 'asp.net' in powered_by:
            return 'asp.net'
        elif '.php' in body:
            return 'php'
        elif '.jsp' in body or 'java' in powered_by:
            return 'java'
        elif '.aspx' in body:
            return 'asp.net'
            
        return None
        
    def _collect_technologies(self, headers: Dict, body: str) -> List[str]:
        """Collect detected technologies"""
        techs = []
        
        # From headers
        if 'x-powered-by' in headers:
            techs.append(headers['x-powered-by'])
        if 'server' in headers:
            techs.append(headers['server'])
            
        # JavaScript libraries
        js_libs = {
            'jquery': r'jquery[.-]?(\d+\.[\d.]+)?\.js',
            'react': r'react[.-]?(\d+\.[\d.]+)?\.js',
            'vue': r'vue[.-]?(\d+\.[\d.]+)?\.js',
            'angular': r'angular[.-]?(\d+\.[\d.]+)?\.js',
            'bootstrap': r'bootstrap[.-]?(\d+\.[\d.]+)?\.js',
        }
        
        for lib, pattern in js_libs.items():
            if re.search(pattern, body, re.IGNORECASE):
                techs.append(lib)
                
        return list(set(techs))


class ServiceFingerprint:
    """Service version fingerprinting"""
    
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        
    async def fingerprint(self, port: int) -> Dict[str, Any]:
        """Fingerprint service on port"""
        result = {'port': port, 'service': None, 'version': None, 'banner': None}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            # Read banner
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2)
                if data:
                    result['banner'] = data.decode('utf-8', errors='ignore')
            except asyncio.TimeoutError:
                # Send probe
                writer.write(b'\r\n')
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2)
                    if data:
                        result['banner'] = data.decode('utf-8', errors='ignore')
                except asyncio.TimeoutError:
                    pass
                    
            writer.close()
            
            # Parse banner
            if result['banner']:
                result['service'], result['version'] = self._parse_banner(result['banner'])
                
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def _parse_banner(self, banner: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse service banner"""
        patterns = {
            'ssh': (r'SSH-[\d.]+-(\S+)', 'ssh'),
            'ftp': (r'220[- ](.+)', 'ftp'),
            'smtp': (r'220[- ](.+)', 'smtp'),
            'http': (r'HTTP/[\d.]+\s+\d+', 'http'),
            'mysql': (r'mysql', 'mysql'),
            'redis': (r'redis_version:(\S+)', 'redis'),
        }
        
        for service, (pattern, name) in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                return name, version
                
        return None, None


class TLSFingerprint:
    """
    TLS/SSL Fingerprinting
    
    Analyzes TLS configuration:
    - Supported protocols
    - Cipher suites
    - Certificate info
    """
    
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
        
    async def fingerprint(self) -> Dict[str, Any]:
        """Perform TLS fingerprinting"""
        result = {
            'protocols': [],
            'cipher': None,
            'certificate': {},
            'ja3': None,
        }
        
        # Test different TLS versions
        protocols = [
            ('TLSv1.3', ssl.TLSVersion.TLSv1_3),
            ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
            ('TLSv1.0', ssl.TLSVersion.TLSv1),
        ]
        
        for name, version in protocols:
            if await self._test_protocol(version):
                result['protocols'].append(name)
                
        # Get certificate info
        cert_info = await self._get_certificate()
        if cert_info:
            result['certificate'] = cert_info
            result['cipher'] = cert_info.get('cipher')
            
        return result
        
    async def _test_protocol(self, version) -> bool:
        """Test if protocol version is supported"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, self.port, ssl=ctx),
                timeout=5
            )
            writer.close()
            return True
        except Exception:
            return False
            
    async def _get_certificate(self) -> Optional[Dict[str, Any]]:
        """Get certificate information"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.open_connection(
                self.target, self.port, ssl=ctx
            )
            
            ssl_obj = writer.get_extra_info('ssl_object')
            cert = ssl_obj.getpeercert(binary_form=False)
            cipher = ssl_obj.cipher()
            
            writer.close()
            
            result = {
                'subject': dict(x[0] for x in cert.get('subject', [])) if cert else {},
                'issuer': dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                'not_before': cert.get('notBefore') if cert else None,
                'not_after': cert.get('notAfter') if cert else None,
                'cipher': cipher[0] if cipher else None,
                'cipher_bits': cipher[2] if cipher else None,
            }
            
            return result
            
        except Exception as e:
            logger.debug(f"Certificate error: {e}")
            return None


class HTTPFingerprint:
    """HTTP-specific fingerprinting"""
    
    def __init__(self, target: str, port: int = 80, ssl: bool = False):
        self.target = target
        self.port = port
        self.use_ssl = ssl
        
    async def fingerprint(self) -> Dict[str, Any]:
        """Perform HTTP fingerprinting"""
        result = {
            'methods': [],
            'headers': {},
            'security_headers': {},
            'cookies': [],
        }
        
        # Test HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE']
        for method in methods:
            if await self._test_method(method):
                result['methods'].append(method)
                
        # Get headers
        headers = await self._get_headers()
        result['headers'] = headers
        
        # Check security headers
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
        ]
        
        for header in security_headers:
            if header in headers:
                result['security_headers'][header] = headers[header]
                
        return result
        
    async def _test_method(self, method: str) -> bool:
        """Test if HTTP method is allowed"""
        try:
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(
                    self.target, self.port, ssl=ctx
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.target, self.port
                )
                
            request = f"{method} / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            
            # Check if method is allowed (not 405)
            if b'405' not in response[:50]:
                return True
                
        except Exception:
            pass
            
        return False
        
    async def _get_headers(self) -> Dict[str, str]:
        """Get HTTP response headers"""
        try:
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(
                    self.target, self.port, ssl=ctx
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.target, self.port
                )
                
            request = f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
            
            headers = {}
            for line in response.decode('utf-8', errors='ignore').split('\r\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.lower().strip()] = value.strip()
                    
            return headers
            
        except Exception:
            return {}
