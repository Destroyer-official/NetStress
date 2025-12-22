"""
Port Scanner Module

Implements various port scanning techniques:
- TCP Connect scan
- SYN scan (requires raw sockets)
- UDP scan
- Service version detection

Enhanced with Rust pnet integration for high-performance scanning.
"""

import asyncio
import socket
import struct
import time
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum
import logging

# Import Rust engine for high-performance scanning
try:
    from ..native_engine import RustScanner
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    RustScanner = None

logger = logging.getLogger(__name__)


class PortState(Enum):
    """Port state enumeration"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


@dataclass
class ScanResult:
    """Result of a port scan"""
    port: int
    state: PortState
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    response_time: float = 0.0


@dataclass
class ScanConfig:
    """Configuration for port scanning"""
    target: str
    ports: List[int] = field(default_factory=lambda: list(range(1, 1025)))
    timeout: float = 2.0
    max_concurrent: int = 100
    retries: int = 1
    randomize: bool = True


# Common service ports
COMMON_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
    139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
    993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3306: 'mysql',
    3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
    6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
    27017: 'mongodb', 11211: 'memcached',
}


class PortScanner(ABC):
    """Base class for port scanners"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: Dict[int, ScanResult] = {}
        self._running = False
        
    @abstractmethod
    async def scan_port(self, port: int) -> ScanResult:
        """Scan a single port"""
        pass
    
    async def scan(self) -> Dict[int, ScanResult]:
        """Scan all configured ports"""
        self._running = True
        self.results = {}
        
        ports = self.config.ports.copy()
        if self.config.randomize:
            random.shuffle(ports)
            
        logger.info(f"Scanning {self.config.target} ({len(ports)} ports)")
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        async def scan_with_semaphore(port: int):
            async with semaphore:
                if not self._running:
                    return
                result = await self.scan_port(port)
                self.results[port] = result
                
        tasks = [scan_with_semaphore(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self._running = False
        return self.results
    
    async def stop(self):
        """Stop scanning"""
        self._running = False
        
    def get_open_ports(self) -> List[int]:
        """Get list of open ports"""
        return [port for port, result in self.results.items() 
                if result.state == PortState.OPEN]
                
    def get_summary(self) -> Dict[str, Any]:
        """Get scan summary"""
        states = {}
        for result in self.results.values():
            state = result.state.value
            states[state] = states.get(state, 0) + 1
            
        return {
            'target': self.config.target,
            'ports_scanned': len(self.results),
            'states': states,
            'open_ports': self.get_open_ports(),
        }


class TCPScanner(PortScanner):
    """TCP Connect Scanner - Full TCP handshake"""
    
    async def scan_port(self, port: int) -> ScanResult:
        """Scan port using TCP connect"""
        start_time = time.monotonic()
        
        for attempt in range(self.config.retries + 1):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.target, port),
                    timeout=self.config.timeout
                )
                
                response_time = time.monotonic() - start_time
                
                # Try to grab banner
                banner = None
                try:
                    writer.write(b'\r\n')
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                    
                writer.close()
                await writer.wait_closed()
                
                return ScanResult(
                    port=port,
                    state=PortState.OPEN,
                    service=COMMON_PORTS.get(port),
                    banner=banner,
                    response_time=response_time
                )
                
            except asyncio.TimeoutError:
                continue
            except ConnectionRefusedError:
                return ScanResult(port=port, state=PortState.CLOSED)
            except Exception:
                continue
                
        return ScanResult(port=port, state=PortState.FILTERED)


class ConnectScanner(TCPScanner):
    """Alias for TCP Connect Scanner"""
    pass


class UDPScanner(PortScanner):
    """UDP Scanner"""
    
    async def scan_port(self, port: int) -> ScanResult:
        """Scan port using UDP"""
        start_time = time.monotonic()
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.settimeout(self.config.timeout)
            
            # Send probe
            probe = self._get_probe(port)
            sock.sendto(probe, (self.config.target, port))
            
            # Wait for response
            try:
                loop = asyncio.get_event_loop()
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 1024),
                    timeout=self.config.timeout
                )
                
                response_time = time.monotonic() - start_time
                
                return ScanResult(
                    port=port,
                    state=PortState.OPEN,
                    service=COMMON_PORTS.get(port),
                    banner=data.decode('utf-8', errors='ignore')[:100] if data else None,
                    response_time=response_time
                )
                
            except asyncio.TimeoutError:
                # No response - could be open or filtered
                return ScanResult(port=port, state=PortState.OPEN_FILTERED)
                
        except Exception:
            return ScanResult(port=port, state=PortState.UNKNOWN)
        finally:
            try:
                sock.close()
            except Exception:
                pass
                
    def _get_probe(self, port: int) -> bytes:
        """Get appropriate probe for port"""
        probes = {
            53: b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS
            123: b'\x1b' + b'\x00' * 47,  # NTP
            161: b'\x30\x26\x02\x01\x01\x04\x06public',  # SNMP
            1900: b'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\n\r\n',  # SSDP
        }
        return probes.get(port, b'\x00')


class SYNScanner(PortScanner):
    """
    SYN Scanner - Half-open scanning
    
    Fast SYN scan with raw sockets for efficient port scanning.
    Uses Rust pnet for high-performance packet crafting when available.
    Falls back to raw sockets or TCP connect if Rust unavailable.
    
    Requirements: 11.1, 21.1 - Fast SYN scan with raw sockets, port range configuration
    """
    
    def __init__(self, config: ScanConfig, detect_versions: bool = False):
        super().__init__(config)
        self._rust_available = RUST_AVAILABLE
        self._raw_available = self._check_raw_sockets() if not self._rust_available else False
        self._detect_versions = detect_versions
        self._service_detector = None
        if detect_versions:
            self._service_detector = ServiceDetector(config.target, config.timeout)
        
    def _check_raw_sockets(self) -> bool:
        """Check if raw sockets are available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.close()
            return True
        except (PermissionError, OSError):
            return False
            
    async def scan_port(self, port: int) -> ScanResult:
        """
        Scan port using SYN packets with optional service version detection.
        
        Requirements: 11.1, 21.1 - Fast SYN scan with service version detection
        """
        # Use Rust pnet for high-performance scanning (Requirement 1.1)
        if self._rust_available:
            result = await self._rust_syn_scan(port)
        elif self._raw_available:
            result = await self._raw_syn_scan(port)
        else:
            # Fall back to TCP connect
            scanner = TCPScanner(ScanConfig(
                target=self.config.target,
                ports=[port],
                timeout=self.config.timeout
            ))
            result = await scanner.scan_port(port)
        
        # Perform service version detection if enabled and port is open
        if self._detect_versions and result.state == PortState.OPEN and self._service_detector:
            try:
                service_info = await self._service_detector.detect(port, result.service)
                result.service = service_info.get('service', result.service)
                result.version = service_info.get('version')
                if not result.banner and service_info.get('banner'):
                    result.banner = service_info['banner']
            except Exception as e:
                logger.debug(f"Service detection failed for port {port}: {e}")
        
        return result
            
    async def _rust_syn_scan(self, port: int) -> ScanResult:
        """Use Rust pnet for SYN scanning"""
        start_time = time.monotonic()
        
        try:
            # Create Rust scanner instance
            rust_scanner = RustScanner({
                'target': self.config.target,
                'port': port,
                'timeout': self.config.timeout,
                'scan_type': 'syn'
            })
            
            # Execute scan using Rust pnet
            result = await asyncio.get_event_loop().run_in_executor(
                None, rust_scanner.scan_port
            )
            
            response_time = time.monotonic() - start_time
            
            # Convert Rust result to Python ScanResult
            if result['state'] == 'open':
                state = PortState.OPEN
            elif result['state'] == 'closed':
                state = PortState.CLOSED
            elif result['state'] == 'filtered':
                state = PortState.FILTERED
            else:
                state = PortState.UNKNOWN
                
            return ScanResult(
                port=port,
                state=state,
                service=COMMON_PORTS.get(port),
                response_time=response_time
            )
            
        except Exception as e:
            logger.debug(f"Rust SYN scan error on port {port}: {e}")
            return ScanResult(port=port, state=PortState.UNKNOWN)
            
    async def _raw_syn_scan(self, port: int) -> ScanResult:
        """Raw socket SYN scan implementation (fallback)"""
        start_time = time.monotonic()
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setblocking(False)
            
            # Build SYN packet
            src_port = random.randint(1024, 65535)
            packet = self._build_syn_packet(src_port, port)
            
            # Send packet
            sock.sendto(packet, (self.config.target, 0))
            
            # Wait for response
            loop = asyncio.get_event_loop()
            try:
                response = await asyncio.wait_for(
                    loop.sock_recv(sock, 1024),
                    timeout=self.config.timeout
                )
                
                # Parse response
                if len(response) >= 40:
                    tcp_header = response[20:40]
                    flags = tcp_header[13]
                    
                    if flags & 0x12 == 0x12:  # SYN-ACK
                        return ScanResult(
                            port=port,
                            state=PortState.OPEN,
                            service=COMMON_PORTS.get(port),
                            response_time=time.monotonic() - start_time
                        )
                    elif flags & 0x04:  # RST
                        return ScanResult(port=port, state=PortState.CLOSED)
                        
            except asyncio.TimeoutError:
                return ScanResult(port=port, state=PortState.FILTERED)
                
        except Exception as e:
            logger.debug(f"Raw SYN scan error on port {port}: {e}")
            return ScanResult(port=port, state=PortState.UNKNOWN)
        finally:
            try:
                sock.close()
            except Exception:
                pass
                
        return ScanResult(port=port, state=PortState.UNKNOWN)
        
    def _build_syn_packet(self, src_port: int, dst_port: int) -> bytes:
        """Build a TCP SYN packet"""
        # IP header
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            0x45,  # Version + IHL
            0,     # TOS
            40,    # Total length
            random.randint(1, 65535),  # ID
            0,     # Flags + Fragment offset
            64,    # TTL
            socket.IPPROTO_TCP,  # Protocol
            0,     # Checksum (will be filled by kernel)
            socket.inet_aton('0.0.0.0'),  # Source (will be filled)
            socket.inet_aton(self.config.target)  # Destination
        )
        
        # TCP header
        seq = random.randint(0, 2**32 - 1)
        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port,  # Source port
            dst_port,  # Destination port
            seq,       # Sequence number
            0,         # Acknowledgment number
            0x50,      # Data offset (5 words)
            0x02,      # Flags (SYN)
            65535,     # Window size
            0,         # Checksum (calculated below)
            0          # Urgent pointer
        )
        
        return ip_header + tcp_header


class RustPortScanner(PortScanner):
    """
    High-performance port scanner using Rust pnet library.
    
    Provides significant performance improvements over Python socket scanning
    by leveraging compiled Rust code and the pnet packet manipulation library.
    
    Requirements: 1.1 - Use Rust pnet for scanning
    """
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        if not RUST_AVAILABLE:
            raise RuntimeError("Rust scanner not available - falling back to Python implementation")
            
    async def scan_port(self, port: int) -> ScanResult:
        """Scan port using Rust pnet"""
        start_time = time.monotonic()
        
        try:
            # Create Rust scanner instance
            rust_scanner = RustScanner({
                'target': self.config.target,
                'port': port,
                'timeout': self.config.timeout,
                'scan_type': 'connect'  # Default to connect scan
            })
            
            # Execute scan using Rust
            result = await asyncio.get_event_loop().run_in_executor(
                None, rust_scanner.scan_port
            )
            
            response_time = time.monotonic() - start_time
            
            # Convert Rust result to Python ScanResult
            if result['state'] == 'open':
                state = PortState.OPEN
            elif result['state'] == 'closed':
                state = PortState.CLOSED
            elif result['state'] == 'filtered':
                state = PortState.FILTERED
            else:
                state = PortState.UNKNOWN
                
            return ScanResult(
                port=port,
                state=state,
                service=COMMON_PORTS.get(port),
                banner=result.get('banner'),
                response_time=response_time
            )
            
        except Exception as e:
            logger.debug(f"Rust scan error on port {port}: {e}")
            return ScanResult(port=port, state=PortState.UNKNOWN)
            
    async def scan(self) -> Dict[int, ScanResult]:
        """Batch scan using Rust for maximum performance"""
        self._running = True
        self.results = {}
        
        ports = self.config.ports.copy()
        if self.config.randomize:
            random.shuffle(ports)
            
        logger.info(f"Rust scanning {self.config.target} ({len(ports)} ports)")
        
        try:
            # Create Rust batch scanner
            rust_scanner = RustScanner({
                'target': self.config.target,
                'ports': ports,
                'timeout': self.config.timeout,
                'max_concurrent': self.config.max_concurrent,
                'scan_type': 'batch'
            })
            
            # Execute batch scan
            results = await asyncio.get_event_loop().run_in_executor(
                None, rust_scanner.batch_scan
            )
            
            # Convert results
            for port_result in results:
                port = port_result['port']
                
                if port_result['state'] == 'open':
                    state = PortState.OPEN
                elif port_result['state'] == 'closed':
                    state = PortState.CLOSED
                elif port_result['state'] == 'filtered':
                    state = PortState.FILTERED
                else:
                    state = PortState.UNKNOWN
                    
                self.results[port] = ScanResult(
                    port=port,
                    state=state,
                    service=COMMON_PORTS.get(port),
                    banner=port_result.get('banner'),
                    response_time=port_result.get('response_time', 0.0)
                )
                
        except Exception as e:
            logger.error(f"Rust batch scan failed: {e}")
            # Fall back to individual scans
            return await super().scan()
            
        self._running = False
        return self.results


class BannerGrabber:
    """
    Banner Grabbing Module
    
    Collects service banners for identification and fingerprinting.
    
    Requirements: 11.2 - TCP banner collection, HTTP server identification, TLS certificate analysis
    """
    
    # Service-specific probes
    PROBES = {
        'http': b'GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n',
        'https': b'GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n',
        'ftp': b'',  # FTP sends banner on connect
        'ssh': b'',  # SSH sends banner on connect
        'smtp': b'EHLO banner-grabber\r\n',
        'pop3': b'',  # POP3 sends banner on connect
        'imap': b'',  # IMAP sends banner on connect
        'mysql': b'',  # MySQL sends banner on connect
        'redis': b'INFO\r\n',
        'mongodb': b'\x3a\x00\x00\x00',  # MongoDB wire protocol
        'telnet': b'',  # Telnet sends banner on connect
        'vnc': b'RFB 003.008\n',  # VNC handshake
    }
    
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        
    async def grab_banner(self, port: int, service_hint: Optional[str] = None) -> Dict[str, Any]:
        """
        Grab banner from a port.
        
        Requirements: 11.2 - TCP banner collection
        
        Args:
            port: Port number to grab banner from
            service_hint: Optional service name hint
            
        Returns:
            Dictionary with banner information
        """
        result = {
            'port': port,
            'service': service_hint or COMMON_PORTS.get(port, 'unknown'),
            'banner': None,
            'raw_banner': None,
            'server_header': None,
            'tls_info': None,
        }
        
        # Special handling for HTTPS/TLS ports
        if port == 443 or (service_hint and 'https' in service_hint.lower()):
            return await self._grab_https_banner(port, result)
        
        # Standard TCP banner grab
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            # Get probe for service
            probe = self.PROBES.get(result['service'], b'\r\n')
            if isinstance(probe, bytes) and b'{host}' in probe:
                probe = probe.replace(b'{host}', self.target.encode())
            
            # Send probe if needed
            if probe:
                writer.write(probe)
                await writer.drain()
                
            # Read response
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                if data:
                    result['raw_banner'] = data
                    result['banner'] = data.decode('utf-8', errors='ignore')[:1000]
                    
                    # Extract server header for HTTP services
                    if result['service'] in ('http', 'https'):
                        result['server_header'] = self._extract_server_header(result['banner'])
                        
            except asyncio.TimeoutError:
                pass
                
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Banner grab failed for {self.target}:{port}: {e}")
            
        return result
    
    async def _grab_https_banner(self, port: int, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Grab banner from HTTPS port with TLS certificate analysis.
        
        Requirements: 11.2 - HTTP server identification, TLS certificate analysis
        """
        import ssl as ssl_module
        
        try:
            # Create SSL context
            ctx = ssl_module.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_module.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port, ssl=ctx),
                timeout=self.timeout
            )
            
            # Get TLS certificate info
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                cert = ssl_obj.getpeercert(binary_form=False)
                cipher = ssl_obj.cipher()
                
                result['tls_info'] = {
                    'protocol': ssl_obj.version(),
                    'cipher': cipher[0] if cipher else None,
                    'cipher_bits': cipher[2] if cipher else None,
                    'certificate': {
                        'subject': dict(x[0] for x in cert.get('subject', [])) if cert else {},
                        'issuer': dict(x[0] for x in cert.get('issuer', [])) if cert else {},
                        'not_before': cert.get('notBefore') if cert else None,
                        'not_after': cert.get('notAfter') if cert else None,
                        'serial_number': cert.get('serialNumber') if cert else None,
                    }
                }
            
            # Send HTTP request
            request = f"GET / HTTP/1.0\r\nHost: {self.target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                if data:
                    result['raw_banner'] = data
                    result['banner'] = data.decode('utf-8', errors='ignore')[:1000]
                    result['server_header'] = self._extract_server_header(result['banner'])
            except asyncio.TimeoutError:
                pass
                
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"HTTPS banner grab failed for {self.target}:{port}: {e}")
            
        return result
    
    def _extract_server_header(self, banner: str) -> Optional[str]:
        """
        Extract Server header from HTTP response.
        
        Requirements: 11.2 - HTTP server identification
        """
        import re
        match = re.search(r'Server:\s*(.+)', banner, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    async def grab_multiple(self, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """
        Grab banners from multiple ports concurrently.
        
        Args:
            ports: List of ports to grab banners from
            
        Returns:
            Dictionary mapping port -> banner info
        """
        tasks = [self.grab_banner(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        banner_dict = {}
        for result in results:
            if isinstance(result, dict) and 'port' in result:
                banner_dict[result['port']] = result
                
        return banner_dict


class ServiceDetector:
    """
    Service Version Detection
    
    Probes open ports to identify service versions.
    """
    
    # Service probes
    PROBES = {
        'http': b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        'https': b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        'ftp': b'',  # FTP sends banner on connect
        'ssh': b'',  # SSH sends banner on connect
        'smtp': b'EHLO test\r\n',
        'pop3': b'',  # POP3 sends banner on connect
        'imap': b'',  # IMAP sends banner on connect
        'mysql': b'',  # MySQL sends banner on connect
        'redis': b'INFO\r\n',
        'mongodb': b'\x3a\x00\x00\x00',  # MongoDB wire protocol
    }
    
    # Version patterns
    VERSION_PATTERNS = {
        'ssh': r'SSH-[\d.]+-(\S+)',
        'http': r'Server:\s*(.+)',
        'ftp': r'220[- ](.+)',
        'smtp': r'220[- ](.+)',
        'mysql': r'(\d+\.\d+\.\d+)',
    }
    
    def __init__(self, target: str, timeout: float = 5.0):
        self.target = target
        self.timeout = timeout
        
    async def detect(self, port: int, service_hint: Optional[str] = None) -> Dict[str, Any]:
        """Detect service on port"""
        result = {
            'port': port,
            'service': service_hint or COMMON_PORTS.get(port, 'unknown'),
            'version': None,
            'banner': None,
            'extra_info': {}
        }
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            # Get probe for service
            probe = self.PROBES.get(result['service'], b'\r\n')
            
            # Send probe
            if probe:
                writer.write(probe)
                await writer.drain()
                
            # Read response
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                if data:
                    result['banner'] = data.decode('utf-8', errors='ignore')[:500]
                    
                    # Try to extract version
                    import re
                    pattern = self.VERSION_PATTERNS.get(result['service'])
                    if pattern:
                        match = re.search(pattern, result['banner'], re.IGNORECASE)
                        if match:
                            result['version'] = match.group(1).strip()
                            
            except asyncio.TimeoutError:
                pass
                
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    async def detect_all(self, ports: List[int]) -> List[Dict[str, Any]]:
        """Detect services on multiple ports"""
        tasks = [self.detect(port) for port in ports]
        return await asyncio.gather(*tasks, return_exceptions=True)


# Scanner factory functions

def create_scanner(scan_type: str, config: ScanConfig) -> PortScanner:
    """
    Create the best available scanner for the given type.
    
    Automatically selects Rust-based scanners when available for better performance.
    
    Args:
        scan_type: Type of scan ('tcp', 'syn', 'udp', 'rust')
        config: Scanner configuration
        
    Returns:
        Appropriate scanner instance
        
    Requirements: 1.1 - Use Rust pnet for scanning
    """
    scan_type = scan_type.lower()
    
    if scan_type == 'rust' and RUST_AVAILABLE:
        return RustPortScanner(config)
    elif scan_type == 'syn':
        return SYNScanner(config)  # Will use Rust if available
    elif scan_type == 'udp':
        return UDPScanner(config)
    elif scan_type in ('tcp', 'connect'):
        return TCPScanner(config)
    else:
        # Default to best available scanner
        if RUST_AVAILABLE:
            logger.info("Using Rust scanner for optimal performance")
            return RustPortScanner(config)
        else:
            logger.info("Rust scanner unavailable, using Python TCP scanner")
            return TCPScanner(config)


async def quick_scan(target: str, ports: List[int] = None, 
                    scan_type: str = 'auto', timeout: float = 2.0,
                    max_concurrent: int = 100) -> Dict[int, ScanResult]:
    """
    Quick port scan with automatic scanner selection.
    
    Args:
        target: Target IP or hostname
        ports: List of ports to scan (default: common ports)
        scan_type: Scanner type ('auto', 'rust', 'syn', 'tcp', 'udp')
        timeout: Scan timeout per port
        max_concurrent: Maximum concurrent scans
        
    Returns:
        Dictionary of port -> ScanResult
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())
        
    config = ScanConfig(
        target=target,
        ports=ports,
        timeout=timeout,
        max_concurrent=max_concurrent
    )
    
    scanner = create_scanner(scan_type, config)
    return await scanner.scan()


async def syn_scan_with_detection(target: str, ports: List[int] = None,
                                  timeout: float = 2.0, max_concurrent: int = 100,
                                  detect_versions: bool = True) -> Dict[int, ScanResult]:
    """
    Fast SYN scan with service version detection.
    
    Requirements: 11.1, 21.1 - Fast SYN scan with port range configuration and service version detection
    
    Args:
        target: Target IP or hostname
        ports: List of ports to scan (default: common ports)
        timeout: Scan timeout per port
        max_concurrent: Maximum concurrent scans
        detect_versions: Enable service version detection
        
    Returns:
        Dictionary of port -> ScanResult with service versions
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())
        
    config = ScanConfig(
        target=target,
        ports=ports,
        timeout=timeout,
        max_concurrent=max_concurrent
    )
    
    scanner = SYNScanner(config, detect_versions=detect_versions)
    return await scanner.scan()
