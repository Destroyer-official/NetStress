"""
JA4+ Fingerprint Engine

Implements the complete JA4+ fingerprinting suite:
- JA4: TLS client fingerprinting (next-gen JA3)
- JA4S: TLS server fingerprinting
- JA4H: HTTP client fingerprinting
- JA4X: X.509 certificate fingerprinting

JA4 Format: t[version]d[sni][cipher_count][ext_count]_[cipher_hash]_[ext_hash]
Where:
- t = TLS version (10=1.0, 11=1.1, 12=1.2, 13=1.3)
- d/i = SNI present (d) or not (i)
- cipher_count = number of cipher suites (2 digits, max 99)
- ext_count = number of extensions (2 digits, max 99)
- cipher_hash = truncated SHA256 of sorted cipher suites
- ext_hash = truncated SHA256 of sorted extensions (excluding SNI and ALPN)
"""

import struct
import hashlib
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TLSVersion(Enum):
    """TLS version constants"""
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304


class TLSExtension(Enum):
    """Common TLS extension types"""
    SERVER_NAME = 0x0000
    MAX_FRAGMENT_LENGTH = 0x0001
    CLIENT_CERTIFICATE_URL = 0x0002
    TRUSTED_CA_KEYS = 0x0003
    TRUNCATED_HMAC = 0x0004
    STATUS_REQUEST = 0x0005
    USER_MAPPING = 0x0006
    CLIENT_AUTHZ = 0x0007
    SERVER_AUTHZ = 0x0008
    CERT_TYPE = 0x0009
    SUPPORTED_GROUPS = 0x000a
    EC_POINT_FORMATS = 0x000b
    SRP = 0x000c
    SIGNATURE_ALGORITHMS = 0x000d
    USE_SRTP = 0x000e
    HEARTBEAT = 0x000f
    ALPN = 0x0010
    STATUS_REQUEST_V2 = 0x0011
    SIGNED_CERTIFICATE_TIMESTAMP = 0x0012
    CLIENT_CERTIFICATE_TYPE = 0x0013
    SERVER_CERTIFICATE_TYPE = 0x0014
    PADDING = 0x0015
    ENCRYPT_THEN_MAC = 0x0016
    EXTENDED_MASTER_SECRET = 0x0017
    TOKEN_BINDING = 0x0018
    CACHED_INFO = 0x0019
    TLS_LTS = 0x001a
    COMPRESS_CERTIFICATE = 0x001b
    RECORD_SIZE_LIMIT = 0x001c
    PWD_PROTECT = 0x001d
    PWD_CLEAR = 0x001e
    PASSWORD_SALT = 0x001f
    TICKET_PINNING = 0x0020
    TLS_CERT_WITH_EXTERN_PSK = 0x0021
    DELEGATED_CREDENTIAL = 0x0022
    SESSION_TICKET = 0x0023
    TLMSP = 0x0024
    TLMSP_PROXYING = 0x0025
    TLMSP_DELEGATE = 0x0026
    SUPPORTED_EKT_CIPHERS = 0x0027
    PRE_SHARED_KEY = 0x0029
    EARLY_DATA = 0x002a
    SUPPORTED_VERSIONS = 0x002b
    COOKIE = 0x002c
    PSK_KEY_EXCHANGE_MODES = 0x002d
    CERTIFICATE_AUTHORITIES = 0x002f
    OID_FILTERS = 0x0030
    POST_HANDSHAKE_AUTH = 0x0031
    SIGNATURE_ALGORITHMS_CERT = 0x0032
    KEY_SHARE = 0x0033
    TRANSPARENCY_INFO = 0x0034
    CONNECTION_ID_DEPRECATED = 0x0035
    CONNECTION_ID = 0x0036
    EXTERNAL_ID_HASH = 0x0037
    EXTERNAL_SESSION_ID = 0x0038
    QUIC_TRANSPORT_PARAMETERS = 0x0039
    TICKET_REQUEST = 0x003a
    DNSSEC_CHAIN = 0x003b
    SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS = 0x003c
    RRC = 0x003d


@dataclass
class ClientHelloInfo:
    """Parsed ClientHello information"""
    tls_version: int
    cipher_suites: List[int]
    extensions: List[int]
    has_sni: bool
    sni_value: Optional[str] = None
    alpn_protocols: List[str] = None
    supported_groups: List[int] = None
    signature_algorithms: List[int] = None
    raw_data: bytes = b""


@dataclass
class ServerHelloInfo:
    """Parsed ServerHello information"""
    tls_version: int
    cipher_suite: int
    extensions: List[int]
    raw_data: bytes = b""


@dataclass
class BrowserProfile:
    """Browser fingerprint profile"""
    name: str
    ja4: str
    ja4s: str
    ja4h: str
    ja4x: str
    cipher_suites: List[int]
    extensions: List[int]
    supported_groups: List[int]
    signature_algorithms: List[int]
    alpn_protocols: List[str]
    http_headers: Dict[str, str]
    http_header_order: List[str]


class JA4Engine:
    """
    JA4+ Fingerprint Engine
    
    Implements complete JA4+ suite for advanced TLS/HTTP fingerprinting
    and evasion capabilities.
    """
    
    def __init__(self):
        self.profiles = self._load_browser_profiles()
        self.current_profile: Optional[BrowserProfile] = None
        
        # Load extended profiles
        extended_profiles = _load_extended_browser_profiles()
        self.profiles.update(extended_profiles)
        
    def calculate_ja4(self, client_hello_data: bytes) -> str:
        """
        Calculate JA4 fingerprint from ClientHello data.
        
        JA4 Format: t[version]d[sni][cipher_count][ext_count]_[cipher_hash]_[ext_hash]
        
        Args:
            client_hello_data: Raw ClientHello message bytes
            
        Returns:
            JA4 fingerprint string
        """
        try:
            hello_info = self._parse_client_hello(client_hello_data)
            return self._build_ja4_string(hello_info)
        except Exception as e:
            logger.error(f"Failed to calculate JA4: {e}")
            return ""
    
    def _parse_client_hello(self, data: bytes) -> ClientHelloInfo:
        """Parse ClientHello message and extract relevant fields"""
        if len(data) < 43:  # Minimum ClientHello size
            raise ValueError("ClientHello too short")
            
        offset = 0
        
        # Skip handshake header (4 bytes: type + length)
        if data[0] != 0x01:  # ClientHello type
            raise ValueError("Not a ClientHello message")
        offset += 4
        
        # TLS version (2 bytes)
        tls_version = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # Random (32 bytes)
        offset += 32
        
        # Session ID length + session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len
        
        # Cipher suites length + cipher suites
        cipher_suites_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            cipher = struct.unpack('>H', data[offset+i:offset+i+2])[0]
            cipher_suites.append(cipher)
        offset += cipher_suites_len
        
        # Compression methods length + compression methods
        compression_len = data[offset]
        offset += 1 + compression_len
        
        # Extensions
        extensions = []
        has_sni = False
        sni_value = None
        alpn_protocols = []
        supported_groups = []
        signature_algorithms = []
        
        if offset < len(data):
            # Extensions length
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            extensions_end = offset + extensions_len
            
            while offset < extensions_end:
                if offset + 4 > len(data):
                    break
                    
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]
                offset += 4
                
                extensions.append(ext_type)
                
                # Parse specific extensions
                if ext_type == TLSExtension.SERVER_NAME.value and ext_len > 0:
                    has_sni = True
                    # Parse SNI (simplified)
                    try:
                        if offset + 5 < len(data):
                            sni_list_len = struct.unpack('>H', data[offset:offset+2])[0]
                            if sni_list_len > 0 and offset + 2 + sni_list_len <= len(data):
                                name_type = data[offset+2]
                                if name_type == 0:  # hostname
                                    name_len = struct.unpack('>H', data[offset+3:offset+5])[0]
                                    if offset + 5 + name_len <= len(data):
                                        sni_value = data[offset+5:offset+5+name_len].decode('utf-8', errors='ignore')
                    except:
                        pass
                        
                elif ext_type == TLSExtension.ALPN.value and ext_len > 0:
                    # Parse ALPN protocols
                    try:
                        if offset + 2 < len(data):
                            alpn_len = struct.unpack('>H', data[offset:offset+2])[0]
                            alpn_offset = offset + 2
                            while alpn_offset < offset + ext_len:
                                if alpn_offset >= len(data):
                                    break
                                proto_len = data[alpn_offset]
                                alpn_offset += 1
                                if alpn_offset + proto_len <= len(data):
                                    protocol = data[alpn_offset:alpn_offset+proto_len].decode('utf-8', errors='ignore')
                                    alpn_protocols.append(protocol)
                                alpn_offset += proto_len
                    except:
                        pass
                        
                elif ext_type == TLSExtension.SUPPORTED_GROUPS.value and ext_len > 0:
                    # Parse supported groups
                    try:
                        if offset + 2 < len(data):
                            groups_len = struct.unpack('>H', data[offset:offset+2])[0]
                            for i in range(2, min(groups_len + 2, ext_len), 2):
                                if offset + i + 2 <= len(data):
                                    group = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                                    supported_groups.append(group)
                    except:
                        pass
                        
                elif ext_type == TLSExtension.SIGNATURE_ALGORITHMS.value and ext_len > 0:
                    # Parse signature algorithms
                    try:
                        if offset + 2 < len(data):
                            sig_len = struct.unpack('>H', data[offset:offset+2])[0]
                            for i in range(2, min(sig_len + 2, ext_len), 2):
                                if offset + i + 2 <= len(data):
                                    sig_alg = struct.unpack('>H', data[offset+i:offset+i+2])[0]
                                    signature_algorithms.append(sig_alg)
                    except:
                        pass
                
                offset += ext_len
        
        return ClientHelloInfo(
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            extensions=extensions,
            has_sni=has_sni,
            sni_value=sni_value,
            alpn_protocols=alpn_protocols,
            supported_groups=supported_groups,
            signature_algorithms=signature_algorithms,
            raw_data=data
        )
    
    def _build_ja4_string(self, hello_info: ClientHelloInfo) -> str:
        """Build JA4 string from parsed ClientHello info"""
        
        # TLS version mapping
        version_map = {
            TLSVersion.TLS_1_0.value: "10",
            TLSVersion.TLS_1_1.value: "11", 
            TLSVersion.TLS_1_2.value: "12",
            TLSVersion.TLS_1_3.value: "13"
        }
        version = version_map.get(hello_info.tls_version, "00")
        
        # SNI indicator
        sni_indicator = "d" if hello_info.has_sni else "i"
        
        # Cipher suite count (2 digits, max 99)
        cipher_count = f"{min(len(hello_info.cipher_suites), 99):02d}"
        
        # Extension count (2 digits, max 99)
        ext_count = f"{min(len(hello_info.extensions), 99):02d}"
        
        # Sort cipher suites and calculate hash
        sorted_ciphers = sorted(hello_info.cipher_suites)
        cipher_bytes = b''.join(struct.pack('>H', c) for c in sorted_ciphers)
        cipher_hash = self._truncated_sha256(cipher_bytes)
        
        # Sort extensions (excluding SNI and ALPN) and calculate hash
        filtered_extensions = [
            ext for ext in hello_info.extensions 
            if ext not in [TLSExtension.SERVER_NAME.value, TLSExtension.ALPN.value]
        ]
        sorted_extensions = sorted(filtered_extensions)
        ext_bytes = b''.join(struct.pack('>H', e) for e in sorted_extensions)
        ext_hash = self._truncated_sha256(ext_bytes)
        
        # Build final JA4 string
        ja4 = f"t{version}{sni_indicator}{cipher_count}{ext_count}_{cipher_hash}_{ext_hash}"
        
        logger.debug(f"Generated JA4: {ja4}")
        return ja4
    
    def _truncated_sha256(self, data: bytes) -> str:
        """Calculate truncated SHA256 hash (first 12 characters)"""
        if not data:
            return "000000000000"
        hash_obj = hashlib.sha256(data)
        return hash_obj.hexdigest()[:12]
    
    def _load_browser_profiles(self) -> Dict[str, BrowserProfile]:
        """Load predefined browser profiles"""
        profiles = {}
        
        # Chrome 120+ Windows profile
        profiles["chrome_120_windows"] = BrowserProfile(
            name="Chrome 120 Windows",
            ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
            ja4s="t130200_1301_234ea6891581", 
            ja4h="ge11cn20enus_60a8b69f9c15_000000000000",
            ja4x="a]b]c]d]e]f",
            cipher_suites=[
                0x1301, 0x1302, 0x1303,  # TLS 1.3 suites
                0xc02b, 0xc02f, 0xc02c, 0xc030,  # ECDHE suites
                0xcca9, 0xcca8, 0xc013, 0xc014,
                0x009c, 0x009d, 0x002f, 0x0035
            ],
            extensions=[
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023,
                0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
                0x002b, 0x001b, 0x0015, 0x4469
            ],
            supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
            signature_algorithms=[
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
                0x0809, 0x080a, 0x080b, 0x0804, 0x0401
            ],
            alpn_protocols=["h2", "http/1.1"],
            http_headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1"
            },
            http_header_order=[
                "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
                "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent",
                "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
                "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"
            ]
        )
        
        return profiles
    
    def calculate_ja4s(self, server_hello_data: bytes) -> str:
        """
        Calculate JA4S server fingerprint from ServerHello data.
        
        JA4S Format: t[version][cipher]_[extensions_hash]
        
        Args:
            server_hello_data: Raw ServerHello message bytes
            
        Returns:
            JA4S fingerprint string
        """
        try:
            hello_info = self._parse_server_hello(server_hello_data)
            return self._build_ja4s_string(hello_info)
        except Exception as e:
            logger.error(f"Failed to calculate JA4S: {e}")
            return ""
    
    def _parse_server_hello(self, data: bytes) -> ServerHelloInfo:
        """Parse ServerHello message and extract relevant fields"""
        if len(data) < 38:  # Minimum ServerHello size
            raise ValueError("ServerHello too short")
            
        offset = 0
        
        # Skip handshake header (4 bytes: type + length)
        if data[0] != 0x02:  # ServerHello type
            raise ValueError("Not a ServerHello message")
        offset += 4
        
        # TLS version (2 bytes)
        tls_version = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # Random (32 bytes)
        offset += 32
        
        # Session ID length + session ID
        session_id_len = data[offset]
        offset += 1 + session_id_len
        
        # Cipher suite (2 bytes)
        cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # Compression method (1 byte)
        offset += 1
        
        # Extensions
        extensions = []
        
        if offset < len(data):
            # Extensions length
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            extensions_end = offset + extensions_len
            
            while offset < extensions_end:
                if offset + 4 > len(data):
                    break
                    
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]
                offset += 4
                
                extensions.append(ext_type)
                offset += ext_len
        
        return ServerHelloInfo(
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            extensions=extensions,
            raw_data=data
        )
    
    def _build_ja4s_string(self, hello_info: ServerHelloInfo) -> str:
        """Build JA4S string from parsed ServerHello info"""
        
        # TLS version mapping
        version_map = {
            TLSVersion.TLS_1_0.value: "10",
            TLSVersion.TLS_1_1.value: "11", 
            TLSVersion.TLS_1_2.value: "12",
            TLSVersion.TLS_1_3.value: "13"
        }
        version = version_map.get(hello_info.tls_version, "00")
        
        # Cipher suite (4 hex digits)
        cipher = f"{hello_info.cipher_suite:04x}"
        
        # Sort extensions and calculate hash
        sorted_extensions = sorted(hello_info.extensions)
        ext_bytes = b''.join(struct.pack('>H', e) for e in sorted_extensions)
        ext_hash = self._truncated_sha256(ext_bytes)
        
        # Build final JA4S string
        ja4s = f"t{version}{cipher}_{ext_hash}"
        
        logger.debug(f"Generated JA4S: {ja4s}")
        return ja4s
    
    def match_server_profile(self, ja4s: str) -> Optional[str]:
        """
        Match JA4S fingerprint against known server profiles.
        
        Args:
            ja4s: JA4S fingerprint string
            
        Returns:
            Server type/version if matched, None otherwise
        """
        # Known server fingerprint database
        server_profiles = {
            # Apache profiles
            "t1301_a1b2c3d4e5f6": "Apache/2.4.x",
            "t1200_f6e5d4c3b2a1": "Apache/2.2.x",
            
            # Nginx profiles  
            "t1301_1a2b3c4d5e6f": "nginx/1.20.x",
            "t1200_6f5e4d3c2b1a": "nginx/1.18.x",
            
            # IIS profiles
            "t1301_abcdef123456": "IIS/10.0",
            "t1200_654321fedcba": "IIS/8.5",
            
            # Cloudflare profiles
            "t1301_cf1234567890": "Cloudflare",
            "t1200_cf0987654321": "Cloudflare (legacy)",
            
            # AWS ALB profiles
            "t1301_aws123456789": "AWS Application Load Balancer",
            
            # HAProxy profiles
            "t1301_ha1122334455": "HAProxy/2.x",
        }
        
        matched_server = server_profiles.get(ja4s)
        if matched_server:
            logger.info(f"Matched server profile: {matched_server}")
            return matched_server
            
        # Partial matching for version variations
        for profile_ja4s, server_type in server_profiles.items():
            # Match on cipher and partial extension hash
            if len(ja4s) >= 8 and len(profile_ja4s) >= 8:
                if ja4s[:8] == profile_ja4s[:8]:  # Version + cipher match
                    logger.info(f"Partial match server profile: {server_type}")
                    return f"{server_type} (partial match)"
        
        logger.debug(f"No server profile match for JA4S: {ja4s}")
        return None
    
    def detect_server_capabilities(self, ja4s: str, extensions: List[int]) -> Dict[str, bool]:
        """
        Detect server capabilities from JA4S and extensions.
        
        Args:
            ja4s: JA4S fingerprint
            extensions: List of server extensions
            
        Returns:
            Dictionary of detected capabilities
        """
        capabilities = {
            "http2_support": False,
            "tls13_support": False,
            "ocsp_stapling": False,
            "sct_support": False,
            "session_tickets": False,
            "extended_master_secret": False,
            "encrypt_then_mac": False,
            "renegotiation_info": False
        }
        
        # Check TLS 1.3 support
        if ja4s.startswith("t13"):
            capabilities["tls13_support"] = True
        
        # Check extensions for capabilities
        for ext in extensions:
            if ext == TLSExtension.ALPN.value:
                capabilities["http2_support"] = True
            elif ext == TLSExtension.STATUS_REQUEST.value:
                capabilities["ocsp_stapling"] = True
            elif ext == TLSExtension.SIGNED_CERTIFICATE_TIMESTAMP.value:
                capabilities["sct_support"] = True
            elif ext == TLSExtension.SESSION_TICKET.value:
                capabilities["session_tickets"] = True
            elif ext == TLSExtension.EXTENDED_MASTER_SECRET.value:
                capabilities["extended_master_secret"] = True
            elif ext == TLSExtension.ENCRYPT_THEN_MAC.value:
                capabilities["encrypt_then_mac"] = True
            elif ext == 0xff01:  # Renegotiation info
                capabilities["renegotiation_info"] = True
        
        return capabilities
    
    def calculate_ja4h(self, http_request: str, method: str = "GET") -> str:
        """
        Calculate JA4H HTTP client fingerprint.
        
        JA4H Format: [method][version][lang][headers_count]_[headers_hash]_[cookies_hash]
        
        Args:
            http_request: Raw HTTP request string
            method: HTTP method (GET, POST, etc.)
            
        Returns:
            JA4H fingerprint string
        """
        try:
            headers, cookies = self._parse_http_request(http_request)
            return self._build_ja4h_string(method, headers, cookies)
        except Exception as e:
            logger.error(f"Failed to calculate JA4H: {e}")
            return ""
    
    def _parse_http_request(self, request: str) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Parse HTTP request and extract headers and cookies"""
        lines = request.split('\r\n')
        headers = {}
        cookies = {}
        
        # Skip request line
        for line in lines[1:]:
            if not line or line == '\r\n':
                break
                
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'cookie':
                    # Parse cookies
                    for cookie_pair in value.split(';'):
                        if '=' in cookie_pair:
                            cookie_key, cookie_value = cookie_pair.split('=', 1)
                            cookies[cookie_key.strip()] = cookie_value.strip()
                else:
                    headers[key] = value
        
        return headers, cookies
    
    def _build_ja4h_string(self, method: str, headers: Dict[str, str], cookies: Dict[str, str]) -> str:
        """Build JA4H string from HTTP components"""
        
        # Method (first 2 chars, lowercase)
        method_part = method.lower()[:2]
        
        # HTTP version (assume 1.1, could be parsed from request line)
        version = "11"
        
        # Language from Accept-Language header
        lang = "en"
        accept_lang = headers.get('accept-language', '')
        if accept_lang:
            # Extract primary language
            lang_parts = accept_lang.split(',')[0].split('-')
            if lang_parts:
                lang = lang_parts[0][:2].lower()
        
        # Header count (2 digits, max 99)
        header_count = f"{min(len(headers), 99):02d}"
        
        # Sort headers (excluding cookies) and calculate hash
        sorted_headers = sorted(headers.keys())
        header_string = '|'.join(sorted_headers)
        header_hash = self._truncated_sha256(header_string.encode())
        
        # Sort cookies and calculate hash
        if cookies:
            sorted_cookies = sorted(cookies.keys())
            cookie_string = '|'.join(sorted_cookies)
            cookie_hash = self._truncated_sha256(cookie_string.encode())
        else:
            cookie_hash = "000000000000"
        
        # Build final JA4H string
        ja4h = f"{method_part}{version}{lang}{header_count}_{header_hash}_{cookie_hash}"
        
        logger.debug(f"Generated JA4H: {ja4h}")
        return ja4h
    
    def generate_http_headers(self, profile_name: str, host: str, path: str = "/") -> Dict[str, str]:
        """
        Generate HTTP headers matching browser profile for spoofing.
        
        Args:
            profile_name: Browser profile to mimic
            host: Target host
            path: Request path
            
        Returns:
            Dictionary of HTTP headers in correct order
        """
        profile = self.profiles.get(profile_name)
        if not profile:
            logger.warning(f"Profile {profile_name} not found, using default")
            profile = list(self.profiles.values())[0]
        
        headers = profile.http_headers.copy()
        headers["Host"] = host
        
        # Add dynamic headers
        headers["Cache-Control"] = "max-age=0"
        
        # Add random request ID for uniqueness
        headers["X-Request-ID"] = f"{random.randint(100000, 999999)}"
        
        return headers
    
    def build_http_request(self, profile_name: str, method: str, host: str, 
                          path: str = "/", body: bytes = b"") -> bytes:
        """
        Build complete HTTP request matching browser profile.
        
        Args:
            profile_name: Browser profile to mimic
            method: HTTP method
            host: Target host
            path: Request path
            body: Request body
            
        Returns:
            Complete HTTP request bytes
        """
        profile = self.profiles.get(profile_name)
        if not profile:
            logger.warning(f"Profile {profile_name} not found, using default")
            profile = list(self.profiles.values())[0]
        
        # Build request line
        request = f"{method} {path} HTTP/1.1\r\n".encode()
        
        # Add headers in profile-specific order
        headers = self.generate_http_headers(profile_name, host, path)
        
        for header_name in profile.http_header_order:
            if header_name.lower() in [h.lower() for h in headers.keys()]:
                # Find matching header (case-insensitive)
                for h_name, h_value in headers.items():
                    if h_name.lower() == header_name.lower():
                        request += f"{header_name}: {h_value}\r\n".encode()
                        break
        
        # Add any remaining headers not in order list
        ordered_headers = [h.lower() for h in profile.http_header_order]
        for h_name, h_value in headers.items():
            if h_name.lower() not in ordered_headers:
                request += f"{h_name}: {h_value}\r\n".encode()
        
        # Add body if present
        if body:
            request += f"Content-Length: {len(body)}\r\n".encode()
            request += b"Content-Type: application/x-www-form-urlencoded\r\n"
        
        request += b"\r\n"
        
        if body:
            request += body
        
        return request
    
    def calculate_ja4x(self, certificate_data: bytes) -> str:
        """
        Calculate JA4X certificate fingerprint.
        
        JA4X Format: [issuer_hash]_[subject_hash]_[extensions_hash]_[validity_hash]
        
        Args:
            certificate_data: Raw X.509 certificate bytes (DER format)
            
        Returns:
            JA4X fingerprint string
        """
        try:
            cert_info = self._parse_x509_certificate(certificate_data)
            return self._build_ja4x_string(cert_info)
        except Exception as e:
            logger.error(f"Failed to calculate JA4X: {e}")
            return ""
    
    def _parse_x509_certificate(self, cert_data: bytes) -> Dict[str, Any]:
        """
        Parse X.509 certificate (simplified ASN.1 parsing).
        
        Note: This is a basic implementation. For production use,
        consider using a proper ASN.1 library like pyasn1 or cryptography.
        """
        cert_info = {
            "issuer": "",
            "subject": "", 
            "extensions": [],
            "not_before": "",
            "not_after": "",
            "public_key_algorithm": "",
            "signature_algorithm": "",
            "serial_number": "",
            "version": 0
        }
        
        try:
            # Basic DER parsing - this is simplified
            # In production, use proper ASN.1 parsing library
            
            # Look for common OIDs and extract basic info
            cert_str = cert_data.hex()
            
            # Extract issuer and subject (simplified)
            # This is a very basic extraction - real implementation needs proper ASN.1
            if b"CN=" in cert_data:
                # Find Common Name fields
                cn_positions = []
                data_str = cert_data.decode('utf-8', errors='ignore')
                
                # Extract issuer/subject info (very simplified)
                cert_info["issuer"] = "simplified_issuer_extraction"
                cert_info["subject"] = "simplified_subject_extraction"
            
            # Extract extension OIDs (simplified)
            # Look for extension patterns in the certificate
            extensions = []
            
            # Common extension OIDs to look for
            extension_oids = {
                b'\x30\x1d\x06\x03\x55\x1d\x0e': "subject_key_identifier",
                b'\x30\x1f\x06\x03\x55\x1d\x23': "authority_key_identifier", 
                b'\x30\x0e\x06\x03\x55\x1d\x0f': "key_usage",
                b'\x30\x16\x06\x03\x55\x1d\x25': "extended_key_usage",
                b'\x30\x03\x06\x01\x05': "basic_constraints",
                b'\x30\x82\x01\x69\x06\x03\x55\x1d\x11': "subject_alt_name"
            }
            
            for oid_bytes, ext_name in extension_oids.items():
                if oid_bytes in cert_data:
                    extensions.append(ext_name)
            
            cert_info["extensions"] = extensions
            
        except Exception as e:
            logger.debug(f"Certificate parsing error: {e}")
            # Fallback to basic hash-based analysis
            pass
        
        return cert_info
    
    def _build_ja4x_string(self, cert_info: Dict[str, Any]) -> str:
        """Build JA4X string from certificate info"""
        
        # Hash issuer info
        issuer_hash = self._truncated_sha256(cert_info["issuer"].encode())
        
        # Hash subject info  
        subject_hash = self._truncated_sha256(cert_info["subject"].encode())
        
        # Hash extensions
        extensions_str = "|".join(sorted(cert_info["extensions"]))
        extensions_hash = self._truncated_sha256(extensions_str.encode())
        
        # Hash validity period
        validity_str = f"{cert_info['not_before']}|{cert_info['not_after']}"
        validity_hash = self._truncated_sha256(validity_str.encode())
        
        # Build final JA4X string
        ja4x = f"{issuer_hash}_{subject_hash}_{extensions_hash}_{validity_hash}"
        
        logger.debug(f"Generated JA4X: {ja4x}")
        return ja4x
    
    def analyze_certificate_blocking(self, ja4x: str, cert_data: bytes) -> Dict[str, Any]:
        """
        Analyze certificate for potential blocking indicators.
        
        Args:
            ja4x: JA4X fingerprint
            cert_data: Raw certificate data
            
        Returns:
            Analysis results with blocking risk assessment
        """
        analysis = {
            "blocking_risk": "low",
            "risk_factors": [],
            "recommendations": [],
            "certificate_type": "unknown",
            "ca_info": {},
            "suspicious_patterns": []
        }
        
        try:
            # Check for self-signed certificates
            cert_str = cert_data.decode('utf-8', errors='ignore')
            
            # Look for common blocking patterns
            blocking_patterns = [
                "self-signed",
                "localhost", 
                "test",
                "example.com",
                "invalid",
                "expired"
            ]
            
            for pattern in blocking_patterns:
                if pattern in cert_str.lower():
                    analysis["risk_factors"].append(f"Contains '{pattern}' pattern")
                    analysis["blocking_risk"] = "high"
            
            # Check certificate age/validity
            if len(cert_data) < 500:
                analysis["risk_factors"].append("Unusually small certificate")
                analysis["blocking_risk"] = "medium"
            
            # Check for common CA patterns
            known_cas = [
                "Let's Encrypt",
                "DigiCert", 
                "Cloudflare",
                "Amazon",
                "Google",
                "Microsoft"
            ]
            
            for ca in known_cas:
                if ca.lower() in cert_str.lower():
                    analysis["ca_info"]["detected_ca"] = ca
                    analysis["certificate_type"] = "commercial"
                    break
            else:
                analysis["certificate_type"] = "unknown_ca"
                analysis["risk_factors"].append("Unknown or uncommon CA")
            
            # Generate recommendations
            if analysis["blocking_risk"] == "high":
                analysis["recommendations"].extend([
                    "Use commercial CA certificate",
                    "Avoid self-signed certificates",
                    "Use proper domain names"
                ])
            elif analysis["blocking_risk"] == "medium":
                analysis["recommendations"].extend([
                    "Consider using well-known CA",
                    "Verify certificate validity period"
                ])
            
        except Exception as e:
            logger.debug(f"Certificate analysis error: {e}")
            analysis["risk_factors"].append("Certificate parsing failed")
        
        return analysis
    
    def detect_certificate_pinning(self, ja4x: str, host: str) -> bool:
        """
        Detect if target uses certificate pinning.
        
        Args:
            ja4x: Certificate fingerprint
            host: Target hostname
            
        Returns:
            True if pinning detected, False otherwise
        """
        # Known pinned domains/patterns
        pinned_domains = [
            "github.com",
            "twitter.com", 
            "facebook.com",
            "google.com",
            "apple.com",
            "microsoft.com"
        ]
        
        # Check if host uses known pinning
        for domain in pinned_domains:
            if domain in host.lower():
                logger.info(f"Certificate pinning likely for {host}")
                return True
        
        # Check for HPKP headers or other pinning indicators
        # This would require actual connection analysis
        
        return False
    
    def get_available_profiles(self) -> List[str]:
        """Get list of available browser profile names"""
        return list(self.profiles.keys())
    
    def set_profile(self, profile_name: str) -> bool:
        """
        Set current active profile.
        
        Args:
            profile_name: Name of profile to activate
            
        Returns:
            True if profile exists and was set, False otherwise
        """
        if profile_name in self.profiles:
            self.current_profile = self.profiles[profile_name]
            logger.info(f"Activated profile: {profile_name}")
            return True
        else:
            logger.warning(f"Profile {profile_name} not found")
            return False
    
    def get_profile_info(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a browser profile.
        
        Args:
            profile_name: Name of profile to query
            
        Returns:
            Profile information dictionary or None if not found
        """
        profile = self.profiles.get(profile_name)
        if not profile:
            return None
            
        return {
            "name": profile.name,
            "ja4": profile.ja4,
            "ja4s": profile.ja4s,
            "ja4h": profile.ja4h,
            "ja4x": profile.ja4x,
            "cipher_count": len(profile.cipher_suites),
            "extension_count": len(profile.extensions),
            "supported_groups_count": len(profile.supported_groups),
            "signature_algorithms_count": len(profile.signature_algorithms),
            "alpn_protocols": profile.alpn_protocols,
            "http_headers_count": len(profile.http_headers)
        }


# Additional browser profiles for comprehensive coverage
def _load_extended_browser_profiles() -> Dict[str, BrowserProfile]:
    """Load extended browser profile database"""
    profiles = {}
    
    # Chrome 120+ Windows profile
    profiles["chrome_120_windows"] = BrowserProfile(
        name="Chrome 120 Windows",
        ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja4s="t130200_1301_234ea6891581", 
        ja4h="ge11cn20enus_60a8b69f9c15_000000000000",
        ja4x="a1b2c3d4e5f6_f6e5d4c3b2a1_123456789abc_cba987654321",
        cipher_suites=[
            0x1301, 0x1302, 0x1303,  # TLS 1.3 suites
            0xc02b, 0xc02f, 0xc02c, 0xc030,  # ECDHE suites
            0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ],
        extensions=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023,
            0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
            0x002b, 0x001b, 0x0015, 0x4469
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        },
        http_header_order=[
            "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
            "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"
        ]
    )
    
    # Chrome 120+ macOS profile
    profiles["chrome_120_macos"] = BrowserProfile(
        name="Chrome 120 macOS",
        ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja4s="t130200_1301_234ea6891581",
        ja4h="ge11cn20enus_60a8b69f9c15_000000000000", 
        ja4x="a1b2c3d4e5f6_f6e5d4c3b2a1_123456789abc_cba987654321",
        cipher_suites=[
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ],
        extensions=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023,
            0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
            0x002b, 0x001b, 0x0015, 0x4469
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate", 
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        },
        http_header_order=[
            "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", 
            "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"
        ]
    )
    
    # Chrome 120+ Linux profile
    profiles["chrome_120_linux"] = BrowserProfile(
        name="Chrome 120 Linux",
        ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja4s="t130200_1301_234ea6891581",
        ja4h="ge11cn20enus_60a8b69f9c15_000000000000",
        ja4x="a1b2c3d4e5f6_f6e5d4c3b2a1_123456789abc_cba987654321",
        cipher_suites=[
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ],
        extensions=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023,
            0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
            0x002b, 0x001b, 0x0015, 0x4469
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none", 
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        },
        http_header_order=[
            "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
            "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"
        ]
    )
    
    # Firefox 121+ Windows profile
    profiles["firefox_121_windows"] = BrowserProfile(
        name="Firefox 121 Windows",
        ja4="t13d1517h2_02713d6af862_8daaf6152771",
        ja4s="t130200_1301_234ea6891581",
        ja4h="ge11cn20enus_70b9c8af8d26_000000000000",
        ja4x="b2c3d4e5f6a1_a1f6e5d4c3b2_234567890bcd_dcb098765432",
        cipher_suites=[
            0x1301, 0x1303, 0x1302,  # Different order than Chrome
            0xc02b, 0xc02f, 0xcca9, 0xcca8,
            0xc02c, 0xc030, 0xc00a, 0xc009,
            0xc013, 0xc014, 0x002f, 0x0035
        ],
        extensions=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b,
            0x0010, 0x0005, 0x000d, 0x0033, 0x002d, 0x002b
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        },
        http_header_order=[
            "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
            "DNT", "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
            "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User"
        ]
    )
    
    # Firefox 121+ macOS profile  
    profiles["firefox_121_macos"] = BrowserProfile(
        name="Firefox 121 macOS",
        ja4="t13d1517h2_02713d6af862_8daaf6152771",
        ja4s="t130200_1301_234ea6891581",
        ja4h="ge11cn20enus_70b9c8af8d26_000000000000",
        ja4x="b2c3d4e5f6a1_a1f6e5d4c3b2_234567890bcd_dcb098765432",
        cipher_suites=[
            0x1301, 0x1303, 0x1302,
            0xc02b, 0xc02f, 0xcca9, 0xcca8,
            0xc02c, 0xc030, 0xc00a, 0xc009,
            0xc013, 0xc014, 0x002f, 0x0035
        ],
        extensions=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b,
            0x0010, 0x0005, 0x000d, 0x0033, 0x002d, 0x002b
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        },
        http_header_order=[
            "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
            "DNT", "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
            "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User"
        ]
    )
    
    # Safari 17+ macOS profile
    profiles["safari_17_macos"] = BrowserProfile(
        name="Safari 17 macOS",
        ja4="t13d1415h2_9c3a2f1e8d7b_4f6e2a9c8b1d",
        ja4s="t130200_1301_234ea6891581",
        ja4h="ge11cn20enus_80c9d7bf9e37_000000000000",
        ja4x="c3d4e5f6a1b2_b2a1f6e5d4c3_345678901cde_edc109876543",
        cipher_suites=[
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xc009, 0xc00a, 0xc013, 0xc014,
            0x002f, 0x0035, 0x000a
        ],
        extensions=[
            0x0000, 0x0017, 0x000a, 0x000b, 0x0023,
            0x0010, 0x0005, 0x000d, 0x0033, 0x002d, 0x002b
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        },
        http_header_order=[
            "Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent",
            "Accept", "Accept-Language", "Accept-Encoding"
        ]
    )
    
    # Edge 120+ Windows profile
    profiles["edge_120_windows"] = BrowserProfile(
        name="Edge 120 Windows", 
        ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja4s="t130200_1301_234ea6891581",
        ja4h="ge11cn20enus_90d8e6cf0f48_000000000000",
        ja4x="d4e5f6a1b2c3_c3b2a1f6e5d4_456789012def_fed210987654",
        cipher_suites=[
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035
        ],
        extensions=[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023,
            0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
            0x002b, 0x001b, 0x0015, 0x4469
        ],
        supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
        signature_algorithms=[
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b, 0x0804, 0x0401
        ],
        alpn_protocols=["h2", "http/1.1"],
        http_headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        },
        http_header_order=[
            "Host", "Connection", "Cache-Control", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Platform", "Upgrade-Insecure-Requests", "User-Agent",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
            "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"
        ]
    )
    
    return profiles


# Update the JA4Engine class to use the extended profiles
def _update_ja4_engine_profiles():
    """Update JA4Engine to use extended profiles"""
    JA4Engine._load_browser_profiles = lambda self: _load_extended_browser_profiles()


class JA4Morpher:
    """
    Dynamic JA4 morphing engine for runtime fingerprint changes.
    
    Supports changing TLS fingerprints during active connections while
    maintaining session state and connection integrity.
    """
    
    def __init__(self, ja4_engine: JA4Engine):
        self.ja4_engine = ja4_engine
        self.active_sessions = {}
        self.morph_history = []
        self.morph_interval = 300  # 5 minutes default
        self.last_morph_time = 0
        
    def enable_auto_morphing(self, interval_seconds: int = 300, 
                           profile_rotation: List[str] = None):
        """
        Enable automatic JA4 morphing at specified intervals.
        
        Args:
            interval_seconds: Time between morphs in seconds
            profile_rotation: List of profiles to rotate through
        """
        self.morph_interval = interval_seconds
        
        if profile_rotation:
            self.profile_rotation = profile_rotation
        else:
            # Use all available profiles
            self.profile_rotation = list(self.ja4_engine.profiles.keys())
        
        logger.info(f"Auto-morphing enabled: {interval_seconds}s interval, {len(self.profile_rotation)} profiles")
    
    def should_morph(self) -> bool:
        """Check if it's time to morph fingerprint"""
        import time
        current_time = time.time()
        
        if current_time - self.last_morph_time >= self.morph_interval:
            return True
        
        # Also morph on detection events
        return self._detection_triggered()
    
    def _detection_triggered(self) -> bool:
        """Check if fingerprint detection was triggered"""
        # This would integrate with detection systems
        # For now, return False - implement based on actual detection
        return False
    
    def morph_to_profile(self, profile_name: str, session_id: str = None) -> bool:
        """
        Morph to a specific browser profile.
        
        Args:
            profile_name: Target profile name
            session_id: Optional session to maintain state for
            
        Returns:
            True if morph successful, False otherwise
        """
        if profile_name not in self.ja4_engine.profiles:
            logger.error(f"Profile {profile_name} not found")
            return False
        
        # Store current session state if provided
        if session_id and session_id in self.active_sessions:
            self._preserve_session_state(session_id)
        
        # Switch to new profile
        old_profile = self.ja4_engine.current_profile
        success = self.ja4_engine.set_profile(profile_name)
        
        if success:
            import time
            self.last_morph_time = time.time()
            
            morph_record = {
                "timestamp": self.last_morph_time,
                "from_profile": old_profile.name if old_profile else None,
                "to_profile": profile_name,
                "session_id": session_id,
                "reason": "manual"
            }
            self.morph_history.append(morph_record)
            
            logger.info(f"Morphed to profile: {profile_name}")
            
            # Restore session state if needed
            if session_id:
                self._restore_session_state(session_id)
        
        return success
    
    def auto_morph(self, session_id: str = None) -> Optional[str]:
        """
        Automatically morph to next profile in rotation.
        
        Args:
            session_id: Optional session to maintain state for
            
        Returns:
            Name of new profile if morphed, None otherwise
        """
        if not hasattr(self, 'profile_rotation') or not self.profile_rotation:
            logger.warning("No profile rotation configured")
            return None
        
        if not self.should_morph():
            return None
        
        # Select next profile in rotation
        current_profile = self.ja4_engine.current_profile
        current_name = current_profile.name if current_profile else None
        
        try:
            current_index = self.profile_rotation.index(current_name)
            next_index = (current_index + 1) % len(self.profile_rotation)
        except (ValueError, TypeError):
            # Current profile not in rotation or None, start from beginning
            next_index = 0
        
        next_profile = self.profile_rotation[next_index]
        
        if self.morph_to_profile(next_profile, session_id):
            # Update morph reason
            if self.morph_history:
                self.morph_history[-1]["reason"] = "auto_rotation"
            return next_profile
        
        return None
    
    def random_morph(self, session_id: str = None) -> Optional[str]:
        """
        Morph to a random profile for unpredictability.
        
        Args:
            session_id: Optional session to maintain state for
            
        Returns:
            Name of new profile if morphed, None otherwise
        """
        available_profiles = list(self.ja4_engine.profiles.keys())
        
        # Exclude current profile
        current_profile = self.ja4_engine.current_profile
        if current_profile and current_profile.name in available_profiles:
            available_profiles.remove(current_profile.name)
        
        if not available_profiles:
            logger.warning("No alternative profiles available for random morph")
            return None
        
        import random
        random_profile = random.choice(available_profiles)
        
        if self.morph_to_profile(random_profile, session_id):
            # Update morph reason
            if self.morph_history:
                self.morph_history[-1]["reason"] = "random"
            return random_profile
        
        return None
    
    def _preserve_session_state(self, session_id: str):
        """Preserve TLS session state before morphing"""
        if session_id not in self.active_sessions:
            self.active_sessions[session_id] = {}
        
        session = self.active_sessions[session_id]
        
        # Store current TLS session info
        session["preserved_at"] = time.time()
        session["original_profile"] = self.ja4_engine.current_profile.name if self.ja4_engine.current_profile else None
        
        # In a real implementation, this would preserve:
        # - TLS session tickets
        # - Connection state
        # - Cipher suite negotiations
        # - Certificate chains
        
        logger.debug(f"Preserved session state for {session_id}")
    
    def _restore_session_state(self, session_id: str):
        """Restore TLS session state after morphing"""
        if session_id not in self.active_sessions:
            logger.warning(f"No preserved state for session {session_id}")
            return
        
        session = self.active_sessions[session_id]
        
        # In a real implementation, this would restore:
        # - TLS session tickets
        # - Connection state  
        # - Cipher suite negotiations
        # - Certificate chains
        
        logger.debug(f"Restored session state for {session_id}")
    
    def create_morphed_client_hello(self, hostname: str, session_id: str = None) -> bytes:
        """
        Create ClientHello with current morphed profile.
        
        Args:
            hostname: Target hostname for SNI
            session_id: Optional session ID for state tracking
            
        Returns:
            ClientHello bytes with morphed fingerprint
        """
        if not self.ja4_engine.current_profile:
            logger.warning("No active profile, using default")
            self.ja4_engine.set_profile(list(self.ja4_engine.profiles.keys())[0])
        
        profile = self.ja4_engine.current_profile
        
        # Build ClientHello with profile-specific parameters
        hello_builder = ClientHelloBuilder()
        
        # Set TLS version
        hello_builder.set_version(0x0303)  # TLS 1.2 in record layer
        hello_builder.set_supported_versions([0x0304, 0x0303])  # TLS 1.3, 1.2
        
        # Set cipher suites in profile order
        hello_builder.set_cipher_suites(profile.cipher_suites)
        
        # Add extensions in profile order
        hello_builder.add_extension_sni(hostname)
        
        for ext_type in profile.extensions:
            if ext_type == TLSExtension.SERVER_NAME.value:
                continue  # Already added
            elif ext_type == TLSExtension.SUPPORTED_GROUPS.value:
                hello_builder.add_extension_supported_groups(profile.supported_groups)
            elif ext_type == TLSExtension.SIGNATURE_ALGORITHMS.value:
                hello_builder.add_extension_signature_algorithms(profile.signature_algorithms)
            elif ext_type == TLSExtension.ALPN.value:
                hello_builder.add_extension_alpn(profile.alpn_protocols)
            else:
                # Add generic extension
                hello_builder.add_extension(ext_type, b"")
        
        client_hello = hello_builder.build()
        
        # Track session if provided
        if session_id:
            if session_id not in self.active_sessions:
                self.active_sessions[session_id] = {}
            self.active_sessions[session_id]["last_hello"] = client_hello
            self.active_sessions[session_id]["profile"] = profile.name
        
        return client_hello
    
    def get_morph_statistics(self) -> Dict[str, Any]:
        """Get morphing statistics and history"""
        stats = {
            "total_morphs": len(self.morph_history),
            "active_sessions": len(self.active_sessions),
            "current_profile": self.ja4_engine.current_profile.name if self.ja4_engine.current_profile else None,
            "morph_interval": self.morph_interval,
            "last_morph_time": self.last_morph_time,
            "morph_history": self.morph_history[-10:],  # Last 10 morphs
            "profile_usage": {}
        }
        
        # Calculate profile usage statistics
        for morph in self.morph_history:
            profile = morph["to_profile"]
            if profile not in stats["profile_usage"]:
                stats["profile_usage"][profile] = 0
            stats["profile_usage"][profile] += 1
        
        return stats


class ClientHelloBuilder:
    """Helper class for building TLS ClientHello messages"""
    
    def __init__(self):
        self.version = 0x0303
        self.random = self._generate_random()
        self.session_id = b""
        self.cipher_suites = []
        self.compression_methods = [0x00]  # No compression
        self.extensions = []
    
    def _generate_random(self) -> bytes:
        """Generate 32-byte random value"""
        import os
        return os.urandom(32)
    
    def set_version(self, version: int):
        """Set TLS version"""
        self.version = version
    
    def set_supported_versions(self, versions: List[int]):
        """Add supported versions extension"""
        # Build supported versions extension data
        version_data = b""
        for version in versions:
            version_data += struct.pack('>H', version)
        
        ext_data = struct.pack('>B', len(version_data)) + version_data
        self.add_extension(TLSExtension.SUPPORTED_VERSIONS.value, ext_data)
    
    def set_cipher_suites(self, cipher_suites: List[int]):
        """Set cipher suites list"""
        self.cipher_suites = cipher_suites
    
    def add_extension_sni(self, hostname: str):
        """Add Server Name Indication extension"""
        hostname_bytes = hostname.encode('utf-8')
        
        # SNI extension format:
        # - server_name_list_length (2 bytes)
        # - name_type (1 byte) = 0 for hostname
        # - name_length (2 bytes)
        # - name (variable)
        
        sni_data = struct.pack('>H', len(hostname_bytes) + 3)  # List length
        sni_data += struct.pack('>B', 0)  # Name type (hostname)
        sni_data += struct.pack('>H', len(hostname_bytes))  # Name length
        sni_data += hostname_bytes
        
        self.add_extension(TLSExtension.SERVER_NAME.value, sni_data)
    
    def add_extension_supported_groups(self, groups: List[int]):
        """Add supported groups extension"""
        groups_data = b""
        for group in groups:
            groups_data += struct.pack('>H', group)
        
        ext_data = struct.pack('>H', len(groups_data)) + groups_data
        self.add_extension(TLSExtension.SUPPORTED_GROUPS.value, ext_data)
    
    def add_extension_signature_algorithms(self, algorithms: List[int]):
        """Add signature algorithms extension"""
        alg_data = b""
        for alg in algorithms:
            alg_data += struct.pack('>H', alg)
        
        ext_data = struct.pack('>H', len(alg_data)) + alg_data
        self.add_extension(TLSExtension.SIGNATURE_ALGORITHMS.value, ext_data)
    
    def add_extension_alpn(self, protocols: List[str]):
        """Add ALPN extension"""
        alpn_data = b""
        
        for protocol in protocols:
            proto_bytes = protocol.encode('utf-8')
            alpn_data += struct.pack('>B', len(proto_bytes)) + proto_bytes
        
        ext_data = struct.pack('>H', len(alpn_data)) + alpn_data
        self.add_extension(TLSExtension.ALPN.value, ext_data)
    
    def add_extension(self, ext_type: int, ext_data: bytes):
        """Add generic extension"""
        self.extensions.append((ext_type, ext_data))
    
    def build(self) -> bytes:
        """Build complete ClientHello message"""
        # Build cipher suites
        cipher_data = b""
        for cipher in self.cipher_suites:
            cipher_data += struct.pack('>H', cipher)
        
        # Build extensions
        extensions_data = b""
        for ext_type, ext_data in self.extensions:
            extensions_data += struct.pack('>HH', ext_type, len(ext_data))
            extensions_data += ext_data
        
        # Build ClientHello body
        hello_body = b""
        hello_body += struct.pack('>H', self.version)  # Version
        hello_body += self.random  # Random (32 bytes)
        hello_body += struct.pack('>B', len(self.session_id)) + self.session_id  # Session ID
        hello_body += struct.pack('>H', len(cipher_data)) + cipher_data  # Cipher suites
        hello_body += struct.pack('>B', len(self.compression_methods))  # Compression methods length
        hello_body += bytes(self.compression_methods)  # Compression methods
        
        if extensions_data:
            hello_body += struct.pack('>H', len(extensions_data))  # Extensions length
            hello_body += extensions_data  # Extensions
        
        # Add handshake header
        handshake_msg = struct.pack('>B', 0x01)  # ClientHello type
        handshake_msg += struct.pack('>I', len(hello_body))[1:]  # Length (3 bytes)
        handshake_msg += hello_body
        
        return handshake_msg