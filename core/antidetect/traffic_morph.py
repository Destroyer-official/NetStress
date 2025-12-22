"""
Traffic Morphing Module

Transforms traffic to evade detection:
- Protocol mimicry
- Payload mutation
- Traffic shaping
- Timing manipulation
"""

import random
import struct
import base64
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Optional, Callable, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class MorphType(Enum):
    """Traffic morphing types"""
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    WEBSOCKET = "websocket"
    CUSTOM = "custom"


@dataclass
class MorphConfig:
    """Morphing configuration"""
    morph_type: MorphType = MorphType.HTTP
    add_noise: bool = True
    noise_ratio: float = 0.1
    fragment: bool = False
    fragment_size: int = 100
    delay_range: Tuple[float, float] = (0.0, 0.1)


class TrafficMorpher:
    """
    Traffic Morpher
    
    Transforms traffic to look like legitimate protocols.
    """
    
    def __init__(self, config: MorphConfig):
        self.config = config
        self._morphers = {
            MorphType.HTTP: self._morph_http,
            MorphType.DNS: self._morph_dns,
            MorphType.TLS: self._morph_tls,
            MorphType.WEBSOCKET: self._morph_websocket,
        }
        
    def morph(self, data: bytes) -> bytes:
        """Morph data to look like target protocol"""
        morpher = self._morphers.get(self.config.morph_type, self._morph_custom)
        morphed = morpher(data)
        
        if self.config.add_noise:
            morphed = self._add_noise(morphed)
            
        if self.config.fragment:
            return morphed  # Fragmentation handled at send time
            
        return morphed
        
    def demorph(self, data: bytes) -> bytes:
        """Extract original data from morphed traffic"""
        if self.config.morph_type == MorphType.HTTP:
            return self._demorph_http(data)
        elif self.config.morph_type == MorphType.DNS:
            return self._demorph_dns(data)
        elif self.config.morph_type == MorphType.WEBSOCKET:
            return self._demorph_websocket(data)
        return data
        
    def _morph_http(self, data: bytes) -> bytes:
        """Morph as HTTP traffic"""
        encoded = base64.b64encode(data).decode()
        
        # Create fake HTTP request
        paths = ['/api/v1/data', '/images/pixel.gif', '/static/app.js', '/analytics']
        path = random.choice(paths)
        
        request = f"POST {path} HTTP/1.1\r\n"
        request += f"Host: cdn{random.randint(1,99)}.example.com\r\n"
        request += "Content-Type: application/x-www-form-urlencoded\r\n"
        request += f"Content-Length: {len(encoded)}\r\n"
        request += "Connection: keep-alive\r\n"
        request += f"X-Request-ID: {hashlib.md5(data).hexdigest()[:16]}\r\n"
        request += "\r\n"
        request += f"data={encoded}"
        
        return request.encode()
        
    def _demorph_http(self, data: bytes) -> bytes:
        """Extract data from HTTP morphed traffic"""
        try:
            text = data.decode('utf-8', errors='ignore')
            if 'data=' in text:
                encoded = text.split('data=')[1].split('\r\n')[0]
                return base64.b64decode(encoded)
        except Exception:
            pass
        return data
        
    def _morph_dns(self, data: bytes) -> bytes:
        """Morph as DNS traffic"""
        # Encode data in DNS query format
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into labels (max 63 chars each)
        labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        
        # Build DNS query
        transaction_id = struct.pack('>H', random.randint(0, 65535))
        flags = struct.pack('>H', 0x0100)  # Standard query
        counts = struct.pack('>HHHH', 1, 0, 0, 0)  # 1 question
        
        qname = b''
        for label in labels:
            qname += bytes([len(label)]) + label.encode()
        qname += b'\x07example\x03com\x00'
        
        qtype = struct.pack('>H', 16)  # TXT
        qclass = struct.pack('>H', 1)  # IN
        
        return transaction_id + flags + counts + qname + qtype + qclass
        
    def _demorph_dns(self, data: bytes) -> bytes:
        """Extract data from DNS morphed traffic"""
        try:
            # Skip header (12 bytes)
            qname = data[12:]
            
            # Extract labels
            labels = []
            i = 0
            while qname[i] != 0 and i < len(qname):
                length = qname[i]
                label = qname[i+1:i+1+length].decode()
                if label not in ['example', 'com']:
                    labels.append(label)
                i += length + 1
                
            encoded = ''.join(labels).upper()
            # Add padding
            padding = (8 - len(encoded) % 8) % 8
            encoded += '=' * padding
            
            return base64.b32decode(encoded)
        except Exception:
            pass
        return data
        
    def _morph_tls(self, data: bytes) -> bytes:
        """Morph as TLS application data"""
        # TLS record header
        content_type = b'\x17'  # Application data
        version = b'\x03\x03'  # TLS 1.2
        length = struct.pack('>H', len(data))
        
        return content_type + version + length + data
        
    def _morph_websocket(self, data: bytes) -> bytes:
        """Morph as WebSocket frame"""
        # WebSocket frame
        fin_opcode = 0x82  # Final frame, binary
        
        if len(data) < 126:
            header = bytes([fin_opcode, 0x80 | len(data)])
        elif len(data) < 65536:
            header = bytes([fin_opcode, 0x80 | 126]) + struct.pack('>H', len(data))
        else:
            header = bytes([fin_opcode, 0x80 | 127]) + struct.pack('>Q', len(data))
            
        # Masking key
        mask = bytes(random.randint(0, 255) for _ in range(4))
        
        # Mask data
        masked = bytes(data[i] ^ mask[i % 4] for i in range(len(data)))
        
        return header + mask + masked
        
    def _demorph_websocket(self, data: bytes) -> bytes:
        """Extract data from WebSocket frame"""
        try:
            payload_len = data[1] & 0x7f
            mask_start = 2
            
            if payload_len == 126:
                payload_len = struct.unpack('>H', data[2:4])[0]
                mask_start = 4
            elif payload_len == 127:
                payload_len = struct.unpack('>Q', data[2:10])[0]
                mask_start = 10
                
            if data[1] & 0x80:  # Masked
                mask = data[mask_start:mask_start+4]
                payload = data[mask_start+4:mask_start+4+payload_len]
                return bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
            else:
                return data[mask_start:mask_start+payload_len]
        except Exception:
            pass
        return data
        
    def _morph_custom(self, data: bytes) -> bytes:
        """Custom morphing (XOR with key)"""
        key = b'NetStress'
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
        
    def _add_noise(self, data: bytes) -> bytes:
        """Add random noise to data"""
        noise_len = int(len(data) * self.config.noise_ratio)
        noise = bytes(random.randint(0, 255) for _ in range(noise_len))
        
        # Append noise with length prefix
        return data + struct.pack('>H', noise_len) + noise


class ProtocolMimicry:
    """
    Protocol Mimicry
    
    Makes traffic look like specific applications.
    """
    
    # Application signatures
    SIGNATURES = {
        'chrome': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'headers': ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-fetch-site'],
            'tls_fingerprint': 'chrome_120',
        },
        'firefox': {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'headers': ['te', 'upgrade-insecure-requests'],
            'tls_fingerprint': 'firefox_121',
        },
        'curl': {
            'user_agent': 'curl/8.0.0',
            'headers': [],
            'tls_fingerprint': 'curl',
        },
    }
    
    def __init__(self, application: str = 'chrome'):
        self.application = application
        self.signature = self.SIGNATURES.get(application, self.SIGNATURES['chrome'])
        
    def get_headers(self) -> Dict[str, str]:
        """Get headers for mimicked application"""
        headers = {
            'User-Agent': self.signature['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        
        if self.application == 'chrome':
            headers.update({
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-site': 'none',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-user': '?1',
                'sec-fetch-dest': 'document',
            })
            
        return headers
        
    def build_request(self, method: str, path: str, host: str, body: bytes = b'') -> bytes:
        """Build HTTP request mimicking application"""
        headers = self.get_headers()
        headers['Host'] = host
        
        if body:
            headers['Content-Length'] = str(len(body))
            
        request = f"{method} {path} HTTP/1.1\r\n"
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        
        return request.encode() + body


class PayloadMutation:
    """
    Payload Mutation
    
    Mutates payloads to evade signature detection.
    """
    
    def __init__(self):
        self._mutations: List[Callable[[bytes], bytes]] = [
            self._xor_mutation,
            self._base64_mutation,
            self._padding_mutation,
            self._split_mutation,
            self._case_mutation,
        ]
        
    def mutate(self, payload: bytes, mutations: int = 1) -> bytes:
        """Apply random mutations to payload"""
        result = payload
        
        selected = random.sample(self._mutations, min(mutations, len(self._mutations)))
        for mutation in selected:
            result = mutation(result)
            
        return result
        
    def _xor_mutation(self, data: bytes) -> bytes:
        """XOR with random key"""
        key = random.randint(1, 255)
        return bytes([b ^ key for b in data]) + bytes([key])
        
    def _base64_mutation(self, data: bytes) -> bytes:
        """Base64 encode"""
        return base64.b64encode(data)
        
    def _padding_mutation(self, data: bytes) -> bytes:
        """Add random padding"""
        padding_len = random.randint(1, 32)
        padding = bytes(random.randint(0, 255) for _ in range(padding_len))
        return struct.pack('>H', len(data)) + data + padding
        
    def _split_mutation(self, data: bytes) -> bytes:
        """Split and interleave"""
        mid = len(data) // 2
        first = data[:mid]
        second = data[mid:]
        
        result = b''
        for i in range(max(len(first), len(second))):
            if i < len(first):
                result += bytes([first[i]])
            if i < len(second):
                result += bytes([second[i]])
                
        return struct.pack('>HH', len(first), len(second)) + result
        
    def _case_mutation(self, data: bytes) -> bytes:
        """Random case changes for text"""
        try:
            text = data.decode('utf-8')
            result = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
            return result.encode()
        except Exception:
            return data


# =============================================================================
# PROTOCOL TUNNELING - Real implementations for traffic masking
# =============================================================================

class TunnelType(Enum):
    """Supported tunnel types"""
    GRE = "gre"
    IPIP = "ipip"
    DNS_OVER_HTTPS = "doh"
    DNS_OVER_TLS = "dot"
    ICMP = "icmp"
    HTTP_CHUNKED = "http_chunked"


@dataclass
class TunnelConfig:
    """Tunnel configuration"""
    tunnel_type: TunnelType
    tunnel_endpoint: str = ""
    tunnel_port: int = 0
    encryption_key: Optional[bytes] = None
    mtu: int = 1400
    fragment: bool = True


class GRETunnel:
    """
    GRE (Generic Routing Encapsulation) Tunnel
    
    Encapsulates traffic in GRE packets (RFC 2784).
    Real implementation - creates valid GRE headers.
    """
    
    # GRE Protocol Types
    PROTO_IP = 0x0800
    PROTO_IPV6 = 0x86DD
    
    def __init__(self, config: TunnelConfig):
        self.config = config
        self.sequence = 0
        self.key = config.encryption_key or b'\x00\x00\x00\x00'
        
    def encapsulate(self, payload: bytes, protocol: int = PROTO_IP) -> bytes:
        """
        Encapsulate payload in GRE header.
        
        GRE Header Format (RFC 2784):
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Checksum (optional)      |       Offset (optional)       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                         Key (optional)                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Sequence Number (optional)                 |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        # Flags: C=0, R=0, K=1 (key present), S=1 (sequence present)
        flags = 0x3000  # Key and Sequence present
        
        # Build GRE header
        header = struct.pack('>HH', flags, protocol)
        header += self.key[:4]  # 4-byte key
        header += struct.pack('>I', self.sequence)
        
        self.sequence = (self.sequence + 1) & 0xFFFFFFFF
        
        return header + payload
        
    def decapsulate(self, data: bytes) -> Tuple[bytes, int]:
        """
        Extract payload from GRE packet.
        
        Returns:
            Tuple of (payload, protocol_type)
        """
        if len(data) < 4:
            raise ValueError("GRE packet too short")
            
        flags, protocol = struct.unpack('>HH', data[:4])
        offset = 4
        
        # Check for optional fields
        if flags & 0x8000:  # Checksum present
            offset += 4
        if flags & 0x2000:  # Key present
            offset += 4
        if flags & 0x1000:  # Sequence present
            offset += 4
            
        return data[offset:], protocol


class IPIPTunnel:
    """
    IP-in-IP Tunnel (RFC 2003)
    
    Encapsulates IP packets inside IP packets.
    Real implementation - creates valid IP-in-IP headers.
    """
    
    PROTO_IPIP = 4  # IP-in-IP protocol number
    
    def __init__(self, config: TunnelConfig, src_ip: str = "0.0.0.0", dst_ip: str = "0.0.0.0"):
        self.config = config
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.identification = random.randint(0, 65535)
        
    def _ip_to_bytes(self, ip: str) -> bytes:
        """Convert IP string to bytes"""
        parts = ip.split('.')
        return bytes(int(p) for p in parts)
        
    def _calculate_checksum(self, header: bytes) -> int:
        """Calculate IP header checksum"""
        if len(header) % 2:
            header += b'\x00'
            
        total = 0
        for i in range(0, len(header), 2):
            total += (header[i] << 8) + header[i + 1]
            
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
            
        return ~total & 0xFFFF
        
    def encapsulate(self, inner_packet: bytes) -> bytes:
        """
        Encapsulate inner IP packet in outer IP header.
        
        Outer IP Header:
        - Protocol: 4 (IP-in-IP)
        - Payload: Complete inner IP packet
        """
        total_length = 20 + len(inner_packet)  # Outer header + inner packet
        
        # Build outer IP header (20 bytes, no options)
        header = struct.pack('>BBHHHBBH',
            0x45,  # Version 4, IHL 5 (20 bytes)
            0x00,  # DSCP/ECN
            total_length,
            self.identification,
            0x4000,  # Don't Fragment
            64,  # TTL
            self.PROTO_IPIP,  # Protocol
            0,  # Checksum placeholder
        )
        header += self._ip_to_bytes(self.src_ip)
        header += self._ip_to_bytes(self.dst_ip)
        
        # Calculate checksum
        checksum = self._calculate_checksum(header)
        header = header[:10] + struct.pack('>H', checksum) + header[12:]
        
        self.identification = (self.identification + 1) & 0xFFFF
        
        return header + inner_packet
        
    def decapsulate(self, data: bytes) -> bytes:
        """Extract inner IP packet from IP-in-IP tunnel"""
        if len(data) < 20:
            raise ValueError("IP-in-IP packet too short")
            
        # Get IHL from first byte
        ihl = (data[0] & 0x0F) * 4
        
        # Return inner packet (everything after outer header)
        return data[ihl:]


class DNSOverHTTPSTunnel:
    """
    DNS-over-HTTPS (DoH) Tunnel
    
    Encapsulates traffic as DNS queries over HTTPS.
    Real implementation - creates valid DoH requests.
    """
    
    # Public DoH servers
    DOH_SERVERS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
    ]
    
    def __init__(self, config: TunnelConfig):
        self.config = config
        self.server = config.tunnel_endpoint or random.choice(self.DOH_SERVERS)
        
        # Ensure server URL is properly formatted
        if self.server and not self.server.startswith('https://'):
            self.server = f"https://{self.server}/dns-query"
        
        self.transaction_id = random.randint(0, 65535)
        
    def _encode_domain(self, data: bytes) -> str:
        """Encode data as DNS-safe domain labels"""
        # Base32 encode (DNS-safe characters)
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into labels (max 63 chars each)
        labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        
        return '.'.join(labels) + '.tunnel.local'
        
    def _decode_domain(self, domain: str) -> bytes:
        """Decode data from DNS domain labels"""
        # Remove tunnel suffix
        if domain.endswith('.tunnel.local'):
            domain = domain[:-13]
            
        # Join labels and decode
        encoded = domain.replace('.', '').upper()
        
        # Add padding
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        return base64.b32decode(encoded)
        
    def encapsulate(self, payload: bytes) -> bytes:
        """
        Encapsulate payload as DoH request.
        
        Creates a valid DNS query with data encoded in the query name.
        """
        # Encode payload as domain name
        domain = self._encode_domain(payload)
        
        # Build DNS query
        dns_query = self._build_dns_query(domain)
        
        # Build HTTP request for DoH
        http_request = self._build_doh_request(dns_query)
        
        return http_request
        
    def _build_dns_query(self, domain: str) -> bytes:
        """Build DNS query packet"""
        # Transaction ID
        query = struct.pack('>H', self.transaction_id)
        self.transaction_id = (self.transaction_id + 1) & 0xFFFF
        
        # Flags: Standard query
        query += struct.pack('>H', 0x0100)
        
        # Counts: 1 question, 0 answers, 0 authority, 0 additional
        query += struct.pack('>HHHH', 1, 0, 0, 0)
        
        # Question section
        for label in domain.split('.'):
            query += bytes([len(label)]) + label.encode()
        query += b'\x00'  # Root label
        
        # Type: TXT (16), Class: IN (1)
        query += struct.pack('>HH', 16, 1)
        
        return query
        
    def _build_doh_request(self, dns_query: bytes) -> bytes:
        """Build DoH HTTP request"""
        # Base64url encode DNS query
        encoded = base64.urlsafe_b64encode(dns_query).rstrip(b'=').decode()
        
        # Extract hostname from server URL
        if '//' in self.server:
            hostname = self.server.split('//')[1].split('/')[0]
        else:
            hostname = self.server.split('/')[0]
        
        # Build HTTP GET request
        request = f"GET /dns-query?dns={encoded} HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        request += "Accept: application/dns-message\r\n"
        request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
        request += "Connection: keep-alive\r\n"
        request += "\r\n"
        
        return request.encode()
        
    def decapsulate(self, data: bytes) -> bytes:
        """Extract payload from DoH response"""
        try:
            # Parse HTTP response to get DNS response
            if b'\r\n\r\n' in data:
                dns_response = data.split(b'\r\n\r\n')[1]
            else:
                dns_response = data
                
            # Skip DNS header (12 bytes) and question section
            offset = 12
            while dns_response[offset] != 0:
                offset += dns_response[offset] + 1
            offset += 5  # Skip null byte, type, class
            
            # Parse answer section
            if len(dns_response) > offset:
                # Skip name pointer, type, class, TTL, rdlength
                offset += 12
                txt_length = dns_response[offset]
                txt_data = dns_response[offset + 1:offset + 1 + txt_length]
                return self._decode_domain(txt_data.decode())
                
        except Exception as e:
            logger.warning(f"DoH decapsulation failed: {e}")
            
        return data


class ICMPTunnel:
    """
    ICMP Tunnel
    
    Encapsulates traffic in ICMP echo request/reply packets.
    Real implementation - creates valid ICMP packets.
    """
    
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    
    def __init__(self, config: TunnelConfig):
        self.config = config
        self.sequence = 0
        self.identifier = random.randint(0, 65535)
        
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
            
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
            
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
            
        return ~total & 0xFFFF
        
    def encapsulate(self, payload: bytes, is_request: bool = True) -> bytes:
        """
        Encapsulate payload in ICMP echo packet.
        
        ICMP Echo Header:
        - Type: 8 (request) or 0 (reply)
        - Code: 0
        - Checksum: 16-bit
        - Identifier: 16-bit
        - Sequence: 16-bit
        - Data: payload
        """
        icmp_type = self.ICMP_ECHO_REQUEST if is_request else self.ICMP_ECHO_REPLY
        
        # Build ICMP header without checksum
        header = struct.pack('>BBHHH',
            icmp_type,
            0,  # Code
            0,  # Checksum placeholder
            self.identifier,
            self.sequence
        )
        
        # Calculate checksum over header + payload
        packet = header + payload
        checksum = self._calculate_checksum(packet)
        
        # Insert checksum
        packet = struct.pack('>BBHHH',
            icmp_type,
            0,
            checksum,
            self.identifier,
            self.sequence
        ) + payload
        
        self.sequence = (self.sequence + 1) & 0xFFFF
        
        return packet
        
    def decapsulate(self, data: bytes) -> bytes:
        """Extract payload from ICMP packet"""
        if len(data) < 8:
            raise ValueError("ICMP packet too short")
            
        # Skip ICMP header (8 bytes)
        return data[8:]


class ProtocolTunneler:
    """
    Protocol Tunneler - Main interface for all tunnel types.
    
    Provides unified interface for encapsulating traffic in various
    tunnel protocols to evade detection.
    """
    
    def __init__(self, config: TunnelConfig):
        self.config = config
        self._tunnel = self._create_tunnel()
        
    def _create_tunnel(self):
        """Create appropriate tunnel based on config"""
        if self.config.tunnel_type == TunnelType.GRE:
            return GRETunnel(self.config)
        elif self.config.tunnel_type == TunnelType.IPIP:
            return IPIPTunnel(self.config)
        elif self.config.tunnel_type == TunnelType.DNS_OVER_HTTPS:
            return DNSOverHTTPSTunnel(self.config)
        elif self.config.tunnel_type == TunnelType.ICMP:
            return ICMPTunnel(self.config)
        else:
            raise ValueError(f"Unsupported tunnel type: {self.config.tunnel_type}")
            
    def encapsulate(self, data: bytes) -> bytes:
        """Encapsulate data in tunnel protocol"""
        # Fragment if needed
        if self.config.fragment and len(data) > self.config.mtu:
            fragments = []
            for i in range(0, len(data), self.config.mtu):
                fragment = data[i:i + self.config.mtu]
                fragments.append(self._tunnel.encapsulate(fragment))
            return b''.join(fragments)
        
        return self._tunnel.encapsulate(data)
        
    def decapsulate(self, data: bytes) -> bytes:
        """Extract data from tunnel protocol"""
        return self._tunnel.decapsulate(data)
        
    @staticmethod
    def create_gre_tunnel(key: bytes = None) -> 'ProtocolTunneler':
        """Factory method for GRE tunnel"""
        config = TunnelConfig(
            tunnel_type=TunnelType.GRE,
            encryption_key=key
        )
        return ProtocolTunneler(config)
        
    @staticmethod
    def create_doh_tunnel(server: str = None) -> 'ProtocolTunneler':
        """Factory method for DNS-over-HTTPS tunnel"""
        config = TunnelConfig(
            tunnel_type=TunnelType.DNS_OVER_HTTPS,
            tunnel_endpoint=server or "https://cloudflare-dns.com/dns-query"
        )
        return ProtocolTunneler(config)
        
    @staticmethod
    def create_icmp_tunnel() -> 'ProtocolTunneler':
        """Factory method for ICMP tunnel"""
        config = TunnelConfig(tunnel_type=TunnelType.ICMP)
        return ProtocolTunneler(config)
