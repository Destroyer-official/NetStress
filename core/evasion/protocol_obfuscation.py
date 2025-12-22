"""
Protocol Obfuscation Module

Implements protocol-level obfuscation techniques:
- Header manipulation
- Payload encoding
- Protocol mimicry
- Fragmentation evasion
"""

import random
import struct
import base64
import hashlib
import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class ObfuscationMethod(Enum):
    """Available obfuscation methods"""
    NONE = "none"
    RANDOM_PADDING = "random_padding"
    XOR_ENCODE = "xor_encode"
    BASE64_WRAP = "base64_wrap"
    FRAGMENT = "fragment"
    HEADER_MANIPULATION = "header_manipulation"
    PROTOCOL_MIMICRY = "protocol_mimicry"
    POLYMORPHIC = "polymorphic"


@dataclass
class ObfuscationConfig:
    """Configuration for protocol obfuscation"""
    method: ObfuscationMethod = ObfuscationMethod.NONE
    xor_key: bytes = b'\x42'
    padding_min: int = 0
    padding_max: int = 100
    fragment_size: int = 64
    mimic_protocol: str = "http"  # http, dns, tls
    rotate_methods: bool = False
    compression: bool = False


class ProtocolObfuscator:
    """
    Protocol obfuscation engine.
    
    Transforms packets to evade signature-based detection:
    - Modifies packet structure
    - Encodes payloads
    - Mimics legitimate protocols
    """
    
    def __init__(self, config: Optional[ObfuscationConfig] = None):
        self.config = config or ObfuscationConfig()
        self._method_index = 0
        self._methods = list(ObfuscationMethod)
        self.packets_processed = 0
        
    def obfuscate(self, data: bytes) -> bytes:
        """
        Obfuscate data using configured method.
        Returns obfuscated bytes.
        """
        if self.config.rotate_methods:
            method = self._get_rotating_method()
        else:
            method = self.config.method
            
        self.packets_processed += 1
        
        # Apply compression first if enabled
        if self.config.compression and len(data) > 100:
            try:
                compressed = zlib.compress(data, level=1)
                if len(compressed) < len(data):
                    data = compressed
            except Exception:
                pass
        
        # Apply obfuscation method
        if method == ObfuscationMethod.NONE:
            return data
        elif method == ObfuscationMethod.RANDOM_PADDING:
            return self._add_random_padding(data)
        elif method == ObfuscationMethod.XOR_ENCODE:
            return self._xor_encode(data)
        elif method == ObfuscationMethod.BASE64_WRAP:
            return self._base64_wrap(data)
        elif method == ObfuscationMethod.FRAGMENT:
            return self._fragment_data(data)
        elif method == ObfuscationMethod.HEADER_MANIPULATION:
            return self._manipulate_headers(data)
        elif method == ObfuscationMethod.PROTOCOL_MIMICRY:
            return self._mimic_protocol(data)
        elif method == ObfuscationMethod.POLYMORPHIC:
            return self._polymorphic_encode(data)
        else:
            return data
            
    def _get_rotating_method(self) -> ObfuscationMethod:
        """Get next method in rotation"""
        # Skip NONE in rotation
        active_methods = [m for m in self._methods if m != ObfuscationMethod.NONE]
        method = active_methods[self._method_index % len(active_methods)]
        self._method_index += 1
        return method
        
    def _add_random_padding(self, data: bytes) -> bytes:
        """Add random padding to data"""
        padding_size = random.randint(self.config.padding_min, self.config.padding_max)
        
        # Random position for padding
        position = random.choice(['prefix', 'suffix', 'both'])
        
        if position == 'prefix':
            padding = bytes(random.randint(0, 255) for _ in range(padding_size))
            return padding + data
        elif position == 'suffix':
            padding = bytes(random.randint(0, 255) for _ in range(padding_size))
            return data + padding
        else:
            prefix_size = padding_size // 2
            suffix_size = padding_size - prefix_size
            prefix = bytes(random.randint(0, 255) for _ in range(prefix_size))
            suffix = bytes(random.randint(0, 255) for _ in range(suffix_size))
            return prefix + data + suffix
            
    def _xor_encode(self, data: bytes) -> bytes:
        """XOR encode data with key"""
        key = self.config.xor_key
        key_len = len(key)
        
        encoded = bytearray(len(data))
        for i, byte in enumerate(data):
            encoded[i] = byte ^ key[i % key_len]
            
        return bytes(encoded)
        
    def _base64_wrap(self, data: bytes) -> bytes:
        """Wrap data in base64 encoding"""
        encoded = base64.b64encode(data)
        
        # Add fake HTTP-like wrapper
        wrapper = b"data=" + encoded + b"&checksum=" + hashlib.md5(data).hexdigest().encode()
        return wrapper
        
    def _fragment_data(self, data: bytes) -> bytes:
        """Fragment data into smaller pieces with markers"""
        fragment_size = self.config.fragment_size
        fragments = []
        
        for i in range(0, len(data), fragment_size):
            fragment = data[i:i + fragment_size]
            # Add fragment header: [index:2][total:2][size:2][data]
            total = (len(data) + fragment_size - 1) // fragment_size
            header = struct.pack('>HHH', i // fragment_size, total, len(fragment))
            fragments.append(header + fragment)
            
        # Return concatenated fragments (in real use, send separately)
        return b''.join(fragments)
        
    def _manipulate_headers(self, data: bytes) -> bytes:
        """Manipulate protocol headers to evade detection"""
        # Add fake protocol headers
        fake_headers = [
            b"X-Request-ID: " + hashlib.md5(data[:16] if len(data) >= 16 else data).hexdigest().encode() + b"\r\n",
            b"X-Forwarded-For: " + f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}".encode() + b"\r\n",
            b"X-Real-IP: " + f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}".encode() + b"\r\n",
            b"Cache-Control: no-cache\r\n",
            b"Pragma: no-cache\r\n",
        ]
        
        # Select random subset of headers
        selected = random.sample(fake_headers, random.randint(1, len(fake_headers)))
        return b''.join(selected) + b"\r\n" + data
        
    def _mimic_protocol(self, data: bytes) -> bytes:
        """Wrap data to mimic legitimate protocol"""
        protocol = self.config.mimic_protocol.lower()
        
        if protocol == "http":
            return self._mimic_http(data)
        elif protocol == "dns":
            return self._mimic_dns(data)
        elif protocol == "tls":
            return self._mimic_tls(data)
        else:
            return data
            
    def _mimic_http(self, data: bytes) -> bytes:
        """Wrap data as HTTP request"""
        methods = [b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS"]
        paths = [b"/api/v1/data", b"/search", b"/update", b"/status", b"/health"]
        
        method = random.choice(methods)
        path = random.choice(paths)
        
        # Encode data as query param or body
        encoded_data = base64.b64encode(data)
        
        if method in [b"GET", b"HEAD"]:
            request = method + b" " + path + b"?d=" + encoded_data + b" HTTP/1.1\r\n"
        else:
            request = method + b" " + path + b" HTTP/1.1\r\n"
            request += b"Content-Length: " + str(len(encoded_data)).encode() + b"\r\n"
            request += b"Content-Type: application/octet-stream\r\n"
            request += b"\r\n"
            request += encoded_data
            
        request += b"Host: " + f"api{random.randint(1,99)}.example.com".encode() + b"\r\n"
        request += b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        request += b"Accept: */*\r\n"
        request += b"Connection: keep-alive\r\n"
        request += b"\r\n"
        
        return request
        
    def _mimic_dns(self, data: bytes) -> bytes:
        """Wrap data as DNS query"""
        # DNS header (simplified)
        transaction_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        
        header = struct.pack('>HHHHHH', 
            transaction_id, flags, questions, 0, 0, 0)
        
        # Encode data as subdomain labels
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        
        # Split into DNS labels (max 63 chars each)
        labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        labels.append("data")
        labels.append("example")
        labels.append("com")
        
        # Build QNAME
        qname = b''
        for label in labels:
            qname += bytes([len(label)]) + label.encode()
        qname += b'\x00'  # Root label
        
        # QTYPE (TXT=16) and QCLASS (IN=1)
        question = qname + struct.pack('>HH', 16, 1)
        
        return header + question
        
    def _mimic_tls(self, data: bytes) -> bytes:
        """Wrap data as TLS record"""
        # TLS record header
        content_type = 23  # Application data
        version = 0x0303  # TLS 1.2
        
        # Add random IV-like prefix
        iv = bytes(random.randint(0, 255) for _ in range(16))
        
        # Pad to block size
        block_size = 16
        padding_len = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_len] * padding_len)
        
        payload = iv + padded_data
        
        # TLS record header
        header = struct.pack('>BHH', content_type, version, len(payload))
        
        return header + payload
        
    def _polymorphic_encode(self, data: bytes) -> bytes:
        """
        Polymorphic encoding - different encoding each time.
        Makes signature detection very difficult.
        """
        # Generate random encoding parameters
        xor_key = bytes(random.randint(0, 255) for _ in range(random.randint(1, 8)))
        shift = random.randint(1, 7)
        
        # Apply transformations
        encoded = bytearray(len(data))
        for i, byte in enumerate(data):
            # XOR with rotating key
            byte ^= xor_key[i % len(xor_key)]
            # Bit rotation
            byte = ((byte << shift) | (byte >> (8 - shift))) & 0xFF
            encoded[i] = byte
            
        # Prepend encoding parameters (for decoding)
        header = struct.pack('>BB', len(xor_key), shift) + xor_key
        
        return header + bytes(encoded)


class HTTPObfuscator:
    """Specialized HTTP request obfuscation"""
    
    # Legitimate-looking user agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ]
    
    # Common referrers
    REFERRERS = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://www.facebook.com/",
        "https://twitter.com/",
        "https://www.linkedin.com/",
    ]
    
    @classmethod
    def generate_request(cls, host: str, path: str = "/", 
                        method: str = "GET", body: bytes = b"") -> bytes:
        """Generate obfuscated HTTP request"""
        
        # Randomize case of method (some servers accept)
        if random.random() < 0.1:
            method = ''.join(random.choice([c.upper(), c.lower()]) for c in method)
            
        request = f"{method} {path} HTTP/1.1\r\n".encode()
        request += f"Host: {host}\r\n".encode()
        request += f"User-Agent: {random.choice(cls.USER_AGENTS)}\r\n".encode()
        
        # Random headers
        if random.random() < 0.7:
            request += f"Referer: {random.choice(cls.REFERRERS)}\r\n".encode()
            
        if random.random() < 0.5:
            request += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            
        if random.random() < 0.5:
            request += b"Accept-Language: en-US,en;q=0.9\r\n"
            
        if random.random() < 0.3:
            request += b"Accept-Encoding: gzip, deflate, br\r\n"
            
        # Cache busting
        if random.random() < 0.4:
            request += f"X-Request-ID: {random.randint(100000, 999999)}\r\n".encode()
            
        # Connection handling
        request += random.choice([b"Connection: keep-alive\r\n", b"Connection: close\r\n"])
        
        if body:
            request += f"Content-Length: {len(body)}\r\n".encode()
            request += b"Content-Type: application/x-www-form-urlencoded\r\n"
            
        request += b"\r\n"
        
        if body:
            request += body
            
        return request
