"""
Advanced Payload Generation Module

Generates sophisticated attack payloads:
- Polymorphic payloads (change each time)
- Protocol fuzzing payloads
- Evasion-optimized payloads
- Custom protocol payloads
"""

import random
import struct
import hashlib
import base64
import string
import zlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Iterator
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Payload types"""
    RANDOM = "random"
    PATTERN = "pattern"
    POLYMORPHIC = "polymorphic"
    FUZZING = "fuzzing"
    PROTOCOL = "protocol"
    EVASION = "evasion"


@dataclass
class PayloadConfig:
    """Payload generation configuration"""
    payload_type: PayloadType = PayloadType.RANDOM
    min_size: int = 64
    max_size: int = 1472
    mutation_rate: float = 0.1
    encoding: Optional[str] = None  # base64, hex, url
    compression: bool = False


class PayloadGenerator(ABC):
    """Base class for payload generators"""
    
    def __init__(self, config: PayloadConfig):
        self.config = config
        self._generated = 0
        
    @abstractmethod
    def generate(self) -> bytes:
        """Generate a single payload"""
        pass
    
    def generate_batch(self, count: int) -> List[bytes]:
        """Generate multiple payloads"""
        return [self.generate() for _ in range(count)]
        
    def stream(self) -> Iterator[bytes]:
        """Stream payloads infinitely"""
        while True:
            yield self.generate()
            
    def _apply_encoding(self, data: bytes) -> bytes:
        """Apply configured encoding"""
        if self.config.compression:
            data = zlib.compress(data)
            
        if self.config.encoding == 'base64':
            data = base64.b64encode(data)
        elif self.config.encoding == 'hex':
            data = data.hex().encode()
        elif self.config.encoding == 'url':
            import urllib.parse
            data = urllib.parse.quote_from_bytes(data).encode()
            
        return data


class RandomPayload(PayloadGenerator):
    """Generate random byte payloads"""
    
    def generate(self) -> bytes:
        size = random.randint(self.config.min_size, self.config.max_size)
        data = bytes(random.randint(0, 255) for _ in range(size))
        self._generated += 1
        return self._apply_encoding(data)


class PatternPayload(PayloadGenerator):
    """Generate pattern-based payloads"""
    
    PATTERNS = [
        b'\x00' * 100,  # Null bytes
        b'\xff' * 100,  # All ones
        b'\x41' * 100,  # 'A' pattern
        b'\x00\xff' * 50,  # Alternating
        bytes(range(256)) * 4,  # Sequential
    ]
    
    def __init__(self, config: PayloadConfig, custom_pattern: bytes = None):
        super().__init__(config)
        self.custom_pattern = custom_pattern
        
    def generate(self) -> bytes:
        if self.custom_pattern:
            pattern = self.custom_pattern
        else:
            pattern = random.choice(self.PATTERNS)
            
        size = random.randint(self.config.min_size, self.config.max_size)
        
        # Repeat pattern to fill size
        repeats = (size // len(pattern)) + 1
        data = (pattern * repeats)[:size]
        
        self._generated += 1
        return self._apply_encoding(data)


class PolymorphicPayload(PayloadGenerator):
    """
    Generate polymorphic payloads that change each time.
    
    Uses multiple mutation techniques:
    - Byte substitution
    - Block shuffling
    - Encoding variation
    - Padding insertion
    """
    
    def __init__(self, config: PayloadConfig, base_payload: bytes = None):
        super().__init__(config)
        self.base_payload = base_payload or self._generate_base()
        self._mutation_count = 0
        
    def _generate_base(self) -> bytes:
        """Generate base payload"""
        size = (self.config.min_size + self.config.max_size) // 2
        return bytes(random.randint(0, 255) for _ in range(size))
        
    def generate(self) -> bytes:
        # Start with base payload
        data = bytearray(self.base_payload)
        
        # Apply mutations
        mutations = [
            self._mutate_bytes,
            self._shuffle_blocks,
            self._insert_nops,
            self._xor_sections,
            self._reverse_sections,
        ]
        
        # Apply 1-3 random mutations
        for mutation in random.sample(mutations, random.randint(1, 3)):
            data = mutation(data)
            
        # Adjust size
        target_size = random.randint(self.config.min_size, self.config.max_size)
        if len(data) < target_size:
            data.extend(bytes(random.randint(0, 255) for _ in range(target_size - len(data))))
        elif len(data) > target_size:
            data = data[:target_size]
            
        self._generated += 1
        self._mutation_count += 1
        
        return self._apply_encoding(bytes(data))
        
    def _mutate_bytes(self, data: bytearray) -> bytearray:
        """Randomly mutate bytes"""
        num_mutations = int(len(data) * self.config.mutation_rate)
        for _ in range(num_mutations):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        return data
        
    def _shuffle_blocks(self, data: bytearray) -> bytearray:
        """Shuffle blocks of data"""
        block_size = max(4, len(data) // 8)
        blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
        random.shuffle(blocks)
        return bytearray(b''.join(blocks))
        
    def _insert_nops(self, data: bytearray) -> bytearray:
        """Insert NOP-like bytes"""
        nops = [b'\x90', b'\x00', b'\xff']
        result = bytearray()
        for byte in data:
            result.append(byte)
            if random.random() < 0.05:
                result.extend(random.choice(nops))
        return result
        
    def _xor_sections(self, data: bytearray) -> bytearray:
        """XOR random sections"""
        if len(data) < 8:
            return data
        start = random.randint(0, len(data) - 8)
        length = random.randint(4, min(32, len(data) - start))
        key = random.randint(1, 255)
        for i in range(start, start + length):
            data[i] ^= key
        return data
        
    def _reverse_sections(self, data: bytearray) -> bytearray:
        """Reverse random sections"""
        if len(data) < 8:
            return data
        start = random.randint(0, len(data) - 8)
        length = random.randint(4, min(32, len(data) - start))
        section = data[start:start+length]
        data[start:start+length] = section[::-1]
        return data


class FuzzingPayload(PayloadGenerator):
    """
    Generate fuzzing payloads for vulnerability testing.
    
    Includes:
    - Buffer overflow patterns
    - Format string attacks
    - Integer overflow values
    - Boundary conditions
    """
    
    # Fuzzing patterns
    OVERFLOW_PATTERNS = [
        b'A' * 256,
        b'A' * 1024,
        b'A' * 4096,
        b'A' * 10000,
        b'\x00' * 1024,
        b'\xff' * 1024,
    ]
    
    FORMAT_STRINGS = [
        b'%s' * 100,
        b'%n' * 50,
        b'%x' * 100,
        b'%p' * 100,
        b'%.1000d',
        b'%99999999s',
    ]
    
    INTEGER_VALUES = [
        struct.pack('<I', 0),
        struct.pack('<I', 0xffffffff),
        struct.pack('<I', 0x7fffffff),
        struct.pack('<I', 0x80000000),
        struct.pack('<i', -1),
        struct.pack('<Q', 0xffffffffffffffff),
    ]
    
    BOUNDARY_VALUES = [
        b'\x00',
        b'\xff',
        b'\x00\x00',
        b'\xff\xff',
        b'\x7f',
        b'\x80',
    ]
    
    SPECIAL_CHARS = [
        b"'",
        b'"',
        b'`',
        b'\\',
        b'\n',
        b'\r\n',
        b'\x00',
        b'<script>',
        b'../../../',
        b'|',
        b';',
        b'&',
    ]
    
    def __init__(self, config: PayloadConfig, fuzz_type: str = 'all'):
        super().__init__(config)
        self.fuzz_type = fuzz_type
        self._patterns = self._build_patterns()
        
    def _build_patterns(self) -> List[bytes]:
        """Build fuzzing pattern list"""
        patterns = []
        
        if self.fuzz_type in ('all', 'overflow'):
            patterns.extend(self.OVERFLOW_PATTERNS)
        if self.fuzz_type in ('all', 'format'):
            patterns.extend(self.FORMAT_STRINGS)
        if self.fuzz_type in ('all', 'integer'):
            patterns.extend(self.INTEGER_VALUES)
        if self.fuzz_type in ('all', 'boundary'):
            patterns.extend(self.BOUNDARY_VALUES)
        if self.fuzz_type in ('all', 'special'):
            patterns.extend(self.SPECIAL_CHARS)
            
        return patterns
        
    def generate(self) -> bytes:
        # Select base pattern
        pattern = random.choice(self._patterns)
        
        # Optionally combine patterns
        if random.random() < 0.3:
            pattern = pattern + random.choice(self._patterns)
            
        # Add random prefix/suffix
        if random.random() < 0.5:
            prefix = bytes(random.randint(0, 255) for _ in range(random.randint(1, 16)))
            pattern = prefix + pattern
            
        if random.random() < 0.5:
            suffix = bytes(random.randint(0, 255) for _ in range(random.randint(1, 16)))
            pattern = pattern + suffix
            
        self._generated += 1
        return self._apply_encoding(pattern)


class ProtocolPayload(PayloadGenerator):
    """
    Generate protocol-specific payloads.
    
    Supports:
    - HTTP payloads
    - DNS payloads
    - TCP/UDP payloads
    - Custom protocols
    """
    
    def __init__(self, config: PayloadConfig, protocol: str = 'http'):
        super().__init__(config)
        self.protocol = protocol
        
    def generate(self) -> bytes:
        if self.protocol == 'http':
            return self._generate_http()
        elif self.protocol == 'dns':
            return self._generate_dns()
        elif self.protocol == 'sip':
            return self._generate_sip()
        elif self.protocol == 'smtp':
            return self._generate_smtp()
        else:
            return self._generate_generic()
            
    def _generate_http(self) -> bytes:
        """Generate HTTP request payload"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
        paths = ['/', '/index.html', '/api/v1/data', '/search', '/admin']
        
        method = random.choice(methods)
        path = random.choice(paths)
        
        # Add random query params
        if random.random() < 0.5:
            params = '&'.join(f"p{i}={random.randint(1,9999)}" for i in range(random.randint(1, 5)))
            path += f"?{params}"
            
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: target{random.randint(1,999)}.example.com\r\n"
        request += f"User-Agent: Mozilla/5.0 (Test/{random.randint(1,100)})\r\n"
        request += f"Accept: */*\r\n"
        request += f"X-Request-ID: {hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}\r\n"
        
        if method == 'POST':
            body = ''.join(random.choices(string.ascii_letters, k=random.randint(10, 100)))
            request += f"Content-Length: {len(body)}\r\n"
            request += f"Content-Type: application/x-www-form-urlencoded\r\n"
            request += f"\r\n{body}"
        else:
            request += "\r\n"
            
        self._generated += 1
        return request.encode()
        
    def _generate_dns(self) -> bytes:
        """Generate DNS query payload"""
        # Transaction ID
        tid = struct.pack('>H', random.randint(0, 65535))
        
        # Flags: Standard query, recursion desired
        flags = struct.pack('>H', 0x0100)
        
        # Counts
        counts = struct.pack('>HHHH', 1, 0, 0, 0)
        
        # Random domain
        labels = [
            ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 10)))
            for _ in range(random.randint(2, 4))
        ]
        
        qname = b''
        for label in labels:
            qname += bytes([len(label)]) + label.encode()
        qname += b'\x00'
        
        # Query type (A, AAAA, MX, TXT, ANY)
        qtypes = [1, 28, 15, 16, 255]
        qtype = struct.pack('>HH', random.choice(qtypes), 1)
        
        self._generated += 1
        return tid + flags + counts + qname + qtype
        
    def _generate_sip(self) -> bytes:
        """Generate SIP request payload"""
        methods = ['INVITE', 'REGISTER', 'OPTIONS', 'BYE', 'CANCEL']
        method = random.choice(methods)
        
        call_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
        
        request = f"{method} sip:user@target.example.com SIP/2.0\r\n"
        request += f"Via: SIP/2.0/UDP client.example.com:5060\r\n"
        request += f"From: <sip:caller@example.com>;tag={random.randint(1000,9999)}\r\n"
        request += f"To: <sip:user@target.example.com>\r\n"
        request += f"Call-ID: {call_id}@client.example.com\r\n"
        request += f"CSeq: {random.randint(1, 1000)} {method}\r\n"
        request += f"Content-Length: 0\r\n"
        request += "\r\n"
        
        self._generated += 1
        return request.encode()
        
    def _generate_smtp(self) -> bytes:
        """Generate SMTP command payload"""
        commands = [
            f"EHLO test{random.randint(1,999)}.example.com\r\n",
            f"MAIL FROM:<test{random.randint(1,999)}@example.com>\r\n",
            f"RCPT TO:<user{random.randint(1,999)}@target.com>\r\n",
            "VRFY root\r\n",
            "EXPN users\r\n",
            "NOOP\r\n",
        ]
        
        self._generated += 1
        return random.choice(commands).encode()
        
    def _generate_generic(self) -> bytes:
        """Generate generic payload"""
        size = random.randint(self.config.min_size, self.config.max_size)
        self._generated += 1
        return bytes(random.randint(0, 255) for _ in range(size))


class EvasionPayload(PayloadGenerator):
    """
    Generate evasion-optimized payloads.
    
    Designed to bypass:
    - Signature-based detection
    - Pattern matching
    - Rate limiting
    """
    
    def __init__(self, config: PayloadConfig):
        super().__init__(config)
        self._encoders = [
            self._xor_encode,
            self._base64_chunks,
            self._unicode_encode,
            self._null_insertion,
            self._case_variation,
        ]
        
    def generate(self) -> bytes:
        # Generate base payload
        size = random.randint(self.config.min_size, self.config.max_size)
        data = bytes(random.randint(0, 255) for _ in range(size))
        
        # Apply 1-2 evasion techniques
        for encoder in random.sample(self._encoders, random.randint(1, 2)):
            data = encoder(data)
            
        self._generated += 1
        return self._apply_encoding(data)
        
    def _xor_encode(self, data: bytes) -> bytes:
        """XOR encode with random key"""
        key = random.randint(1, 255)
        encoded = bytes(b ^ key for b in data)
        # Prepend key
        return bytes([key]) + encoded
        
    def _base64_chunks(self, data: bytes) -> bytes:
        """Base64 encode in chunks"""
        chunk_size = random.randint(10, 50)
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        encoded_chunks = [base64.b64encode(chunk) for chunk in chunks]
        return b'|'.join(encoded_chunks)
        
    def _unicode_encode(self, data: bytes) -> bytes:
        """Unicode escape encoding"""
        result = b''
        for byte in data:
            if random.random() < 0.3:
                result += f'\\x{byte:02x}'.encode()
            else:
                result += bytes([byte])
        return result
        
    def _null_insertion(self, data: bytes) -> bytes:
        """Insert null bytes"""
        result = bytearray()
        for byte in data:
            result.append(byte)
            if random.random() < 0.1:
                result.append(0)
        return bytes(result)
        
    def _case_variation(self, data: bytes) -> bytes:
        """Vary case for text payloads"""
        try:
            text = data.decode('utf-8', errors='ignore')
            varied = ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in text
            )
            return varied.encode()
        except Exception:
            return data


class PayloadFactory:
    """Factory for creating payload generators"""
    
    @staticmethod
    def create(payload_type: PayloadType, config: PayloadConfig = None, **kwargs) -> PayloadGenerator:
        """Create payload generator by type"""
        config = config or PayloadConfig(payload_type=payload_type)
        
        generators = {
            PayloadType.RANDOM: RandomPayload,
            PayloadType.PATTERN: PatternPayload,
            PayloadType.POLYMORPHIC: PolymorphicPayload,
            PayloadType.FUZZING: FuzzingPayload,
            PayloadType.PROTOCOL: ProtocolPayload,
            PayloadType.EVASION: EvasionPayload,
        }
        
        generator_class = generators.get(payload_type, RandomPayload)
        return generator_class(config, **kwargs)
