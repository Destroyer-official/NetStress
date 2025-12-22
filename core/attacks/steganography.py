"""
Steganography Module

Hides attack traffic within normal-looking data:
- Image-based steganography
- Text-based steganography
- Protocol steganography
- Timing-based covert channels
"""

import random
import struct
import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Iterator
from enum import Enum
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class StegoMethod(Enum):
    """Steganography methods"""
    LSB = "lsb"  # Least Significant Bit
    TEXT_WHITESPACE = "whitespace"
    TEXT_UNICODE = "unicode"
    PROTOCOL_HEADER = "protocol_header"
    TIMING = "timing"
    FREQUENCY = "frequency"


@dataclass
class StegoConfig:
    """Steganography configuration"""
    method: StegoMethod = StegoMethod.LSB
    capacity_ratio: float = 0.1  # Max data to carrier ratio
    redundancy: int = 1  # Repeat encoding for reliability
    encryption: bool = False
    key: Optional[bytes] = None


class StegoEncoder(ABC):
    """Base class for steganography encoders"""
    
    def __init__(self, config: StegoConfig):
        self.config = config
        
    @abstractmethod
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into carrier"""
        pass
        
    @abstractmethod
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from carrier"""
        pass
        
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption"""
        if not key:
            return data
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


class LSBEncoder(StegoEncoder):
    """
    Least Significant Bit Steganography
    
    Hides data in the least significant bits of carrier bytes.
    """
    
    def __init__(self, config: StegoConfig, bits_per_byte: int = 1):
        super().__init__(config)
        self.bits_per_byte = bits_per_byte
        
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into carrier using LSB"""
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        # Add length header
        length_header = struct.pack('>I', len(payload))
        full_payload = length_header + payload
        
        # Convert payload to bits
        payload_bits = []
        for byte in full_payload:
            for i in range(8):
                payload_bits.append((byte >> (7 - i)) & 1)
                
        # Check capacity
        required_bytes = len(payload_bits) // self.bits_per_byte
        if required_bytes > len(carrier):
            raise ValueError(f"Carrier too small: need {required_bytes}, have {len(carrier)}")
            
        # Encode into carrier
        result = bytearray(carrier)
        bit_index = 0
        
        for i in range(len(result)):
            if bit_index >= len(payload_bits):
                break
                
            # Clear LSB(s) and set payload bits
            mask = ~((1 << self.bits_per_byte) - 1) & 0xFF
            result[i] = result[i] & mask
            
            for b in range(self.bits_per_byte):
                if bit_index < len(payload_bits):
                    result[i] |= payload_bits[bit_index] << (self.bits_per_byte - 1 - b)
                    bit_index += 1
                    
        return bytes(result)
        
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from carrier"""
        # Extract bits
        bits = []
        for byte in carrier:
            for b in range(self.bits_per_byte):
                bits.append((byte >> (self.bits_per_byte - 1 - b)) & 1)
                
        # Convert bits to bytes
        extracted = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 > len(bits):
                break
            byte = 0
            for j in range(8):
                byte |= bits[i + j] << (7 - j)
            extracted.append(byte)
            
        if len(extracted) < 4:
            return b''
            
        # Extract length and payload
        length = struct.unpack('>I', bytes(extracted[:4]))[0]
        payload = bytes(extracted[4:4 + length])
        
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        return payload


class WhitespaceEncoder(StegoEncoder):
    """
    Whitespace Steganography
    
    Hides data using invisible whitespace characters in text.
    """
    
    # Invisible characters
    ZERO_CHAR = '\u200b'  # Zero-width space (0)
    ONE_CHAR = '\u200c'   # Zero-width non-joiner (1)
    SEPARATOR = '\u200d'  # Zero-width joiner (separator)
    
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into text carrier"""
        try:
            text = carrier.decode('utf-8')
        except UnicodeDecodeError:
            text = carrier.decode('latin-1')
            
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        # Convert payload to binary string
        binary = ''.join(format(b, '08b') for b in payload)
        
        # Encode as invisible characters
        encoded = ''
        for bit in binary:
            encoded += self.ONE_CHAR if bit == '1' else self.ZERO_CHAR
            
        # Insert at end of text with separator
        result = text + self.SEPARATOR + encoded + self.SEPARATOR
        
        return result.encode('utf-8')
        
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from text carrier"""
        try:
            text = carrier.decode('utf-8')
        except UnicodeDecodeError:
            return b''
            
        # Find encoded section
        parts = text.split(self.SEPARATOR)
        if len(parts) < 3:
            return b''
            
        encoded = parts[1]
        
        # Convert back to binary
        binary = ''
        for char in encoded:
            if char == self.ONE_CHAR:
                binary += '1'
            elif char == self.ZERO_CHAR:
                binary += '0'
                
        # Convert to bytes
        payload = bytearray()
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                payload.append(int(binary[i:i+8], 2))
                
        result = bytes(payload)
        
        if self.config.encryption and self.config.key:
            result = self._xor_encrypt(result, self.config.key)
            
        return result


class UnicodeEncoder(StegoEncoder):
    """
    Unicode Steganography
    
    Hides data using homoglyph substitution and unicode tricks.
    """
    
    # Homoglyph mappings (ASCII -> Unicode lookalikes)
    HOMOGLYPHS = {
        'a': ['а', 'ɑ', 'α'],  # Cyrillic, Latin, Greek
        'e': ['е', 'ε'],
        'o': ['о', 'ο'],
        'p': ['р', 'ρ'],
        'c': ['с', 'ϲ'],
        'x': ['х', 'χ'],
        'y': ['у', 'γ'],
        'i': ['і', 'ι'],
    }
    
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload using homoglyph substitution"""
        try:
            text = carrier.decode('utf-8')
        except UnicodeDecodeError:
            text = carrier.decode('latin-1')
            
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        # Convert payload to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
                
        # Substitute characters based on bits
        result = []
        bit_index = 0
        
        for char in text:
            lower = char.lower()
            if lower in self.HOMOGLYPHS and bit_index < len(bits):
                if bits[bit_index] == 1:
                    # Use homoglyph
                    replacement = random.choice(self.HOMOGLYPHS[lower])
                    result.append(replacement if char.islower() else replacement.upper())
                else:
                    result.append(char)
                bit_index += 1
            else:
                result.append(char)
                
        return ''.join(result).encode('utf-8')
        
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from homoglyph-encoded text"""
        try:
            text = carrier.decode('utf-8')
        except UnicodeDecodeError:
            return b''
            
        # Build reverse mapping
        reverse_map = {}
        for ascii_char, homoglyphs in self.HOMOGLYPHS.items():
            for h in homoglyphs:
                reverse_map[h] = ascii_char
                reverse_map[h.upper()] = ascii_char.upper()
                
        # Extract bits
        bits = []
        for char in text:
            lower = char.lower()
            if lower in self.HOMOGLYPHS:
                bits.append(0)  # Original ASCII
            elif char in reverse_map or char.lower() in reverse_map:
                bits.append(1)  # Homoglyph
                
        # Convert to bytes
        payload = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte |= bits[i + j] << (7 - j)
                payload.append(byte)
                
        result = bytes(payload)
        
        if self.config.encryption and self.config.key:
            result = self._xor_encrypt(result, self.config.key)
            
        return result


class ProtocolHeaderEncoder(StegoEncoder):
    """
    Protocol Header Steganography
    
    Hides data in protocol header fields.
    """
    
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Encode payload into HTTP headers"""
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        # Base64 encode payload
        encoded_payload = base64.b64encode(payload).decode('ascii')
        
        # Split into chunks for different headers
        chunk_size = 32
        chunks = [encoded_payload[i:i+chunk_size] for i in range(0, len(encoded_payload), chunk_size)]
        
        # Create HTTP request with hidden data
        headers = [
            f"GET / HTTP/1.1",
            f"Host: example.com",
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            f"Accept: text/html,application/xhtml+xml",
            f"Accept-Language: en-US,en;q=0.9",
        ]
        
        # Hide data in custom headers
        header_names = ['X-Request-ID', 'X-Correlation-ID', 'X-Trace-ID', 'X-Session-Token']
        for i, chunk in enumerate(chunks):
            if i < len(header_names):
                headers.append(f"{header_names[i]}: {chunk}")
            else:
                headers.append(f"X-Custom-{i}: {chunk}")
                
        headers.append("")
        headers.append("")
        
        return '\r\n'.join(headers).encode('utf-8')
        
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from HTTP headers"""
        try:
            text = carrier.decode('utf-8')
        except UnicodeDecodeError:
            return b''
            
        # Extract custom headers
        chunks = []
        for line in text.split('\r\n'):
            if line.startswith('X-'):
                parts = line.split(': ', 1)
                if len(parts) == 2:
                    chunks.append(parts[1])
                    
        if not chunks:
            return b''
            
        # Combine and decode
        encoded = ''.join(chunks)
        try:
            payload = base64.b64decode(encoded)
        except Exception:
            return b''
            
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        return payload


class TimingEncoder(StegoEncoder):
    """
    Timing-Based Covert Channel
    
    Encodes data in inter-packet timing delays.
    """
    
    def __init__(self, config: StegoConfig, base_delay: float = 0.1, bit_delay: float = 0.05):
        super().__init__(config)
        self.base_delay = base_delay
        self.bit_delay = bit_delay
        
    def encode(self, carrier: bytes, payload: bytes) -> bytes:
        """Generate timing schedule for payload transmission"""
        if self.config.encryption and self.config.key:
            payload = self._xor_encrypt(payload, self.config.key)
            
        # Convert to bits
        bits = []
        for byte in payload:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
                
        # Generate timing schedule
        schedule = []
        for bit in bits:
            if bit == 1:
                delay = self.base_delay + self.bit_delay
            else:
                delay = self.base_delay
            schedule.append(delay)
            
        # Encode schedule as JSON-like structure
        result = {
            'type': 'timing_schedule',
            'base_delay': self.base_delay,
            'bit_delay': self.bit_delay,
            'schedule': schedule
        }
        
        import json
        return json.dumps(result).encode('utf-8')
        
    def decode(self, carrier: bytes) -> bytes:
        """Decode payload from timing measurements"""
        import json
        
        try:
            data = json.loads(carrier.decode('utf-8'))
        except Exception:
            return b''
            
        schedule = data.get('schedule', [])
        base_delay = data.get('base_delay', self.base_delay)
        threshold = base_delay + (self.bit_delay / 2)
        
        # Extract bits from timing
        bits = []
        for delay in schedule:
            bits.append(1 if delay > threshold else 0)
            
        # Convert to bytes
        payload = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte |= bits[i + j] << (7 - j)
                payload.append(byte)
                
        result = bytes(payload)
        
        if self.config.encryption and self.config.key:
            result = self._xor_encrypt(result, self.config.key)
            
        return result
        
    def get_delays(self, payload: bytes) -> List[float]:
        """Get timing delays for payload"""
        encoded = self.encode(b'', payload)
        import json
        data = json.loads(encoded.decode('utf-8'))
        return data.get('schedule', [])


class StegoFactory:
    """Factory for creating steganography encoders"""
    
    @staticmethod
    def create(method: StegoMethod, config: StegoConfig = None, **kwargs) -> StegoEncoder:
        """Create encoder by method"""
        config = config or StegoConfig(method=method)
        
        encoders = {
            StegoMethod.LSB: LSBEncoder,
            StegoMethod.TEXT_WHITESPACE: WhitespaceEncoder,
            StegoMethod.TEXT_UNICODE: UnicodeEncoder,
            StegoMethod.PROTOCOL_HEADER: ProtocolHeaderEncoder,
            StegoMethod.TIMING: TimingEncoder,
        }
        
        encoder_class = encoders.get(method, LSBEncoder)
        return encoder_class(config, **kwargs)


class CovertChannel:
    """
    Covert Communication Channel
    
    Provides high-level interface for covert data transmission.
    """
    
    def __init__(self, method: StegoMethod = StegoMethod.LSB, key: bytes = None):
        config = StegoConfig(method=method, encryption=key is not None, key=key)
        self.encoder = StegoFactory.create(method, config)
        self.method = method
        
    def hide(self, carrier: bytes, secret: bytes) -> bytes:
        """Hide secret data in carrier"""
        return self.encoder.encode(carrier, secret)
        
    def reveal(self, carrier: bytes) -> bytes:
        """Reveal hidden data from carrier"""
        return self.encoder.decode(carrier)
        
    def generate_carrier(self, size: int = 1024) -> bytes:
        """Generate random carrier data"""
        if self.method in [StegoMethod.TEXT_WHITESPACE, StegoMethod.TEXT_UNICODE]:
            # Generate random text
            words = ['the', 'quick', 'brown', 'fox', 'jumps', 'over', 'lazy', 'dog',
                    'hello', 'world', 'test', 'data', 'sample', 'text', 'random']
            text = ' '.join(random.choices(words, k=size // 5))
            return text.encode('utf-8')
        else:
            # Generate random bytes
            return bytes(random.randint(0, 255) for _ in range(size))
