"""
Advanced Protocol Fuzzer

Intelligent protocol fuzzing for discovering vulnerabilities and edge cases.
Uses grammar-based, mutation-based, and generation-based fuzzing techniques.
"""

import os
import random
import struct
import hashlib
import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable, Generator, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class FuzzStrategy(Enum):
    """Fuzzing strategies"""
    RANDOM = auto()          # Pure random mutation
    GRAMMAR = auto()         # Grammar-based generation
    MUTATION = auto()        # Mutate valid inputs
    GENERATION = auto()      # Generate from scratch
    EVOLUTIONARY = auto()    # Genetic algorithm based
    COVERAGE = auto()        # Coverage-guided
    SMART = auto()           # AI-assisted


class MutationType(Enum):
    """Types of mutations"""
    BIT_FLIP = auto()
    BYTE_FLIP = auto()
    ARITHMETIC = auto()
    INTERESTING = auto()
    HAVOC = auto()
    SPLICE = auto()
    INSERT = auto()
    DELETE = auto()
    DUPLICATE = auto()
    SWAP = auto()


@dataclass
class FuzzConfig:
    """Fuzzer configuration"""
    strategy: FuzzStrategy = FuzzStrategy.SMART
    max_iterations: int = 10000
    max_input_size: int = 65535
    min_input_size: int = 1
    mutation_rate: float = 0.1
    crossover_rate: float = 0.3
    population_size: int = 100
    timeout_ms: int = 5000
    save_crashes: bool = True
    crash_dir: str = "crashes"


@dataclass
class FuzzResult:
    """Result of a fuzz test"""
    input_data: bytes
    response: Optional[bytes]
    crashed: bool
    timeout: bool
    error: Optional[str]
    response_time_ms: float
    mutation_history: List[str] = field(default_factory=list)


@dataclass
class CrashInfo:
    """Information about a crash"""
    input_data: bytes
    crash_type: str
    stack_trace: Optional[str]
    timestamp: float
    hash: str


class ProtocolGrammar:
    """Grammar definition for protocol fuzzing"""
    
    def __init__(self):
        self.rules: Dict[str, List[Any]] = {}
        self.terminals: Dict[str, Callable[[], bytes]] = {}
    
    def add_rule(self, name: str, productions: List[Any]):
        """Add a grammar rule"""
        self.rules[name] = productions
    
    def add_terminal(self, name: str, generator: Callable[[], bytes]):
        """Add a terminal symbol generator"""
        self.terminals[name] = generator
    
    def generate(self, start: str = "start", depth: int = 0, max_depth: int = 10) -> bytes:
        """Generate data from grammar"""
        if depth > max_depth:
            return b""
        
        if start in self.terminals:
            return self.terminals[start]()
        
        if start not in self.rules:
            return start.encode() if isinstance(start, str) else start
        
        production = random.choice(self.rules[start])
        
        if isinstance(production, list):
            result = b""
            for item in production:
                result += self.generate(item, depth + 1, max_depth)
            return result
        elif isinstance(production, bytes):
            return production
        elif isinstance(production, str):
            return self.generate(production, depth + 1, max_depth)
        else:
            return b""


class Mutator:
    """Mutation engine for fuzzing"""
    
    # Interesting values for fuzzing
    INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
    INTERESTING_16 = [0, 1, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
    INTERESTING_32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647, 4294967295]
    
    def __init__(self, config: FuzzConfig):
        self.config = config
    
    def mutate(self, data: bytes, mutation_type: Optional[MutationType] = None) -> Tuple[bytes, str]:
        """Apply mutation to data"""
        if not data:
            return os.urandom(random.randint(1, 100)), "random_gen"
        
        if mutation_type is None:
            mutation_type = random.choice(list(MutationType))
        
        mutators = {
            MutationType.BIT_FLIP: self._bit_flip,
            MutationType.BYTE_FLIP: self._byte_flip,
            MutationType.ARITHMETIC: self._arithmetic,
            MutationType.INTERESTING: self._interesting,
            MutationType.HAVOC: self._havoc,
            MutationType.SPLICE: self._splice,
            MutationType.INSERT: self._insert,
            MutationType.DELETE: self._delete,
            MutationType.DUPLICATE: self._duplicate,
            MutationType.SWAP: self._swap,
        }
        
        mutated, desc = mutators[mutation_type](data)
        return mutated, f"{mutation_type.name}:{desc}"
    
    def _bit_flip(self, data: bytes) -> Tuple[bytes, str]:
        """Flip random bits"""
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        data[pos] ^= (1 << bit)
        return bytes(data), f"pos={pos},bit={bit}"
    
    def _byte_flip(self, data: bytes) -> Tuple[bytes, str]:
        """Flip random bytes"""
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        width = random.choice([1, 2, 4])
        for i in range(min(width, len(data) - pos)):
            data[pos + i] ^= 0xFF
        return bytes(data), f"pos={pos},width={width}"
    
    def _arithmetic(self, data: bytes) -> Tuple[bytes, str]:
        """Apply arithmetic operations"""
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        delta = random.randint(-35, 35)
        data[pos] = (data[pos] + delta) % 256
        return bytes(data), f"pos={pos},delta={delta}"
    
    def _interesting(self, data: bytes) -> Tuple[bytes, str]:
        """Insert interesting values"""
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        width = random.choice([1, 2, 4])
        
        if width == 1:
            val = random.choice(self.INTERESTING_8)
            data[pos] = val
        elif width == 2 and pos < len(data) - 1:
            val = random.choice(self.INTERESTING_16)
            data[pos:pos+2] = struct.pack('<H', val)
        elif width == 4 and pos < len(data) - 3:
            val = random.choice(self.INTERESTING_32)
            data[pos:pos+4] = struct.pack('<I', val)
        
        return bytes(data), f"pos={pos},width={width}"
    
    def _havoc(self, data: bytes) -> Tuple[bytes, str]:
        """Apply multiple random mutations"""
        mutations = []
        for _ in range(random.randint(1, 16)):
            mut_type = random.choice([
                MutationType.BIT_FLIP, MutationType.BYTE_FLIP,
                MutationType.ARITHMETIC, MutationType.INTERESTING
            ])
            data, desc = self.mutate(data, mut_type)
            mutations.append(desc)
        return data, f"havoc({len(mutations)})"
    
    def _splice(self, data: bytes) -> Tuple[bytes, str]:
        """Splice with random data"""
        pos = random.randint(0, len(data))
        splice_len = random.randint(1, 100)
        splice_data = os.urandom(splice_len)
        return data[:pos] + splice_data + data[pos:], f"pos={pos},len={splice_len}"
    
    def _insert(self, data: bytes) -> Tuple[bytes, str]:
        """Insert random bytes"""
        pos = random.randint(0, len(data))
        insert_len = random.randint(1, 32)
        insert_data = os.urandom(insert_len)
        return data[:pos] + insert_data + data[pos:], f"pos={pos},len={insert_len}"
    
    def _delete(self, data: bytes) -> Tuple[bytes, str]:
        """Delete random bytes"""
        if len(data) <= 1:
            return data, "skip"
        pos = random.randint(0, len(data) - 1)
        del_len = random.randint(1, min(32, len(data) - pos))
        return data[:pos] + data[pos+del_len:], f"pos={pos},len={del_len}"
    
    def _duplicate(self, data: bytes) -> Tuple[bytes, str]:
        """Duplicate a section"""
        if len(data) < 2:
            return data * 2, "full"
        start = random.randint(0, len(data) - 1)
        length = random.randint(1, min(32, len(data) - start))
        section = data[start:start+length]
        pos = random.randint(0, len(data))
        return data[:pos] + section + data[pos:], f"start={start},len={length}"
    
    def _swap(self, data: bytes) -> Tuple[bytes, str]:
        """Swap two sections"""
        if len(data) < 4:
            return data[::-1], "reverse"
        data = bytearray(data)
        pos1 = random.randint(0, len(data) - 2)
        pos2 = random.randint(pos1 + 1, len(data) - 1)
        data[pos1], data[pos2] = data[pos2], data[pos1]
        return bytes(data), f"pos1={pos1},pos2={pos2}"


class ProtocolFuzzer:
    """Advanced protocol fuzzer"""
    
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.mutator = Mutator(config)
        self.corpus: List[bytes] = []
        self.crashes: List[CrashInfo] = []
        self.coverage: Dict[str, int] = {}
        self.stats = {
            'iterations': 0,
            'crashes': 0,
            'timeouts': 0,
            'unique_crashes': 0
        }
    
    def add_seed(self, data: bytes):
        """Add seed input to corpus"""
        self.corpus.append(data)
    
    def add_seeds_from_file(self, filepath: str):
        """Load seeds from file"""
        with open(filepath, 'rb') as f:
            self.corpus.append(f.read())
    
    def _generate_input(self) -> bytes:
        """Generate fuzz input based on strategy"""
        if self.config.strategy == FuzzStrategy.RANDOM:
            size = random.randint(self.config.min_input_size, self.config.max_input_size)
            return os.urandom(size)
        
        elif self.config.strategy == FuzzStrategy.MUTATION:
            if not self.corpus:
                return os.urandom(random.randint(1, 100))
            base = random.choice(self.corpus)
            mutated, _ = self.mutator.mutate(base)
            return mutated
        
        elif self.config.strategy == FuzzStrategy.SMART:
            # Combine multiple strategies
            if random.random() < 0.3:
                return os.urandom(random.randint(1, 1000))
            elif self.corpus:
                base = random.choice(self.corpus)
                mutated, _ = self.mutator._havoc(base)
                return mutated
            else:
                return os.urandom(random.randint(1, 100))
        
        return os.urandom(random.randint(1, 100))
    
    def _record_crash(self, input_data: bytes, crash_type: str, stack_trace: Optional[str] = None):
        """Record a crash"""
        crash_hash = hashlib.sha256(input_data).hexdigest()[:16]
        
        # Check for duplicate
        for crash in self.crashes:
            if crash.hash == crash_hash:
                return
        
        crash = CrashInfo(
            input_data=input_data,
            crash_type=crash_type,
            stack_trace=stack_trace,
            timestamp=asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0,
            hash=crash_hash
        )
        self.crashes.append(crash)
        self.stats['unique_crashes'] += 1
        
        # Save crash to disk
        if self.config.save_crashes:
            os.makedirs(self.config.crash_dir, exist_ok=True)
            filepath = os.path.join(self.config.crash_dir, f"crash_{crash_hash}.bin")
            with open(filepath, 'wb') as f:
                f.write(input_data)
            logger.info(f"Crash saved: {filepath}")
    
    async def fuzz_target(self, send_func: Callable[[bytes], Any], iterations: Optional[int] = None) -> List[FuzzResult]:
        """Run fuzzing against target"""
        results = []
        max_iter = iterations or self.config.max_iterations
        
        for i in range(max_iter):
            self.stats['iterations'] += 1
            input_data = self._generate_input()
            
            result = FuzzResult(
                input_data=input_data,
                response=None,
                crashed=False,
                timeout=False,
                error=None,
                response_time_ms=0.0
            )
            
            start_time = asyncio.get_event_loop().time()
            
            try:
                response = await asyncio.wait_for(
                    send_func(input_data),
                    timeout=self.config.timeout_ms / 1000
                )
                result.response = response
                result.response_time_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                
            except asyncio.TimeoutError:
                result.timeout = True
                self.stats['timeouts'] += 1
                
            except Exception as e:
                result.crashed = True
                result.error = str(e)
                self.stats['crashes'] += 1
                self._record_crash(input_data, type(e).__name__, str(e))
            
            results.append(result)
            
            # Add interesting inputs to corpus
            if result.response and len(result.response) > 0:
                if random.random() < 0.01:  # 1% chance
                    self.corpus.append(input_data)
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fuzzing statistics"""
        return {
            **self.stats,
            'corpus_size': len(self.corpus),
            'crash_hashes': [c.hash for c in self.crashes]
        }


# Protocol-specific fuzzers

class HTTPFuzzer(ProtocolFuzzer):
    """HTTP protocol fuzzer"""
    
    HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', 
                   b'PATCH', b'TRACE', b'CONNECT', b'PROPFIND', b'PROPPATCH']
    
    def __init__(self, config: FuzzConfig):
        super().__init__(config)
        self._init_http_seeds()
    
    def _init_http_seeds(self):
        """Initialize HTTP-specific seeds"""
        self.add_seed(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.add_seed(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        self.add_seed(b"GET / HTTP/1.0\r\n\r\n")
    
    def generate_http_request(self) -> bytes:
        """Generate fuzzed HTTP request"""
        method = random.choice(self.HTTP_METHODS)
        path = self._fuzz_path()
        version = random.choice([b'HTTP/1.0', b'HTTP/1.1', b'HTTP/2.0', b'HTTP/9.9'])
        headers = self._fuzz_headers()
        body = self._fuzz_body()
        
        request = method + b' ' + path + b' ' + version + b'\r\n'
        request += headers
        request += b'\r\n'
        request += body
        
        return request
    
    def _fuzz_path(self) -> bytes:
        """Generate fuzzed URL path"""
        paths = [
            b'/',
            b'/' + os.urandom(random.randint(1, 100)),
            b'/../' * random.randint(1, 20),
            b'/?' + b'A' * random.randint(1, 10000),
            b'/%00%00%00',
            b'/\x00\x00\x00',
        ]
        return random.choice(paths)
    
    def _fuzz_headers(self) -> bytes:
        """Generate fuzzed HTTP headers"""
        headers = b'Host: localhost\r\n'
        
        # Add random headers
        for _ in range(random.randint(0, 20)):
            name = os.urandom(random.randint(1, 50)).replace(b'\r', b'').replace(b'\n', b'')
            value = os.urandom(random.randint(1, 1000)).replace(b'\r', b'').replace(b'\n', b'')
            headers += name + b': ' + value + b'\r\n'
        
        return headers
    
    def _fuzz_body(self) -> bytes:
        """Generate fuzzed HTTP body"""
        if random.random() < 0.5:
            return b''
        return os.urandom(random.randint(1, 10000))


class DNSFuzzer(ProtocolFuzzer):
    """DNS protocol fuzzer"""
    
    def __init__(self, config: FuzzConfig):
        super().__init__(config)
        self._init_dns_seeds()
    
    def _init_dns_seeds(self):
        """Initialize DNS-specific seeds"""
        # Standard A record query
        self.add_seed(self._build_dns_query(b'example.com', 1, 1))
    
    def _build_dns_query(self, domain: bytes, qtype: int, qclass: int) -> bytes:
        """Build DNS query packet"""
        # Transaction ID
        tid = struct.pack('>H', random.randint(0, 65535))
        # Flags (standard query)
        flags = struct.pack('>H', 0x0100)
        # Questions, Answers, Authority, Additional
        counts = struct.pack('>HHHH', 1, 0, 0, 0)
        
        # Question section
        question = b''
        for label in domain.split(b'.'):
            question += bytes([len(label)]) + label
        question += b'\x00'  # Root label
        question += struct.pack('>HH', qtype, qclass)
        
        return tid + flags + counts + question
    
    def generate_dns_query(self) -> bytes:
        """Generate fuzzed DNS query"""
        # Random transaction ID
        tid = struct.pack('>H', random.randint(0, 65535))
        
        # Fuzzed flags
        flags = struct.pack('>H', random.randint(0, 65535))
        
        # Fuzzed counts
        counts = struct.pack('>HHHH', 
            random.randint(0, 100),
            random.randint(0, 100),
            random.randint(0, 100),
            random.randint(0, 100)
        )
        
        # Fuzzed question
        question = self._fuzz_dns_name()
        question += struct.pack('>HH', random.randint(0, 65535), random.randint(0, 65535))
        
        return tid + flags + counts + question
    
    def _fuzz_dns_name(self) -> bytes:
        """Generate fuzzed DNS name"""
        name = b''
        for _ in range(random.randint(1, 20)):
            label_len = random.randint(0, 63)
            label = os.urandom(label_len)
            name += bytes([label_len]) + label
        name += b'\x00'
        return name


class TCPFuzzer(ProtocolFuzzer):
    """TCP protocol fuzzer (for raw packet fuzzing)"""
    
    def generate_tcp_header(self) -> bytes:
        """Generate fuzzed TCP header"""
        src_port = random.randint(0, 65535)
        dst_port = random.randint(0, 65535)
        seq_num = random.randint(0, 0xFFFFFFFF)
        ack_num = random.randint(0, 0xFFFFFFFF)
        
        # Data offset (4 bits) + Reserved (3 bits) + Flags (9 bits)
        data_offset = random.randint(5, 15) << 12
        flags = random.randint(0, 0x1FF)
        offset_flags = data_offset | flags
        
        window = random.randint(0, 65535)
        checksum = 0  # Will be calculated
        urgent = random.randint(0, 65535)
        
        header = struct.pack('>HHIIHHH',
            src_port, dst_port,
            seq_num, ack_num,
            offset_flags, window,
            checksum
        )
        header += struct.pack('>H', urgent)
        
        # Add random options
        if random.random() < 0.5:
            options_len = random.randint(0, 40)
            header += os.urandom(options_len)
        
        return header


# Factory function
def create_fuzzer(protocol: str, config: Optional[FuzzConfig] = None) -> ProtocolFuzzer:
    """Create protocol-specific fuzzer"""
    config = config or FuzzConfig()
    
    fuzzers = {
        'http': HTTPFuzzer,
        'dns': DNSFuzzer,
        'tcp': TCPFuzzer,
        'generic': ProtocolFuzzer,
    }
    
    fuzzer_class = fuzzers.get(protocol.lower(), ProtocolFuzzer)
    return fuzzer_class(config)


__all__ = [
    'FuzzStrategy', 'MutationType', 'FuzzConfig', 'FuzzResult', 'CrashInfo',
    'ProtocolGrammar', 'Mutator', 'ProtocolFuzzer',
    'HTTPFuzzer', 'DNSFuzzer', 'TCPFuzzer',
    'create_fuzzer',
]
