"""Real DNS query generator per RFC 1035 specification."""

import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class DNSQueryType(IntEnum):
    """DNS query types per RFC 1035."""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255


class DNSClass(IntEnum):
    """DNS classes per RFC 1035."""
    IN = 1
    CS = 2
    CH = 3
    HS = 4


@dataclass
class DNSQueryStats:
    """Statistics for DNS queries."""
    queries_sent: int = 0
    responses_received: int = 0
    queries_failed: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    response_codes: Dict[int, int] = field(default_factory=dict)
    amplification_ratios: List[float] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    @property
    def queries_per_second(self) -> float:
        return self.queries_sent / self.duration if self.duration > 0 else 0.0
    
    @property
    def success_rate(self) -> float:
        return self.responses_received / self.queries_sent if self.queries_sent > 0 else 0.0
    
    @property
    def average_amplification(self) -> float:
        return sum(self.amplification_ratios) / len(self.amplification_ratios) if self.amplification_ratios else 0.0


class RealDNSGenerator:
    """Real DNS query generator using valid DNS protocol."""
    
    def __init__(self, dns_server: str, dns_port: int = 53, source_port: Optional[int] = None):
        self.dns_server = dns_server
        self.dns_port = dns_port
        self.source_port = source_port or random.randint(1024, 65535)
        self.socket: Optional[socket.socket] = None
        self.stats = DNSQueryStats()
        self.transaction_id = random.randint(1, 65535)
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def open(self) -> None:
        """Open UDP socket for DNS queries."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', self.source_port))
        self.socket.settimeout(5.0)
        logger.info(f"DNS generator opened: {self.dns_server}:{self.dns_port}")
    
    def close(self) -> None:
        """Close DNS socket."""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.warning(f"Error closing DNS socket: {e}")
            finally:
                self.socket = None
    
    def _encode_domain_name(self, domain: str) -> bytes:
        """Encode domain name in DNS format."""
        if not domain:
            return b'\x00'
        
        encoded = b''
        for label in domain.split('.'):
            if len(label) > 63:
                raise ValueError(f"DNS label too long: {label}")
            encoded += bytes([len(label)]) + label.encode('ascii')
        return encoded + b'\x00'
    
    def _create_dns_query(self, domain: str, query_type: DNSQueryType = DNSQueryType.A,
                         query_class: DNSClass = DNSClass.IN, recursion_desired: bool = True) -> bytes:
        """Create DNS query packet per RFC 1035."""
        transaction_id = self.transaction_id
        self.transaction_id = (self.transaction_id + 1) % 65536
        
        flags = 0x0100 if recursion_desired else 0x0000
        
        header = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
        question = self._encode_domain_name(domain) + struct.pack('!HH', int(query_type), int(query_class))
        
        return header + question
    
    def _parse_dns_response(self, response_data: bytes) -> Dict[str, Any]:
        """Parse DNS response packet."""
        if len(response_data) < 12:
            return {'error': 'Response too short'}
        
        try:
            header = struct.unpack('!HHHHHH', response_data[:12])
            return {
                'transaction_id': header[0],
                'response_code': header[1] & 0x000F,
                'answer_count': header[3],
                'authority_count': header[4],
                'additional_count': header[5],
                'size': len(response_data)
            }
        except Exception as e:
            return {'error': f'Parse error: {e}'}
    
    def send_query(self, domain: str, query_type: DNSQueryType = DNSQueryType.A,
                  wait_for_response: bool = True) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Send a single DNS query."""
        if not self.socket:
            return False, None
        
        try:
            query_packet = self._create_dns_query(domain, query_type)
            bytes_sent = self.socket.sendto(query_packet, (self.dns_server, self.dns_port))
            
            self.stats.queries_sent += 1
            self.stats.bytes_sent += bytes_sent
            
            if not wait_for_response:
                return True, None
            
            try:
                response_data, _ = self.socket.recvfrom(4096)
                self.stats.responses_received += 1
                self.stats.bytes_received += len(response_data)
                
                if bytes_sent > 0:
                    self.stats.amplification_ratios.append(len(response_data) / bytes_sent)
                
                response_info = self._parse_dns_response(response_data)
                if 'response_code' in response_info:
                    rcode = response_info['response_code']
                    self.stats.response_codes[rcode] = self.stats.response_codes.get(rcode, 0) + 1
                
                return True, response_info
                
            except socket.timeout:
                self.stats.queries_failed += 1
                return False, None
                
        except Exception as e:
            logger.warning(f"DNS query failed for {domain}: {e}")
            self.stats.queries_failed += 1
            return False, None
    
    def send_amplification_test(self, target_domains: List[str],
                               query_types: Optional[List[DNSQueryType]] = None,
                               queries_per_domain: int = 1) -> DNSQueryStats:
        """Test DNS amplification potential."""
        if not self.socket:
            raise RuntimeError("Socket not opened")
        
        if query_types is None:
            query_types = [DNSQueryType.A, DNSQueryType.ANY, DNSQueryType.TXT]
        
        test_stats = DNSQueryStats()
        test_stats.start_time = time.perf_counter()
        
        for domain in target_domains:
            for query_type in query_types:
                for _ in range(queries_per_domain):
                    success, response = self.send_query(domain, query_type, wait_for_response=True)
                    test_stats.queries_sent += 1
                    if success and response:
                        test_stats.responses_received += 1
                    else:
                        test_stats.queries_failed += 1
        
        test_stats.end_time = time.perf_counter()
        test_stats.bytes_sent = self.stats.bytes_sent
        test_stats.bytes_received = self.stats.bytes_received
        test_stats.amplification_ratios = self.stats.amplification_ratios.copy()
        
        logger.info(f"DNS amplification test: {test_stats.responses_received}/{test_stats.queries_sent} successful, "
                   f"avg amplification {test_stats.average_amplification:.2f}x")
        return test_stats
    
    def send_query_flood(self, domain: str, query_count: int,
                        query_type: DNSQueryType = DNSQueryType.A,
                        delay_ms: float = 0, wait_for_responses: bool = False) -> DNSQueryStats:
        """Send DNS query flood."""
        if not self.socket:
            raise RuntimeError("Socket not opened")
        
        flood_stats = DNSQueryStats()
        flood_stats.start_time = time.perf_counter()
        
        for _ in range(query_count):
            success, response = self.send_query(domain, query_type, wait_for_responses)
            if success:
                flood_stats.queries_sent += 1
                if response:
                    flood_stats.responses_received += 1
            else:
                flood_stats.queries_failed += 1
            
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
        
        flood_stats.end_time = time.perf_counter()
        flood_stats.bytes_sent = self.stats.bytes_sent
        flood_stats.bytes_received = self.stats.bytes_received
        
        logger.info(f"DNS flood: {flood_stats.queries_sent} queries, {flood_stats.queries_per_second:.1f} QPS")
        return flood_stats
    
    def generate_random_subdomain(self, base_domain: str, subdomain_length: int = 8) -> str:
        """Generate random subdomain for varied queries."""
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        subdomain = ''.join(random.choice(chars) for _ in range(subdomain_length))
        return f"{subdomain}.{base_domain}"
    
    def get_stats(self) -> DNSQueryStats:
        """Get current statistics."""
        return self.stats


def create_dns_generator(dns_server: str, dns_port: int = 53,
                        source_port: Optional[int] = None) -> RealDNSGenerator:
    """Factory function to create DNS generator."""
    return RealDNSGenerator(dns_server, dns_port, source_port)
