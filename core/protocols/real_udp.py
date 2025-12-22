"""Real UDP packet generator using socket.sendto() calls."""

import logging
import random
import socket
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class UDPPacketStats:
    """Statistics for UDP packet generation."""
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_failed: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    @property
    def packets_per_second(self) -> float:
        return self.packets_sent / self.duration if self.duration > 0 else 0.0
    
    @property
    def bytes_per_second(self) -> float:
        return self.bytes_sent / self.duration if self.duration > 0 else 0.0


class RealUDPGenerator:
    """Real UDP packet generator using actual socket operations."""
    
    def __init__(self, target_host: str, target_port: int, source_port: Optional[int] = None):
        self.target_host = target_host
        self.target_port = target_port
        self.source_port = source_port or random.randint(1024, 65535)
        self.socket: Optional[socket.socket] = None
        self.stats = UDPPacketStats()
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def open(self) -> None:
        """Open UDP socket with optimizations."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.source_port:
            self.socket.bind(('', self.source_port))
        self._apply_socket_optimizations()
        logger.info(f"UDP generator opened: {self.target_host}:{self.target_port}")
    
    def close(self) -> None:
        """Close UDP socket."""
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                logger.warning(f"Error closing UDP socket: {e}")
            finally:
                self.socket = None
    
    def _apply_socket_optimizations(self) -> None:
        """Apply socket optimizations."""
        if not self.socket:
            return
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            self.socket.setblocking(False)
        except Exception as e:
            logger.warning(f"Failed to apply socket optimizations: {e}")
    
    def generate_payload(self, size: int, pattern: str = 'random') -> bytes:
        """Generate UDP payload data."""
        if size <= 0:
            return b''
        
        if pattern == 'random':
            return bytes(random.getrandbits(8) for _ in range(size))
        elif pattern == 'zeros':
            return b'\x00' * size
        elif pattern == 'ones':
            return b'\xff' * size
        elif pattern == 'sequence':
            return bytes(i % 256 for i in range(size))
        return bytes(random.getrandbits(8) for _ in range(size))
    
    def send_packet(self, payload: bytes) -> bool:
        """Send a single UDP packet."""
        if not self.socket:
            return False
        
        try:
            bytes_sent = self.socket.sendto(payload, (self.target_host, self.target_port))
            self.stats.packets_sent += 1
            self.stats.bytes_sent += bytes_sent
            return True
        except socket.error as e:
            if e.errno not in (11, 10055):  # EAGAIN, WSAENOBUFS
                logger.warning(f"UDP send failed: {e}")
            self.stats.packets_failed += 1
            return False
    
    def send_burst(self, packet_count: int, payload_size: int,
                   pattern: str = 'random', delay_ms: float = 0) -> UDPPacketStats:
        """Send a burst of UDP packets."""
        if not self.socket:
            raise RuntimeError("Socket not opened")
        
        burst_stats = UDPPacketStats()
        burst_stats.start_time = time.perf_counter()
        
        for _ in range(packet_count):
            payload = self.generate_payload(payload_size, pattern)
            if self.send_packet(payload):
                burst_stats.packets_sent += 1
                burst_stats.bytes_sent += len(payload)
            else:
                burst_stats.packets_failed += 1
            
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
        
        burst_stats.end_time = time.perf_counter()
        logger.info(f"UDP burst: {burst_stats.packets_sent}/{packet_count} sent, "
                   f"{burst_stats.packets_per_second:.1f} PPS")
        return burst_stats
    
    def send_flood(self, duration_seconds: float, payload_size: int,
                   pattern: str = 'random', max_rate_pps: Optional[int] = None) -> UDPPacketStats:
        """Send UDP flood for specified duration."""
        if not self.socket:
            raise RuntimeError("Socket not opened")
        
        flood_stats = UDPPacketStats()
        flood_stats.start_time = time.perf_counter()
        end_time = flood_stats.start_time + duration_seconds
        packet_delay = 1.0 / max_rate_pps if max_rate_pps else 0
        last_packet_time = flood_stats.start_time
        
        while time.perf_counter() < end_time:
            if packet_delay > 0:
                time_since_last = time.perf_counter() - last_packet_time
                if time_since_last < packet_delay:
                    time.sleep(packet_delay - time_since_last)
            
            payload = self.generate_payload(payload_size, pattern)
            if self.send_packet(payload):
                flood_stats.packets_sent += 1
                flood_stats.bytes_sent += len(payload)
            else:
                flood_stats.packets_failed += 1
            
            last_packet_time = time.perf_counter()
        
        flood_stats.end_time = time.perf_counter()
        logger.info(f"UDP flood: {flood_stats.packets_sent} packets, "
                   f"{flood_stats.packets_per_second:.1f} PPS")
        return flood_stats
    
    def get_stats(self) -> UDPPacketStats:
        """Get current statistics."""
        return self.stats


def create_udp_generator(target_host: str, target_port: int,
                        source_port: Optional[int] = None) -> RealUDPGenerator:
    """Factory function to create UDP generator."""
    return RealUDPGenerator(target_host, target_port, source_port)
