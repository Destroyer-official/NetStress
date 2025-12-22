#!/usr/bin/env python3
"""
Real Packet Engine - Production Ready

This module provides ACTUAL packet generation and sending capabilities.
Every operation either succeeds and does something real, or fails honestly.

What this module ACTUALLY does:
- Creates real UDP/TCP sockets
- Sends real packets to targets
- Tracks real performance metrics
- Applies socket optimizations

What this module does NOT do:
- Kernel bypass (requires DPDK or similar)
- Raw packet injection without privileges
- Fake performance numbers
"""

import os
import sys
import socket
import time
import platform
import logging
import threading
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import random

logger = logging.getLogger(__name__)


@dataclass
class PacketStats:
    """Real packet statistics"""
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def duration(self) -> float:
        return max(0.001, time.time() - self.start_time)
    
    @property
    def pps(self) -> float:
        return self.packets_sent / self.duration
    
    @property
    def mbps(self) -> float:
        return (self.bytes_sent * 8) / (self.duration * 1_000_000)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'packets_sent': self.packets_sent,
            'bytes_sent': self.bytes_sent,
            'errors': self.errors,
            'duration': round(self.duration, 2),
            'pps': round(self.pps),
            'mbps': round(self.mbps, 2)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PacketStats':
        """Create PacketStats from dictionary"""
        stats = cls()
        stats.packets_sent = data.get('packets_sent', 0)
        stats.bytes_sent = data.get('bytes_sent', 0)
        stats.errors = data.get('errors', 0)
        return stats


@dataclass
class SocketOptimizationResult:
    """Result of socket optimization"""
    optimization: str
    success: bool
    requested_value: Optional[Any] = None
    actual_value: Optional[Any] = None
    error: Optional[str] = None


class RealPerformanceMonitor:
    """Real performance monitoring - no fake numbers"""
    
    def __init__(self):
        self.stats = PacketStats()
        self._lock = threading.Lock()
        self._running = False
        self._start_time = None
        
    def start_measurement(self):
        """Start performance measurement"""
        self._running = True
        self._start_time = time.time()
        self.stats = PacketStats()
        logger.info("Performance measurement started")
    
    def stop_measurement(self):
        """Stop performance measurement"""
        self._running = False
        logger.info("Performance measurement stopped")
    
    def record_packet(self, size: int, success: bool = True):
        """Record a packet send attempt"""
        with self._lock:
            if success:
                self.stats.packets_sent += 1
                self.stats.bytes_sent += size
            else:
                self.stats.errors += 1
    
    def get_measurement(self) -> Dict[str, Any]:
        """Get current measurement results"""
        with self._lock:
            return self.stats.to_dict()
    
    def get_stats(self) -> PacketStats:
        """Get current stats object"""
        return self.stats


class RealPacketEngine:
    """
    Real packet engine - no simulations.
    
    This class provides actual packet sending capabilities using
    standard sockets. It's honest about what it can and cannot do.
    """
    
    def __init__(self, target: str, port: int, protocol: str = 'UDP'):
        self.target = target
        self.port = port
        self.protocol = protocol.upper()
        self.platform = platform.system()
        
        self.socket = None
        self.stats = PacketStats()
        self.monitor = RealPerformanceMonitor()
        self._running = False
        self._lock = threading.Lock()
        
        # Socket optimization results
        self.optimizations: List[SocketOptimizationResult] = []
        
    def initialize(self) -> bool:
        """Initialize the packet engine"""
        try:
            if self.protocol == 'UDP':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.protocol == 'TCP':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                logger.error(f"Unsupported protocol: {self.protocol}")
                return False
            
            # Apply optimizations
            self._apply_socket_optimizations()
            
            # Connect for TCP
            if self.protocol == 'TCP':
                try:
                    self.socket.connect((self.target, self.port))
                except Exception as e:
                    logger.warning(f"TCP connect failed: {e}")
                    return False
            
            logger.info(f"Packet engine initialized: {self.protocol} -> {self.target}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Packet engine initialization failed: {e}")
            return False
    
    def _apply_socket_optimizations(self):
        """Apply socket optimizations and record results"""
        if not self.socket:
            return
        
        # Set non-blocking
        try:
            self.socket.setblocking(False)
            self.optimizations.append(SocketOptimizationResult(
                optimization='non_blocking',
                success=True
            ))
        except Exception as e:
            self.optimizations.append(SocketOptimizationResult(
                optimization='non_blocking',
                success=False,
                error=str(e)
            ))
        
        # Set SO_REUSEADDR
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.optimizations.append(SocketOptimizationResult(
                optimization='SO_REUSEADDR',
                success=True
            ))
        except Exception as e:
            self.optimizations.append(SocketOptimizationResult(
                optimization='SO_REUSEADDR',
                success=False,
                error=str(e)
            ))
        
        # Set send buffer size
        try:
            desired = 16 * 1024 * 1024
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, desired)
            actual = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.optimizations.append(SocketOptimizationResult(
                optimization='SO_SNDBUF',
                success=True,
                requested_value=desired,
                actual_value=actual
            ))
        except Exception as e:
            self.optimizations.append(SocketOptimizationResult(
                optimization='SO_SNDBUF',
                success=False,
                error=str(e)
            ))
        
        # Set receive buffer size
        try:
            desired = 16 * 1024 * 1024
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, desired)
            actual = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.optimizations.append(SocketOptimizationResult(
                optimization='SO_RCVBUF',
                success=True,
                requested_value=desired,
                actual_value=actual
            ))
        except Exception as e:
            self.optimizations.append(SocketOptimizationResult(
                optimization='SO_RCVBUF',
                success=False,
                error=str(e)
            ))
    
    def send_packet(self, data: bytes) -> bool:
        """
        Send a single packet.
        
        Returns True if successful, False otherwise.
        """
        if not self.socket:
            return False
        
        try:
            if self.protocol == 'UDP':
                sent = self.socket.sendto(data, (self.target, self.port))
            else:
                sent = self.socket.send(data)
            
            with self._lock:
                self.stats.packets_sent += 1
                self.stats.bytes_sent += sent
            
            self.monitor.record_packet(sent, True)
            return True
            
        except BlockingIOError:
            # Non-blocking socket would block - not an error
            return False
        except Exception as e:
            with self._lock:
                self.stats.errors += 1
            self.monitor.record_packet(0, False)
            return False
    
    def send_burst(self, data: bytes, count: int) -> int:
        """
        Send a burst of packets.
        
        Returns number of packets successfully sent.
        """
        sent_count = 0
        for _ in range(count):
            if self.send_packet(data):
                sent_count += 1
        return sent_count
    
    def get_stats(self) -> PacketStats:
        """Get current statistics"""
        return self.stats
    
    def get_optimization_results(self) -> List[Dict[str, Any]]:
        """Get socket optimization results"""
        return [
            {
                'optimization': opt.optimization,
                'success': opt.success,
                'requested_value': opt.requested_value,
                'actual_value': opt.actual_value,
                'error': opt.error
            }
            for opt in self.optimizations
        ]
    
    def start(self):
        """Start the packet engine"""
        self._running = True
        self.stats = PacketStats()
        self.monitor.start_measurement()
        logger.info("Packet engine started")
    
    def stop(self):
        """Stop the packet engine"""
        self._running = False
        self.monitor.stop_measurement()
        logger.info("Packet engine stopped")
    
    def is_running(self) -> bool:
        """Check if engine is running"""
        return self._running
    
    def close(self):
        """Close the packet engine and release resources"""
        self._running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
        logger.info("Packet engine closed")
    
    def __enter__(self):
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def create_engine(target: str, port: int, protocol: str = 'UDP') -> RealPacketEngine:
    """Factory function to create a packet engine"""
    engine = RealPacketEngine(target, port, protocol)
    engine.initialize()
    return engine
