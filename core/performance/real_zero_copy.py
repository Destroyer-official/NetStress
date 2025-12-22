#!/usr/bin/env python3
"""
Real Zero-Copy Implementation - Production Ready

This module provides ACTUAL zero-copy networking capabilities.
Every operation either succeeds and does something real, or fails honestly.

What this module ACTUALLY does:
- Uses os.sendfile() for file-to-socket transfers (Linux, macOS)
- Uses MSG_ZEROCOPY socket flag on Linux 4.14+ kernels
- Provides honest capability reporting
- Implements platform-specific optimizations

What this module does NOT do:
- Direct NIC hardware access (requires DPDK)
- True DMA buffer mapping (requires kernel driver)
- Kernel bypass (requires specialized drivers)
"""

import os
import sys
import socket
import platform
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ZeroCopyStatus:
    """Status of zero-copy capabilities on the current platform"""
    platform: str
    kernel_version: str
    sendfile_available: bool = False
    msg_zerocopy_available: bool = False
    splice_available: bool = False
    active_method: str = "buffered"
    is_true_zero_copy: bool = False
    recommendations: list = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'platform': self.platform,
            'kernel_version': self.kernel_version,
            'sendfile_available': self.sendfile_available,
            'msg_zerocopy_available': self.msg_zerocopy_available,
            'splice_available': self.splice_available,
            'active_method': self.active_method,
            'is_true_zero_copy': self.is_true_zero_copy,
            'recommendations': self.recommendations
        }


class RealZeroCopy:
    """
    Real zero-copy implementation - no simulations.
    
    This class provides honest zero-copy capabilities based on
    what the current platform actually supports.
    """
    
    def __init__(self):
        self.platform = platform.system()
        self.kernel_version = platform.release()
        self._status = self._check_capabilities()
        
    def _check_capabilities(self) -> ZeroCopyStatus:
        """Check actual zero-copy capabilities"""
        status = ZeroCopyStatus(
            platform=self.platform,
            kernel_version=self.kernel_version
        )
        
        # Check sendfile availability
        status.sendfile_available = hasattr(os, 'sendfile')
        
        # Check MSG_ZEROCOPY availability (Linux 4.14+)
        status.msg_zerocopy_available = self._check_msg_zerocopy()
        
        # Check splice availability (Linux only)
        status.splice_available = self._check_splice()
        
        # Determine active method
        if status.msg_zerocopy_available:
            status.active_method = "MSG_ZEROCOPY"
            status.is_true_zero_copy = True
        elif status.sendfile_available:
            status.active_method = "sendfile"
            status.is_true_zero_copy = True
        else:
            status.active_method = "buffered"
            status.is_true_zero_copy = False
        
        # Add recommendations
        status.recommendations = self._get_recommendations(status)
        
        return status
    
    def _check_msg_zerocopy(self) -> bool:
        """Check if MSG_ZEROCOPY is available (Linux 4.14+)"""
        if self.platform != 'Linux':
            return False
        
        if not hasattr(socket, 'MSG_ZEROCOPY'):
            return False
        
        try:
            parts = self.kernel_version.split('.')
            major = int(parts[0])
            minor = int(parts[1].split('-')[0])
            return (major > 4) or (major == 4 and minor >= 14)
        except Exception:
            return False
    
    def _check_splice(self) -> bool:
        """Check if splice() is available"""
        if self.platform != 'Linux':
            return False
        
        try:
            import ctypes
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            return hasattr(libc, 'splice')
        except Exception:
            return False
    
    def _get_recommendations(self, status: ZeroCopyStatus) -> list:
        """Get recommendations for better performance"""
        recommendations = []
        
        if not status.sendfile_available:
            recommendations.append(
                "sendfile() not available - file transfers will use buffered I/O"
            )
        
        if not status.msg_zerocopy_available:
            if self.platform == 'Linux':
                recommendations.append(
                    "MSG_ZEROCOPY requires Linux 4.14+ kernel"
                )
            else:
                recommendations.append(
                    f"MSG_ZEROCOPY not available on {self.platform}"
                )
        
        recommendations.append(
            "For true kernel bypass, use external tools: DPDK, XDP-tools, or PF_RING"
        )
        
        return recommendations
    
    def get_status(self) -> ZeroCopyStatus:
        """Get current zero-copy status"""
        return self._status
    
    def optimize_socket(self, sock: socket.socket) -> Dict[str, Any]:
        """
        Apply zero-copy optimizations to a socket.
        
        Returns dict with results of each optimization attempt.
        """
        results = {}
        
        # Set large buffer sizes
        try:
            desired_sndbuf = 16 * 1024 * 1024
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, desired_sndbuf)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            results['SO_SNDBUF'] = {
                'requested': desired_sndbuf,
                'actual': actual,
                'success': True
            }
        except OSError as e:
            results['SO_SNDBUF'] = {'error': str(e), 'success': False}
        
        try:
            desired_rcvbuf = 16 * 1024 * 1024
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, desired_rcvbuf)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            results['SO_RCVBUF'] = {
                'requested': desired_rcvbuf,
                'actual': actual,
                'success': True
            }
        except OSError as e:
            results['SO_RCVBUF'] = {'error': str(e), 'success': False}
        
        # Enable MSG_ZEROCOPY if available (Linux only)
        if self._status.msg_zerocopy_available:
            try:
                SO_ZEROCOPY = 60  # Linux constant
                sock.setsockopt(socket.SOL_SOCKET, SO_ZEROCOPY, 1)
                results['SO_ZEROCOPY'] = {'success': True}
                logger.info("MSG_ZEROCOPY enabled on socket")
            except OSError as e:
                results['SO_ZEROCOPY'] = {'error': str(e), 'success': False}
        
        return results
    
    def sendfile(self, out_fd: int, in_fd: int, offset: int, count: int) -> int:
        """
        Real sendfile() system call - TRUE zero-copy.
        Data goes directly from file to socket in kernel space.
        
        Args:
            out_fd: Output file descriptor (socket)
            in_fd: Input file descriptor (file)
            offset: Offset in input file
            count: Number of bytes to send
            
        Returns:
            Number of bytes sent
            
        Raises:
            NotImplementedError: If sendfile() is not available
        """
        if not self._status.sendfile_available:
            raise NotImplementedError("sendfile() not available on this platform")
        
        return os.sendfile(out_fd, in_fd, offset, count)
    
    def send_zero_copy(self, sock: socket.socket, data: bytes) -> int:
        """
        Send data using zero-copy if available.
        
        Falls back to regular send if zero-copy is not available.
        
        Args:
            sock: Socket to send on
            data: Data to send
            
        Returns:
            Number of bytes sent
        """
        if self._status.msg_zerocopy_available:
            try:
                return sock.send(data, socket.MSG_ZEROCOPY)
            except OSError:
                # Fall back to regular send
                pass
        
        return sock.send(data)


def get_zero_copy() -> RealZeroCopy:
    """Factory function to get the zero-copy handler"""
    return RealZeroCopy()
