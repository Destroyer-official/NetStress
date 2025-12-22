#!/usr/bin/env python3
"""
Real Kernel Optimizations - No Simulations

This module provides ACTUAL kernel optimizations that really work.
Every operation either succeeds and does something real, or fails honestly.

What this module ACTUALLY does:
- Applies sysctl settings on Linux (requires root, verified after application)
- Sets socket options (works on all platforms, no root needed for most)
- Configures Windows registry/netsh settings (requires admin)
- Reports honest capability status

What this module does NOT do (and is honest about it):
- XDP/eBPF (requires C code compilation and BPF loading - use xdp-tools)
- DPDK (requires separate installation and NIC binding - see dpdk.org)
- Kernel bypass (requires specialized drivers)

For true kernel bypass, use external tools:
- DPDK: https://www.dpdk.org/
- XDP-tools: https://github.com/xdp-project/xdp-tools
- PF_RING: https://www.ntop.org/products/packet-capture/pf_ring/
"""

import os
import sys
import platform
import ctypes
import logging
import subprocess
import socket
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class OptimizationResult:
    """Result of an optimization attempt"""
    name: str
    success: bool
    requested_value: str
    actual_value: Optional[str] = None
    error: Optional[str] = None
    requires_root: bool = False


@dataclass
class CapabilityReport:
    """Honest report of available capabilities"""
    platform: str
    is_root: bool
    
    # Real capabilities that ARE implemented
    sysctl_available: bool = False
    socket_options_available: bool = True  # Always available
    sendfile_available: bool = False
    msg_zerocopy_available: bool = False
    sendmmsg_available: bool = False
    
    # Capabilities that are NOT implemented (honest)
    xdp_available: bool = False
    ebpf_available: bool = False
    dpdk_available: bool = False
    kernel_bypass_available: bool = False
    
    # Applied optimizations
    applied: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    
    # Recommendations for users wanting more performance
    recommendations: List[str] = field(default_factory=list)


class RealKernelOptimizer:
    """
    Real kernel optimizations - no simulations, no fake code.
    
    Every method either:
    1. Does something real and verifies it worked
    2. Fails honestly with a clear error message
    3. Skips with explanation if not applicable to platform
    
    User-Space Only Mode:
    When running without root/admin privileges, only socket-level optimizations
    are applied. The following optimizations require root/admin:
    
    Linux (requires root):
    - sysctl network tuning (net.core.*, net.ipv4.*)
    - Raw socket creation (SOCK_RAW)
    - Interface-level optimizations
    
    Windows (requires Administrator):
    - netsh TCP/IP settings
    - Registry network optimizations
    - Raw socket creation
    
    User-space optimizations (no root needed):
    - SO_SNDBUF, SO_RCVBUF (socket buffer sizes)
    - SO_REUSEADDR, SO_REUSEPORT
    - TCP_NODELAY, TCP_QUICKACK
    - Non-blocking socket mode
    """
    
    # Document what requires root for user reference
    ROOT_REQUIRED_OPTIMIZATIONS = {
        'Linux': [
            'sysctl net.core.rmem_max',
            'sysctl net.core.wmem_max',
            'sysctl net.ipv4.tcp_rmem',
            'sysctl net.ipv4.tcp_wmem',
            'sysctl net.core.somaxconn',
            'sysctl net.core.netdev_max_backlog',
            'Raw socket creation (SOCK_RAW)',
            'Interface MTU changes',
            'Traffic control (tc) rules',
        ],
        'Windows': [
            'netsh TCP auto-tuning',
            'netsh RSS settings',
            'Registry TCP/IP parameters',
            'Raw socket creation',
        ],
        'Darwin': [
            'sysctl kern.ipc.maxsockbuf',
            'sysctl net.inet.tcp.*',
            'Raw socket creation',
        ]
    }
    
    USER_SPACE_OPTIMIZATIONS = [
        'SO_SNDBUF (socket send buffer)',
        'SO_RCVBUF (socket receive buffer)',
        'SO_REUSEADDR (address reuse)',
        'SO_REUSEPORT (port reuse, Linux/BSD)',
        'TCP_NODELAY (disable Nagle)',
        'TCP_QUICKACK (immediate ACKs, Linux)',
        'Non-blocking mode',
    ]
    
    def __init__(self):
        self.platform = platform.system()
        self.is_root = self._check_root()
        self.results: List[OptimizationResult] = []
        self._user_space_mode = not self.is_root
        
    def _check_root(self) -> bool:
        """Check if running with root/admin privileges"""
        if self.platform == 'Windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0
    
    def apply_sysctl(self, param: str, value: str) -> OptimizationResult:
        """
        Apply a sysctl setting - REAL implementation.
        
        This actually runs sysctl and verifies the value was set.
        Returns detailed result including what value the kernel accepted.
        """
        result = OptimizationResult(
            name=f"sysctl:{param}",
            success=False,
            requested_value=value,
            requires_root=True
        )
        
        if self.platform != 'Linux':
            result.error = f"sysctl not available on {self.platform}"
            self.results.append(result)
            return result
        
        if not self.is_root:
            result.error = "Requires root privileges. Run with: sudo python ..."
            self.results.append(result)
            return result
        
        try:
            # Actually apply the sysctl
            proc = subprocess.run(
                ['sysctl', '-w', f'{param}={value}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if proc.returncode != 0:
                result.error = proc.stderr.strip() or "sysctl command failed"
                self.results.append(result)
                return result
            
            # Verify it was applied by reading it back
            verify = subprocess.run(
                ['sysctl', '-n', param],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            result.actual_value = verify.stdout.strip()
            
            # Check if value matches (handle multi-value params like tcp_rmem)
            if result.actual_value == value or value in result.actual_value:
                result.success = True
                logger.info(f"Applied sysctl {param}={value} (verified: {result.actual_value})")
            else:
                result.error = f"Kernel accepted different value: {result.actual_value}"
                logger.warning(f"sysctl {param}: requested '{value}', got '{result.actual_value}'")
                
        except subprocess.TimeoutExpired:
            result.error = "Command timed out"
        except FileNotFoundError:
            result.error = "sysctl command not found"
        except Exception as e:
            result.error = str(e)
        
        self.results.append(result)
        return result
    
    def optimize_socket(self, sock: socket.socket, 
                       sndbuf: int = 16 * 1024 * 1024,
                       rcvbuf: int = 16 * 1024 * 1024) -> Dict[str, Any]:
        """
        Apply socket-level optimizations - works on all platforms.
        
        Returns dict with actual values the kernel accepted.
        """
        results = {}
        
        # Set send buffer
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            results['SO_SNDBUF'] = {
                'requested': sndbuf,
                'actual': actual,
                'success': True
            }
            logger.info(f"SO_SNDBUF: requested {sndbuf}, kernel accepted {actual}")
        except OSError as e:
            results['SO_SNDBUF'] = {'error': str(e), 'success': False}
        
        # Set receive buffer
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            results['SO_RCVBUF'] = {
                'requested': rcvbuf,
                'actual': actual,
                'success': True
            }
            logger.info(f"SO_RCVBUF: requested {rcvbuf}, kernel accepted {actual}")
        except OSError as e:
            results['SO_RCVBUF'] = {'error': str(e), 'success': False}
        
        # Set SO_REUSEADDR
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            results['SO_REUSEADDR'] = {'success': True}
        except OSError as e:
            results['SO_REUSEADDR'] = {'error': str(e), 'success': False}
        
        # Set SO_REUSEPORT if available (Linux, BSD)
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                results['SO_REUSEPORT'] = {'success': True}
            except OSError as e:
                results['SO_REUSEPORT'] = {'error': str(e), 'success': False}
        
        return results
    
    def optimize_tcp_socket(self, sock: socket.socket) -> Dict[str, Any]:
        """
        Apply TCP-specific optimizations.
        """
        results = {}
        
        # TCP_NODELAY - disable Nagle's algorithm for low latency
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            results['TCP_NODELAY'] = {'success': True}
        except OSError as e:
            results['TCP_NODELAY'] = {'error': str(e), 'success': False}
        
        # TCP_QUICKACK - send ACKs immediately (Linux only)
        if hasattr(socket, 'TCP_QUICKACK'):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                results['TCP_QUICKACK'] = {'success': True}
            except OSError as e:
                results['TCP_QUICKACK'] = {'error': str(e), 'success': False}
        
        return results
    
    def apply_linux_network_optimizations(self) -> List[OptimizationResult]:
        """
        Apply Linux network stack optimizations via sysctl.
        
        These are REAL optimizations that actually improve performance.
        Each one is verified after application.
        """
        if self.platform != 'Linux':
            logger.info(f"Linux optimizations not applicable on {self.platform}")
            return []
        
        # Real sysctl values that actually improve network performance
        optimizations = {
            # Buffer sizes
            'net.core.rmem_max': '16777216',
            'net.core.wmem_max': '16777216',
            'net.core.rmem_default': '1048576',
            'net.core.wmem_default': '1048576',
            
            # TCP tuning
            'net.ipv4.tcp_rmem': '4096 1048576 16777216',
            'net.ipv4.tcp_wmem': '4096 1048576 16777216',
            'net.ipv4.tcp_fastopen': '3',
            'net.ipv4.tcp_tw_reuse': '1',
            'net.ipv4.tcp_fin_timeout': '15',
            
            # Connection handling
            'net.core.somaxconn': '65535',
            'net.core.netdev_max_backlog': '5000',
            'net.ipv4.tcp_max_syn_backlog': '65535',
            
            # UDP tuning
            'net.ipv4.udp_rmem_min': '8192',
            'net.ipv4.udp_wmem_min': '8192',
        }
        
        results = []
        for param, value in optimizations.items():
            result = self.apply_sysctl(param, value)
            results.append(result)
        
        return results
    
    def apply_windows_optimizations(self) -> List[OptimizationResult]:
        """
        Apply Windows network optimizations via netsh.
        """
        if self.platform != 'Windows':
            return []
        
        results = []
        
        # Windows netsh commands that actually work
        commands = [
            ('netsh int tcp set global autotuninglevel=normal', 'TCP Auto-tuning'),
            ('netsh int tcp set global rss=enabled', 'RSS'),
            ('netsh int tcp set global chimney=disabled', 'TCP Chimney'),  # Often better disabled
            ('netsh int tcp set global ecncapability=enabled', 'ECN'),
        ]
        
        for cmd, name in commands:
            result = OptimizationResult(
                name=f"netsh:{name}",
                success=False,
                requested_value=cmd,
                requires_root=True
            )
            
            if not self.is_root:
                result.error = "Requires Administrator privileges"
                results.append(result)
                continue
            
            try:
                proc = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if proc.returncode == 0:
                    result.success = True
                    result.actual_value = "Applied"
                    logger.info(f"Applied Windows optimization: {name}")
                else:
                    result.error = proc.stderr.strip() or proc.stdout.strip()
                    
            except Exception as e:
                result.error = str(e)
            
            results.append(result)
        
        return results
    
    def get_capability_report(self) -> CapabilityReport:
        """
        Get an HONEST report of what capabilities are available.
        
        This does not lie about XDP, eBPF, or DPDK - they are NOT implemented.
        """
        report = CapabilityReport(
            platform=self.platform,
            is_root=self.is_root
        )
        
        # Check real capabilities
        if self.platform == 'Linux':
            report.sysctl_available = self.is_root
            report.sendfile_available = hasattr(os, 'sendfile')
            report.msg_zerocopy_available = hasattr(socket, 'MSG_ZEROCOPY')
            
            # Check for sendmmsg via libc
            try:
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                report.sendmmsg_available = hasattr(libc, 'sendmmsg')
            except Exception:
                report.sendmmsg_available = False
        
        elif self.platform == 'Darwin':  # macOS
            report.sendfile_available = hasattr(os, 'sendfile')
        
        # These are ALWAYS false - we don't implement them
        report.xdp_available = False
        report.ebpf_available = False
        report.dpdk_available = False
        report.kernel_bypass_available = False
        
        # Collect results
        for result in self.results:
            if result.success:
                report.applied.append(result.name)
            elif result.requires_root and not self.is_root:
                report.skipped.append(f"{result.name} (requires root)")
            else:
                report.failed.append(result.name)
        
        # Add honest recommendations
        report.recommendations = [
            "For kernel bypass networking, use DPDK: https://www.dpdk.org/",
            "For XDP packet processing, use xdp-tools: https://github.com/xdp-project/xdp-tools",
            "For high-performance capture, use PF_RING: https://www.ntop.org/products/packet-capture/pf_ring/",
            "This tool uses standard sockets - expect ~1-5 Gbps on typical hardware",
        ]
        
        if not self.is_root:
            report.recommendations.insert(0, "Run with root/admin for additional optimizations")
        
        return report
    
    def apply_all_optimizations(self) -> CapabilityReport:
        """
        Apply all available optimizations for the current platform.
        Returns honest capability report.
        """
        logger.info(f"Applying optimizations for {self.platform} (root={self.is_root})")
        
        if self.platform == 'Linux':
            self.apply_linux_network_optimizations()
        elif self.platform == 'Windows':
            self.apply_windows_optimizations()
        
        return self.get_capability_report()
    
    def apply_user_space_optimizations(self, sock: socket.socket) -> Dict[str, Any]:
        """
        Apply only user-space optimizations that don't require root/admin.
        
        This is the safe mode when running without elevated privileges.
        All optimizations here work on any platform without special permissions.
        
        Returns dict with results of each optimization attempt.
        """
        results = {}
        
        # Apply general socket optimizations
        socket_results = self.optimize_socket(sock)
        results.update(socket_results)
        
        # Apply TCP-specific if it's a TCP socket
        try:
            # Check if it's a TCP socket by trying to get TCP_NODELAY
            sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
            tcp_results = self.optimize_tcp_socket(sock)
            results.update(tcp_results)
        except OSError:
            # Not a TCP socket, skip TCP optimizations
            pass
        
        logger.info(f"Applied user-space optimizations: {len([r for r in results.values() if isinstance(r, dict) and r.get('success', False)])} successful")
        
        return results
    
    def get_user_space_mode_info(self) -> Dict[str, Any]:
        """
        Get information about user-space only mode.
        
        Returns details about what optimizations are available without root
        and what additional optimizations would be available with root.
        """
        return {
            'is_user_space_mode': self._user_space_mode,
            'is_root': self.is_root,
            'platform': self.platform,
            'available_without_root': self.USER_SPACE_OPTIMIZATIONS,
            'requires_root': self.ROOT_REQUIRED_OPTIMIZATIONS.get(self.platform, []),
            'instructions': self._get_privilege_instructions()
        }
    
    def _get_privilege_instructions(self) -> str:
        """Get platform-specific instructions for gaining elevated privileges."""
        if self.is_root:
            return "Already running with elevated privileges."
        
        if self.platform == 'Linux':
            return (
                "To enable kernel-level optimizations, run with sudo:\n"
                "  sudo python your_script.py\n"
                "Or add your user to appropriate groups for specific capabilities."
            )
        elif self.platform == 'Windows':
            return (
                "To enable system-level optimizations, run as Administrator:\n"
                "  Right-click Command Prompt -> Run as administrator\n"
                "  Then run your script from the elevated prompt."
            )
        elif self.platform == 'Darwin':
            return (
                "To enable kernel-level optimizations, run with sudo:\n"
                "  sudo python your_script.py"
            )
        else:
            return "Run with elevated privileges for additional optimizations."
    
    def check_privilege_for_operation(self, operation: str) -> Tuple[bool, str]:
        """
        Check if current privileges are sufficient for an operation.
        
        Returns (has_privilege, message) tuple.
        - has_privilege: True if operation can proceed
        - message: Explanation or instructions if privilege is insufficient
        
        This method should be called BEFORE attempting privileged operations.
        """
        # Operations that always work
        user_space_ops = [
            'socket_buffer', 'tcp_nodelay', 'tcp_quickack', 
            'so_reuseaddr', 'so_reuseport', 'nonblocking'
        ]
        
        if operation.lower() in user_space_ops:
            return True, "User-space operation, no special privileges needed."
        
        # Operations that require root
        root_ops = [
            'sysctl', 'raw_socket', 'interface_config', 
            'netsh', 'registry', 'traffic_control'
        ]
        
        if operation.lower() in root_ops:
            if self.is_root:
                return True, "Running with elevated privileges."
            else:
                return False, self._get_privilege_instructions()
        
        # Unknown operation - be conservative
        if self.is_root:
            return True, "Running with elevated privileges."
        else:
            return False, f"Unknown operation '{operation}'. {self._get_privilege_instructions()}"


def get_optimizer() -> RealKernelOptimizer:
    """Factory function to get the kernel optimizer"""
    return RealKernelOptimizer()
