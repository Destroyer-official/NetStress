#!/usr/bin/env python3
"""
Honest Capability Reporting

This module provides truthful reporting of what NetStress can actually do.
No exaggerated claims, no simulated features - just honest capabilities.
"""

import os
import sys
import socket
import platform
import ctypes
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CapabilityReport:
    """
    Honest report of NetStress capabilities.
    
    This tells you exactly what the tool can and cannot do.
    """
    # Platform info
    platform: str = ""
    platform_version: str = ""
    python_version: str = ""
    is_root: bool = False
    
    # REAL capabilities that ARE implemented
    udp_flood: bool = True  # Always available
    tcp_flood: bool = True  # Always available
    http_flood: bool = True  # Always available
    
    # System call availability
    sendfile: bool = False
    msg_zerocopy: bool = False
    sendmmsg: bool = False
    raw_sockets: bool = False
    
    # Socket optimizations (always available)
    socket_buffer_tuning: bool = True
    tcp_nodelay: bool = True
    so_reuseaddr: bool = True
    so_reuseport: bool = False
    
    # Kernel optimizations (require root)
    sysctl_tuning: bool = False
    
    # Features that are NOT implemented (honest)
    xdp: bool = False
    ebpf: bool = False
    dpdk: bool = False
    kernel_bypass: bool = False
    af_xdp: bool = False
    io_uring: bool = False
    
    # Performance expectations (honest)
    expected_udp_pps: str = ""
    expected_tcp_cps: str = ""
    expected_bandwidth: str = ""
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


class CapabilityChecker:
    """
    Checks and reports actual system capabilities.
    """
    
    def __init__(self):
        self.platform = platform.system()
        self.platform_version = platform.release()
        self.python_version = platform.python_version()
        self.is_root = self._check_root()
    
    def _check_root(self) -> bool:
        """Check for root/admin privileges"""
        if self.platform == 'Windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0
    
    def _check_sendfile(self) -> bool:
        """Check if sendfile() is available"""
        return hasattr(os, 'sendfile')
    
    def _check_msg_zerocopy(self) -> bool:
        """Check if MSG_ZEROCOPY is available (Linux 4.14+)"""
        if self.platform != 'Linux':
            return False
        
        if not hasattr(socket, 'MSG_ZEROCOPY'):
            return False
        
        try:
            parts = self.platform_version.split('.')
            major = int(parts[0])
            minor = int(parts[1].split('-')[0])
            return (major > 4) or (major == 4 and minor >= 14)
        except Exception:
            return False
    
    def _check_sendmmsg(self) -> bool:
        """Check if sendmmsg() is available"""
        if self.platform != 'Linux':
            return False
        
        try:
            libc = ctypes.CDLL('libc.so.6', use_errno=True)
            return hasattr(libc, 'sendmmsg')
        except Exception:
            return False
    
    def _check_raw_sockets(self) -> bool:
        """Check if raw sockets are available"""
        if not self.is_root:
            return False
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.close()
            return True
        except Exception:
            return False
    
    def _check_so_reuseport(self) -> bool:
        """Check if SO_REUSEPORT is available"""
        return hasattr(socket, 'SO_REUSEPORT')
    
    def _get_performance_expectations(self) -> Dict[str, str]:
        """
        Get honest performance expectations based on platform.
        
        These are realistic ranges, not marketing claims.
        """
        if self.platform == 'Linux':
            if self.is_root and self._check_sendmmsg():
                return {
                    'udp_pps': '500K-2M PPS (with sendmmsg)',
                    'tcp_cps': '10K-50K connections/sec',
                    'bandwidth': '1-10 Gbps (depends on NIC)'
                }
            else:
                return {
                    'udp_pps': '100K-500K PPS',
                    'tcp_cps': '5K-20K connections/sec',
                    'bandwidth': '500 Mbps - 5 Gbps'
                }
        elif self.platform == 'Windows':
            return {
                'udp_pps': '50K-200K PPS (Windows networking overhead)',
                'tcp_cps': '2K-10K connections/sec',
                'bandwidth': '100 Mbps - 2 Gbps'
            }
        else:  # macOS
            return {
                'udp_pps': '100K-300K PPS',
                'tcp_cps': '5K-15K connections/sec',
                'bandwidth': '500 Mbps - 3 Gbps'
            }
    
    def get_report(self) -> CapabilityReport:
        """
        Generate an honest capability report.
        """
        perf = self._get_performance_expectations()
        
        report = CapabilityReport(
            platform=self.platform,
            platform_version=self.platform_version,
            python_version=self.python_version,
            is_root=self.is_root,
            
            # Real capabilities
            sendfile=self._check_sendfile(),
            msg_zerocopy=self._check_msg_zerocopy(),
            sendmmsg=self._check_sendmmsg(),
            raw_sockets=self._check_raw_sockets(),
            so_reuseport=self._check_so_reuseport(),
            sysctl_tuning=self.is_root and self.platform == 'Linux',
            
            # NOT implemented - always false
            xdp=False,
            ebpf=False,
            dpdk=False,
            kernel_bypass=False,
            af_xdp=False,
            io_uring=False,
            
            # Performance expectations
            expected_udp_pps=perf['udp_pps'],
            expected_tcp_cps=perf['tcp_cps'],
            expected_bandwidth=perf['bandwidth'],
        )
        
        # Add recommendations
        report.recommendations = self._get_recommendations()
        report.limitations = self._get_limitations()
        
        return report
    
    def _get_recommendations(self) -> List[str]:
        """Get recommendations for improving performance"""
        recs = []
        
        if not self.is_root:
            recs.append("Run with root/admin privileges for additional optimizations")
        
        if self.platform == 'Linux':
            recs.append("Use Linux for best performance (sendmmsg, MSG_ZEROCOPY)")
            if not self._check_sendmmsg():
                recs.append("Upgrade to newer kernel for sendmmsg support")
        
        recs.extend([
            "For kernel bypass (10+ Gbps), use DPDK: https://www.dpdk.org/",
            "For XDP packet processing, use xdp-tools: https://github.com/xdp-project/xdp-tools",
            "For high-performance capture, use PF_RING: https://www.ntop.org/products/packet-capture/pf_ring/",
            "Test on real network interfaces, not localhost, for accurate measurements"
        ])
        
        return recs
    
    def _get_limitations(self) -> List[str]:
        """Get honest limitations of this tool"""
        return [
            "This tool uses standard Python sockets - not kernel bypass",
            "XDP, eBPF, and DPDK are NOT implemented - use external tools for those",
            "Performance is limited by Python GIL and OS networking stack",
            "Localhost tests measure memory copy speed, not real network performance",
            "Maximum realistic throughput: 1-10 Gbps depending on hardware",
            "For 10+ Gbps, you need kernel bypass (DPDK, XDP) which this tool does not provide"
        ]
    
    def print_report(self):
        """Print a human-readable capability report"""
        report = self.get_report()
        
        print("\n" + "="*60)
        print("NetStress Capability Report (HONEST)")
        print("="*60)
        
        print(f"\nPlatform: {report.platform} {report.platform_version}")
        print(f"Python: {report.python_version}")
        print(f"Root/Admin: {report.is_root}")
        
        print("\n--- AVAILABLE FEATURES ---")
        print(f"  UDP Flood: ✓")
        print(f"  TCP Flood: ✓")
        print(f"  HTTP Flood: ✓")
        print(f"  sendfile(): {'✓' if report.sendfile else '✗'}")
        print(f"  MSG_ZEROCOPY: {'✓' if report.msg_zerocopy else '✗'}")
        print(f"  sendmmsg(): {'✓' if report.sendmmsg else '✗'}")
        print(f"  Raw Sockets: {'✓' if report.raw_sockets else '✗'}")
        print(f"  sysctl Tuning: {'✓' if report.sysctl_tuning else '✗'}")
        
        print("\n--- NOT IMPLEMENTED (use external tools) ---")
        print(f"  XDP: ✗ (use xdp-tools)")
        print(f"  eBPF: ✗ (use bcc/libbpf)")
        print(f"  DPDK: ✗ (use dpdk.org)")
        print(f"  Kernel Bypass: ✗")
        
        print("\n--- EXPECTED PERFORMANCE ---")
        print(f"  UDP: {report.expected_udp_pps}")
        print(f"  TCP: {report.expected_tcp_cps}")
        print(f"  Bandwidth: {report.expected_bandwidth}")
        
        print("\n--- LIMITATIONS ---")
        for lim in report.limitations[:3]:
            print(f"  • {lim}")
        
        print("\n" + "="*60 + "\n")


def get_capabilities() -> CapabilityReport:
    """Factory function to get capability report"""
    return CapabilityChecker().get_report()


if __name__ == '__main__':
    CapabilityChecker().print_report()
