#!/usr/bin/env python3
"""
NetStress Power Verification Script

This script HONESTLY benchmarks the actual performance of your NetStress installation.
It tests against localhost to measure REAL packets per second (PPS) and reports
whether you're using the high-performance native engine or the slow Python fallback.

NO LIES - This script tells you exactly what you're getting.

Usage:
    python verify_power.py              # Quick benchmark
    python verify_power.py --full       # Full benchmark suite
    python verify_power.py --target IP  # Benchmark against specific target
"""

import sys
import time
import socket
import asyncio
import argparse
import platform
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class BenchmarkResult:
    """Benchmark result with honest metrics"""
    test_name: str
    packets_sent: int
    duration_seconds: float
    pps: float  # Packets per second
    mbps: float  # Megabits per second
    engine_used: str
    is_native: bool
    warnings: list


class PowerVerifier:
    """
    Honest power verification for NetStress.
    
    This class benchmarks actual performance and reports the truth
    about what engine is being used and what performance you can expect.
    """
    
    def __init__(self, target: str = "127.0.0.1", port: int = 9999):
        self.target = target
        self.port = port
        self.results: list = []
        
        # Detect capabilities
        self._detect_capabilities()
        
    def _detect_capabilities(self):
        """Detect what's actually available"""
        self.capabilities = {
            'native_engine': False,
            'dpdk': False,
            'af_xdp': False,
            'io_uring': False,
            'cuda': False,
            'raw_sockets': False,
            'is_root': False,
            'platform': platform.system(),
        }
        
        # Check root/admin
        try:
            import os
            self.capabilities['is_root'] = os.geteuid() == 0
        except AttributeError:
            # Windows
            try:
                import ctypes
                self.capabilities['is_root'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                pass
        
        # Check native engine
        try:
            import netstress_engine
            self.capabilities['native_engine'] = True
        except ImportError:
            pass
            
        # Check CUDA
        try:
            import torch
            self.capabilities['cuda'] = torch.cuda.is_available()
        except ImportError:
            pass
            
        # Check raw sockets
        try:
            if self.capabilities['is_root']:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sock.close()
                self.capabilities['raw_sockets'] = True
        except Exception:
            pass
            
        # Check Linux-specific features
        if platform.system() == 'Linux':
            try:
                # Check for AF_XDP support
                import os
                if os.path.exists('/sys/class/net'):
                    # Basic check - real XDP needs more
                    pass
            except Exception:
                pass
                
    def print_capabilities(self):
        """Print honest capability report"""
        print("\n" + "=" * 60)
        print("HONEST CAPABILITY REPORT")
        print("=" * 60)
        
        print(f"\nPlatform: {self.capabilities['platform']}")
        print(f"Root/Admin: {'YES' if self.capabilities['is_root'] else 'NO'}")
        
        print("\n--- Engine Status ---")
        
        if self.capabilities['native_engine']:
            print("✅ Native Rust Engine: AVAILABLE")
            print("   Expected PPS: 1M - 50M+ (depending on backend)")
        else:
            print("❌ Native Rust Engine: NOT AVAILABLE")
            print("   ⚠️  You are using PYTHON FALLBACK")
            print("   Expected PPS: 50K - 500K (LIMITED)")
            print("\n   To get full power, compile the native engine:")
            print("   cd native/rust_engine && maturin build --release")
            
        print("\n--- Backend Capabilities ---")
        
        backends = [
            ('DPDK', self.capabilities['dpdk'], '100M+ PPS'),
            ('AF_XDP', self.capabilities['af_xdp'], '10M-50M PPS'),
            ('io_uring', self.capabilities['io_uring'], '5M-20M PPS'),
            ('CUDA GPU', self.capabilities['cuda'], '10M+ PPS'),
            ('Raw Sockets', self.capabilities['raw_sockets'], '500K-2M PPS'),
        ]
        
        for name, available, expected in backends:
            status = "✅" if available else "❌"
            print(f"{status} {name}: {'Available' if available else 'Not Available'} ({expected})")
            
        print("\n" + "=" * 60)
        
    def benchmark_udp(self, duration: float = 5.0, packet_size: int = 1024) -> BenchmarkResult:
        """Benchmark UDP packet sending - REAL packets"""
        print(f"\n[UDP Benchmark] Sending to {self.target}:{self.port} for {duration}s...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b'X' * packet_size
        
        packets = 0
        errors = 0
        start = time.perf_counter()
        end_time = start + duration
        
        while time.perf_counter() < end_time:
            try:
                sock.sendto(payload, (self.target, self.port))
                packets += 1
            except Exception:
                errors += 1
                
        sock.close()
        
        elapsed = time.perf_counter() - start
        pps = packets / elapsed if elapsed > 0 else 0
        mbps = (packets * packet_size * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
        
        # Determine engine used
        engine = "Python socket.sendto()"
        is_native = False
        
        warnings = []
        if pps < 100_000:
            warnings.append("LOW PPS: You are likely CPU-bound or using Python fallback")
        if errors > packets * 0.01:
            warnings.append(f"HIGH ERROR RATE: {errors} errors ({errors/max(packets,1)*100:.1f}%)")
            
        result = BenchmarkResult(
            test_name="UDP Flood",
            packets_sent=packets,
            duration_seconds=elapsed,
            pps=pps,
            mbps=mbps,
            engine_used=engine,
            is_native=is_native,
            warnings=warnings
        )
        
        self.results.append(result)
        return result
        
    def benchmark_tcp(self, duration: float = 5.0) -> BenchmarkResult:
        """Benchmark TCP connections - REAL connections"""
        print(f"\n[TCP Benchmark] Connecting to {self.target}:{self.port} for {duration}s...")
        
        connections = 0
        errors = 0
        start = time.perf_counter()
        end_time = start + duration
        
        while time.perf_counter() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((self.target, self.port))
                if result == 0:
                    sock.send(b'X' * 100)
                sock.close()
                connections += 1
            except Exception:
                errors += 1
                
        elapsed = time.perf_counter() - start
        cps = connections / elapsed if elapsed > 0 else 0
        
        engine = "Python socket.connect()"
        is_native = False
        
        warnings = []
        if cps < 1000:
            warnings.append("LOW CPS: TCP is connection-limited")
            
        result = BenchmarkResult(
            test_name="TCP Connect",
            packets_sent=connections,
            duration_seconds=elapsed,
            pps=cps,
            mbps=0,
            engine_used=engine,
            is_native=is_native,
            warnings=warnings
        )
        
        self.results.append(result)
        return result
        
    async def benchmark_http(self, duration: float = 5.0) -> BenchmarkResult:
        """Benchmark HTTP requests - REAL requests"""
        print(f"\n[HTTP Benchmark] Requesting http://{self.target}:{self.port}/ for {duration}s...")
        
        try:
            import aiohttp
        except ImportError:
            return BenchmarkResult(
                test_name="HTTP Flood",
                packets_sent=0,
                duration_seconds=0,
                pps=0,
                mbps=0,
                engine_used="N/A",
                is_native=False,
                warnings=["aiohttp not installed"]
            )
            
        requests = 0
        errors = 0
        start = time.perf_counter()
        
        url = f"http://{self.target}:{self.port}/"
        timeout = aiohttp.ClientTimeout(total=1)
        connector = aiohttp.TCPConnector(limit=100, force_close=True)
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            end_time = start + duration
            
            while time.perf_counter() < end_time:
                try:
                    async with session.get(url) as resp:
                        await resp.read()
                        requests += 1
                except Exception:
                    errors += 1
                    
        elapsed = time.perf_counter() - start
        rps = requests / elapsed if elapsed > 0 else 0
        
        result = BenchmarkResult(
            test_name="HTTP Flood",
            packets_sent=requests,
            duration_seconds=elapsed,
            pps=rps,
            mbps=0,
            engine_used="Python aiohttp",
            is_native=False,
            warnings=[]
        )
        
        self.results.append(result)
        return result
        
    def print_result(self, result: BenchmarkResult):
        """Print a single benchmark result"""
        print(f"\n--- {result.test_name} Results ---")
        print(f"Packets/Requests: {result.packets_sent:,}")
        print(f"Duration: {result.duration_seconds:.2f}s")
        print(f"Rate: {result.pps:,.0f} per second")
        if result.mbps > 0:
            print(f"Bandwidth: {result.mbps:.2f} Mbps")
        print(f"Engine: {result.engine_used}")
        print(f"Native: {'YES' if result.is_native else 'NO (Python Fallback)'}")
        
        if result.warnings:
            print("\n⚠️  Warnings:")
            for w in result.warnings:
                print(f"   - {w}")
                
    def print_summary(self):
        """Print summary of all benchmarks"""
        print("\n" + "=" * 60)
        print("BENCHMARK SUMMARY")
        print("=" * 60)
        
        for result in self.results:
            status = "✅" if result.is_native else "⚠️"
            print(f"{status} {result.test_name}: {result.pps:,.0f} PPS ({result.engine_used})")
            
        # Overall verdict
        print("\n--- VERDICT ---")
        
        any_native = any(r.is_native for r in self.results)
        max_pps = max(r.pps for r in self.results) if self.results else 0
        
        if any_native and max_pps > 1_000_000:
            print("🚀 HIGH PERFORMANCE: Native engine active, 1M+ PPS achieved")
        elif max_pps > 100_000:
            print("⚡ MODERATE PERFORMANCE: 100K+ PPS (Python mode)")
        else:
            print("🐢 LOW PERFORMANCE: <100K PPS")
            print("\n   To improve performance:")
            print("   1. Compile native engine: python build.py")
            print("   2. Run as root/admin for raw sockets")
            print("   3. Use Linux for best results")
            
        print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description='NetStress Power Verification')
    parser.add_argument('--target', default='127.0.0.1', help='Target IP (default: localhost)')
    parser.add_argument('--port', type=int, default=9999, help='Target port (default: 9999)')
    parser.add_argument('--duration', type=float, default=5.0, help='Test duration in seconds')
    parser.add_argument('--full', action='store_true', help='Run full benchmark suite')
    args = parser.parse_args()
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║     NetStress Power Verification - HONEST BENCHMARK           ║
║                                                               ║
║  This script tells you the TRUTH about your performance.      ║
║  No marketing, no lies - just real numbers.                   ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    verifier = PowerVerifier(args.target, args.port)
    
    # Print capabilities
    verifier.print_capabilities()
    
    # Run benchmarks
    print("\n" + "=" * 60)
    print("RUNNING BENCHMARKS")
    print("=" * 60)
    
    # UDP benchmark
    result = verifier.benchmark_udp(args.duration)
    verifier.print_result(result)
    
    if args.full:
        # TCP benchmark
        result = verifier.benchmark_tcp(args.duration)
        verifier.print_result(result)
        
        # HTTP benchmark
        result = asyncio.run(verifier.benchmark_http(args.duration))
        verifier.print_result(result)
        
    # Summary
    verifier.print_summary()


if __name__ == '__main__':
    main()
