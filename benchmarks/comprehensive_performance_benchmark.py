#!/usr/bin/env python3
"""
Comprehensive Performance Benchmark Suite

Runs all platform-specific benchmarks and generates unified performance report.
Validates performance targets across all backends.

Requirements: 25 - Performance Benchmarks (all subtasks)
"""

import os
import sys
import time
import json
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import individual benchmarkers
from benchmarks.windows_rio_benchmark import WindowsRIOBenchmarker
from benchmarks.macos_network_framework_benchmark import MacOSNetworkFrameworkBenchmarker
from benchmarks.linux_afxdp_iouring_benchmark import LinuxAFXDPIOUringBenchmarker
from benchmarks.gpu_packet_generation_benchmark import GPUPacketGenerationBenchmarker

@dataclass
class ComprehensiveBenchmarkResult:
    """Comprehensive benchmark result"""
    timestamp: str
    platform: str
    test_duration: float
    
    # Individual benchmark results
    windows_rio_result: Optional[Dict[str, Any]] = None
    macos_network_framework_result: Optional[Dict[str, Any]] = None
    linux_afxdp_iouring_result: Optional[Dict[str, Any]] = None
    gpu_packet_generation_result: Optional[Dict[str, Any]] = None
    
    # Summary metrics
    total_benchmarks_run: int = 0
    benchmarks_passed: int = 0
    benchmarks_failed: int = 0
    
    # Performance summary
    best_pps: float = 0.0
    best_backend: str = "None"
    total_throughput_gbps: float = 0.0
    
    # Target validation
    all_targets_met: bool = False
    performance_grade: str = "FAIL"


class ComprehensivePerformanceBenchmarker:
    """Comprehensive performance benchmarker for all backends"""
    
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 9999):
        self.target_host = target_host
        self.target_port = target_port
        self.current_platform = platform.system()
        
    def run_all_benchmarks(self, duration: float = 10.0, 
                          save_individual_reports: bool = True,
                          output_dir: str = "benchmark_reports") -> ComprehensiveBenchmarkResult:
        """Run all applicable benchmarks for the current platform"""
        
        print(f"\n{'='*80}")
        print(f"  NetStress Comprehensive Performance Benchmark Suite")
        print(f"{'='*80}")
        print(f"Platform: {self.current_platform}")
        print(f"Test Duration: {duration}s per benchmark")
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        
        result = ComprehensiveBenchmarkResult(
            timestamp=datetime.now().isoformat(),
            platform=self.current_platform,
            test_duration=duration
        )
        
        # Run platform-specific benchmarks
        if self.current_platform == "Windows":
            result.windows_rio_result = self._run_windows_rio_benchmark(
                duration, save_individual_reports, output_dir
            )
        elif self.current_platform == "Darwin":
            result.macos_network_framework_result = self._run_macos_network_framework_benchmark(
                duration, save_individual_reports, output_dir
            )
        elif self.current_platform == "Linux":
            result.linux_afxdp_iouring_result = self._run_linux_afxdp_iouring_benchmark(
                duration, save_individual_reports, output_dir
            )
        
        # Always run GPU benchmark (cross-platform)
        result.gpu_packet_generation_result = self._run_gpu_packet_generation_benchmark(
            duration, save_individual_reports, output_dir
        )
        
        # Calculate summary metrics
        self._calculate_summary_metrics(result)
        
        return result
    
    def _run_windows_rio_benchmark(self, duration: float, save_report: bool, 
                                  output_dir: str) -> Optional[Dict[str, Any]]:
        """Run Windows RIO benchmark"""
        try:
            print(f"\n🪟 Running Windows RIO Benchmark...")
            benchmarker = WindowsRIOBenchmarker(self.target_host, self.target_port)
            result = benchmarker.run_benchmark(duration=duration)
            
            if save_report:
                benchmarker.save_report(result, output_dir)
            
            return asdict(result)
            
        except Exception as e:
            print(f"❌ Windows RIO benchmark failed: {e}")
            return {"error": str(e), "performance_grade": "ERROR"}
    
    def _run_macos_network_framework_benchmark(self, duration: float, save_report: bool,
                                             output_dir: str) -> Optional[Dict[str, Any]]:
        """Run macOS Network.framework benchmark"""
        try:
            print(f"\n🍎 Running macOS Network.framework Benchmark...")
            benchmarker = MacOSNetworkFrameworkBenchmarker(self.target_host, self.target_port)
            result = benchmarker.run_benchmark(duration=duration)
            
            if save_report:
                benchmarker.save_report(result, output_dir)
            
            return asdict(result)
            
        except Exception as e:
            print(f"❌ macOS Network.framework benchmark failed: {e}")
            return {"error": str(e), "performance_grade": "ERROR"}
    
    def _run_linux_afxdp_iouring_benchmark(self, duration: float, save_report: bool,
                                         output_dir: str) -> Optional[Dict[str, Any]]:
        """Run Linux AF_XDP + io_uring benchmark"""
        try:
            print(f"\n🐧 Running Linux AF_XDP + io_uring Benchmark...")
            benchmarker = LinuxAFXDPIOUringBenchmarker(self.target_host, self.target_port)
            result = benchmarker.run_benchmark(duration=duration)
            
            if save_report:
                benchmarker.save_report(result, output_dir)
            
            return asdict(result)
            
        except Exception as e:
            print(f"❌ Linux AF_XDP + io_uring benchmark failed: {e}")
            return {"error": str(e), "performance_grade": "ERROR"}
    
    def _run_gpu_packet_generation_benchmark(self, duration: float, save_report: bool,
                                           output_dir: str) -> Optional[Dict[str, Any]]:
        """Run GPU packet generation benchmark"""
        try:
            print(f"\n🎮 Running GPU Packet Generation Benchmark...")
            benchmarker = GPUPacketGenerationBenchmarker()
            result = benchmarker.run_benchmark(duration=duration)
            
            if save_report:
                benchmarker.save_report(result, output_dir)
            
            return asdict(result)
            
        except Exception as e:
            print(f"❌ GPU packet generation benchmark failed: {e}")
            return {"error": str(e), "performance_grade": "ERROR"}
    
    def _calculate_summary_metrics(self, result: ComprehensiveBenchmarkResult):
        """Calculate summary metrics from individual benchmark results"""
        benchmarks = [
            ("Windows RIO", result.windows_rio_result),
            ("macOS Network.framework", result.macos_network_framework_result),
            ("Linux AF_XDP + io_uring", result.linux_afxdp_iouring_result),
            ("GPU Packet Generation", result.gpu_packet_generation_result)
        ]
        
        total_benchmarks = 0
        passed_benchmarks = 0
        failed_benchmarks = 0
        best_pps = 0.0
        best_backend = "None"
        total_throughput = 0.0
        targets_met = []
        
        for name, benchmark_result in benchmarks:
            if benchmark_result is None:
                continue
                
            total_benchmarks += 1
            
            if "error" in benchmark_result:
                failed_benchmarks += 1
                continue
            
            # Extract PPS and target validation
            pps = benchmark_result.get("pps", 0.0)
            gbps = benchmark_result.get("gbps", 0.0)
            
            # Check target validation based on benchmark type
            target_met = False
            if "meets_1m_pps_target" in benchmark_result:  # Windows RIO
                target_met = benchmark_result["meets_1m_pps_target"]
            elif "meets_500k_pps_target" in benchmark_result:  # macOS Network.framework
                target_met = benchmark_result["meets_500k_pps_target"]
            elif "meets_10m_pps_target" in benchmark_result:  # Linux AF_XDP
                target_met = benchmark_result["meets_10m_pps_target"]
            elif "meets_50m_pps_target" in benchmark_result:  # GPU
                target_met = benchmark_result["meets_50m_pps_target"]
            
            if target_met:
                passed_benchmarks += 1
            else:
                failed_benchmarks += 1
            
            targets_met.append(target_met)
            
            # Track best performance
            if pps > best_pps:
                best_pps = pps
                best_backend = name
            
            total_throughput += gbps
        
        # Update result
        result.total_benchmarks_run = total_benchmarks
        result.benchmarks_passed = passed_benchmarks
        result.benchmarks_failed = failed_benchmarks
        result.best_pps = best_pps
        result.best_backend = best_backend
        result.total_throughput_gbps = total_throughput
        result.all_targets_met = all(targets_met) if targets_met else False
        
        # Assign overall performance grade
        if result.all_targets_met and passed_benchmarks > 0:
            result.performance_grade = "EXCELLENT"
        elif passed_benchmarks > failed_benchmarks:
            result.performance_grade = "GOOD"
        elif passed_benchmarks > 0:
            result.performance_grade = "FAIR"
        else:
            result.performance_grade = "POOR"
    
    def print_comprehensive_summary(self, result: ComprehensiveBenchmarkResult):
        """Print comprehensive benchmark summary"""
        print(f"\n{'='*80}")
        print(f"  COMPREHENSIVE BENCHMARK SUMMARY")
        print(f"{'='*80}")
        
        print(f"\n📊 Overall Results:")
        print(f"  Platform: {result.platform}")
        print(f"  Total Benchmarks: {result.total_benchmarks_run}")
        print(f"  Passed: {result.benchmarks_passed}")
        print(f"  Failed: {result.benchmarks_failed}")
        print(f"  Success Rate: {(result.benchmarks_passed / max(result.total_benchmarks_run, 1)) * 100:.1f}%")
        print(f"  Overall Grade: {result.performance_grade}")
        
        print(f"\n🚀 Performance Highlights:")
        print(f"  Best Backend: {result.best_backend}")
        print(f"  Peak PPS: {result.best_pps:,.0f}")
        print(f"  Total Throughput: {result.total_throughput_gbps:.2f} Gbps")
        print(f"  All Targets Met: {'✅ Yes' if result.all_targets_met else '❌ No'}")
        
        # Individual benchmark summaries
        print(f"\n📋 Individual Benchmark Results:")
        
        if result.windows_rio_result:
            self._print_individual_summary("Windows RIO", result.windows_rio_result, "1M+ PPS")
        
        if result.macos_network_framework_result:
            self._print_individual_summary("macOS Network.framework", 
                                         result.macos_network_framework_result, "500K+ PPS")
        
        if result.linux_afxdp_iouring_result:
            self._print_individual_summary("Linux AF_XDP + io_uring", 
                                         result.linux_afxdp_iouring_result, "10M+ PPS")
        
        if result.gpu_packet_generation_result:
            self._print_individual_summary("GPU Packet Generation", 
                                         result.gpu_packet_generation_result, "50M+ PPS")
        
        # Performance targets table
        print(f"\n🎯 Performance Targets:")
        print(f"{'Backend':<25} {'Target':<12} {'Achieved':<15} {'Status'}")
        print(f"{'-'*65}")
        
        targets = [
            ("Windows RIO", "1M+ PPS", result.windows_rio_result),
            ("macOS Network.framework", "500K+ PPS", result.macos_network_framework_result),
            ("Linux AF_XDP + io_uring", "10M+ PPS", result.linux_afxdp_iouring_result),
            ("GPU Packet Generation", "50M+ PPS", result.gpu_packet_generation_result)
        ]
        
        for backend, target, benchmark_result in targets:
            if benchmark_result is None:
                continue
                
            if "error" in benchmark_result:
                print(f"{backend:<25} {target:<12} {'ERROR':<15} ❌")
                continue
            
            pps = benchmark_result.get("pps", 0.0)
            status = "✅" if self._check_target_met(benchmark_result) else "❌"
            print(f"{backend:<25} {target:<12} {pps:>13,.0f} {status}")
    
    def _print_individual_summary(self, name: str, result: Dict[str, Any], target: str):
        """Print individual benchmark summary"""
        if "error" in result:
            print(f"  ❌ {name}: ERROR - {result['error']}")
            return
        
        pps = result.get("pps", 0.0)
        grade = result.get("performance_grade", "UNKNOWN")
        target_met = self._check_target_met(result)
        
        status = "✅" if target_met else "❌"
        print(f"  {status} {name}: {pps:,.0f} PPS ({grade}) - Target: {target}")
    
    def _check_target_met(self, result: Dict[str, Any]) -> bool:
        """Check if benchmark met its target"""
        return (result.get("meets_1m_pps_target", False) or
                result.get("meets_500k_pps_target", False) or
                result.get("meets_10m_pps_target", False) or
                result.get("meets_50m_pps_target", False))
    
    def save_comprehensive_report(self, result: ComprehensiveBenchmarkResult,
                                output_dir: str = "benchmark_reports") -> str:
        """Save comprehensive benchmark report"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/comprehensive_performance_benchmark_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        
        print(f"\n📄 Comprehensive report saved to: {filename}")
        return filename


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Performance Benchmark Suite")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--port", type=int, default=9999, help="Target port")
    parser.add_argument("--duration", type=float, default=10.0, help="Test duration per benchmark (seconds)")
    parser.add_argument("--save", action="store_true", help="Save individual and comprehensive reports")
    parser.add_argument("--output", default="benchmark_reports", help="Output directory")
    parser.add_argument("--no-individual", action="store_true", help="Don't save individual benchmark reports")
    
    args = parser.parse_args()
    
    try:
        benchmarker = ComprehensivePerformanceBenchmarker(args.target, args.port)
        result = benchmarker.run_all_benchmarks(
            duration=args.duration,
            save_individual_reports=args.save and not args.no_individual,
            output_dir=args.output
        )
        
        benchmarker.print_comprehensive_summary(result)
        
        if args.save:
            benchmarker.save_comprehensive_report(result, args.output)
        
        # Exit with appropriate code
        if result.all_targets_met:
            print(f"\n✅ All performance benchmarks PASSED")
            return 0
        else:
            print(f"\n❌ Some performance benchmarks FAILED to meet targets")
            return 1
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Benchmark suite interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Benchmark suite failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())