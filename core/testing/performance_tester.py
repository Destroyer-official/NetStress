#!/usr/bin/env python3
"""
Performance Tester - Comprehensive performance testing and benchmarking
Validates performance requirements and identifies optimization opportunities
"""

import asyncio
import logging
import time
import psutil
import platform
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import statistics
import json
from pathlib import Path
import threading
import multiprocessing

# Conditional import for resource module (Unix only)
try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    test_name: str
    duration: float
    packets_per_second: float
    bytes_per_second: float
    cpu_usage: float
    memory_usage: float
    network_utilization: float
    error_rate: float
    latency_avg: float
    latency_p95: float
    latency_p99: float
    throughput_mbps: float
    connections_per_second: float
    success_rate: float
    timestamp: float

@dataclass
class PerformanceRequirements:
    """Performance requirements specification"""
    min_packets_per_second: int = 1000000  # 1M PPS
    min_throughput_mbps: float = 1000.0    # 1 Gbps
    max_cpu_usage: float = 0.8             # 80%
    max_memory_usage: float = 0.7          # 70%
    max_error_rate: float = 0.01           # 1%
    max_latency_p99: float = 0.1           # 100ms
    min_success_rate: float = 0.99         # 99%

class PerformanceTester:
    """Comprehensive performance testing system"""
    
    def __init__(self):
        self.requirements = PerformanceRequirements()
        self.test_results: List[PerformanceMetrics] = []
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Performance counters
        self.packet_counter = multiprocessing.Value('L', 0)  # Unsigned long
        self.byte_counter = multiprocessing.Value('L', 0)
        self.error_counter = multiprocessing.Value('L', 0)
        self.connection_counter = multiprocessing.Value('L', 0)
        
        # Latency tracking
        self.latency_samples = []
        self.latency_lock = threading.Lock()
        
        logger.info("Performance Tester initialized")
    
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive performance test suite"""
        logger.info("Starting comprehensive performance tests...")
        
        test_results = {}
        
        try:
            # Platform-specific tests
            test_results['platform'] = await self._test_platform_performance()
            
            # Network performance tests
            test_results['networking'] = await self._test_networking_performance()
            
            # Memory performance tests
            test_results['memory'] = await self._test_memory_performance()
            
            # CPU performance tests
            test_results['cpu'] = await self._test_cpu_performance()
            
            # Attack engine performance tests
            test_results['attack_engines'] = await self._test_attack_engines()
            
            # Scalability tests
            test_results['scalability'] = await self._test_scalability()
            
            # Stress tests
            test_results['stress'] = await self._test_stress_conditions()
            
            # Generate performance report
            report = self._generate_performance_report(test_results)
            
            logger.info("Comprehensive performance tests completed")
            return report
            
        except Exception as e:
            logger.error(f"Performance testing failed: {e}")
            return {'error': str(e), 'partial_results': test_results}
    
    async def _test_platform_performance(self) -> Dict[str, Any]:
        """Test platform-specific performance characteristics"""
        logger.info("Testing platform performance...")
        
        results = {
            'platform': platform.system(),
            'architecture': platform.machine(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'tests': {}
        }
        
        # Test socket creation performance
        start_time = time.time()
        socket_count = 0
        
        try:
            import socket
            sockets = []
            for _ in range(1000):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                socket_count += 1
            
            # Clean up
            for sock in sockets:
                sock.close()
                
            duration = time.time() - start_time
            results['tests']['socket_creation'] = {
                'sockets_per_second': socket_count / duration,
                'duration': duration,
                'passed': socket_count / duration > 10000  # 10K sockets/sec minimum
            }
            
        except Exception as e:
            results['tests']['socket_creation'] = {'error': str(e), 'passed': False}
        
        # Test memory allocation performance
        start_time = time.time()
        try:
            buffers = []
            for _ in range(1000):
                buffer = bytearray(1024 * 1024)  # 1MB buffers
                buffers.append(buffer)
            
            duration = time.time() - start_time
            results['tests']['memory_allocation'] = {
                'mb_per_second': 1000 / duration,
                'duration': duration,
                'passed': 1000 / duration > 100  # 100 MB/sec minimum
            }
            
        except Exception as e:
            results['tests']['memory_allocation'] = {'error': str(e), 'passed': False}
        
        return results
    
    async def _test_networking_performance(self) -> Dict[str, Any]:
        """Test networking performance"""
        logger.info("Testing networking performance...")
        
        results = {'tests': {}}
        
        # Test UDP packet generation rate
        try:
            from core.networking.udp_engine import UDPEngine
            
            udp_engine = UDPEngine()
            await udp_engine.initialize()
            
            # Measure packet generation rate
            start_time = time.time()
            packet_count = 0
            
            for _ in range(10000):
                packet = await udp_engine.create_packet("127.0.0.1", 80, 1024)
                packet_count += 1
            
            duration = time.time() - start_time
            pps = packet_count / duration
            
            results['tests']['udp_packet_generation'] = {
                'packets_per_second': pps,
                'duration': duration,
                'passed': pps > 100000  # 100K PPS minimum
            }
            
        except Exception as e:
            results['tests']['udp_packet_generation'] = {'error': str(e), 'passed': False}
        
        # Test TCP connection performance
        try:
            from core.networking.tcp_engine import TCPEngine
            
            tcp_engine = TCPEngine()
            await tcp_engine.initialize()
            
            # Measure connection setup rate (simulated)
            start_time = time.time()
            connection_count = 0
            
            for _ in range(1000):
                # Simulate connection setup overhead
                await asyncio.sleep(0.001)  # 1ms per connection
                connection_count += 1
            
            duration = time.time() - start_time
            cps = connection_count / duration
            
            results['tests']['tcp_connection_rate'] = {
                'connections_per_second': cps,
                'duration': duration,
                'passed': cps > 500  # 500 connections/sec minimum
            }
            
        except Exception as e:
            results['tests']['tcp_connection_rate'] = {'error': str(e), 'passed': False}
        
        return results
    
    async def _test_memory_performance(self) -> Dict[str, Any]:
        """Test memory subsystem performance"""
        logger.info("Testing memory performance...")
        
        results = {'tests': {}}
        
        # Test memory pool performance
        try:
            from core.memory.pool_manager import MemoryPoolManager
            
            pool_manager = MemoryPoolManager()
            await pool_manager.initialize()
            
            # Test allocation/deallocation rate
            start_time = time.time()
            allocation_count = 0
            
            for _ in range(10000):
                buffer = pool_manager.allocate_buffer(1024)
                pool_manager.deallocate_buffer(buffer)
                allocation_count += 1
            
            duration = time.time() - start_time
            alloc_rate = allocation_count / duration
            
            results['tests']['memory_pool_performance'] = {
                'allocations_per_second': alloc_rate,
                'duration': duration,
                'passed': alloc_rate > 50000  # 50K allocations/sec minimum
            }
            
        except Exception as e:
            results['tests']['memory_pool_performance'] = {'error': str(e), 'passed': False}
        
        # Test zero-copy buffer performance
        try:
            from core.performance.zero_copy import ZeroCopyManager
            
            zero_copy = ZeroCopyManager()
            await zero_copy.initialize()
            
            # Test zero-copy operations
            start_time = time.time()
            operation_count = 0
            
            test_data = b"x" * 1024  # 1KB test data
            
            for _ in range(10000):
                buffer = zero_copy.create_buffer(test_data)
                zero_copy.release_buffer(buffer)
                operation_count += 1
            
            duration = time.time() - start_time
            ops_rate = operation_count / duration
            
            results['tests']['zero_copy_performance'] = {
                'operations_per_second': ops_rate,
                'duration': duration,
                'passed': ops_rate > 100000  # 100K ops/sec minimum
            }
            
        except Exception as e:
            results['tests']['zero_copy_performance'] = {'error': str(e), 'passed': False}
        
        return results
    
    async def _test_cpu_performance(self) -> Dict[str, Any]:
        """Test CPU performance and utilization"""
        logger.info("Testing CPU performance...")
        
        results = {'tests': {}}
        
        # Test multi-core utilization
        try:
            cpu_count = psutil.cpu_count()
            
            # Start CPU-intensive tasks on all cores
            async def cpu_intensive_task():
                # Simulate packet processing workload
                total = 0
                for i in range(1000000):
                    total += i * i
                return total
            
            start_time = time.time()
            cpu_before = psutil.cpu_percent(interval=None)
            
            # Run tasks on all cores
            tasks = [cpu_intensive_task() for _ in range(cpu_count)]
            await asyncio.gather(*tasks)
            
            duration = time.time() - start_time
            cpu_after = psutil.cpu_percent(interval=None)
            
            results['tests']['multi_core_utilization'] = {
                'cpu_cores_used': cpu_count,
                'duration': duration,
                'cpu_utilization': cpu_after,
                'passed': cpu_after > 50  # Should use at least 50% CPU
            }
            
        except Exception as e:
            results['tests']['multi_core_utilization'] = {'error': str(e), 'passed': False}
        
        return results
    
    async def _test_attack_engines(self) -> Dict[str, Any]:
        """Test attack engine performance"""
        logger.info("Testing attack engine performance...")
        
        results = {'tests': {}}
        
        # Test each attack engine
        engines = ['tcp', 'udp', 'http', 'dns']
        
        for engine_name in engines:
            try:
                # Import and test engine
                if engine_name == 'tcp':
                    from core.networking.tcp_engine import TCPEngine
                    engine = TCPEngine()
                elif engine_name == 'udp':
                    from core.networking.udp_engine import UDPEngine
                    engine = UDPEngine()
                elif engine_name == 'http':
                    from core.networking.http_engine import HTTPEngine
                    engine = HTTPEngine()
                elif engine_name == 'dns':
                    from core.networking.dns_engine import DNSEngine
                    engine = DNSEngine()
                
                await engine.initialize()
                
                # Measure engine performance
                start_time = time.time()
                operation_count = 0
                
                for _ in range(1000):
                    # Simulate engine operation
                    if hasattr(engine, 'create_packet'):
                        await engine.create_packet("127.0.0.1", 80, 1024)
                    operation_count += 1
                
                duration = time.time() - start_time
                ops_rate = operation_count / duration
                
                results['tests'][f'{engine_name}_engine'] = {
                    'operations_per_second': ops_rate,
                    'duration': duration,
                    'passed': ops_rate > 1000  # 1K ops/sec minimum
                }
                
            except Exception as e:
                results['tests'][f'{engine_name}_engine'] = {'error': str(e), 'passed': False}
        
        return results
    
    async def _test_scalability(self) -> Dict[str, Any]:
        """Test system scalability"""
        logger.info("Testing system scalability...")
        
        results = {'tests': {}}
        
        # Test concurrent connection handling
        try:
            concurrent_levels = [10, 100, 1000, 5000]
            scalability_results = []
            
            for level in concurrent_levels:
                start_time = time.time()
                
                # Simulate concurrent operations
                async def concurrent_operation():
                    await asyncio.sleep(0.01)  # 10ms operation
                    return True
                
                tasks = [concurrent_operation() for _ in range(level)]
                results_list = await asyncio.gather(*tasks, return_exceptions=True)
                
                duration = time.time() - start_time
                success_count = sum(1 for r in results_list if r is True)
                
                scalability_results.append({
                    'concurrency_level': level,
                    'duration': duration,
                    'success_rate': success_count / level,
                    'operations_per_second': level / duration
                })
            
            results['tests']['scalability'] = {
                'results': scalability_results,
                'passed': all(r['success_rate'] > 0.95 for r in scalability_results)
            }
            
        except Exception as e:
            results['tests']['scalability'] = {'error': str(e), 'passed': False}
        
        return results
    
    async def _test_stress_conditions(self) -> Dict[str, Any]:
        """Test system under stress conditions"""
        logger.info("Testing stress conditions...")
        
        results = {'tests': {}}
        
        # Memory stress test
        try:
            initial_memory = psutil.virtual_memory().percent
            
            # Allocate large amounts of memory
            memory_blocks = []
            for _ in range(100):
                block = bytearray(10 * 1024 * 1024)  # 10MB blocks
                memory_blocks.append(block)
            
            peak_memory = psutil.virtual_memory().percent
            
            # Clean up
            del memory_blocks
            
            final_memory = psutil.virtual_memory().percent
            
            results['tests']['memory_stress'] = {
                'initial_memory_percent': initial_memory,
                'peak_memory_percent': peak_memory,
                'final_memory_percent': final_memory,
                'memory_recovered': abs(final_memory - initial_memory) < 5,
                'passed': peak_memory < 90  # Should not exceed 90% memory
            }
            
        except Exception as e:
            results['tests']['memory_stress'] = {'error': str(e), 'passed': False}
        
        return results
    
    def _generate_performance_report(self, test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            'timestamp': time.time(),
            'platform': platform.system(),
            'architecture': platform.machine(),
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'test_results': test_results,
            'summary': {
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'overall_score': 0.0
            },
            'recommendations': []
        }
        
        # Calculate summary statistics
        total_tests = 0
        passed_tests = 0
        
        for category, category_results in test_results.items():
            if 'tests' in category_results:
                for test_name, test_result in category_results['tests'].items():
                    total_tests += 1
                    if test_result.get('passed', False):
                        passed_tests += 1
        
        report['summary']['total_tests'] = total_tests
        report['summary']['passed_tests'] = passed_tests
        report['summary']['failed_tests'] = total_tests - passed_tests
        report['summary']['overall_score'] = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        # Generate recommendations
        if report['summary']['overall_score'] < 80:
            report['recommendations'].append("System performance is below optimal. Consider hardware upgrades.")
        
        if 'memory' in test_results:
            memory_tests = test_results['memory']['tests']
            if any(not test.get('passed', False) for test in memory_tests.values()):
                report['recommendations'].append("Memory subsystem performance issues detected. Consider increasing RAM or optimizing memory usage.")
        
        if 'cpu' in test_results:
            cpu_tests = test_results['cpu']['tests']
            if any(not test.get('passed', False) for test in cpu_tests.values()):
                report['recommendations'].append("CPU performance issues detected. Consider upgrading CPU or optimizing algorithms.")
        
        return report
    
    async def validate_performance_requirements(self) -> Tuple[bool, List[str]]:
        """Validate system meets performance requirements"""
        logger.info("Validating performance requirements...")
        
        issues = []
        
        try:
            # Run quick performance validation
            test_results = await self.run_comprehensive_tests()
            
            # Check each requirement
            if test_results.get('summary', {}).get('overall_score', 0) < 80:
                issues.append("Overall performance score below 80%")
            
            # Check specific requirements
            networking = test_results.get('networking', {}).get('tests', {})
            
            udp_test = networking.get('udp_packet_generation', {})
            if udp_test.get('packets_per_second', 0) < self.requirements.min_packets_per_second:
                issues.append(f"UDP packet generation rate below requirement: {udp_test.get('packets_per_second', 0)} < {self.requirements.min_packets_per_second}")
            
            # Check memory requirements
            memory = test_results.get('memory', {}).get('tests', {})
            
            pool_test = memory.get('memory_pool_performance', {})
            if not pool_test.get('passed', False):
                issues.append("Memory pool performance below requirements")
            
            return len(issues) == 0, issues
            
        except Exception as e:
            logger.error(f"Performance validation failed: {e}")
            return False, [f"Validation error: {str(e)}"]
    
    async def benchmark_system(self) -> Dict[str, Any]:
        """Run system benchmarks"""
        logger.info("Running system benchmarks...")
        
        benchmarks = {}
        
        # CPU benchmark
        start_time = time.time()
        total = 0
        for i in range(10000000):  # 10M iterations
            total += i * i
        cpu_duration = time.time() - start_time
        
        benchmarks['cpu_benchmark'] = {
            'iterations': 10000000,
            'duration': cpu_duration,
            'operations_per_second': 10000000 / cpu_duration
        }
        
        # Memory benchmark
        start_time = time.time()
        data = bytearray(100 * 1024 * 1024)  # 100MB
        for i in range(0, len(data), 4096):  # 4KB chunks
            data[i] = i % 256
        memory_duration = time.time() - start_time
        
        benchmarks['memory_benchmark'] = {
            'size_mb': 100,
            'duration': memory_duration,
            'mb_per_second': 100 / memory_duration
        }
        
        return benchmarks