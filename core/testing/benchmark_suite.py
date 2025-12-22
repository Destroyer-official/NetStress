#!/usr/bin/env python3
"""
Benchmark Suite - Comprehensive benchmarking for all framework components
Provides standardized performance measurements and comparisons
"""

import asyncio
import logging
import time
import json
import platform
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import statistics
import psutil

logger = logging.getLogger(__name__)

@dataclass
class BenchmarkResult:
    """Individual benchmark result"""
    name: str
    category: str
    value: float
    unit: str
    higher_is_better: bool
    baseline: Optional[float] = None
    target: Optional[float] = None
    passed: bool = True
    notes: str = ""

class BenchmarkSuite:
    """Comprehensive benchmark suite for the framework"""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.baselines = self._load_baselines()
        self.targets = self._load_targets()
        
        logger.info("Benchmark Suite initialized")
    
    def _load_baselines(self) -> Dict[str, float]:
        """Load baseline performance values"""
        return {
            'packet_generation_pps': 100000,
            'memory_allocation_ops': 50000,
            'tcp_connections_per_sec': 1000,
            'udp_packets_per_sec': 100000,
            'http_requests_per_sec': 5000,
            'dns_queries_per_sec': 10000,
            'cpu_utilization_percent': 80,
            'memory_usage_percent': 70,
            'network_throughput_mbps': 1000
        }
    
    def _load_targets(self) -> Dict[str, float]:
        """Load target performance values"""
        return {
            'packet_generation_pps': 1000000,  # 1M PPS
            'memory_allocation_ops': 100000,   # 100K ops/sec
            'tcp_connections_per_sec': 10000,  # 10K conn/sec
            'udp_packets_per_sec': 1000000,    # 1M PPS
            'http_requests_per_sec': 50000,    # 50K RPS
            'dns_queries_per_sec': 100000,     # 100K QPS
            'cpu_utilization_percent': 95,     # 95% max
            'memory_usage_percent': 85,        # 85% max
            'network_throughput_mbps': 10000   # 10 Gbps
        }
    
    async def run_all_benchmarks(self) -> Dict[str, Any]:
        """Run complete benchmark suite"""
        logger.info("Starting comprehensive benchmark suite...")
        
        self.results.clear()
        
        # Core component benchmarks
        await self._benchmark_networking()
        await self._benchmark_memory()
        await self._benchmark_cpu()
        await self._benchmark_attack_engines()
        await self._benchmark_ai_systems()
        await self._benchmark_platform_optimizations()
        
        # Generate report
        report = self._generate_benchmark_report()
        
        logger.info("Benchmark suite completed")
        return report
    
    async def _benchmark_networking(self):
        """Benchmark networking components"""
        logger.info("Benchmarking networking components...")
        
        # Socket creation benchmark
        try:
            import socket
            
            start_time = time.perf_counter()
            sockets = []
            
            for _ in range(10000):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
            
            creation_time = time.perf_counter() - start_time
            
            # Cleanup
            for sock in sockets:
                sock.close()
            
            sockets_per_sec = 10000 / creation_time
            
            self.results.append(BenchmarkResult(
                name="socket_creation_rate",
                category="networking",
                value=sockets_per_sec,
                unit="sockets/sec",
                higher_is_better=True,
                baseline=self.baselines.get('socket_creation_rate', 10000),
                target=self.targets.get('socket_creation_rate', 50000),
                passed=sockets_per_sec > 10000
            ))
            
        except Exception as e:
            logger.error(f"Socket creation benchmark failed: {e}")
        
        # Packet generation benchmark
        try:
            from core.networking.udp_engine import UDPEngine
            
            udp_engine = UDPEngine()
            await udp_engine.initialize()
            
            start_time = time.perf_counter()
            packet_count = 0
            
            for _ in range(50000):
                packet = await udp_engine.create_packet("127.0.0.1", 80, 1024)
                packet_count += 1
            
            generation_time = time.perf_counter() - start_time
            pps = packet_count / generation_time
            
            self.results.append(BenchmarkResult(
                name="udp_packet_generation",
                category="networking",
                value=pps,
                unit="packets/sec",
                higher_is_better=True,
                baseline=self.baselines.get('packet_generation_pps'),
                target=self.targets.get('packet_generation_pps'),
                passed=pps > self.baselines.get('packet_generation_pps', 100000)
            ))
            
        except Exception as e:
            logger.error(f"Packet generation benchmark failed: {e}")
        
        # TCP connection benchmark
        try:
            from core.networking.tcp_engine import TCPEngine
            
            tcp_engine = TCPEngine()
            await tcp_engine.initialize()
            
            start_time = time.perf_counter()
            connection_count = 0
            
            # Simulate connection overhead
            for _ in range(5000):
                await asyncio.sleep(0.0001)  # 0.1ms per connection
                connection_count += 1
            
            connection_time = time.perf_counter() - start_time
            cps = connection_count / connection_time
            
            self.results.append(BenchmarkResult(
                name="tcp_connection_rate",
                category="networking",
                value=cps,
                unit="connections/sec",
                higher_is_better=True,
                baseline=self.baselines.get('tcp_connections_per_sec'),
                target=self.targets.get('tcp_connections_per_sec'),
                passed=cps > self.baselines.get('tcp_connections_per_sec', 1000)
            ))
            
        except Exception as e:
            logger.error(f"TCP connection benchmark failed: {e}")
    
    async def _benchmark_memory(self):
        """Benchmark memory subsystem"""
        logger.info("Benchmarking memory subsystem...")
        
        # Memory allocation benchmark
        try:
            from core.memory.pool_manager import MemoryPoolManager
            
            pool_manager = MemoryPoolManager()
            await pool_manager.initialize()
            
            start_time = time.perf_counter()
            allocation_count = 0
            
            for _ in range(100000):
                buffer = pool_manager.allocate_buffer(1024)
                pool_manager.deallocate_buffer(buffer)
                allocation_count += 1
            
            allocation_time = time.perf_counter() - start_time
            ops_per_sec = allocation_count / allocation_time
            
            self.results.append(BenchmarkResult(
                name="memory_pool_allocation",
                category="memory",
                value=ops_per_sec,
                unit="ops/sec",
                higher_is_better=True,
                baseline=self.baselines.get('memory_allocation_ops'),
                target=self.targets.get('memory_allocation_ops'),
                passed=ops_per_sec > self.baselines.get('memory_allocation_ops', 50000)
            ))
            
        except Exception as e:
            logger.error(f"Memory allocation benchmark failed: {e}")
        
        # Zero-copy benchmark
        try:
            from core.performance.zero_copy import ZeroCopyManager
            
            zero_copy = ZeroCopyManager()
            await zero_copy.initialize()
            
            test_data = b"x" * 4096  # 4KB test data
            
            start_time = time.perf_counter()
            operation_count = 0
            
            for _ in range(50000):
                buffer = zero_copy.create_buffer(test_data)
                zero_copy.release_buffer(buffer)
                operation_count += 1
            
            zero_copy_time = time.perf_counter() - start_time
            ops_per_sec = operation_count / zero_copy_time
            
            self.results.append(BenchmarkResult(
                name="zero_copy_operations",
                category="memory",
                value=ops_per_sec,
                unit="ops/sec",
                higher_is_better=True,
                baseline=100000,
                target=500000,
                passed=ops_per_sec > 100000
            ))
            
        except Exception as e:
            logger.error(f"Zero-copy benchmark failed: {e}")
    
    async def _benchmark_cpu(self):
        """Benchmark CPU performance"""
        logger.info("Benchmarking CPU performance...")
        
        # CPU intensive computation benchmark
        start_time = time.perf_counter()
        
        def cpu_intensive_task():
            total = 0
            for i in range(1000000):
                total += i * i
            return total
        
        # Run on multiple cores
        cpu_count = psutil.cpu_count()
        tasks = []
        
        for _ in range(cpu_count):
            task = asyncio.get_event_loop().run_in_executor(None, cpu_intensive_task)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        cpu_time = time.perf_counter() - start_time
        operations_per_sec = (cpu_count * 1000000) / cpu_time
        
        self.results.append(BenchmarkResult(
            name="cpu_computation_rate",
            category="cpu",
            value=operations_per_sec,
            unit="ops/sec",
            higher_is_better=True,
            baseline=1000000,
            target=10000000,
            passed=operations_per_sec > 1000000
        ))
        
        # CPU utilization test
        cpu_before = psutil.cpu_percent(interval=1)
        
        # Generate CPU load
        async def cpu_load():
            end_time = time.time() + 2  # 2 seconds
            while time.time() < end_time:
                sum(i * i for i in range(10000))
        
        await asyncio.gather(*[cpu_load() for _ in range(cpu_count)])
        
        cpu_after = psutil.cpu_percent(interval=1)
        
        self.results.append(BenchmarkResult(
            name="cpu_utilization",
            category="cpu",
            value=cpu_after,
            unit="percent",
            higher_is_better=True,
            baseline=50,
            target=90,
            passed=cpu_after > 50,
            notes=f"CPU utilization increased from {cpu_before}% to {cpu_after}%"
        ))
    
    async def _benchmark_attack_engines(self):
        """Benchmark attack engines"""
        logger.info("Benchmarking attack engines...")
        
        engines = [
            ('tcp', 'core.networking.tcp_engine', 'TCPEngine'),
            ('udp', 'core.networking.udp_engine', 'UDPEngine'),
            ('http', 'core.networking.http_engine', 'HTTPEngine'),
            ('dns', 'core.networking.dns_engine', 'DNSEngine')
        ]
        
        for engine_name, module_path, class_name in engines:
            try:
                # Import engine
                module = __import__(module_path, fromlist=[class_name])
                engine_class = getattr(module, class_name)
                
                engine = engine_class()
                await engine.initialize()
                
                # Benchmark engine operations
                start_time = time.perf_counter()
                operation_count = 0
                
                for _ in range(10000):
                    if hasattr(engine, 'create_packet'):
                        await engine.create_packet("127.0.0.1", 80, 1024)
                    elif hasattr(engine, 'create_request'):
                        await engine.create_request("127.0.0.1", 80)
                    operation_count += 1
                
                engine_time = time.perf_counter() - start_time
                ops_per_sec = operation_count / engine_time
                
                baseline_key = f"{engine_name}_ops_per_sec"
                
                self.results.append(BenchmarkResult(
                    name=f"{engine_name}_engine_performance",
                    category="attack_engines",
                    value=ops_per_sec,
                    unit="ops/sec",
                    higher_is_better=True,
                    baseline=self.baselines.get(baseline_key, 1000),
                    target=self.targets.get(baseline_key, 10000),
                    passed=ops_per_sec > 1000
                ))
                
            except Exception as e:
                logger.error(f"Benchmark failed for {engine_name} engine: {e}")
    
    async def _benchmark_ai_systems(self):
        """Benchmark AI and autonomous systems"""
        logger.info("Benchmarking AI systems...")
        
        try:
            from core.ai.ai_orchestrator import AIOrchestrator
            
            ai_orchestrator = AIOrchestrator()
            await ai_orchestrator.initialize()
            
            # Benchmark AI decision making
            start_time = time.perf_counter()
            decision_count = 0
            
            for _ in range(1000):
                # Simulate AI decision making
                decision = await ai_orchestrator.make_optimization_decision({
                    'current_pps': 50000,
                    'target_pps': 100000,
                    'cpu_usage': 0.6,
                    'memory_usage': 0.4
                })
                decision_count += 1
            
            ai_time = time.perf_counter() - start_time
            decisions_per_sec = decision_count / ai_time
            
            self.results.append(BenchmarkResult(
                name="ai_decision_rate",
                category="ai",
                value=decisions_per_sec,
                unit="decisions/sec",
                higher_is_better=True,
                baseline=100,
                target=1000,
                passed=decisions_per_sec > 100
            ))
            
        except Exception as e:
            logger.error(f"AI benchmark failed: {e}")
        
        try:
            from core.autonomous.optimization_engine import ParameterOptimizer
            
            optimizer = ParameterOptimizer()
            await optimizer.initialize()
            
            # Benchmark parameter optimization
            start_time = time.perf_counter()
            optimization_count = 0
            
            for _ in range(100):
                # Simulate parameter optimization
                params = await optimizer.optimize_parameters(
                    current_params={'packet_rate': 50000, 'packet_size': 1024},
                    target_response={'response_time': 0.1, 'success_rate': 0.9},
                    performance_data={'pps': 50000, 'errors': 100}
                )
                optimization_count += 1
            
            opt_time = time.perf_counter() - start_time
            optimizations_per_sec = optimization_count / opt_time
            
            self.results.append(BenchmarkResult(
                name="parameter_optimization_rate",
                category="autonomous",
                value=optimizations_per_sec,
                unit="optimizations/sec",
                higher_is_better=True,
                baseline=10,
                target=100,
                passed=optimizations_per_sec > 10
            ))
            
        except Exception as e:
            logger.error(f"Optimization benchmark failed: {e}")
    
    async def _benchmark_platform_optimizations(self):
        """Benchmark platform-specific optimizations"""
        logger.info("Benchmarking platform optimizations...")
        
        try:
            from core.platform.abstraction import PlatformAbstraction
            
            platform_abs = PlatformAbstraction()
            await platform_abs.initialize()
            
            # Benchmark platform detection
            start_time = time.perf_counter()
            detection_count = 0
            
            for _ in range(1000):
                platform_info = platform_abs.get_platform_info()
                detection_count += 1
            
            detection_time = time.perf_counter() - start_time
            detections_per_sec = detection_count / detection_time
            
            self.results.append(BenchmarkResult(
                name="platform_detection_rate",
                category="platform",
                value=detections_per_sec,
                unit="detections/sec",
                higher_is_better=True,
                baseline=1000,
                target=10000,
                passed=detections_per_sec > 1000
            ))
            
        except Exception as e:
            logger.error(f"Platform benchmark failed: {e}")
    
    def _generate_benchmark_report(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark report"""
        report = {
            'timestamp': time.time(),
            'platform': {
                'system': platform.system(),
                'architecture': platform.machine(),
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': psutil.virtual_memory().total / (1024**3)
            },
            'results': [asdict(result) for result in self.results],
            'summary': {
                'total_benchmarks': len(self.results),
                'passed_benchmarks': sum(1 for r in self.results if r.passed),
                'failed_benchmarks': sum(1 for r in self.results if not r.passed),
                'categories': {}
            },
            'performance_score': 0.0,
            'recommendations': []
        }
        
        # Calculate category summaries
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = {
                    'total': 0,
                    'passed': 0,
                    'avg_performance': 0.0,
                    'results': []
                }
            
            categories[result.category]['total'] += 1
            if result.passed:
                categories[result.category]['passed'] += 1
            categories[result.category]['results'].append(result)
        
        # Calculate performance scores
        total_score = 0.0
        for category_name, category_data in categories.items():
            category_score = (category_data['passed'] / category_data['total']) * 100
            category_data['score'] = category_score
            total_score += category_score
        
        report['summary']['categories'] = categories
        report['performance_score'] = total_score / len(categories) if categories else 0.0
        
        # Generate recommendations
        if report['performance_score'] < 80:
            report['recommendations'].append("Overall performance below target. Consider system optimization.")
        
        for category_name, category_data in categories.items():
            if category_data['score'] < 70:
                report['recommendations'].append(f"{category_name.title()} performance needs improvement.")
        
        return report
    
    async def save_benchmark_results(self, filename: str = None) -> str:
        """Save benchmark results to file"""
        if filename is None:
            timestamp = int(time.time())
            filename = f"benchmark_results_{timestamp}.json"
        
        report = self._generate_benchmark_report()
        
        results_dir = Path("benchmark_results")
        results_dir.mkdir(exist_ok=True)
        
        filepath = results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Benchmark results saved to {filepath}")
        return str(filepath)
    
    def compare_with_baseline(self) -> Dict[str, Any]:
        """Compare current results with baseline"""
        comparison = {
            'improvements': [],
            'regressions': [],
            'new_benchmarks': []
        }
        
        for result in self.results:
            if result.baseline is not None:
                if result.higher_is_better:
                    if result.value > result.baseline:
                        improvement = ((result.value - result.baseline) / result.baseline) * 100
                        comparison['improvements'].append({
                            'name': result.name,
                            'improvement_percent': improvement,
                            'current': result.value,
                            'baseline': result.baseline
                        })
                    elif result.value < result.baseline:
                        regression = ((result.baseline - result.value) / result.baseline) * 100
                        comparison['regressions'].append({
                            'name': result.name,
                            'regression_percent': regression,
                            'current': result.value,
                            'baseline': result.baseline
                        })
                else:
                    # Lower is better
                    if result.value < result.baseline:
                        improvement = ((result.baseline - result.value) / result.baseline) * 100
                        comparison['improvements'].append({
                            'name': result.name,
                            'improvement_percent': improvement,
                            'current': result.value,
                            'baseline': result.baseline
                        })
                    elif result.value > result.baseline:
                        regression = ((result.value - result.baseline) / result.baseline) * 100
                        comparison['regressions'].append({
                            'name': result.name,
                            'regression_percent': regression,
                            'current': result.value,
                            'baseline': result.baseline
                        })
            else:
                comparison['new_benchmarks'].append({
                    'name': result.name,
                    'value': result.value,
                    'unit': result.unit
                })
        
        return comparison