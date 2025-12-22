#!/usr/bin/env python3
"""
Test Coordinator - Orchestrates comprehensive testing and validation
Coordinates performance testing, benchmarking, and validation
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import json

from .performance_tester import PerformanceTester
from .benchmark_suite import BenchmarkSuite
from .validation_engine import ValidationEngine, ValidationLevel

logger = logging.getLogger(__name__)

class TestCoordinator:
    """Coordinates all testing and validation activities"""
    
    def __init__(self):
        self.performance_tester = PerformanceTester()
        self.benchmark_suite = BenchmarkSuite()
        self.validation_engine = ValidationEngine()
        
        self.test_results = {}
        
        logger.info("Test Coordinator initialized")
    
    async def run_complete_test_suite(self, validation_level: ValidationLevel = ValidationLevel.COMPREHENSIVE) -> Dict[str, Any]:
        """Run complete test suite including performance, benchmarks, and validation"""
        logger.info("Starting complete test suite...")
        
        start_time = time.time()
        
        try:
            # Run validation first
            logger.info("Running system validation...")
            validation_results = await self.validation_engine.validate_all_requirements(validation_level)
            
            # Run performance tests
            logger.info("Running performance tests...")
            performance_results = await self.performance_tester.run_comprehensive_tests()
            
            # Run benchmarks
            logger.info("Running benchmark suite...")
            benchmark_results = await self.benchmark_suite.run_all_benchmarks()
            
            # Compile comprehensive report
            total_time = time.time() - start_time
            
            comprehensive_report = {
                'timestamp': time.time(),
                'total_execution_time': total_time,
                'validation': validation_results,
                'performance': performance_results,
                'benchmarks': benchmark_results,
                'overall_assessment': self._generate_overall_assessment(
                    validation_results, performance_results, benchmark_results
                )
            }
            
            # Save results
            await self._save_test_results(comprehensive_report)
            
            logger.info(f"Complete test suite finished in {total_time:.2f} seconds")
            return comprehensive_report
            
        except Exception as e:
            logger.error(f"Test suite execution failed: {e}")
            return {
                'error': str(e),
                'timestamp': time.time(),
                'partial_results': self.test_results
            }
    
    async def run_quick_validation(self) -> Dict[str, Any]:
        """Run quick validation for basic system checks"""
        logger.info("Running quick validation...")
        
        try:
            # Basic validation only
            validation_results = await self.validation_engine.validate_all_requirements(ValidationLevel.BASIC)
            
            # Quick performance check
            performance_check = await self._quick_performance_check()
            
            report = {
                'timestamp': time.time(),
                'validation': validation_results,
                'performance_check': performance_check,
                'quick_assessment': self._generate_quick_assessment(validation_results, performance_check)
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Quick validation failed: {e}")
            return {'error': str(e), 'timestamp': time.time()}
    
    async def _quick_performance_check(self) -> Dict[str, Any]:
        """Perform quick performance check"""
        results = {}
        
        try:
            # Test packet generation rate
            from core.networking.udp_engine import UDPEngine
            
            engine = UDPEngine()
            await engine.initialize()
            
            start_time = time.perf_counter()
            packet_count = 0
            
            # Generate packets for 1 second
            end_time = start_time + 1.0
            while time.perf_counter() < end_time:
                await engine.create_packet("127.0.0.1", 80, 1024)
                packet_count += 1
            
            duration = time.perf_counter() - start_time
            pps = packet_count / duration
            
            results['packet_generation'] = {
                'packets_per_second': pps,
                'meets_minimum': pps > 10000,  # 10K PPS minimum for quick check
                'duration': duration
            }
            
        except Exception as e:
            results['packet_generation'] = {'error': str(e)}
        
        try:
            # Test memory allocation
            from core.memory.pool_manager import MemoryPoolManager
            
            pool_manager = MemoryPoolManager()
            await pool_manager.initialize()
            
            start_time = time.perf_counter()
            
            # Allocate and deallocate buffers
            for _ in range(1000):
                buffer = pool_manager.allocate_buffer(1024)
                pool_manager.deallocate_buffer(buffer)
            
            duration = time.perf_counter() - start_time
            ops_per_sec = 1000 / duration
            
            results['memory_allocation'] = {
                'operations_per_second': ops_per_sec,
                'meets_minimum': ops_per_sec > 5000,  # 5K ops/sec minimum
                'duration': duration
            }
            
        except Exception as e:
            results['memory_allocation'] = {'error': str(e)}
        
        return results
    
    def _generate_overall_assessment(self, validation_results: Dict[str, Any], 
                                   performance_results: Dict[str, Any], 
                                   benchmark_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall system assessment"""
        
        assessment = {
            'system_ready': True,
            'confidence_level': 'high',
            'critical_issues': [],
            'warnings': [],
            'recommendations': [],
            'scores': {}
        }
        
        # Validation assessment
        validation_success_rate = validation_results.get('summary', {}).get('success_rate', 0)
        assessment['scores']['validation'] = validation_success_rate
        
        if validation_success_rate < 90:
            assessment['system_ready'] = False
            assessment['critical_issues'].append(f"Validation success rate too low: {validation_success_rate:.1f}%")
        elif validation_success_rate < 95:
            assessment['warnings'].append(f"Validation success rate below optimal: {validation_success_rate:.1f}%")
        
        # Performance assessment
        if 'error' not in performance_results:
            performance_score = 100  # Default if no specific scoring
            
            # Check for performance issues
            for category, category_results in performance_results.get('test_results', {}).items():
                if 'tests' in category_results:
                    failed_tests = [name for name, result in category_results['tests'].items() 
                                  if not result.get('passed', False)]
                    if failed_tests:
                        performance_score -= len(failed_tests) * 10
                        assessment['warnings'].extend([f"Performance issue in {category}: {test}" for test in failed_tests])
            
            assessment['scores']['performance'] = max(0, performance_score)
        else:
            assessment['scores']['performance'] = 0
            assessment['critical_issues'].append("Performance testing failed")
            assessment['system_ready'] = False
        
        # Benchmark assessment
        benchmark_score = benchmark_results.get('performance_score', 0)
        assessment['scores']['benchmark'] = benchmark_score
        
        if benchmark_score < 70:
            assessment['system_ready'] = False
            assessment['critical_issues'].append(f"Benchmark score too low: {benchmark_score:.1f}")
        elif benchmark_score < 80:
            assessment['warnings'].append(f"Benchmark score below optimal: {benchmark_score:.1f}")
        
        # Overall score
        scores = [score for score in assessment['scores'].values() if score > 0]
        assessment['overall_score'] = sum(scores) / len(scores) if scores else 0
        
        # Confidence level
        if assessment['overall_score'] >= 90 and not assessment['critical_issues']:
            assessment['confidence_level'] = 'high'
        elif assessment['overall_score'] >= 75 and len(assessment['critical_issues']) <= 1:
            assessment['confidence_level'] = 'medium'
        else:
            assessment['confidence_level'] = 'low'
            assessment['system_ready'] = False
        
        # Generate recommendations
        if assessment['critical_issues']:
            assessment['recommendations'].append("Address all critical issues before deployment")
        
        if assessment['warnings']:
            assessment['recommendations'].append("Consider addressing warnings for optimal performance")
        
        if assessment['overall_score'] < 85:
            assessment['recommendations'].append("System performance below optimal, consider optimization")
        
        if assessment['system_ready']:
            assessment['recommendations'].append("System ready for deployment")
        
        return assessment
    
    def _generate_quick_assessment(self, validation_results: Dict[str, Any], 
                                 performance_check: Dict[str, Any]) -> Dict[str, Any]:
        """Generate quick assessment for basic checks"""
        
        assessment = {
            'system_functional': True,
            'issues': [],
            'recommendations': []
        }
        
        # Check validation results
        validation_success_rate = validation_results.get('summary', {}).get('success_rate', 0)
        
        if validation_success_rate < 80:
            assessment['system_functional'] = False
            assessment['issues'].append(f"Basic validation failed: {validation_success_rate:.1f}% success rate")
        
        # Check performance
        packet_gen = performance_check.get('packet_generation', {})
        if not packet_gen.get('meets_minimum', False):
            assessment['issues'].append("Packet generation performance below minimum")
        
        memory_alloc = performance_check.get('memory_allocation', {})
        if not memory_alloc.get('meets_minimum', False):
            assessment['issues'].append("Memory allocation performance below minimum")
        
        # Generate recommendations
        if assessment['issues']:
            assessment['recommendations'].append("Run full test suite to identify specific issues")
        else:
            assessment['recommendations'].append("Basic checks passed, system appears functional")
        
        return assessment
    
    async def _save_test_results(self, results: Dict[str, Any]):
        """Save test results to file"""
        try:
            results_dir = Path("test_results")
            results_dir.mkdir(exist_ok=True)
            
            timestamp = int(time.time())
            filename = f"test_results_{timestamp}.json"
            filepath = results_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            logger.info(f"Test results saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save test results: {e}")
    
    async def validate_deployment_readiness(self) -> Dict[str, Any]:
        """Validate if system is ready for deployment"""
        logger.info("Validating deployment readiness...")
        
        try:
            # Run comprehensive validation
            validation_results = await self.validation_engine.validate_all_requirements(ValidationLevel.COMPREHENSIVE)
            
            # Check performance requirements
            performance_valid, performance_issues = await self.performance_tester.validate_performance_requirements()
            
            # Generate deployment assessment
            deployment_assessment = {
                'ready_for_deployment': True,
                'validation_passed': validation_results.get('summary', {}).get('success_rate', 0) >= 95,
                'performance_passed': performance_valid,
                'blocking_issues': [],
                'warnings': [],
                'deployment_recommendations': []
            }
            
            # Check for blocking issues
            if not deployment_assessment['validation_passed']:
                deployment_assessment['ready_for_deployment'] = False
                deployment_assessment['blocking_issues'].append("System validation failed")
            
            if not deployment_assessment['performance_passed']:
                deployment_assessment['ready_for_deployment'] = False
                deployment_assessment['blocking_issues'].extend(performance_issues)
            
            # Check critical safety requirements
            safety_requirements = ['8.1', '8.2', '8.3', '8.4', '8.5']
            failed_safety = [r for r in validation_results.get('failed_requirements', []) 
                           if r['requirement_id'] in safety_requirements]
            
            if failed_safety:
                deployment_assessment['ready_for_deployment'] = False
                deployment_assessment['blocking_issues'].append("Critical safety requirements failed")
            
            # Generate recommendations
            if deployment_assessment['ready_for_deployment']:
                deployment_assessment['deployment_recommendations'].append("System ready for deployment")
            else:
                deployment_assessment['deployment_recommendations'].append("Address blocking issues before deployment")
                deployment_assessment['deployment_recommendations'].extend([
                    f"Fix: {issue}" for issue in deployment_assessment['blocking_issues']
                ])
            
            return {
                'timestamp': time.time(),
                'deployment_assessment': deployment_assessment,
                'validation_details': validation_results,
                'performance_details': {
                    'passed': performance_valid,
                    'issues': performance_issues
                }
            }
            
        except Exception as e:
            logger.error(f"Deployment readiness validation failed: {e}")
            return {
                'timestamp': time.time(),
                'error': str(e),
                'deployment_assessment': {
                    'ready_for_deployment': False,
                    'blocking_issues': [f"Validation error: {str(e)}"]
                }
            }
    
    async def run_stress_tests(self) -> Dict[str, Any]:
        """Run stress tests to validate system under load"""
        logger.info("Running stress tests...")
        
        try:
            # Run stress-level validation
            validation_results = await self.validation_engine.validate_all_requirements(ValidationLevel.STRESS)
            
            # Run extended performance tests
            performance_results = await self.performance_tester.run_comprehensive_tests()
            
            # Additional stress-specific tests
            stress_results = await self._run_stress_specific_tests()
            
            return {
                'timestamp': time.time(),
                'validation': validation_results,
                'performance': performance_results,
                'stress_tests': stress_results,
                'stress_assessment': self._generate_stress_assessment(
                    validation_results, performance_results, stress_results
                )
            }
            
        except Exception as e:
            logger.error(f"Stress testing failed: {e}")
            return {'error': str(e), 'timestamp': time.time()}
    
    async def _run_stress_specific_tests(self) -> Dict[str, Any]:
        """Run stress-specific tests"""
        results = {}
        
        # High concurrency test
        try:
            logger.info("Running high concurrency stress test...")
            
            async def concurrent_operation():
                await asyncio.sleep(0.01)
                return True
            
            # Test with very high concurrency
            concurrency_levels = [1000, 5000, 10000]
            
            for level in concurrency_levels:
                start_time = time.perf_counter()
                
                tasks = [concurrent_operation() for _ in range(level)]
                results_list = await asyncio.gather(*tasks, return_exceptions=True)
                
                duration = time.perf_counter() - start_time
                success_count = sum(1 for r in results_list if r is True)
                
                results[f'concurrency_{level}'] = {
                    'success_rate': success_count / level,
                    'duration': duration,
                    'operations_per_second': level / duration,
                    'passed': success_count / level > 0.95
                }
                
        except Exception as e:
            results['concurrency_test'] = {'error': str(e)}
        
        # Memory stress test
        try:
            logger.info("Running memory stress test...")
            
            import psutil
            initial_memory = psutil.virtual_memory().percent
            
            # Allocate large amounts of memory
            memory_blocks = []
            try:
                for i in range(500):  # 5GB if 10MB blocks
                    block = bytearray(10 * 1024 * 1024)  # 10MB
                    memory_blocks.append(block)
                    
                    current_memory = psutil.virtual_memory().percent
                    if current_memory > 90:  # Stop at 90% memory usage
                        break
                
                peak_memory = psutil.virtual_memory().percent
                
                # Clean up
                del memory_blocks
                
                final_memory = psutil.virtual_memory().percent
                
                results['memory_stress'] = {
                    'initial_memory_percent': initial_memory,
                    'peak_memory_percent': peak_memory,
                    'final_memory_percent': final_memory,
                    'memory_recovered': abs(final_memory - initial_memory) < 5,
                    'passed': peak_memory < 95
                }
                
            except MemoryError:
                results['memory_stress'] = {
                    'error': 'Memory allocation failed',
                    'passed': False
                }
                
        except Exception as e:
            results['memory_stress'] = {'error': str(e)}
        
        return results
    
    def _generate_stress_assessment(self, validation_results: Dict[str, Any], 
                                  performance_results: Dict[str, Any], 
                                  stress_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate stress test assessment"""
        
        assessment = {
            'stress_ready': True,
            'stress_score': 0,
            'critical_failures': [],
            'performance_degradation': [],
            'recommendations': []
        }
        
        # Check validation under stress
        validation_success = validation_results.get('summary', {}).get('success_rate', 0)
        if validation_success < 85:
            assessment['stress_ready'] = False
            assessment['critical_failures'].append(f"Validation degraded under stress: {validation_success:.1f}%")
        
        # Check stress-specific tests
        stress_failures = []
        for test_name, test_result in stress_results.items():
            if not test_result.get('passed', False):
                stress_failures.append(test_name)
        
        if stress_failures:
            assessment['stress_ready'] = False
            assessment['critical_failures'].extend([f"Stress test failed: {test}" for test in stress_failures])
        
        # Calculate stress score
        total_tests = len(stress_results)
        passed_tests = sum(1 for result in stress_results.values() if result.get('passed', False))
        
        if total_tests > 0:
            assessment['stress_score'] = (passed_tests / total_tests) * 100
        
        # Generate recommendations
        if assessment['stress_ready']:
            assessment['recommendations'].append("System handles stress conditions well")
        else:
            assessment['recommendations'].append("System requires optimization for high-stress scenarios")
            assessment['recommendations'].extend([
                f"Address: {failure}" for failure in assessment['critical_failures']
            ])
        
        return assessment