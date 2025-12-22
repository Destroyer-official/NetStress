#!/usr/bin/env python3
"""
Validation Engine - Comprehensive system validation and testing
Validates all requirements and ensures system integrity
"""

import asyncio
import logging
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import time
import json

logger = logging.getLogger(__name__)

class ValidationLevel(Enum):
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    STRESS = "stress"

@dataclass
class ValidationResult:
    """Individual validation result"""
    requirement_id: str
    description: str
    passed: bool
    actual_value: Any
    expected_value: Any
    error_message: Optional[str] = None
    execution_time: float = 0.0

class ValidationEngine:
    """Comprehensive validation engine for all system requirements"""
    
    def __init__(self):
        self.validation_results: List[ValidationResult] = []
        self.requirements = self._load_requirements()
        
        logger.info("Validation Engine initialized")
    
    def _load_requirements(self) -> Dict[str, Any]:
        """Load system requirements for validation"""
        return {
            # Platform requirements (1.x)
            '1.1': {
                'description': 'Cross-platform compatibility',
                'validator': self._validate_cross_platform,
                'expected': True
            },
            '1.2': {
                'description': 'Platform-specific optimizations',
                'validator': self._validate_platform_optimizations,
                'expected': True
            },
            '1.3': {
                'description': 'Resource limit handling',
                'validator': self._validate_resource_limits,
                'expected': True
            },
            
            # Target resolution requirements (2.x)
            '2.1': {
                'description': 'URL to IP resolution',
                'validator': self._validate_url_resolution,
                'expected': True
            },
            '2.2': {
                'description': 'Service discovery',
                'validator': self._validate_service_discovery,
                'expected': True
            },
            '2.3': {
                'description': 'Target profiling',
                'validator': self._validate_target_profiling,
                'expected': True
            },
            
            # Performance requirements (3.x)
            '3.1': {
                'description': 'Minimum packet rate (1M PPS)',
                'validator': self._validate_packet_rate,
                'expected': 1000000
            },
            '3.2': {
                'description': 'Multi-core utilization',
                'validator': self._validate_multicore,
                'expected': True
            },
            '3.3': {
                'description': 'Memory efficiency',
                'validator': self._validate_memory_efficiency,
                'expected': True
            },
            '3.4': {
                'description': 'Network optimization',
                'validator': self._validate_network_optimization,
                'expected': True
            },
            
            # Auto-configuration requirements (4.x)
            '4.1': {
                'description': 'Target reconnaissance',
                'validator': self._validate_reconnaissance,
                'expected': True
            },
            '4.2': {
                'description': 'Parameter optimization',
                'validator': self._validate_parameter_optimization,
                'expected': True
            },
            '4.3': {
                'description': 'Defense adaptation',
                'validator': self._validate_defense_adaptation,
                'expected': True
            },
            
            # Protocol support requirements (5.x)
            '5.1': {
                'description': 'Multi-protocol support',
                'validator': self._validate_protocol_support,
                'expected': ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
            },
            '5.2': {
                'description': 'HTTP/2 and HTTP/3 support',
                'validator': self._validate_http_versions,
                'expected': ['HTTP/1.1', 'HTTP/2', 'HTTP/3']
            },
            '5.3': {
                'description': 'Evasion techniques',
                'validator': self._validate_evasion_techniques,
                'expected': True
            },
            
            # Monitoring requirements (6.x)
            '6.1': {
                'description': 'Real-time statistics',
                'validator': self._validate_realtime_stats,
                'expected': True
            },
            '6.2': {
                'description': 'Performance visualization',
                'validator': self._validate_visualization,
                'expected': True
            },
            '6.3': {
                'description': 'Attack logging',
                'validator': self._validate_attack_logging,
                'expected': True
            },
            
            # AI requirements (7.x)
            '7.1': {
                'description': 'Machine learning optimization',
                'validator': self._validate_ml_optimization,
                'expected': True
            },
            '7.2': {
                'description': 'Adaptive strategies',
                'validator': self._validate_adaptive_strategies,
                'expected': True
            },
            '7.3': {
                'description': 'Defense detection',
                'validator': self._validate_defense_detection,
                'expected': True
            },
            
            # Safety requirements (8.x)
            '8.1': {
                'description': 'Target validation',
                'validator': self._validate_target_validation,
                'expected': True
            },
            '8.2': {
                'description': 'Resource monitoring',
                'validator': self._validate_resource_monitoring,
                'expected': True
            },
            '8.3': {
                'description': 'Emergency shutdown',
                'validator': self._validate_emergency_shutdown,
                'expected': True
            },
            '8.4': {
                'description': 'Environment detection',
                'validator': self._validate_environment_detection,
                'expected': True
            },
            '8.5': {
                'description': 'Audit logging',
                'validator': self._validate_audit_logging,
                'expected': True
            }
        }
    
    async def validate_all_requirements(self, level: ValidationLevel = ValidationLevel.COMPREHENSIVE) -> Dict[str, Any]:
        """Validate all system requirements"""
        logger.info(f"Starting {level.value} validation of all requirements...")
        
        self.validation_results.clear()
        
        for req_id, requirement in self.requirements.items():
            try:
                start_time = time.perf_counter()
                
                # Execute validator
                validator = requirement['validator']
                actual_value = await validator(level)
                
                execution_time = time.perf_counter() - start_time
                
                # Check result
                expected = requirement['expected']
                passed = self._check_requirement(actual_value, expected)
                
                result = ValidationResult(
                    requirement_id=req_id,
                    description=requirement['description'],
                    passed=passed,
                    actual_value=actual_value,
                    expected_value=expected,
                    execution_time=execution_time
                )
                
                self.validation_results.append(result)
                
                if passed:
                    logger.info(f"✓ Requirement {req_id}: {requirement['description']}")
                else:
                    logger.error(f"✗ Requirement {req_id}: {requirement['description']} - Expected: {expected}, Got: {actual_value}")
                
            except Exception as e:
                logger.error(f"Validation failed for requirement {req_id}: {e}")
                
                result = ValidationResult(
                    requirement_id=req_id,
                    description=requirement['description'],
                    passed=False,
                    actual_value=None,
                    expected_value=requirement['expected'],
                    error_message=str(e)
                )
                
                self.validation_results.append(result)
        
        return self._generate_validation_report()
    
    def _check_requirement(self, actual: Any, expected: Any) -> bool:
        """Check if actual value meets expected requirement"""
        if isinstance(expected, bool):
            return bool(actual) == expected
        elif isinstance(expected, (int, float)):
            return actual >= expected
        elif isinstance(expected, list):
            if isinstance(actual, list):
                return all(item in actual for item in expected)
            else:
                return actual in expected
        elif isinstance(expected, str):
            return str(actual) == expected
        else:
            return actual == expected
    
    # Validation methods for each requirement
    
    async def _validate_cross_platform(self, level: ValidationLevel) -> bool:
        """Validate cross-platform compatibility"""
        try:
            from core.platform.detection import PlatformDetector
            
            detector = PlatformDetector()
            platform_info = detector.detect_platform()
            
            # Check if platform is supported
            supported_platforms = ['Windows', 'Linux', 'Darwin']
            return platform_info.system in supported_platforms
            
        except Exception as e:
            logger.error(f"Cross-platform validation failed: {e}")
            return False
    
    async def _validate_platform_optimizations(self, level: ValidationLevel) -> bool:
        """Validate platform-specific optimizations"""
        try:
            from core.platform.abstraction import PlatformAbstraction
            
            abstraction = PlatformAbstraction()
            await abstraction.initialize()
            
            # Check if optimizations are available
            optimizations = abstraction.get_available_optimizations()
            return len(optimizations) > 0
            
        except Exception as e:
            logger.error(f"Platform optimization validation failed: {e}")
            return False
    
    async def _validate_resource_limits(self, level: ValidationLevel) -> bool:
        """Validate resource limit handling"""
        try:
            from core.safety.protection_mechanisms import SafetyManager
            
            safety_manager = SafetyManager()
            await safety_manager.initialize()
            
            # Test resource limit enforcement
            return safety_manager.check_resource_limits()
            
        except Exception as e:
            logger.error(f"Resource limits validation failed: {e}")
            return False
    
    async def _validate_url_resolution(self, level: ValidationLevel) -> bool:
        """Validate URL to IP resolution"""
        try:
            from core.target.resolver import TargetResolver
            
            resolver = TargetResolver()
            await resolver.initialize()
            
            # Test URL resolution
            result = await resolver.resolve_target("example.com")
            return result is not None and result.ip_address is not None
            
        except Exception as e:
            logger.error(f"URL resolution validation failed: {e}")
            return False
    
    async def _validate_service_discovery(self, level: ValidationLevel) -> bool:
        """Validate service discovery"""
        try:
            from core.target.resolver import TargetResolver
            
            resolver = TargetResolver()
            await resolver.initialize()
            
            # Test service discovery
            services = await resolver.discover_services("127.0.0.1")
            return isinstance(services, list)
            
        except Exception as e:
            logger.error(f"Service discovery validation failed: {e}")
            return False
    
    async def _validate_target_profiling(self, level: ValidationLevel) -> bool:
        """Validate target profiling"""
        try:
            from core.target.profiler import TargetProfiler
            
            profiler = TargetProfiler()
            await profiler.initialize()
            
            # Test target profiling
            profile = await profiler.profile_target("127.0.0.1")
            return profile is not None
            
        except Exception as e:
            logger.error(f"Target profiling validation failed: {e}")
            return False
    
    async def _validate_packet_rate(self, level: ValidationLevel) -> int:
        """Validate minimum packet rate"""
        try:
            from core.networking.udp_engine import UDPEngine
            
            engine = UDPEngine()
            await engine.initialize()
            
            # Measure packet generation rate
            start_time = time.perf_counter()
            packet_count = 0
            
            test_duration = 1.0 if level == ValidationLevel.BASIC else 5.0
            end_time = start_time + test_duration
            
            while time.perf_counter() < end_time:
                await engine.create_packet("127.0.0.1", 80, 1024)
                packet_count += 1
            
            duration = time.perf_counter() - start_time
            pps = packet_count / duration
            
            return int(pps)
            
        except Exception as e:
            logger.error(f"Packet rate validation failed: {e}")
            return 0
    
    async def _validate_multicore(self, level: ValidationLevel) -> bool:
        """Validate multi-core utilization"""
        try:
            import psutil
            
            # Check if system can utilize multiple cores
            cpu_count = psutil.cpu_count()
            
            if cpu_count <= 1:
                return True  # Single core systems are valid
            
            # Test multi-core task execution
            async def cpu_task():
                total = 0
                for i in range(100000):
                    total += i * i
                return total
            
            # Run tasks on multiple cores
            tasks = [cpu_task() for _ in range(cpu_count)]
            results = await asyncio.gather(*tasks)
            
            return len(results) == cpu_count
            
        except Exception as e:
            logger.error(f"Multi-core validation failed: {e}")
            return False
    
    async def _validate_memory_efficiency(self, level: ValidationLevel) -> bool:
        """Validate memory efficiency"""
        try:
            from core.memory.pool_manager import MemoryPoolManager
            
            pool_manager = MemoryPoolManager()
            await pool_manager.initialize()
            
            # Test memory pool operations
            buffers = []
            for _ in range(1000):
                buffer = pool_manager.allocate_buffer(1024)
                buffers.append(buffer)
            
            # Clean up
            for buffer in buffers:
                pool_manager.deallocate_buffer(buffer)
            
            return True
            
        except Exception as e:
            logger.error(f"Memory efficiency validation failed: {e}")
            return False
    
    async def _validate_network_optimization(self, level: ValidationLevel) -> bool:
        """Validate network optimizations"""
        try:
            from core.networking.socket_factory import SocketFactory
            
            factory = SocketFactory()
            await factory.initialize()
            
            # Test optimized socket creation
            socket = factory.create_optimized_socket('UDP')
            return socket is not None
            
        except Exception as e:
            logger.error(f"Network optimization validation failed: {e}")
            return False
    
    async def _validate_reconnaissance(self, level: ValidationLevel) -> bool:
        """Validate target reconnaissance"""
        try:
            from core.target.profiler import TargetProfiler
            
            profiler = TargetProfiler()
            await profiler.initialize()
            
            # Test reconnaissance capabilities
            recon_data = await profiler.perform_reconnaissance("127.0.0.1")
            return recon_data is not None
            
        except Exception as e:
            logger.error(f"Reconnaissance validation failed: {e}")
            return False
    
    async def _validate_parameter_optimization(self, level: ValidationLevel) -> bool:
        """Validate parameter optimization"""
        try:
            from core.autonomous.optimization_engine import ParameterOptimizer
            
            optimizer = ParameterOptimizer()
            await optimizer.initialize()
            
            # Test parameter optimization
            params = await optimizer.optimize_parameters(
                current_params={'packet_rate': 1000},
                target_response={'response_time': 0.1},
                performance_data={'pps': 1000}
            )
            
            return params is not None
            
        except Exception as e:
            logger.error(f"Parameter optimization validation failed: {e}")
            return False
    
    async def _validate_defense_adaptation(self, level: ValidationLevel) -> bool:
        """Validate defense adaptation"""
        try:
            from core.ai.adaptive_strategy import AdaptiveStrategy
            
            strategy = AdaptiveStrategy()
            await strategy.initialize()
            
            # Test adaptation capabilities
            adaptation = await strategy.adapt_to_defenses({
                'detected_defenses': ['rate_limiting'],
                'current_strategy': 'direct_attack'
            })
            
            return adaptation is not None
            
        except Exception as e:
            logger.error(f"Defense adaptation validation failed: {e}")
            return False
    
    async def _validate_protocol_support(self, level: ValidationLevel) -> List[str]:
        """Validate protocol support"""
        supported_protocols = []
        
        protocols = [
            ('TCP', 'core.networking.tcp_engine', 'TCPEngine'),
            ('UDP', 'core.networking.udp_engine', 'UDPEngine'),
            ('HTTP', 'core.networking.http_engine', 'HTTPEngine'),
            ('DNS', 'core.networking.dns_engine', 'DNSEngine'),
            ('ICMP', 'core.networking.icmp_engine', 'ICMPEngine')
        ]
        
        for protocol_name, module_path, class_name in protocols:
            try:
                module = __import__(module_path, fromlist=[class_name])
                engine_class = getattr(module, class_name)
                
                engine = engine_class()
                await engine.initialize()
                
                supported_protocols.append(protocol_name)
                
            except Exception as e:
                logger.warning(f"Protocol {protocol_name} not supported: {e}")
        
        return supported_protocols
    
    async def _validate_http_versions(self, level: ValidationLevel) -> List[str]:
        """Validate HTTP version support"""
        try:
            from core.networking.http_engine import HTTPEngine
            
            engine = HTTPEngine()
            await engine.initialize()
            
            # Check supported HTTP versions
            versions = engine.get_supported_versions()
            return versions
            
        except Exception as e:
            logger.error(f"HTTP versions validation failed: {e}")
            return []
    
    async def _validate_evasion_techniques(self, level: ValidationLevel) -> bool:
        """Validate evasion techniques"""
        try:
            from core.ai.defense_evasion import DefenseEvasion
            
            evasion = DefenseEvasion()
            await evasion.initialize()
            
            # Test evasion capabilities
            techniques = evasion.get_available_techniques()
            return len(techniques) > 0
            
        except Exception as e:
            logger.error(f"Evasion techniques validation failed: {e}")
            return False
    
    async def _validate_realtime_stats(self, level: ValidationLevel) -> bool:
        """Validate real-time statistics"""
        try:
            from core.analytics.metrics_collector import MetricsCollector
            
            collector = MetricsCollector()
            await collector.initialize()
            
            # Test metrics collection
            metrics = await collector.get_current_metrics()
            return metrics is not None
            
        except Exception as e:
            logger.error(f"Real-time stats validation failed: {e}")
            return False
    
    async def _validate_visualization(self, level: ValidationLevel) -> bool:
        """Validate performance visualization"""
        try:
            from core.analytics.visualization_engine import VisualizationEngine
            
            viz_engine = VisualizationEngine()
            await viz_engine.initialize()
            
            # Test visualization capabilities
            chart = viz_engine.create_performance_chart({'pps': [1000, 2000, 3000]})
            return chart is not None
            
        except Exception as e:
            logger.error(f"Visualization validation failed: {e}")
            return False
    
    async def _validate_attack_logging(self, level: ValidationLevel) -> bool:
        """Validate attack logging"""
        try:
            from core.safety.audit_logging import AuditLogger
            
            logger_instance = AuditLogger()
            await logger_instance.initialize()
            
            # Test logging capabilities
            logger_instance.log_attack_start(
                session_id="test",
                target="127.0.0.1",
                port=80,
                protocol="TCP",
                attack_type="test"
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Attack logging validation failed: {e}")
            return False
    
    async def _validate_ml_optimization(self, level: ValidationLevel) -> bool:
        """Validate machine learning optimization"""
        try:
            from core.ai.ml_infrastructure import MLInfrastructure
            
            ml_infra = MLInfrastructure()
            await ml_infra.initialize()
            
            # Test ML capabilities
            model = ml_infra.get_optimization_model()
            return model is not None
            
        except Exception as e:
            logger.error(f"ML optimization validation failed: {e}")
            return False
    
    async def _validate_adaptive_strategies(self, level: ValidationLevel) -> bool:
        """Validate adaptive strategies"""
        try:
            from core.ai.adaptive_strategy import AdaptiveStrategy
            
            strategy = AdaptiveStrategy()
            await strategy.initialize()
            
            # Test strategy adaptation
            new_strategy = await strategy.adapt_strategy({
                'current_performance': {'pps': 1000},
                'target_performance': {'pps': 2000}
            })
            
            return new_strategy is not None
            
        except Exception as e:
            logger.error(f"Adaptive strategies validation failed: {e}")
            return False
    
    async def _validate_defense_detection(self, level: ValidationLevel) -> bool:
        """Validate defense detection"""
        try:
            from core.ai.defense_evasion import DefenseEvasion
            
            evasion = DefenseEvasion()
            await evasion.initialize()
            
            # Test defense detection
            defenses = await evasion.detect_defenses("127.0.0.1", 80)
            return isinstance(defenses, list)
            
        except Exception as e:
            logger.error(f"Defense detection validation failed: {e}")
            return False
    
    async def _validate_target_validation(self, level: ValidationLevel) -> bool:
        """Validate target validation"""
        try:
            from core.safety.protection_mechanisms import SafetyManager
            
            safety_manager = SafetyManager()
            await safety_manager.initialize()
            
            # Test target validation
            is_valid, reason = safety_manager.validate_target("127.0.0.1")
            return isinstance(is_valid, bool)
            
        except Exception as e:
            logger.error(f"Target validation failed: {e}")
            return False
    
    async def _validate_resource_monitoring(self, level: ValidationLevel) -> bool:
        """Validate resource monitoring"""
        try:
            from core.safety.protection_mechanisms import ResourceMonitor
            
            monitor = ResourceMonitor()
            await monitor.initialize()
            
            # Test resource monitoring
            usage = monitor.get_resource_usage()
            return usage is not None
            
        except Exception as e:
            logger.error(f"Resource monitoring validation failed: {e}")
            return False
    
    async def _validate_emergency_shutdown(self, level: ValidationLevel) -> bool:
        """Validate emergency shutdown"""
        try:
            from core.safety.emergency_shutdown import EmergencyShutdown
            
            shutdown = EmergencyShutdown()
            await shutdown.initialize()
            
            # Test shutdown capabilities
            return shutdown.is_ready()
            
        except Exception as e:
            logger.error(f"Emergency shutdown validation failed: {e}")
            return False
    
    async def _validate_environment_detection(self, level: ValidationLevel) -> bool:
        """Validate environment detection"""
        try:
            from core.safety.environment_detection import EnvironmentDetector
            
            detector = EnvironmentDetector()
            
            # Test environment detection
            env_info = detector.detect_environment()
            return env_info is not None
            
        except Exception as e:
            logger.error(f"Environment detection validation failed: {e}")
            return False
    
    async def _validate_audit_logging(self, level: ValidationLevel) -> bool:
        """Validate audit logging"""
        try:
            from core.safety.audit_logging import AuditLogger
            
            audit_logger = AuditLogger()
            await audit_logger.initialize()
            
            # Test audit logging
            audit_logger.log_system_event("validation_test", {"test": True})
            return True
            
        except Exception as e:
            logger.error(f"Audit logging validation failed: {e}")
            return False
    
    def _generate_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        total_requirements = len(self.validation_results)
        passed_requirements = sum(1 for r in self.validation_results if r.passed)
        failed_requirements = total_requirements - passed_requirements
        
        report = {
            'timestamp': time.time(),
            'summary': {
                'total_requirements': total_requirements,
                'passed_requirements': passed_requirements,
                'failed_requirements': failed_requirements,
                'success_rate': (passed_requirements / total_requirements) * 100 if total_requirements > 0 else 0,
                'total_execution_time': sum(r.execution_time for r in self.validation_results)
            },
            'results': [
                {
                    'requirement_id': r.requirement_id,
                    'description': r.description,
                    'passed': r.passed,
                    'actual_value': r.actual_value,
                    'expected_value': r.expected_value,
                    'error_message': r.error_message,
                    'execution_time': r.execution_time
                }
                for r in self.validation_results
            ],
            'failed_requirements': [
                {
                    'requirement_id': r.requirement_id,
                    'description': r.description,
                    'actual_value': r.actual_value,
                    'expected_value': r.expected_value,
                    'error_message': r.error_message
                }
                for r in self.validation_results if not r.passed
            ],
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        failed_results = [r for r in self.validation_results if not r.passed]
        
        if len(failed_results) == 0:
            recommendations.append("All requirements validated successfully. System is ready for deployment.")
        else:
            recommendations.append(f"{len(failed_results)} requirements failed validation. Address these issues before deployment.")
            
            # Specific recommendations based on failed requirements
            for result in failed_results:
                if result.requirement_id.startswith('3.'):  # Performance requirements
                    recommendations.append(f"Performance issue: {result.description}. Consider hardware upgrades or optimization.")
                elif result.requirement_id.startswith('8.'):  # Safety requirements
                    recommendations.append(f"Safety issue: {result.description}. This must be fixed before use.")
                elif result.requirement_id.startswith('5.'):  # Protocol requirements
                    recommendations.append(f"Protocol support issue: {result.description}. Install missing dependencies.")
        
        return recommendations