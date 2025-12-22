"""
Enhanced Adaptation Integration

Provides enhanced adaptive rate limiting and real-time adaptation
capabilities for integration with the main DDoS framework.
"""

import asyncio
import logging
import time
from typing import Dict, Callable, Any

logger = logging.getLogger(__name__)

async def enhanced_adaptive_rate_limiter(stats, 
                                       adaptation_interval: float = 5.0,
                                       initial_pps: int = 1000):
    """Enhanced adaptive rate limiter with real-time adaptation system"""
    
    try:
        from core.autonomous.adaptation_system import RealTimeAdaptationSystem, SystemState
        
        adaptation_system = RealTimeAdaptationSystem(adaptation_interval=adaptation_interval)
        
        # Register adaptation callbacks
        def adjust_packet_rate(params):
            factor = params.get('factor', 0.8)
            adjustment = params.get('adjustment', 0.0)
            
            with stats.current_pps.get_lock():
                if 'factor' in params:
                    stats.current_pps.value = int(stats.current_pps.value * factor)
                elif 'adjustment' in params:
                    stats.current_pps.value = int(stats.current_pps.value * (1 + adjustment))
                    
            logger.info(f"Adapted packet rate: factor={factor}, adjustment={adjustment}")
        
        def reduce_concurrency(params):
            factor = params.get('factor', 0.7)
            logger.info(f"Reducing concurrency by factor {factor}")
        
        def optimize_resources(params):
            target_metric = params.get('target_metric', 'cpu_usage')
            reduction = params.get('reduction', 0.1)
            logger.info(f"Optimizing {target_metric} with reduction {reduction}")
        
        def enable_evasion_techniques(params):
            techniques = params.get('techniques', [])
            logger.info(f"Enabling evasion techniques: {techniques}")
        
        def change_protocol_mix(params):
            increase_udp = params.get('increase_udp', False)
            logger.info(f"Changing protocol mix: increase_udp={increase_udp}")
        
        def increase_delays(params):
            delay_multiplier = params.get('delay_multiplier', 1.5)
            logger.info(f"Increasing delays by multiplier {delay_multiplier}")
        
        def optimize_memory_usage(params):
            enable_compression = params.get('enable_compression', False)
            logger.info(f"Optimizing memory usage: compression={enable_compression}")
        
        def adaptive_rate_control(params):
            enable = params.get('enable', True)
            target_latency = params.get('target_latency', 0.5)
            logger.info(f"Adaptive rate control: enable={enable}, target_latency={target_latency}")
        
        def optimize_packet_size(params):
            target_mtu = params.get('target_mtu', False)
            logger.info(f"Optimizing packet size: target_mtu={target_mtu}")
        
        # Register all callbacks
        callbacks = {
            "reduce_packet_rate": adjust_packet_rate,
            "adjust_packet_rate": adjust_packet_rate,
            "reduce_concurrency": reduce_concurrency,
            "reduce_intensity": adjust_packet_rate,
            "optimize_resources": optimize_resources,
            "enable_evasion_techniques": enable_evasion_techniques,
            "change_protocol_mix": change_protocol_mix,
            "increase_delays": increase_delays,
            "optimize_memory_usage": optimize_memory_usage,
            "adaptive_rate_control": adaptive_rate_control,
            "optimize_packet_size": optimize_packet_size
        }
        
        for action_type, callback in callbacks.items():
            adaptation_system.register_adaptation_callback(action_type, callback)
        
        # Metrics provider function
        def get_metrics():
            report = stats.report()
            return {
                'success_rate': min(1.0, report.get('conn_rate', 0) / 1000.0),
                'packet_rate': report.get('pps', 0),
                'error_rate': report.get('errors', 0) / max(1, report.get('packets_sent', 1)),
                'bandwidth_utilization': report.get('bps', 0) / 1e9
            }
        
        # System state provider function
        def get_system_state():
            try:
                import psutil
                cpu_usage = psutil.cpu_percent() / 100.0
                memory_usage = psutil.virtual_memory().percent / 100.0
            except ImportError:
                cpu_usage = 0.5  # Default values if psutil not available
                memory_usage = 0.5
            
            report = stats.report()
            return SystemState(
                packet_rate=report.get('pps', 0),
                success_rate=min(1.0, report.get('conn_rate', 0) / 1000.0),
                error_rate=report.get('errors', 0) / max(1, report.get('packets_sent', 1)),
                bandwidth_utilization=report.get('bps', 0) / 1e9,
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                network_latency=0.1  # Placeholder - could be measured
            )
        
        # Start advanced adaptation system
        logger.info("Starting enhanced real-time adaptation system")
        await adaptation_system.start_monitoring(get_metrics, get_system_state)
        
    except ImportError as e:
        logger.warning(f"Advanced adaptation system not available ({e}), using fallback")
        await fallback_adaptive_rate_limiter(stats, adaptation_interval, initial_pps)
    except Exception as e:
        logger.error(f"Enhanced adaptation system failed ({e}), using fallback")
        await fallback_adaptive_rate_limiter(stats, adaptation_interval, initial_pps)

async def fallback_adaptive_rate_limiter(stats, 
                                       adaptation_interval: float = 5.0,
                                       initial_pps: int = 1000):
    """Fallback adaptive rate limiter (original implementation)"""
    
    while True:
        await asyncio.sleep(adaptation_interval)
        report = stats.report()
        current_pps = report.get('current_pps', initial_pps)
        errors = report.get('errors', 0)
        
        if errors > current_pps * 0.1:
            stats.adjust_rate(False)
            logger.debug("Decreased attack rate")
        else:
            stats.adjust_rate(True)
            logger.debug("Increased attack rate")