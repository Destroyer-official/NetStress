"""
Real-Time Adaptation System

Implements continuous monitoring and adjustment capabilities, feedback loops
for performance optimization, and automatic recovery and failover mechanisms.
"""

import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from collections import deque
from enum import Enum
import numpy as np

logger = logging.getLogger(__name__)

class AdaptationTrigger(Enum):
    """Types of events that can trigger adaptation"""
    PERFORMANCE_DEGRADATION = "performance_degradation"
    ERROR_RATE_INCREASE = "error_rate_increase"
    TARGET_DEFENSE_DETECTED = "target_defense_detected"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    NETWORK_CONGESTION = "network_congestion"
    TIMEOUT_INCREASE = "timeout_increase"
    SUCCESS_RATE_DROP = "success_rate_drop"

@dataclass
class AdaptationEvent:
    """Represents an adaptation event"""
    trigger: AdaptationTrigger
    severity: float  # 0.0 to 1.0
    timestamp: float = field(default_factory=time.time)
    metrics: Dict[str, Any] = field(default_factory=dict)
    suggested_actions: List[str] = field(default_factory=list)

@dataclass
class AdaptationAction:
    """Represents an adaptation action to be taken"""
    action_type: str
    parameters: Dict[str, Any]
    priority: int  # 1 (highest) to 10 (lowest)
    estimated_impact: float  # Expected improvement (0.0 to 1.0)
    rollback_possible: bool = True

@dataclass
class SystemState:
    """Current state of the attack system"""
    packet_rate: float
    success_rate: float
    error_rate: float
    bandwidth_utilization: float
    cpu_usage: float
    memory_usage: float
    network_latency: float
    timestamp: float = field(default_factory=time.time)

class FeedbackLoop:
    """
    Implements feedback control loop for continuous system optimization
    """
    
    def __init__(self, 
                 target_metrics: Dict[str, float],
                 control_gains: Dict[str, float] = None):
        self.target_metrics = target_metrics
        self.control_gains = control_gains or {
            'proportional': 0.5,
            'integral': 0.1,
            'derivative': 0.2
        }
        
        self.error_history = deque(maxlen=50)
        self.integral_error = {}
        self.previous_error = {}
        self.last_update = time.time()
        
    def update(self, current_metrics: Dict[str, float]) -> Dict[str, float]:
        """Update feedback loop with current metrics and return control signals"""
        
        current_time = time.time()
        dt = current_time - self.last_update
        
        control_signals = {}
        
        for metric, target_value in self.target_metrics.items():
            if metric not in current_metrics:
                continue
                
            current_value = current_metrics[metric]
            error = target_value - current_value
            
            # Initialize error tracking for new metrics
            if metric not in self.integral_error:
                self.integral_error[metric] = 0.0
                self.previous_error[metric] = 0.0
            
            # PID control calculation
            proportional = error
            self.integral_error[metric] += error * dt
            derivative = (error - self.previous_error[metric]) / dt if dt > 0 else 0
            
            # Calculate control signal
            control_signal = (
                self.control_gains['proportional'] * proportional +
                self.control_gains['integral'] * self.integral_error[metric] +
                self.control_gains['derivative'] * derivative
            )
            
            control_signals[metric] = control_signal
            self.previous_error[metric] = error
        
        # Store error for analysis
        self.error_history.append({
            'timestamp': current_time,
            'errors': {metric: target - current_metrics.get(metric, 0) 
                      for metric, target in self.target_metrics.items()},
            'control_signals': control_signals.copy()
        })
        
        self.last_update = current_time
        return control_signals
    
    def get_stability_metrics(self) -> Dict[str, float]:
        """Calculate system stability metrics"""
        if len(self.error_history) < 10:
            return {"status": "insufficient_data"}
        
        if not self.target_metrics:
            return {"status": "no_target_metrics", "overall_stability": 0.5}
        
        recent_errors = list(self.error_history)[-10:]
        
        stability_metrics = {}
        
        for metric in self.target_metrics.keys():
            errors = [e['errors'].get(metric, 0) for e in recent_errors]
            if not errors:
                continue
            
            stability_metrics[f"{metric}_variance"] = np.var(errors)
            stability_metrics[f"{metric}_mean_error"] = np.mean(np.abs(errors))
            stability_metrics[f"{metric}_trend"] = self._calculate_trend(errors)
        
        # Overall stability score
        variances = [v for k, v in stability_metrics.items() if k.endswith('_variance')]
        if variances:
            stability_metrics['overall_stability'] = 1.0 / (1.0 + np.mean(variances))
        else:
            stability_metrics['overall_stability'] = 0.5
        
        return stability_metrics
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend in error values (-1 to 1, where -1 is improving)"""
        if len(values) < 3:
            return 0.0
        
        # Simple linear regression slope
        x = np.arange(len(values))
        y = np.array(values)
        
        slope = np.corrcoef(x, y)[0, 1] if np.std(y) > 0 else 0.0
        return np.clip(slope, -1.0, 1.0)

class RealTimeAdaptationSystem:
    """
    Main real-time adaptation system that monitors performance and
    automatically adjusts parameters to maintain optimal performance.
    """
    
    def __init__(self, 
                 adaptation_interval: float = 1.0,
                 max_adaptations_per_minute: int = 10):
        self.adaptation_interval = adaptation_interval
        self.max_adaptations_per_minute = max_adaptations_per_minute
        
        self.monitoring_active = False
        self.adaptation_callbacks = {}
        self.event_handlers = {}
        self.system_state_history = deque(maxlen=100)
        self.adaptation_history = deque(maxlen=50)
        self.recent_adaptations = deque(maxlen=max_adaptations_per_minute)
        
        # Feedback loops for different aspects
        self.performance_feedback = FeedbackLoop({
            'success_rate': 0.8,
            'packet_rate': 10000,
            'error_rate': 0.05
        })
        
        self.resource_feedback = FeedbackLoop({
            'cpu_usage': 0.8,
            'memory_usage': 0.7,
            'network_latency': 0.1
        })
        
        # Thresholds for triggering adaptations
        self.adaptation_thresholds = {
            AdaptationTrigger.PERFORMANCE_DEGRADATION: 0.3,
            AdaptationTrigger.ERROR_RATE_INCREASE: 0.15,
            AdaptationTrigger.SUCCESS_RATE_DROP: 0.5,
            AdaptationTrigger.RESOURCE_EXHAUSTION: 0.9,
            AdaptationTrigger.NETWORK_CONGESTION: 0.8,
            AdaptationTrigger.TIMEOUT_INCREASE: 2.0
        }
        
    async def start_monitoring(self, 
                             metrics_provider: Callable[[], Dict[str, float]],
                             system_state_provider: Callable[[], SystemState]):
        """Start real-time monitoring and adaptation"""
        
        self.monitoring_active = True
        logger.info("Real-time adaptation system started")
        
        try:
            while self.monitoring_active:
                # Get current metrics and system state
                current_metrics = metrics_provider()
                current_state = system_state_provider()
                
                # Store system state
                self.system_state_history.append(current_state)
                
                # Analyze for adaptation triggers
                events = self._analyze_for_adaptation_triggers(current_metrics, current_state)
                
                # Process events and generate actions
                for event in events:
                    await self._process_adaptation_event(event)
                
                # Update feedback loops
                performance_signals = self.performance_feedback.update(current_metrics)
                resource_signals = self.resource_feedback.update({
                    'cpu_usage': current_state.cpu_usage,
                    'memory_usage': current_state.memory_usage,
                    'network_latency': current_state.network_latency
                })
                
                # Apply feedback control
                await self._apply_feedback_control(performance_signals, resource_signals)
                
                await asyncio.sleep(self.adaptation_interval)
                
        except Exception as e:
            logger.error(f"Adaptation system error: {e}")
        finally:
            self.monitoring_active = False
            logger.info("Real-time adaptation system stopped")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
    
    def register_adaptation_callback(self, 
                                   action_type: str, 
                                   callback: Callable[[Dict[str, Any]], None]):
        """Register callback for specific adaptation actions"""
        self.adaptation_callbacks[action_type] = callback
    
    def register_event_handler(self, 
                             trigger: AdaptationTrigger,
                             handler: Callable[[AdaptationEvent], List[AdaptationAction]]):
        """Register custom event handler for specific triggers"""
        self.event_handlers[trigger] = handler
    
    def _analyze_for_adaptation_triggers(self, 
                                       metrics: Dict[str, float],
                                       state: SystemState) -> List[AdaptationEvent]:
        """Analyze current state for adaptation triggers"""
        
        events = []
        
        # Performance degradation detection
        if len(self.system_state_history) >= 5:
            recent_states = list(self.system_state_history)[-5:]
            avg_recent_success = np.mean([s.success_rate for s in recent_states])
            
            if avg_recent_success < self.adaptation_thresholds[AdaptationTrigger.PERFORMANCE_DEGRADATION]:
                events.append(AdaptationEvent(
                    trigger=AdaptationTrigger.PERFORMANCE_DEGRADATION,
                    severity=1.0 - avg_recent_success,
                    metrics={'avg_success_rate': avg_recent_success},
                    suggested_actions=['reduce_packet_rate', 'change_protocol_mix', 'enable_evasion']
                ))
        
        # Error rate increase detection
        if state.error_rate > self.adaptation_thresholds[AdaptationTrigger.ERROR_RATE_INCREASE]:
            events.append(AdaptationEvent(
                trigger=AdaptationTrigger.ERROR_RATE_INCREASE,
                severity=min(1.0, state.error_rate / 0.5),
                metrics={'error_rate': state.error_rate},
                suggested_actions=['reduce_concurrency', 'increase_delays', 'switch_protocol']
            ))
        
        # Resource exhaustion detection
        if (state.cpu_usage > self.adaptation_thresholds[AdaptationTrigger.RESOURCE_EXHAUSTION] or
            state.memory_usage > self.adaptation_thresholds[AdaptationTrigger.RESOURCE_EXHAUSTION]):
            
            events.append(AdaptationEvent(
                trigger=AdaptationTrigger.RESOURCE_EXHAUSTION,
                severity=max(state.cpu_usage, state.memory_usage),
                metrics={'cpu_usage': state.cpu_usage, 'memory_usage': state.memory_usage},
                suggested_actions=['reduce_concurrency', 'optimize_memory', 'scale_down']
            ))
        
        # Network congestion detection
        if state.network_latency > self.adaptation_thresholds[AdaptationTrigger.NETWORK_CONGESTION]:
            events.append(AdaptationEvent(
                trigger=AdaptationTrigger.NETWORK_CONGESTION,
                severity=min(1.0, state.network_latency / 5.0),
                metrics={'network_latency': state.network_latency},
                suggested_actions=['reduce_packet_rate', 'increase_packet_size', 'add_delays']
            ))
        
        # Success rate drop detection
        if state.success_rate < self.adaptation_thresholds[AdaptationTrigger.SUCCESS_RATE_DROP]:
            events.append(AdaptationEvent(
                trigger=AdaptationTrigger.SUCCESS_RATE_DROP,
                severity=1.0 - state.success_rate,
                metrics={'success_rate': state.success_rate},
                suggested_actions=['change_strategy', 'enable_evasion', 'adjust_timing']
            ))
        
        return events
    
    async def _process_adaptation_event(self, event: AdaptationEvent):
        """Process an adaptation event and execute appropriate actions"""
        
        # Check rate limiting
        current_time = time.time()
        self.recent_adaptations = deque([
            t for t in self.recent_adaptations 
            if current_time - t < 60.0  # Keep only last minute
        ], maxlen=self.max_adaptations_per_minute)
        
        if len(self.recent_adaptations) >= self.max_adaptations_per_minute:
            logger.warning("Adaptation rate limit reached, skipping adaptation")
            return
        
        # Generate actions
        actions = []
        
        # Use custom event handler if available
        if event.trigger in self.event_handlers:
            actions = self.event_handlers[event.trigger](event)
        else:
            # Use default action generation
            actions = self._generate_default_actions(event)
        
        # Sort actions by priority and execute
        actions.sort(key=lambda a: a.priority)
        
        for action in actions[:3]:  # Execute top 3 actions
            try:
                await self._execute_adaptation_action(action)
                self.recent_adaptations.append(current_time)
                
                # Record adaptation
                self.adaptation_history.append({
                    'timestamp': current_time,
                    'event': event,
                    'action': action
                })
                
                logger.info(f"Executed adaptation: {action.action_type} for {event.trigger.value}")
                
            except Exception as e:
                logger.error(f"Failed to execute adaptation action {action.action_type}: {e}")
    
    def _generate_default_actions(self, event: AdaptationEvent) -> List[AdaptationAction]:
        """Generate default adaptation actions for an event"""
        
        actions = []
        
        if event.trigger == AdaptationTrigger.PERFORMANCE_DEGRADATION:
            actions.extend([
                AdaptationAction(
                    action_type="reduce_packet_rate",
                    parameters={"factor": 0.8},
                    priority=2,
                    estimated_impact=0.6
                ),
                AdaptationAction(
                    action_type="enable_evasion_techniques",
                    parameters={"techniques": ["ip_spoofing", "fragmentation"]},
                    priority=1,
                    estimated_impact=0.7
                ),
                AdaptationAction(
                    action_type="change_protocol_mix",
                    parameters={"increase_udp": True},
                    priority=3,
                    estimated_impact=0.5
                )
            ])
        
        elif event.trigger == AdaptationTrigger.ERROR_RATE_INCREASE:
            actions.extend([
                AdaptationAction(
                    action_type="reduce_concurrency",
                    parameters={"factor": 0.7},
                    priority=1,
                    estimated_impact=0.8
                ),
                AdaptationAction(
                    action_type="increase_delays",
                    parameters={"delay_multiplier": 1.5},
                    priority=2,
                    estimated_impact=0.6
                )
            ])
        
        elif event.trigger == AdaptationTrigger.RESOURCE_EXHAUSTION:
            actions.extend([
                AdaptationAction(
                    action_type="optimize_memory_usage",
                    parameters={"enable_compression": True},
                    priority=1,
                    estimated_impact=0.7
                ),
                AdaptationAction(
                    action_type="reduce_concurrency",
                    parameters={"factor": 0.6},
                    priority=2,
                    estimated_impact=0.8
                )
            ])
        
        elif event.trigger == AdaptationTrigger.NETWORK_CONGESTION:
            actions.extend([
                AdaptationAction(
                    action_type="adaptive_rate_control",
                    parameters={"enable": True, "target_latency": 0.5},
                    priority=1,
                    estimated_impact=0.8
                ),
                AdaptationAction(
                    action_type="optimize_packet_size",
                    parameters={"target_mtu": True},
                    priority=2,
                    estimated_impact=0.6
                )
            ])
        
        return actions
    
    async def _execute_adaptation_action(self, action: AdaptationAction):
        """Execute a specific adaptation action"""
        
        if action.action_type in self.adaptation_callbacks:
            # Use registered callback
            callback = self.adaptation_callbacks[action.action_type]
            await asyncio.get_event_loop().run_in_executor(None, callback, action.parameters)
        else:
            # Log unhandled action
            logger.warning(f"No callback registered for adaptation action: {action.action_type}")
    
    async def _apply_feedback_control(self, 
                                    performance_signals: Dict[str, float],
                                    resource_signals: Dict[str, float]):
        """Apply feedback control signals to system parameters"""
        
        # Apply performance feedback
        for metric, signal in performance_signals.items():
            if abs(signal) > 0.1:  # Only apply significant signals
                
                if metric == 'success_rate' and signal < -0.2:
                    # Success rate too low, increase packet rate
                    action = AdaptationAction(
                        action_type="adjust_packet_rate",
                        parameters={"adjustment": abs(signal) * 0.1},
                        priority=3,
                        estimated_impact=0.4
                    )
                    await self._execute_adaptation_action(action)
                
                elif metric == 'error_rate' and signal > 0.2:
                    # Error rate too high, reduce intensity
                    action = AdaptationAction(
                        action_type="reduce_intensity",
                        parameters={"factor": 1.0 - abs(signal) * 0.1},
                        priority=2,
                        estimated_impact=0.6
                    )
                    await self._execute_adaptation_action(action)
        
        # Apply resource feedback
        for metric, signal in resource_signals.items():
            if abs(signal) > 0.1:
                
                if metric in ['cpu_usage', 'memory_usage'] and signal > 0.2:
                    # Resource usage too high
                    action = AdaptationAction(
                        action_type="optimize_resources",
                        parameters={"target_metric": metric, "reduction": abs(signal) * 0.1},
                        priority=1,
                        estimated_impact=0.7
                    )
                    await self._execute_adaptation_action(action)
    
    def get_adaptation_statistics(self) -> Dict[str, Any]:
        """Get statistics about adaptation system performance"""
        
        if not self.adaptation_history:
            return {"status": "no_adaptations"}
        
        recent_adaptations = list(self.adaptation_history)[-20:]
        
        # Count adaptations by trigger type
        trigger_counts = {}
        for adaptation in recent_adaptations:
            trigger = adaptation['event'].trigger.value
            trigger_counts[trigger] = trigger_counts.get(trigger, 0) + 1
        
        # Calculate adaptation effectiveness
        effectiveness_scores = []
        for adaptation in recent_adaptations:
            effectiveness_scores.append(adaptation['action'].estimated_impact)
        
        # System stability metrics
        performance_stability = self.performance_feedback.get_stability_metrics()
        resource_stability = self.resource_feedback.get_stability_metrics()
        
        return {
            "total_adaptations": len(self.adaptation_history),
            "recent_adaptations": len(recent_adaptations),
            "adaptations_by_trigger": trigger_counts,
            "avg_adaptation_effectiveness": np.mean(effectiveness_scores) if effectiveness_scores else 0,
            "adaptation_rate_per_minute": len([
                a for a in recent_adaptations 
                if time.time() - a['timestamp'] < 60
            ]),
            "performance_stability": performance_stability,
            "resource_stability": resource_stability,
            "system_responsive": self.monitoring_active
        }

class AutoRecoverySystem:
    """
    Automatic recovery and failover system for handling critical failures
    """
    
    def __init__(self):
        self.recovery_strategies = {}
        self.failure_history = deque(maxlen=100)
        self.recovery_in_progress = False
        self.backup_configurations = deque(maxlen=5)
        
    def register_recovery_strategy(self, 
                                 failure_type: str,
                                 strategy: Callable[[Dict[str, Any]], bool]):
        """Register a recovery strategy for a specific failure type"""
        self.recovery_strategies[failure_type] = strategy
    
    async def handle_critical_failure(self, 
                                    failure_type: str,
                                    failure_context: Dict[str, Any]) -> bool:
        """Handle a critical system failure"""
        
        if self.recovery_in_progress:
            logger.warning("Recovery already in progress, queuing failure")
            return False
        
        self.recovery_in_progress = True
        
        try:
            # Record failure
            self.failure_history.append({
                'timestamp': time.time(),
                'type': failure_type,
                'context': failure_context
            })
            
            logger.error(f"Critical failure detected: {failure_type}")
            
            # Attempt recovery
            if failure_type in self.recovery_strategies:
                strategy = self.recovery_strategies[failure_type]
                success = await asyncio.get_event_loop().run_in_executor(
                    None, strategy, failure_context
                )
                
                if success:
                    logger.info(f"Recovery successful for {failure_type}")
                    return True
                else:
                    logger.error(f"Recovery failed for {failure_type}")
            
            # Fallback to emergency procedures
            return await self._emergency_recovery(failure_type, failure_context)
            
        finally:
            self.recovery_in_progress = False
    
    async def _emergency_recovery(self, 
                                failure_type: str,
                                failure_context: Dict[str, Any]) -> bool:
        """Emergency recovery procedures"""
        
        logger.warning("Initiating emergency recovery procedures")
        
        # Emergency actions based on failure type
        if failure_type == "network_failure":
            # Switch to backup network configuration
            return await self._switch_to_backup_network()
        
        elif failure_type == "resource_exhaustion":
            # Emergency resource cleanup
            return await self._emergency_resource_cleanup()
        
        elif failure_type == "target_unreachable":
            # Switch to alternative targets or protocols
            return await self._switch_attack_strategy()
        
        else:
            # Generic emergency stop and restart
            return await self._emergency_restart()
    
    async def _switch_to_backup_network(self) -> bool:
        """Switch to backup network configuration"""
        # Implementation would switch network interfaces or routes
        logger.info("Switching to backup network configuration")
        await asyncio.sleep(1)  # Simulate network switch
        return True
    
    async def _emergency_resource_cleanup(self) -> bool:
        """Emergency cleanup of system resources"""
        logger.info("Performing emergency resource cleanup")
        # Implementation would free memory, close connections, etc.
        await asyncio.sleep(0.5)
        return True
    
    async def _switch_attack_strategy(self) -> bool:
        """Switch to alternative attack strategy"""
        logger.info("Switching to alternative attack strategy")
        # Implementation would change protocols, targets, or methods
        await asyncio.sleep(0.5)
        return True
    
    async def _emergency_restart(self) -> bool:
        """Emergency system restart"""
        logger.warning("Performing emergency system restart")
        # Implementation would restart critical components
        await asyncio.sleep(2)
        return True
    
    def save_backup_configuration(self, config: Dict[str, Any]):
        """Save current configuration as backup"""
        self.backup_configurations.append({
            'timestamp': time.time(),
            'config': config.copy()
        })
    
    def get_latest_backup_configuration(self) -> Optional[Dict[str, Any]]:
        """Get the most recent backup configuration"""
        if self.backup_configurations:
            return self.backup_configurations[-1]['config']
        return None