"""
Real-Time Attack Adaptation Module

Provides intelligent attack adaptation based on:
- Target response analysis
- Detection evasion
- Resource optimization
- Effectiveness maximization
"""

import asyncio
import time
import random
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum
from collections import deque
import logging

logger = logging.getLogger(__name__)


class AdaptationStrategy(Enum):
    """Adaptation strategies"""
    AGGRESSIVE = "aggressive"      # Maximize impact
    STEALTHY = "stealthy"          # Minimize detection
    BALANCED = "balanced"          # Balance impact and stealth
    RESOURCE_AWARE = "resource"    # Optimize resource usage
    LEARNING = "learning"          # ML-based adaptation


class TargetState(Enum):
    """Target state assessment"""
    HEALTHY = "healthy"
    STRESSED = "stressed"
    DEGRADED = "degraded"
    FAILING = "failing"
    DOWN = "down"
    RECOVERING = "recovering"


@dataclass
class AdaptiveConfig:
    """Adaptive attack configuration"""
    strategy: AdaptationStrategy = AdaptationStrategy.BALANCED
    min_rate: int = 100
    max_rate: int = 100000
    adaptation_interval: float = 5.0
    learning_rate: float = 0.1
    detection_threshold: float = 0.7
    target_impact: float = 0.5  # Desired target degradation


@dataclass
class ResponseMetrics:
    """Metrics from target responses"""
    response_time: float = 0.0
    status_code: int = 200
    error: bool = False
    timestamp: float = field(default_factory=time.time)
    bytes_received: int = 0


class ResponseAnalyzer:
    """Analyzes target responses for adaptation decisions"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._metrics: deque = deque(maxlen=window_size)
        self._baseline_response_time: Optional[float] = None
        self._state_history: deque = deque(maxlen=20)
        
    def record(self, metrics: ResponseMetrics):
        """Record response metrics"""
        self._metrics.append(metrics)
        
    def set_baseline(self, response_time: float):
        """Set baseline response time"""
        self._baseline_response_time = response_time
        
    def get_state(self) -> TargetState:
        """Assess current target state"""
        if len(self._metrics) < 5:
            return TargetState.HEALTHY
            
        recent = list(self._metrics)[-20:]
        
        # Calculate metrics
        response_times = [m.response_time for m in recent if not m.error]
        error_rate = sum(1 for m in recent if m.error) / len(recent)
        
        if not response_times:
            return TargetState.DOWN
            
        avg_response = statistics.mean(response_times)
        
        # Compare to baseline
        if self._baseline_response_time:
            slowdown = avg_response / self._baseline_response_time
        else:
            slowdown = 1.0
            
        # Determine state
        if error_rate > 0.9:
            state = TargetState.DOWN
        elif error_rate > 0.5 or slowdown > 10:
            state = TargetState.FAILING
        elif error_rate > 0.2 or slowdown > 5:
            state = TargetState.DEGRADED
        elif error_rate > 0.05 or slowdown > 2:
            state = TargetState.STRESSED
        else:
            state = TargetState.HEALTHY
            
        # Check for recovery
        if len(self._state_history) > 5:
            prev_states = list(self._state_history)[-5:]
            if all(s in [TargetState.DOWN, TargetState.FAILING] for s in prev_states):
                if state in [TargetState.STRESSED, TargetState.HEALTHY]:
                    state = TargetState.RECOVERING
                    
        self._state_history.append(state)
        return state
        
    def get_impact_score(self) -> float:
        """Calculate impact score (0-1)"""
        state = self.get_state()
        
        scores = {
            TargetState.HEALTHY: 0.0,
            TargetState.STRESSED: 0.3,
            TargetState.DEGRADED: 0.6,
            TargetState.FAILING: 0.8,
            TargetState.DOWN: 1.0,
            TargetState.RECOVERING: 0.4,
        }
        
        return scores.get(state, 0.5)
        
    def get_detection_risk(self) -> float:
        """Estimate detection risk (0-1)"""
        if len(self._metrics) < 10:
            return 0.0
            
        recent = list(self._metrics)[-50:]
        
        # Factors that increase detection risk:
        # 1. High error rate (might trigger alerts)
        error_rate = sum(1 for m in recent if m.error) / len(recent)
        
        # 2. Consistent timing (bot-like behavior)
        if len(recent) > 10:
            intervals = [
                recent[i].timestamp - recent[i-1].timestamp
                for i in range(1, len(recent))
            ]
            if intervals:
                timing_variance = statistics.variance(intervals) if len(intervals) > 1 else 0
                timing_risk = max(0, 1 - timing_variance * 10)  # Low variance = high risk
            else:
                timing_risk = 0.5
        else:
            timing_risk = 0.5
            
        # 3. High request rate
        if len(recent) > 1:
            duration = recent[-1].timestamp - recent[0].timestamp
            rate = len(recent) / max(duration, 0.001)
            rate_risk = min(1, rate / 1000)  # >1000 rps is risky
        else:
            rate_risk = 0.0
            
        return (error_rate * 0.3 + timing_risk * 0.3 + rate_risk * 0.4)
        
    def recommend_rate_adjustment(self, current_rate: float, config: AdaptiveConfig) -> float:
        """Recommend rate adjustment"""
        state = self.get_state()
        impact = self.get_impact_score()
        detection_risk = self.get_detection_risk()
        
        if config.strategy == AdaptationStrategy.AGGRESSIVE:
            # Maximize impact, ignore detection
            if impact < config.target_impact:
                return min(current_rate * 1.5, config.max_rate)
            elif impact > config.target_impact + 0.2:
                return max(current_rate * 0.9, config.min_rate)
            return current_rate
            
        elif config.strategy == AdaptationStrategy.STEALTHY:
            # Minimize detection, accept lower impact
            if detection_risk > config.detection_threshold:
                return max(current_rate * 0.5, config.min_rate)
            elif detection_risk < config.detection_threshold * 0.5:
                return min(current_rate * 1.2, config.max_rate)
            return current_rate
            
        elif config.strategy == AdaptationStrategy.BALANCED:
            # Balance impact and detection
            if detection_risk > config.detection_threshold:
                return max(current_rate * 0.7, config.min_rate)
            elif impact < config.target_impact and detection_risk < config.detection_threshold * 0.7:
                return min(current_rate * 1.3, config.max_rate)
            elif impact > config.target_impact + 0.2:
                return max(current_rate * 0.85, config.min_rate)
            return current_rate
            
        elif config.strategy == AdaptationStrategy.RESOURCE_AWARE:
            # Optimize for efficiency
            if impact > 0.5 and current_rate > config.min_rate * 2:
                # Good impact, can reduce rate
                return max(current_rate * 0.8, config.min_rate)
            elif impact < 0.3:
                return min(current_rate * 1.2, config.max_rate)
            return current_rate
            
        return current_rate


class AdaptiveController:
    """
    Adaptive Attack Controller
    
    Dynamically adjusts attack parameters based on target response.
    """
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.analyzer = ResponseAnalyzer()
        self.current_rate = config.min_rate
        self._running = False
        self._adaptation_task: Optional[asyncio.Task] = None
        self._callbacks: List[Callable] = []
        
    def add_callback(self, callback: Callable[[float, TargetState], None]):
        """Add callback for rate changes"""
        self._callbacks.append(callback)
        
    async def start(self):
        """Start adaptive controller"""
        self._running = True
        self._adaptation_task = asyncio.create_task(self._adaptation_loop())
        
    async def stop(self):
        """Stop adaptive controller"""
        self._running = False
        if self._adaptation_task:
            self._adaptation_task.cancel()
            
    def record_response(self, response_time: float, status_code: int = 200,
                       error: bool = False, bytes_received: int = 0):
        """Record a response"""
        metrics = ResponseMetrics(
            response_time=response_time,
            status_code=status_code,
            error=error,
            bytes_received=bytes_received
        )
        self.analyzer.record(metrics)
        
    def get_current_rate(self) -> float:
        """Get current attack rate"""
        return self.current_rate
        
    def get_state(self) -> TargetState:
        """Get current target state"""
        return self.analyzer.get_state()
        
    async def _adaptation_loop(self):
        """Main adaptation loop"""
        while self._running:
            try:
                await asyncio.sleep(self.config.adaptation_interval)
                
                # Get recommendation
                new_rate = self.analyzer.recommend_rate_adjustment(
                    self.current_rate, self.config
                )
                
                # Apply learning rate for smooth transitions
                rate_change = new_rate - self.current_rate
                self.current_rate += rate_change * self.config.learning_rate
                
                # Clamp to bounds
                self.current_rate = max(self.config.min_rate,
                                       min(self.config.max_rate, self.current_rate))
                
                # Get state
                state = self.analyzer.get_state()
                
                # Notify callbacks
                for callback in self._callbacks:
                    try:
                        callback(self.current_rate, state)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")
                        
                logger.debug(f"Adapted rate to {self.current_rate:.0f}, state: {state.value}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Adaptation error: {e}")
                
    def get_stats(self) -> Dict[str, Any]:
        """Get adaptation statistics"""
        return {
            'current_rate': self.current_rate,
            'target_state': self.analyzer.get_state().value,
            'impact_score': self.analyzer.get_impact_score(),
            'detection_risk': self.analyzer.get_detection_risk(),
            'strategy': self.config.strategy.value,
        }


class PatternLearner:
    """
    Learns target response patterns for better adaptation.
    
    Uses simple statistical learning to identify:
    - Optimal attack rates
    - Effective attack vectors
    - Detection thresholds
    """
    
    def __init__(self):
        self._rate_impact: Dict[int, List[float]] = {}  # rate -> [impact scores]
        self._vector_effectiveness: Dict[str, List[float]] = {}
        self._detection_events: List[Tuple[float, float]] = []  # (rate, detection_score)
        
    def record_rate_impact(self, rate: int, impact: float):
        """Record impact at a given rate"""
        bucket = (rate // 1000) * 1000  # Bucket by 1000s
        if bucket not in self._rate_impact:
            self._rate_impact[bucket] = []
        self._rate_impact[bucket].append(impact)
        
    def record_vector_effectiveness(self, vector: str, effectiveness: float):
        """Record vector effectiveness"""
        if vector not in self._vector_effectiveness:
            self._vector_effectiveness[vector] = []
        self._vector_effectiveness[vector].append(effectiveness)
        
    def record_detection(self, rate: float, detection_score: float):
        """Record potential detection event"""
        self._detection_events.append((rate, detection_score))
        
    def get_optimal_rate(self) -> Optional[int]:
        """Get optimal rate based on learned data"""
        if not self._rate_impact:
            return None
            
        # Find rate with best impact
        best_rate = None
        best_impact = 0
        
        for rate, impacts in self._rate_impact.items():
            if len(impacts) >= 3:  # Need enough samples
                avg_impact = statistics.mean(impacts)
                if avg_impact > best_impact:
                    best_impact = avg_impact
                    best_rate = rate
                    
        return best_rate
        
    def get_best_vector(self) -> Optional[str]:
        """Get most effective vector"""
        if not self._vector_effectiveness:
            return None
            
        best_vector = None
        best_effectiveness = 0
        
        for vector, scores in self._vector_effectiveness.items():
            if len(scores) >= 3:
                avg = statistics.mean(scores)
                if avg > best_effectiveness:
                    best_effectiveness = avg
                    best_vector = vector
                    
        return best_vector
        
    def get_safe_rate_limit(self) -> Optional[float]:
        """Get rate limit that avoids detection"""
        if len(self._detection_events) < 5:
            return None
            
        # Find rate where detection starts
        sorted_events = sorted(self._detection_events, key=lambda x: x[0])
        
        for rate, score in sorted_events:
            if score > 0.7:  # Detection threshold
                return rate * 0.8  # 20% safety margin
                
        return None


class MultiStrategyAdapter:
    """
    Adapts between multiple strategies based on conditions.
    """
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.analyzer = ResponseAnalyzer()
        self.learner = PatternLearner()
        self._current_strategy = config.strategy
        self._strategy_scores: Dict[AdaptationStrategy, float] = {
            s: 0.5 for s in AdaptationStrategy
        }
        
    def select_strategy(self) -> AdaptationStrategy:
        """Select best strategy for current conditions"""
        state = self.analyzer.get_state()
        detection_risk = self.analyzer.get_detection_risk()
        impact = self.analyzer.get_impact_score()
        
        # Score each strategy
        scores = {}
        
        for strategy in AdaptationStrategy:
            base_score = self._strategy_scores[strategy]
            
            if strategy == AdaptationStrategy.AGGRESSIVE:
                # Good when target is healthy and detection risk is low
                if state == TargetState.HEALTHY and detection_risk < 0.3:
                    scores[strategy] = base_score + 0.3
                elif detection_risk > 0.7:
                    scores[strategy] = base_score - 0.3
                else:
                    scores[strategy] = base_score
                    
            elif strategy == AdaptationStrategy.STEALTHY:
                # Good when detection risk is high
                if detection_risk > 0.5:
                    scores[strategy] = base_score + 0.3
                elif detection_risk < 0.2:
                    scores[strategy] = base_score - 0.2
                else:
                    scores[strategy] = base_score
                    
            elif strategy == AdaptationStrategy.BALANCED:
                # Good general-purpose strategy
                scores[strategy] = base_score + 0.1
                
            elif strategy == AdaptationStrategy.RESOURCE_AWARE:
                # Good when impact is already high
                if impact > 0.6:
                    scores[strategy] = base_score + 0.2
                else:
                    scores[strategy] = base_score
                    
            elif strategy == AdaptationStrategy.LEARNING:
                # Good when we have enough data
                if self.learner.get_optimal_rate() is not None:
                    scores[strategy] = base_score + 0.2
                else:
                    scores[strategy] = base_score - 0.2
                    
        # Select best strategy
        best_strategy = max(scores, key=scores.get)
        
        # Update scores based on outcome
        if best_strategy != self._current_strategy:
            logger.info(f"Switching strategy: {self._current_strategy.value} -> {best_strategy.value}")
            self._current_strategy = best_strategy
            
        return best_strategy
        
    def update_strategy_score(self, strategy: AdaptationStrategy, success: bool):
        """Update strategy score based on outcome"""
        current = self._strategy_scores[strategy]
        if success:
            self._strategy_scores[strategy] = min(1.0, current + 0.05)
        else:
            self._strategy_scores[strategy] = max(0.0, current - 0.05)


class AdaptiveAttackEngine:
    """
    Complete adaptive attack engine combining all components.
    """
    
    def __init__(self, config: AdaptiveConfig):
        self.config = config
        self.controller = AdaptiveController(config)
        self.multi_strategy = MultiStrategyAdapter(config)
        self._running = False
        
    async def start(self):
        """Start adaptive attack engine"""
        self._running = True
        await self.controller.start()
        
        # Start strategy adaptation loop
        asyncio.create_task(self._strategy_loop())
        
    async def stop(self):
        """Stop adaptive attack engine"""
        self._running = False
        await self.controller.stop()
        
    def record_response(self, response_time: float, status_code: int = 200,
                       error: bool = False):
        """Record response for adaptation"""
        self.controller.record_response(response_time, status_code, error)
        self.multi_strategy.analyzer.record(ResponseMetrics(
            response_time=response_time,
            status_code=status_code,
            error=error
        ))
        
        # Record for learning
        rate = self.controller.get_current_rate()
        impact = self.multi_strategy.analyzer.get_impact_score()
        self.multi_strategy.learner.record_rate_impact(int(rate), impact)
        
    def get_rate(self) -> float:
        """Get current attack rate"""
        return self.controller.get_current_rate()
        
    def get_strategy(self) -> AdaptationStrategy:
        """Get current strategy"""
        return self.multi_strategy._current_strategy
        
    async def _strategy_loop(self):
        """Strategy adaptation loop"""
        while self._running:
            await asyncio.sleep(30)  # Check strategy every 30s
            
            # Select best strategy
            new_strategy = self.multi_strategy.select_strategy()
            
            # Update controller config
            self.controller.config.strategy = new_strategy
            
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive stats"""
        return {
            **self.controller.get_stats(),
            'strategy_scores': {
                s.value: score
                for s, score in self.multi_strategy._strategy_scores.items()
            },
            'optimal_rate': self.multi_strategy.learner.get_optimal_rate(),
            'safe_rate_limit': self.multi_strategy.learner.get_safe_rate_limit(),
        }
