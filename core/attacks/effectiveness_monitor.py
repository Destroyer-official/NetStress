"""
Attack Effectiveness Monitoring Module

Tracks attack effectiveness in real-time by monitoring:
- Response times
- Defense activation detection
- Attack success rate

Requirements:
- 21.3: Track response times, detect defense activation, measure attack success rate
"""

import time
import asyncio
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Deque
from collections import deque
from enum import Enum
import statistics

logger = logging.getLogger(__name__)


class DefenseState(Enum):
    """Defense system state"""
    NONE = "none"  # No defense detected
    RATE_LIMITING = "rate_limiting"  # Rate limiting active
    CAPTCHA = "captcha"  # CAPTCHA challenge
    BLOCKING = "blocking"  # IP blocking
    WAF = "waf"  # WAF active
    CLOUDFLARE = "cloudflare"  # Cloudflare protection
    UNKNOWN = "unknown"  # Unknown defense


@dataclass
class ResponseMetrics:
    """Metrics for a single response"""
    timestamp: float
    response_time: float  # seconds
    status_code: int
    error: bool
    bytes_received: int = 0
    defense_detected: Optional[DefenseState] = None


@dataclass
class EffectivenessStats:
    """
    Attack effectiveness statistics.
    
    Requirements: 21.3 - Track response times, detect defense activation, measure success rate
    """
    # Response time metrics
    avg_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    median_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    
    # Success metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    success_rate: float = 0.0
    
    # Status code distribution
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    status_timeout: int = 0
    
    # Defense detection
    defense_state: DefenseState = DefenseState.NONE
    defense_confidence: float = 0.0
    defense_detected_at: Optional[float] = None
    
    # Effectiveness score (0-1)
    effectiveness_score: float = 0.0
    
    # Trend indicators
    response_time_trend: str = "stable"  # improving, stable, degrading
    success_rate_trend: str = "stable"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'response_time': {
                'avg': self.avg_response_time,
                'min': self.min_response_time,
                'max': self.max_response_time,
                'median': self.median_response_time,
                'p95': self.p95_response_time,
                'p99': self.p99_response_time,
                'trend': self.response_time_trend,
            },
            'success': {
                'total': self.total_requests,
                'successful': self.successful_requests,
                'failed': self.failed_requests,
                'rate': self.success_rate,
                'trend': self.success_rate_trend,
            },
            'status_codes': {
                '2xx': self.status_2xx,
                '3xx': self.status_3xx,
                '4xx': self.status_4xx,
                '5xx': self.status_5xx,
                'timeout': self.status_timeout,
            },
            'defense': {
                'state': self.defense_state.value,
                'confidence': self.defense_confidence,
                'detected_at': self.defense_detected_at,
            },
            'effectiveness_score': self.effectiveness_score,
        }


class EffectivenessMonitor:
    """
    Monitors attack effectiveness in real-time.
    
    Requirements:
    - 21.3: Track response times, detect defense activation, measure attack success rate
    """
    
    def __init__(self, window_size: int = 1000, baseline_duration: float = 10.0):
        """
        Initialize effectiveness monitor.
        
        Args:
            window_size: Number of recent responses to track
            baseline_duration: Duration (seconds) to establish baseline metrics
        """
        self.window_size = window_size
        self.baseline_duration = baseline_duration
        
        # Response tracking
        self._responses: Deque[ResponseMetrics] = deque(maxlen=window_size)
        self._baseline_response_time: Optional[float] = None
        self._baseline_success_rate: Optional[float] = None
        self._baseline_established = False
        self._baseline_start: Optional[float] = None
        
        # Current stats
        self.stats = EffectivenessStats()
        
        # Defense detection patterns
        self._defense_patterns = {
            DefenseState.RATE_LIMITING: {
                'status_codes': [429, 503],
                'response_time_increase': 0.5,  # 50% increase
            },
            DefenseState.CAPTCHA: {
                'status_codes': [403],
                'keywords': ['captcha', 'challenge', 'verify'],
            },
            DefenseState.BLOCKING: {
                'status_codes': [403, 401],
                'consecutive_failures': 10,
            },
            DefenseState.WAF: {
                'status_codes': [403, 406],
                'keywords': ['waf', 'firewall', 'blocked'],
            },
            DefenseState.CLOUDFLARE: {
                'status_codes': [403, 503, 520, 521, 522, 523, 524],
                'keywords': ['cloudflare', 'cf-ray'],
            },
        }
        
    def record_response(self, response_time: float, status_code: int, 
                       error: bool = False, bytes_received: int = 0,
                       response_body: Optional[str] = None):
        """
        Record a response for effectiveness tracking.
        
        Requirements: 21.3 - Track response times, measure attack success rate
        
        Args:
            response_time: Response time in seconds
            status_code: HTTP status code (or 0 for network errors)
            error: Whether this was an error
            bytes_received: Number of bytes received
            response_body: Optional response body for defense detection
        """
        # Detect defense
        defense = self._detect_defense(status_code, response_body)
        
        # Create metrics
        metrics = ResponseMetrics(
            timestamp=time.time(),
            response_time=response_time,
            status_code=status_code,
            error=error,
            bytes_received=bytes_received,
            defense_detected=defense
        )
        
        self._responses.append(metrics)
        
        # Establish baseline if needed
        if not self._baseline_established:
            if self._baseline_start is None:
                self._baseline_start = time.time()
            elif time.time() - self._baseline_start >= self.baseline_duration:
                self._establish_baseline()
        
        # Update stats
        self._update_stats()
        
    def _detect_defense(self, status_code: int, 
                       response_body: Optional[str] = None) -> Optional[DefenseState]:
        """
        Detect if defense system is active.
        
        Requirements: 21.3 - Detect defense activation
        
        Args:
            status_code: HTTP status code
            response_body: Optional response body
            
        Returns:
            Detected defense state or None
        """
        # Check each defense pattern
        for defense_state, pattern in self._defense_patterns.items():
            # Check status code
            if status_code in pattern.get('status_codes', []):
                # Check keywords if response body provided
                if response_body and 'keywords' in pattern:
                    body_lower = response_body.lower()
                    if any(keyword in body_lower for keyword in pattern['keywords']):
                        return defense_state
                else:
                    # Status code match is enough
                    return defense_state
        
        # Check for consecutive failures (blocking)
        if len(self._responses) >= 10:
            recent = list(self._responses)[-10:]
            if all(r.error or r.status_code >= 400 for r in recent):
                return DefenseState.BLOCKING
        
        return None
    
    def _establish_baseline(self):
        """Establish baseline metrics from initial responses"""
        if not self._responses:
            return
        
        response_times = [r.response_time for r in self._responses if not r.error]
        if response_times:
            self._baseline_response_time = statistics.mean(response_times)
        
        total = len(self._responses)
        successful = sum(1 for r in self._responses if not r.error and 200 <= r.status_code < 400)
        self._baseline_success_rate = successful / total if total > 0 else 0.0
        
        self._baseline_established = True
        logger.info(f"Baseline established: RT={self._baseline_response_time:.3f}s, "
                   f"Success={self._baseline_success_rate:.2%}")
    
    def _update_stats(self):
        """
        Update effectiveness statistics.
        
        Requirements: 21.3 - Track response times, measure attack success rate
        """
        if not self._responses:
            return
        
        # Response time metrics
        response_times = [r.response_time for r in self._responses if not r.error]
        if response_times:
            self.stats.avg_response_time = statistics.mean(response_times)
            self.stats.min_response_time = min(response_times)
            self.stats.max_response_time = max(response_times)
            self.stats.median_response_time = statistics.median(response_times)
            
            # Percentiles
            sorted_times = sorted(response_times)
            p95_idx = int(len(sorted_times) * 0.95)
            p99_idx = int(len(sorted_times) * 0.99)
            self.stats.p95_response_time = sorted_times[p95_idx] if p95_idx < len(sorted_times) else sorted_times[-1]
            self.stats.p99_response_time = sorted_times[p99_idx] if p99_idx < len(sorted_times) else sorted_times[-1]
        
        # Success metrics
        self.stats.total_requests = len(self._responses)
        self.stats.successful_requests = sum(1 for r in self._responses 
                                            if not r.error and 200 <= r.status_code < 400)
        self.stats.failed_requests = self.stats.total_requests - self.stats.successful_requests
        self.stats.success_rate = (self.stats.successful_requests / self.stats.total_requests 
                                  if self.stats.total_requests > 0 else 0.0)
        
        # Status code distribution
        self.stats.status_2xx = sum(1 for r in self._responses if 200 <= r.status_code < 300)
        self.stats.status_3xx = sum(1 for r in self._responses if 300 <= r.status_code < 400)
        self.stats.status_4xx = sum(1 for r in self._responses if 400 <= r.status_code < 500)
        self.stats.status_5xx = sum(1 for r in self._responses if 500 <= r.status_code < 600)
        self.stats.status_timeout = sum(1 for r in self._responses if r.status_code == 0)
        
        # Defense detection
        recent_defenses = [r.defense_detected for r in list(self._responses)[-100:] 
                          if r.defense_detected is not None]
        if recent_defenses:
            # Most common defense in recent responses
            from collections import Counter
            defense_counts = Counter(recent_defenses)
            most_common_defense, count = defense_counts.most_common(1)[0]
            
            self.stats.defense_state = most_common_defense
            self.stats.defense_confidence = count / min(100, len(self._responses))
            
            if self.stats.defense_detected_at is None:
                self.stats.defense_detected_at = time.time()
        else:
            self.stats.defense_state = DefenseState.NONE
            self.stats.defense_confidence = 0.0
        
        # Calculate effectiveness score
        self._calculate_effectiveness_score()
        
        # Calculate trends
        self._calculate_trends()
    
    def _calculate_effectiveness_score(self):
        """
        Calculate overall effectiveness score (0-1).
        
        Higher score = more effective attack
        """
        score = 0.0
        
        # Success rate component (40%)
        score += self.stats.success_rate * 0.4
        
        # Response time degradation component (30%)
        if self._baseline_response_time and self.stats.avg_response_time > 0:
            # Higher response time = more effective
            rt_ratio = self.stats.avg_response_time / self._baseline_response_time
            rt_score = min(rt_ratio / 5.0, 1.0)  # Cap at 5x baseline
            score += rt_score * 0.3
        else:
            score += 0.15  # Neutral if no baseline
        
        # Server error rate component (20%)
        if self.stats.total_requests > 0:
            error_rate = self.stats.status_5xx / self.stats.total_requests
            score += error_rate * 0.2
        
        # Defense detection penalty (10%)
        if self.stats.defense_state != DefenseState.NONE:
            # Defense detected = less effective
            defense_penalty = self.stats.defense_confidence * 0.1
            score -= defense_penalty
        else:
            score += 0.1
        
        self.stats.effectiveness_score = max(0.0, min(1.0, score))
    
    def _calculate_trends(self):
        """Calculate trend indicators"""
        if len(self._responses) < 100:
            return
        
        # Split into two halves
        mid = len(self._responses) // 2
        first_half = list(self._responses)[:mid]
        second_half = list(self._responses)[mid:]
        
        # Response time trend
        first_rt = statistics.mean([r.response_time for r in first_half if not r.error] or [0])
        second_rt = statistics.mean([r.response_time for r in second_half if not r.error] or [0])
        
        if second_rt > first_rt * 1.2:
            self.stats.response_time_trend = "degrading"
        elif second_rt < first_rt * 0.8:
            self.stats.response_time_trend = "improving"
        else:
            self.stats.response_time_trend = "stable"
        
        # Success rate trend
        first_success = sum(1 for r in first_half if not r.error and 200 <= r.status_code < 400) / len(first_half)
        second_success = sum(1 for r in second_half if not r.error and 200 <= r.status_code < 400) / len(second_half)
        
        if second_success > first_success * 1.1:
            self.stats.success_rate_trend = "improving"
        elif second_success < first_success * 0.9:
            self.stats.success_rate_trend = "degrading"
        else:
            self.stats.success_rate_trend = "stable"
    
    def get_stats(self) -> EffectivenessStats:
        """Get current effectiveness statistics"""
        return self.stats
    
    def is_defense_active(self) -> bool:
        """
        Check if defense system is active.
        
        Requirements: 21.3 - Detect defense activation
        """
        return (self.stats.defense_state != DefenseState.NONE and 
                self.stats.defense_confidence > 0.5)
    
    def get_defense_state(self) -> DefenseState:
        """Get current defense state"""
        return self.stats.defense_state
    
    def is_effective(self, threshold: float = 0.5) -> bool:
        """
        Check if attack is effective.
        
        Args:
            threshold: Effectiveness threshold (0-1)
            
        Returns:
            True if effectiveness score >= threshold
        """
        return self.stats.effectiveness_score >= threshold
    
    def should_adapt(self) -> bool:
        """
        Determine if attack should adapt strategy.
        
        Returns:
            True if adaptation is recommended
        """
        # Adapt if defense detected
        if self.is_defense_active():
            return True
        
        # Adapt if effectiveness is low
        if self.stats.effectiveness_score < 0.3:
            return True
        
        # Adapt if success rate is degrading
        if self.stats.success_rate_trend == "degrading":
            return True
        
        # Adapt if too many 4xx/5xx errors
        if self.stats.total_requests > 100:
            error_rate = (self.stats.status_4xx + self.stats.status_5xx) / self.stats.total_requests
            if error_rate > 0.5:
                return True
        
        return False
    
    def get_adaptation_reason(self) -> str:
        """Get reason why adaptation is recommended"""
        if self.is_defense_active():
            return f"Defense detected: {self.stats.defense_state.value}"
        
        if self.stats.effectiveness_score < 0.3:
            return f"Low effectiveness: {self.stats.effectiveness_score:.2f}"
        
        if self.stats.success_rate_trend == "degrading":
            return f"Success rate degrading: {self.stats.success_rate:.2%}"
        
        if self.stats.total_requests > 100:
            error_rate = (self.stats.status_4xx + self.stats.status_5xx) / self.stats.total_requests
            if error_rate > 0.5:
                return f"High error rate: {error_rate:.2%}"
        
        return "Unknown"
    
    def reset(self):
        """Reset all metrics"""
        self._responses.clear()
        self._baseline_response_time = None
        self._baseline_success_rate = None
        self._baseline_established = False
        self._baseline_start = None
        self.stats = EffectivenessStats()
