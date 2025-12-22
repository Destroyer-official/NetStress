#!/usr/bin/env python3
"""
Advanced Defense Detection System

Enhanced defense detection capabilities including:
- Rate limiting pattern analysis
- WAF signature detection
- Behavioral analysis defense identification
- Real-time defense adaptation monitoring
- Machine learning-based defense classification
"""

import numpy as np
import logging
import time
import threading
import json
import re
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict, Counter
from enum import Enum, auto
import statistics
import hashlib

from .defense_evasion import DefenseType, DefenseSignature, EvasionTechnique

logger = logging.getLogger(__name__)


class DefensePattern(Enum):
    """Specific defense patterns that can be detected"""
    RATE_LIMIT_SLIDING_WINDOW = auto()
    RATE_LIMIT_TOKEN_BUCKET = auto()
    RATE_LIMIT_FIXED_WINDOW = auto()
    IP_BLACKLIST_IMMEDIATE = auto()
    IP_BLACKLIST_PROGRESSIVE = auto()
    WAF_SIGNATURE_BASED = auto()
    WAF_ANOMALY_BASED = auto()
    BEHAVIORAL_THRESHOLD = auto()
    BEHAVIORAL_ML_BASED = auto()
    CAPTCHA_CHALLENGE = auto()
    GEOBLOCKING = auto()
    DPI_CONTENT_FILTERING = auto()
    LOAD_BALANCER_FAILOVER = auto()


@dataclass
class DefenseMetrics:
    """Metrics for analyzing defense behavior"""
    response_times: List[float] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)
    error_rates: List[float] = field(default_factory=list)
    connection_success_rates: List[float] = field(default_factory=list)
    throughput_measurements: List[float] = field(default_factory=list)
    timestamps: List[datetime] = field(default_factory=list)
    
    def add_measurement(self, response_time: float, status_code: int, 
                       error_rate: float, connection_success: float, 
                       throughput: float):
        """Add a new measurement"""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        self.error_rates.append(error_rate)
        self.connection_success_rates.append(connection_success)
        self.throughput_measurements.append(throughput)
        self.timestamps.append(datetime.now())
        
        # Keep only recent measurements (last 1000)
        max_size = 1000
        if len(self.timestamps) > max_size:
            self.response_times = self.response_times[-max_size:]
            self.status_codes = self.status_codes[-max_size:]
            self.error_rates = self.error_rates[-max_size:]
            self.connection_success_rates = self.connection_success_rates[-max_size:]
            self.throughput_measurements = self.throughput_measurements[-max_size:]
            self.timestamps = self.timestamps[-max_size:]


@dataclass
class RateLimitAnalysis:
    """Analysis results for rate limiting detection"""
    limit_type: DefensePattern
    estimated_limit: float
    window_size: float
    confidence: float
    evidence: List[str]
    detection_time: datetime = field(default_factory=datetime.now)


@dataclass
class WAFSignature:
    """WAF signature detection result"""
    waf_type: str
    signature_patterns: List[str]
    blocked_payloads: List[str]
    confidence: float
    bypass_suggestions: List[str]
    detection_time: datetime = field(default_factory=datetime.now)


class RateLimitDetector:
    """Specialized detector for rate limiting mechanisms"""
    
    def __init__(self):
        self.request_history = deque(maxlen=10000)
        self.rate_limit_patterns = {}
        self.analysis_cache = {}
        
    def analyze_rate_limiting(self, metrics: DefenseMetrics) -> Optional[RateLimitAnalysis]:
        """Analyze metrics to detect rate limiting patterns"""
        if len(metrics.timestamps) < 10:
            return None
        
        # Analyze different rate limiting patterns
        analyses = []
        
        # Check for sliding window rate limiting
        sliding_analysis = self._analyze_sliding_window(metrics)
        if sliding_analysis:
            analyses.append(sliding_analysis)
        
        # Check for token bucket rate limiting
        token_analysis = self._analyze_token_bucket(metrics)
        if token_analysis:
            analyses.append(token_analysis)
        
        # Check for fixed window rate limiting
        fixed_analysis = self._analyze_fixed_window(metrics)
        if fixed_analysis:
            analyses.append(fixed_analysis)
        
        # Return the analysis with highest confidence
        if analyses:
            return max(analyses, key=lambda x: x.confidence)
        
        return None
    
    def _analyze_sliding_window(self, metrics: DefenseMetrics) -> Optional[RateLimitAnalysis]:
        """Analyze for sliding window rate limiting with enhanced detection"""
        evidence = []
        
        # Look for rate limiting responses with expanded status codes
        rate_limited_responses = [
            i for i, code in enumerate(metrics.status_codes) 
            if code in [429, 503, 502, 504, 509]  # Added more rate limit indicators
        ]
        
        if len(rate_limited_responses) < 3:
            return None
        
        # Analyze timing patterns
        rate_limit_times = [metrics.timestamps[i] for i in rate_limited_responses]
        
        # Check for consistent intervals
        intervals = []
        for i in range(1, len(rate_limit_times)):
            interval = (rate_limit_times[i] - rate_limit_times[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return None
        
        # Enhanced sliding window detection
        avg_interval = statistics.mean(intervals)
        interval_variance = statistics.variance(intervals) if len(intervals) > 1 else 0
        
        # Analyze response time correlation with rate limiting
        rate_limit_response_times = [metrics.response_times[i] for i in rate_limited_responses]
        avg_rate_limit_rt = statistics.mean(rate_limit_response_times) if rate_limit_response_times else 0
        
        # Check for gradual recovery pattern (sliding window characteristic)
        recovery_pattern = self._analyze_recovery_pattern(metrics, rate_limited_responses)
        
        # Enhanced confidence calculation
        confidence = 0.5  # Base confidence
        
        # Low variance suggests sliding window
        if interval_variance < avg_interval * 0.3:
            confidence += 0.2
            evidence.append(f"Consistent rate limit intervals: {avg_interval:.2f}s avg, variance: {interval_variance:.2f}")
        
        # Gradual recovery suggests sliding window
        if recovery_pattern['gradual_recovery']:
            confidence += 0.2
            evidence.append(f"Gradual recovery pattern detected: {recovery_pattern['recovery_time']:.2f}s avg")
        
        # Response time correlation
        if avg_rate_limit_rt > 0:
            normal_rt = statistics.mean([rt for i, rt in enumerate(metrics.response_times) 
                                       if metrics.status_codes[i] == 200])
            if normal_rt > 0 and avg_rate_limit_rt > normal_rt * 1.5:
                confidence += 0.1
                evidence.append(f"Rate limit responses slower: {avg_rate_limit_rt:.0f}ms vs {normal_rt:.0f}ms")
        
        if confidence >= 0.7:  # Minimum confidence threshold
            # Estimate rate limit with improved accuracy
            successful_requests = len([c for c in metrics.status_codes if c == 200])
            total_time = (metrics.timestamps[-1] - metrics.timestamps[0]).total_seconds()
            estimated_rate = successful_requests / total_time if total_time > 0 else 0
            
            # Adjust estimate based on rate limit frequency
            rate_limit_frequency = len(rate_limited_responses) / len(metrics.status_codes)
            if rate_limit_frequency > 0.3:  # High rate limit frequency
                estimated_rate *= 0.7  # Reduce estimate
                evidence.append(f"High rate limit frequency ({rate_limit_frequency:.2f}) - adjusted estimate")
            
            evidence.append(f"Estimated rate limit: {estimated_rate:.2f} req/s")
            
            return RateLimitAnalysis(
                limit_type=DefensePattern.RATE_LIMIT_SLIDING_WINDOW,
                estimated_limit=estimated_rate,
                window_size=avg_interval,
                confidence=confidence,
                evidence=evidence
            )
        
        return None
    
    def _analyze_recovery_pattern(self, metrics: DefenseMetrics, rate_limited_indices: List[int]) -> Dict[str, Any]:
        """Analyze recovery patterns after rate limiting"""
        recovery_times = []
        gradual_recovery = False
        
        for idx in rate_limited_indices:
            # Look for recovery after this rate limit
            recovery_start = idx + 1
            recovery_found = False
            
            for i in range(recovery_start, min(recovery_start + 10, len(metrics.status_codes))):
                if metrics.status_codes[i] == 200:  # Successful response
                    recovery_time = (metrics.timestamps[i] - metrics.timestamps[idx]).total_seconds()
                    recovery_times.append(recovery_time)
                    recovery_found = True
                    break
            
            # Check for gradual recovery (multiple successful responses)
            if recovery_found and recovery_start + 3 < len(metrics.status_codes):
                subsequent_successes = sum(1 for i in range(recovery_start, recovery_start + 3)
                                         if i < len(metrics.status_codes) and metrics.status_codes[i] == 200)
                if subsequent_successes >= 2:
                    gradual_recovery = True
        
        return {
            'gradual_recovery': gradual_recovery,
            'recovery_time': statistics.mean(recovery_times) if recovery_times else 0,
            'recovery_count': len(recovery_times)
        }
    
    def _analyze_token_bucket(self, metrics: DefenseMetrics) -> Optional[RateLimitAnalysis]:
        """Analyze for token bucket rate limiting"""
        evidence = []
        
        # Token bucket allows bursts followed by steady rate
        # Look for burst patterns followed by rate limiting
        
        # Analyze throughput patterns
        if len(metrics.throughput_measurements) < 10:
            return None
        
        # Find burst periods (high throughput followed by drops)
        burst_periods = []
        for i in range(1, len(metrics.throughput_measurements)):
            current = metrics.throughput_measurements[i]
            previous = metrics.throughput_measurements[i-1]
            
            # Significant drop indicates bucket depletion
            if previous > 0 and current / previous < 0.5:
                burst_periods.append(i)
        
        if len(burst_periods) >= 2:
            evidence.append(f"Detected {len(burst_periods)} burst-to-limit transitions")
            
            # Analyze recovery patterns
            recovery_times = []
            for burst_idx in burst_periods:
                # Look for recovery after burst
                for j in range(burst_idx, min(burst_idx + 20, len(metrics.throughput_measurements))):
                    if metrics.throughput_measurements[j] > metrics.throughput_measurements[burst_idx] * 1.5:
                        recovery_time = (metrics.timestamps[j] - metrics.timestamps[burst_idx]).total_seconds()
                        recovery_times.append(recovery_time)
                        break
            
            if recovery_times:
                avg_recovery = statistics.mean(recovery_times)
                evidence.append(f"Average recovery time: {avg_recovery:.2f}s")
                
                # Estimate bucket parameters
                max_throughput = max(metrics.throughput_measurements)
                sustained_throughput = statistics.median(metrics.throughput_measurements)
                
                return RateLimitAnalysis(
                    limit_type=DefensePattern.RATE_LIMIT_TOKEN_BUCKET,
                    estimated_limit=sustained_throughput,
                    window_size=avg_recovery,
                    confidence=0.75,
                    evidence=evidence
                )
        
        return None
    
    def _analyze_fixed_window(self, metrics: DefenseMetrics) -> Optional[RateLimitAnalysis]:
        """Analyze for fixed window rate limiting"""
        evidence = []
        
        # Fixed window shows periodic resets
        rate_limited_times = [
            metrics.timestamps[i] for i, code in enumerate(metrics.status_codes)
            if code in [429, 503]
        ]
        
        if len(rate_limited_times) < 5:
            return None
        
        # Look for periodic patterns
        # Group rate limits by time windows
        window_sizes = [60, 300, 600, 3600]  # 1min, 5min, 10min, 1hour
        
        for window_size in window_sizes:
            windows = defaultdict(int)
            
            for timestamp in rate_limited_times:
                window_start = timestamp.replace(second=0, microsecond=0)
                window_key = int(window_start.timestamp() // window_size)
                windows[window_key] += 1
            
            # Check for consistent window behavior
            window_counts = list(windows.values())
            if len(window_counts) >= 3:
                avg_count = statistics.mean(window_counts)
                variance = statistics.variance(window_counts) if len(window_counts) > 1 else 0
                
                # Low variance suggests fixed windows
                if variance < avg_count * 0.4:
                    evidence.append(f"Consistent rate limits per {window_size}s window")
                    evidence.append(f"Average rate limits per window: {avg_count:.1f}")
                    
                    return RateLimitAnalysis(
                        limit_type=DefensePattern.RATE_LIMIT_FIXED_WINDOW,
                        estimated_limit=avg_count,
                        window_size=window_size,
                        confidence=0.7,
                        evidence=evidence
                    )
        
        return None


class WAFDetector:
    """Specialized detector for Web Application Firewall signatures"""
    
    def __init__(self):
        self.waf_signatures = self._load_waf_signatures()
        self.blocked_payloads = deque(maxlen=1000)
        self.detection_cache = {}
        
    def _load_waf_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load known WAF signatures and patterns"""
        return {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'server: cloudflare', 'cf-request-id', 'cf-visitor'],
                'error_pages': ['cloudflare', 'ray id', 'checking your browser', 'ddos protection'],
                'status_codes': [403, 429, 503, 520, 521, 522, 523, 524],
                'response_patterns': ['attention required', 'security check', 'browser check', 'challenge page'],
                'timing_patterns': {'consistent_delays': True, 'challenge_timeout': 5000}
            },
            'aws_waf': {
                'headers': ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amzn-errortype', 'x-amz-apigw-id'],
                'error_pages': ['aws', 'forbidden', 'access denied', 'api gateway'],
                'status_codes': [403, 429, 502, 503],
                'response_patterns': ['access denied', 'request blocked', 'throttling exception', 'rate exceeded'],
                'timing_patterns': {'burst_detection': True, 'sliding_window': True}
            },
            'akamai': {
                'headers': ['akamai-ghost-ip', 'x-akamai-edgescape', 'akamai-origin-hop', 'x-akamai-request-id'],
                'error_pages': ['akamai', 'reference #', 'edge server', 'kona security'],
                'status_codes': [403, 406, 429, 503],
                'response_patterns': ['access denied', 'policy violation', 'kona site defender', 'bot detection'],
                'timing_patterns': {'edge_caching': True, 'geo_blocking': True}
            },
            'incapsula': {
                'headers': ['x-iinfo', 'x-cdn', 'incap-ses', 'x-cdn-forward'],
                'error_pages': ['incapsula', 'incident id', 'imperva', 'security incident'],
                'status_codes': [403, 406, 429, 503],
                'response_patterns': ['request unsuccessful', 'incident id', 'imperva incapsula', 'security violation'],
                'timing_patterns': {'behavioral_analysis': True, 'progressive_delays': True}
            },
            'sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block', 'server: sucuri'],
                'error_pages': ['sucuri', 'access denied', 'website firewall', 'security block'],
                'status_codes': [403, 406, 429, 503],
                'response_patterns': ['access denied', 'sucuri website firewall', 'security block', 'malicious request'],
                'timing_patterns': {'signature_matching': True, 'ip_reputation': True}
            },
            'mod_security': {
                'headers': ['server: apache', 'server: nginx', 'x-mod-security'],
                'error_pages': ['mod_security', 'not acceptable', 'security filter', 'owasp'],
                'status_codes': [403, 406, 501, 500],
                'response_patterns': ['not acceptable', 'mod_security', 'security filter triggered', 'owasp rule'],
                'timing_patterns': {'rule_processing': True, 'pattern_matching': True}
            },
            'f5_asm': {
                'headers': ['server: bigip', 'x-waf-event-info', 'f5-ltm-pool'],
                'error_pages': ['f5', 'bigip', 'application security', 'asm policy'],
                'status_codes': [403, 406, 429, 503],
                'response_patterns': ['request rejected', 'asm policy violation', 'f5 application security'],
                'timing_patterns': {'load_balancer': True, 'policy_enforcement': True}
            },
            'barracuda': {
                'headers': ['server: barracuda', 'x-barracuda-connect-time'],
                'error_pages': ['barracuda', 'web application firewall', 'security policy'],
                'status_codes': [403, 406, 429],
                'response_patterns': ['barracuda waf', 'security policy violation', 'request blocked'],
                'timing_patterns': {'content_filtering': True, 'reputation_check': True}
            },
            'fortinet': {
                'headers': ['server: fortinet', 'x-fortinet-waf'],
                'error_pages': ['fortinet', 'fortigate', 'web filter'],
                'status_codes': [403, 406, 429],
                'response_patterns': ['fortinet', 'fortigate waf', 'web filtering'],
                'timing_patterns': {'utm_filtering': True, 'threat_detection': True}
            },
            'palo_alto': {
                'headers': ['server: pan-os', 'x-pan-globalprotect'],
                'error_pages': ['palo alto', 'pan-os', 'threat prevention'],
                'status_codes': [403, 406, 429],
                'response_patterns': ['palo alto', 'threat prevention', 'security policy'],
                'timing_patterns': {'threat_analysis': True, 'sandbox_check': True}
            }
        }
    
    def detect_waf(self, response_data: List[Dict[str, Any]]) -> Optional[WAFSignature]:
        """Detect WAF from response data"""
        if not response_data:
            return None
        
        waf_scores = defaultdict(float)
        detected_patterns = defaultdict(list)
        blocked_payloads = []
        
        for response in response_data:
            status_code = response.get('status_code', 200)
            headers = response.get('headers', {})
            content = response.get('content', '').lower()
            request_payload = response.get('request_payload', '')
            
            # Check each WAF signature
            for waf_name, signature in self.waf_signatures.items():
                score = 0.0
                patterns = []
                
                # Check status codes
                if status_code in signature['status_codes']:
                    score += 0.3
                    patterns.append(f"status_code_{status_code}")
                
                # Check headers
                headers_str = str(headers).lower()
                for header_pattern in signature['headers']:
                    if header_pattern.lower() in headers_str:
                        score += 0.4
                        patterns.append(f"header_{header_pattern}")
                
                # Check error page patterns
                for error_pattern in signature['error_pages']:
                    if error_pattern.lower() in content:
                        score += 0.3
                        patterns.append(f"error_page_{error_pattern}")
                
                # Check response patterns
                for response_pattern in signature['response_patterns']:
                    if response_pattern.lower() in content:
                        score += 0.2
                        patterns.append(f"response_{response_pattern}")
                
                if score > 0:
                    waf_scores[waf_name] += score
                    detected_patterns[waf_name].extend(patterns)
                    
                    # Track blocked payloads
                    if status_code in [403, 406] and request_payload:
                        blocked_payloads.append(request_payload)
        
        # Find the WAF with highest score
        if waf_scores:
            best_waf = max(waf_scores, key=waf_scores.get)
            confidence = min(waf_scores[best_waf] / len(response_data), 1.0)
            
            if confidence > 0.3:  # Minimum confidence threshold
                bypass_suggestions = self._generate_bypass_suggestions(best_waf, detected_patterns[best_waf])
                
                return WAFSignature(
                    waf_type=best_waf,
                    signature_patterns=list(set(detected_patterns[best_waf])),
                    blocked_payloads=list(set(blocked_payloads)),
                    confidence=confidence,
                    bypass_suggestions=bypass_suggestions
                )
        
        return None
    
    def _generate_bypass_suggestions(self, waf_type: str, detected_patterns: List[str]) -> List[str]:
        """Generate bypass suggestions based on detected WAF"""
        suggestions = []
        
        bypass_techniques = {
            'cloudflare': [
                'Use HTTP/2 protocol switching',
                'Implement request fragmentation',
                'Try different User-Agent headers',
                'Use legitimate traffic blending',
                'Implement slow HTTP attacks'
            ],
            'aws_waf': [
                'Use payload encoding variations',
                'Implement request header manipulation',
                'Try different HTTP methods',
                'Use geographic IP rotation',
                'Implement timing randomization'
            ],
            'akamai': [
                'Use edge server bypassing',
                'Implement origin server direct access',
                'Try different TLS versions',
                'Use request smuggling techniques',
                'Implement cache poisoning'
            ],
            'incapsula': [
                'Use legitimate session establishment',
                'Implement JavaScript challenge solving',
                'Try different browser fingerprints',
                'Use distributed request sources',
                'Implement behavioral mimicking'
            ],
            'sucuri': [
                'Use payload obfuscation',
                'Implement request rate variation',
                'Try different encoding methods',
                'Use legitimate referrer headers',
                'Implement session token management'
            ],
            'mod_security': [
                'Use SQL injection evasion techniques',
                'Implement XSS payload obfuscation',
                'Try different parameter encoding',
                'Use comment-based evasion',
                'Implement case variation techniques'
            ]
        }
        
        base_suggestions = bypass_techniques.get(waf_type, [])
        
        # Add pattern-specific suggestions
        if any('header_' in pattern for pattern in detected_patterns):
            suggestions.append('Implement header spoofing and rotation')
        
        if any('status_code_403' in pattern for pattern in detected_patterns):
            suggestions.append('Use request method variation (GET/POST/PUT)')
        
        if any('error_page_' in pattern for pattern in detected_patterns):
            suggestions.append('Avoid triggering error pages with legitimate requests')
        
        return base_suggestions + suggestions


class BehavioralDefenseDetector:
    """Detector for behavioral analysis defenses"""
    
    def __init__(self):
        self.behavior_patterns = {}
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        
    def detect_behavioral_defenses(self, metrics: DefenseMetrics, 
                                 attack_patterns: Dict[str, Any]) -> List[DefenseSignature]:
        """Detect behavioral analysis defenses"""
        detected_defenses = []
        
        # Analyze response time patterns
        rt_defense = self._analyze_response_time_behavior(metrics)
        if rt_defense:
            detected_defenses.append(rt_defense)
        
        # Analyze connection patterns
        conn_defense = self._analyze_connection_behavior(metrics)
        if conn_defense:
            detected_defenses.append(conn_defense)
        
        # Analyze throughput adaptation
        throughput_defense = self._analyze_throughput_adaptation(metrics, attack_patterns)
        if throughput_defense:
            detected_defenses.append(throughput_defense)
        
        return detected_defenses
    
    def _analyze_response_time_behavior(self, metrics: DefenseMetrics) -> Optional[DefenseSignature]:
        """Analyze response time patterns for behavioral defenses"""
        if len(metrics.response_times) < 20:
            return None
        
        # Calculate baseline response time
        baseline_rt = statistics.median(metrics.response_times[:10])
        recent_rt = statistics.median(metrics.response_times[-10:])
        
        # Check for gradual increase (behavioral throttling)
        if recent_rt > baseline_rt * 2:
            # Analyze the progression
            window_size = 5
            rt_progression = []
            
            for i in range(window_size, len(metrics.response_times), window_size):
                window_rt = statistics.median(
                    metrics.response_times[i-window_size:i]
                )
                rt_progression.append(window_rt)
            
            # Check for consistent increase
            if len(rt_progression) >= 3:
                increases = sum(1 for i in range(1, len(rt_progression)) 
                              if rt_progression[i] > rt_progression[i-1])
                
                if increases >= len(rt_progression) * 0.6:  # 60% increases
                    return DefenseSignature(
                        defense_type=DefenseType.BEHAVIORAL_ANALYSIS,
                        confidence=0.8,
                        indicators=[
                            f"Response time increased from {baseline_rt:.0f}ms to {recent_rt:.0f}ms",
                            f"Gradual throttling detected over {len(rt_progression)} windows"
                        ],
                        detection_time=datetime.now(),
                        response_pattern={
                            'baseline_response_time': baseline_rt,
                            'current_response_time': recent_rt,
                            'progression': rt_progression
                        }
                    )
        
        return None
    
    def _analyze_connection_behavior(self, metrics: DefenseMetrics) -> Optional[DefenseSignature]:
        """Analyze connection success patterns"""
        if len(metrics.connection_success_rates) < 10:
            return None
        
        # Check for declining connection success
        baseline_success = statistics.mean(metrics.connection_success_rates[:5])
        recent_success = statistics.mean(metrics.connection_success_rates[-5:])
        
        if baseline_success > 0.8 and recent_success < 0.5:
            return DefenseSignature(
                defense_type=DefenseType.BEHAVIORAL_ANALYSIS,
                confidence=0.7,
                indicators=[
                    f"Connection success dropped from {baseline_success:.2f} to {recent_success:.2f}",
                    "Progressive connection blocking detected"
                ],
                detection_time=datetime.now(),
                response_pattern={
                    'baseline_success_rate': baseline_success,
                    'current_success_rate': recent_success
                }
            )
        
        return None
    
    def _analyze_throughput_adaptation(self, metrics: DefenseMetrics, 
                                     attack_patterns: Dict[str, Any]) -> Optional[DefenseSignature]:
        """Analyze throughput adaptation patterns"""
        if len(metrics.throughput_measurements) < 15:
            return None
        
        # Check if throughput decreases as attack intensity increases
        attack_intensity = attack_patterns.get('packet_rate', 0)
        
        # Correlate attack intensity with throughput
        if attack_intensity > 0:
            # Split into intensity periods
            low_intensity_throughput = []
            high_intensity_throughput = []
            
            intensity_threshold = attack_intensity * 0.7
            
            for i, throughput in enumerate(metrics.throughput_measurements):
                current_intensity = attack_patterns.get('intensity_history', [attack_intensity])[
                    min(i, len(attack_patterns.get('intensity_history', [])) - 1)
                ]
                
                if current_intensity < intensity_threshold:
                    low_intensity_throughput.append(throughput)
                else:
                    high_intensity_throughput.append(throughput)
            
            if low_intensity_throughput and high_intensity_throughput:
                low_avg = statistics.mean(low_intensity_throughput)
                high_avg = statistics.mean(high_intensity_throughput)
                
                # Adaptive defense reduces throughput under high intensity
                if low_avg > high_avg * 1.5:
                    return DefenseSignature(
                        defense_type=DefenseType.BEHAVIORAL_ANALYSIS,
                        confidence=0.75,
                        indicators=[
                            f"Throughput adaptation detected",
                            f"Low intensity: {low_avg:.0f} req/s, High intensity: {high_avg:.0f} req/s"
                        ],
                        detection_time=datetime.now(),
                        response_pattern={
                            'low_intensity_throughput': low_avg,
                            'high_intensity_throughput': high_avg,
                            'adaptation_ratio': low_avg / high_avg
                        }
                    )
        
        return None


class AdvancedDefenseDetectionSystem:
    """Main advanced defense detection system with enhanced real-time capabilities"""
    
    def __init__(self):
        self.rate_limit_detector = RateLimitDetector()
        self.waf_detector = WAFDetector()
        self.behavioral_detector = BehavioralDefenseDetector()
        
        # Metrics collection
        self.defense_metrics = DefenseMetrics()
        self.detection_history = deque(maxlen=1000)
        
        # Enhanced real-time monitoring
        self.monitoring_active = False
        self.monitoring_thread = None
        self._lock = threading.Lock()
        
        # Real-time signature detection
        self.signature_cache = {}
        self.pattern_buffer = deque(maxlen=100)  # Buffer for pattern analysis
        self.detection_callbacks = []
        
        # Enhanced detection statistics
        self.detection_stats = {
            'total_detections': 0,
            'rate_limit_detections': 0,
            'waf_detections': 0,
            'behavioral_detections': 0,
            'signature_matches': 0,
            'false_positives': 0,
            'detection_accuracy': 0.0
        }
        
        # Adaptive thresholds
        self.adaptive_thresholds = {
            'rate_limit_confidence': 0.7,
            'waf_confidence': 0.6,
            'behavioral_confidence': 0.8,
            'signature_match_threshold': 0.5
        }
        
        logger.info("Advanced Defense Detection System initialized with enhanced capabilities")
    
    def analyze_comprehensive_defenses(self, 
                                     response_history: List[Dict[str, Any]],
                                     attack_parameters: Dict[str, Any]) -> List[DefenseSignature]:
        """Comprehensive defense analysis using all detectors"""
        
        with self._lock:
            detected_defenses = []
            
            # Update metrics from response history
            self._update_metrics_from_responses(response_history)
            
            # Rate limiting detection
            rate_limit_analysis = self.rate_limit_detector.analyze_rate_limiting(self.defense_metrics)
            if rate_limit_analysis:
                defense_sig = DefenseSignature(
                    defense_type=DefenseType.RATE_LIMITING,
                    confidence=rate_limit_analysis.confidence,
                    indicators=rate_limit_analysis.evidence,
                    detection_time=rate_limit_analysis.detection_time,
                    response_pattern={
                        'limit_type': rate_limit_analysis.limit_type.name,
                        'estimated_limit': rate_limit_analysis.estimated_limit,
                        'window_size': rate_limit_analysis.window_size
                    }
                )
                detected_defenses.append(defense_sig)
            
            # WAF detection
            waf_signature = self.waf_detector.detect_waf(response_history)
            if waf_signature:
                defense_sig = DefenseSignature(
                    defense_type=DefenseType.WAF,
                    confidence=waf_signature.confidence,
                    indicators=waf_signature.signature_patterns,
                    detection_time=waf_signature.detection_time,
                    response_pattern={
                        'waf_type': waf_signature.waf_type,
                        'blocked_payloads': waf_signature.blocked_payloads,
                        'bypass_suggestions': waf_signature.bypass_suggestions
                    }
                )
                detected_defenses.append(defense_sig)
            
            # Behavioral defense detection
            behavioral_defenses = self.behavioral_detector.detect_behavioral_defenses(
                self.defense_metrics, attack_parameters
            )
            detected_defenses.extend(behavioral_defenses)
            
            # Store detection results
            detection_result = {
                'timestamp': datetime.now(),
                'detected_defenses': [d.defense_type.value for d in detected_defenses],
                'response_count': len(response_history),
                'attack_parameters': attack_parameters.copy()
            }
            self.detection_history.append(detection_result)
            
            logger.info(f"Advanced defense analysis complete: {len(detected_defenses)} defenses detected")
            
            return detected_defenses
    
    def _update_metrics_from_responses(self, response_history: List[Dict[str, Any]]):
        """Update defense metrics from response history"""
        for response in response_history:
            response_time = response.get('response_time', 0)
            status_code = response.get('status_code', 200)
            
            # Calculate error rate for this response
            error_rate = 1.0 if status_code >= 400 else 0.0
            
            # Calculate connection success
            connection_success = 0.0 if response.get('connection_error', False) else 1.0
            
            # Estimate throughput (simplified)
            throughput = response.get('throughput', 0)
            if throughput == 0 and response_time > 0:
                # Estimate based on response time
                throughput = 1000.0 / response_time  # Rough estimate
            
            self.defense_metrics.add_measurement(
                response_time=response_time,
                status_code=status_code,
                error_rate=error_rate,
                connection_success=connection_success,
                throughput=throughput
            )
    
    def start_real_time_monitoring(self, callback: Optional[callable] = None):
        """Start real-time defense monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(callback,),
            daemon=True
        )
        self.monitoring_thread.start()
        
        logger.info("Real-time defense monitoring started")
    
    def stop_real_time_monitoring(self):
        """Stop real-time defense monitoring"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("Real-time defense monitoring stopped")
    
    def _monitoring_loop(self, callback: Optional[callable]):
        """Real-time monitoring loop"""
        while self.monitoring_active:
            try:
                # Check for new defense patterns every 5 seconds
                time.sleep(5)
                
                # Analyze recent metrics
                if len(self.defense_metrics.timestamps) >= 10:
                    # Quick analysis of recent data
                    recent_responses = []
                    cutoff_time = datetime.now() - timedelta(seconds=30)
                    
                    for i, timestamp in enumerate(self.defense_metrics.timestamps):
                        if timestamp > cutoff_time:
                            recent_responses.append({
                                'response_time': self.defense_metrics.response_times[i],
                                'status_code': self.defense_metrics.status_codes[i],
                                'timestamp': timestamp
                            })
                    
                    if recent_responses and callback:
                        # Trigger callback with recent analysis
                        callback(recent_responses)
                
            except Exception as e:
                logger.error(f"Error in defense monitoring loop: {e}")
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics"""
        with self._lock:
            # Defense type frequency
            defense_counts = defaultdict(int)
            for detection in self.detection_history:
                for defense_type in detection['detected_defenses']:
                    defense_counts[defense_type] += 1
            
            # Recent detection trends
            recent_detections = list(self.detection_history)[-50:]
            recent_defense_counts = defaultdict(int)
            for detection in recent_detections:
                for defense_type in detection['detected_defenses']:
                    recent_defense_counts[defense_type] += 1
            
            # Metrics summary
            metrics_summary = {}
            if self.defense_metrics.response_times:
                metrics_summary = {
                    'avg_response_time': statistics.mean(self.defense_metrics.response_times),
                    'response_time_trend': self._calculate_trend(self.defense_metrics.response_times),
                    'error_rate': statistics.mean(self.defense_metrics.error_rates),
                    'connection_success_rate': statistics.mean(self.defense_metrics.connection_success_rates),
                    'avg_throughput': statistics.mean(self.defense_metrics.throughput_measurements)
                }
            
            return {
                'total_detections': len(self.detection_history),
                'defense_type_frequency': dict(defense_counts),
                'recent_defense_frequency': dict(recent_defense_counts),
                'metrics_summary': metrics_summary,
                'monitoring_active': self.monitoring_active,
                'metrics_count': len(self.defense_metrics.timestamps)
            }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a list of values"""
        if len(values) < 10:
            return "insufficient_data"
        
        # Compare first half with second half
        mid_point = len(values) // 2
        first_half_avg = statistics.mean(values[:mid_point])
        second_half_avg = statistics.mean(values[mid_point:])
        
        if second_half_avg > first_half_avg * 1.1:
            return "increasing"
        elif second_half_avg < first_half_avg * 0.9:
            return "decreasing"
        else:
            return "stable"
    
    def detect_real_time_signatures(self, response_data: Dict[str, Any]) -> List[DefenseSignature]:
        """Enhanced real-time signature detection"""
        detected_signatures = []
        
        with self._lock:
            # Add to pattern buffer for analysis
            self.pattern_buffer.append({
                'timestamp': datetime.now(),
                'response': response_data
            })
            
            # Quick signature matching
            quick_matches = self._quick_signature_match(response_data)
            if quick_matches:
                detected_signatures.extend(quick_matches)
                self.detection_stats['signature_matches'] += len(quick_matches)
            
            # Pattern-based detection (analyze recent patterns)
            if len(self.pattern_buffer) >= 5:
                pattern_signatures = self._analyze_pattern_signatures()
                if pattern_signatures:
                    detected_signatures.extend(pattern_signatures)
            
            # Update detection statistics
            if detected_signatures:
                self.detection_stats['total_detections'] += 1
                
                # Notify callbacks
                for callback in self.detection_callbacks:
                    try:
                        callback(detected_signatures, response_data)
                    except Exception as e:
                        logger.error(f"Detection callback error: {e}")
        
        return detected_signatures
    
    def _quick_signature_match(self, response_data: Dict[str, Any]) -> List[DefenseSignature]:
        """Quick signature matching for real-time detection"""
        signatures = []
        
        status_code = response_data.get('status_code', 200)
        headers = response_data.get('headers', {})
        content = response_data.get('content', '').lower()
        response_time = response_data.get('response_time', 0)
        
        # Quick WAF detection
        for waf_name, waf_sig in self.waf_detector.waf_signatures.items():
            confidence = 0.0
            indicators = []
            
            # Status code match
            if status_code in waf_sig['status_codes']:
                confidence += 0.4
                indicators.append(f"status_code_{status_code}")
            
            # Header match
            headers_str = str(headers).lower()
            for header_pattern in waf_sig['headers']:
                if header_pattern.lower() in headers_str:
                    confidence += 0.3
                    indicators.append(f"header_{header_pattern}")
                    break  # Only count first header match for quick detection
            
            # Content match
            for pattern in waf_sig['response_patterns']:
                if pattern.lower() in content:
                    confidence += 0.3
                    indicators.append(f"content_{pattern}")
                    break  # Only count first content match for quick detection
            
            # Timing pattern match
            timing_patterns = waf_sig.get('timing_patterns', {})
            if timing_patterns.get('consistent_delays') and response_time > 3000:
                confidence += 0.2
                indicators.append("timing_delay_pattern")
            
            if confidence >= self.adaptive_thresholds['signature_match_threshold']:
                signatures.append(DefenseSignature(
                    defense_type=DefenseType.WAF,
                    confidence=min(confidence, 1.0),
                    indicators=indicators,
                    detection_time=datetime.now(),
                    response_pattern={
                        'waf_type': waf_name,
                        'quick_match': True,
                        'response_time': response_time
                    }
                ))
                break  # Only return first match for quick detection
        
        # Quick rate limiting detection
        if status_code in [429, 503, 502, 504, 509]:
            # Check recent pattern buffer for rate limiting patterns
            recent_rate_limits = [
                p for p in list(self.pattern_buffer)[-10:]
                if p['response'].get('status_code') in [429, 503, 502, 504, 509]
            ]
            
            if len(recent_rate_limits) >= 3:  # Multiple rate limits in recent history
                confidence = min(0.8, 0.2 * len(recent_rate_limits))
                signatures.append(DefenseSignature(
                    defense_type=DefenseType.RATE_LIMITING,
                    confidence=confidence,
                    indicators=[f"quick_rate_limit_pattern_{len(recent_rate_limits)}_occurrences"],
                    detection_time=datetime.now(),
                    response_pattern={
                        'quick_match': True,
                        'recent_rate_limits': len(recent_rate_limits),
                        'status_code': status_code
                    }
                ))
        
        return signatures
    
    def _analyze_pattern_signatures(self) -> List[DefenseSignature]:
        """Analyze patterns in the buffer for signature detection"""
        signatures = []
        
        recent_patterns = list(self.pattern_buffer)[-20:]  # Analyze last 20 responses
        
        # Analyze response time patterns
        response_times = [p['response'].get('response_time', 0) for p in recent_patterns]
        if response_times:
            avg_rt = statistics.mean(response_times)
            rt_variance = statistics.variance(response_times) if len(response_times) > 1 else 0
            
            # Consistent high response times suggest behavioral defense
            if avg_rt > 5000 and rt_variance < avg_rt * 0.2:  # High RT with low variance
                signatures.append(DefenseSignature(
                    defense_type=DefenseType.BEHAVIORAL_ANALYSIS,
                    confidence=0.7,
                    indicators=[f"consistent_high_response_time_{avg_rt:.0f}ms"],
                    detection_time=datetime.now(),
                    response_pattern={
                        'pattern_match': True,
                        'avg_response_time': avg_rt,
                        'variance': rt_variance
                    }
                ))
        
        # Analyze status code patterns
        status_codes = [p['response'].get('status_code', 200) for p in recent_patterns]
        error_rate = len([c for c in status_codes if c >= 400]) / len(status_codes)
        
        if error_rate > 0.5:  # High error rate
            # Determine if it's WAF or rate limiting based on specific codes
            waf_codes = len([c for c in status_codes if c in [403, 406, 418]])
            rate_limit_codes = len([c for c in status_codes if c in [429, 503, 502, 504]])
            
            if waf_codes > rate_limit_codes:
                signatures.append(DefenseSignature(
                    defense_type=DefenseType.WAF,
                    confidence=0.6,
                    indicators=[f"pattern_high_waf_error_rate_{error_rate:.2f}"],
                    detection_time=datetime.now(),
                    response_pattern={
                        'pattern_match': True,
                        'error_rate': error_rate,
                        'waf_codes': waf_codes
                    }
                ))
            elif rate_limit_codes > 0:
                signatures.append(DefenseSignature(
                    defense_type=DefenseType.RATE_LIMITING,
                    confidence=0.6,
                    indicators=[f"pattern_high_rate_limit_error_rate_{error_rate:.2f}"],
                    detection_time=datetime.now(),
                    response_pattern={
                        'pattern_match': True,
                        'error_rate': error_rate,
                        'rate_limit_codes': rate_limit_codes
                    }
                ))
        
        return signatures
    
    def register_detection_callback(self, callback: callable):
        """Register callback for real-time detection events"""
        if callback not in self.detection_callbacks:
            self.detection_callbacks.append(callback)
            logger.info("Detection callback registered")
    
    def unregister_detection_callback(self, callback: callable):
        """Unregister detection callback"""
        if callback in self.detection_callbacks:
            self.detection_callbacks.remove(callback)
            logger.info("Detection callback unregistered")
    
    def update_adaptive_thresholds(self, detection_accuracy: float):
        """Update adaptive thresholds based on detection accuracy"""
        with self._lock:
            self.detection_stats['detection_accuracy'] = detection_accuracy
            
            # Adjust thresholds based on accuracy
            if detection_accuracy > 0.9:  # High accuracy - can be more sensitive
                self.adaptive_thresholds['signature_match_threshold'] *= 0.9
                self.adaptive_thresholds['waf_confidence'] *= 0.95
            elif detection_accuracy < 0.7:  # Low accuracy - be more conservative
                self.adaptive_thresholds['signature_match_threshold'] *= 1.1
                self.adaptive_thresholds['waf_confidence'] *= 1.05
            
            # Ensure thresholds stay within reasonable bounds
            self.adaptive_thresholds['signature_match_threshold'] = max(0.3, min(0.8, 
                self.adaptive_thresholds['signature_match_threshold']))
            self.adaptive_thresholds['waf_confidence'] = max(0.5, min(0.9,
                self.adaptive_thresholds['waf_confidence']))
            
            logger.info(f"Adaptive thresholds updated based on accuracy {detection_accuracy:.2f}")
    
    def export_detection_data(self, filepath: str):
        """Export detection data for analysis"""
        export_data = {
            'detection_history': [
                {
                    'timestamp': detection['timestamp'].isoformat(),
                    'detected_defenses': detection['detected_defenses'],
                    'response_count': detection['response_count'],
                    'attack_parameters': detection['attack_parameters']
                }
                for detection in self.detection_history
            ],
            'metrics_summary': self.get_detection_statistics(),
            'detection_stats': self.detection_stats.copy(),
            'adaptive_thresholds': self.adaptive_thresholds.copy(),
            'export_timestamp': datetime.now().isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Enhanced detection data exported to {filepath}")


# Global advanced defense detection system
advanced_defense_detector = AdvancedDefenseDetectionSystem()

__all__ = [
    'DefensePattern', 'DefenseMetrics', 'RateLimitAnalysis', 'WAFSignature',
    'RateLimitDetector', 'WAFDetector', 'BehavioralDefenseDetector',
    'AdvancedDefenseDetectionSystem', 'advanced_defense_detector'
]