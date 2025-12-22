#!/usr/bin/env python3
"""
Attack Insights Generator

Analyzes effectiveness patterns from attack data to generate actionable insights
and recommendations for manual parameter tuning. This module implements
requirement 8.5 by providing comprehensive analysis of attack effectiveness
patterns and generating strategic recommendations.
"""

import logging
import numpy as np
import statistics
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum, auto
import json
import threading

logger = logging.getLogger(__name__)


class InsightType(Enum):
    """Types of insights that can be generated"""
    PERFORMANCE_PATTERN = auto()
    EFFECTIVENESS_TREND = auto()
    PARAMETER_CORRELATION = auto()
    DEFENSE_DETECTION = auto()
    OPTIMIZATION_OPPORTUNITY = auto()
    RESOURCE_EFFICIENCY = auto()
    TARGET_BEHAVIOR = auto()


class InsightSeverity(Enum):
    """Severity levels for insights"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AttackInsight:
    """Represents a single attack insight"""
    insight_type: InsightType
    title: str
    description: str
    severity: InsightSeverity
    confidence: float  # 0.0 to 1.0
    impact_score: float  # 0.0 to 100.0
    recommendations: List[str]
    supporting_data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert insight to dictionary for serialization"""
        return {
            'insight_type': self.insight_type.name,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'impact_score': self.impact_score,
            'recommendations': self.recommendations,
            'supporting_data': self.supporting_data,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class EffectivenessPattern:
    """Represents an effectiveness pattern discovered in attack data"""
    pattern_name: str
    pattern_type: str  # 'temporal', 'parameter', 'target_response'
    description: str
    frequency: float  # How often this pattern occurs
    impact: float  # Impact on effectiveness (0-100)
    conditions: Dict[str, Any]  # Conditions when pattern occurs
    examples: List[Dict[str, Any]]  # Example data points


class AttackInsightsGenerator:
    """
    Generates actionable insights from attack effectiveness data.
    
    This class analyzes patterns in attack performance, parameter effectiveness,
    target responses, and resource utilization to provide strategic recommendations
    for manual parameter tuning and attack optimization.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.attack_history = deque(maxlen=10000)
        self.insights_cache = deque(maxlen=1000)
        self.patterns_cache = {}
        self.analysis_lock = threading.Lock()
        
        # Pattern detection thresholds
        self.min_samples_for_pattern = 20
        self.correlation_threshold = 0.7
        self.trend_significance_threshold = 0.05
        
        self.logger.info("Attack Insights Generator initialized")
    
    def add_attack_data(self, attack_data: Dict[str, Any]):
        """
        Add attack performance data for analysis.
        
        Args:
            attack_data: Dictionary containing attack metrics and configuration
        """
        try:
            # Validate required fields
            required_fields = ['timestamp', 'pps', 'success_rate', 'config']
            if not all(field in attack_data for field in required_fields):
                self.logger.warning(f"Attack data missing required fields: {required_fields}")
                return
            
            # Add timestamp if not present
            if 'timestamp' not in attack_data:
                attack_data['timestamp'] = datetime.now()
            elif isinstance(attack_data['timestamp'], str):
                attack_data['timestamp'] = datetime.fromisoformat(attack_data['timestamp'])
            
            with self.analysis_lock:
                self.attack_history.append(attack_data.copy())
                
            self.logger.debug(f"Added attack data: PPS={attack_data.get('pps', 0):.0f}, "
                            f"Success Rate={attack_data.get('success_rate', 0):.2f}")
                            
        except Exception as e:
            self.logger.error(f"Error adding attack data: {e}")
    
    def generate_insights(self, min_confidence: float = 0.6) -> List[AttackInsight]:
        """
        Generate comprehensive insights from accumulated attack data.
        
        Args:
            min_confidence: Minimum confidence threshold for insights
            
        Returns:
            List of AttackInsight objects
        """
        insights = []
        
        try:
            with self.analysis_lock:
                if len(self.attack_history) < self.min_samples_for_pattern:
                    self.logger.info(f"Insufficient data for insights generation: "
                                   f"{len(self.attack_history)} < {self.min_samples_for_pattern}")
                    return insights
                
                # Generate different types of insights
                insights.extend(self._analyze_performance_patterns())
                insights.extend(self._analyze_effectiveness_trends())
                insights.extend(self._analyze_parameter_correlations())
                insights.extend(self._detect_defense_mechanisms())
                insights.extend(self._identify_optimization_opportunities())
                insights.extend(self._analyze_resource_efficiency())
                insights.extend(self._analyze_target_behavior())
                
                # Filter by confidence threshold
                insights = [insight for insight in insights if insight.confidence >= min_confidence]
                
                # Sort by impact score (highest first)
                insights.sort(key=lambda x: x.impact_score, reverse=True)
                
                # Cache insights
                for insight in insights:
                    self.insights_cache.append(insight)
                
                self.logger.info(f"Generated {len(insights)} insights from {len(self.attack_history)} data points")
                
        except Exception as e:
            self.logger.error(f"Error generating insights: {e}")
        
        return insights
    
    def _analyze_performance_patterns(self) -> List[AttackInsight]:
        """Analyze performance patterns in attack data"""
        insights = []
        
        try:
            # Extract performance metrics
            pps_values = [data['pps'] for data in self.attack_history if 'pps' in data]
            success_rates = [data['success_rate'] for data in self.attack_history if 'success_rate' in data]
            
            if len(pps_values) < self.min_samples_for_pattern:
                return insights
            
            # Analyze PPS patterns
            pps_mean = statistics.mean(pps_values)
            pps_stdev = statistics.stdev(pps_values) if len(pps_values) > 1 else 0
            pps_trend = self._calculate_trend(pps_values)
            
            # High variability pattern
            if pps_stdev > pps_mean * 0.3:  # High coefficient of variation
                insight = AttackInsight(
                    insight_type=InsightType.PERFORMANCE_PATTERN,
                    title="High Performance Variability Detected",
                    description=f"Packet rate shows high variability (σ={pps_stdev:.0f}, μ={pps_mean:.0f}). "
                               f"This suggests inconsistent performance that could be optimized.",
                    severity=InsightSeverity.MEDIUM,
                    confidence=0.8,
                    impact_score=60.0,
                    recommendations=[
                        "Consider stabilizing thread count and CPU affinity",
                        "Review rate limiting configuration for consistency",
                        "Monitor system resource usage during attacks",
                        "Consider using fixed packet sizes for more predictable performance"
                    ],
                    supporting_data={
                        'pps_mean': pps_mean,
                        'pps_stdev': pps_stdev,
                        'coefficient_of_variation': pps_stdev / pps_mean,
                        'sample_count': len(pps_values)
                    }
                )
                insights.append(insight)
            
            # Performance trend analysis
            if abs(pps_trend) > self.trend_significance_threshold:
                trend_direction = "increasing" if pps_trend > 0 else "decreasing"
                severity = InsightSeverity.HIGH if abs(pps_trend) > 0.1 else InsightSeverity.MEDIUM
                
                insight = AttackInsight(
                    insight_type=InsightType.PERFORMANCE_PATTERN,
                    title=f"Performance Trend: {trend_direction.title()}",
                    description=f"Packet rate is {trend_direction} over time (trend={pps_trend:.3f}). "
                               f"This may indicate system adaptation or degradation.",
                    severity=severity,
                    confidence=0.75,
                    impact_score=70.0 if abs(pps_trend) > 0.1 else 45.0,
                    recommendations=[
                        "Investigate system resource trends" if pps_trend < 0 else "Monitor for performance ceiling",
                        "Consider adjusting attack duration or intensity",
                        "Review target system behavior patterns",
                        "Implement performance monitoring alerts"
                    ],
                    supporting_data={
                        'trend_slope': pps_trend,
                        'trend_direction': trend_direction,
                        'sample_count': len(pps_values)
                    }
                )
                insights.append(insight)
            
            # Success rate patterns
            if success_rates:
                success_mean = statistics.mean(success_rates)
                if success_mean < 0.7:  # Low success rate
                    insight = AttackInsight(
                        insight_type=InsightType.PERFORMANCE_PATTERN,
                        title="Low Success Rate Pattern",
                        description=f"Average success rate is {success_mean:.1%}, indicating potential "
                                   f"target defenses or network issues.",
                        severity=InsightSeverity.HIGH,
                        confidence=0.85,
                        impact_score=80.0,
                        recommendations=[
                            "Investigate target defense mechanisms",
                            "Consider IP spoofing or source rotation",
                            "Adjust packet rate to avoid rate limiting",
                            "Review network path and routing",
                            "Consider different attack vectors or protocols"
                        ],
                        supporting_data={
                            'success_rate_mean': success_mean,
                            'success_rate_samples': len(success_rates)
                        }
                    )
                    insights.append(insight)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing performance patterns: {e}")
        
        return insights
    
    def _analyze_effectiveness_trends(self) -> List[AttackInsight]:
        """Analyze trends in attack effectiveness over time"""
        insights = []
        
        try:
            # Group data by time windows for trend analysis
            time_windows = self._group_by_time_windows(hours=1)
            
            if len(time_windows) < 3:  # Need at least 3 time windows
                return insights
            
            # Calculate effectiveness score for each window
            effectiveness_scores = []
            for window_data in time_windows:
                if not window_data:
                    continue
                    
                avg_pps = statistics.mean([d['pps'] for d in window_data if 'pps' in d])
                avg_success = statistics.mean([d['success_rate'] for d in window_data if 'success_rate' in d])
                
                # Combined effectiveness score (weighted)
                effectiveness = (avg_pps / 10000) * 0.6 + avg_success * 0.4  # Normalize PPS to 0-1 range
                effectiveness_scores.append(effectiveness)
            
            # Analyze trend
            trend = self._calculate_trend(effectiveness_scores)
            
            if abs(trend) > self.trend_significance_threshold:
                trend_direction = "improving" if trend > 0 else "declining"
                severity = InsightSeverity.HIGH if abs(trend) > 0.1 else InsightSeverity.MEDIUM
                
                insight = AttackInsight(
                    insight_type=InsightType.EFFECTIVENESS_TREND,
                    title=f"Effectiveness Trend: {trend_direction.title()}",
                    description=f"Attack effectiveness is {trend_direction} over time. "
                               f"Trend coefficient: {trend:.3f}",
                    severity=severity,
                    confidence=0.8,
                    impact_score=75.0 if abs(trend) > 0.1 else 50.0,
                    recommendations=[
                        "Investigate target adaptation patterns" if trend < 0 else "Maintain current strategy",
                        "Consider varying attack parameters to avoid detection",
                        "Monitor target defense deployment",
                        "Adjust attack timing and intensity"
                    ],
                    supporting_data={
                        'trend_coefficient': trend,
                        'effectiveness_scores': effectiveness_scores,
                        'time_windows_analyzed': len(time_windows)
                    }
                )
                insights.append(insight)
                
        except Exception as e:
            self.logger.error(f"Error analyzing effectiveness trends: {e}")
        
        return insights
    
    def _analyze_parameter_correlations(self) -> List[AttackInsight]:
        """Analyze correlations between attack parameters and effectiveness"""
        insights = []
        
        try:
            # Extract parameter and performance data
            data_points = []
            for attack_data in self.attack_history:
                if 'config' not in attack_data:
                    continue
                    
                config = attack_data['config']
                point = {
                    'packet_rate': config.get('packet_rate', 0),
                    'packet_size': config.get('packet_size', 0),
                    'thread_count': config.get('thread_count', 0),
                    'pps': attack_data.get('pps', 0),
                    'success_rate': attack_data.get('success_rate', 0),
                    'effectiveness': attack_data.get('pps', 0) * attack_data.get('success_rate', 0)
                }
                data_points.append(point)
            
            if len(data_points) < self.min_samples_for_pattern:
                return insights
            
            # Analyze correlations
            parameters = ['packet_rate', 'packet_size', 'thread_count']
            targets = ['pps', 'success_rate', 'effectiveness']
            
            strong_correlations = []
            
            for param in parameters:
                for target in targets:
                    param_values = [dp[param] for dp in data_points if dp[param] > 0]
                    target_values = [dp[target] for dp in data_points if dp[param] > 0]
                    
                    if len(param_values) >= self.min_samples_for_pattern:
                        correlation = self._calculate_correlation(param_values, target_values)
                        
                        if abs(correlation) >= self.correlation_threshold:
                            strong_correlations.append({
                                'parameter': param,
                                'target': target,
                                'correlation': correlation,
                                'sample_count': len(param_values)
                            })
            
            # Generate insights for strong correlations
            for corr in strong_correlations:
                correlation_type = "positive" if corr['correlation'] > 0 else "negative"
                strength = "strong" if abs(corr['correlation']) > 0.8 else "moderate"
                
                insight = AttackInsight(
                    insight_type=InsightType.PARAMETER_CORRELATION,
                    title=f"{strength.title()} {correlation_type} correlation: {corr['parameter']} vs {corr['target']}",
                    description=f"Found {strength} {correlation_type} correlation ({corr['correlation']:.3f}) "
                               f"between {corr['parameter']} and {corr['target']}.",
                    severity=InsightSeverity.MEDIUM,
                    confidence=min(0.9, abs(corr['correlation'])),
                    impact_score=60.0 + abs(corr['correlation']) * 30,
                    recommendations=self._get_correlation_recommendations(corr),
                    supporting_data=corr
                )
                insights.append(insight)
                
        except Exception as e:
            self.logger.error(f"Error analyzing parameter correlations: {e}")
        
        return insights
    
    def _detect_defense_mechanisms(self) -> List[AttackInsight]:
        """Detect potential defense mechanisms based on attack patterns"""
        insights = []
        
        try:
            # Analyze for rate limiting patterns
            rate_limiting_detected = self._detect_rate_limiting()
            if rate_limiting_detected:
                insights.append(rate_limiting_detected)
            
            # Analyze for WAF patterns
            waf_detected = self._detect_waf_behavior()
            if waf_detected:
                insights.append(waf_detected)
            
            # Analyze for DDoS protection
            ddos_protection_detected = self._detect_ddos_protection()
            if ddos_protection_detected:
                insights.append(ddos_protection_detected)
                
        except Exception as e:
            self.logger.error(f"Error detecting defense mechanisms: {e}")
        
        return insights
    
    def _identify_optimization_opportunities(self) -> List[AttackInsight]:
        """Identify opportunities for attack optimization"""
        insights = []
        
        try:
            # Analyze resource utilization
            cpu_usage_data = [d.get('cpu_usage', 0) for d in self.attack_history if 'cpu_usage' in d]
            memory_usage_data = [d.get('memory_usage', 0) for d in self.attack_history if 'memory_usage' in d]
            
            # Low resource utilization opportunity
            if cpu_usage_data and statistics.mean(cpu_usage_data) < 0.5:
                insight = AttackInsight(
                    insight_type=InsightType.OPTIMIZATION_OPPORTUNITY,
                    title="Low CPU Utilization - Scaling Opportunity",
                    description=f"Average CPU usage is {statistics.mean(cpu_usage_data):.1%}. "
                               f"There's opportunity to increase attack intensity.",
                    severity=InsightSeverity.MEDIUM,
                    confidence=0.8,
                    impact_score=65.0,
                    recommendations=[
                        "Increase thread count to utilize more CPU cores",
                        "Increase packet rate within system limits",
                        "Consider running multiple attack instances",
                        "Optimize packet generation algorithms"
                    ],
                    supporting_data={
                        'avg_cpu_usage': statistics.mean(cpu_usage_data),
                        'sample_count': len(cpu_usage_data)
                    }
                )
                insights.append(insight)
            
            # Suboptimal parameter combinations
            suboptimal_configs = self._find_suboptimal_configurations()
            for config_insight in suboptimal_configs:
                insights.append(config_insight)
                
        except Exception as e:
            self.logger.error(f"Error identifying optimization opportunities: {e}")
        
        return insights
    
    def _analyze_resource_efficiency(self) -> List[AttackInsight]:
        """Analyze resource efficiency patterns"""
        insights = []
        
        try:
            # Calculate efficiency metrics
            efficiency_data = []
            for data in self.attack_history:
                if all(key in data for key in ['pps', 'cpu_usage', 'memory_usage']):
                    # Efficiency = PPS per unit of resource usage
                    cpu_efficiency = data['pps'] / max(data['cpu_usage'], 0.01)
                    memory_efficiency = data['pps'] / max(data['memory_usage'], 0.01)
                    
                    efficiency_data.append({
                        'cpu_efficiency': cpu_efficiency,
                        'memory_efficiency': memory_efficiency,
                        'timestamp': data['timestamp']
                    })
            
            if len(efficiency_data) >= self.min_samples_for_pattern:
                cpu_efficiencies = [d['cpu_efficiency'] for d in efficiency_data]
                cpu_trend = self._calculate_trend(cpu_efficiencies)
                
                if cpu_trend < -self.trend_significance_threshold:
                    insight = AttackInsight(
                        insight_type=InsightType.RESOURCE_EFFICIENCY,
                        title="Declining CPU Efficiency",
                        description=f"CPU efficiency is declining over time (trend={cpu_trend:.3f}). "
                                   f"This may indicate resource contention or system degradation.",
                        severity=InsightSeverity.MEDIUM,
                        confidence=0.75,
                        impact_score=55.0,
                        recommendations=[
                            "Monitor system resource contention",
                            "Consider CPU affinity settings",
                            "Review background processes",
                            "Optimize packet generation algorithms"
                        ],
                        supporting_data={
                            'efficiency_trend': cpu_trend,
                            'avg_efficiency': statistics.mean(cpu_efficiencies),
                            'sample_count': len(cpu_efficiencies)
                        }
                    )
                    insights.append(insight)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing resource efficiency: {e}")
        
        return insights
    
    def _analyze_target_behavior(self) -> List[AttackInsight]:
        """Analyze target system behavior patterns"""
        insights = []
        
        try:
            # Analyze response time patterns
            response_times = [d.get('response_time', 0) for d in self.attack_history if 'response_time' in d]
            
            if len(response_times) >= self.min_samples_for_pattern:
                response_trend = self._calculate_trend(response_times)
                
                if response_trend > self.trend_significance_threshold:
                    insight = AttackInsight(
                        insight_type=InsightType.TARGET_BEHAVIOR,
                        title="Target Response Time Increasing",
                        description=f"Target response times are increasing (trend={response_trend:.3f}). "
                                   f"This may indicate target system stress or defensive measures.",
                        severity=InsightSeverity.MEDIUM,
                        confidence=0.7,
                        impact_score=50.0,
                        recommendations=[
                            "Monitor target system health indicators",
                            "Consider adjusting attack intensity",
                            "Analyze target capacity limits",
                            "Implement response time monitoring"
                        ],
                        supporting_data={
                            'response_time_trend': response_trend,
                            'avg_response_time': statistics.mean(response_times),
                            'sample_count': len(response_times)
                        }
                    )
                    insights.append(insight)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing target behavior: {e}")
        
        return insights
    
    # Helper methods
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate linear trend coefficient for a series of values"""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        x = list(range(n))
        
        # Calculate linear regression slope
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(values)
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _calculate_correlation(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0.0
        
        n = len(x_values)
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(y_values)
        
        numerator = sum((x_values[i] - x_mean) * (y_values[i] - y_mean) for i in range(n))
        
        x_variance = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        y_variance = sum((y_values[i] - y_mean) ** 2 for i in range(n))
        
        denominator = (x_variance * y_variance) ** 0.5
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _group_by_time_windows(self, hours: int = 1) -> List[List[Dict[str, Any]]]:
        """Group attack data by time windows"""
        if not self.attack_history:
            return []
        
        # Sort by timestamp
        sorted_data = sorted(self.attack_history, key=lambda x: x['timestamp'])
        
        windows = []
        current_window = []
        window_start = sorted_data[0]['timestamp']
        window_duration = timedelta(hours=hours)
        
        for data in sorted_data:
            if data['timestamp'] - window_start <= window_duration:
                current_window.append(data)
            else:
                if current_window:
                    windows.append(current_window)
                current_window = [data]
                window_start = data['timestamp']
        
        if current_window:
            windows.append(current_window)
        
        return windows
    
    def _get_correlation_recommendations(self, correlation_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on correlation analysis"""
        param = correlation_data['parameter']
        target = correlation_data['target']
        corr = correlation_data['correlation']
        
        recommendations = []
        
        if corr > 0:  # Positive correlation
            if param == 'packet_rate' and target in ['pps', 'effectiveness']:
                recommendations.extend([
                    f"Increase {param} to improve {target}",
                    "Monitor system limits to avoid bottlenecks",
                    "Consider gradual increases to find optimal point"
                ])
            elif param == 'thread_count' and target in ['pps', 'effectiveness']:
                recommendations.extend([
                    f"Increase {param} to improve {target}",
                    "Monitor CPU usage to avoid oversubscription",
                    "Consider CPU affinity for thread optimization"
                ])
        else:  # Negative correlation
            if param == 'packet_size' and target == 'success_rate':
                recommendations.extend([
                    "Consider reducing packet size to improve success rate",
                    "Large packets may trigger defense mechanisms",
                    "Test different packet size ranges"
                ])
        
        return recommendations
    
    def _detect_rate_limiting(self) -> Optional[AttackInsight]:
        """Detect rate limiting patterns"""
        try:
            # Look for sudden drops in success rate or PPS
            recent_data = list(self.attack_history)[-50:]  # Last 50 data points
            
            if len(recent_data) < 20:
                return None
            
            success_rates = [d.get('success_rate', 0) for d in recent_data]
            
            # Check for sudden drops
            for i in range(5, len(success_rates)):
                before_avg = statistics.mean(success_rates[i-5:i])
                after_avg = statistics.mean(success_rates[i:i+5]) if i+5 <= len(success_rates) else statistics.mean(success_rates[i:])
                
                if before_avg > 0.8 and after_avg < 0.5:  # Significant drop
                    return AttackInsight(
                        insight_type=InsightType.DEFENSE_DETECTION,
                        title="Rate Limiting Detected",
                        description=f"Sudden drop in success rate from {before_avg:.1%} to {after_avg:.1%} "
                                   f"suggests rate limiting implementation.",
                        severity=InsightSeverity.HIGH,
                        confidence=0.8,
                        impact_score=85.0,
                        recommendations=[
                            "Implement IP rotation or spoofing",
                            "Reduce packet rate to stay under limits",
                            "Use distributed attack sources",
                            "Vary timing patterns to avoid detection"
                        ],
                        supporting_data={
                            'before_success_rate': before_avg,
                            'after_success_rate': after_avg,
                            'drop_magnitude': before_avg - after_avg
                        }
                    )
        except Exception as e:
            self.logger.error(f"Error detecting rate limiting: {e}")
        
        return None
    
    def _detect_waf_behavior(self) -> Optional[AttackInsight]:
        """Detect WAF (Web Application Firewall) behavior"""
        try:
            # Look for patterns in HTTP-based attacks
            http_data = [d for d in self.attack_history if d.get('config', {}).get('protocol') == 'HTTP']
            
            if len(http_data) < self.min_samples_for_pattern:
                return None
            
            # Check for consistent low success rates with HTTP
            success_rates = [d.get('success_rate', 0) for d in http_data]
            avg_success = statistics.mean(success_rates)
            
            if avg_success < 0.3:  # Consistently low success rate
                return AttackInsight(
                    insight_type=InsightType.DEFENSE_DETECTION,
                    title="Potential WAF Detection",
                    description=f"HTTP attacks show consistently low success rate ({avg_success:.1%}), "
                               f"suggesting WAF or application-layer filtering.",
                    severity=InsightSeverity.HIGH,
                    confidence=0.7,
                    impact_score=75.0,
                    recommendations=[
                        "Try different HTTP methods and headers",
                        "Implement request obfuscation techniques",
                        "Use legitimate-looking HTTP payloads",
                        "Consider switching to lower-layer protocols"
                    ],
                    supporting_data={
                        'avg_success_rate': avg_success,
                        'http_samples': len(http_data)
                    }
                )
        except Exception as e:
            self.logger.error(f"Error detecting WAF behavior: {e}")
        
        return None
    
    def _detect_ddos_protection(self) -> Optional[AttackInsight]:
        """Detect DDoS protection mechanisms"""
        try:
            # Look for patterns indicating DDoS protection
            pps_values = [d.get('pps', 0) for d in self.attack_history]
            
            if len(pps_values) < self.min_samples_for_pattern:
                return None
            
            # Check for PPS ceiling (consistent maximum despite increased attempts)
            max_pps = max(pps_values)
            recent_max = max(pps_values[-20:]) if len(pps_values) >= 20 else max_pps
            
            # If recent max is significantly lower than historical max
            if max_pps > 0 and recent_max < max_pps * 0.7:
                return AttackInsight(
                    insight_type=InsightType.DEFENSE_DETECTION,
                    title="DDoS Protection Detected",
                    description=f"Maximum PPS has decreased from {max_pps:.0f} to {recent_max:.0f}, "
                               f"suggesting DDoS protection activation.",
                    severity=InsightSeverity.HIGH,
                    confidence=0.75,
                    impact_score=80.0,
                    recommendations=[
                        "Implement distributed attack coordination",
                        "Use IP spoofing and rotation",
                        "Vary attack patterns and timing",
                        "Consider lower-intensity, longer-duration attacks"
                    ],
                    supporting_data={
                        'historical_max_pps': max_pps,
                        'recent_max_pps': recent_max,
                        'reduction_percentage': (1 - recent_max / max_pps) * 100
                    }
                )
        except Exception as e:
            self.logger.error(f"Error detecting DDoS protection: {e}")
        
        return None
    
    def _find_suboptimal_configurations(self) -> List[AttackInsight]:
        """Find suboptimal parameter configurations"""
        insights = []
        
        try:
            # Group configurations by similarity and compare effectiveness
            config_groups = defaultdict(list)
            
            for data in self.attack_history:
                if 'config' not in data:
                    continue
                
                config = data['config']
                # Create a key based on rounded parameter values
                key = (
                    round(config.get('packet_rate', 0), -2),  # Round to nearest 100
                    round(config.get('packet_size', 0), -1),  # Round to nearest 10
                    config.get('thread_count', 0)
                )
                
                effectiveness = data.get('pps', 0) * data.get('success_rate', 0)
                config_groups[key].append({
                    'effectiveness': effectiveness,
                    'data': data
                })
            
            # Find configurations with consistently low effectiveness
            for config_key, group_data in config_groups.items():
                if len(group_data) >= 5:  # Need sufficient samples
                    avg_effectiveness = statistics.mean([d['effectiveness'] for d in group_data])
                    
                    # Compare with overall average
                    all_effectiveness = [d.get('pps', 0) * d.get('success_rate', 0) for d in self.attack_history]
                    overall_avg = statistics.mean(all_effectiveness) if all_effectiveness else 0
                    
                    if overall_avg > 0 and avg_effectiveness < overall_avg * 0.7:  # 30% below average
                        packet_rate, packet_size, thread_count = config_key
                        
                        insight = AttackInsight(
                            insight_type=InsightType.OPTIMIZATION_OPPORTUNITY,
                            title="Suboptimal Configuration Detected",
                            description=f"Configuration (rate={packet_rate}, size={packet_size}, "
                                       f"threads={thread_count}) shows {avg_effectiveness:.0f} effectiveness "
                                       f"vs {overall_avg:.0f} average.",
                            severity=InsightSeverity.MEDIUM,
                            confidence=0.7,
                            impact_score=60.0,
                            recommendations=[
                                "Try increasing packet rate if CPU allows",
                                "Experiment with different packet sizes",
                                "Adjust thread count based on CPU cores",
                                "Test alternative parameter combinations"
                            ],
                            supporting_data={
                                'config': {
                                    'packet_rate': packet_rate,
                                    'packet_size': packet_size,
                                    'thread_count': thread_count
                                },
                                'avg_effectiveness': avg_effectiveness,
                                'overall_avg_effectiveness': overall_avg,
                                'sample_count': len(group_data)
                            }
                        )
                        insights.append(insight)
                        
        except Exception as e:
            self.logger.error(f"Error finding suboptimal configurations: {e}")
        
        return insights
    
    def get_insights_summary(self) -> Dict[str, Any]:
        """Get a summary of all generated insights"""
        try:
            if not self.insights_cache:
                return {
                    'total_insights': 0,
                    'by_type': {},
                    'by_severity': {},
                    'avg_confidence': 0.0,
                    'avg_impact': 0.0
                }
            
            insights = list(self.insights_cache)
            
            # Count by type
            by_type = defaultdict(int)
            for insight in insights:
                by_type[insight.insight_type.name] += 1
            
            # Count by severity
            by_severity = defaultdict(int)
            for insight in insights:
                by_severity[insight.severity.value] += 1
            
            # Calculate averages
            avg_confidence = statistics.mean([i.confidence for i in insights])
            avg_impact = statistics.mean([i.impact_score for i in insights])
            
            return {
                'total_insights': len(insights),
                'by_type': dict(by_type),
                'by_severity': dict(by_severity),
                'avg_confidence': avg_confidence,
                'avg_impact': avg_impact,
                'data_points_analyzed': len(self.attack_history)
            }
            
        except Exception as e:
            self.logger.error(f"Error generating insights summary: {e}")
            return {}
    
    def export_insights(self, format_type: str = 'json') -> str:
        """Export insights in specified format"""
        try:
            insights_data = [insight.to_dict() for insight in self.insights_cache]
            
            if format_type.lower() == 'json':
                return json.dumps({
                    'insights': insights_data,
                    'summary': self.get_insights_summary(),
                    'generated_at': datetime.now().isoformat()
                }, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
        except Exception as e:
            self.logger.error(f"Error exporting insights: {e}")
            return ""


# Example usage and integration
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create insights generator
    insights_gen = AttackInsightsGenerator()
    
    # Simulate attack data
    import random
    from datetime import datetime, timedelta
    
    base_time = datetime.now() - timedelta(hours=2)
    
    for i in range(100):
        # Simulate varying attack performance
        timestamp = base_time + timedelta(minutes=i)
        
        attack_data = {
            'timestamp': timestamp,
            'pps': random.uniform(5000, 15000) * (0.9 + 0.2 * random.random()),  # Some trend
            'success_rate': max(0.1, random.uniform(0.6, 0.95) - i * 0.002),  # Declining trend
            'cpu_usage': random.uniform(0.3, 0.8),
            'memory_usage': random.uniform(0.2, 0.6),
            'response_time': random.uniform(0.01, 0.1) + i * 0.0005,  # Increasing trend
            'config': {
                'packet_rate': random.choice([1000, 5000, 10000]),
                'packet_size': random.choice([64, 512, 1024, 1500]),
                'thread_count': random.choice([2, 4, 8]),
                'protocol': random.choice(['UDP', 'TCP', 'HTTP'])
            }
        }
        
        insights_gen.add_attack_data(attack_data)
    
    # Generate insights
    insights = insights_gen.generate_insights(min_confidence=0.6)
    
    print(f"\nGenerated {len(insights)} insights:")
    print("=" * 50)
    
    for insight in insights[:5]:  # Show top 5
        print(f"\n{insight.title}")
        print(f"Type: {insight.insight_type.name}")
        print(f"Severity: {insight.severity.value}")
        print(f"Confidence: {insight.confidence:.2f}")
        print(f"Impact: {insight.impact_score:.1f}")
        print(f"Description: {insight.description}")
        print("Recommendations:")
        for rec in insight.recommendations:
            print(f"  • {rec}")
    
    # Show summary
    summary = insights_gen.get_insights_summary()
    print(f"\n\nInsights Summary:")
    print(f"Total insights: {summary['total_insights']}")
    print(f"Average confidence: {summary['avg_confidence']:.2f}")
    print(f"Average impact: {summary['avg_impact']:.1f}")
    print(f"Data points analyzed: {summary['data_points_analyzed']}")