#!/usr/bin/env python3
"""
Multi-Dimensional Performance Tracking System

This module provides comprehensive multi-dimensional performance tracking
capabilities for the DDoS testing framework, including hierarchical metrics,
correlation analysis, and performance profiling.
"""

import asyncio
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
import multiprocessing
import logging
import statistics
import numpy as np
from datetime import datetime, timedelta
import json
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class PerformanceDimension:
    """Represents a single performance dimension"""
    name: str
    category: str
    unit: str
    description: str
    tags: Dict[str, str] = field(default_factory=dict)
    thresholds: Dict[str, float] = field(default_factory=dict)  # warning, critical, etc.

@dataclass
class PerformanceSnapshot:
    """A snapshot of performance metrics at a specific time"""
    timestamp: float
    dimensions: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None

@dataclass
class PerformanceProfile:
    """Performance profile for a specific operation or time period"""
    name: str
    start_time: float
    end_time: float
    snapshots: List[PerformanceSnapshot]
    summary_stats: Dict[str, Any] = field(default_factory=dict)
    correlations: Dict[str, float] = field(default_factory=dict)

class DimensionRegistry:
    """Registry for performance dimensions"""
    
    def __init__(self):
        self.dimensions = {}
        self.categories = defaultdict(list)
        self._register_default_dimensions()
    
    def register_dimension(self, dimension: PerformanceDimension):
        """Register a new performance dimension"""
        self.dimensions[dimension.name] = dimension
        self.categories[dimension.category].append(dimension.name)
        logger.debug(f"Registered dimension: {dimension.name} ({dimension.category})")
    
    def get_dimension(self, name: str) -> Optional[PerformanceDimension]:
        """Get a dimension by name"""
        return self.dimensions.get(name)
    
    def get_dimensions_by_category(self, category: str) -> List[PerformanceDimension]:
        """Get all dimensions in a category"""
        return [self.dimensions[name] for name in self.categories.get(category, [])]
    
    def _register_default_dimensions(self):
        """Register default performance dimensions"""
        # Network performance dimensions
        network_dimensions = [
            PerformanceDimension(
                name="packets_per_second",
                category="network",
                unit="pps",
                description="Packets transmitted per second",
                thresholds={"warning": 50000, "critical": 100000}
            ),
            PerformanceDimension(
                name="bytes_per_second",
                category="network",
                unit="bps",
                description="Bytes transmitted per second",
                thresholds={"warning": 100000000, "critical": 1000000000}  # 100MB/s, 1GB/s
            ),
            PerformanceDimension(
                name="connection_rate",
                category="network",
                unit="cps",
                description="Connections established per second",
                thresholds={"warning": 1000, "critical": 5000}
            ),
            PerformanceDimension(
                name="error_rate",
                category="network",
                unit="percentage",
                description="Network error rate",
                thresholds={"warning": 0.01, "critical": 0.05}  # 1%, 5%
            )
        ]
        
        # System performance dimensions
        system_dimensions = [
            PerformanceDimension(
                name="cpu_usage",
                category="system",
                unit="percentage",
                description="CPU utilization percentage",
                thresholds={"warning": 80, "critical": 95}
            ),
            PerformanceDimension(
                name="memory_usage",
                category="system",
                unit="percentage",
                description="Memory utilization percentage",
                thresholds={"warning": 80, "critical": 90}
            ),
            PerformanceDimension(
                name="disk_io_rate",
                category="system",
                unit="iops",
                description="Disk I/O operations per second",
                thresholds={"warning": 1000, "critical": 5000}
            ),
            PerformanceDimension(
                name="network_io_rate",
                category="system",
                unit="bps",
                description="Network I/O bytes per second",
                thresholds={"warning": 100000000, "critical": 1000000000}
            )
        ]
        
        # Attack performance dimensions
        attack_dimensions = [
            PerformanceDimension(
                name="attack_effectiveness",
                category="attack",
                unit="score",
                description="Overall attack effectiveness score",
                thresholds={"warning": 0.5, "critical": 0.8}
            ),
            PerformanceDimension(
                name="target_response_time",
                category="attack",
                unit="seconds",
                description="Target system response time",
                thresholds={"warning": 1.0, "critical": 5.0}
            ),
            PerformanceDimension(
                name="protocol_efficiency",
                category="attack",
                unit="ratio",
                description="Protocol-specific efficiency ratio",
                thresholds={"warning": 0.7, "critical": 0.9}
            )
        ]
        
        # Register all dimensions
        for dimension in network_dimensions + system_dimensions + attack_dimensions:
            self.register_dimension(dimension)

class CorrelationAnalyzer:
    """Analyzes correlations between performance dimensions"""
    
    def __init__(self, min_samples: int = 10):
        self.min_samples = min_samples
        self.correlation_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.last_cache_update = {}
    
    def calculate_correlation(self, x_values: List[float], 
                            y_values: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        if len(x_values) != len(y_values) or len(x_values) < self.min_samples:
            return 0.0
        
        try:
            return np.corrcoef(x_values, y_values)[0, 1]
        except Exception:
            return 0.0
    
    def analyze_correlations(self, snapshots: List[PerformanceSnapshot]) -> Dict[str, float]:
        """Analyze correlations between all dimension pairs"""
        if len(snapshots) < self.min_samples:
            return {}
        
        # Extract dimension values
        dimension_values = defaultdict(list)
        for snapshot in snapshots:
            for dim_name, value in snapshot.dimensions.items():
                dimension_values[dim_name].append(value)
        
        # Calculate correlations
        correlations = {}
        dimension_names = list(dimension_values.keys())
        
        for i, dim1 in enumerate(dimension_names):
            for dim2 in dimension_names[i+1:]:
                values1 = dimension_values[dim1]
                values2 = dimension_values[dim2]
                
                correlation = self.calculate_correlation(values1, values2)
                if abs(correlation) > 0.1:  # Only store significant correlations
                    correlations[f"{dim1}_vs_{dim2}"] = correlation
        
        return correlations
    
    def find_strong_correlations(self, correlations: Dict[str, float], 
                               threshold: float = 0.7) -> Dict[str, float]:
        """Find correlations above the specified threshold"""
        return {
            pair: corr for pair, corr in correlations.items()
            if abs(corr) >= threshold
        }

class PerformanceProfiler:
    """Profiles performance for specific operations"""
    
    def __init__(self):
        self.active_profiles = {}
        self.completed_profiles = deque(maxlen=1000)
        self.profile_lock = threading.Lock()
    
    def start_profile(self, name: str, metadata: Dict[str, Any] = None) -> str:
        """Start a new performance profile"""
        profile_id = hashlib.md5(f"{name}_{time.time()}".encode()).hexdigest()[:8]
        
        with self.profile_lock:
            self.active_profiles[profile_id] = PerformanceProfile(
                name=name,
                start_time=time.time(),
                end_time=0.0,
                snapshots=[],
                summary_stats={},
                correlations={}
            )
        
        logger.debug(f"Started performance profile: {name} ({profile_id})")
        return profile_id
    
    def add_snapshot(self, profile_id: str, dimensions: Dict[str, float],
                    metadata: Dict[str, Any] = None):
        """Add a performance snapshot to an active profile"""
        with self.profile_lock:
            if profile_id in self.active_profiles:
                snapshot = PerformanceSnapshot(
                    timestamp=time.time(),
                    dimensions=dimensions.copy(),
                    metadata=metadata or {},
                    correlation_id=profile_id
                )
                self.active_profiles[profile_id].snapshots.append(snapshot)
    
    def end_profile(self, profile_id: str) -> Optional[PerformanceProfile]:
        """End a performance profile and return the completed profile"""
        with self.profile_lock:
            if profile_id not in self.active_profiles:
                return None
            
            profile = self.active_profiles.pop(profile_id)
            profile.end_time = time.time()
            
            # Calculate summary statistics
            profile.summary_stats = self._calculate_summary_stats(profile.snapshots)
            
            # Calculate correlations
            analyzer = CorrelationAnalyzer()
            profile.correlations = analyzer.analyze_correlations(profile.snapshots)
            
            self.completed_profiles.append(profile)
            
            logger.debug(f"Completed performance profile: {profile.name} "
                        f"({len(profile.snapshots)} snapshots)")
            
            return profile
    
    def _calculate_summary_stats(self, snapshots: List[PerformanceSnapshot]) -> Dict[str, Any]:
        """Calculate summary statistics for a profile"""
        if not snapshots:
            return {}
        
        # Group values by dimension
        dimension_values = defaultdict(list)
        for snapshot in snapshots:
            for dim_name, value in snapshot.dimensions.items():
                dimension_values[dim_name].append(value)
        
        # Calculate statistics for each dimension
        summary = {}
        for dim_name, values in dimension_values.items():
            if values:
                summary[dim_name] = {
                    'count': len(values),
                    'min': min(values),
                    'max': max(values),
                    'avg': statistics.mean(values),
                    'median': statistics.median(values),
                    'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
                    'percentiles': {
                        'p25': np.percentile(values, 25),
                        'p75': np.percentile(values, 75),
                        'p90': np.percentile(values, 90),
                        'p95': np.percentile(values, 95)
                    }
                }
        
        return summary

class MultiDimensionalPerformanceTracker:
    """Main multi-dimensional performance tracking system"""
    
    def __init__(self, history_size: int = 10000):
        self.history_size = history_size
        
        # Core components
        self.dimension_registry = DimensionRegistry()
        self.correlation_analyzer = CorrelationAnalyzer()
        self.profiler = PerformanceProfiler()
        
        # Data storage
        self.performance_history = deque(maxlen=history_size)
        self.dimension_histories = defaultdict(lambda: deque(maxlen=history_size))
        
        # Real-time tracking
        self.current_snapshot = {}
        self.tracking_enabled = True
        
        # Background tasks
        self.running = False
        self.analysis_task = None
        self.cleanup_task = None
        
        # Performance metrics
        self.snapshots_taken = multiprocessing.Value('L', 0)
        self.analysis_cycles = multiprocessing.Value('L', 0)
        
    def track_dimension(self, name: str, value: float, 
                       tags: Dict[str, str] = None,
                       metadata: Dict[str, Any] = None):
        """Track a single performance dimension"""
        if not self.tracking_enabled:
            return
        
        # Validate dimension
        dimension = self.dimension_registry.get_dimension(name)
        if not dimension:
            logger.warning(f"Unknown dimension: {name}")
            return
        
        # Update current snapshot
        self.current_snapshot[name] = value
        
        # Add to dimension history
        self.dimension_histories[name].append({
            'timestamp': time.time(),
            'value': value,
            'tags': tags or {},
            'metadata': metadata or {}
        })
        
        # Check thresholds
        self._check_thresholds(dimension, value)
    
    def take_snapshot(self, metadata: Dict[str, Any] = None) -> PerformanceSnapshot:
        """Take a complete performance snapshot"""
        snapshot = PerformanceSnapshot(
            timestamp=time.time(),
            dimensions=self.current_snapshot.copy(),
            metadata=metadata or {}
        )
        
        self.performance_history.append(snapshot)
        
        with self.snapshots_taken.get_lock():
            self.snapshots_taken.value += 1
        
        return snapshot
    
    def _check_thresholds(self, dimension: PerformanceDimension, value: float):
        """Check if a value exceeds dimension thresholds"""
        for threshold_name, threshold_value in dimension.thresholds.items():
            if value >= threshold_value:
                logger.warning(f"Dimension {dimension.name} exceeded {threshold_name} "
                             f"threshold: {value} >= {threshold_value}")
    
    def get_dimension_stats(self, dimension_name: str, 
                          window_seconds: int = 300) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific dimension"""
        history = self.dimension_histories.get(dimension_name, [])
        if not history:
            return None
        
        # Filter by time window
        cutoff_time = time.time() - window_seconds
        recent_values = [
            entry['value'] for entry in history
            if entry['timestamp'] >= cutoff_time
        ]
        
        if not recent_values:
            return None
        
        return {
            'count': len(recent_values),
            'min': min(recent_values),
            'max': max(recent_values),
            'avg': statistics.mean(recent_values),
            'median': statistics.median(recent_values),
            'std_dev': statistics.stdev(recent_values) if len(recent_values) > 1 else 0.0,
            'current': recent_values[-1] if recent_values else None,
            'trend': self._calculate_trend(recent_values)
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a series of values"""
        if len(values) < 2:
            return "stable"
        
        # Simple trend calculation using first and last quartiles
        quarter_size = len(values) // 4
        if quarter_size < 1:
            return "stable"
        
        first_quarter_avg = statistics.mean(values[:quarter_size])
        last_quarter_avg = statistics.mean(values[-quarter_size:])
        
        change_percent = (last_quarter_avg - first_quarter_avg) / first_quarter_avg * 100
        
        if change_percent > 5:
            return "increasing"
        elif change_percent < -5:
            return "decreasing"
        else:
            return "stable"
    
    def analyze_performance(self, window_seconds: int = 300) -> Dict[str, Any]:
        """Perform comprehensive performance analysis"""
        cutoff_time = time.time() - window_seconds
        recent_snapshots = [
            snapshot for snapshot in self.performance_history
            if snapshot.timestamp >= cutoff_time
        ]
        
        if not recent_snapshots:
            return {}
        
        # Calculate correlations
        correlations = self.correlation_analyzer.analyze_correlations(recent_snapshots)
        strong_correlations = self.correlation_analyzer.find_strong_correlations(correlations)
        
        # Get dimension statistics
        dimension_stats = {}
        for category, dimension_names in self.dimension_registry.categories.items():
            category_stats = {}
            for dim_name in dimension_names:
                stats = self.get_dimension_stats(dim_name, window_seconds)
                if stats:
                    category_stats[dim_name] = stats
            if category_stats:
                dimension_stats[category] = category_stats
        
        # Performance summary
        analysis = {
            'timestamp': time.time(),
            'window_seconds': window_seconds,
            'snapshot_count': len(recent_snapshots),
            'dimension_stats': dimension_stats,
            'correlations': correlations,
            'strong_correlations': strong_correlations,
            'performance_summary': self._generate_performance_summary(dimension_stats)
        }
        
        with self.analysis_cycles.get_lock():
            self.analysis_cycles.value += 1
        
        return analysis
    
    def _generate_performance_summary(self, dimension_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a high-level performance summary"""
        summary = {
            'overall_health': 'good',
            'bottlenecks': [],
            'recommendations': []
        }
        
        # Check for performance issues
        for category, stats in dimension_stats.items():
            for dim_name, dim_stats in stats.items():
                dimension = self.dimension_registry.get_dimension(dim_name)
                if not dimension:
                    continue
                
                current_value = dim_stats.get('current', 0)
                
                # Check against thresholds
                for threshold_name, threshold_value in dimension.thresholds.items():
                    if current_value >= threshold_value:
                        summary['bottlenecks'].append({
                            'dimension': dim_name,
                            'category': category,
                            'current_value': current_value,
                            'threshold': threshold_value,
                            'severity': threshold_name
                        })
                        
                        if threshold_name == 'critical':
                            summary['overall_health'] = 'critical'
                        elif threshold_name == 'warning' and summary['overall_health'] == 'good':
                            summary['overall_health'] = 'warning'
        
        # Generate recommendations
        if summary['bottlenecks']:
            summary['recommendations'].extend([
                "Monitor resource usage closely",
                "Consider scaling resources if bottlenecks persist",
                "Review attack parameters for optimization opportunities"
            ])
        
        return summary
    
    async def background_analysis(self):
        """Background task for continuous performance analysis"""
        while self.running:
            try:
                # Perform analysis every 30 seconds
                analysis = self.analyze_performance()
                
                # Log significant findings
                if analysis.get('strong_correlations'):
                    logger.info(f"Found {len(analysis['strong_correlations'])} "
                               f"strong performance correlations")
                
                bottlenecks = analysis.get('performance_summary', {}).get('bottlenecks', [])
                if bottlenecks:
                    logger.warning(f"Performance bottlenecks detected: {len(bottlenecks)}")
                
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in background analysis: {e}")
                await asyncio.sleep(60)
    
    async def cleanup_task_func(self):
        """Background task for cleanup operations"""
        while self.running:
            try:
                # Clean up old completed profiles
                current_time = time.time()
                cutoff_time = current_time - 3600  # Keep profiles for 1 hour
                
                profiles_to_remove = []
                for profile in self.profiler.completed_profiles:
                    if profile.end_time < cutoff_time:
                        profiles_to_remove.append(profile)
                
                for profile in profiles_to_remove:
                    self.profiler.completed_profiles.remove(profile)
                
                if profiles_to_remove:
                    logger.debug(f"Cleaned up {len(profiles_to_remove)} old profiles")
                
                await asyncio.sleep(300)  # Run cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(600)
    
    def get_tracking_stats(self) -> Dict[str, Any]:
        """Get performance tracking statistics"""
        return {
            'snapshots_taken': self.snapshots_taken.value,
            'analysis_cycles': self.analysis_cycles.value,
            'active_dimensions': len(self.current_snapshot),
            'total_dimensions': len(self.dimension_registry.dimensions),
            'history_size': len(self.performance_history),
            'active_profiles': len(self.profiler.active_profiles),
            'completed_profiles': len(self.profiler.completed_profiles)
        }
    
    async def start(self):
        """Start the performance tracking system"""
        if self.running:
            logger.warning("Performance tracker already running")
            return
        
        self.running = True
        logger.info("Starting multi-dimensional performance tracking")
        
        # Start background tasks
        self.analysis_task = asyncio.create_task(self.background_analysis())
        self.cleanup_task = asyncio.create_task(self.cleanup_task_func())
        
        logger.info("Multi-dimensional performance tracking started")
    
    async def stop(self):
        """Stop the performance tracking system"""
        if not self.running:
            return
        
        logger.info("Stopping multi-dimensional performance tracking")
        self.running = False
        
        # Cancel background tasks
        if self.analysis_task:
            self.analysis_task.cancel()
            try:
                await self.analysis_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Multi-dimensional performance tracking stopped")

# Global performance tracker instance
_global_tracker = None

def get_performance_tracker() -> MultiDimensionalPerformanceTracker:
    """Get the global performance tracker instance"""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = MultiDimensionalPerformanceTracker()
    return _global_tracker

def track_performance(dimension_name: str, value: float,
                     tags: Dict[str, str] = None,
                     metadata: Dict[str, Any] = None):
    """Convenience function to track performance"""
    tracker = get_performance_tracker()
    tracker.track_dimension(dimension_name, value, tags, metadata)