"""Real-time analytics and metrics collection."""

from .metrics_collector import (
    RealTimeMetricsCollector,
    MetricAggregator,
    MetricPoint,
    AggregatedMetric,
    get_metrics_collector,
    collect_metric,
    collect_attack_metrics,
)
from .native_stats_bridge import (
    NativeStatsBridge,
    NativeStatsSnapshot,
    get_native_stats_bridge,
    register_native_engine,
    unregister_native_engine,
    start_native_stats_collection,
    stop_native_stats_collection,
)
from .performance_tracker import MultiDimensionalPerformanceTracker as PerformanceTracker
from .visualization_engine import AdvancedVisualizationEngine as VisualizationEngine
from .predictive_analytics import PredictiveAnalyticsSystem as PredictiveAnalytics

MetricsCollector = RealTimeMetricsCollector

__all__ = [
    "RealTimeMetricsCollector",
    "MetricsCollector",
    "MetricAggregator",
    "MetricPoint",
    "AggregatedMetric",
    "get_metrics_collector",
    "collect_metric",
    "collect_attack_metrics",
    "PerformanceTracker",
    "VisualizationEngine",
    "PredictiveAnalytics",
    "NativeStatsBridge",
    "NativeStatsSnapshot",
    "get_native_stats_bridge",
    "register_native_engine",
    "unregister_native_engine",
    "start_native_stats_collection",
    "stop_native_stats_collection",
]
