#!/usr/bin/env python3
"""
High-Performance Real-Time Metrics Collection System

This module implements a high-performance metrics collection system for real-time
monitoring of DDoS attack operations. It provides multi-dimensional performance
tracking with minimal overhead.
"""

import asyncio
import time
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union
import multiprocessing
import ctypes
import json
import logging
from datetime import datetime, timedelta
import statistics
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class MetricPoint:
    """Individual metric data point"""
    timestamp: float
    value: Union[int, float]
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AggregatedMetric:
    """Aggregated metric with statistical information"""
    name: str
    count: int
    sum_value: float
    min_value: float
    max_value: float
    avg_value: float
    std_dev: float
    percentiles: Dict[str, float]
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)

class LockFreeMetricBuffer:
    """Lock-free circular buffer for high-performance metric storage"""
    
    def __init__(self, size: int = 10000):
        self.size = size
        self.buffer = multiprocessing.Array(ctypes.c_double, size * 3)  # timestamp, value, hash
        self.write_index = multiprocessing.Value(ctypes.c_ulonglong, 0)
        self.read_index = multiprocessing.Value(ctypes.c_ulonglong, 0)
        
    def write(self, timestamp: float, value: float, tag_hash: int = 0):
        """Write a metric point to the buffer"""
        with self.write_index.get_lock():
            idx = self.write_index.value % self.size
            base_idx = idx * 3
            
            self.buffer[base_idx] = timestamp
            self.buffer[base_idx + 1] = value
            self.buffer[base_idx + 2] = float(tag_hash)
            
            self.write_index.value += 1
    
    def read_batch(self, batch_size: int = 1000) -> List[tuple]:
        """Read a batch of metric points"""
        points = []
        with self.read_index.get_lock():
            current_write = self.write_index.value
            available = min(batch_size, current_write - self.read_index.value)
            
            for _ in range(available):
                idx = self.read_index.value % self.size
                base_idx = idx * 3
                
                timestamp = self.buffer[base_idx]
                value = self.buffer[base_idx + 1]
                tag_hash = int(self.buffer[base_idx + 2])
                
                points.append((timestamp, value, tag_hash))
                self.read_index.value += 1
        
        return points

class MetricAggregator:
    """High-performance metric aggregation engine"""
    
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.metric_windows = defaultdict(lambda: deque(maxlen=window_size * 10))
        self.aggregation_cache = {}
        self.cache_ttl = 1.0  # Cache for 1 second
        self.last_aggregation = {}
        
    def add_point(self, metric_name: str, point: MetricPoint):
        """Add a metric point for aggregation"""
        self.metric_windows[metric_name].append(point)
        
        # Invalidate cache for this metric
        if metric_name in self.aggregation_cache:
            del self.aggregation_cache[metric_name]
    
    def get_aggregated_metric(self, metric_name: str, 
                            window_seconds: int = 60) -> Optional[AggregatedMetric]:
        """Get aggregated metric for the specified time window"""
        cache_key = f"{metric_name}_{window_seconds}"
        current_time = time.time()
        
        # Check cache
        if (cache_key in self.aggregation_cache and 
            current_time - self.last_aggregation.get(cache_key, 0) < self.cache_ttl):
            return self.aggregation_cache[cache_key]
        
        # Get points within window
        cutoff_time = current_time - window_seconds
        points = [p for p in self.metric_windows[metric_name] 
                 if p.timestamp >= cutoff_time]
        
        if not points:
            return None
        
        # Calculate aggregations
        values = [p.value for p in points]
        
        aggregated = AggregatedMetric(
            name=metric_name,
            count=len(values),
            sum_value=sum(values),
            min_value=min(values),
            max_value=max(values),
            avg_value=statistics.mean(values),
            std_dev=statistics.stdev(values) if len(values) > 1 else 0.0,
            percentiles={
                'p50': np.percentile(values, 50),
                'p90': np.percentile(values, 90),
                'p95': np.percentile(values, 95),
                'p99': np.percentile(values, 99)
            },
            timestamp=current_time,
            tags=points[0].tags if points else {}
        )
        
        # Cache result
        self.aggregation_cache[cache_key] = aggregated
        self.last_aggregation[cache_key] = current_time
        
        return aggregated

class RealTimeMetricsCollector:
    """Main real-time metrics collection system"""
    
    def __init__(self, buffer_size: int = 100000, 
                 collection_interval: float = 0.1):
        self.buffer_size = buffer_size
        self.collection_interval = collection_interval
        
        # Metric buffers for different categories
        self.buffers = {
            'performance': LockFreeMetricBuffer(buffer_size),
            'network': LockFreeMetricBuffer(buffer_size),
            'attack': LockFreeMetricBuffer(buffer_size),
            'system': LockFreeMetricBuffer(buffer_size)
        }
        
        # Aggregators
        self.aggregators = {
            category: MetricAggregator() for category in self.buffers.keys()
        }
        
        # Metric registry
        self.metric_registry = {}
        self.custom_collectors = {}
        
        # Processing state
        self.running = False
        self.processor_task = None
        self.collection_tasks = []
        
        # Statistics
        self.total_metrics_collected = multiprocessing.Value(ctypes.c_ulonglong, 0)
        self.metrics_per_second = multiprocessing.Value(ctypes.c_double, 0.0)
        self.last_stats_update = time.time()
        
    def register_metric(self, name: str, category: str = 'performance',
                       collector_func: Optional[Callable] = None,
                       tags: Dict[str, str] = None):
        """Register a new metric for collection"""
        self.metric_registry[name] = {
            'category': category,
            'collector': collector_func,
            'tags': tags or {},
            'last_collected': 0.0
        }
        logger.debug(f"Registered metric: {name} in category: {category}")
    
    def collect_metric(self, name: str, value: Union[int, float],
                      category: str = 'performance',
                      tags: Dict[str, str] = None,
                      metadata: Dict[str, Any] = None):
        """Collect a single metric point"""
        timestamp = time.time()
        
        # Create metric point
        point = MetricPoint(
            timestamp=timestamp,
            value=float(value),
            tags=tags or {},
            metadata=metadata or {}
        )
        
        # Add to buffer
        if category in self.buffers:
            tag_hash = hash(str(sorted((tags or {}).items())))
            self.buffers[category].write(timestamp, float(value), tag_hash)
            
            # Add to aggregator
            self.aggregators[category].add_point(name, point)
        
        # Update statistics
        with self.total_metrics_collected.get_lock():
            self.total_metrics_collected.value += 1
    
    def collect_performance_metrics(self):
        """Collect system performance metrics"""
        try:
            import psutil
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            self.collect_metric('cpu_usage_percent', cpu_percent, 'performance')
            
            # Memory metrics
            memory = psutil.virtual_memory()
            self.collect_metric('memory_usage_percent', memory.percent, 'performance')
            self.collect_metric('memory_available_bytes', memory.available, 'performance')
            
            # Network metrics
            net_io = psutil.net_io_counters()
            self.collect_metric('network_bytes_sent', net_io.bytes_sent, 'network')
            self.collect_metric('network_bytes_recv', net_io.bytes_recv, 'network')
            self.collect_metric('network_packets_sent', net_io.packets_sent, 'network')
            self.collect_metric('network_packets_recv', net_io.packets_recv, 'network')
            
        except ImportError:
            logger.warning("psutil not available, skipping system metrics")
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
    
    def collect_attack_metrics(self, stats_dict: Dict[str, Any]):
        """Collect attack-specific metrics from stats dictionary"""
        timestamp = time.time()
        
        # Core attack metrics
        attack_metrics = {
            'packets_per_second': stats_dict.get('pps', 0),
            'bytes_per_second': stats_dict.get('bps', 0),
            'connections_per_second': stats_dict.get('conn_rate', 0),
            'error_rate': stats_dict.get('errors', 0),
            'total_packets_sent': stats_dict.get('packets_sent', 0),
            'total_bytes_sent': stats_dict.get('bytes_sent', 0)
        }
        
        for metric_name, value in attack_metrics.items():
            self.collect_metric(metric_name, value, 'attack')
        
        # Protocol-specific metrics
        protocol_metrics = {
            'tcp_syn_pps': stats_dict.get('tcp_syn_pps', 0),
            'tcp_ack_pps': stats_dict.get('tcp_ack_pps', 0),
            'udp_pps': stats_dict.get('udp_pps', 0),
            'http_rps': stats_dict.get('http_rps', 0),
            'dns_qps': stats_dict.get('dns_qps', 0),
            'icmp_pps': stats_dict.get('icmp_pps', 0)
        }
        
        for metric_name, value in protocol_metrics.items():
            self.collect_metric(metric_name, value, 'attack',
                              tags={'protocol': metric_name.split('_')[0].upper()})
    
    async def process_metrics(self):
        """Background task to process collected metrics"""
        while self.running:
            try:
                # Process each buffer
                for category, buffer in self.buffers.items():
                    points = buffer.read_batch(1000)
                    
                    if points:
                        logger.debug(f"Processed {len(points)} {category} metrics")
                
                # Update metrics per second
                current_time = time.time()
                if current_time - self.last_stats_update >= 1.0:
                    with self.total_metrics_collected.get_lock():
                        total = self.total_metrics_collected.value
                    
                    elapsed = current_time - self.last_stats_update
                    with self.metrics_per_second.get_lock():
                        self.metrics_per_second.value = total / elapsed if elapsed > 0 else 0
                    
                    self.last_stats_update = current_time
                
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                logger.error(f"Error processing metrics: {e}")
                await asyncio.sleep(1.0)
    
    async def collect_system_metrics(self):
        """Background task to collect system metrics"""
        while self.running:
            try:
                self.collect_performance_metrics()
                
                # Collect custom metrics
                for name, config in self.metric_registry.items():
                    if config['collector']:
                        try:
                            value = config['collector']()
                            self.collect_metric(name, value, config['category'],
                                              tags=config['tags'])
                        except Exception as e:
                            logger.error(f"Error collecting custom metric {name}: {e}")
                
                await asyncio.sleep(1.0)  # Collect system metrics every second
                
            except Exception as e:
                logger.error(f"Error in system metrics collection: {e}")
                await asyncio.sleep(5.0)
    
    def get_metrics_summary(self, window_seconds: int = 60) -> Dict[str, Any]:
        """Get a summary of all collected metrics"""
        summary = {
            'timestamp': time.time(),
            'window_seconds': window_seconds,
            'categories': {},
            'collection_stats': {
                'total_metrics_collected': self.total_metrics_collected.value,
                'metrics_per_second': self.metrics_per_second.value
            }
        }
        
        # Get aggregated metrics for each category
        for category, aggregator in self.aggregators.items():
            category_metrics = {}
            
            # Get all unique metric names for this category
            metric_names = set()
            for points in aggregator.metric_windows.values():
                for point in points:
                    # Extract metric name from point metadata or use category
                    metric_names.add(f"{category}_metric")
            
            # For demonstration, we'll use some common metric names
            common_metrics = {
                'performance': ['cpu_usage_percent', 'memory_usage_percent'],
                'network': ['network_bytes_sent', 'network_packets_sent'],
                'attack': ['packets_per_second', 'bytes_per_second', 'error_rate'],
                'system': ['system_load', 'disk_usage']
            }
            
            for metric_name in common_metrics.get(category, []):
                aggregated = aggregator.get_aggregated_metric(metric_name, window_seconds)
                if aggregated:
                    category_metrics[metric_name] = {
                        'count': aggregated.count,
                        'avg': aggregated.avg_value,
                        'min': aggregated.min_value,
                        'max': aggregated.max_value,
                        'std_dev': aggregated.std_dev,
                        'percentiles': aggregated.percentiles
                    }
            
            summary['categories'][category] = category_metrics
        
        return summary
    
    def export_metrics(self, format_type: str = 'json',
                      window_seconds: int = 60) -> str:
        """Export metrics in specified format"""
        summary = self.get_metrics_summary(window_seconds)
        
        if format_type.lower() == 'json':
            return json.dumps(summary, indent=2, default=str)
        elif format_type.lower() == 'prometheus':
            return self._export_prometheus_format(summary)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_prometheus_format(self, summary: Dict[str, Any]) -> str:
        """Export metrics in Prometheus format"""
        lines = []
        timestamp = int(summary['timestamp'] * 1000)  # Prometheus uses milliseconds
        
        for category, metrics in summary['categories'].items():
            for metric_name, data in metrics.items():
                # Average value
                lines.append(f"ddos_{category}_{metric_name}_avg {data['avg']} {timestamp}")
                
                # Min/Max values
                lines.append(f"ddos_{category}_{metric_name}_min {data['min']} {timestamp}")
                lines.append(f"ddos_{category}_{metric_name}_max {data['max']} {timestamp}")
                
                # Percentiles
                for percentile, value in data['percentiles'].items():
                    lines.append(f"ddos_{category}_{metric_name}_{percentile} {value} {timestamp}")
        
        return '\n'.join(lines)
    
    async def start(self):
        """Start the metrics collection system"""
        if self.running:
            logger.warning("Metrics collector already running")
            return
        
        self.running = True
        logger.info("Starting real-time metrics collection system")
        
        # Start background tasks
        self.processor_task = asyncio.create_task(self.process_metrics())
        self.collection_tasks = [
            asyncio.create_task(self.collect_system_metrics())
        ]
        
        logger.info("Real-time metrics collection system started")
    
    async def stop(self):
        """Stop the metrics collection system"""
        if not self.running:
            return
        
        logger.info("Stopping real-time metrics collection system")
        self.running = False
        
        # Cancel tasks
        if self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError:
                pass
        
        for task in self.collection_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        logger.info("Real-time metrics collection system stopped")

# Global metrics collector instance
_global_collector = None

def get_metrics_collector() -> RealTimeMetricsCollector:
    """Get the global metrics collector instance"""
    global _global_collector
    if _global_collector is None:
        _global_collector = RealTimeMetricsCollector()
    return _global_collector

def collect_metric(name: str, value: Union[int, float],
                  category: str = 'performance',
                  tags: Dict[str, str] = None,
                  metadata: Dict[str, Any] = None):
    """Convenience function to collect a metric"""
    collector = get_metrics_collector()
    collector.collect_metric(name, value, category, tags, metadata)

def collect_attack_metrics(stats_dict: Dict[str, Any]):
    """Convenience function to collect attack metrics"""
    collector = get_metrics_collector()
    collector.collect_attack_metrics(stats_dict)