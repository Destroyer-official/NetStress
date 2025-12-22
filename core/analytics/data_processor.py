#!/usr/bin/env python3
"""
Real-Time Data Processing and Aggregation Engine

This module provides high-performance real-time data processing capabilities
for the analytics system, including stream processing, aggregation, and
multi-dimensional analysis.
"""

import asyncio
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
import multiprocessing
import logging
import statistics
import numpy as np
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

@dataclass
class ProcessingRule:
    """Rule for processing incoming data streams"""
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    processor: Callable[[Dict[str, Any]], Dict[str, Any]]
    priority: int = 0
    enabled: bool = True

@dataclass
class StreamWindow:
    """Time-based window for stream processing"""
    size_seconds: int
    slide_seconds: int
    data_points: deque = field(default_factory=deque)
    last_processed: float = 0.0

class RealTimeDataProcessor:
    """High-performance real-time data processing engine"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or multiprocessing.cpu_count()
        
        # Processing pipelines
        self.processing_rules = []
        self.stream_windows = {}
        self.aggregation_functions = {}
        
        # Data streams
        self.input_queues = defaultdict(lambda: asyncio.Queue(maxsize=10000))
        self.output_queues = defaultdict(lambda: asyncio.Queue(maxsize=10000))
        
        # Processing state
        self.running = False
        self.processor_tasks = []
        self.aggregator_tasks = []
        
        # Performance metrics
        self.processed_count = multiprocessing.Value('L', 0)
        self.processing_rate = multiprocessing.Value('d', 0.0)
        self.last_rate_update = time.time()
        
        # Error handling
        self.error_count = multiprocessing.Value('L', 0)
        self.error_handlers = {}
        
    def add_processing_rule(self, rule: ProcessingRule):
        """Add a new processing rule"""
        self.processing_rules.append(rule)
        self.processing_rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info(f"Added processing rule: {rule.name}")
    
    def create_stream_window(self, name: str, size_seconds: int, 
                           slide_seconds: int = None):
        """Create a new stream processing window"""
        if slide_seconds is None:
            slide_seconds = size_seconds // 4  # Default 25% overlap
        
        self.stream_windows[name] = StreamWindow(
            size_seconds=size_seconds,
            slide_seconds=slide_seconds
        )
        logger.info(f"Created stream window: {name} ({size_seconds}s)")
    
    def register_aggregation_function(self, name: str, 
                                    func: Callable[[List[Any]], Any]):
        """Register a custom aggregation function"""
        self.aggregation_functions[name] = func
        logger.info(f"Registered aggregation function: {name}")
    
    async def process_data_point(self, stream_name: str, data: Dict[str, Any]):
        """Process a single data point through the pipeline"""
        try:
            # Add timestamp if not present
            if 'timestamp' not in data:
                data['timestamp'] = time.time()
            
            # Apply processing rules
            processed_data = data.copy()
            for rule in self.processing_rules:
                if rule.enabled and rule.condition(processed_data):
                    try:
                        processed_data = rule.processor(processed_data)
                    except Exception as e:
                        logger.error(f"Error in processing rule {rule.name}: {e}")
                        with self.error_count.get_lock():
                            self.error_count.value += 1
            
            # Add to stream windows
            for window_name, window in self.stream_windows.items():
                if stream_name in window_name or window_name == 'all':
                    window.data_points.append(processed_data)
                    
                    # Remove old data points
                    cutoff_time = time.time() - window.size_seconds
                    while (window.data_points and 
                           window.data_points[0]['timestamp'] < cutoff_time):
                        window.data_points.popleft()
            
            # Send to output queue
            await self.output_queues[stream_name].put(processed_data)
            
            # Update processing statistics
            with self.processed_count.get_lock():
                self.processed_count.value += 1
            
        except Exception as e:
            logger.error(f"Error processing data point: {e}")
            with self.error_count.get_lock():
                self.error_count.value += 1
    
    async def stream_processor(self, stream_name: str):
        """Background task to process a specific data stream"""
        while self.running:
            try:
                # Get data from input queue
                data = await asyncio.wait_for(
                    self.input_queues[stream_name].get(), 
                    timeout=1.0
                )
                
                await self.process_data_point(stream_name, data)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in stream processor {stream_name}: {e}")
                await asyncio.sleep(0.1)
    
    async def window_aggregator(self, window_name: str):
        """Background task to perform window aggregations"""
        window = self.stream_windows[window_name]
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if it's time to process the window
                if current_time - window.last_processed >= window.slide_seconds:
                    await self.process_window(window_name, window)
                    window.last_processed = current_time
                
                await asyncio.sleep(min(1.0, window.slide_seconds / 4))
                
            except Exception as e:
                logger.error(f"Error in window aggregator {window_name}: {e}")
                await asyncio.sleep(1.0)
    
    async def process_window(self, window_name: str, window: StreamWindow):
        """Process a complete window of data"""
        if not window.data_points:
            return
        
        try:
            # Convert to list for processing
            data_points = list(window.data_points)
            
            # Perform basic aggregations
            aggregations = await self.compute_window_aggregations(data_points)
            
            # Create window summary
            window_summary = {
                'window_name': window_name,
                'timestamp': time.time(),
                'window_size_seconds': window.size_seconds,
                'data_point_count': len(data_points),
                'aggregations': aggregations,
                'time_range': {
                    'start': min(p['timestamp'] for p in data_points),
                    'end': max(p['timestamp'] for p in data_points)
                }
            }
            
            # Send to output
            await self.output_queues[f"{window_name}_aggregated"].put(window_summary)
            
            logger.debug(f"Processed window {window_name}: {len(data_points)} points")
            
        except Exception as e:
            logger.error(f"Error processing window {window_name}: {e}")
    
    async def compute_window_aggregations(self, data_points: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute aggregations for a window of data points"""
        aggregations = {}
        
        # Group numeric fields
        numeric_fields = defaultdict(list)
        categorical_fields = defaultdict(list)
        
        for point in data_points:
            for key, value in point.items():
                if key == 'timestamp':
                    continue
                
                if isinstance(value, (int, float)):
                    numeric_fields[key].append(value)
                else:
                    categorical_fields[key].append(str(value))
        
        # Compute numeric aggregations
        for field, values in numeric_fields.items():
            if values:
                aggregations[field] = {
                    'count': len(values),
                    'sum': sum(values),
                    'min': min(values),
                    'max': max(values),
                    'avg': statistics.mean(values),
                    'median': statistics.median(values),
                    'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
                    'percentiles': {
                        'p25': np.percentile(values, 25),
                        'p50': np.percentile(values, 50),
                        'p75': np.percentile(values, 75),
                        'p90': np.percentile(values, 90),
                        'p95': np.percentile(values, 95),
                        'p99': np.percentile(values, 99)
                    }
                }
        
        # Compute categorical aggregations
        for field, values in categorical_fields.items():
            if values:
                value_counts = defaultdict(int)
                for value in values:
                    value_counts[value] += 1
                
                aggregations[f"{field}_categories"] = {
                    'unique_count': len(value_counts),
                    'total_count': len(values),
                    'top_values': sorted(value_counts.items(), 
                                       key=lambda x: x[1], reverse=True)[:10]
                }
        
        # Apply custom aggregation functions
        for func_name, func in self.aggregation_functions.items():
            try:
                aggregations[f"custom_{func_name}"] = func(data_points)
            except Exception as e:
                logger.error(f"Error in custom aggregation {func_name}: {e}")
        
        return aggregations
    
    def add_error_handler(self, error_type: type, handler: Callable):
        """Add a custom error handler"""
        self.error_handlers[error_type] = handler
    
    async def submit_data(self, stream_name: str, data: Dict[str, Any]):
        """Submit data to a processing stream"""
        try:
            await self.input_queues[stream_name].put(data)
        except asyncio.QueueFull:
            logger.warning(f"Input queue full for stream {stream_name}")
            # Try to make space by removing oldest item
            try:
                self.input_queues[stream_name].get_nowait()
                await self.input_queues[stream_name].put(data)
            except asyncio.QueueEmpty:
                pass
    
    async def get_processed_data(self, stream_name: str, 
                               timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Get processed data from an output stream"""
        try:
            return await asyncio.wait_for(
                self.output_queues[stream_name].get(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            return None
    
    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing performance statistics"""
        current_time = time.time()
        
        # Update processing rate
        elapsed = current_time - self.last_rate_update
        if elapsed >= 1.0:
            with self.processed_count.get_lock():
                count = self.processed_count.value
            
            with self.processing_rate.get_lock():
                self.processing_rate.value = count / elapsed if elapsed > 0 else 0
            
            self.last_rate_update = current_time
        
        return {
            'processed_count': self.processed_count.value,
            'processing_rate': self.processing_rate.value,
            'error_count': self.error_count.value,
            'active_streams': len(self.input_queues),
            'active_windows': len(self.stream_windows),
            'queue_sizes': {
                name: queue.qsize() 
                for name, queue in self.input_queues.items()
            }
        }
    
    async def start(self):
        """Start the data processing system"""
        if self.running:
            logger.warning("Data processor already running")
            return
        
        self.running = True
        logger.info("Starting real-time data processing system")
        
        # Start stream processors
        stream_names = ['performance', 'network', 'attack', 'system']
        for stream_name in stream_names:
            task = asyncio.create_task(self.stream_processor(stream_name))
            self.processor_tasks.append(task)
        
        # Start window aggregators
        for window_name in self.stream_windows.keys():
            task = asyncio.create_task(self.window_aggregator(window_name))
            self.aggregator_tasks.append(task)
        
        logger.info(f"Started {len(self.processor_tasks)} stream processors and "
                   f"{len(self.aggregator_tasks)} window aggregators")
    
    async def stop(self):
        """Stop the data processing system"""
        if not self.running:
            return
        
        logger.info("Stopping real-time data processing system")
        self.running = False
        
        # Cancel all tasks
        all_tasks = self.processor_tasks + self.aggregator_tasks
        for task in all_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if all_tasks:
            await asyncio.gather(*all_tasks, return_exceptions=True)
        
        self.processor_tasks.clear()
        self.aggregator_tasks.clear()
        
        logger.info("Real-time data processing system stopped")

# Predefined processing rules
def create_attack_metrics_rule() -> ProcessingRule:
    """Create a processing rule for attack metrics"""
    def condition(data: Dict[str, Any]) -> bool:
        return 'pps' in data or 'packets_sent' in data
    
    def processor(data: Dict[str, Any]) -> Dict[str, Any]:
        # Enhance attack data with derived metrics
        processed = data.copy()
        
        if 'pps' in data and 'packet_size' in data:
            processed['bps'] = data['pps'] * data.get('packet_size', 1024)
        
        if 'errors' in data and 'packets_sent' in data:
            total_packets = data['packets_sent']
            if total_packets > 0:
                processed['error_rate'] = data['errors'] / total_packets
            else:
                processed['error_rate'] = 0.0
        
        # Add performance classification
        pps = data.get('pps', 0)
        if pps > 100000:
            processed['performance_class'] = 'high'
        elif pps > 10000:
            processed['performance_class'] = 'medium'
        else:
            processed['performance_class'] = 'low'
        
        return processed
    
    return ProcessingRule(
        name="attack_metrics_enhancement",
        condition=condition,
        processor=processor,
        priority=10
    )

def create_anomaly_detection_rule() -> ProcessingRule:
    """Create a processing rule for anomaly detection"""
    def condition(data: Dict[str, Any]) -> bool:
        return isinstance(data.get('value'), (int, float))
    
    def processor(data: Dict[str, Any]) -> Dict[str, Any]:
        # Simple anomaly detection based on value ranges
        processed = data.copy()
        value = data.get('value', 0)
        
        # Define normal ranges for different metrics
        normal_ranges = {
            'cpu_usage_percent': (0, 90),
            'memory_usage_percent': (0, 85),
            'error_rate': (0, 0.05),
            'pps': (0, 1000000)
        }
        
        metric_name = data.get('metric_name', '')
        if metric_name in normal_ranges:
            min_val, max_val = normal_ranges[metric_name]
            if value < min_val or value > max_val:
                processed['anomaly'] = True
                processed['anomaly_type'] = 'out_of_range'
                processed['expected_range'] = normal_ranges[metric_name]
            else:
                processed['anomaly'] = False
        
        return processed
    
    return ProcessingRule(
        name="anomaly_detection",
        condition=condition,
        processor=processor,
        priority=5
    )

# Global data processor instance
_global_processor = None

def get_data_processor() -> RealTimeDataProcessor:
    """Get the global data processor instance"""
    global _global_processor
    if _global_processor is None:
        _global_processor = RealTimeDataProcessor()
        
        # Add default processing rules
        _global_processor.add_processing_rule(create_attack_metrics_rule())
        _global_processor.add_processing_rule(create_anomaly_detection_rule())
        
        # Create default windows
        _global_processor.create_stream_window('attack_1min', 60, 15)
        _global_processor.create_stream_window('performance_5min', 300, 60)
        _global_processor.create_stream_window('network_30sec', 30, 10)
    
    return _global_processor