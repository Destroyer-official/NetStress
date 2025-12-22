"""
Garbage collection optimization for managed components.
Provides GC tuning and memory pressure management for high-performance scenarios.
"""

import gc
import threading
import time
import sys
import weakref
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass
from enum import Enum
import psutil
import os

from .lockfree import LockFreeCounter, AtomicReference, LockFreeStatistics


class GCMode(Enum):
    """Garbage collection modes"""
    AUTOMATIC = "automatic"      # Default Python GC
    MANUAL = "manual"           # Manual GC control
    ADAPTIVE = "adaptive"       # Adaptive based on memory pressure
    DISABLED = "disabled"       # GC disabled for maximum performance


class MemoryPressure(Enum):
    """Memory pressure levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GCStatistics:
    """Garbage collection statistics"""
    collections_count: int = 0
    objects_collected: int = 0
    total_time_ms: float = 0.0
    average_time_ms: float = 0.0
    max_time_ms: float = 0.0
    memory_freed_mb: float = 0.0
    generation_0_collections: int = 0
    generation_1_collections: int = 0
    generation_2_collections: int = 0


@dataclass
class MemoryStats:
    """Memory usage statistics"""
    total_memory_mb: float = 0.0
    available_memory_mb: float = 0.0
    used_memory_mb: float = 0.0
    memory_percent: float = 0.0
    process_memory_mb: float = 0.0
    gc_objects_count: int = 0


class MemoryMonitor:
    """Monitors system and process memory usage"""
    
    def __init__(self, update_interval: float = 1.0):
        self.update_interval = update_interval
        self._stats = AtomicReference(MemoryStats())
        self._running = False
        self._monitor_thread = None
        self._process = psutil.Process()
    
    def start(self):
        """Start memory monitoring"""
        if self._running:
            return
        
        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    
    def stop(self):
        """Stop memory monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
    
    def _monitor_loop(self):
        """Memory monitoring loop"""
        while self._running:
            try:
                self._update_stats()
                time.sleep(self.update_interval)
            except Exception:
                pass
    
    def _update_stats(self):
        """Update memory statistics"""
        try:
            # System memory
            system_memory = psutil.virtual_memory()
            
            # Process memory
            process_memory = self._process.memory_info()
            
            # GC objects
            gc_objects = len(gc.get_objects())
            
            stats = MemoryStats(
                total_memory_mb=system_memory.total / (1024 * 1024),
                available_memory_mb=system_memory.available / (1024 * 1024),
                used_memory_mb=system_memory.used / (1024 * 1024),
                memory_percent=system_memory.percent,
                process_memory_mb=process_memory.rss / (1024 * 1024),
                gc_objects_count=gc_objects
            )
            
            self._stats.set(stats)
            
        except Exception:
            pass
    
    def get_stats(self) -> MemoryStats:
        """Get current memory statistics"""
        return self._stats.get()
    
    def get_memory_pressure(self) -> MemoryPressure:
        """Determine current memory pressure level"""
        stats = self.get_stats()
        
        if stats.memory_percent >= 95:
            return MemoryPressure.CRITICAL
        elif stats.memory_percent >= 85:
            return MemoryPressure.HIGH
        elif stats.memory_percent >= 70:
            return MemoryPressure.MEDIUM
        else:
            return MemoryPressure.LOW


class GCController:
    """Controls garbage collection behavior"""
    
    def __init__(self):
        self._mode = GCMode.AUTOMATIC
        self._original_thresholds = gc.get_threshold()
        self._gc_enabled = gc.isenabled()
        self._manual_collections = LockFreeCounter(0)
        self._last_manual_gc = AtomicReference(0.0)
        self._gc_statistics = LockFreeStatistics()
    
    def set_mode(self, mode: GCMode):
        """Set garbage collection mode"""
        self._mode = mode
        
        if mode == GCMode.DISABLED:
            gc.disable()
        elif mode == GCMode.MANUAL:
            gc.disable()
        elif mode == GCMode.AUTOMATIC:
            gc.enable()
            gc.set_threshold(*self._original_thresholds)
        elif mode == GCMode.ADAPTIVE:
            gc.enable()
            # Set more aggressive thresholds for adaptive mode
            gc.set_threshold(1000, 15, 15)
    
    def force_collection(self, generation: Optional[int] = None) -> int:
        """Force garbage collection"""
        start_time = time.time()
        
        if generation is not None:
            collected = gc.collect(generation)
        else:
            collected = gc.collect()
        
        end_time = time.time()
        collection_time_ms = (end_time - start_time) * 1000
        
        self._manual_collections.increment()
        self._last_manual_gc.set(end_time)
        self._gc_statistics.add_sample(collection_time_ms)
        
        return collected
    
    def optimize_thresholds(self, memory_pressure: MemoryPressure):
        """Optimize GC thresholds based on memory pressure"""
        if self._mode not in [GCMode.ADAPTIVE, GCMode.AUTOMATIC]:
            return
        
        if memory_pressure == MemoryPressure.CRITICAL:
            # Very aggressive GC
            gc.set_threshold(100, 5, 5)
        elif memory_pressure == MemoryPressure.HIGH:
            # Aggressive GC
            gc.set_threshold(300, 8, 8)
        elif memory_pressure == MemoryPressure.MEDIUM:
            # Moderate GC
            gc.set_threshold(500, 10, 10)
        else:
            # Relaxed GC
            gc.set_threshold(1000, 15, 15)
    
    def get_gc_info(self) -> Dict[str, Any]:
        """Get garbage collection information"""
        return {
            'mode': self._mode.value,
            'enabled': gc.isenabled(),
            'thresholds': gc.get_threshold(),
            'counts': gc.get_count(),
            'stats': gc.get_stats(),
            'manual_collections': self._manual_collections.value,
            'last_manual_gc': self._last_manual_gc.get(),
            'collection_stats': self._gc_statistics.get_statistics()
        }
    
    def restore_defaults(self):
        """Restore default GC settings"""
        if self._gc_enabled:
            gc.enable()
        else:
            gc.disable()
        
        gc.set_threshold(*self._original_thresholds)
        self._mode = GCMode.AUTOMATIC


class ObjectTracker:
    """Tracks object creation and lifecycle for memory optimization"""
    
    def __init__(self, track_types: Optional[Set[type]] = None):
        self.track_types = track_types or set()
        self._tracked_objects: weakref.WeakSet = weakref.WeakSet()
        self._creation_counts = {}
        self._destruction_counts = {}
        self._lock = threading.Lock()
        self._enabled = False
    
    def enable_tracking(self):
        """Enable object tracking"""
        self._enabled = True
    
    def disable_tracking(self):
        """Disable object tracking"""
        self._enabled = False
    
    def track_object(self, obj: Any):
        """Track an object"""
        if not self._enabled:
            return
        
        obj_type = type(obj)
        if self.track_types and obj_type not in self.track_types:
            return
        
        self._tracked_objects.add(obj)
        
        with self._lock:
            self._creation_counts[obj_type] = self._creation_counts.get(obj_type, 0) + 1
    
    def get_tracked_count(self) -> int:
        """Get number of currently tracked objects"""
        return len(self._tracked_objects)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get object tracking statistics"""
        with self._lock:
            return {
                'tracked_objects': len(self._tracked_objects),
                'creation_counts': self._creation_counts.copy(),
                'destruction_counts': self._destruction_counts.copy(),
                'enabled': self._enabled
            }
    
    def clear_statistics(self):
        """Clear tracking statistics"""
        with self._lock:
            self._creation_counts.clear()
            self._destruction_counts.clear()


class MemoryLeakDetector:
    """Detects potential memory leaks"""
    
    def __init__(self, check_interval: float = 60.0, growth_threshold: float = 1.5):
        self.check_interval = check_interval
        self.growth_threshold = growth_threshold
        self._memory_history: List[float] = []
        self._object_history: List[int] = []
        self._running = False
        self._detector_thread = None
        self._leak_callbacks: List[Callable] = []
    
    def add_leak_callback(self, callback: Callable):
        """Add callback to be called when leak is detected"""
        self._leak_callbacks.append(callback)
    
    def start_detection(self):
        """Start leak detection"""
        if self._running:
            return
        
        self._running = True
        self._detector_thread = threading.Thread(target=self._detection_loop, daemon=True)
        self._detector_thread.start()
    
    def stop_detection(self):
        """Stop leak detection"""
        self._running = False
        if self._detector_thread:
            self._detector_thread.join(timeout=2.0)
    
    def _detection_loop(self):
        """Leak detection loop"""
        while self._running:
            try:
                self._check_for_leaks()
                time.sleep(self.check_interval)
            except Exception:
                pass
    
    def _check_for_leaks(self):
        """Check for potential memory leaks"""
        try:
            # Get current memory usage
            process = psutil.Process()
            current_memory = process.memory_info().rss / (1024 * 1024)  # MB
            current_objects = len(gc.get_objects())
            
            self._memory_history.append(current_memory)
            self._object_history.append(current_objects)
            
            # Keep only recent history (last 10 measurements)
            if len(self._memory_history) > 10:
                self._memory_history.pop(0)
                self._object_history.pop(0)
            
            # Check for consistent growth
            if len(self._memory_history) >= 5:
                if self._is_consistently_growing(self._memory_history):
                    self._trigger_leak_callbacks("memory", current_memory)
                
                if self._is_consistently_growing(self._object_history):
                    self._trigger_leak_callbacks("objects", current_objects)
                    
        except Exception:
            pass
    
    def _is_consistently_growing(self, values: List[float]) -> bool:
        """Check if values are consistently growing"""
        if len(values) < 3:
            return False
        
        # Check if recent values are significantly higher than earlier ones
        recent_avg = sum(values[-3:]) / 3
        earlier_avg = sum(values[:3]) / 3
        
        return recent_avg > earlier_avg * self.growth_threshold
    
    def _trigger_leak_callbacks(self, leak_type: str, current_value: float):
        """Trigger leak detection callbacks"""
        for callback in self._leak_callbacks:
            try:
                callback(leak_type, current_value)
            except Exception:
                pass


class GarbageCollectionOptimizer:
    """Main garbage collection optimizer"""
    
    def __init__(self, 
                 gc_mode: GCMode = GCMode.ADAPTIVE,
                 memory_check_interval: float = 5.0,
                 leak_detection_enabled: bool = True):
        
        self.gc_mode = gc_mode
        self.memory_check_interval = memory_check_interval
        self.leak_detection_enabled = leak_detection_enabled
        
        # Components
        self._memory_monitor = MemoryMonitor(update_interval=1.0)
        self._gc_controller = GCController()
        self._object_tracker = ObjectTracker()
        self._leak_detector = MemoryLeakDetector()
        
        # State
        self._running = False
        self._optimizer_thread = None
        self._last_optimization = AtomicReference(0.0)
        
        # Statistics
        self._optimizations_performed = LockFreeCounter(0)
        self._gc_collections_triggered = LockFreeCounter(0)
        
        # Initialize
        self._setup_leak_detection()
    
    def _setup_leak_detection(self):
        """Setup leak detection callbacks"""
        def leak_callback(leak_type: str, current_value: float):
            # Force garbage collection when leak is detected
            self._gc_controller.force_collection()
            self._gc_collections_triggered.increment()
        
        self._leak_detector.add_leak_callback(leak_callback)
    
    def start(self):
        """Start the garbage collection optimizer"""
        if self._running:
            return
        
        self._running = True
        
        # Set GC mode
        self._gc_controller.set_mode(self.gc_mode)
        
        # Start components
        self._memory_monitor.start()
        
        if self.leak_detection_enabled:
            self._leak_detector.start_detection()
        
        # Start optimization thread
        self._optimizer_thread = threading.Thread(target=self._optimization_loop, daemon=True)
        self._optimizer_thread.start()
    
    def stop(self):
        """Stop the garbage collection optimizer"""
        self._running = False
        
        # Stop components
        self._memory_monitor.stop()
        self._leak_detector.stop_detection()
        
        # Wait for optimizer thread
        if self._optimizer_thread:
            self._optimizer_thread.join(timeout=2.0)
        
        # Restore GC defaults
        self._gc_controller.restore_defaults()
    
    def _optimization_loop(self):
        """Main optimization loop"""
        while self._running:
            try:
                self._perform_optimization()
                time.sleep(self.memory_check_interval)
            except Exception:
                pass
    
    def _perform_optimization(self):
        """Perform GC optimization based on current conditions"""
        current_time = time.time()
        
        # Get memory pressure
        memory_pressure = self._memory_monitor.get_memory_pressure()
        
        # Optimize GC thresholds based on memory pressure
        self._gc_controller.optimize_thresholds(memory_pressure)
        
        # Force collection if memory pressure is high
        if memory_pressure in [MemoryPressure.HIGH, MemoryPressure.CRITICAL]:
            self._gc_controller.force_collection()
            self._gc_collections_triggered.increment()
        
        # Update optimization timestamp
        self._last_optimization.set(current_time)
        self._optimizations_performed.increment()
    
    def force_cleanup(self):
        """Force immediate cleanup and garbage collection"""
        # Force full garbage collection
        collected = self._gc_controller.force_collection()
        
        # Clear weak references
        gc.collect()
        
        return collected
    
    def enable_object_tracking(self, track_types: Optional[Set[type]] = None):
        """Enable object tracking for specific types"""
        if track_types:
            self._object_tracker.track_types = track_types
        self._object_tracker.enable_tracking()
    
    def disable_object_tracking(self):
        """Disable object tracking"""
        self._object_tracker.disable_tracking()
    
    def track_object(self, obj: Any):
        """Track a specific object"""
        self._object_tracker.track_object(obj)
    
    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive GC and memory statistics"""
        memory_stats = self._memory_monitor.get_stats()
        gc_info = self._gc_controller.get_gc_info()
        object_stats = self._object_tracker.get_statistics()
        
        return {
            'memory': {
                'total_mb': memory_stats.total_memory_mb,
                'available_mb': memory_stats.available_memory_mb,
                'used_mb': memory_stats.used_memory_mb,
                'percent': memory_stats.memory_percent,
                'process_mb': memory_stats.process_memory_mb,
                'gc_objects': memory_stats.gc_objects_count,
                'pressure': self._memory_monitor.get_memory_pressure().value
            },
            'gc': gc_info,
            'objects': object_stats,
            'optimizer': {
                'running': self._running,
                'mode': self.gc_mode.value,
                'optimizations_performed': self._optimizations_performed.value,
                'gc_collections_triggered': self._gc_collections_triggered.value,
                'last_optimization': self._last_optimization.get(),
                'leak_detection_enabled': self.leak_detection_enabled
            }
        }
    
    def optimize_for_performance(self):
        """Optimize settings for maximum performance"""
        self._gc_controller.set_mode(GCMode.MANUAL)
        # Disable automatic GC for maximum performance
        # User must manually call force_cleanup() periodically
    
    def optimize_for_memory(self):
        """Optimize settings for minimum memory usage"""
        self._gc_controller.set_mode(GCMode.ADAPTIVE)
        # Enable aggressive GC
        gc.set_threshold(100, 5, 5)
    
    def get_memory_recommendations(self) -> List[str]:
        """Get memory optimization recommendations"""
        recommendations = []
        stats = self.get_comprehensive_statistics()
        
        memory_percent = stats['memory']['percent']
        gc_objects = stats['memory']['gc_objects']
        
        if memory_percent > 90:
            recommendations.append("Critical memory usage - consider reducing object creation")
        elif memory_percent > 80:
            recommendations.append("High memory usage - monitor for memory leaks")
        
        if gc_objects > 100000:
            recommendations.append("High number of GC objects - consider object pooling")
        
        if stats['gc']['collection_stats']['count'] > 0:
            avg_time = stats['gc']['collection_stats']['average_time_ms']
            if avg_time > 100:
                recommendations.append("Long GC pauses detected - consider manual GC control")
        
        if not recommendations:
            recommendations.append("Memory usage is optimal")
        
        return recommendations
    
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        try:
            self.stop()
        except Exception:
            pass