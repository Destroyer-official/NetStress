#!/usr/bin/env python3
"""
Native Stats Bridge for NetStress Power Trio

This module bridges the native Rust engine statistics with the existing
Python analytics system, feeding native stats to the MetricsCollector.

Requirements: 6.1, 6.3
"""

import asyncio
import logging
import time
import threading
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

from .metrics_collector import get_metrics_collector, collect_attack_metrics

logger = logging.getLogger(__name__)

@dataclass
class NativeStatsSnapshot:
    """Snapshot of native engine statistics"""
    timestamp: float
    packets_sent: int
    bytes_sent: int
    packets_per_second: float
    bytes_per_second: float
    errors: int
    duration_secs: float
    backend: str
    is_native: bool
    
    @classmethod
    def from_native_dict(cls, stats_dict: Dict[str, Any]) -> 'NativeStatsSnapshot':
        """Create snapshot from native engine stats dictionary"""
        return cls(
            timestamp=time.time(),
            packets_sent=stats_dict.get('packets_sent', 0),
            bytes_sent=stats_dict.get('bytes_sent', 0),
            packets_per_second=stats_dict.get('packets_per_second', stats_dict.get('pps', 0.0)),
            bytes_per_second=stats_dict.get('bytes_per_second', stats_dict.get('bps', 0.0)),
            errors=stats_dict.get('errors', 0),
            duration_secs=stats_dict.get('duration_secs', stats_dict.get('duration', 0.0)),
            backend=stats_dict.get('backend', 'unknown'),
            is_native=stats_dict.get('is_native', False)
        )


class NativeStatsBridge:
    """
    Bridge between native Rust engine and Python analytics system.
    
    This class automatically feeds native engine statistics to the existing
    MetricsCollector, enabling seamless integration with the Python analytics
    infrastructure while maintaining high performance.
    """
    
    def __init__(self, collection_interval: float = 0.1):
        """
        Initialize the native stats bridge.
        
        Args:
            collection_interval: How often to collect stats from native engine (seconds)
        """
        self.collection_interval = collection_interval
        self.metrics_collector = get_metrics_collector()
        
        # State tracking
        self._running = False
        self._collection_task = None
        self._native_engines = {}  # engine_id -> engine_ref
        self._last_snapshots = {}  # engine_id -> NativeStatsSnapshot
        self._callbacks = []  # List of callback functions
        
        # Statistics
        self._total_collections = 0
        self._failed_collections = 0
        self._start_time = None
        
        logger.info(f"Native stats bridge initialized (interval={collection_interval}s)")
    
    def register_native_engine(self, engine_id: str, engine) -> None:
        """
        Register a native engine for stats collection.
        
        Args:
            engine_id: Unique identifier for the engine
            engine: Native engine instance (UltimateEngine or similar)
        """
        if not hasattr(engine, 'get_stats'):
            raise ValueError(f"Engine {engine_id} does not have get_stats method")
        
        self._native_engines[engine_id] = engine
        logger.info(f"Registered native engine: {engine_id}")
    
    def unregister_native_engine(self, engine_id: str) -> None:
        """
        Unregister a native engine from stats collection.
        
        Args:
            engine_id: Engine identifier to remove
        """
        if engine_id in self._native_engines:
            del self._native_engines[engine_id]
            if engine_id in self._last_snapshots:
                del self._last_snapshots[engine_id]
            logger.info(f"Unregistered native engine: {engine_id}")
    
    def add_stats_callback(self, callback: Callable[[str, NativeStatsSnapshot], None]) -> None:
        """
        Add a callback function to be called when stats are collected.
        
        Args:
            callback: Function that takes (engine_id, stats_snapshot)
        """
        self._callbacks.append(callback)
        logger.debug(f"Added stats callback: {callback.__name__}")
    
    def remove_stats_callback(self, callback: Callable) -> None:
        """Remove a stats callback function."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            logger.debug(f"Removed stats callback: {callback.__name__}")
    
    async def start(self) -> None:
        """Start the stats collection bridge."""
        if self._running:
            logger.warning("Native stats bridge already running")
            return
        
        self._running = True
        self._start_time = time.time()
        self._total_collections = 0
        self._failed_collections = 0
        
        # Start the metrics collector if not already running
        try:
            await self.metrics_collector.start()
        except Exception as e:
            logger.warning(f"Failed to start metrics collector: {e}")
        
        # Start collection task
        self._collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Native stats bridge started")
    
    async def stop(self) -> None:
        """Stop the stats collection bridge."""
        if not self._running:
            return
        
        logger.info("Stopping native stats bridge")
        self._running = False
        
        # Cancel collection task
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        
        # Final stats collection
        await self._collect_all_stats()
        
        logger.info(f"Native stats bridge stopped (collected {self._total_collections} snapshots, "
                   f"{self._failed_collections} failures)")
    
    async def _collection_loop(self) -> None:
        """Main collection loop that runs in the background."""
        logger.debug("Starting native stats collection loop")
        
        while self._running:
            try:
                await self._collect_all_stats()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in stats collection loop: {e}")
                self._failed_collections += 1
                await asyncio.sleep(1.0)  # Back off on error
        
        logger.debug("Native stats collection loop stopped")
    
    async def _collect_all_stats(self) -> None:
        """Collect stats from all registered native engines."""
        if not self._native_engines:
            return
        
        for engine_id, engine in self._native_engines.items():
            try:
                await self._collect_engine_stats(engine_id, engine)
            except Exception as e:
                logger.error(f"Failed to collect stats from engine {engine_id}: {e}")
                self._failed_collections += 1
    
    async def _collect_engine_stats(self, engine_id: str, engine) -> None:
        """Collect stats from a single native engine."""
        try:
            # Get stats from native engine
            stats_dict = engine.get_stats()
            if isinstance(stats_dict, dict):
                # Convert dict to our format
                snapshot = NativeStatsSnapshot.from_native_dict(stats_dict)
            else:
                # Assume it's already a stats object with attributes
                snapshot = NativeStatsSnapshot(
                    timestamp=time.time(),
                    packets_sent=getattr(stats_dict, 'packets_sent', 0),
                    bytes_sent=getattr(stats_dict, 'bytes_sent', 0),
                    packets_per_second=getattr(stats_dict, 'pps', 0.0),
                    bytes_per_second=getattr(stats_dict, 'bps', 0.0),
                    errors=getattr(stats_dict, 'errors', 0),
                    duration_secs=getattr(stats_dict, 'duration', 0.0),
                    backend=getattr(stats_dict, 'backend', 'unknown'),
                    is_native=getattr(stats_dict, 'is_native', False)
                )
            
            # Feed to metrics collector
            await self._feed_to_metrics_collector(engine_id, snapshot)
            
            # Store snapshot for delta calculations
            self._last_snapshots[engine_id] = snapshot
            
            # Call registered callbacks
            for callback in self._callbacks:
                try:
                    callback(engine_id, snapshot)
                except Exception as e:
                    logger.error(f"Error in stats callback {callback.__name__}: {e}")
            
            self._total_collections += 1
            
        except Exception as e:
            logger.error(f"Failed to collect stats from engine {engine_id}: {e}")
            raise
    
    async def _feed_to_metrics_collector(self, engine_id: str, snapshot: NativeStatsSnapshot) -> None:
        """Feed native stats to the existing MetricsCollector."""
        try:
            # Prepare stats dictionary for the metrics collector
            stats_dict = {
                'pps': snapshot.packets_per_second,
                'bps': snapshot.bytes_per_second,
                'packets_sent': snapshot.packets_sent,
                'bytes_sent': snapshot.bytes_sent,
                'errors': snapshot.errors,
                'duration': snapshot.duration_secs,
                'backend': snapshot.backend,
                'engine_id': engine_id,
                'is_native': snapshot.is_native,
                'timestamp': snapshot.timestamp
            }
            
            # Calculate deltas if we have a previous snapshot
            if engine_id in self._last_snapshots:
                prev = self._last_snapshots[engine_id]
                time_delta = snapshot.timestamp - prev.timestamp
                
                if time_delta > 0:
                    # Calculate rates based on deltas
                    packet_delta = snapshot.packets_sent - prev.packets_sent
                    byte_delta = snapshot.bytes_sent - prev.bytes_sent
                    
                    stats_dict.update({
                        'conn_rate': packet_delta / time_delta,  # Connections per second
                        'packet_delta': packet_delta,
                        'byte_delta': byte_delta,
                        'time_delta': time_delta
                    })
            
            # Feed to the existing metrics collector
            self.metrics_collector.collect_attack_metrics(stats_dict)
            
            # Also collect individual metrics for more granular tracking
            tags = {
                'engine_id': engine_id,
                'backend': snapshot.backend,
                'is_native': str(snapshot.is_native)
            }
            
            # Core performance metrics
            self.metrics_collector.collect_metric(
                'native_packets_per_second', snapshot.packets_per_second, 
                'attack', tags
            )
            self.metrics_collector.collect_metric(
                'native_bytes_per_second', snapshot.bytes_per_second, 
                'attack', tags
            )
            self.metrics_collector.collect_metric(
                'native_total_packets', snapshot.packets_sent, 
                'attack', tags
            )
            self.metrics_collector.collect_metric(
                'native_total_bytes', snapshot.bytes_sent, 
                'attack', tags
            )
            self.metrics_collector.collect_metric(
                'native_errors', snapshot.errors, 
                'attack', tags
            )
            
            logger.debug(f"Fed stats to metrics collector: {engine_id} "
                        f"({snapshot.packets_per_second:.0f} PPS, "
                        f"{snapshot.bytes_per_second/1e6:.1f} MB/s)")
            
        except Exception as e:
            logger.error(f"Failed to feed stats to metrics collector: {e}")
            raise
    
    def get_bridge_stats(self) -> Dict[str, Any]:
        """Get statistics about the bridge itself."""
        uptime = time.time() - self._start_time if self._start_time else 0
        
        return {
            'running': self._running,
            'uptime_seconds': uptime,
            'registered_engines': len(self._native_engines),
            'total_collections': self._total_collections,
            'failed_collections': self._failed_collections,
            'success_rate': (
                (self._total_collections - self._failed_collections) / max(1, self._total_collections)
            ) * 100,
            'collection_interval': self.collection_interval,
            'collections_per_second': self._total_collections / max(1, uptime),
            'engine_ids': list(self._native_engines.keys())
        }
    
    def get_latest_snapshots(self) -> Dict[str, NativeStatsSnapshot]:
        """Get the latest stats snapshots for all engines."""
        return self._last_snapshots.copy()
    
    def __repr__(self) -> str:
        return (f"NativeStatsBridge(engines={len(self._native_engines)}, "
                f"running={self._running}, interval={self.collection_interval}s)")


# Global bridge instance
_global_bridge = None

def get_native_stats_bridge() -> NativeStatsBridge:
    """Get the global native stats bridge instance."""
    global _global_bridge
    if _global_bridge is None:
        _global_bridge = NativeStatsBridge()
    return _global_bridge


def register_native_engine(engine_id: str, engine) -> None:
    """Convenience function to register a native engine with the global bridge."""
    bridge = get_native_stats_bridge()
    bridge.register_native_engine(engine_id, engine)


def unregister_native_engine(engine_id: str) -> None:
    """Convenience function to unregister a native engine from the global bridge."""
    bridge = get_native_stats_bridge()
    bridge.unregister_native_engine(engine_id)


async def start_native_stats_collection() -> None:
    """Start the global native stats collection bridge."""
    bridge = get_native_stats_bridge()
    await bridge.start()


async def stop_native_stats_collection() -> None:
    """Stop the global native stats collection bridge."""
    bridge = get_native_stats_bridge()
    await bridge.stop()


# Export public API
__all__ = [
    'NativeStatsBridge',
    'NativeStatsSnapshot',
    'get_native_stats_bridge',
    'register_native_engine',
    'unregister_native_engine',
    'start_native_stats_collection',
    'stop_native_stats_collection',
]