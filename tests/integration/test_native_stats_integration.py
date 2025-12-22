#!/usr/bin/env python3
"""
Test Native Stats Bridge Integration

Tests the integration between native engines and the Python analytics system.
"""

import asyncio
import time
import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.analytics.native_stats_bridge import (
    NativeStatsBridge, NativeStatsSnapshot, 
    get_native_stats_bridge, register_native_engine, unregister_native_engine
)
from core.analytics.metrics_collector import get_metrics_collector


class MockNativeEngine:
    """Mock native engine for testing"""
    
    def __init__(self, target="127.0.0.1", port=80):
        self.target = target
        self.port = port
        self.packets_sent = 0
        self.bytes_sent = 0
        self.errors = 0
        self.start_time = time.time()
        self.running = False
    
    def start(self):
        self.running = True
        self.start_time = time.time()
    
    def stop(self):
        self.running = False
    
    def get_stats(self):
        duration = time.time() - self.start_time
        pps = self.packets_sent / max(0.001, duration)
        bps = self.bytes_sent / max(0.001, duration)
        
        return {
            'packets_sent': self.packets_sent,
            'bytes_sent': self.bytes_sent,
            'packets_per_second': pps,
            'bytes_per_second': bps,
            'errors': self.errors,
            'duration_secs': duration,
            'backend': 'mock_native',
            'is_native': True
        }
    
    def simulate_traffic(self, packets=1000, packet_size=1472):
        """Simulate sending packets"""
        self.packets_sent += packets
        self.bytes_sent += packets * packet_size


class TestNativeStatsBridge(unittest.TestCase):
    """Test the native stats bridge functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.bridge = NativeStatsBridge(collection_interval=0.05)  # Fast collection for testing
        self.mock_engine = MockNativeEngine()
        self.collected_stats = []
        
        # Add callback to collect stats
        def stats_callback(engine_id, snapshot):
            self.collected_stats.append((engine_id, snapshot))
        
        self.bridge.add_stats_callback(stats_callback)
    
    def tearDown(self):
        """Clean up after tests"""
        asyncio.run(self.bridge.stop())
    
    def test_bridge_creation(self):
        """Test bridge can be created"""
        self.assertIsInstance(self.bridge, NativeStatsBridge)
        self.assertEqual(self.bridge.collection_interval, 0.05)
        self.assertFalse(self.bridge._running)
    
    def test_engine_registration(self):
        """Test engine registration and unregistration"""
        engine_id = "test_engine_1"
        
        # Register engine
        self.bridge.register_native_engine(engine_id, self.mock_engine)
        self.assertIn(engine_id, self.bridge._native_engines)
        
        # Unregister engine
        self.bridge.unregister_native_engine(engine_id)
        self.assertNotIn(engine_id, self.bridge._native_engines)
    
    def test_invalid_engine_registration(self):
        """Test registration of invalid engine fails"""
        class InvalidEngine:
            pass
        
        with self.assertRaises(ValueError):
            self.bridge.register_native_engine("invalid", InvalidEngine())
    
    async def test_stats_collection(self):
        """Test stats collection from registered engines"""
        engine_id = "test_engine_2"
        self.bridge.register_native_engine(engine_id, self.mock_engine)
        
        # Start the mock engine
        self.mock_engine.start()
        self.mock_engine.simulate_traffic(packets=5000, packet_size=1472)
        
        # Start bridge
        await self.bridge.start()
        
        # Wait for a few collection cycles
        await asyncio.sleep(0.2)
        
        # Stop bridge
        await self.bridge.stop()
        
        # Check that stats were collected
        self.assertGreater(len(self.collected_stats), 0)
        
        # Check stats content
        engine_id_collected, snapshot = self.collected_stats[0]
        self.assertEqual(engine_id_collected, engine_id)
        self.assertIsInstance(snapshot, NativeStatsSnapshot)
        self.assertEqual(snapshot.packets_sent, 5000)
        self.assertEqual(snapshot.bytes_sent, 5000 * 1472)
        self.assertTrue(snapshot.is_native)
    
    def test_bridge_stats(self):
        """Test bridge statistics"""
        stats = self.bridge.get_bridge_stats()
        
        self.assertIn('running', stats)
        self.assertIn('registered_engines', stats)
        self.assertIn('total_collections', stats)
        self.assertIn('failed_collections', stats)
        self.assertIn('success_rate', stats)
        
        self.assertFalse(stats['running'])
        self.assertEqual(stats['registered_engines'], 0)
    
    def test_global_bridge_functions(self):
        """Test global bridge convenience functions"""
        engine_id = "global_test_engine"
        
        # Test global registration
        register_native_engine(engine_id, self.mock_engine)
        
        global_bridge = get_native_stats_bridge()
        self.assertIn(engine_id, global_bridge._native_engines)
        
        # Test global unregistration
        unregister_native_engine(engine_id)
        self.assertNotIn(engine_id, global_bridge._native_engines)


class TestNativeStatsSnapshot(unittest.TestCase):
    """Test the NativeStatsSnapshot class"""
    
    def test_snapshot_from_dict(self):
        """Test creating snapshot from dictionary"""
        stats_dict = {
            'packets_sent': 10000,
            'bytes_sent': 14720000,
            'packets_per_second': 1000.0,
            'bytes_per_second': 1472000.0,
            'errors': 5,
            'duration_secs': 10.0,
            'backend': 'rust_native',
            'is_native': True
        }
        
        snapshot = NativeStatsSnapshot.from_native_dict(stats_dict)
        
        self.assertEqual(snapshot.packets_sent, 10000)
        self.assertEqual(snapshot.bytes_sent, 14720000)
        self.assertEqual(snapshot.packets_per_second, 1000.0)
        self.assertEqual(snapshot.bytes_per_second, 1472000.0)
        self.assertEqual(snapshot.errors, 5)
        self.assertEqual(snapshot.duration_secs, 10.0)
        self.assertEqual(snapshot.backend, 'rust_native')
        self.assertTrue(snapshot.is_native)
    
    def test_snapshot_with_aliases(self):
        """Test snapshot creation with aliased field names"""
        stats_dict = {
            'packets_sent': 5000,
            'bytes_sent': 7360000,
            'pps': 500.0,  # Alias for packets_per_second
            'bps': 736000.0,  # Alias for bytes_per_second
            'errors': 2,
            'duration': 10.0,  # Alias for duration_secs
            'backend': 'af_xdp',
            'is_native': True
        }
        
        snapshot = NativeStatsSnapshot.from_native_dict(stats_dict)
        
        self.assertEqual(snapshot.packets_per_second, 500.0)
        self.assertEqual(snapshot.bytes_per_second, 736000.0)
        self.assertEqual(snapshot.duration_secs, 10.0)


class TestIntegrationWithMetricsCollector(unittest.TestCase):
    """Test integration with the existing MetricsCollector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.bridge = NativeStatsBridge(collection_interval=0.05)
        self.mock_engine = MockNativeEngine()
        self.metrics_collector = get_metrics_collector()
    
    def tearDown(self):
        """Clean up after tests"""
        asyncio.run(self.bridge.stop())
        asyncio.run(self.metrics_collector.stop())
    
    async def test_metrics_collector_integration(self):
        """Test that native stats are fed to MetricsCollector"""
        engine_id = "integration_test_engine"
        
        # Start metrics collector
        await self.metrics_collector.start()
        
        # Register engine and start bridge
        self.bridge.register_native_engine(engine_id, self.mock_engine)
        self.mock_engine.start()
        self.mock_engine.simulate_traffic(packets=2000, packet_size=1472)
        
        await self.bridge.start()
        
        # Wait for collection
        await asyncio.sleep(0.2)
        
        # Stop everything
        await self.bridge.stop()
        
        # Check that metrics were collected
        summary = self.metrics_collector.get_metrics_summary(window_seconds=10)
        
        self.assertIn('categories', summary)
        self.assertIn('attack', summary['categories'])
        
        # The exact metrics depend on the MetricsCollector implementation
        # but we should see some attack category metrics
        attack_metrics = summary['categories']['attack']
        self.assertIsInstance(attack_metrics, dict)


def run_async_test(test_func):
    """Helper to run async test functions"""
    def wrapper(self):
        asyncio.run(test_func(self))
    return wrapper


# Apply async wrapper to async test methods
TestNativeStatsBridge.test_stats_collection = run_async_test(TestNativeStatsBridge.test_stats_collection)
TestIntegrationWithMetricsCollector.test_metrics_collector_integration = run_async_test(
    TestIntegrationWithMetricsCollector.test_metrics_collector_integration
)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)