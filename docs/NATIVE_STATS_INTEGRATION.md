# Native Stats Integration

This document explains how the NetStress Power Trio integrates native engine statistics with the existing Python analytics system.

## Overview

The Native Stats Bridge automatically feeds statistics from native Rust engines (and Python fallback engines) to the existing `MetricsCollector`, enabling seamless integration with the Python analytics infrastructure while maintaining high performance.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Python Analytics Layer                   │
│  MetricsCollector │ PerformanceTracker │ VisualizationEngine │
├─────────────────────────────────────────────────────────────┤
│                    Native Stats Bridge                       │
│  • Automatic engine registration                            │
│  • Real-time stats collection (100ms intervals)             │
│  • Seamless integration with existing analytics             │
├─────────────────────────────────────────────────────────────┤
│                    Engine Layer                              │
│  UltimateEngine │ UltraEngine │ Native Rust Engine           │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### Automatic Integration

- **Zero Configuration**: Engines automatically register with the stats bridge when started
- **Transparent Operation**: No code changes needed in existing analytics consumers
- **Universal Support**: Works with both native Rust engines and Python fallback engines

### Real-time Statistics

- **High Frequency**: Stats collected every 100ms by default
- **Low Overhead**: Lock-free collection with minimal performance impact
- **Comprehensive Metrics**: Packets/sec, bytes/sec, error rates, and more

### Robust Operation

- **Error Handling**: Graceful handling of engine failures and collection errors
- **Automatic Cleanup**: Engines automatically unregister when stopped
- **Performance Monitoring**: Bridge itself provides performance statistics

## Usage

### Basic Usage

The integration is completely automatic when using `UltimateEngine`:

```python
from core.native_engine import UltimateEngine, EngineConfig
from core.analytics import start_native_stats_collection

# Start the analytics system
await start_native_stats_collection()

# Create and start engine - automatically integrates with analytics
config = EngineConfig(target="192.168.1.1", port=80)
engine = UltimateEngine(config)
engine.start()

# Stats are automatically fed to the analytics system
# No additional code needed!
```

### Manual Registration

For custom engines, you can manually register with the stats bridge:

```python
from core.analytics import register_native_engine, unregister_native_engine

# Register custom engine
register_native_engine("my_engine", my_custom_engine)

# Engine stats will now be collected automatically

# Unregister when done
unregister_native_engine("my_engine")
```

### Accessing Analytics Data

Use the existing analytics APIs to access the integrated data:

```python
from core.analytics import get_metrics_collector

collector = get_metrics_collector()
summary = collector.get_metrics_summary(window_seconds=60)

# Native engine stats are in the 'attack' category
attack_metrics = summary['categories']['attack']
print(f"Packets/sec: {attack_metrics['packets_per_second']['avg']}")
print(f"Bytes/sec: {attack_metrics['bytes_per_second']['avg']}")
```

## Metrics Collected

The bridge collects and forwards these metrics to the analytics system:

### Core Performance Metrics

- `packets_per_second`: Current packet transmission rate
- `bytes_per_second`: Current byte transmission rate
- `native_total_packets`: Cumulative packets sent
- `native_total_bytes`: Cumulative bytes sent
- `native_errors`: Error count

### Engine Metadata

- `engine_id`: Unique engine identifier
- `backend`: Backend type (rust_native, python, etc.)
- `is_native`: Whether using native Rust engine

### Calculated Metrics

- `packet_delta`: Packets sent since last collection
- `byte_delta`: Bytes sent since last collection
- `time_delta`: Time elapsed since last collection
- `conn_rate`: Connection rate (connections per second)

## Configuration

### Collection Interval

Adjust the stats collection frequency:

```python
from core.analytics import NativeStatsBridge

# Create bridge with custom interval
bridge = NativeStatsBridge(collection_interval=0.05)  # 50ms
```

### Callbacks

Add custom callbacks for real-time stats processing:

```python
def my_stats_callback(engine_id, snapshot):
    print(f"Engine {engine_id}: {snapshot.packets_per_second} PPS")

bridge = get_native_stats_bridge()
bridge.add_stats_callback(my_stats_callback)
```

## Monitoring

### Bridge Statistics

Monitor the bridge itself:

```python
from core.analytics import get_native_stats_bridge

bridge = get_native_stats_bridge()
stats = bridge.get_bridge_stats()

print(f"Collections: {stats['total_collections']}")
print(f"Success rate: {stats['success_rate']:.1f}%")
print(f"Engines tracked: {stats['registered_engines']}")
```

### Latest Snapshots

Get the most recent stats from all engines:

```python
snapshots = bridge.get_latest_snapshots()
for engine_id, snapshot in snapshots.items():
    print(f"{engine_id}: {snapshot.packets_per_second} PPS")
```

## Performance Impact

The native stats bridge is designed for minimal performance impact:

- **Collection Overhead**: < 0.1% CPU usage
- **Memory Usage**: ~1MB for typical workloads
- **Network Impact**: Zero (stats collection is local)
- **Engine Impact**: Negligible (stats already calculated)

## Error Handling

The bridge handles various error conditions gracefully:

- **Engine Failures**: Failed collections are logged but don't stop the bridge
- **Analytics Failures**: Bridge continues operating if analytics system fails
- **Registration Errors**: Invalid engines are rejected with clear error messages

## Troubleshooting

### Common Issues

**Stats not appearing in analytics:**

- Ensure `start_native_stats_collection()` was called
- Check that engines are properly registered
- Verify analytics system is running

**High failure rate:**

- Check engine `get_stats()` method is working
- Look for exceptions in logs
- Verify engine lifecycle (start/stop) is correct

**Performance issues:**

- Reduce collection interval if needed
- Check for memory leaks in custom engines
- Monitor bridge statistics for bottlenecks

### Debug Logging

Enable debug logging to troubleshoot issues:

```python
import logging
logging.getLogger('core.analytics.native_stats_bridge').setLevel(logging.DEBUG)
```

## Examples

See `examples/native_stats_bridge_demo.py` for complete working examples demonstrating:

- Basic integration with single engine
- Multiple engines running simultaneously
- Analytics data access and visualization
- Error handling and cleanup

## Requirements

- Python 3.8+
- NetStress analytics system
- Compatible engine with `get_stats()` method

## API Reference

### NativeStatsBridge

Main bridge class for connecting engines to analytics.

#### Methods

- `register_native_engine(engine_id, engine)`: Register an engine
- `unregister_native_engine(engine_id)`: Unregister an engine
- `start()`: Start stats collection
- `stop()`: Stop stats collection
- `get_bridge_stats()`: Get bridge performance statistics
- `get_latest_snapshots()`: Get latest stats from all engines

### Global Functions

- `get_native_stats_bridge()`: Get global bridge instance
- `register_native_engine(engine_id, engine)`: Convenience registration
- `unregister_native_engine(engine_id)`: Convenience unregistration
- `start_native_stats_collection()`: Start global bridge
- `stop_native_stats_collection()`: Stop global bridge

### NativeStatsSnapshot

Data class containing engine statistics snapshot.

#### Attributes

- `packets_sent`: Total packets sent
- `bytes_sent`: Total bytes sent
- `packets_per_second`: Current PPS rate
- `bytes_per_second`: Current BPS rate
- `errors`: Error count
- `duration_secs`: Engine runtime
- `backend`: Backend identifier
- `is_native`: Native engine flag
- `timestamp`: Collection timestamp
