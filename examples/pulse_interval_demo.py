#!/usr/bin/env python3
"""
Pulse Interval Configuration Demo

Demonstrates configurable pulse intervals (10ms, 100ms, 1s) and custom intervals
as required by Requirement 6.3.
"""

import asyncio
import time
import logging
from typing import List

from core.distributed.pulse_sync import (
    PulseSyncEngine, PulseScheduler, PulseInterval, PulseMode, PulseCommand
)
from core.distributed.protocol import AttackConfig

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PulseIntervalDemo:
    """Demonstration of configurable pulse intervals"""
    
    def __init__(self):
        self.pulse_engine = None
        self.scheduler = None
        self.received_pulses: List[PulseCommand] = []
    
    async def setup(self):
        """Initialize pulse sync engine and scheduler"""
        logger.info("Setting up pulse synchronization engine...")
        
        # Create pulse sync engine
        self.pulse_engine = PulseSyncEngine("demo_node", sync_port=8765)
        
        # Create scheduler
        self.scheduler = PulseScheduler(self.pulse_engine)
        
        # Add callback to capture pulse commands
        self.pulse_engine.add_pulse_callback(self._pulse_callback)
        
        # Start the engine
        await self.pulse_engine.start()
        logger.info("Pulse sync engine started")
    
    async def cleanup(self):
        """Clean up resources"""
        if self.scheduler and self.scheduler.running:
            await self.scheduler.stop_scheduler()
        
        if self.pulse_engine and self.pulse_engine.running:
            await self.pulse_engine.stop()
        
        logger.info("Cleanup complete")
    
    def _pulse_callback(self, command: PulseCommand):
        """Callback for received pulse commands"""
        self.received_pulses.append(command)
        logger.info(f"Received pulse: ID={command.pulse_id[:8]}, "
                   f"duration={command.duration_ms}ms, "
                   f"intensity={command.intensity}")
    
    async def demo_predefined_intervals(self):
        """Demonstrate predefined pulse intervals (10ms, 100ms, 1s)"""
        logger.info("\n=== Demonstrating Predefined Pulse Intervals ===")
        
        intervals = [
            (PulseInterval.FAST, "10ms - Ultra-fast bursts"),
            (PulseInterval.MEDIUM, "100ms - Medium bursts"),
            (PulseInterval.SLOW, "1000ms - Slow bursts")
        ]
        
        for interval, description in intervals:
            logger.info(f"\nTesting {description}")
            
            # Configure interval
            self.scheduler.set_interval(interval)
            
            # Set appropriate duration based on interval
            if interval == PulseInterval.FAST:  # 10ms
                duration_ms = 5  # 5ms duration for 10ms interval
            elif interval == PulseInterval.MEDIUM:  # 100ms
                duration_ms = 50  # 50ms duration for 100ms interval
            else:  # SLOW - 1000ms
                duration_ms = 200  # 200ms duration for 1000ms interval
            
            self.scheduler.configure_pulse(duration_ms=duration_ms, intensity=0.8)
            
            # Set to pulse mode
            self.pulse_engine.set_pulse_mode(PulseMode.PULSE)
            
            # Start scheduler briefly
            await self.scheduler.start_scheduler()
            await asyncio.sleep(0.5)  # Run for 500ms
            await self.scheduler.stop_scheduler()
            
            logger.info(f"Interval {interval.value}ms configured successfully")
    
    async def demo_custom_intervals(self):
        """Demonstrate custom pulse intervals"""
        logger.info("\n=== Demonstrating Custom Pulse Intervals ===")
        
        custom_intervals = [250, 500, 1500, 3000]  # Custom intervals in ms
        
        for interval_ms in custom_intervals:
            logger.info(f"\nTesting custom interval: {interval_ms}ms")
            
            # Configure custom interval
            self.scheduler.set_interval(PulseInterval.CUSTOM, custom_ms=interval_ms)
            self.scheduler.configure_pulse(duration_ms=100, intensity=0.9)
            
            # Verify configuration
            assert self.scheduler.config.interval_ms == interval_ms
            logger.info(f"Custom interval {interval_ms}ms configured successfully")
    
    async def demo_attack_config_integration(self):
        """Demonstrate AttackConfig integration with pulse intervals"""
        logger.info("\n=== Demonstrating AttackConfig Integration ===")
        
        # Test different attack configurations
        configs = [
            {
                "name": "Fast Pulse Attack",
                "pulse_mode": "pulse",
                "pulse_interval_ms": 10,
                "pulse_duration_ms": 5,
                "pulse_intensity": 1.0
            },
            {
                "name": "Medium Pulse Attack", 
                "pulse_mode": "pulse",
                "pulse_interval_ms": 100,
                "pulse_duration_ms": 50,
                "pulse_intensity": 0.8
            },
            {
                "name": "Slow Pulse Attack",
                "pulse_mode": "pulse", 
                "pulse_interval_ms": 1000,
                "pulse_duration_ms": 200,
                "pulse_intensity": 0.6
            },
            {
                "name": "Custom Pulse Attack",
                "pulse_mode": "pulse",
                "pulse_interval_ms": 750,  # Custom interval
                "pulse_duration_ms": 150,
                "pulse_intensity": 0.7
            },
            {
                "name": "Continuous Attack",
                "pulse_mode": "continuous",
                "pulse_interval_ms": 100,  # Ignored in continuous mode
                "pulse_duration_ms": 100,
                "pulse_intensity": 1.0
            }
        ]
        
        for config_data in configs:
            logger.info(f"\nTesting: {config_data['name']}")
            
            # Create AttackConfig
            attack_config = AttackConfig(
                target="demo.example.com",
                port=80,
                protocol="udp",
                **{k: v for k, v in config_data.items() if k != "name"}
            )
            
            # Validate configuration
            try:
                attack_config.validate_pulse_config()
                logger.info("✓ Configuration validation passed")
            except ValueError as e:
                logger.error(f"✗ Configuration validation failed: {e}")
                continue
            
            # Apply to scheduler
            self.scheduler.apply_attack_config(attack_config)
            
            # Verify application
            if attack_config.pulse_mode == "pulse":
                assert self.pulse_engine.pulse_mode == PulseMode.PULSE
                assert self.scheduler.config.interval_ms == attack_config.pulse_interval_ms
                assert self.scheduler.config.duration_ms == attack_config.pulse_duration_ms
                assert self.scheduler.config.intensity == attack_config.pulse_intensity
            else:
                assert self.pulse_engine.pulse_mode == PulseMode.CONTINUOUS
            
            logger.info("✓ Configuration applied successfully")
            
            # Check if interval is supported
            if attack_config.is_pulse_interval_supported():
                logger.info("✓ Using standard supported interval")
            else:
                logger.info("✓ Using custom interval")
    
    async def demo_pulse_timing_accuracy(self):
        """Demonstrate pulse timing accuracy"""
        logger.info("\n=== Demonstrating Pulse Timing Accuracy ===")
        
        # Configure for timing test
        self.scheduler.set_interval(PulseInterval.MEDIUM)  # 100ms
        self.scheduler.configure_pulse(duration_ms=10, intensity=1.0, jitter_ms=0)
        
        # Calculate several pulse times
        base_time = time.time()
        pulse_times = []
        
        for i in range(5):
            next_time = self.scheduler.calculate_next_pulse_time(base_time + i * 0.1)
            pulse_times.append(next_time)
            logger.info(f"Pulse {i+1} scheduled for: {next_time:.6f}")
        
        # Verify timing accuracy
        for i in range(1, len(pulse_times)):
            interval = pulse_times[i] - pulse_times[i-1]
            expected_interval = 0.1  # 100ms
            accuracy = abs(interval - expected_interval)
            logger.info(f"Interval {i}: {interval:.6f}s (accuracy: {accuracy*1000:.3f}ms)")
    
    async def demo_configuration_validation(self):
        """Demonstrate configuration validation"""
        logger.info("\n=== Demonstrating Configuration Validation ===")
        
        # Test various invalid configurations
        invalid_configs = [
            {
                "name": "Invalid pulse mode",
                "pulse_mode": "invalid_mode",
                "expected_error": "Invalid pulse mode"
            },
            {
                "name": "Interval too small",
                "pulse_interval_ms": 5,
                "expected_error": "Pulse interval.*too small"
            },
            {
                "name": "Duration too small", 
                "pulse_duration_ms": 0,
                "expected_error": "Pulse duration.*too small"
            },
            {
                "name": "Duration exceeds interval",
                "pulse_interval_ms": 50,
                "pulse_duration_ms": 100,
                "expected_error": "Pulse duration.*cannot exceed interval"
            },
            {
                "name": "Invalid intensity",
                "pulse_intensity": 1.5,
                "expected_error": "Pulse intensity.*must be between"
            },
            {
                "name": "Negative jitter",
                "pulse_jitter_ms": -10,
                "expected_error": "Pulse jitter.*cannot be negative"
            }
        ]
        
        for config_data in invalid_configs:
            logger.info(f"\nTesting: {config_data['name']}")
            
            # Create config with invalid parameter
            attack_config = AttackConfig(
                target="demo.example.com",
                port=80,
                protocol="udp"
            )
            
            # Apply invalid parameter
            for key, value in config_data.items():
                if key not in ["name", "expected_error"]:
                    setattr(attack_config, key, value)
            
            # Test validation
            try:
                attack_config.validate_pulse_config()
                logger.error(f"✗ Expected validation error but none occurred")
            except ValueError as e:
                expected_error = config_data["expected_error"]
                if expected_error in str(e):
                    logger.info(f"✓ Validation correctly caught error: {e}")
                else:
                    logger.error(f"✗ Unexpected error message: {e}")


async def main():
    """Main demonstration function"""
    demo = PulseIntervalDemo()
    
    try:
        await demo.setup()
        
        # Run all demonstrations
        await demo.demo_predefined_intervals()
        await demo.demo_custom_intervals()
        await demo.demo_attack_config_integration()
        await demo.demo_pulse_timing_accuracy()
        await demo.demo_configuration_validation()
        
        logger.info("\n=== Pulse Interval Demo Complete ===")
        logger.info("All configurable pulse interval features demonstrated successfully!")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise
    finally:
        await demo.cleanup()


if __name__ == "__main__":
    asyncio.run(main())