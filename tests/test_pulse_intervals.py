"""
Test configurable pulse intervals implementation.

Tests for Requirement 6.3: Support configurable pulse intervals (10ms, 100ms, 1s)
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch

from core.distributed.pulse_sync import (
    PulseSyncEngine, PulseScheduler, PulseInterval, PulseConfig, PulseMode
)
from core.distributed.protocol import AttackConfig


class TestPulseIntervals:
    """Test configurable pulse intervals"""
    
    def test_supported_intervals(self):
        """Test that all required intervals are supported"""
        scheduler = PulseScheduler(Mock())
        supported = scheduler.get_supported_intervals()
        
        # Requirement 6.3: Support 10ms, 100ms, 1s intervals
        assert 10 in supported, "10ms interval not supported"
        assert 100 in supported, "100ms interval not supported"
        assert 1000 in supported, "1s interval not supported"
    
    def test_predefined_interval_configuration(self):
        """Test setting predefined pulse intervals"""
        sync_engine = Mock()
        scheduler = PulseScheduler(sync_engine)
        
        # Test 10ms (FAST)
        scheduler.set_interval(PulseInterval.FAST)
        assert scheduler.config.interval_ms == 10
        
        # Test 100ms (MEDIUM)
        scheduler.set_interval(PulseInterval.MEDIUM)
        assert scheduler.config.interval_ms == 100
        
        # Test 1000ms (SLOW)
        scheduler.set_interval(PulseInterval.SLOW)
        assert scheduler.config.interval_ms == 1000
    
    def test_custom_interval_configuration(self):
        """Test setting custom pulse intervals"""
        sync_engine = Mock()
        scheduler = PulseScheduler(sync_engine)
        
        # Test custom interval
        custom_interval = 250  # 250ms
        scheduler.set_interval(PulseInterval.CUSTOM, custom_ms=custom_interval)
        assert scheduler.config.interval_ms == custom_interval
        
        # Test another custom interval
        custom_interval = 2500  # 2.5s
        scheduler.set_interval(PulseInterval.CUSTOM, custom_ms=custom_interval)
        assert scheduler.config.interval_ms == custom_interval
    
    def test_custom_interval_validation(self):
        """Test validation of custom intervals"""
        sync_engine = Mock()
        scheduler = PulseScheduler(sync_engine)
        
        # Test missing custom value
        with pytest.raises(ValueError, match="Custom interval value required"):
            scheduler.set_interval(PulseInterval.CUSTOM)
        
        # Test too small custom interval
        with pytest.raises(ValueError, match="Custom interval must be at least 10ms"):
            scheduler.set_interval(PulseInterval.CUSTOM, custom_ms=5)
    
    def test_pulse_config_validation(self):
        """Test pulse configuration validation"""
        config = PulseConfig()
        
        # Valid configuration should not raise
        config.validate()
        
        # Test invalid interval
        config.interval_ms = 5
        with pytest.raises(ValueError, match="Pulse interval must be at least 10ms"):
            config.validate()
        
        # Reset and test invalid duration
        config.interval_ms = 100
        config.duration_ms = 0
        with pytest.raises(ValueError, match="Pulse duration must be at least 1ms"):
            config.validate()
        
        # Test duration exceeding interval
        config.duration_ms = 200
        with pytest.raises(ValueError, match="Pulse duration cannot exceed interval"):
            config.validate()
        
        # Test invalid intensity
        config.duration_ms = 50
        config.intensity = 1.5
        with pytest.raises(ValueError, match="Pulse intensity must be between 0.0 and 1.0"):
            config.validate()
        
        # Test negative jitter
        config.intensity = 0.8
        config.jitter_ms = -10
        with pytest.raises(ValueError, match="Jitter cannot be negative"):
            config.validate()


class TestAttackConfigPulseIntegration:
    """Test AttackConfig integration with pulse intervals"""
    
    def test_attack_config_pulse_validation(self):
        """Test AttackConfig pulse configuration validation"""
        config = AttackConfig(
            target="test.example.com",
            port=80,
            protocol="udp"
        )
        
        # Default config should be valid
        config.validate_pulse_config()
        
        # Test invalid pulse mode
        config.pulse_mode = "invalid"
        with pytest.raises(ValueError, match="Invalid pulse mode"):
            config.validate_pulse_config()
        
        # Test invalid interval
        config.pulse_mode = "pulse"
        config.pulse_interval_ms = 5
        with pytest.raises(ValueError, match="Pulse interval.*too small"):
            config.validate_pulse_config()
    
    def test_supported_pulse_intervals_check(self):
        """Test checking if pulse interval is supported"""
        config = AttackConfig(
            target="test.example.com",
            port=80,
            protocol="udp"
        )
        
        # Test supported intervals
        config.pulse_interval_ms = 10
        assert config.is_pulse_interval_supported()
        
        config.pulse_interval_ms = 100
        assert config.is_pulse_interval_supported()
        
        config.pulse_interval_ms = 1000
        assert config.is_pulse_interval_supported()
        
        # Test unsupported (but valid) interval
        config.pulse_interval_ms = 250
        assert not config.is_pulse_interval_supported()
    
    def test_get_supported_intervals(self):
        """Test getting supported pulse intervals"""
        config = AttackConfig(
            target="test.example.com",
            port=80,
            protocol="udp"
        )
        
        supported = config.get_supported_pulse_intervals()
        assert supported == [10, 100, 1000]
    
    def test_scheduler_apply_attack_config(self):
        """Test applying AttackConfig to PulseScheduler"""
        sync_engine = Mock()
        sync_engine.set_pulse_mode = Mock()
        scheduler = PulseScheduler(sync_engine)
        
        # Test continuous mode
        config = AttackConfig(
            target="test.example.com",
            port=80,
            protocol="udp",
            pulse_mode="continuous"
        )
        
        scheduler.apply_attack_config(config)
        sync_engine.set_pulse_mode.assert_called_with(PulseMode.CONTINUOUS)
        
        # Test pulse mode with standard interval
        config.pulse_mode = "pulse"
        config.pulse_interval_ms = 100
        config.pulse_duration_ms = 50
        config.pulse_intensity = 0.8
        config.pulse_jitter_ms = 5
        
        scheduler.apply_attack_config(config)
        sync_engine.set_pulse_mode.assert_called_with(PulseMode.PULSE)
        assert scheduler.config.interval_ms == 100
        assert scheduler.config.duration_ms == 50
        assert scheduler.config.intensity == 0.8
        assert scheduler.config.jitter_ms == 5
        
        # Test custom interval
        config.pulse_interval_ms = 250
        scheduler.apply_attack_config(config)
        assert scheduler.config.interval_ms == 250


class TestPulseTimingAccuracy:
    """Test pulse timing accuracy"""
    
    def test_calculate_next_pulse_time(self):
        """Test pulse time calculation"""
        sync_engine = Mock()
        sync_engine.get_synchronized_time.return_value = 1000.0  # Mock time
        
        scheduler = PulseScheduler(sync_engine)
        scheduler.config.interval_ms = 100  # 100ms interval
        
        # Calculate next pulse time
        next_time = scheduler.calculate_next_pulse_time(base_time=1000.0)
        
        # Should be at next 100ms boundary
        expected = 1000.1  # 1000.0 + 0.1s
        assert abs(next_time - expected) < 0.001, f"Expected {expected}, got {next_time}"
    
    def test_pulse_time_with_jitter(self):
        """Test pulse time calculation with jitter"""
        sync_engine = Mock()
        scheduler = PulseScheduler(sync_engine)
        scheduler.config.interval_ms = 100
        scheduler.config.jitter_ms = 10  # 10ms jitter
        
        # Calculate multiple pulse times to verify jitter
        times = []
        for _ in range(10):
            next_time = scheduler.calculate_next_pulse_time(base_time=1000.0)
            times.append(next_time)
        
        # All times should be different due to jitter
        assert len(set(times)) > 1, "Jitter should produce different times"
        
        # All times should be within jitter range
        base_time = 1000.1  # Expected base time
        for t in times:
            jitter = abs(t - base_time)
            assert jitter <= 0.010, f"Jitter {jitter*1000}ms exceeds 10ms limit"


@pytest.mark.asyncio
class TestPulseSchedulerIntegration:
    """Test pulse scheduler integration"""
    
    async def test_pulse_scheduler_lifecycle(self):
        """Test pulse scheduler start/stop lifecycle"""
        sync_engine = Mock()
        sync_engine.pulse_mode = PulseMode.CONTINUOUS
        
        scheduler = PulseScheduler(sync_engine)
        
        # Start scheduler
        await scheduler.start_scheduler()
        assert scheduler.running
        
        # Stop scheduler
        await scheduler.stop_scheduler()
        assert not scheduler.running
    
    async def test_pulse_command_creation(self):
        """Test pulse command creation"""
        sync_engine = Mock()
        sync_engine.node_id = "test_node"
        sync_engine.private_key = Mock()
        sync_engine.private_key.sign = Mock(return_value=b"fake_signature")
        
        scheduler = PulseScheduler(sync_engine)
        scheduler.config.duration_ms = 100
        scheduler.config.intensity = 0.8
        
        # Create pulse command
        scheduled_time = time.time() + 1.0
        command = scheduler.create_pulse_command(scheduled_time)
        
        assert command.scheduled_time == scheduled_time
        assert command.duration_ms == 100
        assert command.intensity == 0.8
        assert command.attack_params['burst_count'] == scheduler.config.burst_count
        assert command.signature is not None


if __name__ == "__main__":
    pytest.main([__file__])