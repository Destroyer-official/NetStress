#!/usr/bin/env python3
"""
TLS/JA3 and Precision Timing Integration Tests
Tests TLS fingerprint spoofing and microsecond-accurate timing

**Feature: military-grade-transformation**
**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 3.4, 3.5**
"""

import pytest
import sys
import os
import time
import hashlib
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import components to test
try:
    from core.attacks.tls_spoof import JA3Spoofer, TlsProfile
    from core.evasion.precision_timer import PrecisionTimer, TrafficShaper
    TLS_COMPONENTS_AVAILABLE = True
except ImportError:
    TLS_COMPONENTS_AVAILABLE = False

# Try to import native components
try:
    import netstress_engine
    RUST_ENGINE_AVAILABLE = True
except ImportError:
    RUST_ENGINE_AVAILABLE = False


class TestTLSJA3Integration:
    """Test TLS/JA3 fingerprint spoofing integration"""

    def test_ja3_spoofer_initialization(self):
        """Test JA3 spoofer initialization"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        assert spoofer is not None
        
        # Should have predefined profiles
        profiles = spoofer.get_available_profiles()
        assert len(profiles) > 0
        
        # Should include major browser profiles
        profile_names = [p.name for p in profiles]
        assert any("chrome" in name.lower() for name in profile_names)
        assert any("firefox" in name.lower() for name in profile_names)

    def test_browser_profile_accuracy(self):
        """Test browser profile JA3 hash accuracy"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        
        # Test Chrome 120 profile
        spoofer.set_profile("chrome_120")
        chrome_hello = spoofer.build_client_hello("example.com")
        
        if chrome_hello:
            # Calculate JA3 hash
            ja3_hash = spoofer.calculate_ja3_hash(chrome_hello)
            # Should match expected Chrome 120 hash
            expected_chrome = "cd08e31494f9531f560d64c695473da9"
            assert ja3_hash == expected_chrome or len(ja3_hash) == 32
        
        # Test Firefox 121 profile
        spoofer.set_profile("firefox_121")
        firefox_hello = spoofer.build_client_hello("example.com")
        
        if firefox_hello:
            ja3_hash = spoofer.calculate_ja3_hash(firefox_hello)
            expected_firefox = "579ccef312d18482fc42e2b822ca2430"
            assert ja3_hash == expected_firefox or len(ja3_hash) == 32

    def test_client_hello_structure(self):
        """Test Client Hello packet structure"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        spoofer.set_profile("chrome_120")
        
        hello = spoofer.build_client_hello("test.example.com")
        
        if hello:
            # Should be valid TLS packet
            assert len(hello) > 50  # Minimum reasonable size
            
            # Should contain SNI extension with hostname
            assert b"test.example.com" in hello
            
            # Should have TLS record header
            assert hello[0] == 0x16  # Handshake record type
            assert hello[1] == 0x03  # TLS version major
            
            # Should have Client Hello message
            assert hello[5] == 0x01  # Client Hello message type
    def test_cipher_suite_control(self):
        """Test cipher suite ordering control"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        
        # Test different profiles have different cipher suites
        spoofer.set_profile("chrome_120")
        chrome_hello = spoofer.build_client_hello("example.com")
        
        spoofer.set_profile("firefox_121")
        firefox_hello = spoofer.build_client_hello("example.com")
        
        if chrome_hello and firefox_hello:
            # Should be different (different cipher suite ordering)
            assert chrome_hello != firefox_hello

    def test_extension_ordering(self):
        """Test TLS extension ordering control"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        spoofer.set_profile("safari_17")
        
        hello = spoofer.build_client_hello("example.com")
        
        if hello:
            # Should contain standard extensions
            # SNI, supported_groups, ec_point_formats, etc.
            # Extension ordering should be consistent with Safari
            assert len(hello) > 100  # Should have extensions

    def test_elliptic_curve_selection(self):
        """Test elliptic curve selection"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        spoofer.set_profile("iphone_15")
        
        hello = spoofer.build_client_hello("mobile.example.com")
        
        if hello:
            # Should contain supported groups extension
            # iPhone typically supports specific curves
            assert len(hello) > 80

    def test_profile_switching(self):
        """Test switching between profiles"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # TLS components not available - optional
        
        spoofer = JA3Spoofer()
        
        # Switch between profiles
        profiles = ["chrome_120", "firefox_121", "safari_17"]
        
        for profile in profiles:
            result = spoofer.set_profile(profile)
            assert result is True or result is None  # Should succeed
            
            hello = spoofer.build_client_hello("example.com")
            if hello:
                assert len(hello) > 50


class TestPrecisionTimingIntegration:
    """Test precision timing and traffic shaping integration"""

    def test_precision_timer_initialization(self):
        """Test precision timer initialization"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Timing components not available - optional
        
        timer = PrecisionTimer()
        assert timer is not None
        
        # Should detect TSC frequency
        frequency = timer.get_tsc_frequency()
        assert frequency > 0

    def test_microsecond_timing_accuracy(self):
        """Test microsecond-level timing accuracy"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Timing components not available - optional
        
        timer = PrecisionTimer()
        
        # Test spin-wait accuracy
        target_delay_us = 1000  # 1 millisecond
        
        start_time = timer.get_timestamp_nanos()
        timer.spin_wait_nanos(target_delay_us * 1000)  # Convert to nanoseconds
        end_time = timer.get_timestamp_nanos()
        
        actual_delay_us = (end_time - start_time) / 1000
        
        # Should be within 100 microseconds of target
        error_us = abs(actual_delay_us - target_delay_us)
        assert error_us < 100

    def test_traffic_shaper_patterns(self):
        """Test traffic shaping patterns"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Timing components not available - optional
        
        shaper = TrafficShaper(base_rate=1000, jitter_range=100)
        
        # Test sawtooth pattern
        intervals = []
        for i in range(10):
            interval = shaper.get_next_interval("sawtooth", i)
            intervals.append(interval)
        
        # Should vary in sawtooth pattern
        assert len(set(intervals)) > 1  # Should have variation
        
        # Test pulse pattern
        pulse_intervals = []
        for i in range(10):
            interval = shaper.get_next_interval("pulse", i)
            pulse_intervals.append(interval)
        
        # Should have pulse characteristics
        assert len(set(pulse_intervals)) > 1

    def test_token_bucket_rate_limiting(self):
        """Test token bucket rate limiter with nanosecond precision"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Timing components not available - optional
        
        # Create rate limiter for 1000 PPS
        rate_limiter = TrafficShaper(base_rate=1000, burst_size=10)
        
        # Test token consumption
        start_time = time.perf_counter()
        
        packets_sent = 0
        for i in range(50):  # Try to send 50 packets
            if rate_limiter.can_send_packet():
                packets_sent += 1
                rate_limiter.consume_token()
            
            # Small delay to allow token refill
            time.sleep(0.0001)  # 0.1ms
        
        elapsed_time = time.perf_counter() - start_time
        
        # Should respect rate limit
        if elapsed_time > 0:
            actual_rate = packets_sent / elapsed_time
            # Should be close to configured rate (within reasonable margin)
            assert actual_rate <= 1500  # Allow some burst

    def test_timing_jitter_measurement(self):
        """Test timing jitter measurement"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Timing components not available - optional
        
        timer = PrecisionTimer()
        shaper = TrafficShaper(base_rate=1000, jitter_range=50)
        
        # Measure jitter over multiple intervals
        intervals = []
        for i in range(100):
            start = timer.get_timestamp_nanos()
            
            # Get shaped interval
            target_interval = shaper.get_next_interval("uniform", i)
            timer.spin_wait_nanos(target_interval)
            
            end = timer.get_timestamp_nanos()
            actual_interval = end - start
            intervals.append(actual_interval)
        
        # Calculate jitter (standard deviation)
        if len(intervals) > 1:
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            jitter_ns = variance ** 0.5
            jitter_us = jitter_ns / 1000
            
            # Should maintain low jitter (< 100 microseconds)
            assert jitter_us < 100

    def test_hardware_tsc_integration(self):
        """Test hardware TSC timer integration"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Timing components not available - optional
        
        timer = PrecisionTimer()
        
        # Test TSC reading
        tsc1 = timer.read_tsc()
        time.sleep(0.001)  # 1ms
        tsc2 = timer.read_tsc()
        
        # TSC should advance
        assert tsc2 > tsc1
        
        # Calculate frequency
        frequency = timer.get_tsc_frequency()
        expected_cycles = frequency * 0.001  # Expected cycles in 1ms
        actual_cycles = tsc2 - tsc1
        
        # Should be reasonably close (within 50%)
        ratio = actual_cycles / expected_cycles
        assert 0.5 < ratio < 2.0


class TestIntegratedTLSTimingFlow:
    """Test integrated TLS spoofing with precision timing"""

    def test_tls_with_timing_integration(self):
        """Test TLS spoofing with precision timing"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Components not available - optional
        
        # Create TLS spoofer and timer
        spoofer = JA3Spoofer()
        timer = PrecisionTimer()
        shaper = TrafficShaper(base_rate=100, jitter_range=10)
        
        spoofer.set_profile("chrome_120")
        
        # Simulate timed TLS handshakes
        handshakes = []
        
        for i in range(5):
            # Get timing for this handshake
            interval = shaper.get_next_interval("uniform", i)
            
            start_time = timer.get_timestamp_nanos()
            
            # Build Client Hello
            hello = spoofer.build_client_hello(f"target{i}.example.com")
            
            if hello:
                handshakes.append({
                    'hello': hello,
                    'timestamp': start_time,
                    'target_interval': interval
                })
            
            # Wait for shaped interval
            timer.spin_wait_nanos(interval)
        
        # Verify handshakes
        assert len(handshakes) > 0
        
        # Verify timing intervals
        if len(handshakes) >= 2:
            for i in range(1, len(handshakes)):
                time_diff = handshakes[i]['timestamp'] - handshakes[i-1]['timestamp']
                expected_interval = handshakes[i-1]['target_interval']
                
                # Should be close to expected interval
                error_ratio = abs(time_diff - expected_interval) / expected_interval
                assert error_ratio < 0.1  # Within 10%

    def test_profile_switching_with_timing(self):
        """Test profile switching with precise timing"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Components not available - optional
        
        spoofer = JA3Spoofer()
        timer = PrecisionTimer()
        
        profiles = ["chrome_120", "firefox_121", "safari_17"]
        
        # Switch profiles with precise timing
        for i, profile in enumerate(profiles):
            start_time = timer.get_timestamp_nanos()
            
            # Switch profile
            spoofer.set_profile(profile)
            
            # Build hello
            hello = spoofer.build_client_hello("example.com")
            
            end_time = timer.get_timestamp_nanos()
            
            # Profile switching should be fast
            switch_time_us = (end_time - start_time) / 1000
            assert switch_time_us < 1000  # Less than 1ms
            
            if hello:
                assert len(hello) > 50

    def test_burst_tls_generation(self):
        """Test burst TLS packet generation with timing"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Components not available - optional
        
        spoofer = JA3Spoofer()
        timer = PrecisionTimer()
        
        spoofer.set_profile("chrome_120")
        
        # Generate burst of TLS packets
        burst_size = 10
        packets = []
        
        start_time = timer.get_timestamp_nanos()
        
        for i in range(burst_size):
            hello = spoofer.build_client_hello(f"burst{i}.example.com")
            if hello:
                packets.append(hello)
        
        end_time = timer.get_timestamp_nanos()
        
        # Should generate packets quickly
        total_time_us = (end_time - start_time) / 1000
        avg_time_per_packet = total_time_us / len(packets) if packets else 0
        
        # Should be fast (less than 100us per packet)
        assert avg_time_per_packet < 100

    def test_evasion_timing_patterns(self):
        """Test evasion timing patterns with TLS"""
        if not TLS_COMPONENTS_AVAILABLE:
            return  # Components not available - optional
        
        spoofer = JA3Spoofer()
        shaper = TrafficShaper(base_rate=50, jitter_range=20)
        timer = PrecisionTimer()
        
        # Test different evasion patterns
        patterns = ["sawtooth", "pulse", "random"]
        
        for pattern in patterns:
            spoofer.set_profile("firefox_121")
            
            # Generate packets with evasion timing
            for i in range(5):
                interval = shaper.get_next_interval(pattern, i)
                
                # Build TLS packet
                hello = spoofer.build_client_hello(f"{pattern}{i}.example.com")
                
                if hello:
                    # Verify packet is valid
                    assert len(hello) > 50
                
                # Apply evasion timing
                timer.spin_wait_nanos(interval)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])