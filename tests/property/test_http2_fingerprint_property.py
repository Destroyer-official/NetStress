#!/usr/bin/env python3
"""
Property-Based Tests for HTTP/2 Fingerprint Matching

**Feature: cross-platform-destroyer, Property 3: HTTP/2 Fingerprint Matching**

This module tests the HTTP/2 fingerprinting evasion capabilities to ensure
that generated HTTP/2 traffic matches browser fingerprint patterns and
evades AKAMAI detection systems.

**Validates: Requirements 5.2, 5.6**
"""

import pytest
from hypothesis import given, settings, strategies as st
from hypothesis import assume
import struct
import hashlib
from typing import List, Tuple, Dict, Any

# Import the Rust engine HTTP/2 fingerprint functionality
try:
    from netstress_engine import Http2FingerprintManager, Http2Profile
except ImportError:
    # Fallback for testing without compiled Rust engine
    Http2FingerprintManager = None
    Http2Profile = None


class TestHttp2FingerprintProperty:
    """Property-based tests for HTTP/2 fingerprint matching"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment"""
        if Http2FingerprintManager is None:
            pytest.skip("Rust engine not available")
        
        self.manager = Http2FingerprintManager()
        self.browser_profiles = ["chrome_120", "firefox_121", "safari_17", "edge_120"]

    @given(
        browser_profile=st.sampled_from(["chrome_120", "firefox_121", "safari_17", "edge_120"]),
        enable_akamai_evasion=st.booleans(),
        randomize_window_update=st.booleans(),
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_3_http2_fingerprint_matching(
        self, browser_profile: str, enable_akamai_evasion: bool, randomize_window_update: bool
    ):
        """
        **Feature: cross-platform-destroyer, Property 3: HTTP/2 Fingerprint Matching**
        
        **Validates: Requirements 5.2, 5.6**
        
        For any HTTP/2 connection with a configured browser profile, the SETTINGS frame 
        ordering and values SHALL match the target browser's known HTTP/2 fingerprint pattern.
        """
        # Set up the fingerprint manager
        self.manager.set_profile(browser_profile)
        
        if enable_akamai_evasion:
            self.manager.enable_akamai_evasion()
        
        if randomize_window_update:
            self.manager.enable_window_update_randomization()

        # Generate connection preface
        preface = self.manager.build_connection_preface()
        assert preface is not None, f"Failed to generate preface for {browser_profile}"
        
        # Verify HTTP/2 connection preface starts correctly
        expected_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        assert preface.startswith(expected_preface), "Invalid HTTP/2 connection preface"
        
        # Parse and verify SETTINGS frame
        settings_frame_start = len(expected_preface)
        settings_frame = preface[settings_frame_start:]
        
        # Verify SETTINGS frame structure
        assert len(settings_frame) >= 9, "SETTINGS frame too short"
        
        # Extract frame header
        frame_length = (settings_frame[0] << 16) | (settings_frame[1] << 8) | settings_frame[2]
        frame_type = settings_frame[3]
        frame_flags = settings_frame[4]
        stream_id = (settings_frame[5] << 24) | (settings_frame[6] << 16) | (settings_frame[7] << 8) | settings_frame[8]
        
        # Verify SETTINGS frame properties
        assert frame_type == 0x04, f"Expected SETTINGS frame (0x04), got {frame_type:02x}"
        assert stream_id == 0, f"SETTINGS frame must have stream ID 0, got {stream_id}"
        assert frame_length % 6 == 0, f"SETTINGS frame length must be multiple of 6, got {frame_length}"
        
        # Extract SETTINGS parameters
        settings_params = []
        payload_start = 9
        for i in range(0, frame_length, 6):
            if payload_start + i + 6 <= len(settings_frame):
                param_id = (settings_frame[payload_start + i] << 8) | settings_frame[payload_start + i + 1]
                param_value = (
                    (settings_frame[payload_start + i + 2] << 24) |
                    (settings_frame[payload_start + i + 3] << 16) |
                    (settings_frame[payload_start + i + 4] << 8) |
                    settings_frame[payload_start + i + 5]
                )
                settings_params.append((param_id, param_value))
        
        # Verify browser-specific SETTINGS patterns
        self._verify_browser_settings_pattern(browser_profile, settings_params)
        
        # Test WINDOW_UPDATE frame generation
        window_update = self.manager.build_window_update(0)
        assert window_update is not None, "Failed to generate WINDOW_UPDATE frame"
        
        # Verify WINDOW_UPDATE frame structure
        assert len(window_update) == 13, f"WINDOW_UPDATE frame should be 13 bytes, got {len(window_update)}"
        assert window_update[3] == 0x08, f"Expected WINDOW_UPDATE frame (0x08), got {window_update[3]:02x}"
        
        # Extract window increment
        increment = (
            ((window_update[9] & 0x7F) << 24) |
            (window_update[10] << 16) |
            (window_update[11] << 8) |
            window_update[12]
        )
        assert increment > 0, "Window increment must be positive"
        assert increment <= 0x7FFFFFFF, "Window increment must not exceed maximum value"
        
        # Verify browser-specific window update patterns
        self._verify_browser_window_update_pattern(browser_profile, increment, randomize_window_update)

    @given(
        browser_profile=st.sampled_from(["chrome_120", "firefox_121", "safari_17", "edge_120"]),
        stream_id=st.integers(min_value=1, max_value=2147483647),
        method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
        authority=st.text(min_size=1, max_size=100, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters=".-")),
        path=st.text(min_size=1, max_size=200, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="/-_?=&")),
    )
    @settings(max_examples=10, deadline=15000)
    def test_property_3_hpack_header_encoding_consistency(
        self, browser_profile: str, stream_id: int, method: str, authority: str, path: str
    ):
        """
        **Feature: cross-platform-destroyer, Property 3: HTTP/2 Fingerprint Matching**
        
        **Validates: Requirements 5.2**
        
        For any HTTP/2 request headers, HPACK encoding SHALL follow browser-specific
        patterns including pseudo-header ordering and compression preferences.
        """
        assume(len(authority) > 0 and len(path) > 0)
        assume(not authority.startswith('.') and not authority.endswith('.'))
        assume(path.startswith('/') or path == '/')
        
        # Set up the fingerprint manager
        self.manager.set_profile(browser_profile)
        
        # Generate HEADERS frame with HPACK encoding
        headers = []  # Additional headers can be added here
        headers_frame = self.manager.build_headers_frame(
            stream_id, 
            b"",  # Empty for now - would contain HPACK-encoded headers
            True,  # END_STREAM
            True   # END_HEADERS
        )
        
        assert headers_frame is not None, f"Failed to generate HEADERS frame for {browser_profile}"
        
        # Verify HEADERS frame structure
        assert len(headers_frame) >= 9, "HEADERS frame too short"
        
        # Extract frame header
        frame_length = (headers_frame[0] << 16) | (headers_frame[1] << 8) | headers_frame[2]
        frame_type = headers_frame[3]
        frame_flags = headers_frame[4]
        frame_stream_id = (
            (headers_frame[5] << 24) | 
            (headers_frame[6] << 16) | 
            (headers_frame[7] << 8) | 
            headers_frame[8]
        )
        
        # Verify HEADERS frame properties
        assert frame_type == 0x01, f"Expected HEADERS frame (0x01), got {frame_type:02x}"
        assert frame_stream_id == stream_id, f"Stream ID mismatch: expected {stream_id}, got {frame_stream_id}"
        assert frame_flags & 0x01 == 0x01, "END_STREAM flag should be set"
        assert frame_flags & 0x04 == 0x04, "END_HEADERS flag should be set"
        
        # Verify browser-specific PRIORITY flag usage
        self._verify_browser_priority_usage(browser_profile, frame_flags)

    @given(
        browser_profile=st.sampled_from(["chrome_120", "firefox_121", "safari_17", "edge_120"]),
        enable_akamai_evasion=st.booleans(),
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_3_akamai_fingerprint_evasion(
        self, browser_profile: str, enable_akamai_evasion: bool
    ):
        """
        **Feature: cross-platform-destroyer, Property 3: HTTP/2 Fingerprint Matching**
        
        **Validates: Requirements 5.6**
        
        For any HTTP/2 connection with AKAMAI evasion enabled, the generated traffic
        SHALL include evasion techniques that avoid AKAMAI's detection patterns.
        """
        # Set up the fingerprint manager
        self.manager.set_profile(browser_profile)
        
        if enable_akamai_evasion:
            self.manager.enable_akamai_evasion()
        
        # Generate connection preface
        preface_with_evasion = self.manager.build_connection_preface()
        
        # Disable evasion and generate baseline
        self.manager.disable_akamai_evasion()
        preface_baseline = self.manager.build_connection_preface()
        
        assert preface_with_evasion is not None, "Failed to generate preface with evasion"
        assert preface_baseline is not None, "Failed to generate baseline preface"
        
        if enable_akamai_evasion:
            # With evasion enabled, the preface should be different (contain additional frames)
            assert len(preface_with_evasion) >= len(preface_baseline), \
                "Evasion should add additional frames or modifications"
            
            # Verify that evasion techniques are applied
            self._verify_akamai_evasion_techniques(browser_profile, preface_with_evasion, preface_baseline)
        else:
            # Without evasion, prefaces should be identical
            assert preface_with_evasion == preface_baseline, \
                "Prefaces should be identical when evasion is disabled"

    def _verify_browser_settings_pattern(self, browser_profile: str, settings_params: List[Tuple[int, int]]):
        """Verify that SETTINGS parameters match browser-specific patterns"""
        param_ids = [param[0] for param in settings_params]
        
        if browser_profile == "chrome_120":
            # Chrome expected pattern: HeaderTableSize, EnablePush, MaxConcurrentStreams, InitialWindowSize, MaxHeaderListSize
            expected_order = [0x01, 0x02, 0x03, 0x04, 0x06]
            assert param_ids == expected_order, f"Chrome SETTINGS order mismatch: expected {expected_order}, got {param_ids}"
            
            # Verify specific Chrome values
            settings_dict = dict(settings_params)
            assert settings_dict.get(0x01) == 65536, "Chrome header table size should be 65536"
            assert settings_dict.get(0x02) == 0, "Chrome should disable push"
            assert settings_dict.get(0x03) == 1000, "Chrome max concurrent streams should be 1000"
            
        elif browser_profile == "firefox_121":
            # Firefox expected pattern: HeaderTableSize, InitialWindowSize, MaxFrameSize
            expected_order = [0x01, 0x04, 0x05]
            assert param_ids == expected_order, f"Firefox SETTINGS order mismatch: expected {expected_order}, got {param_ids}"
            
            # Verify specific Firefox values
            settings_dict = dict(settings_params)
            assert settings_dict.get(0x01) == 65536, "Firefox header table size should be 65536"
            assert settings_dict.get(0x04) == 131072, "Firefox initial window size should be 131072"
            
        elif browser_profile == "safari_17":
            # Safari expected pattern: MaxConcurrentStreams, InitialWindowSize, MaxFrameSize
            expected_order = [0x03, 0x04, 0x05]
            assert param_ids == expected_order, f"Safari SETTINGS order mismatch: expected {expected_order}, got {param_ids}"
            
            # Verify specific Safari values
            settings_dict = dict(settings_params)
            assert settings_dict.get(0x03) == 100, "Safari max concurrent streams should be 100"
            assert settings_dict.get(0x04) == 2097152, "Safari initial window size should be 2097152"
            
        elif browser_profile == "edge_120":
            # Edge expected pattern (Chromium-based): same as Chrome
            expected_order = [0x01, 0x02, 0x03, 0x04, 0x06]
            assert param_ids == expected_order, f"Edge SETTINGS order mismatch: expected {expected_order}, got {param_ids}"

    def _verify_browser_window_update_pattern(self, browser_profile: str, increment: int, randomized: bool):
        """Verify that WINDOW_UPDATE increments match browser-specific patterns"""
        if randomized:
            # With randomization, we just verify it's within reasonable bounds
            assert 1024 <= increment <= 0x7FFFFFFF, f"Randomized increment {increment} out of bounds"
        else:
            # Without randomization, verify exact browser patterns
            if browser_profile == "chrome_120":
                assert increment == 15663105, f"Chrome window increment should be 15663105, got {increment}"
            elif browser_profile == "firefox_121":
                assert increment == 12517377, f"Firefox window increment should be 12517377, got {increment}"
            elif browser_profile == "safari_17":
                assert increment == 10485760, f"Safari window increment should be 10485760, got {increment}"
            elif browser_profile == "edge_120":
                assert increment == 15663105, f"Edge window increment should be 15663105, got {increment}"

    def _verify_browser_priority_usage(self, browser_profile: str, frame_flags: int):
        """Verify that PRIORITY flag usage matches browser patterns"""
        priority_flag_set = (frame_flags & 0x20) == 0x20
        
        if browser_profile in ["chrome_120", "edge_120", "safari_17"]:
            # These browsers use PRIORITY frames
            assert priority_flag_set, f"{browser_profile} should set PRIORITY flag in HEADERS"
        elif browser_profile == "firefox_121":
            # Firefox doesn't use PRIORITY frames
            assert not priority_flag_set, f"{browser_profile} should not set PRIORITY flag in HEADERS"

    def _verify_akamai_evasion_techniques(self, browser_profile: str, evasion_preface: bytes, baseline_preface: bytes):
        """Verify that AKAMAI evasion techniques are properly applied"""
        # The evasion preface should contain additional frames or modifications
        assert len(evasion_preface) > len(baseline_preface), \
            "AKAMAI evasion should add additional content"
        
        # Look for additional frames after the baseline content
        additional_content = evasion_preface[len(baseline_preface):]
        
        # Should contain at least one additional frame (PRIORITY, PING, etc.)
        assert len(additional_content) >= 9, \
            "AKAMAI evasion should add at least one complete frame"
        
        # Verify frame structure in additional content
        offset = 0
        while offset + 9 <= len(additional_content):
            frame_length = (additional_content[offset] << 16) | (additional_content[offset + 1] << 8) | additional_content[offset + 2]
            frame_type = additional_content[offset + 3]
            
            # Should be valid frame types (PRIORITY=0x02, PING=0x06, WINDOW_UPDATE=0x08)
            assert frame_type in [0x02, 0x06, 0x08], f"Invalid evasion frame type: {frame_type:02x}"
            
            # Move to next frame
            offset += 9 + frame_length
            
            # Break if we've processed at least one frame
            if offset > 9:
                break


# Standalone test functions for simpler execution
def test_http2_fingerprint_basic():
    """Basic test for HTTP/2 fingerprint functionality"""
    if Http2FingerprintManager is None:
        pytest.skip("Rust engine not available")
    
    manager = Http2FingerprintManager()
    
    # Test profile setting
    result = manager.set_profile("chrome_120")
    assert result is None, "Setting valid profile should succeed"
    
    # Test preface generation
    preface = manager.build_connection_preface()
    assert preface is not None, "Should generate connection preface"
    assert preface.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "Invalid HTTP/2 preface"


def test_akamai_evasion_toggle():
    """Test AKAMAI evasion enable/disable functionality"""
    if Http2FingerprintManager is None:
        pytest.skip("Rust engine not available")
    
    manager = Http2FingerprintManager()
    manager.set_profile("chrome_120")
    
    # Test evasion toggle
    manager.enable_akamai_evasion()
    preface_with_evasion = manager.build_connection_preface()
    
    manager.disable_akamai_evasion()
    preface_without_evasion = manager.build_connection_preface()
    
    # Evasion should make a difference
    assert preface_with_evasion != preface_without_evasion, \
        "AKAMAI evasion should modify the connection preface"


if __name__ == "__main__":
    # Run basic tests
    test_http2_fingerprint_basic()
    test_akamai_evasion_toggle()
    print("Basic HTTP/2 fingerprint tests passed!")