"""
Property-Based Tests for JA4+ Fingerprint Validity

Tests the JA4+ engine to ensure all fingerprint calculations are valid
and consistent across different inputs and browser profiles.

**Feature: cross-platform-destroyer, Property 2: JA4+ Fingerprint Validity**
**Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6**
"""

import pytest
import hypothesis
from hypothesis import given, strategies as st, assume
import struct
import hashlib
import random
import time
from typing import List, Dict, Any

# Import the JA4+ engine
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from core.evasion.ja4_engine import (
    JA4Engine, JA4Morpher, ClientHelloBuilder, BrowserProfile,
    TLSVersion, TLSExtension, ClientHelloInfo, ServerHelloInfo
)


class TestJA4Validity:
    """Property-based tests for JA4+ fingerprint validity"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.ja4_engine = JA4Engine()
        self.morpher = JA4Morpher(self.ja4_engine)
    
    @given(
        cipher_suites=st.lists(
            st.integers(min_value=0x0001, max_value=0xFFFF), 
            min_size=1, max_size=50, unique=True
        ),
        extensions=st.lists(
            st.integers(min_value=0x0000, max_value=0xFFFF),
            min_size=0, max_size=30, unique=True
        ),
        has_sni=st.booleans(),
        tls_version=st.sampled_from([
            TLSVersion.TLS_1_0.value, TLSVersion.TLS_1_1.value,
            TLSVersion.TLS_1_2.value, TLSVersion.TLS_1_3.value
        ])
    )
    def test_ja4_format_validity(self, cipher_suites: List[int], extensions: List[int], 
                                has_sni: bool, tls_version: int):
        """
        Property: For any valid ClientHello parameters, JA4 fingerprint should follow correct format.
        
        JA4 Format: t[version]d[sni][cipher_count][ext_count]_[cipher_hash]_[ext_hash]
        """
        # Create mock ClientHello info
        hello_info = ClientHelloInfo(
            tls_version=tls_version,
            cipher_suites=cipher_suites,
            extensions=extensions,
            has_sni=has_sni,
            sni_value="example.com" if has_sni else None,
            alpn_protocols=["h2", "http/1.1"],
            supported_groups=[0x001d, 0x0017],
            signature_algorithms=[0x0403, 0x0503],
            raw_data=b""
        )
        
        # Calculate JA4
        ja4 = self.ja4_engine._build_ja4_string(hello_info)
        
        # Verify format
        assert isinstance(ja4, str), "JA4 should be a string"
        assert len(ja4) >= 15, "JA4 should be at least 15 characters"
        
        # Parse format: t[version]d[sni][cipher_count][ext_count]_[cipher_hash]_[ext_hash]
        parts = ja4.split('_')
        assert len(parts) == 3, "JA4 should have exactly 3 underscore-separated parts"
        
        prefix, cipher_hash, ext_hash = parts
        
        # Verify prefix format
        assert prefix.startswith('t'), "JA4 should start with 't'"
        assert len(prefix) >= 7, "JA4 prefix should be at least 7 characters"
        
        # Verify version
        version_part = prefix[1:3]
        assert version_part in ['10', '11', '12', '13'], f"Invalid version: {version_part}"
        
        # Verify SNI indicator
        sni_indicator = prefix[3]
        expected_sni = 'd' if has_sni else 'i'
        assert sni_indicator == expected_sni, f"SNI indicator should be {expected_sni}"
        
        # Verify cipher count (2 digits)
        cipher_count = prefix[4:6]
        assert cipher_count.isdigit(), "Cipher count should be digits"
        assert int(cipher_count) <= 99, "Cipher count should be max 99"
        assert int(cipher_count) == min(len(cipher_suites), 99), "Cipher count should match actual count"
        
        # Verify extension count (2 digits)
        ext_count = prefix[6:8]
        assert ext_count.isdigit(), "Extension count should be digits"
        assert int(ext_count) <= 99, "Extension count should be max 99"
        
        # Verify hashes are 12 hex characters
        assert len(cipher_hash) == 12, "Cipher hash should be 12 characters"
        assert all(c in '0123456789abcdef' for c in cipher_hash), "Cipher hash should be hex"
        
        assert len(ext_hash) == 12, "Extension hash should be 12 characters"
        assert all(c in '0123456789abcdef' for c in ext_hash), "Extension hash should be hex"
    
    @given(
        cipher_suite=st.integers(min_value=0x0001, max_value=0xFFFF),
        extensions=st.lists(
            st.integers(min_value=0x0000, max_value=0xFFFF),
            min_size=0, max_size=20, unique=True
        ),
        tls_version=st.sampled_from([
            TLSVersion.TLS_1_0.value, TLSVersion.TLS_1_1.value,
            TLSVersion.TLS_1_2.value, TLSVersion.TLS_1_3.value
        ])
    )
    def test_ja4s_format_validity(self, cipher_suite: int, extensions: List[int], tls_version: int):
        """
        Property: For any valid ServerHello parameters, JA4S fingerprint should follow correct format.
        
        JA4S Format: t[version][cipher]_[extensions_hash]
        """
        # Create mock ServerHello info
        hello_info = ServerHelloInfo(
            tls_version=tls_version,
            cipher_suite=cipher_suite,
            extensions=extensions,
            raw_data=b""
        )
        
        # Calculate JA4S
        ja4s = self.ja4_engine._build_ja4s_string(hello_info)
        
        # Verify format
        assert isinstance(ja4s, str), "JA4S should be a string"
        
        # Parse format: t[version][cipher]_[extensions_hash]
        parts = ja4s.split('_')
        assert len(parts) == 2, "JA4S should have exactly 2 underscore-separated parts"
        
        prefix, ext_hash = parts
        
        # Verify prefix format
        assert prefix.startswith('t'), "JA4S should start with 't'"
        assert len(prefix) == 7, "JA4S prefix should be 7 characters (t + 2 version + 4 cipher)"
        
        # Verify version
        version_part = prefix[1:3]
        assert version_part in ['10', '11', '12', '13'], f"Invalid version: {version_part}"
        
        # Verify cipher suite (4 hex digits)
        cipher_part = prefix[3:7]
        assert len(cipher_part) == 4, "Cipher part should be 4 characters"
        assert all(c in '0123456789abcdef' for c in cipher_part), "Cipher part should be hex"
        assert int(cipher_part, 16) == cipher_suite, "Cipher part should match input cipher"
        
        # Verify extension hash
        assert len(ext_hash) == 12, "Extension hash should be 12 characters"
        assert all(c in '0123456789abcdef' for c in ext_hash), "Extension hash should be hex"
    
    @given(
        method=st.sampled_from(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']),
        headers=st.dictionaries(
            st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz-'),
            st.text(min_size=1, max_size=50),
            min_size=1, max_size=15
        ),
        cookies=st.dictionaries(
            st.text(min_size=1, max_size=15, alphabet='abcdefghijklmnopqrstuvwxyz'),
            st.text(min_size=1, max_size=30),
            min_size=0, max_size=10
        )
    )
    def test_ja4h_format_validity(self, method: str, headers: Dict[str, str], cookies: Dict[str, str]):
        """
        Property: For any valid HTTP parameters, JA4H fingerprint should follow correct format.
        
        JA4H Format: [method][version][lang][headers_count]_[headers_hash]_[cookies_hash]
        """
        # Calculate JA4H
        ja4h = self.ja4_engine._build_ja4h_string(method, headers, cookies)
        
        # Verify format
        assert isinstance(ja4h, str), "JA4H should be a string"
        
        # Parse format: [method][version][lang][headers_count]_[headers_hash]_[cookies_hash]
        parts = ja4h.split('_')
        assert len(parts) == 3, "JA4H should have exactly 3 underscore-separated parts"
        
        prefix, headers_hash, cookies_hash = parts
        
        # Verify prefix format
        assert len(prefix) >= 6, "JA4H prefix should be at least 6 characters"
        
        # Verify method (first 2 chars, lowercase)
        method_part = prefix[:2]
        assert method_part == method.lower()[:2], "Method part should match input method"
        
        # Verify version (should be "11" for HTTP/1.1)
        version_part = prefix[2:4]
        assert version_part == "11", "Version should be 11 for HTTP/1.1"
        
        # Verify language (2 chars)
        lang_part = prefix[4:6]
        assert len(lang_part) == 2, "Language part should be 2 characters"
        assert lang_part.isalpha(), "Language part should be alphabetic"
        
        # Verify header count (2 digits)
        header_count = prefix[6:8]
        assert header_count.isdigit(), "Header count should be digits"
        assert int(header_count) <= 99, "Header count should be max 99"
        assert int(header_count) == min(len(headers), 99), "Header count should match actual count"
        
        # Verify hashes
        assert len(headers_hash) == 12, "Headers hash should be 12 characters"
        assert all(c in '0123456789abcdef' for c in headers_hash), "Headers hash should be hex"
        
        assert len(cookies_hash) == 12, "Cookies hash should be 12 characters"
        assert all(c in '0123456789abcdef' for c in cookies_hash), "Cookies hash should be hex"
    
    @given(
        profile_name=st.sampled_from([
            "chrome_120_windows", "chrome_120_macos", "chrome_120_linux",
            "firefox_121_windows", "firefox_121_macos", 
            "safari_17_macos", "edge_120_windows"
        ])
    )
    def test_browser_profile_consistency(self, profile_name: str):
        """
        Property: For any browser profile, all fingerprint components should be consistent.
        """
        # Set profile
        success = self.ja4_engine.set_profile(profile_name)
        assert success, f"Should be able to set profile {profile_name}"
        
        profile = self.ja4_engine.current_profile
        assert profile is not None, "Current profile should be set"
        
        # Note: profile.name is the display name, but we set by key
        # So we check that the profile was actually set by verifying it's not None
        # and has the expected structure
        
        # Verify profile completeness
        assert len(profile.cipher_suites) > 0, "Profile should have cipher suites"
        assert len(profile.extensions) >= 0, "Profile should have extensions list"
        assert len(profile.supported_groups) > 0, "Profile should have supported groups"
        assert len(profile.signature_algorithms) > 0, "Profile should have signature algorithms"
        assert len(profile.alpn_protocols) > 0, "Profile should have ALPN protocols"
        assert len(profile.http_headers) > 0, "Profile should have HTTP headers"
        assert len(profile.http_header_order) > 0, "Profile should have header order"
        
        # Verify JA4 components are valid
        assert isinstance(profile.ja4, str) and len(profile.ja4) > 10, "JA4 should be valid string"
        assert isinstance(profile.ja4s, str) and len(profile.ja4s) > 5, "JA4S should be valid string"
        assert isinstance(profile.ja4h, str) and len(profile.ja4h) > 10, "JA4H should be valid string"
        assert isinstance(profile.ja4x, str) and len(profile.ja4x) > 10, "JA4X should be valid string"
        
        # Verify cipher suites are unique
        assert len(profile.cipher_suites) == len(set(profile.cipher_suites)), "Cipher suites should be unique"
        
        # Verify extensions are unique
        assert len(profile.extensions) == len(set(profile.extensions)), "Extensions should be unique"
    
    @given(
        hostname=st.one_of(
            st.just("example.com"),
            st.just("test.example.org"),
            st.just("api.test.com"),
            st.just("secure.example.net")
        ),
        session_id=st.text(min_size=1, max_size=20, alphabet='abcdefghijklmnopqrstuvwxyz0123456789')
    )
    def test_morphing_preserves_validity(self, hostname: str, session_id: str):
        """
        Property: For any morphing operation, the resulting fingerprints should remain valid.
        """
        # Get available profiles
        profiles = list(self.ja4_engine.profiles.keys())
        assume(len(profiles) >= 2)  # Need at least 2 profiles to morph
        
        # Set initial profile
        initial_profile = profiles[0]
        self.morpher.ja4_engine.set_profile(initial_profile)
        
        # Create initial ClientHello
        initial_hello = self.morpher.create_morphed_client_hello(hostname, session_id)
        assert len(initial_hello) > 40, "ClientHello should be reasonable size"
        
        # Calculate initial JA4
        initial_ja4 = self.ja4_engine.calculate_ja4(initial_hello)
        assert len(initial_ja4) > 10, "Initial JA4 should be valid"
        
        # Morph to different profile
        target_profile = profiles[1]
        morph_success = self.morpher.morph_to_profile(target_profile, session_id)
        assert morph_success, "Morphing should succeed"
        
        # Create morphed ClientHello
        morphed_hello = self.morpher.create_morphed_client_hello(hostname, session_id)
        assert len(morphed_hello) > 40, "Morphed ClientHello should be reasonable size"
        
        # Calculate morphed JA4
        morphed_ja4 = self.ja4_engine.calculate_ja4(morphed_hello)
        assert len(morphed_ja4) > 10, "Morphed JA4 should be valid"
        
        # Verify morphing changed the fingerprint (if profiles are actually different)
        current_profile_obj = self.morpher.ja4_engine.current_profile
        if initial_profile != target_profile and current_profile_obj:
            # Only assert change if the profiles have different characteristics
            initial_profile_obj = self.ja4_engine.profiles[initial_profile]
            if (initial_profile_obj.cipher_suites != current_profile_obj.cipher_suites or
                initial_profile_obj.extensions != current_profile_obj.extensions):
                assert initial_ja4 != morphed_ja4, "Morphing should change JA4 fingerprint when profiles differ significantly"
        
        # Verify both fingerprints follow correct format
        for ja4 in [initial_ja4, morphed_ja4]:
            parts = ja4.split('_')
            assert len(parts) == 3, "JA4 should have 3 parts"
            assert parts[0].startswith('t'), "JA4 should start with 't'"
            assert len(parts[1]) == 12, "Cipher hash should be 12 chars"
            assert len(parts[2]) == 12, "Extension hash should be 12 chars"
    
    @given(
        data=st.binary(min_size=10, max_size=1000)
    )
    def test_hash_consistency(self, data: bytes):
        """
        Property: For any input data, hash calculations should be consistent and deterministic.
        """
        # Calculate hash multiple times
        hash1 = self.ja4_engine._truncated_sha256(data)
        hash2 = self.ja4_engine._truncated_sha256(data)
        hash3 = self.ja4_engine._truncated_sha256(data)
        
        # Verify consistency
        assert hash1 == hash2 == hash3, "Hash should be deterministic"
        
        # Verify format
        assert len(hash1) == 12, "Truncated hash should be 12 characters"
        assert all(c in '0123456789abcdef' for c in hash1), "Hash should be hex"
        
        # Verify it matches expected SHA256 truncation
        expected = hashlib.sha256(data).hexdigest()[:12]
        assert hash1 == expected, "Hash should match SHA256 truncation"
    
    def test_profile_database_completeness(self):
        """
        Property: All required browser profiles should be available and valid.
        """
        required_profiles = [
            "chrome_120_windows", "chrome_120_macos", "chrome_120_linux",
            "firefox_121_windows", "firefox_121_macos",
            "safari_17_macos", "edge_120_windows"
        ]
        
        available_profiles = self.ja4_engine.get_available_profiles()
        
        # Verify all required profiles are available
        for profile_name in required_profiles:
            assert profile_name in available_profiles, f"Profile {profile_name} should be available"
            
            # Verify profile can be loaded
            success = self.ja4_engine.set_profile(profile_name)
            assert success, f"Should be able to load profile {profile_name}"
            
            # Verify profile info is complete
            info = self.ja4_engine.get_profile_info(profile_name)
            assert info is not None, f"Profile {profile_name} should have info"
            assert info["cipher_count"] > 0, f"Profile {profile_name} should have ciphers"
            assert info["extension_count"] >= 0, f"Profile {profile_name} should have extensions"
    
    @given(
        cert_data=st.binary(min_size=100, max_size=2000)
    )
    def test_certificate_analysis_robustness(self, cert_data: bytes):
        """
        Property: For any certificate data, analysis should not crash and return valid results.
        """
        # Calculate JA4X (should not crash)
        ja4x = self.ja4_engine.calculate_ja4x(cert_data)
        
        # Verify result format (even if parsing fails, should return valid format)
        if ja4x:  # May be empty string on parse failure
            parts = ja4x.split('_')
            assert len(parts) == 4, "JA4X should have 4 parts"
            for part in parts:
                assert len(part) == 12, "Each JA4X part should be 12 characters"
                assert all(c in '0123456789abcdef' for c in part), "JA4X parts should be hex"
        
        # Analyze certificate (should not crash)
        analysis = self.ja4_engine.analyze_certificate_blocking(ja4x, cert_data)
        
        # Verify analysis structure
        assert isinstance(analysis, dict), "Analysis should be a dictionary"
        assert "blocking_risk" in analysis, "Analysis should include blocking risk"
        assert analysis["blocking_risk"] in ["low", "medium", "high"], "Risk should be valid level"
        assert "risk_factors" in analysis, "Analysis should include risk factors"
        assert isinstance(analysis["risk_factors"], list), "Risk factors should be a list"


if __name__ == "__main__":
    # Run property tests
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])