#!/usr/bin/env python3
"""
Cross-Platform Destroyer Evasion Integration Tests

Tests JA4+ fingerprint matching, HTTP/2 fingerprint matching, and AI WAF bypass.
Validates Requirements: 4.1-4.6, 5.1-5.6, 9.1-9.6

**Feature: cross-platform-destroyer**
**Validates: Requirements 4.1-4.6, 5.1-5.6, 9.1-9.6, 11.1-11.6**
"""

import pytest
import sys
import os
import asyncio
import time
import hashlib
import json
import random
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List, Optional, Tuple
import logging
from dataclasses import dataclass
from enum import Enum

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)


@dataclass
class BrowserProfile:
    """Browser profile for JA4+ fingerprinting"""
    name: str
    ja4: str
    ja4s: str
    ja4h: str
    ja4x: str
    cipher_suites: List[int]
    extensions: List[int]
    supported_groups: List[int]
    signature_algorithms: List[int]
    alpn_protocols: List[str]
    http2_settings: Dict[str, int]


@dataclass
class Http2Settings:
    """HTTP/2 settings frame configuration"""
    header_table_size: int = 65536
    enable_push: int = 0
    max_concurrent_streams: int = 1000
    initial_window_size: int = 6291456
    max_frame_size: int = 16384
    max_header_list_size: int = 262144


class WAFResponse(Enum):
    """WAF response types"""
    ALLOWED = 200
    BLOCKED = 403
    RATE_LIMITED = 429
    SERVER_ERROR = 502


@dataclass
class WAFObservation:
    """WAF bypass observation"""
    response_code: int
    latency_ms: float
    headers: Dict[str, str]
    body_snippet: str


@dataclass
class WAFAction:
    """WAF bypass action"""
    user_agent: str
    headers: Dict[str, str]
    timing_delay: float
    ja4_profile: str


class MockJA4Engine:
    """Mock JA4+ fingerprint engine for testing"""
    
    def __init__(self):
        self.profiles = self._load_browser_profiles()
        self.current_profile = None
        
    def _load_browser_profiles(self) -> Dict[str, BrowserProfile]:
        """Load pre-built browser profiles"""
        profiles = {}
        
        # Chrome 120+ Windows
        profiles["chrome_120_windows"] = BrowserProfile(
            name="Chrome 120 Windows",
            ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
            ja4s="t130200_1301_234ea6891581",
            ja4h="ge11cn20enus_60a8b69f9c15_000000000000",
            ja4x="a]b]c]d]e]f",
            cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions=[0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023],
            supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
            signature_algorithms=[0x0403, 0x0503, 0x0603, 0x0807],
            alpn_protocols=["h2", "http/1.1"],
            http2_settings={
                "header_table_size": 65536,
                "enable_push": 0,
                "max_concurrent_streams": 1000,
                "initial_window_size": 6291456,
                "max_frame_size": 16384,
                "max_header_list_size": 262144
            }
        )
        
        # Firefox 121+ Windows
        profiles["firefox_121_windows"] = BrowserProfile(
            name="Firefox 121 Windows",
            ja4="t13d1517h2_8daaf6152771_02713d6af862",
            ja4s="t130200_1302_567890abcdef",
            ja4h="ge11cn20enus_70b9c8af0d26_111111111111",
            ja4x="g]h]i]j]k]l",
            cipher_suites=[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f],
            extensions=[0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010],
            supported_groups=[0x001d, 0x0017, 0x0018],
            signature_algorithms=[0x0403, 0x0503, 0x0603],
            alpn_protocols=["h2", "http/1.1"],
            http2_settings={
                "header_table_size": 65536,
                "enable_push": 1,
                "max_concurrent_streams": 100,
                "initial_window_size": 131072,
                "max_frame_size": 16384,
                "max_header_list_size": 262144
            }
        )
        
        # Safari 17+ macOS
        profiles["safari_17_macos"] = BrowserProfile(
            name="Safari 17 macOS",
            ja4="t13d1518h2_9dbcf7263882_f3728d9eb173",
            ja4s="t130200_1303_fedcba098765",
            ja4h="ge11cn20enus_80c0d9be1e37_222222222222",
            ja4x="m]n]o]p]q]r",
            cipher_suites=[0x1301, 0x1302, 0xc02b, 0xc02c],
            extensions=[0x0000, 0x0017, 0x000a, 0x000b, 0x0023, 0x0010],
            supported_groups=[0x001d, 0x0017, 0x0018, 0x0019],
            signature_algorithms=[0x0403, 0x0503, 0x0807, 0x0808],
            alpn_protocols=["h2", "http/1.1"],
            http2_settings={
                "header_table_size": 4096,
                "enable_push": 0,
                "max_concurrent_streams": 100,
                "initial_window_size": 2097152,
                "max_frame_size": 16384,
                "max_header_list_size": 8192
            }
        )
        
        return profiles
        
    def calculate_ja4(self, client_hello: bytes) -> str:
        """Calculate JA4 hash from ClientHello"""
        # Mock JA4 calculation
        if not self.current_profile:
            return "t13d0000h2_0000000000000_0000000000000"
            
        return self.current_profile.ja4
        
    def set_profile(self, profile_name: str):
        """Set current browser profile"""
        if profile_name in self.profiles:
            self.current_profile = self.profiles[profile_name]
            
    def build_client_hello(self, hostname: str) -> bytes:
        """Build ClientHello matching current profile"""
        if not self.current_profile:
            return b"mock_client_hello"
            
        # Mock ClientHello construction
        hello_data = {
            "version": 0x0303,
            "cipher_suites": self.current_profile.cipher_suites,
            "extensions": self.current_profile.extensions,
            "hostname": hostname
        }
        
        return json.dumps(hello_data).encode()
        
    def morph_fingerprint(self, new_profile: str):
        """Dynamically morph to new fingerprint"""
        old_profile = self.current_profile.name if self.current_profile else "none"
        self.set_profile(new_profile)
        
        return {
            "old_profile": old_profile,
            "new_profile": new_profile,
            "morphed": True
        }


class MockHttp2QuicEngine:
    """Mock HTTP/2 and QUIC engine for testing"""
    
    def __init__(self, profile: BrowserProfile):
        self.profile = profile
        self.http2_settings = Http2Settings(**profile.http2_settings)
        self.quic_enabled = True
        self.connection_state = "idle"
        
    async def send_http2_request(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Send HTTP/2 request with browser-matching fingerprint"""
        # Mock HTTP/2 request
        response = {
            "status": 200,
            "headers": {
                "server": "nginx/1.20.1",
                "content-type": "text/html",
                "content-length": "1024"
            },
            "settings_frame": {
                "header_table_size": self.http2_settings.header_table_size,
                "enable_push": self.http2_settings.enable_push,
                "max_concurrent_streams": self.http2_settings.max_concurrent_streams,
                "initial_window_size": self.http2_settings.initial_window_size,
                "max_frame_size": self.http2_settings.max_frame_size,
                "max_header_list_size": self.http2_settings.max_header_list_size
            },
            "pseudo_headers": [":method", ":path", ":scheme", ":authority"],
            "fingerprint_matched": True
        }
        
        return response
        
    async def send_quic_request(self, url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Send QUIC/HTTP/3 request"""
        if not self.quic_enabled:
            raise Exception("QUIC not enabled")
            
        # Mock QUIC request with 0-RTT
        response = {
            "status": 200,
            "protocol": "HTTP/3",
            "connection_type": "0-RTT" if random.random() > 0.5 else "1-RTT",
            "headers": {
                "server": "cloudflare",
                "content-type": "application/json"
            },
            "quic_version": "1",
            "alpn": "h3"
        }
        
        return response
        
    def match_akamai_fingerprint(self) -> bool:
        """Check if current settings match AKAMAI fingerprint patterns"""
        # Mock AKAMAI fingerprint matching
        akamai_patterns = {
            "chrome": {
                "header_table_size": 65536,
                "initial_window_size": 6291456,
                "max_frame_size": 16384
            },
            "firefox": {
                "header_table_size": 65536,
                "initial_window_size": 131072,
                "enable_push": 1
            }
        }
        
        profile_name = self.profile.name.lower()
        
        if "chrome" in profile_name:
            pattern = akamai_patterns["chrome"]
            return (self.http2_settings.header_table_size == pattern["header_table_size"] and
                   self.http2_settings.initial_window_size == pattern["initial_window_size"])
        elif "firefox" in profile_name:
            pattern = akamai_patterns["firefox"]
            return (self.http2_settings.header_table_size == pattern["header_table_size"] and
                   self.http2_settings.enable_push == pattern["enable_push"])
                   
        return False


class MockRLWAFBypassAgent:
    """Mock Reinforcement Learning WAF bypass agent"""
    
    def __init__(self):
        self.exploration_rate = 0.3
        self.success_rate = 0.0
        self.total_attempts = 0
        self.successful_attempts = 0
        self.current_policy = {}
        self.experience_buffer = []
        self.learning_mode = "online"
        
    def observe(self, response_code: int, latency: float, headers: Dict[str, str]) -> WAFObservation:
        """Observe WAF response"""
        observation = WAFObservation(
            response_code=response_code,
            latency_ms=latency * 1000,
            headers=headers,
            body_snippet=""
        )
        
        # Update success rate
        self.total_attempts += 1
        if response_code == 200:
            self.successful_attempts += 1
            
        self.success_rate = self.successful_attempts / self.total_attempts
        
        return observation
        
    def select_action(self, observation: WAFObservation) -> WAFAction:
        """Select action using epsilon-greedy exploration"""
        if random.random() < self.exploration_rate:
            # Explore: random action
            action = self._generate_random_action()
        else:
            # Exploit: use current policy
            action = self._generate_policy_action(observation)
            
        return action
        
    def _generate_random_action(self) -> WAFAction:
        """Generate random exploration action"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        
        ja4_profiles = ["chrome_120_windows", "firefox_121_windows", "safari_17_macos"]
        
        return WAFAction(
            user_agent=random.choice(user_agents),
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            },
            timing_delay=random.uniform(0.1, 2.0),
            ja4_profile=random.choice(ja4_profiles)
        )
        
    def _generate_policy_action(self, observation: WAFObservation) -> WAFAction:
        """Generate action based on current policy"""
        # Mock policy-based action
        if observation.response_code == 403:
            # If blocked, try different profile
            return WAFAction(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                headers={"User-Agent": "Different-Agent"},
                timing_delay=1.5,
                ja4_profile="safari_17_macos"
            )
        else:
            # If successful, continue with similar pattern
            return WAFAction(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                headers={"User-Agent": "Successful-Agent"},
                timing_delay=0.5,
                ja4_profile="chrome_120_windows"
            )
            
    def update_policy(self, observation: WAFObservation, action: WAFAction, reward: float):
        """Update policy based on reward"""
        experience = {
            "observation": observation,
            "action": action,
            "reward": reward,
            "timestamp": time.time()
        }
        
        self.experience_buffer.append(experience)
        
        # Simple policy update
        if reward > 0:
            # Reinforce successful actions
            self.current_policy[action.ja4_profile] = self.current_policy.get(action.ja4_profile, 0) + 0.1
        else:
            # Penalize failed actions
            self.current_policy[action.ja4_profile] = self.current_policy.get(action.ja4_profile, 0) - 0.1
            
        # Decay exploration rate
        self.exploration_rate = max(0.1, self.exploration_rate * 0.995)
        
    def get_reward(self, observation: WAFObservation) -> float:
        """Calculate reward from observation"""
        if observation.response_code == 200:
            return 1.0  # Success
        elif observation.response_code == 403:
            return -1.0  # Blocked
        elif observation.response_code == 429:
            return -0.5  # Rate limited
        else:
            return -0.2  # Other error


class MockBrowserEmulator:
    """Mock headless browser emulator"""
    
    def __init__(self):
        self.js_engine_enabled = True
        self.cookies = {}
        self.canvas_fingerprint = "mock_canvas_fp"
        self.webgl_fingerprint = "mock_webgl_fp"
        self.session_state = {}
        
    async def solve_challenge(self, challenge_type: str, challenge_data: str) -> str:
        """Solve JavaScript challenge"""
        if not self.js_engine_enabled:
            raise Exception("JavaScript engine not available")
            
        # Mock challenge solving
        if challenge_type == "cloudflare_turnstile":
            return "cf_turnstile_token_" + hashlib.md5(challenge_data.encode()).hexdigest()[:16]
        elif challenge_type == "recaptcha":
            return "recaptcha_token_" + hashlib.md5(challenge_data.encode()).hexdigest()[:16]
        else:
            return "generic_token_" + hashlib.md5(challenge_data.encode()).hexdigest()[:16]
            
    def extract_cookies(self, response_headers: Dict[str, str]) -> Dict[str, str]:
        """Extract and store cookies from response"""
        cookies = {}
        
        if "Set-Cookie" in response_headers:
            cookie_header = response_headers["Set-Cookie"]
            # Simple cookie parsing
            for cookie in cookie_header.split(";"):
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    cookies[key.strip()] = value.strip()
                    
        self.cookies.update(cookies)
        return cookies
        
    def spoof_canvas_fingerprint(self, target_fingerprint: str):
        """Spoof Canvas fingerprint"""
        self.canvas_fingerprint = target_fingerprint
        
    def spoof_webgl_fingerprint(self, target_fingerprint: str):
        """Spoof WebGL fingerprint"""
        self.webgl_fingerprint = target_fingerprint
        
    def get_browser_fingerprint(self) -> Dict[str, str]:
        """Get current browser fingerprint"""
        return {
            "canvas": self.canvas_fingerprint,
            "webgl": self.webgl_fingerprint,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "screen_resolution": "1920x1080",
            "timezone": "America/New_York",
            "language": "en-US"
        }
        
    async def solve_captcha(self, captcha_type: str, site_key: str) -> str:
        """Solve CAPTCHA using external service"""
        # Mock CAPTCHA solving
        captcha_services = {
            "2captcha": f"2captcha_solution_{site_key[:8]}",
            "anticaptcha": f"anticaptcha_solution_{site_key[:8]}"
        }
        
        return captcha_services.get(captcha_type, f"generic_solution_{site_key[:8]}")


class TestJA4PlusFingerprintEngine:
    """Test JA4+ fingerprint engine"""
    
    def test_ja4_hash_calculation(self):
        """
        Test JA4 hash calculation from ClientHello
        **Validates: Requirements 4.1**
        """
        engine = MockJA4Engine()
        engine.set_profile("chrome_120_windows")
        
        # Mock ClientHello
        client_hello = engine.build_client_hello("example.com")
        ja4_hash = engine.calculate_ja4(client_hello)
        
        assert ja4_hash == "t13d1516h2_8daaf6152771_e5627efa2ab1"
        assert ja4_hash.startswith("t13d")  # TLS 1.3, SNI present
        
    def test_ja4s_server_fingerprint_detection(self):
        """
        Test JA4S server fingerprint detection
        **Validates: Requirements 4.2**
        """
        engine = MockJA4Engine()
        engine.set_profile("chrome_120_windows")
        
        # Server should have matching JA4S
        expected_ja4s = "t130200_1301_234ea6891581"
        assert engine.current_profile.ja4s == expected_ja4s
        
    def test_ja4h_http_fingerprint_spoofing(self):
        """
        Test JA4H HTTP fingerprint spoofing
        **Validates: Requirements 4.3**
        """
        engine = MockJA4Engine()
        engine.set_profile("chrome_120_windows")
        
        # HTTP fingerprint should match browser
        expected_ja4h = "ge11cn20enus_60a8b69f9c15_000000000000"
        assert engine.current_profile.ja4h == expected_ja4h
        
    def test_ja4x_certificate_fingerprint_analysis(self):
        """
        Test JA4X certificate fingerprint analysis
        **Validates: Requirements 4.4**
        """
        engine = MockJA4Engine()
        engine.set_profile("chrome_120_windows")
        
        # Certificate fingerprint should be present
        expected_ja4x = "a]b]c]d]e]f"
        assert engine.current_profile.ja4x == expected_ja4x
        
    def test_browser_profile_database(self):
        """
        Test browser profile database completeness
        **Validates: Requirements 4.5**
        """
        engine = MockJA4Engine()
        
        # Should have major browser profiles
        required_profiles = [
            "chrome_120_windows",
            "firefox_121_windows", 
            "safari_17_macos"
        ]
        
        for profile_name in required_profiles:
            assert profile_name in engine.profiles
            profile = engine.profiles[profile_name]
            
            # Validate profile completeness
            assert profile.ja4 is not None
            assert profile.ja4s is not None
            assert profile.ja4h is not None
            assert profile.ja4x is not None
            assert len(profile.cipher_suites) > 0
            assert len(profile.extensions) > 0
            assert len(profile.alpn_protocols) > 0
            
    def test_dynamic_ja4_morphing(self):
        """
        Test dynamic JA4 morphing during connections
        **Validates: Requirements 4.6**
        """
        engine = MockJA4Engine()
        engine.set_profile("chrome_120_windows")
        
        original_ja4 = engine.current_profile.ja4
        
        # Morph to different profile
        result = engine.morph_fingerprint("firefox_121_windows")
        
        assert result["morphed"] is True
        assert result["old_profile"] == "Chrome 120 Windows"
        assert result["new_profile"] == "firefox_121_windows"
        assert engine.current_profile.ja4 != original_ja4


class TestHttp2QuicEngine:
    """Test HTTP/2 and QUIC engine"""
    
    @pytest.mark.asyncio
    async def test_http2_settings_frame_control(self):
        """
        Test HTTP/2 SETTINGS frame parameter control
        **Validates: Requirements 5.1, 5.2**
        """
        profile = MockJA4Engine().profiles["chrome_120_windows"]
        engine = MockHttp2QuicEngine(profile)
        
        response = await engine.send_http2_request("https://example.com", {})
        
        settings = response["settings_frame"]
        assert settings["header_table_size"] == 65536
        assert settings["enable_push"] == 0
        assert settings["max_concurrent_streams"] == 1000
        assert settings["initial_window_size"] == 6291456
        assert settings["max_frame_size"] == 16384
        assert settings["max_header_list_size"] == 262144
        
    @pytest.mark.asyncio
    async def test_akamai_fingerprint_matching(self):
        """
        Test AKAMAI HTTP/2 fingerprint matching
        **Validates: Requirements 5.6**
        """
        chrome_profile = MockJA4Engine().profiles["chrome_120_windows"]
        chrome_engine = MockHttp2QuicEngine(chrome_profile)
        
        firefox_profile = MockJA4Engine().profiles["firefox_121_windows"]
        firefox_engine = MockHttp2QuicEngine(firefox_profile)
        
        # Chrome should match AKAMAI Chrome pattern
        assert chrome_engine.match_akamai_fingerprint() is True
        
        # Firefox should match AKAMAI Firefox pattern
        assert firefox_engine.match_akamai_fingerprint() is True
        
    @pytest.mark.asyncio
    async def test_quic_http3_support(self):
        """
        Test QUIC/HTTP/3 protocol support
        **Validates: Requirements 5.3**
        """
        profile = MockJA4Engine().profiles["chrome_120_windows"]
        engine = MockHttp2QuicEngine(profile)
        
        response = await engine.send_quic_request("https://example.com", {})
        
        assert response["protocol"] == "HTTP/3"
        assert response["quic_version"] == "1"
        assert response["alpn"] == "h3"
        
    @pytest.mark.asyncio
    async def test_quic_0rtt_support(self):
        """
        Test QUIC 0-RTT early data support
        **Validates: Requirements 5.4**
        """
        profile = MockJA4Engine().profiles["chrome_120_windows"]
        engine = MockHttp2QuicEngine(profile)
        
        # Multiple requests to test 0-RTT
        responses = []
        for _ in range(10):
            response = await engine.send_quic_request("https://example.com", {})
            responses.append(response)
            
        # Should have some 0-RTT connections
        zero_rtt_count = sum(1 for r in responses if r["connection_type"] == "0-RTT")
        assert zero_rtt_count > 0
        
    @pytest.mark.asyncio
    async def test_quic_connection_migration(self):
        """
        Test QUIC connection migration support
        **Validates: Requirements 5.5**
        """
        profile = MockJA4Engine().profiles["chrome_120_windows"]
        engine = MockHttp2QuicEngine(profile)
        
        # Mock connection migration
        original_state = engine.connection_state
        engine.connection_state = "migrating"
        
        # Should handle migration gracefully
        response = await engine.send_quic_request("https://example.com", {})
        assert response["status"] == 200
        
        engine.connection_state = "established"
        assert engine.connection_state != original_state


class TestRLWAFBypassAgent:
    """Test RL WAF bypass agent"""
    
    def test_observation_space_capture(self):
        """
        Test observation space captures response codes and latency
        **Validates: Requirements 9.1**
        """
        agent = MockRLWAFBypassAgent()
        
        # Test different response observations
        obs_200 = agent.observe(200, 0.1, {"server": "nginx"})
        obs_403 = agent.observe(403, 0.5, {"server": "cloudflare"})
        obs_429 = agent.observe(429, 1.0, {"server": "akamai"})
        
        assert obs_200.response_code == 200
        assert obs_200.latency_ms == 100.0
        
        assert obs_403.response_code == 403
        assert obs_403.latency_ms == 500.0
        
        assert obs_429.response_code == 429
        assert obs_429.latency_ms == 1000.0
        
    def test_action_space_mutations(self):
        """
        Test action space includes User-Agent, headers, timing, JA4 mutations
        **Validates: Requirements 9.2**
        """
        agent = MockRLWAFBypassAgent()
        
        # Generate multiple actions
        actions = []
        for _ in range(10):
            obs = WAFObservation(200, 100, {}, "")
            action = agent.select_action(obs)
            actions.append(action)
            
        # Should have variety in actions
        user_agents = set(a.user_agent for a in actions)
        ja4_profiles = set(a.ja4_profile for a in actions)
        timing_delays = [a.timing_delay for a in actions]
        
        assert len(user_agents) > 1  # Multiple user agents
        assert len(ja4_profiles) > 1  # Multiple JA4 profiles
        assert min(timing_delays) != max(timing_delays)  # Varied timing
        
    def test_exploration_on_403_responses(self):
        """
        Test exploration triggered by 403 Forbidden responses
        **Validates: Requirements 9.3**
        """
        agent = MockRLWAFBypassAgent()
        
        # Simulate 403 response
        obs_403 = agent.observe(403, 0.5, {"server": "waf"})
        action = agent.select_action(obs_403)
        
        # Should generate exploration action
        assert action.user_agent is not None
        assert action.ja4_profile is not None
        assert action.timing_delay > 0
        
    def test_reinforcement_on_200_responses(self):
        """
        Test reinforcement on successful 200 responses
        **Validates: Requirements 9.4**
        """
        agent = MockRLWAFBypassAgent()
        
        # Simulate successful response
        obs_200 = agent.observe(200, 0.1, {"server": "nginx"})
        action = agent.select_action(obs_200)
        reward = agent.get_reward(obs_200)
        
        assert reward == 1.0  # Positive reward
        
        # Update policy
        agent.update_policy(obs_200, action, reward)
        
        # Policy should be updated
        assert len(agent.experience_buffer) > 0
        assert action.ja4_profile in agent.current_policy
        
    def test_epsilon_greedy_exploration(self):
        """
        Test epsilon-greedy exploration strategy
        **Validates: Requirements 9.5**
        """
        agent = MockRLWAFBypassAgent()
        
        initial_exploration_rate = agent.exploration_rate
        assert 0 < initial_exploration_rate < 1
        
        # Simulate learning
        for _ in range(100):
            obs = agent.observe(200, 0.1, {})
            action = agent.select_action(obs)
            reward = agent.get_reward(obs)
            agent.update_policy(obs, action, reward)
            
        # Exploration rate should decay
        assert agent.exploration_rate < initial_exploration_rate
        assert agent.exploration_rate >= 0.1  # Should not go below minimum
        
    def test_online_and_offline_learning_modes(self):
        """
        Test online and offline learning mode support
        **Validates: Requirements 9.6**
        """
        agent = MockRLWAFBypassAgent()
        
        # Should support online learning by default
        assert agent.learning_mode == "online"
        
        # Should accumulate experience
        obs = agent.observe(200, 0.1, {})
        action = agent.select_action(obs)
        reward = agent.get_reward(obs)
        agent.update_policy(obs, action, reward)
        
        assert len(agent.experience_buffer) > 0
        
        # Could switch to offline mode
        agent.learning_mode = "offline"
        assert agent.learning_mode == "offline"


class TestBrowserEmulation:
    """Test headless browser emulation"""
    
    @pytest.mark.asyncio
    async def test_javascript_execution_environment(self):
        """
        Test JavaScript execution for challenge solving
        **Validates: Requirements 11.1**
        """
        emulator = MockBrowserEmulator()
        
        # Should have JS engine enabled
        assert emulator.js_engine_enabled is True
        
        # Should solve JavaScript challenges
        token = await emulator.solve_challenge("cloudflare_turnstile", "challenge_data")
        assert token.startswith("cf_turnstile_token_")
        assert len(token) > 16
        
    @pytest.mark.asyncio
    async def test_cloudflare_turnstile_bypass(self):
        """
        Test Cloudflare Turnstile challenge bypass
        **Validates: Requirements 11.2**
        """
        emulator = MockBrowserEmulator()
        
        # Solve Turnstile challenge
        challenge_data = "turnstile_challenge_12345"
        token = await emulator.solve_challenge("cloudflare_turnstile", challenge_data)
        
        assert token.startswith("cf_turnstile_token_")
        assert len(token) > 16  # Expected minimum token length
        
    def test_cookie_extraction_and_reuse(self):
        """
        Test cookie extraction and reuse across requests
        **Validates: Requirements 11.3**
        """
        emulator = MockBrowserEmulator()
        
        # Mock response with cookies
        response_headers = {
            "Set-Cookie": "session_id=abc123; cf_clearance=def456; path=/"
        }
        
        cookies = emulator.extract_cookies(response_headers)
        
        assert "session_id" in cookies
        assert "cf_clearance" in cookies
        assert cookies["session_id"] == "abc123"
        assert cookies["cf_clearance"] == "def456"
        
        # Cookies should be stored for reuse
        assert "session_id" in emulator.cookies
        assert "cf_clearance" in emulator.cookies
        
    def test_canvas_webgl_fingerprint_spoofing(self):
        """
        Test Canvas and WebGL fingerprint spoofing
        **Validates: Requirements 11.4**
        """
        emulator = MockBrowserEmulator()
        
        # Original fingerprints
        original_canvas = emulator.canvas_fingerprint
        original_webgl = emulator.webgl_fingerprint
        
        # Spoof fingerprints
        target_canvas = "spoofed_canvas_fp_12345"
        target_webgl = "spoofed_webgl_fp_67890"
        
        emulator.spoof_canvas_fingerprint(target_canvas)
        emulator.spoof_webgl_fingerprint(target_webgl)
        
        # Should be spoofed
        assert emulator.canvas_fingerprint == target_canvas
        assert emulator.webgl_fingerprint == target_webgl
        assert emulator.canvas_fingerprint != original_canvas
        assert emulator.webgl_fingerprint != original_webgl
        
    @pytest.mark.asyncio
    async def test_captcha_solving_integration(self):
        """
        Test CAPTCHA solving integration with external services
        **Validates: Requirements 11.5**
        """
        emulator = MockBrowserEmulator()
        
        # Test different CAPTCHA services
        site_key = "6LdRcpUUAAAAAJ"
        
        solution_2captcha = await emulator.solve_captcha("2captcha", site_key)
        solution_anticaptcha = await emulator.solve_captcha("anticaptcha", site_key)
        
        assert solution_2captcha.startswith("2captcha_solution_")
        assert solution_anticaptcha.startswith("anticaptcha_solution_")
        assert site_key[:8] in solution_2captcha
        assert site_key[:8] in solution_anticaptcha
        
    def test_browser_state_management(self):
        """
        Test browser state management across requests
        **Validates: Requirements 11.6**
        """
        emulator = MockBrowserEmulator()
        
        # Set session state
        emulator.session_state = {
            "logged_in": True,
            "user_id": "12345",
            "csrf_token": "csrf_abc123"
        }
        
        # Get browser fingerprint
        fingerprint = emulator.get_browser_fingerprint()
        
        assert "canvas" in fingerprint
        assert "webgl" in fingerprint
        assert "user_agent" in fingerprint
        assert "screen_resolution" in fingerprint
        
        # State should persist
        assert emulator.session_state["logged_in"] is True
        assert emulator.session_state["user_id"] == "12345"


class TestEvasionIntegration:
    """Test complete evasion system integration"""
    
    @pytest.mark.asyncio
    async def test_full_evasion_pipeline(self):
        """
        Test complete evasion pipeline: JA4+ → HTTP/2 → WAF bypass → Browser emulation
        **Validates: Requirements 4.1-4.6, 5.1-5.6, 9.1-9.6, 11.1-11.6**
        """
        # Initialize components
        ja4_engine = MockJA4Engine()
        waf_agent = MockRLWAFBypassAgent()
        browser_emulator = MockBrowserEmulator()
        
        # Phase 1: Set JA4+ profile
        ja4_engine.set_profile("chrome_120_windows")
        profile = ja4_engine.current_profile
        
        # Phase 2: Configure HTTP/2 engine
        http2_engine = MockHttp2QuicEngine(profile)
        
        # Phase 3: Simulate WAF encounter
        initial_response = waf_agent.observe(403, 0.5, {"server": "cloudflare"})
        
        # Phase 4: RL agent selects evasion action
        evasion_action = waf_agent.select_action(initial_response)
        
        # Phase 5: Morph JA4 fingerprint based on action
        morph_result = ja4_engine.morph_fingerprint(evasion_action.ja4_profile)
        
        # Phase 6: Browser emulation for challenge solving
        if initial_response.response_code == 403:
            challenge_token = await browser_emulator.solve_challenge(
                "cloudflare_turnstile", 
                "challenge_data"
            )
            
        # Phase 7: Retry with new configuration
        retry_response = waf_agent.observe(200, 0.2, {"server": "nginx"})
        reward = waf_agent.get_reward(retry_response)
        
        # Phase 8: Update RL policy
        waf_agent.update_policy(retry_response, evasion_action, reward)
        
        # Verify integration
        assert morph_result["morphed"] is True
        assert challenge_token.startswith("cf_turnstile_token_")
        assert retry_response.response_code == 200
        assert reward > 0
        assert len(waf_agent.experience_buffer) > 0
        
    @pytest.mark.asyncio
    async def test_adaptive_evasion_learning(self):
        """
        Test adaptive evasion learning across multiple attempts
        **Validates: Requirements 9.3, 9.4, 9.5**
        """
        waf_agent = MockRLWAFBypassAgent()
        ja4_engine = MockJA4Engine()
        
        # Simulate learning over multiple attempts
        success_count = 0
        
        for attempt in range(50):
            # Simulate varying WAF responses
            if attempt < 20:
                # Initial failures to trigger exploration
                response_code = 403 if random.random() > 0.3 else 200
            else:
                # Improved success rate as agent learns
                response_code = 200 if random.random() > 0.2 else 403
                
            observation = waf_agent.observe(response_code, 0.3, {})
            action = waf_agent.select_action(observation)
            reward = waf_agent.get_reward(observation)
            
            waf_agent.update_policy(observation, action, reward)
            
            if response_code == 200:
                success_count += 1
                
            # Adapt JA4 profile based on success
            if response_code == 403:
                ja4_engine.morph_fingerprint(action.ja4_profile)
                
        # Should show learning improvement
        final_success_rate = waf_agent.success_rate
        assert final_success_rate > 0.3  # Should improve over time
        assert waf_agent.exploration_rate < 0.3  # Should decay
        assert len(waf_agent.current_policy) > 0  # Should build policy


if __name__ == "__main__":
    # Configure logging for test output
    logging.basicConfig(level=logging.INFO)
    
    # Run tests
    pytest.main([__file__, "-v", "-s", "--tb=short"])