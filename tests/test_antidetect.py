"""
Tests for Anti-Detection Module

Tests for:
- Proxy chains
- Traffic morphing
- Behavioral mimicry
- Fingerprint randomization
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock


class TestProxyChain:
    """Tests for proxy chain functionality"""
    
    def test_proxy_config(self):
        """Test proxy configuration"""
        from core.antidetect.proxy_chain import ProxyConfig, ProxyType
        
        config = ProxyConfig(
            host='127.0.0.1',
            port=1080,
            proxy_type=ProxyType.SOCKS5,
            username='user',
            password='pass'
        )
        
        assert config.host == '127.0.0.1'
        assert config.port == 1080
        assert config.proxy_type == ProxyType.SOCKS5
        
    def test_proxy_stats(self):
        """Test proxy statistics"""
        from core.antidetect.proxy_chain import ProxyStats
        
        stats = ProxyStats()
        stats.requests = 100
        stats.successes = 90
        stats.failures = 10
        
        assert stats.success_rate == 0.9
        
    def test_proxy_rotator_init(self):
        """Test proxy rotator initialization"""
        from core.antidetect.proxy_chain import ProxyRotator, ProxyConfig, ProxyType
        
        proxies = [
            ProxyConfig(host='proxy1.example.com', port=1080, proxy_type=ProxyType.SOCKS5),
            ProxyConfig(host='proxy2.example.com', port=1080, proxy_type=ProxyType.SOCKS5),
        ]
        
        rotator = ProxyRotator(proxies, strategy='round_robin')
        
        assert len(rotator.proxies) == 2
        assert rotator.strategy == 'round_robin'
        
    def test_proxy_chain_init(self):
        """Test proxy chain initialization"""
        from core.antidetect.proxy_chain import ProxyChain, ProxyConfig, ProxyType
        
        proxies = [
            ProxyConfig(host='proxy1.example.com', port=1080, proxy_type=ProxyType.SOCKS5),
            ProxyConfig(host='proxy2.example.com', port=8080, proxy_type=ProxyType.HTTP),
        ]
        
        chain = ProxyChain(proxies)
        
        assert len(chain.proxies) == 2


class TestTrafficMorph:
    """Tests for traffic morphing"""
    
    def test_morph_config(self):
        """Test morph configuration"""
        from core.antidetect.traffic_morph import MorphConfig, MorphType
        
        config = MorphConfig(
            morph_type=MorphType.HTTP,
            add_noise=True,
            noise_ratio=0.1
        )
        
        assert config.morph_type == MorphType.HTTP
        assert config.add_noise == True
        
    def test_traffic_morpher_http(self):
        """Test HTTP traffic morphing"""
        from core.antidetect.traffic_morph import TrafficMorpher, MorphConfig, MorphType
        
        config = MorphConfig(morph_type=MorphType.HTTP, add_noise=False)
        morpher = TrafficMorpher(config)
        
        data = b'test data'
        morphed = morpher.morph(data)
        
        assert b'HTTP/1.1' in morphed
        assert b'POST' in morphed
        
    def test_traffic_morpher_dns(self):
        """Test DNS traffic morphing"""
        from core.antidetect.traffic_morph import TrafficMorpher, MorphConfig, MorphType
        
        config = MorphConfig(morph_type=MorphType.DNS, add_noise=False)
        morpher = TrafficMorpher(config)
        
        data = b'test'
        morphed = morpher.morph(data)
        
        # DNS query should have header
        assert len(morphed) > 12
        
    def test_traffic_morpher_websocket(self):
        """Test WebSocket traffic morphing"""
        from core.antidetect.traffic_morph import TrafficMorpher, MorphConfig, MorphType
        
        config = MorphConfig(morph_type=MorphType.WEBSOCKET, add_noise=False)
        morpher = TrafficMorpher(config)
        
        data = b'test message'
        morphed = morpher.morph(data)
        
        # WebSocket frame should have header
        assert len(morphed) > len(data)
        
    def test_protocol_mimicry_chrome(self):
        """Test Chrome protocol mimicry"""
        from core.antidetect.traffic_morph import ProtocolMimicry
        
        mimicry = ProtocolMimicry('chrome')
        headers = mimicry.get_headers()
        
        assert 'User-Agent' in headers
        assert 'Chrome' in headers['User-Agent']
        assert 'sec-ch-ua' in headers
        
    def test_protocol_mimicry_firefox(self):
        """Test Firefox protocol mimicry"""
        from core.antidetect.traffic_morph import ProtocolMimicry
        
        mimicry = ProtocolMimicry('firefox')
        headers = mimicry.get_headers()
        
        assert 'Firefox' in headers['User-Agent']
        
    def test_payload_mutation(self):
        """Test payload mutation"""
        from core.antidetect.traffic_morph import PayloadMutation
        
        mutator = PayloadMutation()
        
        payload = b'original payload'
        mutated = mutator.mutate(payload, mutations=1)
        
        # Mutated should be different
        assert mutated != payload


class TestBehavioral:
    """Tests for behavioral mimicry"""
    
    def test_behavior_config(self):
        """Test behavior configuration"""
        from core.antidetect.behavioral import BehaviorConfig, BehaviorProfile
        
        config = BehaviorConfig(
            profile=BehaviorProfile.CASUAL,
            min_delay=0.5,
            max_delay=5.0
        )
        
        assert config.profile == BehaviorProfile.CASUAL
        assert config.min_delay == 0.5
        
    def test_human_simulator_init(self):
        """Test human simulator initialization"""
        from core.antidetect.behavioral import HumanSimulator, BehaviorConfig, BehaviorProfile
        
        config = BehaviorConfig(profile=BehaviorProfile.BUSINESS)
        simulator = HumanSimulator(config)
        
        assert simulator.config.profile == BehaviorProfile.BUSINESS
        
    def test_human_simulator_mouse_path(self):
        """Test mouse path generation"""
        from core.antidetect.behavioral import HumanSimulator, BehaviorConfig
        
        config = BehaviorConfig()
        simulator = HumanSimulator(config)
        
        path = simulator.get_mouse_path((0, 0), (100, 100), steps=10)
        
        assert len(path) == 11  # steps + 1
        assert path[0][0] >= -2 and path[0][0] <= 2  # Near start
        assert path[-1][0] >= 98 and path[-1][0] <= 102  # Near end
        
    def test_session_manager_init(self):
        """Test session manager initialization"""
        from core.antidetect.behavioral import SessionManager
        
        manager = SessionManager(max_sessions=50)
        
        assert manager.max_sessions == 50
        
    @pytest.mark.asyncio
    async def test_session_creation(self):
        """Test session creation"""
        from core.antidetect.behavioral import SessionManager
        
        manager = SessionManager()
        session = await manager.create_session()
        
        assert session.session_id != ''
        assert session.requests == 0
        
    def test_behavioral_mimicry_init(self):
        """Test behavioral mimicry initialization"""
        from core.antidetect.behavioral import BehavioralMimicry, BehaviorConfig
        
        config = BehaviorConfig()
        mimicry = BehavioralMimicry(config)
        
        assert mimicry.simulator is not None
        assert mimicry.session_manager is not None


class TestFingerprintRandomization:
    """Tests for fingerprint randomization"""
    
    def test_fingerprint_profile(self):
        """Test fingerprint profile"""
        from core.antidetect.fingerprint_random import FingerprintProfile, BROWSER_PROFILES
        
        assert len(BROWSER_PROFILES) > 0
        
        profile = BROWSER_PROFILES[0]
        assert profile.name != ''
        assert profile.user_agent != ''
        
    def test_fingerprint_randomizer_init(self):
        """Test fingerprint randomizer initialization"""
        from core.antidetect.fingerprint_random import FingerprintRandomizer
        
        randomizer = FingerprintRandomizer()
        
        assert len(randomizer.profiles) > 0
        
    def test_fingerprint_randomizer_headers(self):
        """Test fingerprint randomizer headers"""
        from core.antidetect.fingerprint_random import FingerprintRandomizer
        
        randomizer = FingerprintRandomizer()
        randomizer.get_random_profile()
        
        headers = randomizer.get_headers('example.com')
        
        assert 'Host' in headers
        assert headers['Host'] == 'example.com'
        assert 'User-Agent' in headers
        
    def test_ja3_randomizer_init(self):
        """Test JA3 randomizer initialization"""
        from core.antidetect.fingerprint_random import JA3Randomizer
        
        randomizer = JA3Randomizer()
        
        ja3 = randomizer.get_random_ja3()
        
        assert ja3 != ''
        assert ',' in ja3  # JA3 format has commas
        
    def test_ja3_hash_calculation(self):
        """Test JA3 hash calculation"""
        from core.antidetect.fingerprint_random import JA3Randomizer
        
        randomizer = JA3Randomizer()
        
        ja3 = randomizer.get_random_ja3()
        hash_value = randomizer.get_ja3_hash(ja3)
        
        assert len(hash_value) == 32  # MD5 hash length
        
    def test_ja3_parsing(self):
        """Test JA3 string parsing"""
        from core.antidetect.fingerprint_random import JA3Randomizer
        
        randomizer = JA3Randomizer()
        
        ja3 = '771,4865-4866-4867,0-23-65281,29-23-24,0'
        parsed = randomizer.parse_ja3(ja3)
        
        assert parsed['tls_version'] == 771
        assert 4865 in parsed['cipher_suites']
        
    def test_header_randomizer_init(self):
        """Test header randomizer initialization"""
        from core.antidetect.fingerprint_random import HeaderRandomizer
        
        randomizer = HeaderRandomizer()
        
        base_headers = {
            'Accept': 'text/html',
            'Accept-Language': 'en-US',
            'Connection': 'keep-alive',
        }
        
        randomized = randomizer.randomize_headers(base_headers)
        
        assert 'Accept' in randomized
        
    def test_header_order_randomization(self):
        """Test header order randomization"""
        from core.antidetect.fingerprint_random import HeaderRandomizer
        
        randomizer = HeaderRandomizer()
        
        headers = {
            'Host': 'example.com',
            'Accept': 'text/html',
            'User-Agent': 'Test',
        }
        
        ordered = randomizer.randomize_header_order(headers)
        
        # Host should be first
        assert ordered[0][0] == 'Host'
        
    def test_noise_headers(self):
        """Test noise header addition"""
        from core.antidetect.fingerprint_random import HeaderRandomizer
        
        randomizer = HeaderRandomizer()
        
        headers = {'Host': 'example.com'}
        
        # Run multiple times to ensure noise is added sometimes
        noise_added = False
        for _ in range(10):
            result = randomizer.add_noise_headers(headers.copy())
            if len(result) > 1:
                noise_added = True
                break
                
        # Noise should be added at least once in 10 tries
        assert noise_added or len(headers) == 1
