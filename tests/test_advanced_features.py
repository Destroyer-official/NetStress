"""
Tests for Advanced Features

Tests for protocol fuzzer, attack optimizer, ultra engine, and advanced vectors.
"""

import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestProtocolFuzzer:
    """Tests for protocol fuzzer"""
    
    def test_fuzzer_import(self):
        """Test fuzzer can be imported"""
        from core.attacks.protocol_fuzzer import (
            FuzzStrategy, FuzzConfig, ProtocolFuzzer, create_fuzzer
        )
        assert FuzzStrategy is not None
        assert FuzzConfig is not None
    
    def test_fuzzer_creation(self):
        """Test fuzzer creation"""
        from core.attacks.protocol_fuzzer import create_fuzzer, FuzzConfig
        
        config = FuzzConfig(max_iterations=10)
        fuzzer = create_fuzzer('generic', config)
        assert fuzzer is not None
    
    def test_http_fuzzer(self):
        """Test HTTP fuzzer"""
        from core.attacks.protocol_fuzzer import HTTPFuzzer, FuzzConfig
        
        config = FuzzConfig()
        fuzzer = HTTPFuzzer(config)
        
        # Generate HTTP request
        request = fuzzer.generate_http_request()
        assert isinstance(request, bytes)
        assert b'HTTP' in request
    
    def test_dns_fuzzer(self):
        """Test DNS fuzzer"""
        from core.attacks.protocol_fuzzer import DNSFuzzer, FuzzConfig
        
        config = FuzzConfig()
        fuzzer = DNSFuzzer(config)
        
        # Generate DNS query
        query = fuzzer.generate_dns_query()
        assert isinstance(query, bytes)
        assert len(query) > 12  # Minimum DNS header size
    
    def test_mutator(self):
        """Test mutator"""
        from core.attacks.protocol_fuzzer import Mutator, FuzzConfig, MutationType
        
        config = FuzzConfig()
        mutator = Mutator(config)
        
        original = b"Hello, World!"
        mutated, desc = mutator.mutate(original)
        
        assert isinstance(mutated, bytes)
        assert isinstance(desc, str)
    
    def test_mutation_types(self):
        """Test different mutation types"""
        from core.attacks.protocol_fuzzer import Mutator, FuzzConfig, MutationType
        
        config = FuzzConfig()
        mutator = Mutator(config)
        original = b"Test data for mutation"
        
        for mut_type in MutationType:
            mutated, desc = mutator.mutate(original, mut_type)
            assert isinstance(mutated, bytes)


class TestAttackOptimizer:
    """Tests for attack optimizer"""
    
    def test_optimizer_import(self):
        """Test optimizer can be imported"""
        from core.ai.attack_optimizer import (
            OptimizationGoal, AttackParameters, AttackOptimizer
        )
        assert OptimizationGoal is not None
        assert AttackParameters is not None
    
    def test_attack_parameters(self):
        """Test attack parameters"""
        from core.ai.attack_optimizer import AttackParameters
        
        params = AttackParameters()
        assert params.packet_size == 1472
        assert params.rate_pps == 100000
        assert params.thread_count == 4
    
    def test_parameters_to_vector(self):
        """Test parameter vectorization"""
        from core.ai.attack_optimizer import AttackParameters
        
        params = AttackParameters()
        vector = params.to_vector()
        
        assert isinstance(vector, list)
        assert len(vector) == 7
        assert all(0 <= v <= 1 for v in vector)
    
    def test_parameters_from_vector(self):
        """Test parameter from vector"""
        from core.ai.attack_optimizer import AttackParameters
        
        vector = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
        params = AttackParameters.from_vector(vector)
        
        assert isinstance(params, AttackParameters)
        assert params.packet_size > 0
    
    def test_parameter_mutation(self):
        """Test parameter mutation"""
        from core.ai.attack_optimizer import AttackParameters
        
        params = AttackParameters()
        mutated = params.mutate(mutation_rate=1.0)  # Force mutation
        
        assert isinstance(mutated, AttackParameters)
    
    def test_parameter_crossover(self):
        """Test parameter crossover"""
        from core.ai.attack_optimizer import AttackParameters
        
        params1 = AttackParameters(packet_size=1000)
        params2 = AttackParameters(packet_size=2000)
        
        child = params1.crossover(params2)
        assert isinstance(child, AttackParameters)
    
    def test_genetic_optimizer(self):
        """Test genetic optimizer"""
        from core.ai.attack_optimizer import GeneticOptimizer, AttackParameters
        
        optimizer = GeneticOptimizer(population_size=10)
        optimizer.initialize_population()
        
        assert len(optimizer.population) == 10
        
        # Evaluate with dummy fitness
        optimizer.evaluate_population(lambda p: 0.5)
        
        # Evolve
        optimizer.evolve()
        assert optimizer.generation == 1
    
    def test_reinforcement_learner(self):
        """Test reinforcement learner"""
        from core.ai.attack_optimizer import ReinforcementLearner, AttackParameters
        
        learner = ReinforcementLearner()
        params = AttackParameters()
        
        new_params, reward = learner.optimize_step(params, lambda p: 0.5)
        
        assert isinstance(new_params, AttackParameters)
        assert isinstance(reward, float)
    
    def test_bayesian_optimizer(self):
        """Test Bayesian optimizer"""
        from core.ai.attack_optimizer import BayesianOptimizer
        
        bounds = {
            'packet_size': (64, 65535),
            'rate_pps': (1000, 10000000),
        }
        
        optimizer = BayesianOptimizer(bounds)
        suggestion = optimizer.suggest()
        
        assert 'packet_size' in suggestion
        assert 'rate_pps' in suggestion
        
        optimizer.observe(suggestion, 0.5)
        assert len(optimizer.observations) == 1


class TestUltraEngine:
    """Tests for ultra engine"""
    
    def test_ultra_engine_import(self):
        """Test ultra engine can be imported"""
        from core.performance.ultra_engine import (
            EngineMode, UltraConfig, UltraEngine, create_ultra_engine
        )
        assert EngineMode is not None
        assert UltraConfig is not None
    
    def test_ultra_config(self):
        """Test ultra config"""
        from core.performance.ultra_engine import UltraConfig, EngineMode
        
        config = UltraConfig(
            target="127.0.0.1",
            port=8080,
            mode=EngineMode.HYBRID
        )
        
        assert config.target == "127.0.0.1"
        assert config.port == 8080
        assert config.mode == EngineMode.HYBRID
    
    def test_ultra_stats(self):
        """Test ultra stats"""
        from core.performance.ultra_engine import UltraStats
        import time
        
        stats = UltraStats()
        stats.start_time = time.time() - 1
        stats.packets_sent = 1000
        stats.bytes_sent = 1000000
        
        assert stats.pps > 0
        assert stats.mbps > 0
    
    def test_packet_buffer(self):
        """Test packet buffer pool"""
        from core.performance.ultra_engine import PacketBuffer
        
        pool = PacketBuffer(count=10, size=1500)
        
        idx, buf = pool.acquire()
        assert idx >= 0
        assert len(buf) == 1500
        
        pool.release(idx)
    
    def test_rate_limiter(self):
        """Test rate limiter"""
        from core.performance.ultra_engine import RateLimiter
        
        limiter = RateLimiter(rate=1000)
        
        # Should allow first request
        assert limiter.allow() == True
    
    def test_create_ultra_engine(self):
        """Test create_ultra_engine function"""
        from core.performance.ultra_engine import create_ultra_engine, EngineMode
        
        engine = create_ultra_engine(
            target="127.0.0.1",
            port=9999,
            mode=EngineMode.STANDARD
        )
        
        assert engine is not None
        assert not engine.is_running()


class TestAdvancedVectors:
    """Tests for advanced attack vectors"""
    
    def test_advanced_vectors_import(self):
        """Test advanced vectors can be imported"""
        from core.attacks.advanced_vectors import (
            AttackCategory, PayloadEngine, EvasionEngine,
            MultiVectorAttack, ATTACK_PROFILES
        )
        assert AttackCategory is not None
        assert PayloadEngine is not None
    
    def test_payload_engine_random(self):
        """Test random payload generation"""
        from core.attacks.advanced_vectors import PayloadEngine
        
        payload = PayloadEngine.random_payload(100)
        assert len(payload) == 100
        assert isinstance(payload, bytes)
    
    def test_payload_engine_http(self):
        """Test HTTP payload generation"""
        from core.attacks.advanced_vectors import PayloadEngine
        
        payload = PayloadEngine.http_flood_payload("example.com")
        assert b"HTTP" in payload
        assert b"Host:" in payload
    
    def test_payload_engine_dns(self):
        """Test DNS payload generation"""
        from core.attacks.advanced_vectors import PayloadEngine
        
        payload = PayloadEngine.dns_amplification_payload("example.com")
        assert isinstance(payload, bytes)
        assert len(payload) > 12
    
    def test_payload_engine_ntp(self):
        """Test NTP payload generation"""
        from core.attacks.advanced_vectors import PayloadEngine
        
        payload = PayloadEngine.ntp_monlist_payload()
        assert isinstance(payload, bytes)
    
    def test_payload_engine_ssdp(self):
        """Test SSDP payload generation"""
        from core.attacks.advanced_vectors import PayloadEngine
        
        payload = PayloadEngine.ssdp_amplification_payload()
        assert b"M-SEARCH" in payload
    
    def test_evasion_engine_timing(self):
        """Test evasion timing randomization"""
        from core.attacks.advanced_vectors import EvasionEngine
        
        delays = [EvasionEngine.randomize_timing(1.0) for _ in range(10)]
        
        # Should have variation
        assert len(set(delays)) > 1
    
    def test_evasion_engine_fragment(self):
        """Test payload fragmentation"""
        from core.attacks.advanced_vectors import EvasionEngine
        
        payload = b"A" * 1000
        fragments = EvasionEngine.fragment_payload(payload, max_fragment_size=100)
        
        assert len(fragments) == 10
        assert all(len(f) <= 100 for f in fragments)
    
    def test_evasion_engine_encode(self):
        """Test payload encoding"""
        from core.attacks.advanced_vectors import EvasionEngine
        
        payload = b"Hello, World!"
        
        xor_encoded = EvasionEngine.encode_payload(payload, "xor")
        assert xor_encoded != payload
        
        b64_encoded = EvasionEngine.encode_payload(payload, "base64")
        assert b64_encoded != payload
    
    def test_attack_profiles(self):
        """Test attack profiles"""
        from core.attacks.advanced_vectors import ATTACK_PROFILES, get_attack_profile
        
        assert 'volumetric_udp' in ATTACK_PROFILES
        assert 'http_flood' in ATTACK_PROFILES
        assert 'amplification' in ATTACK_PROFILES
        assert 'hybrid' in ATTACK_PROFILES
        
        profile = get_attack_profile('http_flood')
        assert profile is not None
        assert len(profile.vectors) > 0


class TestIntegration:
    """Integration tests"""
    
    def test_all_modules_import(self):
        """Test all new modules can be imported together"""
        from core.attacks import (
            ProtocolFuzzer, HTTPFuzzer, DNSFuzzer,
            PayloadEngine, EvasionEngine, MultiVectorAttack
        )
        from core.ai import (
            AttackOptimizer, GeneticOptimizer, ReinforcementLearner
        )
        from core.performance import (
            UltraEngine, create_ultra_engine
        )
        
        assert ProtocolFuzzer is not None
        assert AttackOptimizer is not None
        assert UltraEngine is not None
    
    def test_native_engine_with_ultra(self):
        """Test native engine integration with ultra engine"""
        from core.native_engine import is_native_available
        from core.performance.ultra_engine import UltraConfig, EngineMode
        
        # Ultra engine should work regardless of native availability
        config = UltraConfig(
            target="127.0.0.1",
            port=9999,
            mode=EngineMode.HYBRID
        )
        
        assert config is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
