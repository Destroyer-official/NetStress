"""
Tests for Attack Orchestration Module
"""

import pytest
import time
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAttackOrchestration:
    """Test attack orchestration components"""
    
    def test_orchestration_import(self):
        """Test orchestration module imports"""
        from core.orchestration import (
            AttackPhase, VectorType, AttackVector,
            OrchestratorConfig, OrchestratorStats,
            AttackOrchestrator, create_orchestrator
        )
        assert AttackPhase is not None
        assert VectorType is not None
        assert AttackOrchestrator is not None
    
    def test_attack_phase_enum(self):
        """Test attack phase enumeration"""
        from core.orchestration import AttackPhase
        
        assert AttackPhase.RECONNAISSANCE is not None
        assert AttackPhase.PROBING is not None
        assert AttackPhase.ESCALATION is not None
        assert AttackPhase.SUSTAINED is not None
        assert AttackPhase.EVASION is not None
        assert AttackPhase.TERMINATION is not None
    
    def test_vector_type_enum(self):
        """Test vector type enumeration"""
        from core.orchestration import VectorType
        
        assert VectorType.VOLUMETRIC is not None
        assert VectorType.PROTOCOL is not None
        assert VectorType.APPLICATION is not None
        assert VectorType.AMPLIFICATION is not None
        assert VectorType.SLOWLORIS is not None
        assert VectorType.HYBRID is not None
    
    def test_attack_vector_creation(self):
        """Test attack vector creation"""
        from core.orchestration import AttackVector, VectorType
        
        vector = AttackVector(
            name='test_vector',
            vector_type=VectorType.VOLUMETRIC,
            protocol='udp',
            target='127.0.0.1',
            port=80,
            rate_pps=10000
        )
        
        assert vector.name == 'test_vector'
        assert vector.vector_type == VectorType.VOLUMETRIC
        assert vector.protocol == 'udp'
        assert vector.target == '127.0.0.1'
        assert vector.port == 80
        assert vector.rate_pps == 10000
        assert vector.enabled is True
    
    def test_orchestrator_config(self):
        """Test orchestrator configuration"""
        from core.orchestration import OrchestratorConfig, AttackPhase
        
        config = OrchestratorConfig(
            target='127.0.0.1',
            port=80,
            total_rate_pps=1000000,
            duration=300
        )
        
        assert config.target == '127.0.0.1'
        assert config.port == 80
        assert config.total_rate_pps == 1000000
        assert config.duration == 300
        assert config.adaptive_mode is True
    
    def test_orchestrator_stats(self):
        """Test orchestrator statistics"""
        from core.orchestration import OrchestratorStats, AttackPhase
        
        stats = OrchestratorStats()
        stats.total_packets = 1000000
        stats.total_bytes = 1472000000
        stats.start_time = time.time() - 10  # 10 seconds ago
        
        assert stats.total_packets == 1000000
        assert stats.duration > 0
        assert stats.total_pps > 0
        assert stats.total_mbps > 0
    
    def test_phase_controller(self):
        """Test phase controller"""
        from core.orchestration import PhaseController, OrchestratorConfig, AttackPhase
        
        config = OrchestratorConfig(target='127.0.0.1', port=80)
        controller = PhaseController(config)
        
        assert controller.get_current_phase() == AttackPhase.PROBING
        assert controller.get_phase_multiplier() == 0.3
    
    def test_create_orchestrator(self):
        """Test orchestrator creation helper"""
        from core.orchestration import create_orchestrator
        
        orchestrator = create_orchestrator(
            target='127.0.0.1',
            port=80,
            rate_pps=100000,
            duration=60
        )
        
        assert orchestrator is not None
        assert orchestrator.config.target == '127.0.0.1'
        assert orchestrator.config.port == 80


class TestRealTimeIntelligence:
    """Test real-time intelligence components"""
    
    def test_intelligence_import(self):
        """Test intelligence module imports"""
        from core.intelligence import (
            DefenseType, TargetState, TargetProfile,
            IntelligenceReport, RealTimeIntelligence
        )
        assert DefenseType is not None
        assert TargetState is not None
        assert RealTimeIntelligence is not None
    
    def test_defense_type_enum(self):
        """Test defense type enumeration"""
        from core.intelligence import DefenseType
        
        assert DefenseType.NONE is not None
        assert DefenseType.RATE_LIMITING is not None
        assert DefenseType.WAF is not None
        assert DefenseType.DPI is not None
        assert DefenseType.BLACKHOLING is not None
    
    def test_target_state_enum(self):
        """Test target state enumeration"""
        from core.intelligence import TargetState
        
        assert TargetState.HEALTHY is not None
        assert TargetState.DEGRADED is not None
        assert TargetState.STRESSED is not None
        assert TargetState.CRITICAL is not None
        assert TargetState.UNRESPONSIVE is not None
    
    def test_target_profile(self):
        """Test target profile"""
        from core.intelligence import TargetProfile, TargetState
        
        profile = TargetProfile(
            host='127.0.0.1',
            port=80,
            baseline_response_ms=50.0,
            current_response_ms=150.0
        )
        
        assert profile.host == '127.0.0.1'
        assert profile.port == 80
        assert profile.degradation_factor > 0
    
    def test_response_time_analyzer(self):
        """Test response time analyzer"""
        from core.intelligence.realtime_intelligence import ResponseTimeAnalyzer
        
        analyzer = ResponseTimeAnalyzer()
        
        # Add some measurements
        analyzer.measurements.append(50.0)
        analyzer.measurements.append(55.0)
        analyzer.measurements.append(48.0)
        
        assert analyzer.get_current() > 0
    
    def test_defense_detector(self):
        """Test defense detector"""
        from core.intelligence.realtime_intelligence import DefenseDetector, DefenseType
        
        detector = DefenseDetector()
        
        # Test rate limiting detection
        defenses = detector.analyze_response(
            response_code=429,
            response_time_ms=100,
            connection_success=True
        )
        
        assert DefenseType.RATE_LIMITING in defenses
    
    def test_effectiveness_scorer(self):
        """Test effectiveness scorer"""
        from core.intelligence.realtime_intelligence import EffectivenessScorer
        from core.intelligence import TargetProfile, TargetState
        
        scorer = EffectivenessScorer()
        
        profile = TargetProfile(
            host='127.0.0.1',
            port=80,
            baseline_response_ms=50.0,
            current_response_ms=200.0,
            current_success_rate=0.5,
            state=TargetState.STRESSED
        )
        
        score = scorer.calculate_score(profile)
        assert 0 <= score <= 1
    
    def test_rate_optimizer(self):
        """Test rate optimizer"""
        from core.intelligence.realtime_intelligence import RateOptimizer, DefenseType
        
        optimizer = RateOptimizer(initial_rate=100000)
        
        # Low effectiveness should increase rate
        new_rate = optimizer.optimize(0.1, [])
        assert new_rate > 100000
        
        # Rate limiting should decrease rate
        optimizer.current_rate = 100000
        new_rate = optimizer.optimize(0.5, [DefenseType.RATE_LIMITING])
        assert new_rate < 100000
    
    def test_realtime_intelligence_creation(self):
        """Test real-time intelligence creation"""
        from core.intelligence import RealTimeIntelligence
        
        intel = RealTimeIntelligence(target='127.0.0.1', port=80)
        
        assert intel.target == '127.0.0.1'
        assert intel.port == 80
        assert intel.profile is not None
    
    def test_get_optimal_parameters(self):
        """Test getting optimal parameters"""
        from core.intelligence import RealTimeIntelligence
        
        intel = RealTimeIntelligence(target='127.0.0.1', port=80)
        params = intel.get_optimal_parameters()
        
        assert 'rate_pps' in params
        assert 'packet_size' in params
        assert 'evasion_level' in params


class TestAdaptiveController:
    """Test adaptive controller"""
    
    def test_adaptive_controller_creation(self):
        """Test adaptive controller creation"""
        from core.orchestration.attack_orchestrator import AdaptiveController, OrchestratorConfig
        
        config = OrchestratorConfig(target='127.0.0.1', port=80)
        controller = AdaptiveController(config)
        
        assert controller is not None
        assert controller.learning_rate == 0.1
    
    def test_adaptive_analysis(self):
        """Test adaptive analysis"""
        from core.orchestration.attack_orchestrator import (
            AdaptiveController, OrchestratorConfig, OrchestratorStats
        )
        
        config = OrchestratorConfig(target='127.0.0.1', port=80)
        controller = AdaptiveController(config)
        
        stats = OrchestratorStats()
        stats.effectiveness_score = 0.5
        
        result = controller.analyze(stats)
        
        assert 'action' in result
        assert 'confidence' in result


class TestMultiTargetOrchestrator:
    """Test multi-target orchestrator"""
    
    def test_multi_target_creation(self):
        """Test multi-target orchestrator creation"""
        from core.orchestration import MultiTargetOrchestrator
        
        orchestrator = MultiTargetOrchestrator()
        assert orchestrator is not None
        assert len(orchestrator.orchestrators) == 0
    
    def test_add_target(self):
        """Test adding targets"""
        from core.orchestration import MultiTargetOrchestrator
        
        orchestrator = MultiTargetOrchestrator()
        orchestrator.add_target('127.0.0.1', 80)
        orchestrator.add_target('127.0.0.1', 443)
        
        assert len(orchestrator.orchestrators) == 2
    
    def test_get_combined_stats(self):
        """Test getting combined stats"""
        from core.orchestration import MultiTargetOrchestrator
        
        orchestrator = MultiTargetOrchestrator()
        orchestrator.add_target('127.0.0.1', 80)
        
        stats = orchestrator.get_combined_stats()
        
        assert 'total_pps' in stats
        assert 'total_mbps' in stats
        assert 'by_target' in stats
