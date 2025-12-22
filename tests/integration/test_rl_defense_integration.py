#!/usr/bin/env python3
"""
Integration tests for Reinforcement Learning and Defense Detection systems

Tests the integration between:
- RL agent for attack optimization
- Advanced defense detection
- Evasion strategy generation
- Feedback loop between detection and optimization
"""

import pytest
import numpy as np
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Import the modules we're testing
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.ai.reinforcement_learning import (
    QLearningAgent, PolicyGradientAgent, ReinforcementLearningOptimizer,
    State, Action, ActionType, Experience
)
from core.ai.advanced_defense_detection import (
    AdvancedDefenseDetectionSystem, DefenseMetrics, RateLimitDetector,
    WAFDetector, BehavioralDefenseDetector
)
from core.ai.defense_evasion import DefenseType, DefenseSignature


class TestRLAgentBasics:
    """Test basic RL agent functionality"""
    
    def test_q_learning_agent_initialization(self):
        """Test Q-learning agent initializes correctly"""
        agent = QLearningAgent()
        
        assert agent.learning_rate == 0.1
        assert agent.discount_factor == 0.95
        assert agent.epsilon == 0.3
        assert len(agent.q_table) == 0
        assert agent.episode_count == 0
    
    def test_policy_gradient_agent_initialization(self):
        """Test policy gradient agent initializes correctly"""
        agent = PolicyGradientAgent()
        
        assert agent.state_dim == 19  # Updated based on State.to_vector() with defense features
        assert agent.action_dim == len(ActionType)
        assert agent.learning_rate == 0.01
        assert agent.gamma == 0.99
        assert agent.policy_weights.shape == (19, len(ActionType))
    
    def test_state_creation_and_vectorization(self):
        """Test State creation and vector conversion"""
        state = State(
            packet_rate=50000,
            packet_size=1472,
            thread_count=4,
            protocol="UDP",
            evasion_level=3,
            current_pps=45000,
            current_bandwidth=500000000,
            error_rate=0.05,
            success_rate=0.95,
            target_response_time=0.1,
            target_error_rate=0.02,
            target_availability=0.99,
            network_latency=0.05,
            packet_loss=0.01,
            congestion_level=0.3
        )
        
        # Test that state can be vectorized
        vector = state.to_vector()
        assert len(vector) == 19  # Expected state dimension (updated with defense features)
        assert isinstance(vector, np.ndarray)
        
        # Test that values are normalized properly
        assert all(0 <= v <= 1 for v in vector)
        