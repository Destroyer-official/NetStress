#!/usr/bin/env python3
"""
Property-based test for WAF Bypass RL Agent Adaptation

**Feature: cross-platform-destroyer, Property 6: RL Agent Adaptation**
**Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5**

Tests that the RL agent increases the probability of actions that led to 200 responses
and decreases the probability of actions that led to 403 responses.
"""

import sys
import os
import random
import numpy as np
from hypothesis import given, strategies as st, settings, assume
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize
import pytest

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.ai.waf_bypass_agent import (
    WAFBypassAgent, WAFObservation, WAFBypassAction, WAFBypassActionType
)


class TestWAFBypassRLAdaptationProperty:
    """Property-based tests for WAF Bypass RL Agent adaptation"""
    
    @given(
        response_sequence=st.lists(
            st.tuples(
                st.integers(min_value=200, max_value=599),  # HTTP status codes
                st.floats(min_value=10.0, max_value=5000.0),  # Latency in ms
                st.sampled_from(list(WAFBypassActionType))  # Action type
            ),
            min_size=10,
            max_size=50
        )
    )
    @settings(max_examples=10, deadline=5000)
    def test_rl_agent_adaptation_property(self, response_sequence):
        """
        Property 6: RL Agent Adaptation
        
        For any sequence of HTTP responses, the RL agent SHALL increase the probability 
        of actions that led to 200 responses and decrease the probability of actions 
        that led to 403 responses.
        
        **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5**
        """
        # Initialize agent with deterministic settings for testing
        agent = WAFBypassAgent(
            initial_epsilon=0.1,  # Low exploration for testing
            epsilon_decay=0.99,
            learning_rate=0.2,    # Higher learning rate for faster adaptation
            online_learning=True
        )
        
        # Track initial action probabilities
        initial_weights = {}
        for action_type in WAFBypassActionType:
            initial_weights[action_type] = agent.reinforcement_tracker.action_weights[action_type]
        
        # Process the response sequence
        successful_actions = set()
        failed_actions = set()
        
        for status_code, latency_ms, action_type in response_sequence:
            # Create action
            action = WAFBypassAction(
                action_type=action_type,
                magnitude=1.0,
                parameters={}
            )
            
            # Store previous observation for experience replay
            prev_observation = WAFObservation(
                response_codes=agent.observation.response_codes.copy(),
                latencies=agent.observation.latencies.copy(),
                current_user_agent_idx=agent.observation.current_user_agent_idx,
                current_ja4_profile=agent.observation.current_ja4_profile,
                current_headers=agent.observation.current_headers.copy(),
                current_timing_delay=agent.observation.current_timing_delay
            )
            
            # Process response
            reward = agent.process_response(status_code, latency_ms, action)
            
            # Update with experience for online learning
            agent.update_with_experience(prev_observation, action, reward)
            
            # Track successful and failed actions
            if 200 <= status_code < 300:
                successful_actions.add(action_type)
            elif status_code == 403:
                failed_actions.add(action_type)
        
        # Get final action probabilities
        final_weights = {}
        for action_type in WAFBypassActionType:
            final_weights[action_type] = agent.reinforcement_tracker.action_weights[action_type]
        
        # Property verification: Actions that led to 200s should have increased probability
        for action_type in successful_actions:
            if action_type not in failed_actions:  # Only check actions that were purely successful
                assert final_weights[action_type] >= initial_weights[action_type], \
                    f"Action {action_type.name} led to 200 responses but weight decreased: " \
                    f"{initial_weights[action_type]:.3f} -> {final_weights[action_type]:.3f}"
        
        # Property verification: Actions that led to 403s should have decreased probability
        for action_type in failed_actions:
            if action_type not in successful_actions:  # Only check actions that were purely failed
                assert final_weights[action_type] <= initial_weights[action_type], \
                    f"Action {action_type.name} led to 403 responses but weight increased: " \
                    f"{initial_weights[action_type]:.3f} -> {final_weights[action_type]:.3f}"
    
    @given(
        num_403_responses=st.integers(min_value=3, max_value=10),
        num_200_responses=st.integers(min_value=5, max_value=15)
    )
    @settings(max_examples=10, deadline=3000)
    def test_exploration_triggered_on_403_responses(self, num_403_responses, num_200_responses):
        """
        Test that 403 responses trigger exploration mode.
        
        **Validates: Requirements 9.3**
        """
        agent = WAFBypassAgent(initial_epsilon=0.05, online_learning=True)
        
        # Send multiple 403 responses with the same action
        action = WAFBypassAction(
            action_type=WAFBypassActionType.CHANGE_USER_AGENT,
            magnitude=1.0,
            parameters={'user_agent_idx': 0}
        )
        
        # Process 403 responses
        for _ in range(num_403_responses):
            agent.process_response(403, 100.0, action)
        
        # Property: Multiple 403s should increase consecutive count
        assert agent.exploration_tracker.consecutive_403_count >= num_403_responses, \
            f"Expected consecutive 403 count to be at least {num_403_responses}, got {agent.exploration_tracker.consecutive_403_count}"
        
        # Property: 403 responses should be recorded in exploration history
        recent_403s = sum(1 for entry in agent.exploration_tracker.exploration_history 
                         if entry['response_code'] == 403)
        assert recent_403s >= num_403_responses, \
            f"Expected at least {num_403_responses} 403s in history, got {recent_403s}"
        
        # Reset and test with 200 responses - should reset consecutive count
        agent = WAFBypassAgent(initial_epsilon=0.05, online_learning=True)
        
        for _ in range(num_200_responses):
            agent.process_response(200, 100.0, action)
        
        # Property: 200 responses should not increase consecutive 403 count
        assert agent.exploration_tracker.consecutive_403_count == 0, \
            f"200 responses should not increase consecutive 403 count, got {agent.exploration_tracker.consecutive_403_count}"
    
    @given(
        epsilon_decay=st.floats(min_value=0.9, max_value=0.999),
        num_steps=st.integers(min_value=10, max_value=100)
    )
    @settings(max_examples=5, deadline=2000)
    def test_epsilon_greedy_exploration_decay(self, epsilon_decay, num_steps):
        """
        Test that epsilon-greedy exploration rate decays properly.
        
        **Validates: Requirements 9.5**
        """
        initial_epsilon = 0.5
        agent = WAFBypassAgent(
            initial_epsilon=initial_epsilon,
            epsilon_decay=epsilon_decay,
            online_learning=True
        )
        
        initial_exploration_rate = agent.epsilon_policy.get_exploration_rate()
        
        # Process multiple responses to trigger epsilon decay
        action = WAFBypassAction(
            action_type=WAFBypassActionType.NO_ACTION,
            magnitude=1.0,
            parameters={}
        )
        
        for _ in range(num_steps):
            agent.process_response(200, 100.0, action)
        
        final_exploration_rate = agent.epsilon_policy.get_exploration_rate()
        
        # Property: Exploration rate should decrease over time
        assert final_exploration_rate <= initial_exploration_rate, \
            f"Exploration rate should decay: {initial_exploration_rate:.3f} -> {final_exploration_rate:.3f}"
        
        # Property: Should not decay below minimum
        assert final_exploration_rate >= agent.epsilon_policy.epsilon_min, \
            f"Exploration rate should not go below minimum: {final_exploration_rate:.3f} < {agent.epsilon_policy.epsilon_min:.3f}"
    
    @given(
        action_type=st.sampled_from(list(WAFBypassActionType)),
        num_successes=st.integers(min_value=5, max_value=20),
        num_failures=st.integers(min_value=1, max_value=10)
    )
    @settings(max_examples=10, deadline=3000)
    def test_reinforcement_learning_weight_updates(self, action_type, num_successes, num_failures):
        """
        Test that reinforcement learning properly updates action weights.
        
        **Validates: Requirements 9.4**
        """
        agent = WAFBypassAgent(learning_rate=0.2, online_learning=True)
        
        action = WAFBypassAction(
            action_type=action_type,
            magnitude=1.0,
            parameters={}
        )
        
        initial_weight = agent.reinforcement_tracker.action_weights[action_type]
        
        # Process successful responses
        for _ in range(num_successes):
            agent.process_response(200, 100.0, action)
        
        weight_after_successes = agent.reinforcement_tracker.action_weights[action_type]
        
        # Process failed responses
        for _ in range(num_failures):
            agent.process_response(403, 100.0, action)
        
        final_weight = agent.reinforcement_tracker.action_weights[action_type]
        
        # Property: Successes should increase weight
        if num_successes > 0:
            assert weight_after_successes >= initial_weight, \
                f"Weight should increase after successes: {initial_weight:.3f} -> {weight_after_successes:.3f}"
        
        # Property: Failures should decrease weight from the success level
        if num_failures > 0:
            assert final_weight <= weight_after_successes, \
                f"Weight should decrease after failures: {weight_after_successes:.3f} -> {final_weight:.3f}"
    
    def test_observation_space_captures_responses(self):
        """
        Test that observation space properly captures HTTP responses and latencies.
        
        **Validates: Requirements 9.1**
        """
        agent = WAFBypassAgent(online_learning=True)
        
        # Test data
        test_responses = [
            (200, 150.0),
            (403, 200.0),
            (429, 300.0),
            (200, 100.0),
            (500, 1000.0)
        ]
        
        action = WAFBypassAction(
            action_type=WAFBypassActionType.NO_ACTION,
            magnitude=1.0,
            parameters={}
        )
        
        # Process responses
        for status_code, latency in test_responses:
            agent.process_response(status_code, latency, action)
        
        # Verify observation captures the data
        observation = agent.observation
        
        # Property: Response codes should be captured
        assert len(observation.response_codes) == len(test_responses)
        assert observation.response_codes == [r[0] for r in test_responses]
        
        # Property: Latencies should be captured
        assert len(observation.latencies) == len(test_responses)
        assert observation.latencies == [r[1] for r in test_responses]
        
        # Property: Statistics should be calculated correctly
        expected_success_rate = 2 / 5  # 2 out of 5 were 200s
        expected_block_rate = 1 / 5    # 1 out of 5 was 403
        
        assert abs(observation.success_rate - expected_success_rate) < 0.01
        assert abs(observation.block_rate - expected_block_rate) < 0.01
        
        # Property: Observation should convert to vector
        vector = observation.to_vector()
        assert isinstance(vector, np.ndarray)
        assert len(vector) > 0


class WAFBypassRLStateMachine(RuleBasedStateMachine):
    """
    Stateful property testing for WAF Bypass RL Agent.
    
    Tests the agent's behavior over extended sequences of interactions.
    """
    
    def __init__(self):
        super().__init__()
        self.agent = WAFBypassAgent(
            initial_epsilon=0.2,
            learning_rate=0.1,
            online_learning=True
        )
        self.total_responses = 0
        self.successful_responses = 0
        self.blocked_responses = 0
    
    @initialize()
    def initialize_agent(self):
        """Initialize the agent state."""
        self.agent = WAFBypassAgent(
            initial_epsilon=0.2,
            learning_rate=0.1,
            online_learning=True
        )
        self.total_responses = 0
        self.successful_responses = 0
        self.blocked_responses = 0
    
    @rule(
        status_code=st.integers(min_value=200, max_value=599),
        latency=st.floats(min_value=10.0, max_value=2000.0),
        action_type=st.sampled_from(list(WAFBypassActionType))
    )
    def process_response(self, status_code, latency, action_type):
        """Process a response and update agent state."""
        action = WAFBypassAction(
            action_type=action_type,
            magnitude=1.0,
            parameters={}
        )
        
        prev_observation = WAFObservation(
            response_codes=self.agent.observation.response_codes.copy(),
            latencies=self.agent.observation.latencies.copy()
        )
        
        self.agent.process_response(status_code, latency, action)
        self.agent.update_with_experience(prev_observation, action, 
                                        self.agent._calculate_reward(status_code, latency))
        
        self.total_responses += 1
        if 200 <= status_code < 300:
            self.successful_responses += 1
        elif status_code == 403:
            self.blocked_responses += 1
    
    @invariant()
    def statistics_are_consistent(self):
        """Agent statistics should be consistent with processed responses."""
        stats = self.agent.get_statistics()
        
        # Basic consistency checks
        assert stats['total_requests'] >= 0
        assert stats['successful_requests'] >= 0
        assert stats['blocked_requests'] >= 0
        
        # Success rate should be between 0 and 1
        assert 0.0 <= stats['success_rate'] <= 1.0
        assert 0.0 <= stats['block_rate'] <= 1.0
        
        # Exploration rate should be between min and 1
        assert self.agent.epsilon_policy.epsilon_min <= stats['exploration_rate'] <= 1.0
    
    @invariant()
    def action_weights_are_positive(self):
        """All action weights should remain positive."""
        for action_type, weight in self.agent.reinforcement_tracker.action_weights.items():
            assert weight > 0, f"Action weight for {action_type.name} became non-positive: {weight}"
    
    @invariant()
    def observation_vector_is_valid(self):
        """Observation vector should always be valid."""
        vector = self.agent.observation.to_vector()
        assert isinstance(vector, np.ndarray)
        assert len(vector) > 0
        assert np.all(np.isfinite(vector)), "Observation vector contains invalid values"


# Test runner
if __name__ == "__main__":
    print("Testing Property 6: RL Agent Adaptation...")
    
    # Run basic property tests
    test_instance = TestWAFBypassRLAdaptationProperty()
    
    # Test with a simple sequence
    simple_sequence = [
        (200, 100.0, WAFBypassActionType.CHANGE_USER_AGENT),
        (200, 150.0, WAFBypassActionType.CHANGE_USER_AGENT),
        (403, 200.0, WAFBypassActionType.ADD_HEADER),
        (403, 250.0, WAFBypassActionType.ADD_HEADER),
        (200, 120.0, WAFBypassActionType.SWITCH_JA4_PROFILE),
    ]
    
    try:
        test_instance.test_rl_agent_adaptation_property()
        print("✓ Basic adaptation property test passed")
        
        test_instance.test_exploration_triggered_on_403_responses()
        print("✓ Exploration trigger test passed")
        
        test_instance.test_epsilon_greedy_exploration_decay()
        print("✓ Epsilon decay test passed")
        
        test_instance.test_reinforcement_learning_weight_updates()
        print("✓ Weight update test passed")
        
        test_instance.test_observation_space_captures_responses()
        print("✓ Observation space test passed")
        
        print("\n✅ All WAF Bypass RL Agent adaptation property tests passed!")
        
    except Exception as e:
        print(f"\n❌ Property test failed: {e}")
        raise