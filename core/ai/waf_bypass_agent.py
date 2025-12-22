#!/usr/bin/env python3
"""
WAF Bypass Agent - AI-Driven Web Application Firewall Bypass

Implements a Reinforcement Learning agent for automatic WAF bypass.
The agent observes HTTP response codes and latencies, takes actions to
modify request parameters, and learns from the results to improve bypass rates.

**Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6**
"""

import numpy as np
import random
import logging
import pickle
import threading
import time
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
from enum import Enum, auto
import hashlib
import json
import os

logger = logging.getLogger(__name__)


# =============================================================================
# OBSERVATION SPACE (Task 18.1)
# Captures HTTP response codes, latency measurements, and configuration state
# =============================================================================

@dataclass
class WAFObservation:
    """
    Observation space for WAF bypass agent.
    
    Captures:
    - HTTP response codes (last N responses)
    - Latency measurements (last N latencies)
    - Current configuration state
    
    **Validates: Requirements 9.1**
    """
    # HTTP response codes (last 10 responses)
    response_codes: List[int] = field(default_factory=list)
    
    # Latency measurements in milliseconds (last 10 latencies)
    latencies: List[float] = field(default_factory=list)
    
    # Current configuration state
    current_user_agent_idx: int = 0
    current_ja4_profile: str = "chrome_120_windows"
    current_headers: Dict[str, str] = field(default_factory=dict)
    current_timing_delay: float = 0.0
    
    # Request statistics
    request_rate: float = 0.0  # Requests per second
    success_rate: float = 0.0  # Ratio of 2xx responses
    block_rate: float = 0.0    # Ratio of 403 responses
    rate_limit_rate: float = 0.0  # Ratio of 429 responses
    
    # WAF detection indicators
    waf_detected: bool = False
    waf_type: Optional[str] = None
    challenge_detected: bool = False
    
    def add_response(self, status_code: int, latency_ms: float):
        """Add a new response to the observation history."""
        self.response_codes.append(status_code)
        self.latencies.append(latency_ms)
        
        # Keep only last 10 entries
        if len(self.response_codes) > 10:
            self.response_codes = self.response_codes[-10:]
        if len(self.latencies) > 10:
            self.latencies = self.latencies[-10:]
        
        # Update statistics
        self._update_statistics()
    
    def _update_statistics(self):
        """Update success/block/rate-limit rates based on response history."""
        if not self.response_codes:
            return
        
        total = len(self.response_codes)
        success_count = sum(1 for c in self.response_codes if 200 <= c < 300)
        block_count = sum(1 for c in self.response_codes if c == 403)
        rate_limit_count = sum(1 for c in self.response_codes if c == 429)
        
        self.success_rate = success_count / total
        self.block_rate = block_count / total
        self.rate_limit_rate = rate_limit_count / total
    
    def to_vector(self) -> np.ndarray:
        """
        Convert observation to numerical vector for RL algorithms.
        
        Returns:
            numpy array of normalized features
        """
        features = []
        
        # Response code features (one-hot encoded for last 10 responses)
        for i in range(10):
            if i < len(self.response_codes):
                code = self.response_codes[i]
                features.extend([
                    1.0 if 200 <= code < 300 else 0.0,  # Success
                    1.0 if code == 403 else 0.0,        # Blocked
                    1.0 if code == 429 else 0.0,        # Rate limited
                    1.0 if code >= 500 else 0.0,        # Server error
                ])
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])
        
        # Latency features (normalized, last 10)
        for i in range(10):
            if i < len(self.latencies):
                # Normalize latency to [0, 1] range (assuming max 10s)
                features.append(min(self.latencies[i] / 10000.0, 1.0))
            else:
                features.append(0.0)
        
        # Configuration state features
        features.append(self.current_user_agent_idx / 100.0)  # Normalized UA index
        features.append(self.current_timing_delay / 5.0)       # Normalized delay (max 5s)
        
        # Statistics features
        features.append(self.success_rate)
        features.append(self.block_rate)
        features.append(self.rate_limit_rate)
        features.append(min(self.request_rate / 100.0, 1.0))  # Normalized rate
        
        # WAF detection features
        features.append(1.0 if self.waf_detected else 0.0)
        features.append(1.0 if self.challenge_detected else 0.0)
        
        return np.array(features, dtype=np.float32)
    
    def get_state_key(self) -> str:
        """Get discrete state key for Q-table lookup."""
        # Discretize continuous values
        success_bucket = int(self.success_rate * 10)
        block_bucket = int(self.block_rate * 10)
        rate_bucket = int(self.rate_limit_rate * 10)
        latency_bucket = int(np.mean(self.latencies) / 500) if self.latencies else 0
        
        return f"s{success_bucket}_b{block_bucket}_r{rate_bucket}_l{latency_bucket}_ua{self.current_user_agent_idx}"


# =============================================================================
# ACTION SPACE (Task 18.2)
# Defines User-Agent mutation, header modification, timing, and JA4 profile actions
# =============================================================================

class WAFBypassActionType(Enum):
    """
    Action types for WAF bypass agent.
    
    **Validates: Requirements 9.2**
    """
    # User-Agent mutation actions
    CHANGE_USER_AGENT = auto()
    ROTATE_USER_AGENT = auto()
    
    # Header modification actions
    ADD_HEADER = auto()
    REMOVE_HEADER = auto()
    MODIFY_HEADER = auto()
    RANDOMIZE_HEADERS = auto()
    
    # Timing adjustment actions
    INCREASE_DELAY = auto()
    DECREASE_DELAY = auto()
    RANDOMIZE_TIMING = auto()
    
    # JA4 profile switching actions
    SWITCH_JA4_PROFILE = auto()
    MORPH_JA4_FINGERPRINT = auto()
    
    # Combined evasion actions
    ENABLE_FULL_EVASION = auto()
    DISABLE_EVASION = auto()
    
    # No action
    NO_ACTION = auto()


@dataclass
class WAFBypassAction:
    """
    Action for WAF bypass agent.
    
    **Validates: Requirements 9.2**
    """
    action_type: WAFBypassActionType
    magnitude: float = 1.0  # Scaling factor for the action
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def apply_to_config(self, config: Dict[str, Any], 
                       user_agents: List[str],
                       ja4_profiles: List[str]) -> Dict[str, Any]:
        """Apply this action to a request configuration."""
        new_config = config.copy()
        
        if self.action_type == WAFBypassActionType.CHANGE_USER_AGENT:
            # Change to a specific user agent
            idx = self.parameters.get('user_agent_idx', 0)
            if 0 <= idx < len(user_agents):
                new_config['user_agent'] = user_agents[idx]
                new_config['user_agent_idx'] = idx
        
        elif self.action_type == WAFBypassActionType.ROTATE_USER_AGENT:
            # Rotate to next user agent
            current_idx = config.get('user_agent_idx', 0)
            new_idx = (current_idx + 1) % len(user_agents)
            new_config['user_agent'] = user_agents[new_idx]
            new_config['user_agent_idx'] = new_idx
        
        elif self.action_type == WAFBypassActionType.ADD_HEADER:
            # Add a new header
            header_name = self.parameters.get('header_name', 'X-Custom')
            header_value = self.parameters.get('header_value', 'value')
            headers = new_config.get('headers', {}).copy()
            headers[header_name] = header_value
            new_config['headers'] = headers
        
        elif self.action_type == WAFBypassActionType.REMOVE_HEADER:
            # Remove a header
            header_name = self.parameters.get('header_name', '')
            headers = new_config.get('headers', {}).copy()
            if header_name in headers:
                del headers[header_name]
            new_config['headers'] = headers
        
        elif self.action_type == WAFBypassActionType.MODIFY_HEADER:
            # Modify an existing header
            header_name = self.parameters.get('header_name', '')
            header_value = self.parameters.get('header_value', '')
            headers = new_config.get('headers', {}).copy()
            if header_name:
                headers[header_name] = header_value
            new_config['headers'] = headers
        
        elif self.action_type == WAFBypassActionType.RANDOMIZE_HEADERS:
            # Randomize header order and add noise
            headers = new_config.get('headers', {}).copy()
            # Add random request ID
            headers['X-Request-ID'] = str(random.randint(100000, 999999))
            # Add random timestamp
            headers['X-Timestamp'] = str(int(time.time() * 1000))
            new_config['headers'] = headers
        
        elif self.action_type == WAFBypassActionType.INCREASE_DELAY:
            # Increase timing delay
            current_delay = config.get('timing_delay', 0.0)
            new_config['timing_delay'] = min(current_delay + 0.5 * self.magnitude, 5.0)
        
        elif self.action_type == WAFBypassActionType.DECREASE_DELAY:
            # Decrease timing delay
            current_delay = config.get('timing_delay', 0.0)
            new_config['timing_delay'] = max(current_delay - 0.5 * self.magnitude, 0.0)
        
        elif self.action_type == WAFBypassActionType.RANDOMIZE_TIMING:
            # Add random timing jitter
            base_delay = config.get('timing_delay', 0.0)
            jitter = random.uniform(0, 1.0) * self.magnitude
            new_config['timing_delay'] = base_delay + jitter
            new_config['timing_jitter'] = True
        
        elif self.action_type == WAFBypassActionType.SWITCH_JA4_PROFILE:
            # Switch to a different JA4 profile
            profile_name = self.parameters.get('profile_name', '')
            if profile_name in ja4_profiles:
                new_config['ja4_profile'] = profile_name
        
        elif self.action_type == WAFBypassActionType.MORPH_JA4_FINGERPRINT:
            # Morph the JA4 fingerprint dynamically
            new_config['ja4_morphing'] = True
            new_config['ja4_morph_level'] = self.magnitude
        
        elif self.action_type == WAFBypassActionType.ENABLE_FULL_EVASION:
            # Enable all evasion techniques
            new_config['full_evasion'] = True
            new_config['timing_jitter'] = True
            new_config['ja4_morphing'] = True
            new_config['header_randomization'] = True
        
        elif self.action_type == WAFBypassActionType.DISABLE_EVASION:
            # Disable all evasion techniques
            new_config['full_evasion'] = False
            new_config['timing_jitter'] = False
            new_config['ja4_morphing'] = False
            new_config['header_randomization'] = False
        
        # NO_ACTION doesn't modify the config
        
        return new_config



# =============================================================================
# EXPLORATION ON 403 RESPONSES (Task 18.3)
# Detects 403 Forbidden responses and triggers exploration
# =============================================================================

class ExplorationTracker:
    """
    Tracks exploration history and triggers exploration on 403 responses.
    
    **Validates: Requirements 9.3**
    """
    
    def __init__(self, exploration_window: int = 100):
        self.exploration_history: deque = deque(maxlen=exploration_window)
        self.action_success_map: Dict[WAFBypassActionType, List[bool]] = defaultdict(list)
        self.consecutive_403_count: int = 0
        self.exploration_triggered: bool = False
        self.last_exploration_time: Optional[datetime] = None
        self.exploration_cooldown: timedelta = timedelta(seconds=5)
        
    def record_response(self, action: WAFBypassAction, response_code: int):
        """Record a response and update exploration state."""
        is_success = 200 <= response_code < 300
        is_blocked = response_code == 403
        
        # Record in history
        self.exploration_history.append({
            'action_type': action.action_type,
            'response_code': response_code,
            'timestamp': datetime.now(),
            'success': is_success
        })
        
        # Update action success map
        self.action_success_map[action.action_type].append(is_success)
        # Keep only last 50 results per action
        if len(self.action_success_map[action.action_type]) > 50:
            self.action_success_map[action.action_type] = \
                self.action_success_map[action.action_type][-50:]
        
        # Track consecutive 403s
        if is_blocked:
            self.consecutive_403_count += 1
        else:
            self.consecutive_403_count = 0
    
    def should_explore(self, response_code: int) -> bool:
        """
        Determine if exploration should be triggered.
        
        Triggers exploration when:
        - 403 response is detected
        - Multiple consecutive 403s occur
        - Cooldown period has passed
        
        **Validates: Requirements 9.3**
        """
        is_blocked = response_code == 403
        
        # Check cooldown
        if self.last_exploration_time:
            time_since_exploration = datetime.now() - self.last_exploration_time
            if time_since_exploration < self.exploration_cooldown:
                return False
        
        # Trigger exploration on 403
        if is_blocked:
            self.exploration_triggered = True
            self.last_exploration_time = datetime.now()
            logger.info(f"Exploration triggered: 403 response detected "
                       f"(consecutive: {self.consecutive_403_count})")
            return True
        
        # Trigger exploration on multiple consecutive 403s
        if self.consecutive_403_count >= 3:
            self.exploration_triggered = True
            self.last_exploration_time = datetime.now()
            logger.info(f"Exploration triggered: {self.consecutive_403_count} consecutive 403s")
            return True
        
        return False
    
    def get_unexplored_actions(self) -> List[WAFBypassActionType]:
        """Get actions that haven't been tried recently."""
        all_actions = list(WAFBypassActionType)
        recent_actions = set()
        
        # Get actions used in last 20 attempts
        for entry in list(self.exploration_history)[-20:]:
            recent_actions.add(entry['action_type'])
        
        # Return actions not recently used
        unexplored = [a for a in all_actions if a not in recent_actions]
        return unexplored if unexplored else all_actions
    
    def get_action_success_rate(self, action_type: WAFBypassActionType) -> float:
        """Get success rate for a specific action type."""
        results = self.action_success_map.get(action_type, [])
        if not results:
            return 0.5  # Unknown, assume neutral
        return sum(results) / len(results)


# =============================================================================
# REINFORCEMENT ON 200 RESPONSES (Task 18.4)
# Detects successful 200 responses and reinforces patterns
# =============================================================================

class ReinforcementTracker:
    """
    Tracks successful patterns and reinforces them.
    
    **Validates: Requirements 9.4**
    """
    
    def __init__(self, learning_rate: float = 0.1):
        self.learning_rate = learning_rate
        self.action_weights: Dict[WAFBypassActionType, float] = {
            action: 1.0 for action in WAFBypassActionType
        }
        self.successful_patterns: List[Dict[str, Any]] = []
        self.pattern_scores: Dict[str, float] = {}
        
    def record_success(self, action: WAFBypassAction, config: Dict[str, Any]):
        """
        Record a successful action and reinforce the pattern.
        
        **Validates: Requirements 9.4**
        """
        # Increase weight for successful action
        current_weight = self.action_weights[action.action_type]
        self.action_weights[action.action_type] = min(
            current_weight + self.learning_rate, 
            5.0  # Max weight
        )
        
        # Store successful pattern
        pattern = {
            'action_type': action.action_type,
            'parameters': action.parameters.copy(),
            'config_snapshot': {
                'user_agent_idx': config.get('user_agent_idx', 0),
                'ja4_profile': config.get('ja4_profile', ''),
                'timing_delay': config.get('timing_delay', 0.0),
            },
            'timestamp': datetime.now()
        }
        self.successful_patterns.append(pattern)
        
        # Keep only last 100 successful patterns
        if len(self.successful_patterns) > 100:
            self.successful_patterns = self.successful_patterns[-100:]
        
        # Update pattern score
        pattern_key = self._get_pattern_key(action, config)
        self.pattern_scores[pattern_key] = self.pattern_scores.get(pattern_key, 0) + 1
        
        logger.debug(f"Reinforced action {action.action_type.name}, "
                    f"new weight: {self.action_weights[action.action_type]:.3f}")
    
    def record_failure(self, action: WAFBypassAction, response_code: int):
        """
        Record a failed action and decrease its weight.
        
        **Validates: Requirements 9.3**
        """
        # Decrease weight for failed action
        current_weight = self.action_weights[action.action_type]
        
        # Stronger penalty for 403 (blocked)
        penalty = self.learning_rate * 2 if response_code == 403 else self.learning_rate
        
        self.action_weights[action.action_type] = max(
            current_weight - penalty,
            0.1  # Min weight
        )
        
        logger.debug(f"Penalized action {action.action_type.name}, "
                    f"new weight: {self.action_weights[action.action_type]:.3f}")
    
    def get_action_probability(self, action_type: WAFBypassActionType) -> float:
        """Get probability of selecting an action based on weights."""
        total_weight = sum(self.action_weights.values())
        return self.action_weights[action_type] / total_weight
    
    def get_best_pattern(self) -> Optional[Dict[str, Any]]:
        """Get the most successful pattern."""
        if not self.successful_patterns:
            return None
        
        # Find pattern with highest score
        best_key = max(self.pattern_scores, key=self.pattern_scores.get)
        
        # Find matching pattern
        for pattern in reversed(self.successful_patterns):
            if self._get_pattern_key_from_pattern(pattern) == best_key:
                return pattern
        
        return self.successful_patterns[-1]
    
    def _get_pattern_key(self, action: WAFBypassAction, config: Dict[str, Any]) -> str:
        """Generate a unique key for a pattern."""
        return f"{action.action_type.name}_{config.get('user_agent_idx', 0)}_{config.get('ja4_profile', '')}"
    
    def _get_pattern_key_from_pattern(self, pattern: Dict[str, Any]) -> str:
        """Generate a unique key from a stored pattern."""
        config = pattern.get('config_snapshot', {})
        return f"{pattern['action_type'].name}_{config.get('user_agent_idx', 0)}_{config.get('ja4_profile', '')}"


# =============================================================================
# EPSILON-GREEDY EXPLORATION (Task 18.5)
# Implements epsilon-greedy exploration with decay
# =============================================================================

class EpsilonGreedyPolicy:
    """
    Epsilon-greedy exploration policy with configurable decay.
    
    **Validates: Requirements 9.5**
    """
    
    def __init__(self, 
                 initial_epsilon: float = 0.3,
                 epsilon_decay: float = 0.995,
                 epsilon_min: float = 0.01):
        self.epsilon = initial_epsilon
        self.initial_epsilon = initial_epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.step_count = 0
        
    def should_explore(self) -> bool:
        """
        Determine if the agent should explore (random action) or exploit (best action).
        
        **Validates: Requirements 9.5**
        """
        return random.random() < self.epsilon
    
    def decay_epsilon(self):
        """Apply epsilon decay after each step."""
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        self.step_count += 1
    
    def reset_epsilon(self, new_epsilon: Optional[float] = None):
        """Reset epsilon to initial or specified value."""
        self.epsilon = new_epsilon if new_epsilon is not None else self.initial_epsilon
        self.step_count = 0
    
    def get_exploration_rate(self) -> float:
        """Get current exploration rate."""
        return self.epsilon
    
    def set_exploration_rate(self, rate: float):
        """Set exploration rate directly."""
        self.epsilon = max(self.epsilon_min, min(1.0, rate))



# =============================================================================
# ONLINE AND OFFLINE LEARNING MODES (Task 18.6)
# Supports pre-trained model loading and online policy gradient updates
# =============================================================================

@dataclass
class Experience:
    """Experience tuple for experience replay."""
    observation: WAFObservation
    action: WAFBypassAction
    reward: float
    next_observation: WAFObservation
    done: bool
    timestamp: datetime = field(default_factory=datetime.now)


class ExperienceReplayBuffer:
    """
    Experience replay buffer for online learning.
    
    **Validates: Requirements 9.6**
    """
    
    def __init__(self, capacity: int = 10000):
        self.buffer: deque = deque(maxlen=capacity)
        self.capacity = capacity
        
    def add(self, experience: Experience):
        """Add an experience to the buffer."""
        self.buffer.append(experience)
  

    def sample(self, batch_size: int) -> List[Experience]:
        """Sample a batch of experiences for training."""
        if len(self.buffer) < batch_size:
            return list(self.buffer)
        return random.sample(list(self.buffer), batch_size)
    
    def __len__(self) -> int:
        return len(self.buffer)
    
    def clear(self):
        """Clear the buffer."""
        self.buffer.clear()


class PolicyNetwork:
    """
    Simple policy network for online learning.
    
    Uses numpy for lightweight implementation without heavy ML dependencies.
    
    **Validates: Requirements 9.6**
    """
    
    def __init__(self, state_dim: int = 60, action_dim: int = 15, hidden_dim: int = 64):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.hidden_dim = hidden_dim
        
        # Initialize weights with Xavier initialization
        self.w1 = np.random.randn(state_dim, hidden_dim) * np.sqrt(2.0 / state_dim)
        self.b1 = np.zeros(hidden_dim)
        self.w2 = np.random.randn(hidden_dim, action_dim) * np.sqrt(2.0 / hidden_dim)
        self.b2 = np.zeros(action_dim)
        
    def forward(self, state: np.ndarray) -> np.ndarray:
        """Forward pass through the network."""
        # Hidden layer with ReLU
        h = np.maximum(0, np.dot(state, self.w1) + self.b1)
        # Output layer with softmax
        logits = np.dot(h, self.w2) + self.b2
        exp_logits = np.exp(logits - np.max(logits))  # Numerical stability
        return exp_logits / np.sum(exp_logits)
    
    def get_action_probabilities(self, state: np.ndarray) -> np.ndarray:
        """Get action probabilities from state."""
        return self.forward(state)
    
    def update(self, state: np.ndarray, action_idx: int, advantage: float, 
               learning_rate: float = 0.001):
        """
        Update policy using policy gradient.
        
        **Validates: Requirements 9.6**
        """
        # Forward pass
        h = np.maximum(0, np.dot(state, self.w1) + self.b1)
        logits = np.dot(h, self.w2) + self.b2
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / np.sum(exp_logits)
        
        # Compute gradient of log probability
        grad_logits = -probs.copy()
        grad_logits[action_idx] += 1.0
        
        # Scale by advantage
        grad_logits *= advantage
        
        # Backprop through output layer
        grad_w2 = np.outer(h, grad_logits)
        grad_b2 = grad_logits
        
        # Backprop through hidden layer
        grad_h = np.dot(grad_logits, self.w2.T)
        grad_h = grad_h * (h > 0)  # ReLU gradient
        
        grad_w1 = np.outer(state, grad_h)
        grad_b1 = grad_h
        
        # Update weights
        self.w1 += learning_rate * grad_w1
        self.b1 += learning_rate * grad_b1
        self.w2 += learning_rate * grad_w2
        self.b2 += learning_rate * grad_b2
    
    def save(self, filepath: str):
        """Save model weights to file."""
        import pickle
        model_data = {
            'w1': self.w1,
            'b1': self.b1,
            'w2': self.w2,
            'b2': self.b2,
            'state_dim': self.state_dim,
            'action_dim': self.action_dim,
            'hidden_dim': self.hidden_dim
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        logger.info(f"Policy network saved to {filepath}")
    
    def load(self, filepath: str):
        """Load model weights from file."""
        import pickle
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            self.w1 = model_data['w1']
            self.b1 = model_data['b1']
            self.w2 = model_data['w2']
            self.b2 = model_data['b2']
            logger.info(f"Policy network loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load policy network: {e}")


# =============================================================================
# MAIN WAF BYPASS AGENT (Combines all components)
# Implements the complete RL WAF bypass agent
# =============================================================================

class WAFBypassAgent:
    """
    AI-Driven WAF Bypass Agent using Reinforcement Learning.
    
    Combines observation space, action space, exploration/exploitation,
    and online/offline learning to automatically adapt to WAF defenses.
    
    **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6**
    """
    
    # Default user agents for rotation
    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    ]
    
    # Default JA4 profiles
    DEFAULT_JA4_PROFILES = [
        "chrome_120_windows",
        "chrome_120_macos",
        "firefox_121_windows",
        "firefox_121_macos",
        "safari_17_macos",
        "edge_120_windows",
    ]
    
    def __init__(self,
                 initial_epsilon: float = 0.3,
                 epsilon_decay: float = 0.995,
                 epsilon_min: float = 0.01,
                 learning_rate: float = 0.1,
                 replay_buffer_size: int = 10000,
                 model_path: Optional[str] = None,
                 online_learning: bool = True):
        """
        Initialize the WAF Bypass Agent.
        
        Args:
            initial_epsilon: Initial exploration rate
            epsilon_decay: Decay rate for epsilon
            epsilon_min: Minimum exploration rate
            learning_rate: Learning rate for policy updates
            replay_buffer_size: Size of experience replay buffer
            model_path: Path to pre-trained model (offline mode)
            online_learning: Whether to enable online learning
        
        **Validates: Requirements 9.5, 9.6**
        """
        # Core components
        self.observation = WAFObservation()
        self.exploration_tracker = ExplorationTracker()
        self.reinforcement_tracker = ReinforcementTracker(learning_rate=learning_rate)
        self.epsilon_policy = EpsilonGreedyPolicy(
            initial_epsilon=initial_epsilon,
            epsilon_decay=epsilon_decay,
            epsilon_min=epsilon_min
        )
        
        # Experience replay for online learning
        self.replay_buffer = ExperienceReplayBuffer(capacity=replay_buffer_size)
        
        # Policy network for online learning
        # Calculate actual state dimension from observation
        dummy_obs = WAFObservation()
        state_dim = len(dummy_obs.to_vector())
        self.policy_network = PolicyNetwork(
            state_dim=state_dim,
            action_dim=len(WAFBypassActionType)
        )
        
        # Configuration
        self.user_agents = self.DEFAULT_USER_AGENTS.copy()
        self.ja4_profiles = self.DEFAULT_JA4_PROFILES.copy()
        self.online_learning = online_learning
        self.learning_rate = learning_rate
        
        # Current configuration state
        self.current_config: Dict[str, Any] = {
            'user_agent': self.user_agents[0],
            'user_agent_idx': 0,
            'ja4_profile': self.ja4_profiles[0],
            'headers': {},
            'timing_delay': 0.0,
        }
        
        # Statistics
        self.total_requests = 0
        self.successful_requests = 0
        self.blocked_requests = 0
        self.rate_limited_requests = 0
        
        # Load pre-trained model if provided (offline mode)
        if model_path:
            self.load_model(model_path)
            logger.info(f"Loaded pre-trained model from {model_path}")
        
        logger.info(f"WAF Bypass Agent initialized (online_learning={online_learning}, "
                   f"epsilon={initial_epsilon})")
    
    def select_action(self, force_explore: bool = False) -> WAFBypassAction:
        """
        Select an action using epsilon-greedy policy.
        
        **Validates: Requirements 9.2, 9.5**
        """
        # Check if we should explore
        should_explore = force_explore or self.epsilon_policy.should_explore()
        
        if should_explore:
            # Exploration: try unexplored or random actions
            unexplored = self.exploration_tracker.get_unexplored_actions()
            if unexplored:
                action_type = random.choice(unexplored)
            else:
                action_type = random.choice(list(WAFBypassActionType))
            
            magnitude = random.uniform(0.5, 1.5)
            parameters = self._generate_random_parameters(action_type)
            
            logger.debug(f"Exploring: {action_type.name}")
        else:
            # Exploitation: use policy network or reinforcement weights
            if self.online_learning:
                # Use policy network
                state_vector = self.observation.to_vector()
                action_probs = self.policy_network.get_action_probabilities(state_vector)
                action_idx = np.argmax(action_probs)
                action_type = list(WAFBypassActionType)[action_idx]
                magnitude = 1.0 + (action_probs[action_idx] - 0.5)
            else:
                # Use reinforcement weights
                best_action = None
                best_prob = 0.0
                for action_type in WAFBypassActionType:
                    prob = self.reinforcement_tracker.get_action_probability(action_type)
                    if prob > best_prob:
                        best_prob = prob
                        best_action = action_type
                action_type = best_action or WAFBypassActionType.NO_ACTION
                magnitude = 1.0
            
            parameters = self._generate_parameters_for_action(action_type)
            logger.debug(f"Exploiting: {action_type.name}")
        
        action = WAFBypassAction(
            action_type=action_type,
            magnitude=magnitude,
            parameters=parameters
        )
        
        return action
    
    def process_response(self, response_code: int, latency_ms: float, 
                        action: WAFBypassAction) -> float:
        """
        Process HTTP response and update agent state.
        
        **Validates: Requirements 9.1, 9.3, 9.4**
        """
        # Update observation
        self.observation.add_response(response_code, latency_ms)
        
        # Update statistics
        self.total_requests += 1
        if 200 <= response_code < 300:
            self.successful_requests += 1
        elif response_code == 403:
            self.blocked_requests += 1
        elif response_code == 429:
            self.rate_limited_requests += 1
        
        # Calculate reward
        reward = self._calculate_reward(response_code, latency_ms)
        
        # Record in exploration tracker
        self.exploration_tracker.record_response(action, response_code)
        
        # Handle 403 responses - trigger exploration (Requirement 9.3)
        if response_code == 403:
            if self.exploration_tracker.should_explore(response_code):
                logger.info("403 detected - triggering exploration mode")
                self.reinforcement_tracker.record_failure(action, response_code)
        
        # Handle 200 responses - reinforce pattern (Requirement 9.4)
        elif 200 <= response_code < 300:
            self.reinforcement_tracker.record_success(action, self.current_config)
        
        # Handle rate limiting
        elif response_code == 429:
            self.reinforcement_tracker.record_failure(action, response_code)
        
        # Decay epsilon
        self.epsilon_policy.decay_epsilon()
        
        return reward
    
    def update_with_experience(self, 
                              prev_observation: WAFObservation,
                              action: WAFBypassAction,
                              reward: float,
                              done: bool = False):
        """
        Update agent with experience for online learning.
        
        **Validates: Requirements 9.6**
        """
        if not self.online_learning:
            return
        
        # Create experience
        experience = Experience(
            observation=prev_observation,
            action=action,
            reward=reward,
            next_observation=WAFObservation(
                response_codes=self.observation.response_codes.copy(),
                latencies=self.observation.latencies.copy(),
                current_user_agent_idx=self.observation.current_user_agent_idx,
                current_ja4_profile=self.observation.current_ja4_profile,
                current_headers=self.observation.current_headers.copy(),
                current_timing_delay=self.observation.current_timing_delay,
                success_rate=self.observation.success_rate,
                block_rate=self.observation.block_rate,
                rate_limit_rate=self.observation.rate_limit_rate
            ),
            done=done
        )
        
        # Add to replay buffer
        self.replay_buffer.add(experience)
        
        # Online policy gradient update
        state_vector = prev_observation.to_vector()
        action_idx = list(WAFBypassActionType).index(action.action_type)
        
        # Use reward as advantage (simple REINFORCE)
        self.policy_network.update(
            state_vector, 
            action_idx, 
            reward,
            learning_rate=self.learning_rate
        )
    
    def train_from_replay(self, batch_size: int = 32):
        """
        Train from experience replay buffer.
        
        **Validates: Requirements 9.6**
        """
        if len(self.replay_buffer) < batch_size:
            return
        
        batch = self.replay_buffer.sample(batch_size)
        
        for exp in batch:
            state_vector = exp.observation.to_vector()
            action_idx = list(WAFBypassActionType).index(exp.action.action_type)
            
            self.policy_network.update(
                state_vector,
                action_idx,
                exp.reward,
                learning_rate=self.learning_rate * 0.1  # Lower LR for replay
            )
    
    def apply_action(self, action: WAFBypassAction) -> Dict[str, Any]:
        """
        Apply action to current configuration.
        
        **Validates: Requirements 9.2**
        """
        self.current_config = action.apply_to_config(
            self.current_config,
            self.user_agents,
            self.ja4_profiles
        )
        
        # Update observation state
        self.observation.current_user_agent_idx = self.current_config.get('user_agent_idx', 0)
        self.observation.current_ja4_profile = self.current_config.get('ja4_profile', '')
        self.observation.current_headers = self.current_config.get('headers', {})
        self.observation.current_timing_delay = self.current_config.get('timing_delay', 0.0)
        
        return self.current_config
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current request configuration."""
        return self.current_config.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'blocked_requests': self.blocked_requests,
            'rate_limited_requests': self.rate_limited_requests,
            'success_rate': self.successful_requests / max(1, self.total_requests),
            'block_rate': self.blocked_requests / max(1, self.total_requests),
            'exploration_rate': self.epsilon_policy.get_exploration_rate(),
            'replay_buffer_size': len(self.replay_buffer),
        }
    
    def save_model(self, filepath: str):
        """
        Save model to file for offline use.
        
        **Validates: Requirements 9.6**
        """
        import pickle
        model_data = {
            'policy_network': {
                'w1': self.policy_network.w1,
                'b1': self.policy_network.b1,
                'w2': self.policy_network.w2,
                'b2': self.policy_network.b2,
            },
            'reinforcement_weights': dict(self.reinforcement_tracker.action_weights),
            'epsilon': self.epsilon_policy.epsilon,
            'statistics': self.get_statistics(),
            'successful_patterns': self.reinforcement_tracker.successful_patterns[-50:],
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"WAF Bypass Agent model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """
        Load pre-trained model from file.
        
        **Validates: Requirements 9.6**
        """
        import pickle
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            # Load policy network weights
            if 'policy_network' in model_data:
                self.policy_network.w1 = model_data['policy_network']['w1']
                self.policy_network.b1 = model_data['policy_network']['b1']
                self.policy_network.w2 = model_data['policy_network']['w2']
                self.policy_network.b2 = model_data['policy_network']['b2']
            
            # Load reinforcement weights
            if 'reinforcement_weights' in model_data:
                for action_type, weight in model_data['reinforcement_weights'].items():
                    if isinstance(action_type, WAFBypassActionType):
                        self.reinforcement_tracker.action_weights[action_type] = weight
            
            # Load epsilon
            if 'epsilon' in model_data:
                self.epsilon_policy.epsilon = model_data['epsilon']
            
            # Load successful patterns
            if 'successful_patterns' in model_data:
                self.reinforcement_tracker.successful_patterns = model_data['successful_patterns']
            
            logger.info(f"WAF Bypass Agent model loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def _calculate_reward(self, response_code: int, latency_ms: float) -> float:
        """
        Calculate reward from HTTP response.
        
        **Validates: Requirements 9.1**
        """
        # Base reward based on response code
        if 200 <= response_code < 300:
            reward = 1.0  # Success
        elif response_code == 403:
            reward = -0.5  # Blocked
        elif response_code == 429:
            reward = -0.3  # Rate limited
        elif 500 <= response_code < 600:
            reward = 0.5  # Server error (might indicate impact)
        else:
            reward = 0.0  # Other
        
        # Penalize high latency (normalized to max 0.5 penalty)
        latency_penalty = min(latency_ms / 10000.0, 0.5)
        reward -= latency_penalty
        
        return reward
    
    def _generate_random_parameters(self, action_type: WAFBypassActionType) -> Dict[str, Any]:
        """Generate random parameters for an action."""
        params = {}
        
        if action_type == WAFBypassActionType.CHANGE_USER_AGENT:
            params['user_agent_idx'] = random.randint(0, len(self.user_agents) - 1)
        
        elif action_type == WAFBypassActionType.ADD_HEADER:
            headers = [
                ('X-Forwarded-For', f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}'),
                ('X-Real-IP', f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}'),
                ('X-Request-ID', str(random.randint(100000, 999999))),
                ('Accept-Language', random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.9', 'de-DE,de;q=0.9'])),
            ]
            header_name, header_value = random.choice(headers)
            params['header_name'] = header_name
            params['header_value'] = header_value
        
        elif action_type == WAFBypassActionType.REMOVE_HEADER:
            if self.current_config.get('headers'):
                params['header_name'] = random.choice(list(self.current_config['headers'].keys()))
        
        elif action_type == WAFBypassActionType.SWITCH_JA4_PROFILE:
            params['profile_name'] = random.choice(self.ja4_profiles)
        
        return params
    
    def _generate_parameters_for_action(self, action_type: WAFBypassActionType) -> Dict[str, Any]:
        """Generate parameters based on learned patterns."""
        # Try to use successful patterns
        best_pattern = self.reinforcement_tracker.get_best_pattern()
        
        if best_pattern and best_pattern['action_type'] == action_type:
            return best_pattern.get('parameters', {})
        
        # Fall back to random parameters
        return self._generate_random_parameters(action_type)
