#!/usr/bin/env python3
"""
Reinforcement Learning Agent for Attack Optimization

Implements Q-learning and policy gradient methods for dynamic attack parameter
optimization. The RL agent learns from attack results to continuously improve
effectiveness while adapting to changing network conditions and defenses.
"""

import numpy as np
import random
import logging
import json
import pickle
import threading
import time
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
from enum import Enum, auto
import hashlib

# Import defense detection components
from .advanced_defense_detection import (
    AdvancedDefenseDetectionSystem, DefensePattern, DefenseMetrics
)
from .defense_evasion import DefenseType, DefenseSignature

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of actions the RL agent can take"""
    INCREASE_RATE = auto()
    DECREASE_RATE = auto()
    INCREASE_PACKET_SIZE = auto()
    DECREASE_PACKET_SIZE = auto()
    INCREASE_THREADS = auto()
    DECREASE_THREADS = auto()
    CHANGE_PROTOCOL = auto()
    ADJUST_TIMING = auto()
    MODIFY_EVASION = auto()
    # Defense-specific actions
    ENABLE_IP_ROTATION = auto()
    ENABLE_USER_AGENT_ROTATION = auto()
    ENABLE_REQUEST_FRAGMENTATION = auto()
    ENABLE_TIMING_RANDOMIZATION = auto()
    SWITCH_TO_SLOW_ATTACK = auto()
    NO_CHANGE = auto()


@dataclass
class State:
    """Represents the current state of the attack environment"""
    # Attack parameters
    packet_rate: float
    packet_size: int
    thread_count: int
    protocol: str
    evasion_level: int
    
    # Performance metrics
    current_pps: float
    current_bandwidth: float
    error_rate: float
    success_rate: float
    
    # Target response
    target_response_time: float
    target_error_rate: float
    target_availability: float
    
    # Network conditions
    network_latency: float
    packet_loss: float
    congestion_level: float
    
    # Defense detection state
    detected_defenses: List[str] = field(default_factory=list)
    rate_limit_detected: bool = False
    waf_detected: bool = False
    behavioral_defense_detected: bool = False
    defense_confidence: float = 0.0
    
    def to_vector(self) -> np.ndarray:
        """Convert state to numerical vector for RL algorithms"""
        # Normalize values to [0, 1] range
        return np.array([
            min(self.packet_rate / 1000000, 1.0),  # Normalize to 1M PPS
            min(self.packet_size / 65535, 1.0),    # Normalize to max packet size
            min(self.thread_count / 64, 1.0),      # Normalize to 64 threads
            1.0 if self.protocol == 'TCP' else 0.5 if self.protocol == 'UDP' else 0.0,
            min(self.evasion_level / 10, 1.0),     # Normalize to level 10
            min(self.current_pps / 1000000, 1.0),  # Normalize performance
            min(self.current_bandwidth / 10e9, 1.0),  # Normalize to 10 Gbps
            min(self.error_rate, 1.0),
            min(self.success_rate, 1.0),
            min(self.target_response_time / 10000, 1.0),  # Normalize to 10s
            min(self.target_error_rate, 1.0),
            min(self.target_availability, 1.0),
            min(self.network_latency / 1000, 1.0),  # Normalize to 1s
            min(self.packet_loss, 1.0),
            min(self.congestion_level, 1.0),
            # Defense detection features
            1.0 if self.rate_limit_detected else 0.0,
            1.0 if self.waf_detected else 0.0,
            1.0 if self.behavioral_defense_detected else 0.0,
            min(self.defense_confidence, 1.0)
        ], dtype=np.float32)
    
    def get_state_key(self) -> str:
        """Get discrete state key for Q-table"""
        # Discretize continuous values for Q-learning
        rate_bucket = int(self.packet_rate // 100000)  # 100k buckets
        size_bucket = int(self.packet_size // 500)     # 500 byte buckets
        thread_bucket = int(self.thread_count // 2)    # 2 thread buckets
        perf_bucket = int(self.current_pps // 50000)   # 50k PPS buckets
        error_bucket = int(self.error_rate * 10)       # 0.1 error buckets
        
        # Add defense detection state
        defense_state = f"rl{int(self.rate_limit_detected)}_waf{int(self.waf_detected)}_beh{int(self.behavioral_defense_detected)}"
        
        return f"{rate_bucket}_{size_bucket}_{thread_bucket}_{perf_bucket}_{error_bucket}_{defense_state}"


@dataclass
class Action:
    """Represents an action the RL agent can take"""
    action_type: ActionType
    magnitude: float = 1.0  # Scaling factor for the action
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    def apply_to_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply this action to an attack configuration"""
        new_config = config.copy()
        
        if self.action_type == ActionType.INCREASE_RATE:
            new_config['packet_rate'] = min(
                config.get('packet_rate', 10000) * (1 + 0.2 * self.magnitude),
                10000000  # Max 10M PPS
            )
        elif self.action_type == ActionType.DECREASE_RATE:
            new_config['packet_rate'] = max(
                config.get('packet_rate', 10000) * (1 - 0.2 * self.magnitude),
                1000  # Min 1K PPS
            )
        elif self.action_type == ActionType.INCREASE_PACKET_SIZE:
            new_config['packet_size'] = min(
                config.get('packet_size', 1472) + int(100 * self.magnitude),
                65535  # Max packet size
            )
        elif self.action_type == ActionType.DECREASE_PACKET_SIZE:
            new_config['packet_size'] = max(
                config.get('packet_size', 1472) - int(100 * self.magnitude),
                64  # Min packet size
            )
        elif self.action_type == ActionType.INCREASE_THREADS:
            new_config['thread_count'] = min(
                config.get('thread_count', 4) + int(2 * self.magnitude),
                64  # Max threads
            )
        elif self.action_type == ActionType.DECREASE_THREADS:
            new_config['thread_count'] = max(
                config.get('thread_count', 4) - int(2 * self.magnitude),
                1  # Min threads
            )
        elif self.action_type == ActionType.CHANGE_PROTOCOL:
            protocols = ['UDP', 'TCP', 'HTTP', 'ICMP']
            current_proto = config.get('protocol', 'UDP')
            available = [p for p in protocols if p != current_proto]
            new_config['protocol'] = random.choice(available)
        elif self.action_type == ActionType.ADJUST_TIMING:
            new_config['burst_duration'] = max(
                0.1, config.get('burst_duration', 1.0) * (1 + 0.5 * (self.magnitude - 0.5))
            )
            new_config['pause_duration'] = max(
                0.1, config.get('pause_duration', 0.5) * (1 + 0.5 * (self.magnitude - 0.5))
            )
        elif self.action_type == ActionType.MODIFY_EVASION:
            new_config['evasion_level'] = max(
                0, min(10, config.get('evasion_level', 0) + int(2 * (self.magnitude - 0.5)))
            )
        elif self.action_type == ActionType.ENABLE_IP_ROTATION:
            new_config['ip_rotation'] = True
            new_config['ip_rotation_interval'] = max(1, int(10 * self.magnitude))
        elif self.action_type == ActionType.ENABLE_USER_AGENT_ROTATION:
            new_config['user_agent_rotation'] = True
            new_config['user_agent_pool_size'] = max(5, int(20 * self.magnitude))
        elif self.action_type == ActionType.ENABLE_REQUEST_FRAGMENTATION:
            new_config['request_fragmentation'] = True
            new_config['fragment_size'] = max(64, int(512 * self.magnitude))
        elif self.action_type == ActionType.ENABLE_TIMING_RANDOMIZATION:
            new_config['timing_randomization'] = True
            new_config['timing_jitter'] = min(0.5, 0.1 * self.magnitude)
        elif self.action_type == ActionType.SWITCH_TO_SLOW_ATTACK:
            new_config['attack_mode'] = 'slow'
            new_config['slow_attack_delay'] = max(0.1, 2.0 * self.magnitude)
        # NO_CHANGE doesn't modify the config
        
        return new_config


@dataclass
class Experience:
    """Experience tuple for reinforcement learning"""
    state: State
    action: Action
    reward: float
    next_state: State
    done: bool
    timestamp: datetime = field(default_factory=datetime.now)


class QLearningAgent:
    """Q-Learning agent for attack optimization"""
    
    def __init__(self, 
                 learning_rate: float = 0.1,
                 discount_factor: float = 0.95,
                 epsilon: float = 0.3,
                 epsilon_decay: float = 0.995,
                 epsilon_min: float = 0.01):
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        
        # Q-table: state_key -> {action_type -> q_value}
        self.q_table: Dict[str, Dict[ActionType, float]] = defaultdict(
            lambda: {action_type: 0.0 for action_type in ActionType}
        )
        
        # Experience tracking
        self.experiences: deque = deque(maxlen=10000)
        self.episode_count = 0
        self.total_reward = 0.0
        
        # Performance tracking
        self.performance_history = deque(maxlen=1000)
        self.action_counts = defaultdict(int)
        
        logger.info("Q-Learning agent initialized")
    
    def select_action(self, state: State) -> Action:
        """Select action using epsilon-greedy policy"""
        state_key = state.get_state_key()
        
        # Epsilon-greedy exploration
        if random.random() < self.epsilon:
            # Random exploration
            action_type = random.choice(list(ActionType))
            magnitude = random.uniform(0.1, 2.0)
        else:
            # Greedy exploitation
            q_values = self.q_table[state_key]
            action_type = max(q_values, key=q_values.get)
            # Use magnitude based on confidence in action
            magnitude = 1.0 + (q_values[action_type] - 0.5) * 0.5
            magnitude = max(0.1, min(2.0, magnitude))
        
        action = Action(action_type=action_type, magnitude=magnitude)
        self.action_counts[action_type] += 1
        
        return action
    
    def update_q_value(self, experience: Experience):
        """Update Q-value based on experience"""
        state_key = experience.state.get_state_key()
        next_state_key = experience.next_state.get_state_key()
        action_type = experience.action.action_type
        
        # Current Q-value
        current_q = self.q_table[state_key][action_type]
        
        # Maximum Q-value for next state
        if experience.done:
            max_next_q = 0.0
        else:
            max_next_q = max(self.q_table[next_state_key].values())
        
        # Q-learning update rule
        new_q = current_q + self.learning_rate * (
            experience.reward + self.discount_factor * max_next_q - current_q
        )
        
        self.q_table[state_key][action_type] = new_q
        
        # Store experience
        self.experiences.append(experience)
        self.total_reward += experience.reward
        
        # Decay epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
    
    def get_q_value(self, state: State, action_type: ActionType) -> float:
        """Get Q-value for state-action pair"""
        state_key = state.get_state_key()
        return self.q_table[state_key][action_type]
    
    def get_best_action(self, state: State) -> Action:
        """Get the best action for a given state (no exploration)"""
        state_key = state.get_state_key()
        q_values = self.q_table[state_key]
        best_action_type = max(q_values, key=q_values.get)
        
        return Action(action_type=best_action_type, magnitude=1.0)
    
    def save_model(self, filepath: str):
        """Save Q-table to file"""
        model_data = {
            'q_table': dict(self.q_table),
            'learning_rate': self.learning_rate,
            'discount_factor': self.discount_factor,
            'epsilon': self.epsilon,
            'episode_count': self.episode_count,
            'total_reward': self.total_reward,
            'action_counts': dict(self.action_counts)
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Q-Learning model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load Q-table from file"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.q_table = defaultdict(
                lambda: {action_type: 0.0 for action_type in ActionType},
                model_data['q_table']
            )
            self.learning_rate = model_data.get('learning_rate', self.learning_rate)
            self.discount_factor = model_data.get('discount_factor', self.discount_factor)
            self.epsilon = model_data.get('epsilon', self.epsilon)
            self.episode_count = model_data.get('episode_count', 0)
            self.total_reward = model_data.get('total_reward', 0.0)
            self.action_counts = defaultdict(int, model_data.get('action_counts', {}))
            
            logger.info(f"Q-Learning model loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load Q-Learning model: {e}")


class PolicyGradientAgent:
    """Policy Gradient agent using REINFORCE algorithm"""
    
    def __init__(self,
                 state_dim: int = 19,  # Updated based on State.to_vector() with defense features
                 action_dim: int = len(ActionType),
                 learning_rate: float = 0.01,
                 gamma: float = 0.99):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.learning_rate = learning_rate
        self.gamma = gamma
        
        # Simple neural network for policy (weights only)
        self.policy_weights = np.random.normal(0, 0.1, (state_dim, action_dim))
        self.policy_bias = np.zeros(action_dim)
        
        # Experience buffer for episode
        self.episode_states = []
        self.episode_actions = []
        self.episode_rewards = []
        
        # Performance tracking
        self.episode_count = 0
        self.average_reward = 0.0
        self.reward_history = deque(maxlen=100)
        
        logger.info("Policy Gradient agent initialized")
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Softmax activation function"""
        exp_x = np.exp(x - np.max(x))
        return exp_x / np.sum(exp_x)
    
    def _get_action_probabilities(self, state: State) -> np.ndarray:
        """Get action probabilities from policy network"""
        state_vector = state.to_vector()
        logits = np.dot(state_vector, self.policy_weights) + self.policy_bias
        return self._softmax(logits)
    
    def select_action(self, state: State) -> Action:
        """Select action based on policy probabilities"""
        action_probs = self._get_action_probabilities(state)
        
        # Sample action from probability distribution
        action_idx = np.random.choice(len(ActionType), p=action_probs)
        action_type = list(ActionType)[action_idx]
        
        # Generate magnitude based on action probability (higher prob = more confident)
        magnitude = 0.5 + action_probs[action_idx] * 1.5
        magnitude = max(0.1, min(2.0, magnitude))
        
        action = Action(action_type=action_type, magnitude=magnitude)
        
        # Store for training
        self.episode_states.append(state.to_vector())
        self.episode_actions.append(action_idx)
        
        return action
    
    def add_reward(self, reward: float):
        """Add reward for the last action"""
        self.episode_rewards.append(reward)
    
    def update_policy(self):
        """Update policy using REINFORCE algorithm"""
        if len(self.episode_rewards) == 0:
            return
        
        # Calculate discounted rewards
        discounted_rewards = self._calculate_discounted_rewards()
        
        # Normalize rewards
        if len(discounted_rewards) > 1:
            discounted_rewards = (discounted_rewards - np.mean(discounted_rewards)) / (np.std(discounted_rewards) + 1e-8)
        
        # Update policy weights
        for t in range(len(self.episode_states)):
            state = self.episode_states[t]
            action = self.episode_actions[t]
            reward = discounted_rewards[t]
            
            # Get action probabilities
            action_probs = self._softmax(np.dot(state, self.policy_weights) + self.policy_bias)
            
            # Calculate gradients
            grad_log_prob = np.zeros(self.action_dim)
            grad_log_prob[action] = 1.0 / (action_probs[action] + 1e-8)
            
            # Update weights
            self.policy_weights += self.learning_rate * reward * np.outer(state, grad_log_prob)
            self.policy_bias += self.learning_rate * reward * grad_log_prob
        
        # Track performance
        episode_reward = sum(self.episode_rewards)
        self.reward_history.append(episode_reward)
        self.average_reward = np.mean(self.reward_history)
        self.episode_count += 1
        
        # Clear episode data
        self.episode_states.clear()
        self.episode_actions.clear()
        self.episode_rewards.clear()
        
        logger.debug(f"Policy updated. Episode {self.episode_count}, "
                    f"Reward: {episode_reward:.3f}, Avg: {self.average_reward:.3f}")
    
    def _calculate_discounted_rewards(self) -> np.ndarray:
        """Calculate discounted cumulative rewards"""
        discounted = np.zeros_like(self.episode_rewards, dtype=np.float32)
        cumulative = 0.0
        
        # Calculate backwards for efficiency
        for t in reversed(range(len(self.episode_rewards))):
            cumulative = self.episode_rewards[t] + self.gamma * cumulative
            discounted[t] = cumulative
        
        return discounted
    
    def save_model(self, filepath: str):
        """Save policy network to file"""
        model_data = {
            'policy_weights': self.policy_weights,
            'policy_bias': self.policy_bias,
            'learning_rate': self.learning_rate,
            'gamma': self.gamma,
            'episode_count': self.episode_count,
            'average_reward': self.average_reward
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Policy Gradient model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load policy network from file"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.policy_weights = model_data['policy_weights']
            self.policy_bias = model_data['policy_bias']
            self.learning_rate = model_data.get('learning_rate', self.learning_rate)
            self.gamma = model_data.get('gamma', self.gamma)
            self.episode_count = model_data.get('episode_count', 0)
            self.average_reward = model_data.get('average_reward', 0.0)
            
            logger.info(f"Policy Gradient model loaded from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load Policy Gradient model: {e}")


class ReinforcementLearningOptimizer:
    """Main RL optimizer that coordinates Q-learning and Policy Gradient agents"""
    
    def __init__(self, use_both_agents: bool = True):
        self.q_agent = QLearningAgent()
        self.pg_agent = PolicyGradientAgent() if use_both_agents else None
        self.use_both_agents = use_both_agents
        
        # Defense detection integration
        self.defense_detector = AdvancedDefenseDetectionSystem()
        self.detected_defenses = []
        self.defense_adaptation_history = deque(maxlen=100)
        
        # Enhanced defense detection features
        self.defense_pattern_tracker = deque(maxlen=1000)
        self.defense_signature_cache = {}
        self.real_time_monitoring_active = False
        self.defense_callbacks = []
        
        # Defense detection statistics
        self.defense_detection_stats = {
            'total_detections': 0,
            'rate_limit_detections': 0,
            'waf_detections': 0,
            'behavioral_detections': 0,
            'successful_evasions': 0,
            'failed_evasions': 0
        }
        
        # Optimization state
        self.current_episode = 0
        self.optimization_history = []
        self.best_config = None
        self.best_reward = float('-inf')
        
        # Threading for async updates
        self._lock = threading.Lock()
        
        logger.info(f"RL Optimizer initialized with {'both' if use_both_agents else 'Q-learning only'} agents")
        logger.info("Enhanced defense detection system integrated with RL optimizer")
    
    def optimize_attack_parameters(self, 
                                 current_config: Dict[str, Any],
                                 attack_stats: Dict[str, Any],
                                 target_response: Dict[str, Any],
                                 network_conditions: Dict[str, Any],
                                 response_history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Optimize attack parameters using RL agents with defense detection"""
        
        with self._lock:
            # Perform defense detection if response history is available
            if response_history:
                detected_defenses = self.defense_detector.analyze_comprehensive_defenses(
                    response_history, current_config
                )
                self.detected_defenses = detected_defenses
                
                # Log detected defenses
                if detected_defenses:
                    defense_types = [d.defense_type.value for d in detected_defenses]
                    logger.info(f"Detected defenses: {defense_types}")
                    
                    # Store defense detection event
                    self.defense_adaptation_history.append({
                        'timestamp': datetime.now(),
                        'detected_defenses': defense_types,
                        'confidence_scores': [d.confidence for d in detected_defenses],
                        'episode': self.current_episode
                    })
            
            # Create current state with defense information
            current_state = self._create_state_with_defenses(
                current_config, attack_stats, target_response, 
                network_conditions, self.detected_defenses
            )
            
            # Select action using ensemble of agents with defense-aware logic
            selected_action = self._select_defense_aware_action(current_state)
            agent_used = 'defense_aware'
            
            # Apply action to get new configuration
            new_config = selected_action.apply_to_config(current_config)
            
            # Store optimization step
            optimization_step = {
                'episode': self.current_episode,
                'timestamp': datetime.now(),
                'current_state': current_state,
                'action': selected_action,
                'old_config': current_config.copy(),
                'new_config': new_config.copy(),
                'agent_used': agent_used,
                'detected_defenses': [d.defense_type.value for d in self.detected_defenses],
                'defense_confidence': max([d.confidence for d in self.detected_defenses], default=0.0)
            }
            
            self.optimization_history.append(optimization_step)
            self.current_episode += 1
            
            logger.info(f"RL Episode {self.current_episode}: {selected_action.action_type.name} "
                       f"(magnitude: {selected_action.magnitude:.2f}) using {agent_used}")
            
            if self.detected_defenses:
                logger.info(f"Adapting to detected defenses: {[d.defense_type.value for d in self.detected_defenses]}")
            
            return new_config
    
    def update_with_results(self, 
                          old_config: Dict[str, Any],
                          new_config: Dict[str, Any],
                          old_stats: Dict[str, Any],
                          new_stats: Dict[str, Any],
                          target_response: Dict[str, Any],
                          network_conditions: Dict[str, Any]):
        """Update RL agents with attack results"""
        
        with self._lock:
            if not self.optimization_history:
                return
            
            # Get the last optimization step
            last_step = self.optimization_history[-1]
            
            # Create states
            old_state = self._create_state(old_config, old_stats, target_response, network_conditions)
            new_state = self._create_state(new_config, new_stats, target_response, network_conditions)
            
            # Calculate reward
            reward = self._calculate_reward(old_stats, new_stats, target_response)
            
            # Create experience
            experience = Experience(
                state=old_state,
                action=last_step['action'],
                reward=reward,
                next_state=new_state,
                done=False  # Continuous optimization
            )
            
            # Update agents
            self.q_agent.update_q_value(experience)
            
            if self.pg_agent and last_step['agent_used'] == 'policy_gradient':
                self.pg_agent.add_reward(reward)
                # Update policy at end of episode (every N steps)
                if self.current_episode % 10 == 0:
                    self.pg_agent.update_policy()
            
            # Track best configuration
            if reward > self.best_reward:
                self.best_reward = reward
                self.best_config = new_config.copy()
                logger.info(f"New best configuration found! Reward: {reward:.3f}")
            
            # Update optimization history
            last_step.update({
                'reward': reward,
                'new_stats': new_stats.copy(),
                'experience': experience
            })
    
    def _create_state(self, 
                     config: Dict[str, Any],
                     stats: Dict[str, Any],
                     target_response: Dict[str, Any],
                     network_conditions: Dict[str, Any]) -> State:
        """Create State object from current conditions"""
        
        return State(
            # Attack parameters
            packet_rate=config.get('packet_rate', 10000),
            packet_size=config.get('packet_size', 1472),
            thread_count=config.get('thread_count', 4),
            protocol=config.get('protocol', 'UDP'),
            evasion_level=config.get('evasion_level', 0),
            
            # Performance metrics
            current_pps=stats.get('pps', 0),
            current_bandwidth=stats.get('bps', 0),
            error_rate=stats.get('errors', 0) / max(1, stats.get('packets_sent', 1)),
            success_rate=1.0 - (stats.get('errors', 0) / max(1, stats.get('packets_sent', 1))),
            
            # Target response
            target_response_time=target_response.get('response_time', 0),
            target_error_rate=target_response.get('error_rate', 0),
            target_availability=target_response.get('availability', 1.0),
            
            # Network conditions
            network_latency=network_conditions.get('latency', 0),
            packet_loss=network_conditions.get('packet_loss', 0),
            congestion_level=network_conditions.get('congestion', 0)
        )
    
    def _create_state_with_defenses(self, 
                                   config: Dict[str, Any],
                                   stats: Dict[str, Any],
                                   target_response: Dict[str, Any],
                                   network_conditions: Dict[str, Any],
                                   detected_defenses: List[DefenseSignature]) -> State:
        """Create State object with defense detection information"""
        
        # Analyze detected defenses
        defense_types = [d.defense_type for d in detected_defenses]
        rate_limit_detected = DefenseType.RATE_LIMITING in defense_types
        waf_detected = DefenseType.WAF in defense_types
        behavioral_defense_detected = DefenseType.BEHAVIORAL_ANALYSIS in defense_types
        
        # Calculate overall defense confidence
        defense_confidence = max([d.confidence for d in detected_defenses], default=0.0)
        
        return State(
            # Attack parameters
            packet_rate=config.get('packet_rate', 10000),
            packet_size=config.get('packet_size', 1472),
            thread_count=config.get('thread_count', 4),
            protocol=config.get('protocol', 'UDP'),
            evasion_level=config.get('evasion_level', 0),
            
            # Performance metrics
            current_pps=stats.get('pps', 0),
            current_bandwidth=stats.get('bps', 0),
            error_rate=stats.get('errors', 0) / max(1, stats.get('packets_sent', 1)),
            success_rate=1.0 - (stats.get('errors', 0) / max(1, stats.get('packets_sent', 1))),
            
            # Target response
            target_response_time=target_response.get('response_time', 0),
            target_error_rate=target_response.get('error_rate', 0),
            target_availability=target_response.get('availability', 1.0),
            
            # Network conditions
            network_latency=network_conditions.get('latency', 0),
            packet_loss=network_conditions.get('packet_loss', 0),
            congestion_level=network_conditions.get('congestion', 0),
            
            # Defense detection state
            detected_defenses=[d.defense_type.value for d in detected_defenses],
            rate_limit_detected=rate_limit_detected,
            waf_detected=waf_detected,
            behavioral_defense_detected=behavioral_defense_detected,
            defense_confidence=defense_confidence
        )
    
    def _calculate_reward(self, 
                         old_stats: Dict[str, Any],
                         new_stats: Dict[str, Any],
                         target_response: Dict[str, Any]) -> float:
        """Calculate reward based on performance improvement and defense evasion"""
        
        # Performance improvement
        old_pps = old_stats.get('pps', 0)
        new_pps = new_stats.get('pps', 0)
        pps_improvement = (new_pps - old_pps) / max(old_pps, 1)
        
        # Error rate improvement (lower is better)
        old_error_rate = old_stats.get('errors', 0) / max(1, old_stats.get('packets_sent', 1))
        new_error_rate = new_stats.get('errors', 0) / max(1, new_stats.get('packets_sent', 1))
        error_improvement = old_error_rate - new_error_rate  # Positive if errors decreased
        
        # Target impact (higher response time is better for attack)
        target_impact = target_response.get('response_time', 0) / 1000.0  # Normalize
        
        # Bandwidth utilization
        bandwidth_score = min(new_stats.get('bps', 0) / 1e9, 1.0)  # Normalize to Gbps
        
        # Enhanced defense evasion bonus/penalty system
        defense_evasion_bonus = 0.0
        if self.detected_defenses:
            defense_count = len(self.detected_defenses)
            avg_confidence = sum(d.confidence for d in self.detected_defenses) / defense_count
            
            # Successful evasion: performance improved despite defenses
            if pps_improvement > 0 and error_improvement > 0:
                # Base bonus scaled by defense count and confidence
                base_bonus = 0.3 * defense_count
                confidence_multiplier = 1.0 + (avg_confidence - 0.5)  # 0.5 to 1.5 multiplier
                defense_evasion_bonus = base_bonus * confidence_multiplier
                
                # Update success stats
                self.defense_detection_stats['successful_evasions'] += 1
                
                logger.info(f"Defense evasion success bonus: {defense_evasion_bonus:.2f} "
                           f"(defenses: {defense_count}, confidence: {avg_confidence:.2f})")
            
            # Partial evasion: maintained performance despite defenses
            elif pps_improvement > -0.1 and error_improvement > -0.1:  # Small degradation acceptable
                defense_evasion_bonus = 0.1 * defense_count * avg_confidence
                self.defense_detection_stats['successful_evasions'] += 1
                logger.info(f"Defense maintenance bonus: {defense_evasion_bonus:.2f}")
            
            # Failed evasion: significant performance drop
            elif pps_improvement < -0.2:  # Significant performance drop
                penalty_base = -0.2 * defense_count
                confidence_multiplier = 1.0 + (avg_confidence - 0.5)
                defense_evasion_bonus = penalty_base * confidence_multiplier
                
                # Update failure stats
                self.defense_detection_stats['failed_evasions'] += 1
                
                logger.info(f"Defense adaptation penalty: {defense_evasion_bonus:.2f} "
                           f"(defenses: {defense_count}, confidence: {avg_confidence:.2f})")
            
            # Neutral case: some improvement but not significant
            else:
                defense_evasion_bonus = 0.05 * defense_count  # Small bonus for trying
                logger.debug(f"Neutral defense response: {defense_evasion_bonus:.2f}")
        
        # Combined reward
        reward = (
            0.3 * pps_improvement +      # Performance improvement (reduced weight)
            0.25 * error_improvement +   # Error reduction
            0.2 * target_impact +        # Target impact
            0.1 * bandwidth_score +      # Bandwidth utilization
            0.15 * defense_evasion_bonus # Defense evasion (new component)
        )
        
        # Penalty for very poor performance
        if new_pps < 1000:  # Less than 1K PPS
            reward -= 0.5
        
        # Bonus for exceptional performance
        if new_pps > 100000:  # More than 100K PPS
            reward += 0.2
        
        # Additional bonus for maintaining performance under defense pressure
        if self.detected_defenses and new_pps > old_pps * 0.8:  # Maintained 80% of performance
            reward += 0.1
            logger.info("Performance maintenance bonus under defense pressure: +0.1")
        
        return reward
    
    def _select_defense_aware_action(self, state: State) -> Action:
        """Select action with defense-aware logic"""
        
        # If defenses are detected, prioritize evasion actions
        if state.rate_limit_detected or state.waf_detected or state.behavioral_defense_detected:
            return self._select_evasion_action(state)
        
        # Otherwise, use normal RL agent selection
        if self.use_both_agents and self.pg_agent:
            # Use both agents and combine their decisions
            q_action = self.q_agent.select_action(state)
            pg_action = self.pg_agent.select_action(state)
            
            # Ensemble strategy: alternate between agents or use voting
            if self.current_episode % 2 == 0:
                return q_action
            else:
                return pg_action
        else:
            return self.q_agent.select_action(state)
    
    def _select_evasion_action(self, state: State) -> Action:
        """Select evasion action based on detected defenses with enhanced logic"""
        
        evasion_actions = []
        action_weights = {}
        
        # Rate limiting evasion with prioritization
        if state.rate_limit_detected:
            rate_limit_actions = [
                (ActionType.DECREASE_RATE, 0.8),  # High priority for rate limiting
                (ActionType.ENABLE_TIMING_RANDOMIZATION, 0.7),
                (ActionType.ENABLE_IP_ROTATION, 0.6),
                (ActionType.SWITCH_TO_SLOW_ATTACK, 0.5)
            ]
            evasion_actions.extend([action for action, _ in rate_limit_actions])
            action_weights.update(dict(rate_limit_actions))
            
            # Update detection stats
            self.defense_detection_stats['rate_limit_detections'] += 1
        
        # WAF evasion with prioritization
        if state.waf_detected:
            waf_actions = [
                (ActionType.ENABLE_USER_AGENT_ROTATION, 0.9),  # Very effective against WAF
                (ActionType.ENABLE_REQUEST_FRAGMENTATION, 0.8),
                (ActionType.MODIFY_EVASION, 0.7),
                (ActionType.CHANGE_PROTOCOL, 0.6)
            ]
            evasion_actions.extend([action for action, _ in waf_actions])
            action_weights.update(dict(waf_actions))
            
            # Update detection stats
            self.defense_detection_stats['waf_detections'] += 1
        
        # Behavioral defense evasion with prioritization
        if state.behavioral_defense_detected:
            behavioral_actions = [
                (ActionType.ADJUST_TIMING, 0.8),
                (ActionType.ENABLE_TIMING_RANDOMIZATION, 0.7),
                (ActionType.DECREASE_RATE, 0.6),
                (ActionType.MODIFY_EVASION, 0.5)
            ]
            evasion_actions.extend([action for action, _ in behavioral_actions])
            action_weights.update(dict(behavioral_actions))
            
            # Update detection stats
            self.defense_detection_stats['behavioral_detections'] += 1
        
        # Remove duplicates while preserving weights
        unique_actions = list(set(evasion_actions))
        
        if unique_actions:
            # Enhanced selection based on historical effectiveness
            action_scores = {}
            
            for action_type in unique_actions:
                base_weight = action_weights.get(action_type, 0.5)
                
                # Adjust based on historical success
                historical_success = self._get_action_historical_success(action_type)
                
                # Adjust based on defense confidence
                confidence_multiplier = 1.0 + (state.defense_confidence - 0.5)
                
                # Calculate final score
                final_score = base_weight * (1 + historical_success) * confidence_multiplier
                action_scores[action_type] = final_score
            
            # Select action based on weighted probability
            if action_scores:
                # Normalize scores to probabilities
                total_score = sum(action_scores.values())
                probabilities = {action: score/total_score for action, score in action_scores.items()}
                
                # Weighted random selection
                actions = list(probabilities.keys())
                weights = list(probabilities.values())
                selected_action_type = np.random.choice(actions, p=weights)
            else:
                selected_action_type = random.choice(unique_actions)
            
            # Calculate magnitude based on confidence and urgency
            if state.defense_confidence > 0.8:
                # High confidence - aggressive evasion
                magnitude = 1.5 + random.uniform(0, 0.5)
            elif state.defense_confidence > 0.5:
                # Medium confidence - moderate evasion
                magnitude = 1.0 + random.uniform(0, 0.3)
            else:
                # Low confidence - conservative evasion
                magnitude = 0.7 + random.uniform(0, 0.3)
            
            # Adjust magnitude based on multiple defense types
            defense_count = sum([
                state.rate_limit_detected,
                state.waf_detected,
                state.behavioral_defense_detected
            ])
            
            if defense_count > 1:
                magnitude *= 1.2  # More aggressive when multiple defenses detected
            
            logger.info(f"Enhanced evasion action selected: {selected_action_type.name} "
                       f"(confidence: {state.defense_confidence:.2f}, magnitude: {magnitude:.2f}, "
                       f"defenses: {defense_count})")
            
            # Update total detection stats
            self.defense_detection_stats['total_detections'] += 1
            
            return Action(action_type=selected_action_type, magnitude=magnitude)
        
        # Fallback to normal action selection
        return self.q_agent.select_action(state)
    
    def _get_action_historical_success(self, action_type: ActionType) -> float:
        """Get historical success rate for an action type in defense scenarios"""
        if not self.optimization_history:
            return 0.0
        
        # Find episodes where this action was used against defenses
        relevant_episodes = [
            step for step in self.optimization_history
            if (hasattr(step.get('action', {}), 'action_type') and 
                step['action'].action_type == action_type and
                step.get('detected_defenses', []))
        ]
        
        if not relevant_episodes:
            return 0.0
        
        # Calculate success rate (positive rewards)
        successful_episodes = [
            step for step in relevant_episodes
            if step.get('reward', 0) > 0
        ]
        
        success_rate = len(successful_episodes) / len(relevant_episodes)
        
        # Return normalized success bonus (-0.5 to +0.5)
        return (success_rate - 0.5)
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get optimization statistics including defense detection"""
        
        with self._lock:
            q_stats = {
                'episodes': self.q_agent.episode_count,
                'total_reward': self.q_agent.total_reward,
                'epsilon': self.q_agent.epsilon,
                'q_table_size': len(self.q_agent.q_table),
                'action_counts': dict(self.q_agent.action_counts)
            }
            
            pg_stats = {}
            if self.pg_agent:
                pg_stats = {
                    'episodes': self.pg_agent.episode_count,
                    'average_reward': self.pg_agent.average_reward,
                    'recent_rewards': list(self.pg_agent.reward_history)[-10:]
                }
            
            # Defense detection statistics
            defense_stats = self.defense_detector.get_detection_statistics()
            
            # Enhanced defense adaptation statistics
            defense_adaptations = list(self.defense_adaptation_history)
            defense_adaptation_stats = {
                'total_adaptations': len(defense_adaptations),
                'recent_adaptations': defense_adaptations[-5:],
                'defense_types_encountered': list(set([
                    defense_type 
                    for adaptation in defense_adaptations 
                    for defense_type in adaptation['detected_defenses']
                ])),
                'average_confidence': np.mean([
                    np.mean(adaptation['confidence_scores']) 
                    for adaptation in defense_adaptations 
                    if adaptation['confidence_scores']
                ]) if defense_adaptations else 0.0,
                'detection_stats': self.defense_detection_stats.copy(),
                'evasion_success_rate': (
                    self.defense_detection_stats['successful_evasions'] / 
                    max(1, self.defense_detection_stats['successful_evasions'] + 
                        self.defense_detection_stats['failed_evasions'])
                ),
                'pattern_tracking_active': self.real_time_monitoring_active,
                'pattern_history_size': len(self.defense_pattern_tracker)
            }
            
            return {
                'current_episode': self.current_episode,
                'optimization_steps': len(self.optimization_history),
                'best_reward': self.best_reward,
                'best_config': self.best_config,
                'q_learning': q_stats,
                'policy_gradient': pg_stats,
                'defense_detection': defense_stats,
                'defense_adaptation': defense_adaptation_stats,
                'recent_actions': [
                    {
                        'episode': step['episode'],
                        'action': step['action'].action_type.name,
                        'magnitude': step['action'].magnitude,
                        'reward': step.get('reward', 0),
                        'agent': step['agent_used'],
                        'detected_defenses': step.get('detected_defenses', []),
                        'defense_confidence': step.get('defense_confidence', 0.0)
                    }
                    for step in self.optimization_history[-10:]
                ]
            }
    
    def save_models(self, directory: str = "models/rl/"):
        """Save both RL models"""
        import os
        os.makedirs(directory, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save Q-learning model
        q_path = os.path.join(directory, f"q_learning_{timestamp}.pkl")
        self.q_agent.save_model(q_path)
        
        # Save Policy Gradient model
        if self.pg_agent:
            pg_path = os.path.join(directory, f"policy_gradient_{timestamp}.pkl")
            self.pg_agent.save_model(pg_path)
        
        # Save optimization history
        history_path = os.path.join(directory, f"optimization_history_{timestamp}.json")
        with open(history_path, 'w') as f:
            # Convert non-serializable objects to strings
            serializable_history = []
            for step in self.optimization_history:
                serializable_step = {
                    'episode': step['episode'],
                    'timestamp': step['timestamp'].isoformat(),
                    'action_type': step['action'].action_type.name,
                    'action_magnitude': step['action'].magnitude,
                    'reward': step.get('reward', 0),
                    'agent_used': step['agent_used']
                }
                serializable_history.append(serializable_step)
            
            json.dump(serializable_history, f, indent=2)
        
        logger.info(f"RL models saved to {directory}")
    
    def load_models(self, q_learning_path: str, policy_gradient_path: str = None):
        """Load RL models from files"""
        self.q_agent.load_model(q_learning_path)
        
        if policy_gradient_path and self.pg_agent:
            self.pg_agent.load_model(policy_gradient_path)
        
        logger.info("RL models loaded successfully")
    
    def start_real_time_defense_monitoring(self, callback: Optional[callable] = None):
        """Start real-time defense pattern monitoring"""
        if self.real_time_monitoring_active:
            logger.warning("Real-time defense monitoring already active")
            return
        
        self.real_time_monitoring_active = True
        
        # Add callback if provided
        if callback:
            self.defense_callbacks.append(callback)
        
        # Start the defense detector's real-time monitoring
        self.defense_detector.start_real_time_monitoring(
            callback=self._on_defense_detected
        )
        
        logger.info("Real-time defense monitoring started")
    
    def stop_real_time_defense_monitoring(self):
        """Stop real-time defense pattern monitoring"""
        if not self.real_time_monitoring_active:
            return
        
        self.real_time_monitoring_active = False
        self.defense_detector.stop_real_time_monitoring()
        
        logger.info("Real-time defense monitoring stopped")
    
    def _on_defense_detected(self, recent_responses: List[Dict[str, Any]]):
        """Enhanced callback for real-time defense detection"""
        try:
            # Enhanced real-time signature detection
            detected_signatures = []
            for response in recent_responses:
                signatures = self.defense_detector.detect_real_time_signatures(response)
                detected_signatures.extend(signatures)
            
            # Quick analysis of recent responses
            defense_indicators = self._analyze_defense_patterns(recent_responses)
            
            if defense_indicators or detected_signatures:
                logger.info(f"Real-time defense detection - Indicators: {defense_indicators}, "
                           f"Signatures: {len(detected_signatures)}")
                
                # Update defense pattern tracker with enhanced information
                self.defense_pattern_tracker.append({
                    'timestamp': datetime.now(),
                    'indicators': defense_indicators,
                    'signatures': [sig.defense_type.value for sig in detected_signatures],
                    'signature_confidence': [sig.confidence for sig in detected_signatures],
                    'response_count': len(recent_responses),
                    'enhanced_detection': True
                })
                
                # Update current detected defenses for immediate RL adaptation
                if detected_signatures:
                    self.detected_defenses.extend(detected_signatures)
                    # Keep only recent detections (last 50)
                    self.detected_defenses = self.detected_defenses[-50:]
                
                # Notify callbacks with enhanced data
                for callback in self.defense_callbacks:
                    try:
                        callback(defense_indicators, recent_responses, detected_signatures)
                    except Exception as e:
                        logger.error(f"Defense callback error: {e}")
        
        except Exception as e:
            logger.error(f"Error in enhanced defense detection callback: {e}")
    
    def _analyze_defense_patterns(self, responses: List[Dict[str, Any]]) -> List[str]:
        """Analyze responses for defense patterns"""
        indicators = []
        
        if not responses:
            return indicators
        
        # Check for rate limiting patterns
        rate_limit_codes = [r.get('status_code') for r in responses if r.get('status_code') in [429, 503]]
        if len(rate_limit_codes) > len(responses) * 0.3:  # 30% rate limit responses
            indicators.append('rate_limiting_pattern')
        
        # Check for WAF patterns
        waf_codes = [r.get('status_code') for r in responses if r.get('status_code') in [403, 406, 418]]
        if len(waf_codes) > len(responses) * 0.2:  # 20% WAF responses
            indicators.append('waf_pattern')
        
        # Check for response time degradation
        response_times = [r.get('response_time', 0) for r in responses if r.get('response_time')]
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            if avg_response_time > 5000:  # > 5 seconds
                indicators.append('response_degradation')
        
        # Check for connection failures
        connection_failures = [r for r in responses if r.get('connection_error', False)]
        if len(connection_failures) > len(responses) * 0.4:  # 40% connection failures
            indicators.append('connection_blocking')
        
        return indicators
    
    def register_defense_callback(self, callback: callable):
        """Register a callback for defense detection events"""
        if callback not in self.defense_callbacks:
            self.defense_callbacks.append(callback)
            logger.info("Defense detection callback registered")
    
    def unregister_defense_callback(self, callback: callable):
        """Unregister a defense detection callback"""
        if callback in self.defense_callbacks:
            self.defense_callbacks.remove(callback)
            logger.info("Defense detection callback unregistered")
    
    def get_defense_signatures(self) -> Dict[str, Any]:
        """Get detected defense signatures and patterns"""
        with self._lock:
            signatures = {}
            
            # Get current detected defenses
            for defense in self.detected_defenses:
                defense_type = defense.defense_type.value
                signatures[defense_type] = {
                    'confidence': defense.confidence,
                    'indicators': defense.indicators,
                    'detection_time': defense.detection_time.isoformat(),
                    'response_pattern': getattr(defense, 'response_pattern', {})
                }
            
            # Add pattern analysis from tracker
            recent_patterns = list(self.defense_pattern_tracker)[-10:]
            pattern_summary = {}
            for pattern_data in recent_patterns:
                for indicator in pattern_data['indicators']:
                    if indicator not in pattern_summary:
                        pattern_summary[indicator] = 0
                    pattern_summary[indicator] += 1
            
            signatures['recent_patterns'] = pattern_summary
            signatures['pattern_history_count'] = len(self.defense_pattern_tracker)
            
            return signatures
    
    def generate_defense_report(self) -> Dict[str, Any]:
        """Generate comprehensive defense detection report"""
        with self._lock:
            report = {
                'timestamp': datetime.now().isoformat(),
                'detection_statistics': self.defense_detection_stats.copy(),
                'detected_defenses': self.get_defense_signatures(),
                'adaptation_history': list(self.defense_adaptation_history)[-20:],
                'pattern_analysis': self._analyze_defense_trends(),
                'evasion_effectiveness': self._calculate_evasion_effectiveness(),
                'recommendations': self._generate_defense_recommendations()
            }
            
            return report
    
    def _analyze_defense_trends(self) -> Dict[str, Any]:
        """Analyze defense detection trends"""
        if not self.defense_adaptation_history:
            return {'trend': 'no_data'}
        
        # Analyze defense types over time
        defense_timeline = []
        for adaptation in self.defense_adaptation_history:
            defense_timeline.extend(adaptation['detected_defenses'])
        
        # Count defense types
        defense_counts = {}
        for defense_type in defense_timeline:
            defense_counts[defense_type] = defense_counts.get(defense_type, 0) + 1
        
        # Analyze recent vs older patterns
        recent_adaptations = list(self.defense_adaptation_history)[-10:]
        older_adaptations = list(self.defense_adaptation_history)[:-10] if len(self.defense_adaptation_history) > 10 else []
        
        recent_defenses = []
        for adaptation in recent_adaptations:
            recent_defenses.extend(adaptation['detected_defenses'])
        
        older_defenses = []
        for adaptation in older_adaptations:
            older_defenses.extend(adaptation['detected_defenses'])
        
        trend_analysis = {
            'total_defense_types': len(set(defense_timeline)),
            'most_common_defense': max(defense_counts, key=defense_counts.get) if defense_counts else None,
            'defense_frequency': defense_counts,
            'recent_vs_older': {
                'recent_count': len(recent_defenses),
                'older_count': len(older_defenses),
                'trend': 'increasing' if len(recent_defenses) > len(older_defenses) else 'decreasing' if len(recent_defenses) < len(older_defenses) else 'stable'
            }
        }
        
        return trend_analysis
    
    def _calculate_evasion_effectiveness(self) -> Dict[str, Any]:
        """Calculate effectiveness of evasion strategies"""
        if not self.optimization_history:
            return {'effectiveness': 'no_data'}
        
        # Analyze episodes where defenses were detected
        defense_episodes = [
            step for step in self.optimization_history 
            if step.get('detected_defenses', [])
        ]
        
        if not defense_episodes:
            return {'effectiveness': 'no_defense_episodes'}
        
        # Calculate success rate of evasion actions
        successful_evasions = 0
        total_evasions = 0
        
        for episode in defense_episodes:
            if episode.get('reward', 0) > 0:  # Positive reward indicates success
                successful_evasions += 1
            total_evasions += 1
        
        effectiveness_rate = successful_evasions / total_evasions if total_evasions > 0 else 0
        
        # Analyze evasion action effectiveness
        action_effectiveness = {}
        for episode in defense_episodes:
            action_type = episode.get('action', {}).action_type.name if hasattr(episode.get('action', {}), 'action_type') else 'unknown'
            reward = episode.get('reward', 0)
            
            if action_type not in action_effectiveness:
                action_effectiveness[action_type] = {'total': 0, 'successful': 0, 'avg_reward': 0}
            
            action_effectiveness[action_type]['total'] += 1
            if reward > 0:
                action_effectiveness[action_type]['successful'] += 1
            action_effectiveness[action_type]['avg_reward'] += reward
        
        # Calculate averages
        for action_type in action_effectiveness:
            total = action_effectiveness[action_type]['total']
            action_effectiveness[action_type]['success_rate'] = action_effectiveness[action_type]['successful'] / total
            action_effectiveness[action_type]['avg_reward'] /= total
        
        return {
            'overall_effectiveness': effectiveness_rate,
            'successful_evasions': successful_evasions,
            'total_evasion_attempts': total_evasions,
            'action_effectiveness': action_effectiveness,
            'defense_episodes_analyzed': len(defense_episodes)
        }
    
    def _generate_defense_recommendations(self) -> List[str]:
        """Generate recommendations based on defense detection analysis"""
        recommendations = []
        
        # Analyze current defense signatures
        signatures = self.get_defense_signatures()
        
        # Rate limiting recommendations
        if 'rate_limiting_pattern' in signatures.get('recent_patterns', {}):
            recommendations.extend([
                "Consider implementing distributed attack sources to evade rate limiting",
                "Use timing randomization to avoid detection patterns",
                "Implement gradual rate escalation instead of immediate high rates"
            ])
        
        # WAF recommendations
        if 'waf_pattern' in signatures.get('recent_patterns', {}):
            recommendations.extend([
                "Rotate User-Agent headers and request patterns",
                "Implement request fragmentation to bypass signature detection",
                "Use protocol switching (HTTP/1.1 to HTTP/2) for evasion"
            ])
        
        # Connection blocking recommendations
        if 'connection_blocking' in signatures.get('recent_patterns', {}):
            recommendations.extend([
                "Implement IP rotation with larger address pools",
                "Use connection pooling and reuse strategies",
                "Consider switching to UDP-based attacks if TCP is blocked"
            ])
        
        # Response degradation recommendations
        if 'response_degradation' in signatures.get('recent_patterns', {}):
            recommendations.extend([
                "Target may be under stress - consider maintaining current pressure",
                "Monitor for recovery patterns to time escalation",
                "Consider switching attack vectors to maintain effectiveness"
            ])
        
        # Evasion effectiveness recommendations
        evasion_stats = self._calculate_evasion_effectiveness()
        if isinstance(evasion_stats, dict) and evasion_stats.get('overall_effectiveness', 0) < 0.5:
            recommendations.extend([
                "Current evasion strategies showing low effectiveness",
                "Consider implementing more sophisticated evasion techniques",
                "Analyze successful evasion patterns for optimization"
            ])
        
        # General recommendations
        if not recommendations:
            recommendations.append("No specific defense patterns detected - continue monitoring")
        
        return recommendations


# Global RL optimizer instance
rl_optimizer = ReinforcementLearningOptimizer()

__all__ = [
    'ActionType', 'State', 'Action', 'Experience',
    'QLearningAgent', 'PolicyGradientAgent', 'ReinforcementLearningOptimizer',
    'rl_optimizer'
]