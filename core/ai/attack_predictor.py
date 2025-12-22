"""
Machine Learning Attack Predictor

Advanced ML-based attack vector prediction and optimization:
- Neural network-based effectiveness prediction
- Reinforcement learning for attack strategy
- Anomaly detection for defense identification
- Time series forecasting for target behavior
- Ensemble methods for robust predictions
"""

import numpy as np
import random
import time
import math
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque
import logging
import json

logger = logging.getLogger(__name__)


class AttackVector(Enum):
    """Available attack vectors"""
    TCP_SYN = auto()
    TCP_ACK = auto()
    UDP_FLOOD = auto()
    HTTP_GET = auto()
    HTTP_POST = auto()
    SLOWLORIS = auto()
    DNS_AMPLIFICATION = auto()
    NTP_AMPLIFICATION = auto()
    MEMCACHED = auto()
    SSL_EXHAUSTION = auto()
    WEBSOCKET = auto()
    GRPC = auto()
    MQTT = auto()


@dataclass
class AttackPrediction:
    """Prediction result for an attack vector"""
    vector: AttackVector
    effectiveness_score: float
    confidence: float
    recommended_rate: int
    recommended_size: int
    evasion_techniques: List[str]
    estimated_impact: float
    risk_score: float


@dataclass
class TargetProfile:
    """Profile of target system"""
    ip: str
    ports: List[int]
    services: Dict[int, str]
    os_fingerprint: Optional[str]
    waf_detected: bool
    cdn_detected: bool
    rate_limiting: bool
    response_times: List[float]
    error_rates: List[float]


class NeuralPredictor:
    """
    Simple neural network for attack effectiveness prediction.
    Uses numpy for lightweight implementation without heavy dependencies.
    """
    
    def __init__(self, input_size: int = 20, hidden_size: int = 64, output_size: int = 13):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        
        # Initialize weights with Xavier initialization
        self.W1 = np.random.randn(input_size, hidden_size) * np.sqrt(2.0 / input_size)
        self.b1 = np.zeros((1, hidden_size))
        self.W2 = np.random.randn(hidden_size, hidden_size) * np.sqrt(2.0 / hidden_size)
        self.b2 = np.zeros((1, hidden_size))
        self.W3 = np.random.randn(hidden_size, output_size) * np.sqrt(2.0 / hidden_size)
        self.b3 = np.zeros((1, output_size))
        
        # Training history
        self.loss_history = []
        
    def _relu(self, x: np.ndarray) -> np.ndarray:
        """ReLU activation"""
        return np.maximum(0, x)
    
    def _relu_derivative(self, x: np.ndarray) -> np.ndarray:
        """ReLU derivative"""
        return (x > 0).astype(float)
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Softmax activation"""
        exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=1, keepdims=True)
    
    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        """Sigmoid activation"""
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def forward(self, X: np.ndarray) -> np.ndarray:
        """Forward pass"""
        self.z1 = np.dot(X, self.W1) + self.b1
        self.a1 = self._relu(self.z1)
        
        self.z2 = np.dot(self.a1, self.W2) + self.b2
        self.a2 = self._relu(self.z2)
        
        self.z3 = np.dot(self.a2, self.W3) + self.b3
        self.a3 = self._sigmoid(self.z3)
        
        return self.a3
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make prediction"""
        return self.forward(X)
    
    def train(self, X: np.ndarray, y: np.ndarray, 
              epochs: int = 100, learning_rate: float = 0.01):
        """Train the network"""
        m = X.shape[0]
        
        for epoch in range(epochs):
            # Forward pass
            output = self.forward(X)
            
            # Compute loss (MSE)
            loss = np.mean((output - y) ** 2)
            self.loss_history.append(loss)
            
            # Backward pass
            dz3 = (output - y) * output * (1 - output)
            dW3 = np.dot(self.a2.T, dz3) / m
            db3 = np.sum(dz3, axis=0, keepdims=True) / m
            
            da2 = np.dot(dz3, self.W3.T)
            dz2 = da2 * self._relu_derivative(self.z2)
            dW2 = np.dot(self.a1.T, dz2) / m
            db2 = np.sum(dz2, axis=0, keepdims=True) / m
            
            da1 = np.dot(dz2, self.W2.T)
            dz1 = da1 * self._relu_derivative(self.z1)
            dW1 = np.dot(X.T, dz1) / m
            db1 = np.sum(dz1, axis=0, keepdims=True) / m
            
            # Update weights
            self.W3 -= learning_rate * dW3
            self.b3 -= learning_rate * db3
            self.W2 -= learning_rate * dW2
            self.b2 -= learning_rate * db2
            self.W1 -= learning_rate * dW1
            self.b1 -= learning_rate * db1
            
            if epoch % 10 == 0:
                logger.debug(f"Epoch {epoch}, Loss: {loss:.6f}")


class ReinforcementLearner:
    """
    Q-Learning based attack strategy optimizer.
    Learns optimal attack parameters through trial and error.
    """
    
    def __init__(self, state_size: int = 10, action_size: int = 20,
                 learning_rate: float = 0.1, discount_factor: float = 0.95,
                 exploration_rate: float = 1.0, exploration_decay: float = 0.995):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.exploration_decay = exploration_decay
        self.min_exploration = 0.01
        
        # Q-table (discretized state-action values)
        self.q_table = {}
        
        # Experience replay buffer
        self.memory = deque(maxlen=10000)
        
        # Action definitions
        self.actions = self._define_actions()
        
    def _define_actions(self) -> List[Dict[str, Any]]:
        """Define available actions"""
        actions = []
        
        # Rate adjustments
        for rate_mult in [0.5, 0.75, 1.0, 1.25, 1.5, 2.0]:
            actions.append({'type': 'rate', 'multiplier': rate_mult})
        
        # Size adjustments
        for size in [64, 128, 256, 512, 1024, 1460]:
            actions.append({'type': 'size', 'value': size})
        
        # Vector changes
        for vector in AttackVector:
            actions.append({'type': 'vector', 'value': vector})
        
        return actions[:self.action_size]
    
    def _discretize_state(self, state: np.ndarray) -> str:
        """Discretize continuous state to string key"""
        # Bin continuous values
        bins = 10
        discretized = np.digitize(state, np.linspace(0, 1, bins))
        return str(tuple(discretized))
    
    def get_action(self, state: np.ndarray) -> int:
        """Select action using epsilon-greedy policy"""
        if random.random() < self.exploration_rate:
            return random.randint(0, self.action_size - 1)
        
        state_key = self._discretize_state(state)
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(self.action_size)
        
        return int(np.argmax(self.q_table[state_key]))
    
    def update(self, state: np.ndarray, action: int, 
               reward: float, next_state: np.ndarray, done: bool):
        """Update Q-values"""
        state_key = self._discretize_state(state)
        next_state_key = self._discretize_state(next_state)
        
        if state_key not in self.q_table:
            self.q_table[state_key] = np.zeros(self.action_size)
        if next_state_key not in self.q_table:
            self.q_table[next_state_key] = np.zeros(self.action_size)
        
        # Q-learning update
        current_q = self.q_table[state_key][action]
        if done:
            target_q = reward
        else:
            target_q = reward + self.discount_factor * np.max(self.q_table[next_state_key])
        
        self.q_table[state_key][action] += self.learning_rate * (target_q - current_q)
        
        # Decay exploration
        self.exploration_rate = max(self.min_exploration,
                                   self.exploration_rate * self.exploration_decay)
    
    def remember(self, state: np.ndarray, action: int, 
                reward: float, next_state: np.ndarray, done: bool):
        """Store experience in replay buffer"""
        self.memory.append((state, action, reward, next_state, done))
    
    def replay(self, batch_size: int = 32):
        """Train on batch from replay buffer"""
        if len(self.memory) < batch_size:
            return
        
        batch = random.sample(self.memory, batch_size)
        for state, action, reward, next_state, done in batch:
            self.update(state, action, reward, next_state, done)


class TimeSeriesPredictor:
    """
    Time series forecasting for target behavior prediction.
    Uses exponential smoothing and ARIMA-like techniques.
    """
    
    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.history = deque(maxlen=window_size)
        self.alpha = 0.3  # Smoothing factor
        self.beta = 0.1   # Trend factor
        self.gamma = 0.1  # Seasonality factor
        
    def add_observation(self, value: float):
        """Add new observation"""
        self.history.append(value)
    
    def predict_next(self, steps: int = 1) -> List[float]:
        """Predict next values"""
        if len(self.history) < 3:
            return [self.history[-1] if self.history else 0.0] * steps
        
        data = list(self.history)
        predictions = []
        
        # Initialize
        level = data[0]
        trend = data[1] - data[0]
        
        # Fit model
        for i in range(1, len(data)):
            prev_level = level
            level = self.alpha * data[i] + (1 - self.alpha) * (level + trend)
            trend = self.beta * (level - prev_level) + (1 - self.beta) * trend
        
        # Forecast
        for i in range(steps):
            predictions.append(level + (i + 1) * trend)
        
        return predictions
    
    def detect_anomaly(self, value: float, threshold: float = 2.0) -> bool:
        """Detect if value is anomalous"""
        if len(self.history) < 10:
            return False
        
        data = list(self.history)
        mean = np.mean(data)
        std = np.std(data)
        
        if std == 0:
            return False
        
        z_score = abs(value - mean) / std
        return z_score > threshold
    
    def get_trend(self) -> str:
        """Get current trend direction"""
        if len(self.history) < 5:
            return "unknown"
        
        data = list(self.history)
        recent = np.mean(data[-5:])
        earlier = np.mean(data[-10:-5]) if len(data) >= 10 else np.mean(data[:-5])
        
        if recent > earlier * 1.1:
            return "increasing"
        elif recent < earlier * 0.9:
            return "decreasing"
        return "stable"


class AttackPredictor:
    """
    Main attack prediction engine combining multiple ML techniques.
    """
    
    def __init__(self):
        self.neural_predictor = NeuralPredictor()
        self.rl_learner = ReinforcementLearner()
        self.time_series = TimeSeriesPredictor()
        
        # Feature extractors
        self.feature_history = deque(maxlen=1000)
        
        # Prediction cache
        self.prediction_cache = {}
        self.cache_ttl = 60  # seconds
        
        # Training data
        self.training_data = []
        
    def extract_features(self, target_profile: TargetProfile,
                        attack_stats: Dict[str, Any]) -> np.ndarray:
        """Extract features for prediction"""
        features = []
        
        # Target features
        features.append(len(target_profile.ports) / 100.0)
        features.append(1.0 if target_profile.waf_detected else 0.0)
        features.append(1.0 if target_profile.cdn_detected else 0.0)
        features.append(1.0 if target_profile.rate_limiting else 0.0)
        
        # Response time features
        if target_profile.response_times:
            features.append(np.mean(target_profile.response_times) / 1000.0)
            features.append(np.std(target_profile.response_times) / 1000.0)
            features.append(np.min(target_profile.response_times) / 1000.0)
            features.append(np.max(target_profile.response_times) / 1000.0)
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        # Error rate features
        if target_profile.error_rates:
            features.append(np.mean(target_profile.error_rates))
            features.append(np.std(target_profile.error_rates))
        else:
            features.extend([0.0, 0.0])
        
        # Attack stats features
        features.append(attack_stats.get('pps', 0) / 100000.0)
        features.append(attack_stats.get('bps', 0) / 1e9)
        features.append(attack_stats.get('success_rate', 0))
        features.append(attack_stats.get('error_rate', 0))
        features.append(attack_stats.get('connections', 0) / 10000.0)
        features.append(attack_stats.get('duration', 0) / 3600.0)
        
        # Pad to expected size
        while len(features) < 20:
            features.append(0.0)
        
        return np.array(features[:20]).reshape(1, -1)
    
    def predict_best_vectors(self, target_profile: TargetProfile,
                            attack_stats: Dict[str, Any],
                            top_k: int = 3) -> List[AttackPrediction]:
        """Predict best attack vectors for target"""
        features = self.extract_features(target_profile, attack_stats)
        
        # Neural network prediction
        nn_scores = self.neural_predictor.predict(features)[0]
        
        # Get RL action
        rl_action = self.rl_learner.get_action(features[0])
        
        # Time series prediction for response behavior
        if target_profile.response_times:
            for rt in target_profile.response_times[-10:]:
                self.time_series.add_observation(rt)
        
        predicted_response = self.time_series.predict_next(5)
        trend = self.time_series.get_trend()
        
        # Combine predictions
        predictions = []
        vectors = list(AttackVector)
        
        for i, vector in enumerate(vectors):
            if i >= len(nn_scores):
                break
            
            score = nn_scores[i]
            
            # Adjust based on target profile
            if target_profile.waf_detected and vector in [AttackVector.HTTP_GET, AttackVector.HTTP_POST]:
                score *= 0.7  # WAF reduces HTTP effectiveness
            
            if target_profile.cdn_detected and vector in [AttackVector.TCP_SYN, AttackVector.UDP_FLOOD]:
                score *= 0.8  # CDN reduces volumetric effectiveness
            
            if target_profile.rate_limiting:
                score *= 0.9  # Rate limiting reduces all effectiveness
            
            # Adjust based on trend
            if trend == "increasing":
                score *= 0.95  # Target becoming more resilient
            elif trend == "decreasing":
                score *= 1.05  # Target becoming less resilient
            
            # Calculate recommended parameters
            base_rate = 10000
            if score > 0.7:
                recommended_rate = int(base_rate * 2)
            elif score > 0.4:
                recommended_rate = int(base_rate * 1.5)
            else:
                recommended_rate = base_rate
            
            # Evasion techniques based on defenses
            evasion = []
            if target_profile.waf_detected:
                evasion.extend(['request_splitting', 'encoding_bypass', 'header_manipulation'])
            if target_profile.rate_limiting:
                evasion.extend(['ip_rotation', 'slow_rate', 'distributed'])
            if target_profile.cdn_detected:
                evasion.extend(['origin_bypass', 'cache_poisoning'])
            
            predictions.append(AttackPrediction(
                vector=vector,
                effectiveness_score=float(score),
                confidence=0.5 + 0.5 * (1 - abs(score - 0.5)),
                recommended_rate=recommended_rate,
                recommended_size=1460 if vector in [AttackVector.UDP_FLOOD, AttackVector.TCP_SYN] else 512,
                evasion_techniques=evasion[:3],
                estimated_impact=float(score * 0.8),
                risk_score=0.3 if target_profile.waf_detected else 0.1
            ))
        
        # Sort by effectiveness and return top_k
        predictions.sort(key=lambda x: x.effectiveness_score, reverse=True)
        return predictions[:top_k]
    
    def update_with_feedback(self, target_profile: TargetProfile,
                            attack_stats: Dict[str, Any],
                            actual_effectiveness: float):
        """Update models with actual results"""
        features = self.extract_features(target_profile, attack_stats)
        
        # Store training data
        self.training_data.append({
            'features': features,
            'effectiveness': actual_effectiveness,
            'timestamp': time.time()
        })
        
        # Update RL learner
        reward = actual_effectiveness - 0.5  # Center reward around 0
        action = self.rl_learner.get_action(features[0])
        self.rl_learner.remember(features[0], action, reward, features[0], False)
        self.rl_learner.replay()
        
        # Retrain neural network periodically
        if len(self.training_data) >= 100 and len(self.training_data) % 50 == 0:
            self._retrain_neural_network()
    
    def _retrain_neural_network(self):
        """Retrain neural network with collected data"""
        if len(self.training_data) < 50:
            return
        
        # Prepare training data
        X = np.vstack([d['features'] for d in self.training_data[-500:]])
        
        # Create target labels (one-hot encoded effectiveness)
        y = np.zeros((len(self.training_data[-500:]), 13))
        for i, d in enumerate(self.training_data[-500:]):
            # Distribute effectiveness across vectors based on features
            y[i] = d['effectiveness'] * np.random.dirichlet(np.ones(13))
        
        # Train
        self.neural_predictor.train(X, y, epochs=50, learning_rate=0.001)
        logger.info("Neural network retrained with %d samples", len(X))
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of prediction models"""
        return {
            'neural_network': {
                'loss_history': self.neural_predictor.loss_history[-10:],
                'trained_samples': len(self.training_data)
            },
            'reinforcement_learning': {
                'exploration_rate': self.rl_learner.exploration_rate,
                'q_table_size': len(self.rl_learner.q_table),
                'memory_size': len(self.rl_learner.memory)
            },
            'time_series': {
                'history_size': len(self.time_series.history),
                'current_trend': self.time_series.get_trend()
            }
        }


# Global predictor instance
attack_predictor = AttackPredictor()


__all__ = [
    'AttackVector',
    'AttackPrediction',
    'TargetProfile',
    'NeuralPredictor',
    'ReinforcementLearner',
    'TimeSeriesPredictor',
    'AttackPredictor',
    'attack_predictor',
]
