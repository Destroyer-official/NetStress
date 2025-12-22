"""
Defense Detection and Evasion AI

Implements adversarial machine learning for evasion,
defense pattern recognition and classification, and
dynamic evasion technique selection.
"""

import numpy as np
import logging
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import queue
import json
import hashlib
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class DefenseType(Enum):
    """Types of defense mechanisms"""
    RATE_LIMITING = "rate_limiting"
    IP_BLOCKING = "ip_blocking"
    PATTERN_DETECTION = "pattern_detection"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    CAPTCHA = "captcha"
    GEOBLOCKING = "geoblocking"
    DPI_FILTERING = "dpi_filtering"
    LOAD_BALANCER = "load_balancer"
    WAF = "waf"
    DDOS_PROTECTION = "ddos_protection"

class EvasionTechnique(Enum):
    """Types of evasion techniques"""
    IP_SPOOFING = "ip_spoofing"
    USER_AGENT_ROTATION = "user_agent_rotation"
    TIMING_RANDOMIZATION = "timing_randomization"
    PACKET_FRAGMENTATION = "packet_fragmentation"
    PROTOCOL_SWITCHING = "protocol_switching"
    PAYLOAD_OBFUSCATION = "payload_obfuscation"
    DISTRIBUTED_SOURCES = "distributed_sources"
    SLOW_ATTACKS = "slow_attacks"
    LEGITIMATE_MIMICKING = "legitimate_mimicking"
    ENCRYPTION_TUNNELING = "encryption_tunneling"

@dataclass
class DefenseSignature:
    """Signature of a detected defense mechanism"""
    defense_type: DefenseType
    confidence: float
    indicators: List[str]
    detection_time: datetime
    response_pattern: Dict[str, Any]
    effectiveness: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'defense_type': self.defense_type.value,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'detection_time': self.detection_time.isoformat(),
            'response_pattern': self.response_pattern,
            'effectiveness': self.effectiveness
        }

@dataclass
class EvasionStrategy:
    """Strategy for evading detected defenses"""
    technique: EvasionTechnique
    parameters: Dict[str, Any]
    success_rate: float = 0.0
    usage_count: int = 0
    last_used: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'technique': self.technique.value,
            'parameters': self.parameters,
            'success_rate': self.success_rate,
            'usage_count': self.usage_count,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }

class PatternRecognitionClassifier:
    """
    Classifies defense patterns using machine learning
    Identifies defense mechanisms from network responses
    """
    
    def __init__(self, feature_dim: int = 20):
        self.feature_dim = feature_dim
        
        # Simple neural network for classification
        self.weights_input_hidden = np.random.randn(feature_dim, 32) * 0.1
        self.weights_hidden_output = np.random.randn(32, len(DefenseType)) * 0.1
        self.bias_hidden = np.zeros((1, 32))
        self.bias_output = np.zeros((1, len(DefenseType)))
        
        # Training data buffer
        self.training_buffer = deque(maxlen=10000)
        self.defense_patterns = {}
        
        # Known defense signatures
        self._initialize_defense_signatures()
        
    def _initialize_defense_signatures(self):
        """Initialize known defense signatures"""
        self.defense_patterns = {
            DefenseType.RATE_LIMITING: {
                'response_codes': [429, 503],
                'headers': ['retry-after', 'x-ratelimit-limit'],
                'timing_patterns': 'consistent_delays',
                'connection_behavior': 'throttled'
            },
            DefenseType.IP_BLOCKING: {
                'response_codes': [403, 444],
                'headers': ['x-blocked-ip'],
                'timing_patterns': 'immediate_rejection',
                'connection_behavior': 'connection_refused'
            },
            DefenseType.PATTERN_DETECTION: {
                'response_codes': [400, 403],
                'headers': ['x-pattern-detected'],
                'timing_patterns': 'variable_delays',
                'connection_behavior': 'selective_blocking'
            },
            DefenseType.BEHAVIORAL_ANALYSIS: {
                'response_codes': [403, 406],
                'headers': ['x-behavior-score'],
                'timing_patterns': 'adaptive_delays',
                'connection_behavior': 'gradual_degradation'
            },
            DefenseType.CAPTCHA: {
                'response_codes': [200, 302],
                'headers': ['set-cookie'],
                'timing_patterns': 'challenge_response',
                'connection_behavior': 'redirect_to_challenge'
            },
            DefenseType.WAF: {
                'response_codes': [403, 406, 418],
                'headers': ['x-waf-event', 'server'],
                'timing_patterns': 'inspection_delays',
                'connection_behavior': 'deep_packet_inspection'
            }
        }
    
    def extract_features(self, network_response: Dict[str, Any]) -> np.ndarray:
        """Extract features from network response for classification"""
        features = []
        
        # Response code features
        response_code = network_response.get('status_code', 200)
        features.extend([
            1.0 if response_code == 200 else 0.0,
            1.0 if response_code in [400, 403, 406] else 0.0,
            1.0 if response_code in [429, 503] else 0.0,
            1.0 if response_code >= 500 else 0.0
        ])
        
        # Timing features
        response_time = network_response.get('response_time', 0)
        features.extend([
            min(response_time / 1000.0, 1.0),  # Normalize to seconds
            1.0 if response_time > 5000 else 0.0,  # Slow response indicator
            network_response.get('connection_time', 0) / 1000.0
        ])
        
        # Header features
        headers = network_response.get('headers', {})
        features.extend([
            1.0 if 'retry-after' in headers else 0.0,
            1.0 if 'x-ratelimit' in str(headers).lower() else 0.0,
            1.0 if 'x-blocked' in str(headers).lower() else 0.0,
            1.0 if 'x-waf' in str(headers).lower() else 0.0,
            1.0 if 'cloudflare' in str(headers).lower() else 0.0,
            1.0 if 'set-cookie' in headers else 0.0
        ])
        
        # Connection behavior features
        connection_info = network_response.get('connection_info', {})
        features.extend([
            1.0 if connection_info.get('connection_refused', False) else 0.0,
            1.0 if connection_info.get('connection_reset', False) else 0.0,
            1.0 if connection_info.get('timeout', False) else 0.0,
            connection_info.get('handshake_time', 0) / 1000.0
        ])
        
        # Content features
        content = network_response.get('content', '')
        features.extend([
            1.0 if 'captcha' in content.lower() else 0.0,
            1.0 if 'blocked' in content.lower() else 0.0,
            1.0 if 'rate limit' in content.lower() else 0.0,
            len(content) / 10000.0  # Normalized content length
        ])
        
        # Pad or truncate to exact feature dimension
        while len(features) < self.feature_dim:
            features.append(0.0)
        features = features[:self.feature_dim]
        
        return np.array(features, dtype=np.float32)
    
    def _activation_function(self, x: np.ndarray, activation: str = 'relu') -> np.ndarray:
        """Apply activation function"""
        if activation == 'relu':
            return np.maximum(0, x)
        elif activation == 'sigmoid':
            return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
        elif activation == 'softmax':
            exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
            return exp_x / np.sum(exp_x, axis=1, keepdims=True)
        return x
    
    def predict_defense_type(self, network_response: Dict[str, Any]) -> Tuple[DefenseType, float]:
        """Predict defense type from network response"""
        features = self.extract_features(network_response)
        
        # Forward pass through neural network
        hidden = self._activation_function(
            np.dot(features.reshape(1, -1), self.weights_input_hidden) + self.bias_hidden,
            'relu'
        )
        output = self._activation_function(
            np.dot(hidden, self.weights_hidden_output) + self.bias_output,
            'softmax'
        )
        
        # Get prediction
        defense_idx = np.argmax(output)
        confidence = float(output[0, defense_idx])
        
        defense_types = list(DefenseType)
        predicted_defense = defense_types[defense_idx] if defense_idx < len(defense_types) else DefenseType.RATE_LIMITING
        
        return predicted_defense, confidence
    
    def classify_defense_pattern(self, response_history: List[Dict[str, Any]]) -> List[DefenseSignature]:
        """Classify defense patterns from response history"""
        detected_defenses = []
        
        for response in response_history:
            # Extract features and predict
            defense_type, confidence = self.predict_defense_type(response)
            
            # Rule-based validation
            validated_defense = self._validate_with_rules(response, defense_type, confidence)
            
            if validated_defense:
                detected_defenses.append(validated_defense)
        
        # Aggregate and deduplicate
        return self._aggregate_detections(detected_defenses)
    
    def _validate_with_rules(self, response: Dict[str, Any], 
                           predicted_defense: DefenseType, confidence: float) -> Optional[DefenseSignature]:
        """Validate prediction with rule-based checks"""
        if confidence < 0.3:  # Low confidence threshold
            return None
        
        # Get expected patterns for this defense type
        expected_patterns = self.defense_patterns.get(predicted_defense, {})
        
        indicators = []
        validation_score = 0.0
        
        # Check response codes
        response_code = response.get('status_code', 200)
        expected_codes = expected_patterns.get('response_codes', [])
        if response_code in expected_codes:
            indicators.append(f"response_code_{response_code}")
            validation_score += 0.3
        
        # Check headers
        headers = response.get('headers', {})
        expected_headers = expected_patterns.get('headers', [])
        for header in expected_headers:
            if header.lower() in str(headers).lower():
                indicators.append(f"header_{header}")
                validation_score += 0.2
        
        # Check timing patterns
        response_time = response.get('response_time', 0)
        timing_pattern = expected_patterns.get('timing_patterns', '')
        
        if timing_pattern == 'consistent_delays' and response_time > 1000:
            indicators.append("consistent_delay")
            validation_score += 0.2
        elif timing_pattern == 'immediate_rejection' and response_time < 100:
            indicators.append("immediate_rejection")
            validation_score += 0.2
        
        # Require minimum validation score
        if validation_score < 0.3:
            return None
        
        return DefenseSignature(
            defense_type=predicted_defense,
            confidence=min(confidence + validation_score, 1.0),
            indicators=indicators,
            detection_time=datetime.now(),
            response_pattern=response.copy()
        )
    
    def _aggregate_detections(self, detections: List[DefenseSignature]) -> List[DefenseSignature]:
        """Aggregate and deduplicate defense detections"""
        # Group by defense type
        grouped = defaultdict(list)
        for detection in detections:
            grouped[detection.defense_type].append(detection)
        
        # Aggregate each group
        aggregated = []
        for defense_type, group in grouped.items():
            if len(group) == 1:
                aggregated.append(group[0])
            else:
                # Merge multiple detections of same type
                avg_confidence = sum(d.confidence for d in group) / len(group)
                all_indicators = []
                for d in group:
                    all_indicators.extend(d.indicators)
                
                merged = DefenseSignature(
                    defense_type=defense_type,
                    confidence=avg_confidence,
                    indicators=list(set(all_indicators)),
                    detection_time=max(d.detection_time for d in group),
                    response_pattern=group[-1].response_pattern  # Use latest
                )
                aggregated.append(merged)
        
        return aggregated
    
    def train_classifier(self, labeled_data: List[Tuple[Dict[str, Any], DefenseType]]):
        """Train the classifier with labeled data"""
        if not labeled_data:
            return
        
        # Prepare training data
        X = []
        y = []
        defense_types = list(DefenseType)
        
        for response, defense_type in labeled_data:
            features = self.extract_features(response)
            X.append(features)
            
            # One-hot encode defense type
            label = np.zeros(len(defense_types))
            if defense_type in defense_types:
                label[defense_types.index(defense_type)] = 1.0
            y.append(label)
        
        X = np.array(X)
        y = np.array(y)
        
        # Simple gradient descent training
        learning_rate = 0.01
        epochs = 100
        
        for epoch in range(epochs):
            # Forward pass
            hidden = self._activation_function(
                np.dot(X, self.weights_input_hidden) + self.bias_hidden, 'relu'
            )
            output = self._activation_function(
                np.dot(hidden, self.weights_hidden_output) + self.bias_output, 'softmax'
            )
            
            # Calculate loss (cross-entropy)
            loss = -np.mean(np.sum(y * np.log(output + 1e-8), axis=1))
            
            # Backward pass (simplified)
            output_error = output - y
            hidden_error = np.dot(output_error, self.weights_hidden_output.T)
            hidden_error[hidden <= 0] = 0  # ReLU derivative
            
            # Update weights
            self.weights_hidden_output -= learning_rate * np.dot(hidden.T, output_error) / len(X)
            self.weights_input_hidden -= learning_rate * np.dot(X.T, hidden_error) / len(X)
            self.bias_output -= learning_rate * np.mean(output_error, axis=0, keepdims=True)
            self.bias_hidden -= learning_rate * np.mean(hidden_error, axis=0, keepdims=True)
            
            if epoch % 20 == 0:
                logger.debug(f"Training epoch {epoch}, loss: {loss:.4f}")

class EvasionTechniqueSelector:
    """
    Selects optimal evasion techniques based on detected defenses
    Maintains success rates and adapts technique selection
    """
    
    def __init__(self):
        self.evasion_strategies = {}
        self.success_history = defaultdict(list)
        self.technique_effectiveness = {}
        
        self._initialize_evasion_strategies()
    
    def _initialize_evasion_strategies(self):
        """Initialize evasion strategies for each defense type"""
        self.evasion_strategies = {
            DefenseType.RATE_LIMITING: [
                EvasionStrategy(
                    technique=EvasionTechnique.TIMING_RANDOMIZATION,
                    parameters={'min_delay': 0.5, 'max_delay': 2.0, 'distribution': 'exponential'}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.DISTRIBUTED_SOURCES,
                    parameters={'source_rotation_interval': 30, 'max_sources': 100}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.SLOW_ATTACKS,
                    parameters={'connection_rate': 10, 'request_interval': 5.0}
                )
            ],
            DefenseType.IP_BLOCKING: [
                EvasionStrategy(
                    technique=EvasionTechnique.IP_SPOOFING,
                    parameters={'spoofing_rate': 0.8, 'source_pool_size': 1000}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.DISTRIBUTED_SOURCES,
                    parameters={'source_rotation_interval': 10, 'max_sources': 500}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.ENCRYPTION_TUNNELING,
                    parameters={'tunnel_type': 'tor', 'rotation_interval': 60}
                )
            ],
            DefenseType.PATTERN_DETECTION: [
                EvasionStrategy(
                    technique=EvasionTechnique.PAYLOAD_OBFUSCATION,
                    parameters={'obfuscation_level': 0.7, 'randomization_seed': 'dynamic'}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.PROTOCOL_SWITCHING,
                    parameters={'protocols': ['HTTP', 'HTTPS', 'HTTP2'], 'switch_interval': 20}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.LEGITIMATE_MIMICKING,
                    parameters={'user_agent_rotation': True, 'behavior_mimicking': True}
                )
            ],
            DefenseType.BEHAVIORAL_ANALYSIS: [
                EvasionStrategy(
                    technique=EvasionTechnique.LEGITIMATE_MIMICKING,
                    parameters={'human_behavior_simulation': True, 'session_management': True}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.TIMING_RANDOMIZATION,
                    parameters={'human_timing_patterns': True, 'think_time_simulation': True}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.USER_AGENT_ROTATION,
                    parameters={'rotation_frequency': 'per_request', 'realistic_agents': True}
                )
            ],
            DefenseType.WAF: [
                EvasionStrategy(
                    technique=EvasionTechnique.PAYLOAD_OBFUSCATION,
                    parameters={'encoding_methods': ['url', 'base64', 'hex'], 'fragmentation': True}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.PACKET_FRAGMENTATION,
                    parameters={'fragment_size': 'random', 'reassembly_evasion': True}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.PROTOCOL_SWITCHING,
                    parameters={'http_version_switching': True, 'header_manipulation': True}
                )
            ],
            DefenseType.DDOS_PROTECTION: [
                EvasionStrategy(
                    technique=EvasionTechnique.SLOW_ATTACKS,
                    parameters={'low_and_slow': True, 'connection_persistence': True}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.LEGITIMATE_MIMICKING,
                    parameters={'traffic_blending': True, 'legitimate_ratio': 0.3}
                ),
                EvasionStrategy(
                    technique=EvasionTechnique.DISTRIBUTED_SOURCES,
                    parameters={'geographic_distribution': True, 'source_diversity': 'high'}
                )
            ]
        }
    
    def select_evasion_techniques(self, detected_defenses: List[DefenseSignature]) -> List[EvasionStrategy]:
        """Select optimal evasion techniques for detected defenses"""
        selected_techniques = []
        
        for defense in detected_defenses:
            # Get available strategies for this defense type
            available_strategies = self.evasion_strategies.get(defense.defense_type, [])
            
            if not available_strategies:
                continue
            
            # Select best strategy based on historical success rate
            best_strategy = self._select_best_strategy(available_strategies, defense)
            
            if best_strategy:
                # Adapt parameters based on defense characteristics
                adapted_strategy = self._adapt_strategy_parameters(best_strategy, defense)
                selected_techniques.append(adapted_strategy)
        
        # Remove duplicates and conflicts
        return self._resolve_technique_conflicts(selected_techniques)
    
    def _select_best_strategy(self, strategies: List[EvasionStrategy], 
                            defense: DefenseSignature) -> Optional[EvasionStrategy]:
        """Select best strategy based on success rate and defense characteristics"""
        if not strategies:
            return None
        
        # Calculate scores for each strategy
        strategy_scores = []
        
        for strategy in strategies:
            # Base score from historical success rate
            base_score = strategy.success_rate
            
            # Bonus for recent usage (recency bias)
            recency_bonus = 0.0
            if strategy.last_used:
                days_since_use = (datetime.now() - strategy.last_used).days
                recency_bonus = max(0.0, 0.2 - days_since_use * 0.01)
            
            # Penalty for overuse (diversity encouragement)
            overuse_penalty = min(0.3, strategy.usage_count * 0.01)
            
            # Defense-specific bonuses
            defense_bonus = self._calculate_defense_specific_bonus(strategy, defense)
            
            total_score = base_score + recency_bonus - overuse_penalty + defense_bonus
            strategy_scores.append((strategy, total_score))
        
        # Select strategy with highest score
        best_strategy, best_score = max(strategy_scores, key=lambda x: x[1])
        
        # Add some randomness to avoid always selecting the same strategy
        if len(strategy_scores) > 1 and np.random.random() < 0.2:
            # 20% chance to select second best for exploration
            sorted_strategies = sorted(strategy_scores, key=lambda x: x[1], reverse=True)
            best_strategy = sorted_strategies[1][0]
        
        return best_strategy
    
    def _calculate_defense_specific_bonus(self, strategy: EvasionStrategy, 
                                        defense: DefenseSignature) -> float:
        """Calculate defense-specific bonus for strategy selection"""
        bonus = 0.0
        
        # High confidence defenses need more sophisticated evasion
        if defense.confidence > 0.8:
            sophisticated_techniques = [
                EvasionTechnique.PAYLOAD_OBFUSCATION,
                EvasionTechnique.ENCRYPTION_TUNNELING,
                EvasionTechnique.LEGITIMATE_MIMICKING
            ]
            if strategy.technique in sophisticated_techniques:
                bonus += 0.2
        
        # Recent detections need immediate evasion
        time_since_detection = datetime.now() - defense.detection_time
        if time_since_detection < timedelta(minutes=5):
            fast_techniques = [
                EvasionTechnique.IP_SPOOFING,
                EvasionTechnique.PROTOCOL_SWITCHING,
                EvasionTechnique.USER_AGENT_ROTATION
            ]
            if strategy.technique in fast_techniques:
                bonus += 0.15
        
        return bonus
    
    def _adapt_strategy_parameters(self, strategy: EvasionStrategy, 
                                 defense: DefenseSignature) -> EvasionStrategy:
        """Adapt strategy parameters based on defense characteristics"""
        adapted_params = strategy.parameters.copy()
        
        # Adapt based on defense confidence
        if defense.confidence > 0.8:
            # High confidence defense - use more aggressive evasion
            if 'obfuscation_level' in adapted_params:
                adapted_params['obfuscation_level'] = min(1.0, adapted_params['obfuscation_level'] + 0.2)
            if 'spoofing_rate' in adapted_params:
                adapted_params['spoofing_rate'] = min(1.0, adapted_params['spoofing_rate'] + 0.1)
        
        # Adapt based on defense type effectiveness
        if defense.effectiveness > 0.7:
            # Highly effective defense - increase evasion intensity
            if 'rotation_interval' in adapted_params:
                adapted_params['rotation_interval'] = max(5, adapted_params['rotation_interval'] // 2)
            if 'source_pool_size' in adapted_params:
                adapted_params['source_pool_size'] = min(10000, adapted_params['source_pool_size'] * 2)
        
        return EvasionStrategy(
            technique=strategy.technique,
            parameters=adapted_params,
            success_rate=strategy.success_rate,
            usage_count=strategy.usage_count,
            last_used=strategy.last_used
        )
    
    def _resolve_technique_conflicts(self, techniques: List[EvasionStrategy]) -> List[EvasionStrategy]:
        """Resolve conflicts between evasion techniques"""
        # Remove duplicate techniques
        seen_techniques = set()
        resolved = []
        
        for technique in techniques:
            if technique.technique not in seen_techniques:
                resolved.append(technique)
                seen_techniques.add(technique.technique)
        
        # Check for conflicting techniques
        conflicts = {
            EvasionTechnique.IP_SPOOFING: [EvasionTechnique.ENCRYPTION_TUNNELING],
            EvasionTechnique.SLOW_ATTACKS: [EvasionTechnique.DISTRIBUTED_SOURCES],
        }
        
        final_techniques = []
        for technique in resolved:
            conflicting_techniques = conflicts.get(technique.technique, [])
            
            # Check if any conflicting technique is already selected
            has_conflict = any(t.technique in conflicting_techniques for t in final_techniques)
            
            if not has_conflict:
                final_techniques.append(technique)
        
        return final_techniques
    
    def update_technique_success(self, technique: EvasionTechnique, success: bool, 
                               performance_metrics: Dict[str, Any]):
        """Update success rate for evasion technique"""
        # Find the strategy in our collection
        for defense_type, strategies in self.evasion_strategies.items():
            for strategy in strategies:
                if strategy.technique == technique:
                    # Update success rate using exponential moving average
                    alpha = 0.1  # Learning rate
                    new_success = 1.0 if success else 0.0
                    
                    if strategy.usage_count == 0:
                        strategy.success_rate = new_success
                    else:
                        strategy.success_rate = (1 - alpha) * strategy.success_rate + alpha * new_success
                    
                    strategy.usage_count += 1
                    strategy.last_used = datetime.now()
                    
                    # Store detailed success history
                    self.success_history[technique].append({
                        'success': success,
                        'timestamp': datetime.now(),
                        'performance_metrics': performance_metrics.copy()
                    })
                    
                    # Limit history size
                    if len(self.success_history[technique]) > 1000:
                        self.success_history[technique] = self.success_history[technique][-1000:]
                    
                    break
    
    def get_technique_statistics(self) -> Dict[str, Any]:
        """Get statistics for all evasion techniques"""
        stats = {}
        
        for defense_type, strategies in self.evasion_strategies.items():
            defense_stats = {}
            
            for strategy in strategies:
                technique_name = strategy.technique.value
                defense_stats[technique_name] = {
                    'success_rate': strategy.success_rate,
                    'usage_count': strategy.usage_count,
                    'last_used': strategy.last_used.isoformat() if strategy.last_used else None,
                    'parameters': strategy.parameters
                }
            
            stats[defense_type.value] = defense_stats
        
        return stats

class AdversarialMLEngine:
    """
    Adversarial machine learning engine for advanced evasion
    Generates adversarial examples to bypass ML-based defenses
    """
    
    def __init__(self):
        self.adversarial_examples = {}
        self.generation_history = []
        self.success_rate_tracker = defaultdict(float)
        
    def generate_adversarial_traffic(self, baseline_traffic: Dict[str, Any], 
                                   target_defense: DefenseType) -> Dict[str, Any]:
        """Generate adversarial traffic to evade ML-based defenses"""
        
        # Extract traffic features
        features = self._extract_traffic_features(baseline_traffic)
        
        # Generate adversarial perturbations
        adversarial_features = self._generate_perturbations(features, target_defense)
        
        # Convert back to traffic parameters
        adversarial_traffic = self._features_to_traffic(adversarial_features, baseline_traffic)
        
        # Store generation record
        generation_record = {
            'timestamp': datetime.now(),
            'baseline_traffic': baseline_traffic.copy(),
            'adversarial_traffic': adversarial_traffic.copy(),
            'target_defense': target_defense.value,
            'perturbation_magnitude': np.linalg.norm(adversarial_features - features)
        }
        self.generation_history.append(generation_record)
        
        return adversarial_traffic
    
    def _extract_traffic_features(self, traffic: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from traffic parameters"""
        features = []
        
        # Rate features
        features.append(traffic.get('packet_rate', 1000) / 100000.0)  # Normalize
        features.append(traffic.get('connection_rate', 100) / 10000.0)
        
        # Size features
        features.append(traffic.get('packet_size', 1000) / 1500.0)
        features.append(traffic.get('payload_size', 500) / 1000.0)
        
        # Timing features
        features.append(traffic.get('burst_duration', 1.0) / 10.0)
        features.append(traffic.get('pause_duration', 1.0) / 10.0)
        features.append(traffic.get('request_interval', 1.0) / 5.0)
        
        # Protocol features (one-hot encoded)
        protocol = traffic.get('protocol', 'HTTP')
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
        for p in protocols:
            features.append(1.0 if protocol == p else 0.0)
        
        # Behavioral features
        features.append(traffic.get('randomization_level', 0.5))
        features.append(traffic.get('spoofing_rate', 0.0))
        features.append(traffic.get('fragmentation_rate', 0.0))
        
        return np.array(features, dtype=np.float32)
    
    def _generate_perturbations(self, features: np.ndarray, 
                              target_defense: DefenseType) -> np.ndarray:
        """Generate adversarial perturbations using gradient-based methods"""
        
        # Simulate gradient-based attack (FGSM-like)
        epsilon = 0.1  # Perturbation magnitude
        
        # Generate random gradients (in practice, would use actual model gradients)
        gradients = np.random.randn(*features.shape)
        
        # Defense-specific perturbation strategies
        if target_defense == DefenseType.RATE_LIMITING:
            # Focus on timing and rate features
            gradients[:2] *= 2.0  # Amplify rate perturbations
            gradients[4:7] *= 1.5  # Amplify timing perturbations
        
        elif target_defense == DefenseType.PATTERN_DETECTION:
            # Focus on behavioral features
            gradients[-3:] *= 2.0  # Amplify behavioral perturbations
            gradients[7:12] *= 1.5  # Amplify protocol perturbations
        
        elif target_defense == DefenseType.BEHAVIORAL_ANALYSIS:
            # Focus on timing and behavioral patterns
            gradients[4:7] *= 2.0  # Timing features
            gradients[-3:] *= 2.0  # Behavioral features
        
        # Apply perturbations
        perturbations = epsilon * np.sign(gradients)
        adversarial_features = features + perturbations
        
        # Ensure features remain in valid ranges
        adversarial_features = np.clip(adversarial_features, 0.0, 1.0)
        
        return adversarial_features
    
    def _features_to_traffic(self, features: np.ndarray, 
                           baseline_traffic: Dict[str, Any]) -> Dict[str, Any]:
        """Convert feature vector back to traffic parameters"""
        adversarial_traffic = baseline_traffic.copy()
        
        # Rate features
        adversarial_traffic['packet_rate'] = int(features[0] * 100000)
        adversarial_traffic['connection_rate'] = int(features[1] * 10000)
        
        # Size features
        adversarial_traffic['packet_size'] = int(features[2] * 1500)
        adversarial_traffic['payload_size'] = int(features[3] * 1000)
        
        # Timing features
        adversarial_traffic['burst_duration'] = features[4] * 10.0
        adversarial_traffic['pause_duration'] = features[5] * 10.0
        adversarial_traffic['request_interval'] = features[6] * 5.0
        
        # Protocol features (select highest probability)
        protocol_probs = features[7:12]
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']
        adversarial_traffic['protocol'] = protocols[np.argmax(protocol_probs)]
        
        # Behavioral features
        adversarial_traffic['randomization_level'] = features[12]
        adversarial_traffic['spoofing_rate'] = features[13]
        adversarial_traffic['fragmentation_rate'] = features[14]
        
        return adversarial_traffic
    
    def evaluate_evasion_success(self, adversarial_traffic: Dict[str, Any], 
                               defense_response: Dict[str, Any]) -> bool:
        """Evaluate if adversarial traffic successfully evaded defense"""
        
        # Success indicators
        success_indicators = []
        
        # Check if request was not blocked
        status_code = defense_response.get('status_code', 200)
        success_indicators.append(status_code not in [403, 429, 444])
        
        # Check response time (not significantly delayed)
        response_time = defense_response.get('response_time', 0)
        success_indicators.append(response_time < 5000)  # Less than 5 seconds
        
        # Check for defense-specific indicators
        headers = defense_response.get('headers', {})
        success_indicators.append('x-blocked' not in str(headers).lower())
        success_indicators.append('x-ratelimit' not in str(headers).lower())
        
        # Check connection success
        connection_info = defense_response.get('connection_info', {})
        success_indicators.append(not connection_info.get('connection_refused', False))
        
        # Overall success if majority of indicators are positive
        success = sum(success_indicators) >= len(success_indicators) * 0.6
        
        return success
    
    def update_adversarial_model(self, traffic_params: Dict[str, Any], 
                               defense_response: Dict[str, Any], success: bool):
        """Update adversarial model based on evasion results"""
        
        # Extract defense type from response
        defense_type = self._infer_defense_type(defense_response)
        
        # Update success rate tracker
        alpha = 0.1  # Learning rate
        current_rate = self.success_rate_tracker[defense_type]
        new_rate = 1.0 if success else 0.0
        self.success_rate_tracker[defense_type] = (1 - alpha) * current_rate + alpha * new_rate
        
        # Store successful adversarial examples
        if success:
            defense_key = defense_type.value if isinstance(defense_type, DefenseType) else str(defense_type)
            
            if defense_key not in self.adversarial_examples:
                self.adversarial_examples[defense_key] = []
            
            example = {
                'traffic_params': traffic_params.copy(),
                'success_timestamp': datetime.now(),
                'defense_response': defense_response.copy()
            }
            
            self.adversarial_examples[defense_key].append(example)
            
            # Limit stored examples
            if len(self.adversarial_examples[defense_key]) > 100:
                self.adversarial_examples[defense_key] = self.adversarial_examples[defense_key][-100:]
    
    def _infer_defense_type(self, defense_response: Dict[str, Any]) -> DefenseType:
        """Infer defense type from response characteristics"""
        status_code = defense_response.get('status_code', 200)
        headers = defense_response.get('headers', {})
        
        if status_code == 429 or 'ratelimit' in str(headers).lower():
            return DefenseType.RATE_LIMITING
        elif status_code in [403, 444] and 'blocked' in str(headers).lower():
            return DefenseType.IP_BLOCKING
        elif 'waf' in str(headers).lower():
            return DefenseType.WAF
        elif 'captcha' in defense_response.get('content', '').lower():
            return DefenseType.CAPTCHA
        else:
            return DefenseType.PATTERN_DETECTION  # Default
    
    def get_adversarial_statistics(self) -> Dict[str, Any]:
        """Get adversarial ML statistics"""
        return {
            'success_rates': dict(self.success_rate_tracker),
            'stored_examples': {k: len(v) for k, v in self.adversarial_examples.items()},
            'generation_count': len(self.generation_history),
            'avg_perturbation_magnitude': np.mean([
                record['perturbation_magnitude'] for record in self.generation_history
            ]) if self.generation_history else 0.0
        }

class DefenseDetectionAI:
    """
    Main defense detection AI that coordinates all evasion components
    Integrates pattern recognition, evasion selection, and adversarial ML
    """
    
    def __init__(self):
        self.pattern_classifier = PatternRecognitionClassifier()
        self.evasion_selector = EvasionTechniqueSelector()
        self.adversarial_engine = AdversarialMLEngine()
        
        self.detection_history = []
        self.evasion_history = []
        self.active_defenses = {}
        
        self._lock = threading.Lock()
    
    def analyze_target_defenses(self, response_history: List[Dict[str, Any]]) -> List[DefenseSignature]:
        """Analyze target defenses from response history"""
        with self._lock:
            # Classify defense patterns
            detected_defenses = self.pattern_classifier.classify_defense_pattern(response_history)
            
            # Update active defenses
            for defense in detected_defenses:
                self.active_defenses[defense.defense_type] = defense
            
            # Store detection history
            detection_record = {
                'timestamp': datetime.now(),
                'detected_defenses': [d.to_dict() for d in detected_defenses],
                'response_count': len(response_history)
            }
            self.detection_history.append(detection_record)
            
            logger.info(f"Detected {len(detected_defenses)} defense mechanisms")
            
            return detected_defenses
    
    def generate_evasion_strategy(self, detected_defenses: List[DefenseSignature], 
                                current_attack_params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive evasion strategy"""
        with self._lock:
            evasion_strategy = current_attack_params.copy()
            
            # Select evasion techniques
            selected_techniques = self.evasion_selector.select_evasion_techniques(detected_defenses)
            
            # Apply adversarial ML if ML-based defenses detected
            ml_defenses = [d for d in detected_defenses if d.defense_type in [
                DefenseType.BEHAVIORAL_ANALYSIS, DefenseType.PATTERN_DETECTION
            ]]
            
            if ml_defenses:
                for defense in ml_defenses:
                    adversarial_params = self.adversarial_engine.generate_adversarial_traffic(
                        evasion_strategy, defense.defense_type
                    )
                    evasion_strategy.update(adversarial_params)
            
            # Apply evasion technique parameters
            for technique in selected_techniques:
                evasion_strategy.update(technique.parameters)
                evasion_strategy['evasion_techniques'] = evasion_strategy.get('evasion_techniques', [])
                evasion_strategy['evasion_techniques'].append(technique.technique.value)
            
            # Store evasion history
            evasion_record = {
                'timestamp': datetime.now(),
                'detected_defenses': [d.defense_type.value for d in detected_defenses],
                'selected_techniques': [t.technique.value for t in selected_techniques],
                'evasion_strategy': evasion_strategy.copy()
            }
            self.evasion_history.append(evasion_record)
            
            return evasion_strategy
    
    def update_evasion_feedback(self, evasion_techniques: List[str], 
                              attack_results: Dict[str, Any], success: bool):
        """Update evasion effectiveness based on feedback"""
        with self._lock:
            # Update technique success rates
            for technique_name in evasion_techniques:
                try:
                    technique = EvasionTechnique(technique_name)
                    self.evasion_selector.update_technique_success(
                        technique, success, attack_results
                    )
                except ValueError:
                    logger.warning(f"Unknown evasion technique: {technique_name}")
            
            # Update adversarial ML model
            if 'adversarial_traffic' in attack_results:
                self.adversarial_engine.update_adversarial_model(
                    attack_results['adversarial_traffic'],
                    attack_results.get('defense_response', {}),
                    success
                )
    
    def get_defense_intelligence(self) -> Dict[str, Any]:
        """Get comprehensive defense intelligence report"""
        return {
            'active_defenses': {
                defense_type.value: defense.to_dict() 
                for defense_type, defense in self.active_defenses.items()
            },
            'detection_count': len(self.detection_history),
            'evasion_count': len(self.evasion_history),
            'technique_statistics': self.evasion_selector.get_technique_statistics(),
            'adversarial_statistics': self.adversarial_engine.get_adversarial_statistics(),
            'recent_detections': [
                record for record in self.detection_history[-10:]
            ] if len(self.detection_history) > 0 else []
        }
    
    def train_defense_classifier(self, labeled_responses: List[Tuple[Dict[str, Any], DefenseType]]):
        """Train the defense pattern classifier with labeled data"""
        self.pattern_classifier.train_classifier(labeled_responses)
        logger.info(f"Trained defense classifier with {len(labeled_responses)} samples")
    
    def reset_defense_state(self):
        """Reset defense detection state"""
        with self._lock:
            self.active_defenses.clear()
            self.detection_history.clear()
            self.evasion_history.clear()
            logger.info("Defense detection state reset")