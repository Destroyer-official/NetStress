"""
Performance Prediction and Effectiveness Modeling

Implements machine learning models for predicting attack performance
and effectiveness based on target characteristics and parameters.
"""

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
from collections import deque
import logging

logger = logging.getLogger(__name__)

@dataclass
class TargetProfile:
    """Profile of target system characteristics"""
    ip_address: str
    response_times: List[float] = field(default_factory=list)
    bandwidth_capacity: Optional[float] = None
    defense_mechanisms: List[str] = field(default_factory=list)
    service_types: List[str] = field(default_factory=list)
    network_topology: Dict[str, Any] = field(default_factory=dict)
    vulnerability_score: float = 0.5
    last_updated: float = field(default_factory=time.time)

@dataclass
class PredictionResult:
    """Result of performance prediction"""
    predicted_pps: float
    predicted_success_rate: float
    predicted_bandwidth: float
    confidence_interval: Tuple[float, float]
    risk_factors: List[str]
    recommended_parameters: Dict[str, Any]

class PerformancePredictionModel:
    """
    Machine learning model for predicting attack performance
    based on target characteristics and attack parameters.
    """
    
    def __init__(self, model_type: str = "neural_network"):
        self.model_type = model_type
        self.training_data = deque(maxlen=1000)
        self.model_weights = self._initialize_weights()
        self.feature_scalers = {}
        self.prediction_history = deque(maxlen=100)
        
    def _initialize_weights(self) -> Dict[str, np.ndarray]:
        """Initialize neural network weights"""
        # Simple 3-layer neural network
        weights = {
            'input_hidden': np.random.randn(10, 20) * 0.1,  # 10 input features, 20 hidden neurons
            'hidden_output': np.random.randn(20, 3) * 0.1,  # 3 outputs: pps, success_rate, bandwidth
            'hidden_bias': np.zeros(20),
            'output_bias': np.zeros(3)
        }
        return weights
    
    def extract_features(self, 
                        target_profile: TargetProfile,
                        attack_params: Dict[str, Any]) -> np.ndarray:
        """Extract features for prediction model"""
        features = []
        
        # Target characteristics
        features.append(target_profile.vulnerability_score)
        features.append(len(target_profile.defense_mechanisms))
        features.append(np.mean(target_profile.response_times) if target_profile.response_times else 0.1)
        features.append(target_profile.bandwidth_capacity or 1000.0)
        features.append(len(target_profile.service_types))
        
        # Attack parameters
        features.append(attack_params.get('packet_rate', 1000) / 10000.0)  # Normalize
        features.append(attack_params.get('packet_size', 1460) / 1500.0)   # Normalize
        features.append(attack_params.get('concurrency', 100) / 1000.0)    # Normalize
        features.append(attack_params.get('burst_interval', 0.001) * 1000) # Scale up
        
        # Time-based features
        time_of_day = (time.time() % 86400) / 86400.0  # Normalized time of day
        features.append(time_of_day)
        
        return np.array(features)
    
    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        """Sigmoid activation function"""
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def _relu(self, x: np.ndarray) -> np.ndarray:
        """ReLU activation function"""
        return np.maximum(0, x)
    
    def forward_pass(self, features: np.ndarray) -> np.ndarray:
        """Forward pass through neural network"""
        # Input to hidden layer
        hidden_input = np.dot(features, self.model_weights['input_hidden']) + self.model_weights['hidden_bias']
        hidden_output = self._relu(hidden_input)
        
        # Hidden to output layer
        output_input = np.dot(hidden_output, self.model_weights['hidden_output']) + self.model_weights['output_bias']
        output = self._sigmoid(output_input)
        
        return output
    
    async def predict_performance(self, 
                                target_profile: TargetProfile,
                                attack_params: Dict[str, Any]) -> PredictionResult:
        """Predict attack performance for given target and parameters"""
        
        # Extract features
        features = self.extract_features(target_profile, attack_params)
        
        # Make prediction
        if self.model_type == "neural_network":
            prediction = self.forward_pass(features)
        else:
            # Fallback to heuristic model
            prediction = self._heuristic_prediction(features)
        
        # Scale predictions to realistic ranges
        predicted_pps = prediction[0] * 100000  # Scale to 0-100k pps
        predicted_success_rate = prediction[1]   # Already 0-1
        predicted_bandwidth = prediction[2] * 10000  # Scale to 0-10 Gbps
        
        # Calculate confidence interval
        confidence = self._calculate_confidence(features, prediction)
        confidence_interval = (
            predicted_pps * (1 - confidence * 0.2),
            predicted_pps * (1 + confidence * 0.2)
        )
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(target_profile, attack_params)
        
        # Generate parameter recommendations
        recommended_params = self._generate_recommendations(target_profile, prediction)
        
        result = PredictionResult(
            predicted_pps=predicted_pps,
            predicted_success_rate=predicted_success_rate,
            predicted_bandwidth=predicted_bandwidth,
            confidence_interval=confidence_interval,
            risk_factors=risk_factors,
            recommended_parameters=recommended_params
        )
        
        self.prediction_history.append(result)
        return result
    
    def _heuristic_prediction(self, features: np.ndarray) -> np.ndarray:
        """Fallback heuristic prediction model"""
        vulnerability = features[0]
        defense_count = features[1]
        response_time = features[2]
        bandwidth = features[3]
        packet_rate = features[5]
        packet_size = features[6]
        
        # Simple heuristic calculations
        pps_factor = vulnerability * (1 - defense_count * 0.1) * packet_rate
        success_factor = vulnerability * (1 / (response_time + 0.1)) * (1 - defense_count * 0.15)
        bandwidth_factor = (packet_rate * packet_size) / bandwidth
        
        return np.array([
            min(1.0, pps_factor),
            min(1.0, max(0.0, success_factor)),
            min(1.0, bandwidth_factor)
        ])
    
    def _calculate_confidence(self, features: np.ndarray, prediction: np.ndarray) -> float:
        """Calculate prediction confidence based on feature quality and model certainty"""
        # Feature quality assessment
        feature_quality = 1.0
        
        # Penalize missing or default values
        if features[3] == 1000.0:  # Default bandwidth
            feature_quality *= 0.8
        if len(self.training_data) < 10:  # Insufficient training data
            feature_quality *= 0.6
        
        # Model certainty (how close predictions are to extremes)
        if len(prediction) > 0:
            certainty = 1.0 - np.mean(np.abs(prediction - 0.5)) * 2
        else:
            certainty = 0.5
        
        return feature_quality * certainty
    
    def _identify_risk_factors(self, 
                             target_profile: TargetProfile,
                             attack_params: Dict[str, Any]) -> List[str]:
        """Identify potential risk factors that could affect performance"""
        risks = []
        
        # Defense mechanism risks
        if 'rate_limiting' in target_profile.defense_mechanisms:
            risks.append("target_has_rate_limiting")
        if 'ddos_protection' in target_profile.defense_mechanisms:
            risks.append("target_has_ddos_protection")
        if 'firewall' in target_profile.defense_mechanisms:
            risks.append("target_has_firewall")
        
        # Parameter risks
        if attack_params.get('packet_rate', 0) > 50000:
            risks.append("high_packet_rate_may_trigger_defenses")
        if attack_params.get('concurrency', 0) > 500:
            risks.append("high_concurrency_may_exhaust_resources")
        
        # Target characteristic risks
        if target_profile.vulnerability_score < 0.3:
            risks.append("target_appears_well_defended")
        if target_profile.response_times and np.mean(target_profile.response_times) > 5.0:
            risks.append("target_response_times_indicate_overload")
        
        return risks
    
    def _generate_recommendations(self, 
                                target_profile: TargetProfile,
                                prediction: np.ndarray) -> Dict[str, Any]:
        """Generate parameter recommendations based on prediction"""
        recommendations = {}
        
        predicted_success = prediction[1]
        
        if predicted_success < 0.3:
            # Low success rate - recommend more aggressive parameters
            recommendations.update({
                'packet_rate': 'increase_gradually',
                'packet_size': 'use_smaller_packets',
                'evasion_techniques': 'enable_advanced_evasion',
                'protocol_mix': 'use_multiple_protocols'
            })
        elif predicted_success < 0.7:
            # Moderate success - fine-tune parameters
            recommendations.update({
                'packet_rate': 'maintain_current',
                'packet_size': 'optimize_for_mtu',
                'timing': 'add_randomization',
                'monitoring': 'increase_feedback_frequency'
            })
        else:
            # High success rate - maintain or slightly optimize
            recommendations.update({
                'packet_rate': 'maintain_or_increase_slightly',
                'efficiency': 'focus_on_resource_efficiency',
                'stealth': 'enable_stealth_mode'
            })
        
        # Defense-specific recommendations
        if 'rate_limiting' in target_profile.defense_mechanisms:
            recommendations['evasion'] = 'use_distributed_sources'
        if 'ddos_protection' in target_profile.defense_mechanisms:
            recommendations['strategy'] = 'use_application_layer_attacks'
        
        return recommendations
    
    def update_model(self, 
                    target_profile: TargetProfile,
                    attack_params: Dict[str, Any],
                    actual_results: Dict[str, float]):
        """Update model with actual results for continuous learning"""
        
        # Extract features and actual outputs
        features = self.extract_features(target_profile, attack_params)
        actual_outputs = np.array([
            actual_results.get('pps', 0) / 100000.0,
            actual_results.get('success_rate', 0),
            actual_results.get('bandwidth', 0) / 10000.0
        ])
        
        # Store training data
        self.training_data.append((features, actual_outputs))
        
        # Perform online learning update
        if len(self.training_data) >= 5:
            self._online_learning_update()
    
    def _online_learning_update(self):
        """Perform online learning update using recent training data"""
        if len(self.training_data) < 5:
            return
        
        learning_rate = 0.01
        batch_size = min(5, len(self.training_data))
        
        # Sample recent training data
        recent_data = list(self.training_data)[-batch_size:]
        
        for features, targets in recent_data:
            # Forward pass
            hidden_input = np.dot(features, self.model_weights['input_hidden']) + self.model_weights['hidden_bias']
            hidden_output = self._relu(hidden_input)
            
            output_input = np.dot(hidden_output, self.model_weights['hidden_output']) + self.model_weights['output_bias']
            predictions = self._sigmoid(output_input)
            
            # Calculate error
            error = targets - predictions
            
            # Backward pass (simplified gradient descent)
            output_gradient = error * predictions * (1 - predictions)  # Sigmoid derivative
            
            # Update output weights
            self.model_weights['hidden_output'] += learning_rate * np.outer(hidden_output, output_gradient)
            self.model_weights['output_bias'] += learning_rate * output_gradient
            
            # Update hidden weights (simplified)
            hidden_error = np.dot(output_gradient, self.model_weights['hidden_output'].T)
            hidden_gradient = hidden_error * (hidden_output > 0)  # ReLU derivative
            
            self.model_weights['input_hidden'] += learning_rate * np.outer(features, hidden_gradient)
            self.model_weights['hidden_bias'] += learning_rate * hidden_gradient

class EffectivenessPredictor:
    """
    Specialized predictor for attack effectiveness based on
    target analysis and historical performance data.
    """
    
    def __init__(self):
        self.effectiveness_history = deque(maxlen=200)
        self.target_profiles = {}
        self.pattern_weights = {
            'time_of_day': 0.1,
            'target_load': 0.3,
            'defense_adaptation': 0.4,
            'network_conditions': 0.2
        }
    
    async def predict_effectiveness(self, 
                                  target_profile: TargetProfile,
                                  attack_params: Dict[str, Any],
                                  current_time: Optional[float] = None) -> float:
        """Predict attack effectiveness score (0-1)"""
        
        if current_time is None:
            current_time = time.time()
        
        # Base effectiveness from target vulnerability
        base_effectiveness = target_profile.vulnerability_score
        
        # Time-based adjustments
        time_factor = self._calculate_time_factor(current_time)
        
        # Target load factor
        load_factor = self._calculate_load_factor(target_profile)
        
        # Defense adaptation factor
        defense_factor = self._calculate_defense_factor(target_profile)
        
        # Network conditions factor
        network_factor = self._calculate_network_factor(target_profile)
        
        # Weighted combination
        effectiveness = (
            base_effectiveness * 0.4 +
            time_factor * self.pattern_weights['time_of_day'] +
            load_factor * self.pattern_weights['target_load'] +
            defense_factor * self.pattern_weights['defense_adaptation'] +
            network_factor * self.pattern_weights['network_conditions']
        )
        
        return max(0.0, min(1.0, effectiveness))
    
    def _calculate_time_factor(self, current_time: float) -> float:
        """Calculate effectiveness factor based on time of day"""
        # Convert to hour of day (0-23)
        hour = (current_time % 86400) / 3600
        
        # Assume higher effectiveness during off-peak hours (2-6 AM, 14-16 PM)
        if 2 <= hour <= 6 or 14 <= hour <= 16:
            return 0.8
        elif 9 <= hour <= 17:  # Business hours - likely more defended
            return 0.4
        else:
            return 0.6
    
    def _calculate_load_factor(self, target_profile: TargetProfile) -> float:
        """Calculate effectiveness factor based on target load"""
        if not target_profile.response_times:
            return 0.5
        
        avg_response_time = np.mean(target_profile.response_times)
        
        # Higher response times suggest higher load, potentially easier target
        if avg_response_time > 2.0:
            return 0.8
        elif avg_response_time > 1.0:
            return 0.6
        else:
            return 0.4
    
    def _calculate_defense_factor(self, target_profile: TargetProfile) -> float:
        """Calculate effectiveness factor based on defense mechanisms"""
        defense_count = len(target_profile.defense_mechanisms)
        
        # More defenses = lower effectiveness
        if defense_count == 0:
            return 0.9
        elif defense_count <= 2:
            return 0.6
        elif defense_count <= 4:
            return 0.3
        else:
            return 0.1
    
    def _calculate_network_factor(self, target_profile: TargetProfile) -> float:
        """Calculate effectiveness factor based on network conditions"""
        # Simplified network condition assessment
        if target_profile.bandwidth_capacity:
            if target_profile.bandwidth_capacity > 10000:  # High bandwidth
                return 0.3
            elif target_profile.bandwidth_capacity > 1000:  # Medium bandwidth
                return 0.6
            else:  # Low bandwidth
                return 0.9
        
        return 0.5  # Unknown bandwidth
    
    def update_effectiveness_history(self, 
                                   target_profile: TargetProfile,
                                   predicted_effectiveness: float,
                                   actual_effectiveness: float):
        """Update effectiveness prediction accuracy"""
        
        error = abs(predicted_effectiveness - actual_effectiveness)
        
        self.effectiveness_history.append({
            'target': target_profile.ip_address,
            'predicted': predicted_effectiveness,
            'actual': actual_effectiveness,
            'error': error,
            'timestamp': time.time()
        })
        
        # Update target profile with new data
        self.target_profiles[target_profile.ip_address] = target_profile
    
    def get_prediction_accuracy(self) -> Dict[str, float]:
        """Get prediction accuracy metrics"""
        if len(self.effectiveness_history) < 5:
            return {"status": "insufficient_data"}
        
        recent_history = list(self.effectiveness_history)[-20:]
        errors = [h['error'] for h in recent_history]
        
        return {
            "mean_absolute_error": np.mean(errors),
            "accuracy_score": 1.0 - np.mean(errors),
            "prediction_count": len(recent_history),
            "trend": self._calculate_accuracy_trend()
        }
    
    def _calculate_accuracy_trend(self) -> str:
        """Calculate trend in prediction accuracy"""
        if len(self.effectiveness_history) < 10:
            return "unknown"
        
        recent_errors = [h['error'] for h in list(self.effectiveness_history)[-10:]]
        earlier_errors = [h['error'] for h in list(self.effectiveness_history)[-20:-10]]
        
        if not earlier_errors:
            return "unknown"
        
        recent_avg = np.mean(recent_errors)
        earlier_avg = np.mean(earlier_errors)
        
        if recent_avg < earlier_avg * 0.9:
            return "improving"
        elif recent_avg > earlier_avg * 1.1:
            return "declining"
        else:
            return "stable"