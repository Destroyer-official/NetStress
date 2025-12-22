"""
Machine Learning Model Infrastructure

Implements neural network architectures for pattern recognition,
training data collection and preprocessing systems, and model
training, validation, and deployment pipeline.
"""

import numpy as np
import json
import pickle
import logging
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import threading
import queue
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ModelMetadata:
    """Metadata for ML models"""
    model_id: str
    model_type: str
    version: str
    created_at: datetime
    accuracy: float
    loss: float
    training_samples: int
    validation_samples: int
    hyperparameters: Dict[str, Any]
    feature_dimensions: int

@dataclass
class TrainingData:
    """Training data structure"""
    features: np.ndarray
    labels: np.ndarray
    metadata: Dict[str, Any]
    timestamp: datetime

class NeuralNetworkArchitecture:
    """
    Neural network architectures for pattern recognition
    Implements various network types for different AI tasks
    """
    
    def __init__(self, input_dim: int, hidden_layers: List[int], output_dim: int):
        self.input_dim = input_dim
        self.hidden_layers = hidden_layers
        self.output_dim = output_dim
        self.weights = []
        self.biases = []
        self._initialize_weights()
        
    def _initialize_weights(self):
        """Initialize network weights using Xavier initialization"""
        layers = [self.input_dim] + self.hidden_layers + [self.output_dim]
        
        for i in range(len(layers) - 1):
            # Xavier initialization
            limit = np.sqrt(6.0 / (layers[i] + layers[i + 1]))
            weight = np.random.uniform(-limit, limit, (layers[i], layers[i + 1]))
            bias = np.zeros((1, layers[i + 1]))
            
            self.weights.append(weight)
            self.biases.append(bias)
    
    def _activation_function(self, x: np.ndarray, activation: str = 'relu') -> np.ndarray:
        """Apply activation function"""
        if activation == 'relu':
            return np.maximum(0, x)
        elif activation == 'sigmoid':
            return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
        elif activation == 'tanh':
            return np.tanh(x)
        elif activation == 'softmax':
            exp_x = np.exp(x - np.max(x, axis=1, keepdims=True))
            return exp_x / np.sum(exp_x, axis=1, keepdims=True)
        else:
            return x  # linear
    
    def forward_pass(self, X: np.ndarray) -> np.ndarray:
        """Forward propagation through the network"""
        current_input = X
        
        for i, (weight, bias) in enumerate(zip(self.weights, self.biases)):
            linear_output = np.dot(current_input, weight) + bias
            
            # Use ReLU for hidden layers, sigmoid for output
            if i < len(self.weights) - 1:
                current_input = self._activation_function(linear_output, 'relu')
            else:
                current_input = self._activation_function(linear_output, 'sigmoid')
        
        return current_input
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Make predictions"""
        return self.forward_pass(X)
    
    def get_architecture_info(self) -> Dict[str, Any]:
        """Get architecture information"""
        return {
            'input_dim': self.input_dim,
            'hidden_layers': self.hidden_layers,
            'output_dim': self.output_dim,
            'total_parameters': sum(w.size for w in self.weights) + sum(b.size for b in self.biases)
        }

class TrainingDataCollector:
    """
    Collects and preprocesses training data for ML models
    Handles real-time data collection from attack sessions
    """
    
    def __init__(self, buffer_size: int = 10000):
        self.buffer_size = buffer_size
        self.data_buffer = queue.Queue(maxsize=buffer_size)
        self.preprocessing_pipeline = []
        self.feature_extractors = {}
        self._lock = threading.Lock()
        
    def add_feature_extractor(self, name: str, extractor_func):
        """Add a feature extraction function"""
        with self._lock:
            self.feature_extractors[name] = extractor_func
    
    def collect_attack_data(self, attack_stats: Dict[str, Any], 
                          target_response: Dict[str, Any],
                          network_conditions: Dict[str, Any]) -> None:
        """Collect data from ongoing attacks"""
        try:
            # Extract features from attack data
            features = self._extract_features(attack_stats, target_response, network_conditions)
            
            # Create training sample
            sample = {
                'features': features,
                'attack_stats': attack_stats,
                'target_response': target_response,
                'network_conditions': network_conditions,
                'timestamp': datetime.now(),
                'effectiveness_score': self._calculate_effectiveness_score(attack_stats, target_response)
            }
            
            # Add to buffer
            if not self.data_buffer.full():
                self.data_buffer.put(sample)
            else:
                # Remove oldest sample and add new one
                self.data_buffer.get()
                self.data_buffer.put(sample)
                
        except Exception as e:
            logger.error(f"Error collecting attack data: {e}")
    
    def _extract_features(self, attack_stats: Dict, target_response: Dict, 
                         network_conditions: Dict) -> np.ndarray:
        """Extract numerical features from attack data"""
        features = []
        
        # Attack statistics features
        features.extend([
            attack_stats.get('pps', 0),
            attack_stats.get('bps', 0),
            attack_stats.get('errors', 0),
            attack_stats.get('conn_rate', 0),
            attack_stats.get('duration', 0)
        ])
        
        # Target response features
        features.extend([
            target_response.get('response_time', 0),
            target_response.get('error_rate', 0),
            target_response.get('connection_drops', 0),
            target_response.get('bandwidth_usage', 0)
        ])
        
        # Network condition features
        features.extend([
            network_conditions.get('latency', 0),
            network_conditions.get('packet_loss', 0),
            network_conditions.get('jitter', 0),
            network_conditions.get('congestion_level', 0)
        ])
        
        # Apply custom feature extractors
        for name, extractor in self.feature_extractors.items():
            try:
                custom_features = extractor(attack_stats, target_response, network_conditions)
                if isinstance(custom_features, (list, np.ndarray)):
                    features.extend(custom_features)
            except Exception as e:
                logger.warning(f"Feature extractor {name} failed: {e}")
        
        return np.array(features, dtype=np.float32)
    
    def _calculate_effectiveness_score(self, attack_stats: Dict, target_response: Dict) -> float:
        """Calculate attack effectiveness score (0-1)"""
        # Simple effectiveness calculation based on multiple factors
        pps_score = min(attack_stats.get('pps', 0) / 100000, 1.0)  # Normalize to 100k pps
        error_penalty = max(0, 1.0 - attack_stats.get('errors', 0) / 1000)  # Penalty for errors
        response_impact = min(target_response.get('response_time', 0) / 5000, 1.0)  # Response time impact
        
        # Weighted combination
        effectiveness = (0.4 * pps_score + 0.3 * error_penalty + 0.3 * response_impact)
        return max(0.0, min(1.0, effectiveness))
    
    def get_training_batch(self, batch_size: int) -> Optional[TrainingData]:
        """Get a batch of training data"""
        if self.data_buffer.qsize() < batch_size:
            return None
        
        samples = []
        for _ in range(min(batch_size, self.data_buffer.qsize())):
            if not self.data_buffer.empty():
                samples.append(self.data_buffer.get())
        
        if not samples:
            return None
        
        # Convert to numpy arrays
        features = np.array([sample['features'] for sample in samples])
        labels = np.array([sample['effectiveness_score'] for sample in samples])
        
        metadata = {
            'batch_size': len(samples),
            'feature_dim': features.shape[1] if len(features.shape) > 1 else 1,
            'collection_time': datetime.now()
        }
        
        return TrainingData(
            features=features,
            labels=labels,
            metadata=metadata,
            timestamp=datetime.now()
        )
    
    def preprocess_data(self, data: TrainingData) -> TrainingData:
        """Apply preprocessing pipeline to training data"""
        processed_features = data.features.copy()
        
        # Normalization
        processed_features = self._normalize_features(processed_features)
        
        # Handle missing values
        processed_features = self._handle_missing_values(processed_features)
        
        # Feature scaling
        processed_features = self._scale_features(processed_features)
        
        return TrainingData(
            features=processed_features,
            labels=data.labels,
            metadata=data.metadata,
            timestamp=data.timestamp
        )
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """Normalize features to [0, 1] range"""
        if features.size == 0:
            return features
        
        min_vals = np.min(features, axis=0)
        max_vals = np.max(features, axis=0)
        
        # Avoid division by zero
        range_vals = max_vals - min_vals
        range_vals[range_vals == 0] = 1
        
        return (features - min_vals) / range_vals
    
    def _handle_missing_values(self, features: np.ndarray) -> np.ndarray:
        """Handle missing or invalid values"""
        # Replace NaN and inf values with 0
        features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
        return features
    
    def _scale_features(self, features: np.ndarray) -> np.ndarray:
        """Apply feature scaling (standardization)"""
        if features.size == 0:
            return features
        
        mean = np.mean(features, axis=0)
        std = np.std(features, axis=0)
        
        # Avoid division by zero
        std[std == 0] = 1
        
        return (features - mean) / std

class ModelTrainingPipeline:
    """
    Model training, validation, and deployment pipeline
    Handles the complete ML workflow from data to deployed models
    """
    
    def __init__(self, model_storage_path: str = "models/"):
        self.model_storage_path = Path(model_storage_path)
        self.model_storage_path.mkdir(parents=True, exist_ok=True)
        self.trained_models = {}
        self.training_history = []
        
    def train_model(self, architecture: NeuralNetworkArchitecture, 
                   training_data: TrainingData,
                   validation_data: Optional[TrainingData] = None,
                   epochs: int = 100,
                   learning_rate: float = 0.001) -> ModelMetadata:
        """Train a neural network model"""
        
        logger.info(f"Starting model training with {epochs} epochs")
        
        # Training loop (simplified gradient descent)
        best_loss = float('inf')
        training_losses = []
        validation_losses = []
        
        for epoch in range(epochs):
            # Forward pass
            predictions = architecture.forward_pass(training_data.features)
            
            # Calculate loss (mean squared error)
            loss = np.mean((predictions.flatten() - training_data.labels) ** 2)
            training_losses.append(loss)
            
            # Simple gradient descent update (simplified)
            self._update_weights(architecture, training_data.features, 
                               training_data.labels, predictions, learning_rate)
            
            # Validation
            if validation_data is not None:
                val_predictions = architecture.forward_pass(validation_data.features)
                val_loss = np.mean((val_predictions.flatten() - validation_data.labels) ** 2)
                validation_losses.append(val_loss)
                
                if val_loss < best_loss:
                    best_loss = val_loss
            
            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: Training Loss = {loss:.4f}")
        
        # Calculate final accuracy
        final_predictions = architecture.forward_pass(training_data.features)
        accuracy = self._calculate_accuracy(final_predictions.flatten(), training_data.labels)
        
        # Create model metadata
        model_id = self._generate_model_id(architecture)
        metadata = ModelMetadata(
            model_id=model_id,
            model_type="neural_network",
            version="1.0",
            created_at=datetime.now(),
            accuracy=accuracy,
            loss=training_losses[-1],
            training_samples=len(training_data.features),
            validation_samples=len(validation_data.features) if validation_data else 0,
            hyperparameters={
                'epochs': epochs,
                'learning_rate': learning_rate,
                'architecture': architecture.get_architecture_info()
            },
            feature_dimensions=training_data.features.shape[1] if len(training_data.features.shape) > 1 else 1
        )
        
        # Save model
        self._save_model(architecture, metadata)
        
        # Store in memory
        self.trained_models[model_id] = {
            'architecture': architecture,
            'metadata': metadata
        }
        
        # Record training history
        self.training_history.append({
            'model_id': model_id,
            'training_losses': training_losses,
            'validation_losses': validation_losses,
            'metadata': metadata
        })
        
        logger.info(f"Model training completed. Accuracy: {accuracy:.4f}, Loss: {training_losses[-1]:.4f}")
        
        return metadata
    
    def _update_weights(self, architecture: NeuralNetworkArchitecture, 
                       features: np.ndarray, labels: np.ndarray, 
                       predictions: np.ndarray, learning_rate: float):
        """Update network weights using gradient descent (simplified)"""
        # Simplified weight update - in practice, would use proper backpropagation
        error = predictions.flatten() - labels
        
        # Update only the last layer weights (simplified)
        if len(architecture.weights) > 0:
            # Get the input to the last layer
            hidden_output = features
            for i in range(len(architecture.weights) - 1):
                hidden_output = architecture._activation_function(
                    np.dot(hidden_output, architecture.weights[i]) + architecture.biases[i], 'relu'
                )
            
            # Update last layer
            gradient = np.dot(hidden_output.T, error.reshape(-1, 1)) / len(features)
            architecture.weights[-1] -= learning_rate * gradient
            
            bias_gradient = np.mean(error)
            architecture.biases[-1] -= learning_rate * bias_gradient
    
    def _calculate_accuracy(self, predictions: np.ndarray, labels: np.ndarray) -> float:
        """Calculate model accuracy"""
        # For regression, use R-squared coefficient
        ss_res = np.sum((labels - predictions) ** 2)
        ss_tot = np.sum((labels - np.mean(labels)) ** 2)
        
        if ss_tot == 0:
            return 1.0 if ss_res == 0 else 0.0
        
        r_squared = 1 - (ss_res / ss_tot)
        return max(0.0, r_squared)  # Ensure non-negative
    
    def _generate_model_id(self, architecture: NeuralNetworkArchitecture) -> str:
        """Generate unique model ID"""
        arch_info = str(architecture.get_architecture_info())
        timestamp = str(datetime.now().timestamp())
        return hashlib.md5((arch_info + timestamp).encode()).hexdigest()[:16]
    
    def _save_model(self, architecture: NeuralNetworkArchitecture, metadata: ModelMetadata):
        """Save model to disk"""
        model_path = self.model_storage_path / f"{metadata.model_id}.pkl"
        metadata_path = self.model_storage_path / f"{metadata.model_id}_metadata.json"
        
        # Save model architecture
        with open(model_path, 'wb') as f:
            pickle.dump(architecture, f)
        
        # Save metadata
        with open(metadata_path, 'w') as f:
            json.dump(asdict(metadata), f, default=str, indent=2)
    
    def load_model(self, model_id: str) -> Optional[Tuple[NeuralNetworkArchitecture, ModelMetadata]]:
        """Load model from disk"""
        model_path = self.model_storage_path / f"{model_id}.pkl"
        metadata_path = self.model_storage_path / f"{model_id}_metadata.json"
        
        if not model_path.exists() or not metadata_path.exists():
            return None
        
        try:
            # Load architecture
            with open(model_path, 'rb') as f:
                architecture = pickle.load(f)
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata_dict = json.load(f)
                metadata = ModelMetadata(**metadata_dict)
            
            return architecture, metadata
        
        except Exception as e:
            logger.error(f"Error loading model {model_id}: {e}")
            return None
    
    def get_best_model(self, metric: str = 'accuracy') -> Optional[str]:
        """Get the best model ID based on specified metric"""
        if not self.trained_models:
            return None
        
        best_model_id = None
        best_score = -float('inf') if metric == 'accuracy' else float('inf')
        
        for model_id, model_info in self.trained_models.items():
            metadata = model_info['metadata']
            
            if metric == 'accuracy':
                score = metadata.accuracy
                if score > best_score:
                    best_score = score
                    best_model_id = model_id
            elif metric == 'loss':
                score = metadata.loss
                if score < best_score:
                    best_score = score
                    best_model_id = model_id
        
        return best_model_id

class MLModelManager:
    """
    Central manager for all ML models and operations
    Coordinates training, deployment, and inference
    """
    
    def __init__(self):
        self.data_collector = TrainingDataCollector()
        self.training_pipeline = ModelTrainingPipeline()
        self.active_models = {}
        self.model_performance = {}
        
    def initialize_pattern_recognition_model(self) -> str:
        """Initialize neural network for pattern recognition"""
        # Create architecture for defense pattern recognition
        architecture = NeuralNetworkArchitecture(
            input_dim=13,  # Based on feature extraction in data collector
            hidden_layers=[64, 32, 16],
            output_dim=1
        )
        
        # Generate some initial training data for bootstrapping
        initial_data = self._generate_bootstrap_data()
        
        # Train initial model
        metadata = self.training_pipeline.train_model(
            architecture=architecture,
            training_data=initial_data,
            epochs=50,
            learning_rate=0.01
        )
        
        self.active_models['pattern_recognition'] = metadata.model_id
        logger.info(f"Pattern recognition model initialized: {metadata.model_id}")
        
        return metadata.model_id
    
    def update_model_with_attack_data(self, attack_stats: Dict, target_response: Dict, 
                                    network_conditions: Dict):
        """Update models with new attack data"""
        # Collect data
        self.data_collector.collect_attack_data(attack_stats, target_response, network_conditions)
        
        # Check if we have enough data for retraining
        batch = self.data_collector.get_training_batch(batch_size=100)
        if batch is not None:
            # Retrain pattern recognition model
            self._retrain_pattern_recognition_model(batch)
    
    def _generate_bootstrap_data(self) -> TrainingData:
        """Generate initial training data for model bootstrapping"""
        # Generate synthetic training data
        n_samples = 1000
        features = np.random.rand(n_samples, 13)  # 13 features as defined in data collector
        
        # Generate synthetic labels based on feature combinations
        labels = np.zeros(n_samples)
        for i in range(n_samples):
            # Simple synthetic effectiveness calculation
            pps_factor = features[i, 0]  # First feature represents PPS
            error_factor = 1.0 - features[i, 2]  # Third feature represents errors
            response_factor = features[i, 5]  # Sixth feature represents response time
            
            labels[i] = (0.4 * pps_factor + 0.3 * error_factor + 0.3 * response_factor)
        
        metadata = {
            'synthetic': True,
            'generation_method': 'bootstrap',
            'feature_dim': 13
        }
        
        return TrainingData(
            features=features,
            labels=labels,
            metadata=metadata,
            timestamp=datetime.now()
        )
    
    def _retrain_pattern_recognition_model(self, new_data: TrainingData):
        """Retrain the pattern recognition model with new data"""
        if 'pattern_recognition' not in self.active_models:
            return
        
        model_id = self.active_models['pattern_recognition']
        model_info = self.training_pipeline.load_model(model_id)
        
        if model_info is None:
            logger.error(f"Could not load model {model_id} for retraining")
            return
        
        architecture, old_metadata = model_info
        
        # Preprocess new data
        processed_data = self.data_collector.preprocess_data(new_data)
        
        # Retrain model
        new_metadata = self.training_pipeline.train_model(
            architecture=architecture,
            training_data=processed_data,
            epochs=20,  # Fewer epochs for incremental training
            learning_rate=0.001
        )
        
        # Update active model if performance improved
        if new_metadata.accuracy > old_metadata.accuracy:
            self.active_models['pattern_recognition'] = new_metadata.model_id
            logger.info(f"Pattern recognition model updated: {new_metadata.model_id} "
                       f"(accuracy: {new_metadata.accuracy:.4f})")
    
    def predict_attack_effectiveness(self, attack_params: Dict) -> float:
        """Predict attack effectiveness using trained models"""
        if 'pattern_recognition' not in self.active_models:
            return 0.5  # Default prediction
        
        model_id = self.active_models['pattern_recognition']
        model_info = self.training_pipeline.load_model(model_id)
        
        if model_info is None:
            return 0.5
        
        architecture, metadata = model_info
        
        # Convert attack parameters to feature vector
        features = self._params_to_features(attack_params)
        
        # Make prediction
        prediction = architecture.predict(features.reshape(1, -1))
        
        return float(prediction[0, 0]) if prediction.size > 0 else 0.5
    
    def _params_to_features(self, params: Dict) -> np.ndarray:
        """Convert attack parameters to feature vector"""
        # Extract features similar to data collector
        features = [
            params.get('packet_rate', 0),
            params.get('packet_size', 0),
            params.get('connection_rate', 0),
            params.get('duration', 0),
            params.get('protocol_type', 0),  # Encoded as number
            params.get('target_port', 0),
            params.get('payload_size', 0),
            params.get('concurrency', 0),
            params.get('burst_rate', 0),
            params.get('evasion_level', 0),
            params.get('randomization', 0),
            params.get('spoofing_rate', 0),
            params.get('amplification_factor', 0)
        ]
        
        return np.array(features, dtype=np.float32)
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all active models"""
        status = {
            'active_models': self.active_models.copy(),
            'training_data_samples': self.data_collector.data_buffer.qsize(),
            'trained_models_count': len(self.training_pipeline.trained_models),
            'model_performance': {}
        }
        
        # Add performance metrics for each active model
        for model_type, model_id in self.active_models.items():
            if model_id in self.training_pipeline.trained_models:
                metadata = self.training_pipeline.trained_models[model_id]['metadata']
                status['model_performance'][model_type] = {
                    'accuracy': metadata.accuracy,
                    'loss': metadata.loss,
                    'training_samples': metadata.training_samples
                }
        
        return status