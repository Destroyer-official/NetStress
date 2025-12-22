"""
AI Orchestrator - Main Integration Module

Integrates all AI components with the DDoS framework:
- ML Infrastructure
- Adaptive Strategy Engine  
- Defense Detection and Evasion AI
- Model Validation and Testing

Enhanced with Rust engine integration and shared memory stats.
Provides unified interface for AI-driven attack optimization.
"""

import logging
import threading
import asyncio
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

from .ml_infrastructure import MLModelManager, TrainingData
from .adaptive_strategy import AdaptiveStrategyEngine, AttackStrategy, EnvironmentState
from .defense_evasion import DefenseDetectionAI, DefenseSignature, EvasionStrategy
from .model_validation import ModelValidator, ValidationResult

# Import Rust engine and shared memory bridge (Requirement 8.1)
try:
    from ..native_engine import RustEngine
    from ..analytics.shared_memory_bridge import SharedMemoryBridge
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    RustEngine = None
    SharedMemoryBridge = None

logger = logging.getLogger(__name__)

@dataclass
class AIOptimizationResult:
    """Result of AI-driven attack optimization"""
    optimized_parameters: Dict[str, Any]
    confidence_score: float
    detected_defenses: List[DefenseSignature]
    selected_evasions: List[EvasionStrategy]
    predicted_effectiveness: float
    optimization_time: float
    recommendations: List[str]

class AIOrchestrator:
    """
    Main AI Orchestrator that coordinates all AI components
    Provides unified interface for AI-driven attack optimization
    
    Enhanced with Rust engine integration and shared memory stats.
    Requirements: 8.1 - Connect to Rust engine via PyO3, use shared memory for stats
    """
    
    def __init__(self):
        # Initialize AI components
        self.ml_manager = MLModelManager()
        self.strategy_engine = AdaptiveStrategyEngine()
        self.defense_ai = DefenseDetectionAI()
        self.model_validator = ModelValidator()
        
        # Rust engine integration (Requirement 8.1)
        self.rust_engine: Optional[RustEngine] = None
        self.shared_memory_bridge: Optional[SharedMemoryBridge] = None
        self._rust_available = RUST_AVAILABLE
        
        # State management
        self.is_initialized = False
        self.optimization_history = []
        self.performance_metrics = {}
        
        # Threading
        self._lock = threading.Lock()
        
        # Initialize models and Rust integration
        self._initialize_ai_models()
        self._initialize_rust_integration()
    
    def _initialize_ai_models(self):
        """Initialize all AI models"""
        try:
            # Initialize pattern recognition model
            pattern_model_id = self.ml_manager.initialize_pattern_recognition_model()
            logger.info(f"Initialized pattern recognition model: {pattern_model_id}")
            
            # Create validation benchmarks
            self._create_validation_benchmarks()
            
            # Set up initial training data collection
            self._setup_training_data_collection()
            
            self.is_initialized = True
            logger.info("AI Orchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AI models: {e}")
            self.is_initialized = False
    
    def _create_validation_benchmarks(self):
        """Create performance benchmarks for model validation"""
        
        # Attack effectiveness benchmark
        self.model_validator.create_benchmark(
            benchmark_id='attack_effectiveness_v1',
            model_type='attack_effectiveness',
            baseline_accuracy=0.75,
            baseline_performance={
                'r2': 0.75,
                'mse': 0.05,
                'mae': 0.15
            },
            requirements={
                'max_inference_time': 0.1,  # 100ms
                'min_accuracy': 0.70
            }
        )
        
        # Defense detection benchmark
        self.model_validator.create_benchmark(
            benchmark_id='defense_detection_v1',
            model_type='defense_detection',
            baseline_accuracy=0.85,
            baseline_performance={
                'accuracy': 0.85,
                'precision': 0.80,
                'recall': 0.80,
                'f1_score': 0.80
            },
            requirements={
                'max_inference_time': 0.05,  # 50ms
                'min_accuracy': 0.80
            }
        )
    
    def _setup_training_data_collection(self):
        """Set up training data collection from attack sessions"""
        
        # Add feature extractors for different attack types
        def extract_tcp_features(attack_stats, target_response, network_conditions):
            return [
                attack_stats.get('tcp_syn_pps', 0) / 100000.0,
                attack_stats.get('tcp_ack_pps', 0) / 100000.0,
                target_response.get('tcp_response_time', 0) / 5000.0
            ]
        
        def extract_udp_features(attack_stats, target_response, network_conditions):
            return [
                attack_stats.get('udp_pps', 0) / 100000.0,
                target_response.get('udp_packet_loss', 0),
                network_conditions.get('udp_congestion', 0)
            ]
        
        def extract_http_features(attack_stats, target_response, network_conditions):
            return [
                attack_stats.get('http_rps', 0) / 10000.0,
                target_response.get('http_error_rate', 0),
                target_response.get('http_response_size', 0) / 10000.0
            ]
        
        # Register feature extractors
        self.ml_manager.data_collector.add_feature_extractor('tcp_features', extract_tcp_features)
        self.ml_manager.data_collector.add_feature_extractor('udp_features', extract_udp_features)
        self.ml_manager.data_collector.add_feature_extractor('http_features', extract_http_features)
    
    def _initialize_rust_integration(self):
        """
        Initialize Rust engine integration and shared memory bridge.
        
        Requirements: 8.1 - Connect to Rust engine via PyO3, use shared memory for stats
        """
        if not self._rust_available:
            logger.warning("Rust engine not available - AI will use Python fallback")
            return
            
        try:
            # Initialize shared memory bridge for nanosecond-level stats access
            self.shared_memory_bridge = SharedMemoryBridge(
                shm_name="netstress_stats",
                size=4096  # 4KB for stats structure
            )
            
            # Initialize Rust engine connection
            self.rust_engine = RustEngine()
            
            logger.info("Rust engine integration initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Rust integration: {e}")
            self._rust_available = False
            self.rust_engine = None
            self.shared_memory_bridge = None
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """
        Get real-time statistics from Rust engine via shared memory.
        
        Provides microsecond-level access to engine statistics without IPC overhead.
        
        Returns:
            Dictionary containing current engine statistics
            
        Requirements: 8.1, 8.3 - Use shared memory for 1000x faster access than psutil
        """
        if not self.shared_memory_bridge:
            # Fallback to traditional stats collection
            return self._get_fallback_stats()
            
        try:
            # Read stats from shared memory (microsecond access)
            stats = self.shared_memory_bridge.read_stats()
            
            # Convert raw stats to structured format
            return {
                'packets_sent': stats.get('packets_sent', 0),
                'bytes_sent': stats.get('bytes_sent', 0),
                'pps': stats.get('pps', 0.0),
                'bps': stats.get('bps', 0.0),
                'errors': stats.get('errors', 0),
                'duration': stats.get('duration', 0.0),
                'backend': stats.get('backend', 'unknown'),
                'cpu_usage': stats.get('cpu_usage', 0.0),
                'memory_usage': stats.get('memory_usage', 0),
                'network_utilization': stats.get('network_utilization', 0.0),
                'timestamp': stats.get('timestamp', 0.0)
            }
            
        except Exception as e:
            logger.debug(f"Failed to read shared memory stats: {e}")
            return self._get_fallback_stats()
    
    def _get_fallback_stats(self) -> Dict[str, Any]:
        """Fallback stats collection when shared memory unavailable"""
        return {
            'packets_sent': 0,
            'bytes_sent': 0,
            'pps': 0.0,
            'bps': 0.0,
            'errors': 0,
            'duration': 0.0,
            'backend': 'python_fallback',
            'cpu_usage': 0.0,
            'memory_usage': 0,
            'network_utilization': 0.0,
            'timestamp': datetime.now().timestamp()
        }
    
    def configure_rust_engine(self, config: Dict[str, Any]) -> bool:
        """
        Configure the Rust engine with optimized parameters.
        
        Args:
            config: Engine configuration parameters
            
        Returns:
            True if configuration was successful
            
        Requirements: 8.1 - Connect to Rust engine via PyO3
        """
        if not self.rust_engine:
            logger.warning("Rust engine not available for configuration")
            return False
            
        try:
            # Configure Rust engine with AI-optimized parameters
            success = self.rust_engine.configure(config)
            
            if success:
                logger.info("Rust engine configured successfully")
            else:
                logger.warning("Rust engine configuration failed")
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to configure Rust engine: {e}")
            return False
    
    def start_rust_attack(self, attack_config: Dict[str, Any]) -> bool:
        """
        Start attack using Rust engine with AI-optimized parameters.
        
        Args:
            attack_config: Attack configuration
            
        Returns:
            True if attack started successfully
        """
        if not self.rust_engine:
            logger.warning("Rust engine not available - cannot start attack")
            return False
            
        try:
            # Start attack with Rust engine
            success = self.rust_engine.start_attack(attack_config)
            
            if success:
                logger.info("Rust attack started successfully")
            else:
                logger.warning("Failed to start Rust attack")
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to start Rust attack: {e}")
            return False
    
    def stop_rust_attack(self) -> bool:
        """Stop current Rust attack"""
        if not self.rust_engine:
            return False
            
        try:
            success = self.rust_engine.stop_attack()
            logger.info("Rust attack stopped")
            return success
            
        except Exception as e:
            logger.error(f"Failed to stop Rust attack: {e}")
            return False
    
    def optimize_attack_parameters(self, current_params: Dict[str, Any],
                                 attack_stats: Optional[Dict[str, Any]] = None,
                                 target_response: Optional[Dict[str, Any]] = None,
                                 network_conditions: Optional[Dict[str, Any]] = None) -> AIOptimizationResult:
        """
        Main method for AI-driven attack parameter optimization
        Integrates all AI components to provide optimal attack configuration
        """
        
        if not self.is_initialized:
            logger.warning("AI Orchestrator not initialized, using default parameters")
            return AIOptimizationResult(
                optimized_parameters=current_params,
                confidence_score=0.0,
                detected_defenses=[],
                selected_evasions=[],
                predicted_effectiveness=0.5,
                optimization_time=0.0,
                recommendations=["AI system not initialized"]
            )
        
        start_time = datetime.now()
        
        with self._lock:
            try:
                # Get real-time stats from Rust engine if available (Requirement 8.1)
                if attack_stats is None:
                    attack_stats = self.get_real_time_stats()
                if target_response is None:
                    target_response = {}
                if network_conditions is None:
                    network_conditions = {}
                
                self.ml_manager.update_model_with_attack_data(
                    attack_stats, target_response, network_conditions
                )
                
                response_history = self._build_response_history(target_response)
                detected_defenses = self.defense_ai.analyze_target_defenses(response_history)
                
                adapted_strategy = self.strategy_engine.adapt_strategy(
                    attack_stats, target_response, network_conditions
                )
                
                evasion_strategy = self.defense_ai.generate_evasion_strategy(
                    detected_defenses, adapted_strategy
                )
                
                predicted_effectiveness = self.ml_manager.predict_attack_effectiveness(
                    evasion_strategy
                )
                
                optimized_params = self._combine_optimizations(
                    current_params, adapted_strategy, evasion_strategy
                )
                
                confidence_score = self._calculate_confidence_score(
                    detected_defenses, predicted_effectiveness, attack_stats
                )
                
                recommendations = self._generate_recommendations(
                    detected_defenses, evasion_strategy, predicted_effectiveness
                )
                
                optimization_time = (datetime.now() - start_time).total_seconds()
                
                result = AIOptimizationResult(
                    optimized_parameters=optimized_params,
                    confidence_score=confidence_score,
                    detected_defenses=detected_defenses,
                    selected_evasions=evasion_strategy.get('evasion_techniques', []),
                    predicted_effectiveness=predicted_effectiveness,
                    optimization_time=optimization_time,
                    recommendations=recommendations
                )
                
                # Store optimization history
                self.optimization_history.append({
                    'timestamp': datetime.now(),
                    'result': result,
                    'input_params': current_params.copy(),
                    'attack_stats': attack_stats.copy()
                })
                
                logger.info(f"AI optimization completed in {optimization_time:.3f}s, "
                           f"confidence: {confidence_score:.3f}, "
                           f"predicted effectiveness: {predicted_effectiveness:.3f}")
                
                return result
                
            except Exception as e:
                logger.error(f"AI optimization failed: {e}")
                return AIOptimizationResult(
                    optimized_parameters=current_params,
                    confidence_score=0.0,
                    detected_defenses=[],
                    selected_evasions=[],
                    predicted_effectiveness=0.5,
                    optimization_time=(datetime.now() - start_time).total_seconds(),
                    recommendations=[f"Optimization failed: {str(e)}"]
                )
    
    def _build_response_history(self, current_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build response history for defense analysis"""
        
        # In a real implementation, this would maintain a history buffer
        # For now, we'll create a synthetic history based on current response
        history = []
        
        # Add current response
        history.append(current_response.copy())
        
        # Add some synthetic historical responses for analysis
        for i in range(5):
            synthetic_response = current_response.copy()
            
            # Add some variation
            if 'response_time' in synthetic_response:
                synthetic_response['response_time'] += np.random.normal(0, 100)
            
            if 'status_code' in synthetic_response:
                # Occasionally change status code to simulate defense activation
                if np.random.random() < 0.2:
                    synthetic_response['status_code'] = np.random.choice([403, 429, 503])
            
            history.append(synthetic_response)
        
        return history
    
    def _combine_optimizations(self, base_params: Dict[str, Any],
                             adapted_strategy: Dict[str, Any],
                             evasion_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Combine optimizations from different AI components"""
        
        optimized = base_params.copy()
        
        # Apply adaptive strategy optimizations
        for key, value in adapted_strategy.items():
            if key in ['packet_rate', 'packet_size', 'burst_duration', 'pause_duration']:
                # Use weighted average for numerical parameters
                if key in optimized:
                    optimized[key] = int(0.7 * value + 0.3 * optimized[key])
                else:
                    optimized[key] = value
            elif key in ['protocol', 'evasion_technique']:
                # Use strategy recommendation for categorical parameters
                optimized[key] = value
        
        # Apply evasion strategy optimizations
        for key, value in evasion_strategy.items():
            if key == 'evasion_techniques':
                optimized[key] = value
            elif key in ['spoofing_rate', 'randomization_level', 'fragmentation_rate']:
                optimized[key] = value
            elif key in ['rotation_interval', 'source_pool_size']:
                optimized[key] = value
        
        # Ensure parameters are within valid ranges
        optimized = self._validate_parameters(optimized)
        
        return optimized
    
    def _validate_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and constrain parameters to valid ranges"""
        
        validated = params.copy()
        
        # Packet rate constraints
        if 'packet_rate' in validated:
            validated['packet_rate'] = max(1000, min(100000, validated['packet_rate']))
        
        # Packet size constraints
        if 'packet_size' in validated:
            validated['packet_size'] = max(64, min(1500, validated['packet_size']))
        
        # Timing constraints
        if 'burst_duration' in validated:
            validated['burst_duration'] = max(0.1, min(10.0, validated['burst_duration']))
        
        if 'pause_duration' in validated:
            validated['pause_duration'] = max(0.1, min(5.0, validated['pause_duration']))
        
        # Rate constraints (0-1 range)
        for rate_param in ['spoofing_rate', 'randomization_level', 'fragmentation_rate']:
            if rate_param in validated:
                validated[rate_param] = max(0.0, min(1.0, validated[rate_param]))
        
        return validated
    
    def _calculate_confidence_score(self, detected_defenses: List[DefenseSignature],
                                  predicted_effectiveness: float,
                                  attack_stats: Dict[str, Any]) -> float:
        """Calculate confidence score for optimization"""
        
        # Base confidence from model predictions
        base_confidence = 0.5
        
        # Boost confidence if defenses are detected with high confidence
        if detected_defenses:
            avg_defense_confidence = sum(d.confidence for d in detected_defenses) / len(detected_defenses)
            base_confidence += 0.2 * avg_defense_confidence
        
        # Boost confidence based on predicted effectiveness
        base_confidence += 0.2 * predicted_effectiveness
        
        # Boost confidence if we have sufficient attack data
        if attack_stats.get('duration', 0) > 30:  # More than 30 seconds of data
            base_confidence += 0.1
        
        # Reduce confidence if error rate is high
        error_rate = attack_stats.get('errors', 0) / max(1, attack_stats.get('packets_sent', 1))
        if error_rate > 0.1:  # More than 10% error rate
            base_confidence -= 0.2 * error_rate
        
        return max(0.0, min(1.0, base_confidence))
    
    def _generate_recommendations(self, detected_defenses: List[DefenseSignature],
                                evasion_strategy: Dict[str, Any],
                                predicted_effectiveness: float) -> List[str]:
        """Generate human-readable recommendations"""
        
        recommendations = []
        
        # Defense-specific recommendations
        if detected_defenses:
            defense_types = [d.defense_type.value for d in detected_defenses]
            recommendations.append(f"Detected defenses: {', '.join(defense_types)}")
            
            for defense in detected_defenses:
                if defense.confidence > 0.8:
                    recommendations.append(
                        f"High confidence {defense.defense_type.value} detection - "
                        f"applying advanced evasion techniques"
                    )
        
        # Evasion recommendations
        evasion_techniques = evasion_strategy.get('evasion_techniques', [])
        if evasion_techniques:
            recommendations.append(f"Applying evasion techniques: {', '.join(evasion_techniques)}")
        
        # Effectiveness recommendations
        if predicted_effectiveness > 0.8:
            recommendations.append("High predicted effectiveness - maintain current strategy")
        elif predicted_effectiveness < 0.3:
            recommendations.append("Low predicted effectiveness - consider changing attack vector")
        else:
            recommendations.append("Moderate effectiveness - continue with optimizations")
        
        # Parameter-specific recommendations
        if 'spoofing_rate' in evasion_strategy and evasion_strategy['spoofing_rate'] > 0.5:
            recommendations.append("High IP spoofing rate recommended for evasion")
        
        if 'randomization_level' in evasion_strategy and evasion_strategy['randomization_level'] > 0.7:
            recommendations.append("High randomization level applied to avoid pattern detection")
        
        return recommendations
    
    def update_performance_feedback(self, optimization_result: AIOptimizationResult,
                                  actual_results: Dict[str, Any]):
        """Update AI models with performance feedback"""
        
        with self._lock:
            try:
                # Calculate success metrics
                success = self._evaluate_optimization_success(optimization_result, actual_results)
                
                # Update strategy engine with feedback
                strategy_id = f"opt_{len(self.optimization_history)}"
                self.strategy_engine.update_performance_feedback(strategy_id, actual_results)
                
                # Update defense evasion AI with feedback
                evasion_techniques = [t.value if hasattr(t, 'value') else str(t) 
                                    for t in optimization_result.selected_evasions]
                self.defense_ai.update_evasion_feedback(evasion_techniques, actual_results, success)
                
                # Store performance metrics
                self.performance_metrics[datetime.now().isoformat()] = {
                    'predicted_effectiveness': optimization_result.predicted_effectiveness,
                    'actual_effectiveness': self._calculate_actual_effectiveness(actual_results),
                    'success': success,
                    'optimization_time': optimization_result.optimization_time
                }
                
                logger.info(f"Updated AI models with feedback - Success: {success}")
                
            except Exception as e:
                logger.error(f"Failed to update performance feedback: {e}")
    
    def _evaluate_optimization_success(self, optimization_result: AIOptimizationResult,
                                     actual_results: Dict[str, Any]) -> bool:
        """Evaluate if optimization was successful"""
        
        # Success criteria
        success_indicators = []
        
        # Check if predicted effectiveness was close to actual
        actual_effectiveness = self._calculate_actual_effectiveness(actual_results)
        prediction_error = abs(optimization_result.predicted_effectiveness - actual_effectiveness)
        success_indicators.append(prediction_error < 0.3)  # Within 30%
        
        # Check if attack performance improved
        pps = actual_results.get('pps', 0)
        success_indicators.append(pps > 1000)  # Minimum performance threshold
        
        # Check error rate
        error_rate = actual_results.get('errors', 0) / max(1, actual_results.get('packets_sent', 1))
        success_indicators.append(error_rate < 0.2)  # Less than 20% error rate
        
        # Overall success if majority of indicators are positive
        return sum(success_indicators) >= len(success_indicators) * 0.6
    
    def _calculate_actual_effectiveness(self, results: Dict[str, Any]) -> float:
        """Calculate actual effectiveness from attack results"""
        
        # Normalize PPS to 0-1 scale
        pps_score = min(results.get('pps', 0) / 50000.0, 1.0)
        
        # Error penalty
        error_rate = results.get('errors', 0) / max(1, results.get('packets_sent', 1))
        error_penalty = max(0.0, 1.0 - error_rate * 2)  # Penalty for errors
        
        # Bandwidth utilization
        bps_score = min(results.get('bps', 0) / 1e9, 1.0)  # Normalize to Gbps
        
        # Combined effectiveness
        effectiveness = 0.5 * pps_score + 0.3 * error_penalty + 0.2 * bps_score
        
        return max(0.0, min(1.0, effectiveness))
    
    def validate_ai_models(self) -> Dict[str, ValidationResult]:
        """Validate all AI models"""
        
        validation_results = {}
        
        try:
            # Validate pattern recognition model
            if 'pattern_recognition' in self.ml_manager.active_models:
                model_id = self.ml_manager.active_models['pattern_recognition']
                model_info = self.ml_manager.training_pipeline.load_model(model_id)
                
                if model_info:
                    architecture, metadata = model_info
                    test_data = self.model_validator.dataset_generator.generate_attack_effectiveness_dataset(200)
                    
                    result = self.model_validator.validate_neural_network(
                        architecture, test_data, model_id
                    )
                    validation_results['pattern_recognition'] = result
            
            # Validate defense detection model
            defense_result = self.model_validator.validate_defense_detection_model(
                self.defense_ai.pattern_classifier, 'defense_detection'
            )
            validation_results['defense_detection'] = defense_result
            
            logger.info(f"AI model validation completed - {len(validation_results)} models validated")
            
        except Exception as e:
            logger.error(f"AI model validation failed: {e}")
        
        return validation_results
    
    def get_ai_status(self) -> Dict[str, Any]:
        """Get comprehensive AI system status"""
        
        status = {
            'initialized': self.is_initialized,
            'ml_manager_status': self.ml_manager.get_model_status(),
            'strategy_engine_status': self.strategy_engine.get_adaptation_status(),
            'defense_ai_status': self.defense_ai.get_defense_intelligence(),
            'optimization_count': len(self.optimization_history),
            'performance_metrics_count': len(self.performance_metrics),
            'recent_optimizations': [
                {
                    'timestamp': opt['timestamp'].isoformat(),
                    'confidence': opt['result'].confidence_score,
                    'predicted_effectiveness': opt['result'].predicted_effectiveness,
                    'optimization_time': opt['result'].optimization_time
                }
                for opt in self.optimization_history[-5:]
            ],
            'validation_summary': self.model_validator.get_validation_summary(),
            # Rust engine integration status (Requirement 8.1)
            'rust_integration': {
                'available': self._rust_available,
                'engine_connected': self.rust_engine is not None,
                'shared_memory_active': self.shared_memory_bridge is not None,
                'real_time_stats': self._rust_available and self.shared_memory_bridge is not None
            }
        }
        
        # Add current real-time stats if available
        if self._rust_available:
            try:
                status['current_stats'] = self.get_real_time_stats()
            except Exception as e:
                status['stats_error'] = str(e)
        
        return status
    
    def evolve_strategies(self):
        """Trigger evolution in genetic algorithms"""
        self.strategy_engine.evolve_strategies()
    
    def reset_ai_state(self):
        """Reset AI system state"""
        with self._lock:
            self.optimization_history.clear()
            self.performance_metrics.clear()
            self.defense_ai.reset_defense_state()
            
            # Reset Rust engine if available
            if self.rust_engine:
                try:
                    self.rust_engine.reset()
                    logger.info("Rust engine state reset")
                except Exception as e:
                    logger.warning(f"Failed to reset Rust engine: {e}")
            
            logger.info("AI system state reset")
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            # Stop any running attacks
            if self.rust_engine:
                self.stop_rust_attack()
                
            # Cleanup shared memory
            if self.shared_memory_bridge:
                self.shared_memory_bridge.cleanup()
                
            logger.info("AI orchestrator cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during AI orchestrator cleanup: {e}")

# Global AI orchestrator instance
ai_orchestrator = AIOrchestrator()