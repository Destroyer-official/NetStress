#!/usr/bin/env python3
"""
Predictive Analytics System

This module provides comprehensive predictive analytics capabilities including
performance prediction models, anomaly detection, alerting systems, and
effectiveness forecasting with optimization recommendations.
"""

import asyncio
import time
import logging
import statistics
import numpy as np
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error
import joblib
import threading
import queue
@dataclass
class PredictionMetrics:
    """Metrics for prediction accuracy and model performance"""
    mae: float = 0.0  # Mean Absolute Error
    mse: float = 0.0  # Mean Squared Error
    rmse: float = 0.0  # Root Mean Squared Error
    accuracy: float = 0.0  # Prediction accuracy percentage
    confidence: float = 0.0  # Confidence level
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class PerformancePrediction:
    """Performance prediction result"""
    predicted_pps: float  # Predicted packets per second
    predicted_bandwidth: float  # Predicted bandwidth utilization
    predicted_success_rate: float  # Predicted success rate
    confidence_interval: Tuple[float, float]  # Confidence interval
    factors: Dict[str, float]  # Contributing factors
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class Anomaly:
    """Detected anomaly information"""
    metric_name: str
    value: float
    expected_range: Tuple[float, float]
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0

@dataclass
class OptimizationRecommendation:
    """Optimization recommendation"""
    parameter: str
    current_value: Any
    recommended_value: Any
    expected_improvement: float  # Percentage improvement
    confidence: float
    reasoning: str
    priority: str  # 'low', 'medium', 'high', 'critical'

class PerformancePredictor:
    """Advanced performance prediction using machine learning models"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.models = {}
        self.scalers = {}
        self.feature_history = deque(maxlen=10000)
        self.prediction_history = deque(maxlen=1000)
        self.model_lock = threading.Lock()
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models for different prediction tasks"""
        with self.model_lock:
            # Performance prediction models
            self.models['pps'] = RandomForestRegressor(n_estimators=100, random_state=42)
            self.models['bandwidth'] = RandomForestRegressor(n_estimators=100, random_state=42)
            self.models['success_rate'] = RandomForestRegressor(n_estimators=100, random_state=42)
            
            # Scalers for feature normalization
            self.scalers['pps'] = StandardScaler()
            self.scalers['bandwidth'] = StandardScaler()
            self.scalers['success_rate'] = StandardScaler()
            
            self.logger.info("Performance prediction models initialized")
    
    def add_training_data(self, features: Dict[str, float], targets: Dict[str, float]):
        """Add training data for model improvement"""
        try:
            # Store feature-target pairs
            data_point = {
                'features': features.copy(),
                'targets': targets.copy(),
                'timestamp': datetime.now()
            }
            self.feature_history.append(data_point)
            
            # Retrain models if we have enough data
            if len(self.feature_history) >= 100 and len(self.feature_history) % 50 == 0:
                self._retrain_models()
                
        except Exception as e:
            self.logger.error(f"Error adding training data: {e}")
    
    def _retrain_models(self):
        """Retrain models with accumulated data"""
        try:
            if len(self.feature_history) < 50:
                return
            
            with self.model_lock:
                # Prepare training data
                features_list = []
                targets_dict = defaultdict(list)
                
                for data_point in list(self.feature_history)[-1000:]:  # Use last 1000 points
                    feature_vector = [
                        data_point['features'].get('packet_rate', 0),
                        data_point['features'].get('packet_size', 0),
                        data_point['features'].get('thread_count', 0),
                        data_point['features'].get('target_response_time', 0),
                        data_point['features'].get('cpu_usage', 0),
                        data_point['features'].get('memory_usage', 0),
                        data_point['features'].get('network_utilization', 0)
                    ]
                    features_list.append(feature_vector)
                    
                    for target_name in ['pps', 'bandwidth', 'success_rate']:
                        targets_dict[target_name].append(
                            data_point['targets'].get(target_name, 0)
                        )
                
                X = np.array(features_list)
                
                # Train each model
                for target_name in ['pps', 'bandwidth', 'success_rate']:
                    if len(targets_dict[target_name]) > 0:
                        y = np.array(targets_dict[target_name])
                        
                        # Fit scaler and transform features
                        X_scaled = self.scalers[target_name].fit_transform(X)
                        
                        # Train model
                        self.models[target_name].fit(X_scaled, y)
                        
                        self.logger.info(f"Retrained {target_name} prediction model")
                
        except Exception as e:
            self.logger.error(f"Error retraining models: {e}")
    
    def predict_performance(self, features: Dict[str, float]) -> PerformancePrediction:
        """Predict performance metrics based on current features"""
        try:
            with self.model_lock:
                # Prepare feature vector
                feature_vector = np.array([[
                    features.get('packet_rate', 0),
                    features.get('packet_size', 0),
                    features.get('thread_count', 0),
                    features.get('target_response_time', 0),
                    features.get('cpu_usage', 0),
                    features.get('memory_usage', 0),
                    features.get('network_utilization', 0)
                ]])
                
                predictions = {}
                confidence_intervals = {}
                
                # Make predictions for each metric
                for target_name in ['pps', 'bandwidth', 'success_rate']:
                    try:
                        # Scale features
                        X_scaled = self.scalers[target_name].transform(feature_vector)
                        
                        # Make prediction
                        pred = self.models[target_name].predict(X_scaled)[0]
                        predictions[target_name] = max(0, pred)  # Ensure non-negative
                        
                        # Calculate confidence interval (simplified)
                        std_dev = np.std([tree.predict(X_scaled)[0] 
                                        for tree in self.models[target_name].estimators_[:10]])
                        confidence_intervals[target_name] = (
                            max(0, pred - 1.96 * std_dev),
                            pred + 1.96 * std_dev
                        )
                        
                    except Exception as e:
                        self.logger.warning(f"Error predicting {target_name}: {e}")
                        predictions[target_name] = 0
                        confidence_intervals[target_name] = (0, 0)
                
                # Create prediction result
                prediction = PerformancePrediction(
                    predicted_pps=predictions.get('pps', 0),
                    predicted_bandwidth=predictions.get('bandwidth', 0),
                    predicted_success_rate=predictions.get('success_rate', 0),
                    confidence_interval=confidence_intervals.get('pps', (0, 0)),
                    factors=features.copy()
                )
                
                self.prediction_history.append(prediction)
                return prediction
                
        except Exception as e:
            self.logger.error(f"Error making performance prediction: {e}")
            return PerformancePrediction(
                predicted_pps=0,
                predicted_bandwidth=0,
                predicted_success_rate=0,
                confidence_interval=(0, 0),
                factors={}
            )
    
    def get_prediction_accuracy(self) -> PredictionMetrics:
        """Calculate prediction accuracy metrics"""
        try:
            if len(self.prediction_history) < 10:
                return PredictionMetrics()
            
            # Calculate accuracy metrics (simplified)
            recent_predictions = list(self.prediction_history)[-100:]
            
            # This would normally compare with actual results
            # For now, return estimated metrics
            return PredictionMetrics(
                mae=statistics.mean([abs(p.predicted_pps - p.predicted_bandwidth) 
                                   for p in recent_predictions]),
                mse=statistics.mean([(p.predicted_pps - p.predicted_bandwidth) ** 2 
                                   for p in recent_predictions]),
                accuracy=85.0,  # Placeholder
                confidence=0.85
            )
            
        except Exception as e:
            self.logger.error(f"Error calculating prediction accuracy: {e}")
            return PredictionMetrics()

class AnomalyDetector:
    """Advanced anomaly detection system"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.detectors = {}
        self.baseline_stats = defaultdict(dict)
        self.anomaly_history = deque(maxlen=1000)
        self.detection_lock = threading.Lock()
        
        # Initialize anomaly detection models
        self._initialize_detectors()
    
    def _initialize_detectors(self):
        """Initialize anomaly detection models"""
        with self.detection_lock:
            # Isolation Forest for multivariate anomaly detection
            self.detectors['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # Statistical thresholds for individual metrics
            self.detectors['statistical'] = {}
            
            self.logger.info("Anomaly detection models initialized")
    
    def update_baseline(self, metrics: Dict[str, float]):
        """Update baseline statistics for anomaly detection"""
        try:
            with self.detection_lock:
                for metric_name, value in metrics.items():
                    if metric_name not in self.baseline_stats:
                        self.baseline_stats[metric_name] = {
                            'values': deque(maxlen=1000),
                            'mean': 0,
                            'std': 0,
                            'min': float('inf'),
                            'max': float('-inf')
                        }
                    
                    stats = self.baseline_stats[metric_name]
                    stats['values'].append(value)
                    
                    # Update statistics
                    if len(stats['values']) >= 10:
                        values_list = list(stats['values'])
                        stats['mean'] = statistics.mean(values_list)
                        stats['std'] = statistics.stdev(values_list) if len(values_list) > 1 else 0
                        stats['min'] = min(values_list)
                        stats['max'] = max(values_list)
                        
        except Exception as e:
            self.logger.error(f"Error updating baseline: {e}")
    
    def detect_anomalies(self, current_metrics: Dict[str, float]) -> List[Anomaly]:
        """Detect anomalies in current metrics"""
        anomalies = []
        
        try:
            with self.detection_lock:
                # Statistical anomaly detection
                for metric_name, value in current_metrics.items():
                    if metric_name in self.baseline_stats:
                        stats = self.baseline_stats[metric_name]
                        
                        if len(stats['values']) >= 30:  # Need sufficient baseline
                            # Z-score based detection
                            if stats['std'] > 0:
                                z_score = abs(value - stats['mean']) / stats['std']
                                
                                if z_score > 3:  # 3-sigma rule
                                    severity = 'critical' if z_score > 4 else 'high'
                                    anomaly = Anomaly(
                                        metric_name=metric_name,
                                        value=value,
                                        expected_range=(
                                            stats['mean'] - 2 * stats['std'],
                                            stats['mean'] + 2 * stats['std']
                                        ),
                                        severity=severity,
                                        description=f"{metric_name} value {value:.2f} is {z_score:.2f} standard deviations from mean",
                                        confidence=min(0.99, z_score / 4)
                                    )
                                    anomalies.append(anomaly)
                
                # Multivariate anomaly detection using Isolation Forest
                if len(current_metrics) >= 3:
                    try:
                        # Prepare feature vector
                        feature_vector = np.array([list(current_metrics.values())])
                        
                        # Check if model is trained
                        if hasattr(self.detectors['isolation_forest'], 'decision_function'):
                            anomaly_score = self.detectors['isolation_forest'].decision_function(feature_vector)[0]
                            
                            if anomaly_score < -0.5:  # Threshold for anomaly
                                anomaly = Anomaly(
                                    metric_name='multivariate',
                                    value=anomaly_score,
                                    expected_range=(-0.5, 1.0),
                                    severity='medium' if anomaly_score > -0.7 else 'high',
                                    description=f"Multivariate anomaly detected with score {anomaly_score:.3f}",
                                    confidence=abs(anomaly_score)
                                )
                                anomalies.append(anomaly)
                                
                    except Exception as e:
                        self.logger.warning(f"Multivariate anomaly detection failed: {e}")
                
                # Store detected anomalies
                for anomaly in anomalies:
                    self.anomaly_history.append(anomaly)
                
                return anomalies
                
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
            return []
    
    def train_detectors(self, historical_data: List[Dict[str, float]]):
        """Train anomaly detection models with historical data"""
        try:
            if len(historical_data) < 100:
                self.logger.warning("Insufficient data for training anomaly detectors")
                return
            
            with self.detection_lock:
                # Prepare training data for Isolation Forest
                feature_matrix = []
                for data_point in historical_data:
                    if len(data_point) >= 3:  # Need at least 3 features
                        feature_matrix.append(list(data_point.values()))
                
                if len(feature_matrix) >= 100:
                    X = np.array(feature_matrix)
                    self.detectors['isolation_forest'].fit(X)
                    self.logger.info(f"Trained Isolation Forest with {len(feature_matrix)} samples")
                
        except Exception as e:
            self.logger.error(f"Error training anomaly detectors: {e}")

class AlertSystem:
    """Intelligent alerting system with configurable thresholds"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.alert_queue = queue.Queue()
        self.alert_history = deque(maxlen=1000)
        self.alert_rules = {}
        self.alert_callbacks = []
        self.running = False
        self.alert_thread = None
        
        # Initialize default alert rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default alerting rules"""
        self.alert_rules = {
            'performance_degradation': {
                'condition': lambda metrics: metrics.get('pps', 0) < 1000,
                'severity': 'medium',
                'message': 'Performance degradation detected: PPS below threshold'
            },
            'high_error_rate': {
                'condition': lambda metrics: metrics.get('error_rate', 0) > 0.1,
                'severity': 'high',
                'message': 'High error rate detected'
            },
            'resource_exhaustion': {
                'condition': lambda metrics: metrics.get('cpu_usage', 0) > 0.9 or metrics.get('memory_usage', 0) > 0.9,
                'severity': 'critical',
                'message': 'Resource exhaustion detected'
            },
            'anomaly_detected': {
                'condition': lambda metrics: len(metrics.get('anomalies', [])) > 0,
                'severity': 'medium',
                'message': 'Anomalies detected in system metrics'
            }
        }
    
    def add_alert_rule(self, name: str, condition: Callable, severity: str, message: str):
        """Add custom alert rule"""
        self.alert_rules[name] = {
            'condition': condition,
            'severity': severity,
            'message': message
        }
        self.logger.info(f"Added alert rule: {name}")
    
    def add_alert_callback(self, callback: Callable):
        """Add callback function for alert notifications"""
        self.alert_callbacks.append(callback)
    
    def start(self):
        """Start the alert processing system"""
        if not self.running:
            self.running = True
            self.alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
            self.alert_thread.start()
            self.logger.info("Alert system started")
    
    def stop(self):
        """Stop the alert processing system"""
        self.running = False
        if self.alert_thread:
            self.alert_thread.join(timeout=5)
        self.logger.info("Alert system stopped")
    
    def check_alerts(self, metrics: Dict[str, Any]):
        """Check metrics against alert rules"""
        try:
            for rule_name, rule in self.alert_rules.items():
                try:
                    if rule['condition'](metrics):
                        alert = {
                            'rule_name': rule_name,
                            'severity': rule['severity'],
                            'message': rule['message'],
                            'metrics': metrics.copy(),
                            'timestamp': datetime.now()
                        }
                        self.alert_queue.put(alert)
                        
                except Exception as e:
                    self.logger.error(f"Error evaluating alert rule {rule_name}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error checking alerts: {e}")
    
    def _process_alerts(self):
        """Process alerts from the queue"""
        while self.running:
            try:
                # Get alert from queue with timeout
                alert = self.alert_queue.get(timeout=1)
                
                # Store in history
                self.alert_history.append(alert)
                
                # Log alert
                self.logger.warning(f"ALERT [{alert['severity'].upper()}]: {alert['message']}")
                
                # Call registered callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        self.logger.error(f"Error in alert callback: {e}")
                
                self.alert_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing alert: {e}")

class EffectivenessForecaster:
    """Forecasting system for attack effectiveness and optimization"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.forecast_history = deque(maxlen=1000)
        self.optimization_rules = {}
        
        # Initialize optimization rules
        self._initialize_optimization_rules()
    
    def _initialize_optimization_rules(self):
        """Initialize optimization recommendation rules"""
        self.optimization_rules = {
            'packet_rate': {
                'low_performance': lambda metrics: metrics.get('pps', 0) < 10000,
                'recommendation': lambda current: min(current * 1.5, 100000),
                'reasoning': 'Increase packet rate to improve performance'
            },
            'thread_count': {
                'low_cpu_usage': lambda metrics: metrics.get('cpu_usage', 0) < 0.5,
                'recommendation': lambda current: min(current + 2, 16),
                'reasoning': 'Increase thread count to utilize available CPU'
            },
            'packet_size': {
                'high_bandwidth': lambda metrics: metrics.get('bandwidth_utilization', 0) > 0.8,
                'recommendation': lambda current: max(current * 0.8, 64),
                'reasoning': 'Reduce packet size to manage bandwidth usage'
            }
        }
    
    def generate_recommendations(self, current_config: Dict[str, Any], 
                               current_metrics: Dict[str, float]) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations based on current performance"""
        recommendations = []
        
        try:
            for param_name, rules in self.optimization_rules.items():
                current_value = current_config.get(param_name, 0)
                
                for condition_name, condition in rules.items():
                    if condition_name != 'recommendation' and condition_name != 'reasoning':
                        try:
                            if condition(current_metrics):
                                recommended_value = rules['recommendation'](current_value)
                                
                                if recommended_value != current_value:
                                    # Calculate expected improvement (simplified)
                                    improvement = abs(recommended_value - current_value) / max(current_value, 1) * 100
                                    
                                    recommendation = OptimizationRecommendation(
                                        parameter=param_name,
                                        current_value=current_value,
                                        recommended_value=recommended_value,
                                        expected_improvement=min(improvement, 50),  # Cap at 50%
                                        confidence=0.7,  # Default confidence
                                        reasoning=rules['reasoning'],
                                        priority='medium'
                                    )
                                    recommendations.append(recommendation)
                                    
                        except Exception as e:
                            self.logger.error(f"Error evaluating optimization rule {condition_name}: {e}")
            
            # Sort by expected improvement
            recommendations.sort(key=lambda x: x.expected_improvement, reverse=True)
            
            return recommendations[:5]  # Return top 5 recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            return []
    
    def forecast_effectiveness(self, config_changes: Dict[str, Any], 
                            historical_metrics: List[Dict[str, float]]) -> Dict[str, float]:
        """Forecast attack effectiveness with proposed configuration changes"""
        try:
            if len(historical_metrics) < 10:
                return {'confidence': 0.0, 'predicted_improvement': 0.0}
            
            # Simple forecasting based on historical trends
            recent_metrics = historical_metrics[-10:]
            
            # Calculate baseline performance
            baseline_pps = statistics.mean([m.get('pps', 0) for m in recent_metrics])
            baseline_success = statistics.mean([m.get('success_rate', 0) for m in recent_metrics])
            
            # Estimate impact of changes (simplified model)
            predicted_pps = baseline_pps
            predicted_success = baseline_success
            
            for param, new_value in config_changes.items():
                if param == 'packet_rate':
                    # Assume linear relationship (simplified)
                    predicted_pps *= (new_value / max(baseline_pps, 1))
                elif param == 'thread_count':
                    # Diminishing returns for thread count
                    predicted_pps *= min(1.2, 1 + (new_value - 1) * 0.1)
            
            # Calculate predicted improvement
            pps_improvement = (predicted_pps - baseline_pps) / max(baseline_pps, 1) * 100
            success_improvement = (predicted_success - baseline_success) / max(baseline_success, 1) * 100
            
            forecast = {
                'predicted_pps': predicted_pps,
                'predicted_success_rate': predicted_success,
                'pps_improvement': pps_improvement,
                'success_improvement': success_improvement,
                'confidence': 0.6,  # Moderate confidence for simple model
                'predicted_improvement': (pps_improvement + success_improvement) / 2
            }
            
            self.forecast_history.append({
                'config_changes': config_changes.copy(),
                'forecast': forecast.copy(),
                'timestamp': datetime.now()
            })
            
            return forecast
            
        except Exception as e:
            self.logger.error(f"Error forecasting effectiveness: {e}")
            return {'confidence': 0.0, 'predicted_improvement': 0.0}

class PredictiveAnalyticsSystem:
    """Main predictive analytics system coordinating all components"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.performance_predictor = PerformancePredictor()
        self.anomaly_detector = AnomalyDetector()
        self.alert_system = AlertSystem()
        self.effectiveness_forecaster = EffectivenessForecaster()
        
        # System state
        self.running = False
        self.analysis_thread = None
        self.metrics_queue = queue.Queue()
        
        self.logger.info("Predictive Analytics System initialized")
    
    def start(self):
        """Start the predictive analytics system"""
        if not self.running:
            self.running = True
            self.alert_system.start()
            self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
            self.analysis_thread.start()
            self.logger.info("Predictive Analytics System started")
    
    def stop(self):
        """Stop the predictive analytics system"""
        self.running = False
        self.alert_system.stop()
        if self.analysis_thread:
            self.analysis_thread.join(timeout=5)
        self.logger.info("Predictive Analytics System stopped")
    
    def add_metrics(self, metrics: Dict[str, float], config: Dict[str, Any] = None):
        """Add new metrics for analysis"""
        try:
            analysis_data = {
                'metrics': metrics.copy(),
                'config': config.copy() if config else {},
                'timestamp': datetime.now()
            }
            self.metrics_queue.put(analysis_data)
        except Exception as e:
            self.logger.error(f"Error adding metrics: {e}")
    
    def _analysis_loop(self):
        """Main analysis loop processing metrics"""
        while self.running:
            try:
                # Get metrics from queue
                data = self.metrics_queue.get(timeout=1)
                metrics = data['metrics']
                config = data['config']
                
                # Update baseline for anomaly detection
                self.anomaly_detector.update_baseline(metrics)
                
                # Detect anomalies
                anomalies = self.anomaly_detector.detect_anomalies(metrics)
                
                # Add anomalies to metrics for alert checking
                enhanced_metrics = metrics.copy()
                enhanced_metrics['anomalies'] = anomalies
                
                # Check for alerts
                self.alert_system.check_alerts(enhanced_metrics)
                
                # Add training data for performance predictor
                if config:
                    # Extract features and targets for training
                    features = {
                        'packet_rate': config.get('packet_rate', 0),
                        'packet_size': config.get('packet_size', 0),
                        'thread_count': config.get('thread_count', 0),
                        'target_response_time': metrics.get('response_time', 0),
                        'cpu_usage': metrics.get('cpu_usage', 0),
                        'memory_usage': metrics.get('memory_usage', 0),
                        'network_utilization': metrics.get('network_utilization', 0)
                    }
                    
                    targets = {
                        'pps': metrics.get('pps', 0),
                        'bandwidth': metrics.get('bandwidth_utilization', 0),
                        'success_rate': metrics.get('success_rate', 0)
                    }
                    
                    self.performance_predictor.add_training_data(features, targets)
                
                self.metrics_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in analysis loop: {e}")
    
    def get_performance_prediction(self, features: Dict[str, float]) -> PerformancePrediction:
        """Get performance prediction for given features"""
        return self.performance_predictor.predict_performance(features)
    
    def get_optimization_recommendations(self, current_config: Dict[str, Any], 
                                       current_metrics: Dict[str, float]) -> List[OptimizationRecommendation]:
        """Get optimization recommendations"""
        return self.effectiveness_forecaster.generate_recommendations(current_config, current_metrics)
    
    def get_effectiveness_forecast(self, config_changes: Dict[str, Any], 
                                 historical_metrics: List[Dict[str, float]]) -> Dict[str, float]:
        """Get effectiveness forecast for configuration changes"""
        return self.effectiveness_forecaster.forecast_effectiveness(config_changes, historical_metrics)
    
    def get_recent_anomalies(self, limit: int = 10) -> List[Anomaly]:
        """Get recent anomalies"""
        return list(self.anomaly_detector.anomaly_history)[-limit:]
    
    def get_prediction_accuracy(self) -> PredictionMetrics:
        """Get prediction accuracy metrics"""
        return self.performance_predictor.get_prediction_accuracy()

class TimeSeriesForecaster:
    """Advanced time series forecasting for attack metrics"""
    
    def __init__(self, window_size: int = 100):
        self.logger = logging.getLogger(__name__)
        self.window_size = window_size
        self.series_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.trend_models: Dict[str, Dict] = {}
        self.seasonality_detected: Dict[str, bool] = {}
    
    def add_observation(self, metric_name: str, value: float, timestamp: float = None):
        """Add observation to time series"""
        if timestamp is None:
            timestamp = time.time()
        
        self.series_data[metric_name].append({
            'value': value,
            'timestamp': timestamp
        })
        
        # Update trend model if enough data
        if len(self.series_data[metric_name]) >= 20:
            self._update_trend_model(metric_name)
    
    def _update_trend_model(self, metric_name: str):
        """Update trend model for a metric"""
        data = list(self.series_data[metric_name])
        values = [d['value'] for d in data]
        
        # Simple linear regression for trend
        n = len(values)
        x = list(range(n))
        x_mean = sum(x) / n
        y_mean = sum(values) / n
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator > 0:
            slope = numerator / denominator
            intercept = y_mean - slope * x_mean
        else:
            slope = 0
            intercept = y_mean
        
        # Calculate residuals for seasonality detection
        residuals = [values[i] - (slope * i + intercept) for i in range(n)]
        
        self.trend_models[metric_name] = {
            'slope': slope,
            'intercept': intercept,
            'last_index': n - 1,
            'residual_std': statistics.stdev(residuals) if len(residuals) > 1 else 0
        }
    
    def forecast(self, metric_name: str, steps: int = 10) -> List[Dict[str, float]]:
        """Forecast future values"""
        if metric_name not in self.trend_models:
            return []
        
        model = self.trend_models[metric_name]
        forecasts = []
        
        for i in range(1, steps + 1):
            future_index = model['last_index'] + i
            predicted = model['slope'] * future_index + model['intercept']
            
            # Add confidence interval
            confidence = model['residual_std'] * 1.96  # 95% CI
            
            forecasts.append({
                'step': i,
                'predicted': predicted,
                'lower_bound': predicted - confidence,
                'upper_bound': predicted + confidence
            })
        
        return forecasts
    
    def get_trend_direction(self, metric_name: str) -> str:
        """Get trend direction for a metric"""
        if metric_name not in self.trend_models:
            return 'unknown'
        
        slope = self.trend_models[metric_name]['slope']
        
        if slope > 0.01:
            return 'increasing'
        elif slope < -0.01:
            return 'decreasing'
        return 'stable'


class CorrelationAnalyzer:
    """Analyze correlations between attack parameters and outcomes"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.observations: List[Dict[str, float]] = []
        self.correlation_matrix: Dict[str, Dict[str, float]] = {}
        self.max_observations = 1000
    
    def add_observation(self, parameters: Dict[str, float], outcomes: Dict[str, float]):
        """Add observation for correlation analysis"""
        observation = {**parameters, **outcomes}
        self.observations.append(observation)
        
        if len(self.observations) > self.max_observations:
            self.observations = self.observations[-self.max_observations:]
        
        # Update correlations periodically
        if len(self.observations) % 50 == 0:
            self._update_correlations()
    
    def _update_correlations(self):
        """Update correlation matrix"""
        if len(self.observations) < 30:
            return
        
        # Get all keys
        all_keys = set()
        for obs in self.observations:
            all_keys.update(obs.keys())
        
        all_keys = list(all_keys)
        
        # Calculate correlations
        for key1 in all_keys:
            if key1 not in self.correlation_matrix:
                self.correlation_matrix[key1] = {}
            
            for key2 in all_keys:
                if key1 == key2:
                    self.correlation_matrix[key1][key2] = 1.0
                    continue
                
                # Get paired values
                pairs = [(obs.get(key1, 0), obs.get(key2, 0)) 
                        for obs in self.observations 
                        if key1 in obs and key2 in obs]
                
                if len(pairs) < 10:
                    continue
                
                x_vals = [p[0] for p in pairs]
                y_vals = [p[1] for p in pairs]
                
                # Calculate Pearson correlation
                corr = self._pearson_correlation(x_vals, y_vals)
                self.correlation_matrix[key1][key2] = corr
    
    def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient"""
        n = len(x)
        if n < 2:
            return 0.0
        
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        
        x_std = (sum((xi - x_mean) ** 2 for xi in x) / n) ** 0.5
        y_std = (sum((yi - y_mean) ** 2 for yi in y) / n) ** 0.5
        
        if x_std == 0 or y_std == 0:
            return 0.0
        
        return numerator / (n * x_std * y_std)
    
    def get_strongest_correlations(self, target: str, top_n: int = 5) -> List[Tuple[str, float]]:
        """Get strongest correlations with a target variable"""
        if target not in self.correlation_matrix:
            return []
        
        correlations = [
            (key, abs(corr)) 
            for key, corr in self.correlation_matrix[target].items()
            if key != target
        ]
        
        correlations.sort(key=lambda x: x[1], reverse=True)
        return correlations[:top_n]
    
    def get_parameter_impact(self, parameter: str, outcome: str) -> Dict[str, Any]:
        """Get impact analysis of a parameter on an outcome"""
        if parameter not in self.correlation_matrix:
            return {'impact': 'unknown', 'correlation': 0}
        
        corr = self.correlation_matrix.get(parameter, {}).get(outcome, 0)
        
        if abs(corr) > 0.7:
            impact = 'strong'
        elif abs(corr) > 0.4:
            impact = 'moderate'
        elif abs(corr) > 0.2:
            impact = 'weak'
        else:
            impact = 'negligible'
        
        return {
            'impact': impact,
            'correlation': corr,
            'direction': 'positive' if corr > 0 else 'negative'
        }


class AdaptiveThresholdManager:
    """Manage adaptive thresholds for anomaly detection"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.thresholds: Dict[str, Dict[str, float]] = {}
        self.threshold_history: Dict[str, List[float]] = defaultdict(list)
        self.adaptation_rate = 0.05
    
    def update_threshold(self, metric_name: str, current_value: float, 
                        is_anomaly: bool = False):
        """Update threshold based on observed values"""
        if metric_name not in self.thresholds:
            self.thresholds[metric_name] = {
                'upper': current_value * 1.5,
                'lower': current_value * 0.5,
                'mean': current_value,
                'std': current_value * 0.1
            }
            return
        
        thresh = self.thresholds[metric_name]
        
        # Update mean with exponential moving average
        thresh['mean'] = (1 - self.adaptation_rate) * thresh['mean'] + \
                        self.adaptation_rate * current_value
        
        # Update std
        deviation = abs(current_value - thresh['mean'])
        thresh['std'] = (1 - self.adaptation_rate) * thresh['std'] + \
                       self.adaptation_rate * deviation
        
        # Update bounds
        thresh['upper'] = thresh['mean'] + 3 * thresh['std']
        thresh['lower'] = max(0, thresh['mean'] - 3 * thresh['std'])
        
        # If this was flagged as anomaly but value is becoming common, widen bounds
        if is_anomaly and deviation < thresh['std'] * 2:
            thresh['upper'] *= 1.1
            thresh['lower'] *= 0.9
        
        self.threshold_history[metric_name].append(thresh['upper'])
        if len(self.threshold_history[metric_name]) > 100:
            self.threshold_history[metric_name] = self.threshold_history[metric_name][-100:]
    
    def is_anomalous(self, metric_name: str, value: float) -> Tuple[bool, str]:
        """Check if value is anomalous"""
        if metric_name not in self.thresholds:
            return False, 'no_baseline'
        
        thresh = self.thresholds[metric_name]
        
        if value > thresh['upper']:
            return True, 'above_threshold'
        elif value < thresh['lower']:
            return True, 'below_threshold'
        
        return False, 'normal'
    
    def get_threshold_info(self, metric_name: str) -> Dict[str, Any]:
        """Get threshold information for a metric"""
        if metric_name not in self.thresholds:
            return {}
        
        return {
            **self.thresholds[metric_name],
            'history_length': len(self.threshold_history.get(metric_name, []))
        }


class EnhancedPredictiveAnalyticsSystem(PredictiveAnalyticsSystem):
    """
    Enhanced predictive analytics with advanced ML-like capabilities.
    
    Features:
    - Time series forecasting
    - Correlation analysis
    - Adaptive thresholds
    - Multi-model ensemble predictions
    """
    
    def __init__(self):
        super().__init__()
        
        # Enhanced components
        self.time_series_forecaster = TimeSeriesForecaster()
        self.correlation_analyzer = CorrelationAnalyzer()
        self.threshold_manager = AdaptiveThresholdManager()
        
        # Ensemble prediction weights
        self.ensemble_weights = {
            'random_forest': 0.4,
            'trend': 0.3,
            'correlation': 0.3
        }
        
        self.logger.info("Enhanced Predictive Analytics System initialized")
    
    def add_metrics(self, metrics: Dict[str, float], config: Dict[str, Any] = None):
        """Enhanced metrics addition with time series and correlation tracking"""
        # Call parent method
        super().add_metrics(metrics, config)
        
        # Add to time series
        timestamp = time.time()
        for metric_name, value in metrics.items():
            self.time_series_forecaster.add_observation(metric_name, value, timestamp)
            
            # Update adaptive thresholds
            is_anomaly, _ = self.threshold_manager.is_anomalous(metric_name, value)
            self.threshold_manager.update_threshold(metric_name, value, is_anomaly)
        
        # Add to correlation analyzer
        if config:
            self.correlation_analyzer.add_observation(config, metrics)
    
    def get_ensemble_prediction(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Get ensemble prediction combining multiple methods"""
        predictions = {}
        
        # Random Forest prediction
        rf_prediction = self.performance_predictor.predict_performance(features)
        predictions['random_forest'] = {
            'pps': rf_prediction.predicted_pps,
            'bandwidth': rf_prediction.predicted_bandwidth,
            'success_rate': rf_prediction.predicted_success_rate
        }
        
        # Trend-based prediction
        pps_forecast = self.time_series_forecaster.forecast('pps', steps=1)
        if pps_forecast:
            predictions['trend'] = {
                'pps': pps_forecast[0]['predicted'],
                'bandwidth': predictions['random_forest']['bandwidth'],  # Fallback
                'success_rate': predictions['random_forest']['success_rate']
            }
        else:
            predictions['trend'] = predictions['random_forest']
        
        # Correlation-based adjustment
        pps_correlations = self.correlation_analyzer.get_strongest_correlations('pps', top_n=3)
        correlation_adjustment = 1.0
        for param, corr in pps_correlations:
            if param in features:
                correlation_adjustment += corr * 0.1
        
        predictions['correlation'] = {
            'pps': predictions['random_forest']['pps'] * correlation_adjustment,
            'bandwidth': predictions['random_forest']['bandwidth'],
            'success_rate': predictions['random_forest']['success_rate']
        }
        
        # Ensemble combination
        ensemble = {
            'pps': sum(
                predictions[method]['pps'] * weight 
                for method, weight in self.ensemble_weights.items()
            ),
            'bandwidth': sum(
                predictions[method]['bandwidth'] * weight 
                for method, weight in self.ensemble_weights.items()
            ),
            'success_rate': sum(
                predictions[method]['success_rate'] * weight 
                for method, weight in self.ensemble_weights.items()
            )
        }
        
        return {
            'ensemble': ensemble,
            'individual_predictions': predictions,
            'confidence': rf_prediction.confidence_interval
        }
    
    def get_metric_forecast(self, metric_name: str, steps: int = 10) -> List[Dict[str, float]]:
        """Get forecast for a specific metric"""
        return self.time_series_forecaster.forecast(metric_name, steps)
    
    def get_parameter_correlations(self, outcome: str = 'pps') -> List[Tuple[str, float]]:
        """Get parameter correlations with an outcome"""
        return self.correlation_analyzer.get_strongest_correlations(outcome)
    
    def get_adaptive_thresholds(self) -> Dict[str, Dict[str, Any]]:
        """Get all adaptive thresholds"""
        return {
            metric: self.threshold_manager.get_threshold_info(metric)
            for metric in self.threshold_manager.thresholds.keys()
        }
    
    def get_comprehensive_analysis(self, features: Dict[str, float], 
                                  config: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive analysis combining all capabilities"""
        return {
            'ensemble_prediction': self.get_ensemble_prediction(features),
            'trend_directions': {
                metric: self.time_series_forecaster.get_trend_direction(metric)
                for metric in ['pps', 'bandwidth_utilization', 'success_rate', 'error_rate']
            },
            'parameter_impacts': {
                param: self.correlation_analyzer.get_parameter_impact(param, 'pps')
                for param in config.keys()
            },
            'anomaly_thresholds': self.get_adaptive_thresholds(),
            'optimization_recommendations': self.get_optimization_recommendations(config, features),
            'recent_anomalies': self.get_recent_anomalies(5)
        }


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create enhanced predictive analytics system
    analytics = EnhancedPredictiveAnalyticsSystem()
    analytics.start()
    
    try:
        # Simulate some metrics
        import random
        
        for i in range(100):
            metrics = {
                'pps': random.uniform(5000, 15000),
                'bandwidth_utilization': random.uniform(0.3, 0.9),
                'success_rate': random.uniform(0.7, 0.95),
                'cpu_usage': random.uniform(0.2, 0.8),
                'memory_usage': random.uniform(0.1, 0.6),
                'response_time': random.uniform(0.01, 0.1),
                'error_rate': random.uniform(0.01, 0.05)
            }
            
            config = {
                'packet_rate': random.randint(1000, 10000),
                'packet_size': random.randint(64, 1500),
                'thread_count': random.randint(1, 8)
            }
            
            analytics.add_metrics(metrics, config)
            time.sleep(0.05)
        
        # Wait for processing
        time.sleep(2)
        
        # Test enhanced predictions
        test_features = {
            'packet_rate': 5000,
            'packet_size': 1024,
            'thread_count': 4,
            'target_response_time': 0.05,
            'cpu_usage': 0.5,
            'memory_usage': 0.3,
            'network_utilization': 0.6
        }
        
        # Get ensemble prediction
        ensemble = analytics.get_ensemble_prediction(test_features)
        print(f"Ensemble Prediction: PPS={ensemble['ensemble']['pps']:.0f}")
        
        # Get comprehensive analysis
        analysis = analytics.get_comprehensive_analysis(test_features, {
            'packet_rate': 5000,
            'packet_size': 1024,
            'thread_count': 4
        })
        print(f"Trend Directions: {analysis['trend_directions']}")
        
    finally:
        analytics.stop()