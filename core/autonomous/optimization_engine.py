"""
Intelligent Parameter Optimization Engine

Implements probabilistic genetic optimization algorithms, dynamic parameter adjustment
based on target responses, and performance prediction modeling.

This uses standard probabilistic and genetic optimization techniques.
"""

import asyncio
import math
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
from collections import deque
import logging

logger = logging.getLogger(__name__)

@dataclass
class OptimizationParameters:
    """Configuration parameters for optimization algorithms"""
    packet_rate: int = 1000
    packet_size: int = 1460
    concurrency: int = 100
    burst_interval: float = 0.001
    protocol_weights: Dict[str, float] = field(default_factory=lambda: {
        'TCP': 0.3, 'UDP': 0.4, 'HTTP': 0.2, 'DNS': 0.1
    })
    evasion_techniques: List[str] = field(default_factory=lambda: [
        'ip_spoofing', 'fragmentation', 'timing_randomization'
    ])

@dataclass
class TargetResponse:
    """Represents target system response metrics"""
    response_time: float
    success_rate: float
    error_rate: float
    bandwidth_utilization: float
    connection_success: float
    timestamp: float = field(default_factory=time.time)

@dataclass
class OptimizationResult:
    """Result of optimization process"""
    parameters: OptimizationParameters
    predicted_effectiveness: float
    confidence_score: float
    optimization_method: str

class GeneticOptimizationEngine:
    """
    Probabilistic genetic optimization engine for attack parameter optimization.
    
    Uses probabilistic sampling and evolutionary techniques to explore 
    parameter space efficiently. This is a standard genetic algorithm 
    with probabilistic state representation.
    """
    
    def __init__(self, population_size: int = 50, max_iterations: int = 100):
        self.population_size = population_size
        self.max_iterations = max_iterations
        self.population = []  # Probabilistic population for genetic algorithm
        self.best_solution = None
        self.convergence_history = deque(maxlen=20)
        self.fitness_history = deque(maxlen=50)
        self.mutation_rate = 0.1  # Initial mutation rate
        self.min_mutation_rate = 0.01
        self.max_mutation_rate = 0.3
        self.convergence_threshold = 0.001
        self.stagnation_counter = 0
        self.diversity_history = deque(maxlen=10)
        
    def initialize_population(self, bounds: Dict[str, Tuple[float, float]]):
        """Initialize population with probabilistic states for genetic optimization"""
        self.population = []
        
        for _ in range(self.population_size):
            individual = {}
            for param, (min_val, max_val) in bounds.items():
                # Probabilistic representation: normalized weights for sampling
                individual[param] = {
                    'alpha': random.uniform(0, 1),  # Weight for lower bound
                    'beta': random.uniform(0, 1),   # Weight for upper bound
                    'min_val': min_val,
                    'max_val': max_val
                }
                # Normalize weights to sum to 1
                norm = math.sqrt(individual[param]['alpha']**2 + individual[param]['beta']**2)
                individual[param]['alpha'] /= norm
                individual[param]['beta'] /= norm
                
            self.population.append(individual)
    
    def sample_parameters(self, individual: Dict) -> OptimizationParameters:
        """Sample concrete parameters from probabilistic state"""
        params = {}
        
        for param, prob_state in individual.items():
            # Probabilistic sampling based on weights
            probability = prob_state['alpha']**2
            if random.random() < probability:
                value = prob_state['min_val']
            else:
                value = prob_state['max_val']
            
            # Add Gaussian noise for exploration
            noise = random.gauss(0, 0.1) * (prob_state['max_val'] - prob_state['min_val'])
            value = max(prob_state['min_val'], 
                       min(prob_state['max_val'], value + noise))
            
            params[param] = value
        
        return OptimizationParameters(
            packet_rate=int(params.get('packet_rate', 1000)),
            packet_size=int(params.get('packet_size', 1460)),
            concurrency=int(params.get('concurrency', 100)),
            burst_interval=params.get('burst_interval', 0.001)
        )
    
    def apply_mutation(self, individual: Dict, fitness: float, best_fitness: float):
        """Apply rotation transformation to adjust probability weights based on fitness with adaptive mutation"""
        # Base rotation angle adjusted by adaptive mutation rate
        base_rotation = 0.01 * math.pi * (best_fitness - fitness) / (best_fitness + 1e-10)
        adaptive_rotation = base_rotation * self.mutation_rate
        
        for param in individual:
            # Rotation transformation with adaptive mutation
            cos_theta = math.cos(adaptive_rotation)
            sin_theta = math.sin(adaptive_rotation)
            
            old_alpha = individual[param]['alpha']
            old_beta = individual[param]['beta']
            
            individual[param]['alpha'] = cos_theta * old_alpha - sin_theta * old_beta
            individual[param]['beta'] = sin_theta * old_alpha + cos_theta * old_beta
            
            # Apply additional random mutation based on adaptive rate
            if random.random() < self.mutation_rate:
                mutation_strength = self.mutation_rate * 0.5
                individual[param]['alpha'] += random.gauss(0, mutation_strength)
                individual[param]['beta'] += random.gauss(0, mutation_strength)
                
                # Renormalize after mutation
                norm = math.sqrt(individual[param]['alpha']**2 + individual[param]['beta']**2)
                if norm > 0:
                    individual[param]['alpha'] /= norm
                    individual[param]['beta'] /= norm
    
    def crossover(self, individual1: Dict, individual2: Dict) -> Tuple[Dict, Dict]:
        """Crossover operation between two individuals (genetic algorithm crossover)"""
        crossed1 = individual1.copy()
        crossed2 = individual2.copy()
        
        # Select random parameters for crossover
        crossover_params = random.sample(list(individual1.keys()), 
                                       k=random.randint(1, len(individual1)))
        
        for param in crossover_params:
            # Swap weights between individuals
            crossed1[param]['alpha'], crossed2[param]['alpha'] = \
                crossed2[param]['alpha'], crossed1[param]['alpha']
    
        return crossed1, crossed2
    
    async def optimize(self, fitness_function, bounds: Dict[str, Tuple[float, float]]) -> OptimizationResult:
        """Main genetic optimization loop"""
        self.initialize_population(bounds)
        best_fitness = float('-inf')
        
        for iteration in range(self.max_iterations):
            fitness_scores = []
            
            # Evaluate population
            for individual in self.population:
                params = self.sample_parameters(individual)
                fitness = await fitness_function(params)
                fitness_scores.append(fitness)
                
                if fitness > best_fitness:
                    best_fitness = fitness
                    self.best_solution = params
            
            # Apply genetic operations (mutation)
            for i, individual in enumerate(self.population):
                self.apply_mutation(individual, fitness_scores[i], best_fitness)
            
            # Crossover between best individuals
            if len(self.population) >= 2:
                best_indices = np.argsort(fitness_scores)[-2:]
                crossed1, crossed2 = self.crossover(
                    self.population[best_indices[0]],
                    self.population[best_indices[1]]
                )
                self.population[best_indices[0]] = crossed1
                self.population[best_indices[1]] = crossed2
            
            self.convergence_history.append(best_fitness)
            self.fitness_history.append(best_fitness)
            
            # Calculate population diversity
            diversity = self._calculate_population_diversity()
            self.diversity_history.append(diversity)
            
            # Adapt mutation rate based on convergence speed and diversity
            self._adapt_mutation_rate(iteration)
            
            # Check convergence
            if len(self.convergence_history) >= 10:
                recent_improvement = (self.convergence_history[-1] - 
                                    self.convergence_history[-10])
                if recent_improvement < self.convergence_threshold:
                    logger.info(f"Genetic optimization converged at iteration {iteration}")
                    break
        
        confidence = self._calculate_confidence()
        
        return OptimizationResult(
            parameters=self.best_solution,
            predicted_effectiveness=best_fitness,
            confidence_score=confidence,
            optimization_method=f"adaptive_genetic_probabilistic_mr{self.mutation_rate:.3f}"
        )
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence score based on convergence stability"""
        if len(self.convergence_history) < 5:
            return 0.5
        
        recent_values = list(self.convergence_history)[-5:]
        variance = np.var(recent_values)
        mean_value = np.mean(recent_values)
        
        # Lower variance relative to mean indicates higher confidence
        confidence = 1.0 / (1.0 + variance / (mean_value + 1e-10))
        return min(1.0, max(0.0, confidence))
    
    def _calculate_population_diversity(self) -> float:
        """Calculate population diversity to guide mutation rate adaptation"""
        if len(self.population) < 2:
            return 1.0
        
        total_diversity = 0.0
        comparisons = 0
        
        # Compare all pairs of individuals
        for i in range(len(self.population)):
            for j in range(i + 1, len(self.population)):
                individual1 = self.population[i]
                individual2 = self.population[j]
                
                # Calculate parameter-wise diversity
                param_diversity = 0.0
                for param in individual1:
                    # Euclidean distance between probability vectors
                    alpha_diff = individual1[param]['alpha'] - individual2[param]['alpha']
                    beta_diff = individual1[param]['beta'] - individual2[param]['beta']
                    param_diversity += math.sqrt(alpha_diff**2 + beta_diff**2)
                
                total_diversity += param_diversity / len(individual1)
                comparisons += 1
        
        return total_diversity / comparisons if comparisons > 0 else 1.0
    
    def _adapt_mutation_rate(self, iteration: int):
        """Adapt mutation rate based on convergence speed and population diversity"""
        # Calculate convergence speed
        convergence_speed = self._calculate_convergence_speed()
        
        # Get current diversity
        current_diversity = self.diversity_history[-1] if self.diversity_history else 1.0
        
        # Calculate average diversity over recent iterations
        avg_diversity = np.mean(list(self.diversity_history)) if len(self.diversity_history) > 3 else current_diversity
        
        # Adaptation strategy
        if convergence_speed < 0.001 and current_diversity < 0.1:
            # Stagnation detected - increase mutation rate for exploration
            self.stagnation_counter += 1
            if self.stagnation_counter > 3:
                self.mutation_rate = min(self.max_mutation_rate, self.mutation_rate * 1.5)
                self.stagnation_counter = 0
                logger.debug(f"Increased mutation rate to {self.mutation_rate:.4f} due to stagnation")
        
        elif convergence_speed > 0.01:
            # Fast convergence - reduce mutation rate for exploitation
            self.mutation_rate = max(self.min_mutation_rate, self.mutation_rate * 0.9)
            self.stagnation_counter = 0
            logger.debug(f"Decreased mutation rate to {self.mutation_rate:.4f} due to fast convergence")
        
        elif current_diversity < avg_diversity * 0.5:
            # Diversity loss - increase mutation rate
            self.mutation_rate = min(self.max_mutation_rate, self.mutation_rate * 1.2)
            logger.debug(f"Increased mutation rate to {self.mutation_rate:.4f} due to diversity loss")
        
        elif current_diversity > avg_diversity * 1.5:
            # High diversity - can reduce mutation rate slightly
            self.mutation_rate = max(self.min_mutation_rate, self.mutation_rate * 0.95)
            logger.debug(f"Decreased mutation rate to {self.mutation_rate:.4f} due to high diversity")
        
        # Adaptive schedule based on iteration progress
        progress = iteration / self.max_iterations
        if progress > 0.8:  # Late in optimization - reduce mutation for fine-tuning
            schedule_factor = 0.5 + 0.5 * (1.0 - progress)
            self.mutation_rate *= schedule_factor
            self.mutation_rate = max(self.min_mutation_rate, self.mutation_rate)
    
    def _calculate_convergence_speed(self) -> float:
        """Calculate the speed of convergence based on recent fitness improvements"""
        if len(self.fitness_history) < 5:
            return 0.0
        
        recent_fitness = list(self.fitness_history)[-5:]
        
        # Calculate linear regression slope as convergence speed
        x = np.arange(len(recent_fitness))
        y = np.array(recent_fitness)
        
        if len(x) < 2:
            return 0.0
        
        # Simple linear regression
        n = len(x)
        sum_x = np.sum(x)
        sum_y = np.sum(y)
        sum_xy = np.sum(x * y)
        sum_x2 = np.sum(x * x)
        
        denominator = n * sum_x2 - sum_x * sum_x
        if abs(denominator) < 1e-10:
            return 0.0
        
        slope = (n * sum_xy - sum_x * sum_y) / denominator
        return max(0.0, slope)  # Only positive slopes indicate improvement

class ParameterOptimizer:
    """
    Dynamic parameter optimizer that adjusts attack parameters based on
    target responses and performance feedback.
    """
    
    def __init__(self, learning_rate: float = 0.1, momentum: float = 0.9):
        self.learning_rate = learning_rate
        self.momentum = momentum
        self.parameter_history = deque(maxlen=100)
        self.response_history = deque(maxlen=100)
        self.gradient_momentum = {}
        self.genetic_engine = GeneticOptimizationEngine()
        
    async def optimize_parameters(self, 
                                current_params: OptimizationParameters,
                                target_response: TargetResponse,
                                performance_metrics: Dict[str, float]) -> OptimizationParameters:
        """
        Optimize parameters based on target response and performance metrics
        """
        # Record current state
        self.parameter_history.append(current_params)
        self.response_history.append(target_response)
        
        # Calculate effectiveness score
        effectiveness = self._calculate_effectiveness(target_response, performance_metrics)
        
        # Use different optimization strategies based on performance
        if effectiveness < 0.3:
            # Poor performance - use genetic optimization for exploration
            return await self._genetic_optimization(current_params, effectiveness)
        elif effectiveness < 0.7:
            # Moderate performance - use gradient-based optimization
            return self._gradient_optimization(current_params, target_response)
        else:
            # Good performance - fine-tune with small adjustments
            return self._fine_tune_optimization(current_params, target_response)
    
    def _calculate_effectiveness(self, 
                               response: TargetResponse, 
                               metrics: Dict[str, float]) -> float:
        """Calculate overall attack effectiveness score using multi-objective optimization"""
        return self._calculate_multi_objective_fitness(response, metrics)
    
    def _calculate_multi_objective_fitness(self,
                                         response: TargetResponse,
                                         metrics: Dict[str, float]) -> float:
        """
        Multi-objective fitness function considering:
        1. Attack effectiveness (success rate, bandwidth utilization)
        2. Resource efficiency (CPU usage, memory consumption)
        3. Stealth (error rate, detection avoidance)
        4. Sustainability (connection stability, rate consistency)
        """
        # Objective 1: Attack Effectiveness
        effectiveness_score = self._calculate_effectiveness_objective(response, metrics)
        
        # Objective 2: Resource Efficiency
        efficiency_score = self._calculate_efficiency_objective(response, metrics)
        
        # Objective 3: Stealth
        stealth_score = self._calculate_stealth_objective(response, metrics)
        
        # Objective 4: Sustainability
        sustainability_score = self._calculate_sustainability_objective(response, metrics)
        
        # Weighted combination with adaptive weights based on context
        weights = self._get_adaptive_weights(response, metrics)
        
        total_fitness = (
            weights['effectiveness'] * effectiveness_score +
            weights['efficiency'] * efficiency_score +
            weights['stealth'] * stealth_score +
            weights['sustainability'] * sustainability_score
        )
        
        return max(0.0, min(1.0, total_fitness))
    
    def _calculate_effectiveness_objective(self, 
                                         response: TargetResponse,
                                         metrics: Dict[str, float]) -> float:
        """Calculate attack effectiveness objective"""
        # Primary effectiveness metrics
        success_component = response.success_rate * 0.4
        bandwidth_component = response.bandwidth_utilization * 0.3
        throughput_component = min(1.0, metrics.get('pps', 0) / 50000) * 0.2
        connection_component = response.connection_success * 0.1
        
        return success_component + bandwidth_component + throughput_component + connection_component
    
    def _calculate_efficiency_objective(self,
                                      response: TargetResponse,
                                      metrics: Dict[str, float]) -> float:
        """Calculate resource efficiency objective"""
        # Resource utilization metrics (lower is better for efficiency)
        cpu_efficiency = 1.0 - min(1.0, metrics.get('cpu_usage', 0.5))
        memory_efficiency = 1.0 - min(1.0, metrics.get('memory_usage', 0.5))
        network_efficiency = response.bandwidth_utilization / max(0.01, metrics.get('network_overhead', 1.0))
        
        # Packets per resource unit (higher is better)
        pps_per_cpu = metrics.get('pps', 0) / max(1.0, metrics.get('cpu_usage', 1.0) * 100)
        resource_ratio = min(1.0, pps_per_cpu / 1000)  # Normalize to reasonable range
        
        return (cpu_efficiency * 0.3 + memory_efficiency * 0.2 + 
                network_efficiency * 0.3 + resource_ratio * 0.2)
    
    def _calculate_stealth_objective(self,
                                   response: TargetResponse,
                                   metrics: Dict[str, float]) -> float:
        """Calculate stealth/evasion objective"""
        # Lower error rates indicate better stealth
        error_penalty = response.error_rate
        
        # Consistent timing reduces detection
        timing_consistency = 1.0 - metrics.get('timing_variance', 0.5)
        
        # Pattern randomization score
        pattern_randomness = metrics.get('pattern_entropy', 0.5)
        
        # Detection avoidance score (based on response patterns)
        detection_avoidance = self._calculate_detection_avoidance(response, metrics)
        
        return ((1.0 - error_penalty) * 0.3 + timing_consistency * 0.25 + 
                pattern_randomness * 0.25 + detection_avoidance * 0.2)
    
    def _calculate_sustainability_objective(self,
                                          response: TargetResponse,
                                          metrics: Dict[str, float]) -> float:
        """Calculate attack sustainability objective"""
        # Connection stability over time
        connection_stability = response.connection_success
        
        # Rate consistency (ability to maintain target rate)
        rate_consistency = 1.0 - metrics.get('rate_variance', 0.3)
        
        # Long-term effectiveness (doesn't degrade over time)
        effectiveness_stability = metrics.get('effectiveness_trend', 0.5)
        
        # Resource sustainability (not exhausting system resources)
        resource_sustainability = 1.0 - metrics.get('resource_exhaustion_risk', 0.2)
        
        return (connection_stability * 0.3 + rate_consistency * 0.3 + 
                effectiveness_stability * 0.2 + resource_sustainability * 0.2)
    
    def _calculate_detection_avoidance(self,
                                     response: TargetResponse,
                                     metrics: Dict[str, float]) -> float:
        """Calculate detection avoidance score based on response patterns"""
        # Analyze response time patterns for signs of rate limiting
        response_time_score = 1.0
        if response.response_time > 5.0:  # Unusually high response time
            response_time_score = 0.3
        elif response.response_time > 2.0:
            response_time_score = 0.7
        
        # Check for signs of connection throttling
        connection_score = response.connection_success
        if connection_score < 0.5:  # Many connections failing
            connection_score *= 0.5  # Penalty for potential detection
        
        # Pattern detection avoidance
        pattern_score = metrics.get('pattern_diversity', 0.8)
        
        return (response_time_score * 0.4 + connection_score * 0.4 + pattern_score * 0.2)
    
    def _get_adaptive_weights(self,
                            response: TargetResponse,
                            metrics: Dict[str, float]) -> Dict[str, float]:
        """Get adaptive weights based on current attack context"""
        # Default balanced weights
        weights = {
            'effectiveness': 0.4,
            'efficiency': 0.2,
            'stealth': 0.2,
            'sustainability': 0.2
        }
        
        # Adapt weights based on current performance
        if response.error_rate > 0.3:  # High error rate - prioritize stealth
            weights['stealth'] = 0.35
            weights['effectiveness'] = 0.3
            weights['efficiency'] = 0.175
            weights['sustainability'] = 0.175
        elif metrics.get('cpu_usage', 0.5) > 0.8:  # High resource usage - prioritize efficiency
            weights['efficiency'] = 0.35
            weights['effectiveness'] = 0.3
            weights['stealth'] = 0.175
            weights['sustainability'] = 0.175
        elif response.success_rate < 0.3:  # Low success rate - prioritize effectiveness
            weights['effectiveness'] = 0.5
            weights['efficiency'] = 0.15
            weights['stealth'] = 0.2
            weights['sustainability'] = 0.15
        elif len(self.response_history) > 10:  # Long-running attack - prioritize sustainability
            recent_trend = self._calculate_trend([r.success_rate for r in list(self.response_history)[-5:]])
            if recent_trend == "declining":
                weights['sustainability'] = 0.35
                weights['effectiveness'] = 0.3
                weights['efficiency'] = 0.175
                weights['stealth'] = 0.175
        
        return weights
    
    async def _genetic_optimization(self, 
                                  current_params: OptimizationParameters,
                                  effectiveness: float) -> OptimizationParameters:
        """Use genetic optimization for parameter exploration"""
        bounds = {
            'packet_rate': (100, 100000),
            'packet_size': (64, 1500),
            'concurrency': (10, 1000),
            'burst_interval': (0.0001, 0.1)
        }
        
        async def fitness_function(params: OptimizationParameters) -> float:
            # Multi-objective fitness evaluation for parameter combination
            # Simulate metrics based on parameters
            simulated_metrics = self._simulate_metrics_from_params(params)
            simulated_response = self._simulate_response_from_params(params)
            
            # Use multi-objective fitness calculation
            fitness = self._calculate_multi_objective_fitness(simulated_response, simulated_metrics)
            
            # Add small amount of noise to prevent premature convergence
            return fitness + random.uniform(-0.02, 0.02)
        
        result = await self.genetic_engine.optimize(fitness_function, bounds)
        return result.parameters
    
    def _simulate_metrics_from_params(self, params: OptimizationParameters) -> Dict[str, float]:
        """Simulate performance metrics based on parameters for fitness evaluation"""
        # Simulate CPU usage based on packet rate and concurrency
        cpu_usage = min(1.0, (params.packet_rate * params.concurrency) / 1000000)
        
        # Simulate memory usage based on concurrency and packet size
        memory_usage = min(1.0, (params.concurrency * params.packet_size) / 10000000)
        
        # Simulate network overhead based on packet size efficiency
        optimal_size = 1460  # MTU-optimal
        size_efficiency = 1.0 - abs(params.packet_size - optimal_size) / optimal_size
        network_overhead = 1.0 - size_efficiency
        
        # Simulate timing variance based on burst interval
        timing_variance = min(0.5, params.burst_interval * 100)
        
        # Simulate rate variance based on system load
        rate_variance = cpu_usage * 0.3
        
        # Simulate pattern entropy (higher concurrency = more randomness)
        pattern_entropy = min(1.0, params.concurrency / 500)
        
        return {
            'pps': params.packet_rate,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'network_overhead': network_overhead,
            'timing_variance': timing_variance,
            'rate_variance': rate_variance,
            'pattern_entropy': pattern_entropy,
            'pattern_diversity': pattern_entropy,
            'effectiveness_trend': 0.7,  # Assume stable
            'resource_exhaustion_risk': max(cpu_usage, memory_usage) * 0.5
        }
    
    def _simulate_response_from_params(self, params: OptimizationParameters) -> TargetResponse:
        """Simulate target response based on parameters for fitness evaluation"""
        # Simulate success rate based on parameter balance
        rate_factor = 1.0 if params.packet_rate <= 10000 else 0.8
        size_factor = 1.0 if 500 <= params.packet_size <= 1400 else 0.9
        concurrency_factor = 1.0 if params.concurrency <= 200 else 0.85
        
        success_rate = rate_factor * size_factor * concurrency_factor
        success_rate = max(0.1, min(1.0, success_rate + random.uniform(-0.1, 0.1)))
        
        # Simulate response time based on load
        base_response_time = 0.1
        load_factor = (params.packet_rate * params.concurrency) / 100000
        response_time = base_response_time * (1 + load_factor)
        
        # Simulate bandwidth utilization
        bandwidth_utilization = min(1.0, (params.packet_rate * params.packet_size) / 10000000)
        
        # Simulate error rate (inversely related to success rate)
        error_rate = max(0.0, 1.0 - success_rate - 0.3)
        
        # Simulate connection success
        connection_success = success_rate * 0.9 + 0.1
        
        return TargetResponse(
            response_time=response_time,
            success_rate=success_rate,
            error_rate=error_rate,
            bandwidth_utilization=bandwidth_utilization,
            connection_success=connection_success
        )
    
    def _gradient_optimization(self, 
                             current_params: OptimizationParameters,
                             response: TargetResponse) -> OptimizationParameters:
        """Use gradient-based optimization for parameter adjustment"""
        if len(self.response_history) < 2:
            return current_params
        
        # Calculate gradients based on recent history
        prev_response = self.response_history[-2]
        prev_params = self.parameter_history[-2]
        
        # Compute parameter gradients
        gradients = {}
        
        # Packet rate gradient
        if prev_params.packet_rate != current_params.packet_rate:
            rate_gradient = ((response.success_rate - prev_response.success_rate) / 
                           (current_params.packet_rate - prev_params.packet_rate + 1e-10))
            gradients['packet_rate'] = rate_gradient
        
        # Packet size gradient  
        if prev_params.packet_size != current_params.packet_size:
            size_gradient = ((response.bandwidth_utilization - prev_response.bandwidth_utilization) /
                           (current_params.packet_size - prev_params.packet_size + 1e-10))
            gradients['packet_size'] = size_gradient
        
        # Apply momentum and update parameters
        new_packet_rate = current_params.packet_rate
        new_packet_size = current_params.packet_size
        
        if 'packet_rate' in gradients:
            momentum_rate = self.gradient_momentum.get('packet_rate', 0)
            momentum_rate = self.momentum * momentum_rate + self.learning_rate * gradients['packet_rate']
            self.gradient_momentum['packet_rate'] = momentum_rate
            new_packet_rate = max(100, min(100000, 
                                         current_params.packet_rate + int(momentum_rate * 1000)))
        
        if 'packet_size' in gradients:
            momentum_size = self.gradient_momentum.get('packet_size', 0)
            momentum_size = self.momentum * momentum_size + self.learning_rate * gradients['packet_size']
            self.gradient_momentum['packet_size'] = momentum_size
            new_packet_size = max(64, min(1500,
                                        current_params.packet_size + int(momentum_size * 100)))
        
        return OptimizationParameters(
            packet_rate=new_packet_rate,
            packet_size=new_packet_size,
            concurrency=current_params.concurrency,
            burst_interval=current_params.burst_interval,
            protocol_weights=current_params.protocol_weights,
            evasion_techniques=current_params.evasion_techniques
        )
    
    def _fine_tune_optimization(self, 
                              current_params: OptimizationParameters,
                              response: TargetResponse) -> OptimizationParameters:
        """Fine-tune parameters when performance is already good"""
        # Small random adjustments to maintain effectiveness
        adjustment_factor = 0.05
        
        rate_adjustment = int(current_params.packet_rate * 
                            random.uniform(-adjustment_factor, adjustment_factor))
        size_adjustment = int(current_params.packet_size * 
                            random.uniform(-adjustment_factor, adjustment_factor))
        
        new_packet_rate = max(100, min(100000, current_params.packet_rate + rate_adjustment))
        new_packet_size = max(64, min(1500, current_params.packet_size + size_adjustment))
        
        return OptimizationParameters(
            packet_rate=new_packet_rate,
            packet_size=new_packet_size,
            concurrency=current_params.concurrency,
            burst_interval=current_params.burst_interval,
            protocol_weights=current_params.protocol_weights,
            evasion_techniques=current_params.evasion_techniques
        )
    
    def get_optimization_insights(self) -> Dict[str, Any]:
        """Get insights about the optimization process"""
        if len(self.response_history) < 2:
            return {"status": "insufficient_data"}
        
        recent_responses = list(self.response_history)[-10:]
        
        return {
            "status": "active",
            "avg_success_rate": np.mean([r.success_rate for r in recent_responses]),
            "avg_response_time": np.mean([r.response_time for r in recent_responses]),
            "trend_success_rate": self._calculate_trend([r.success_rate for r in recent_responses]),
            "optimization_stability": self._calculate_stability(),
            "recommended_action": self._get_recommendation()
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a series of values"""
        if len(values) < 3:
            return "unknown"
        
        recent_avg = np.mean(values[-3:])
        earlier_avg = np.mean(values[:-3])
        
        if recent_avg > earlier_avg * 1.05:
            return "improving"
        elif recent_avg < earlier_avg * 0.95:
            return "declining"
        else:
            return "stable"
    
    def _calculate_stability(self) -> float:
        """Calculate optimization stability score"""
        if len(self.response_history) < 5:
            return 0.5
        
        recent_success_rates = [r.success_rate for r in list(self.response_history)[-10:]]
        variance = np.var(recent_success_rates)
        
        # Lower variance indicates higher stability
        stability = 1.0 / (1.0 + variance * 10)
        return min(1.0, max(0.0, stability))
    
    def _get_recommendation(self) -> str:
        """Get optimization recommendation based on current state"""
        if len(self.response_history) < 3:
            return "continue_monitoring"
        
        recent_effectiveness = [self._calculate_effectiveness(r, {}) 
                              for r in list(self.response_history)[-3:]]
        avg_effectiveness = np.mean(recent_effectiveness)
        
        if avg_effectiveness < 0.3:
            return "major_parameter_adjustment_needed"
        elif avg_effectiveness < 0.6:
            return "moderate_optimization_required"
        elif avg_effectiveness < 0.8:
            return "fine_tuning_recommended"
        else:
            return "maintain_current_parameters"