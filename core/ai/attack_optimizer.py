"""
Machine Learning Attack Optimizer

AI-driven attack optimization using reinforcement learning and genetic algorithms.
Automatically discovers optimal attack parameters for maximum effectiveness.
"""

import random
import math
import time
import logging
import asyncio
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod
import hashlib

logger = logging.getLogger(__name__)


class OptimizationGoal(Enum):
    """Optimization objectives"""
    MAX_THROUGHPUT = auto()      # Maximize packets/second
    MAX_IMPACT = auto()          # Maximize target degradation
    MIN_DETECTION = auto()       # Minimize detection probability
    BALANCED = auto()            # Balance all factors
    RESOURCE_EFFICIENT = auto()  # Minimize resource usage


@dataclass
class AttackParameters:
    """Parameters that can be optimized"""
    packet_size: int = 1472
    rate_pps: int = 100000
    thread_count: int = 4
    burst_size: int = 100
    burst_interval_ms: int = 10
    jitter_percent: float = 0.1
    protocol_mix: Dict[str, float] = field(default_factory=lambda: {'udp': 1.0})
    timing_pattern: str = 'constant'
    evasion_level: int = 0
    
    def to_vector(self) -> List[float]:
        """Convert to numeric vector for ML"""
        return [
            self.packet_size / 65535,
            self.rate_pps / 10000000,
            self.thread_count / 64,
            self.burst_size / 1000,
            self.burst_interval_ms / 1000,
            self.jitter_percent,
            self.evasion_level / 10,
        ]
    
    @classmethod
    def from_vector(cls, vector: List[float]) -> 'AttackParameters':
        """Create from numeric vector"""
        return cls(
            packet_size=int(vector[0] * 65535),
            rate_pps=int(vector[1] * 10000000),
            thread_count=max(1, int(vector[2] * 64)),
            burst_size=max(1, int(vector[3] * 1000)),
            burst_interval_ms=max(1, int(vector[4] * 1000)),
            jitter_percent=max(0, min(1, vector[5])),
            evasion_level=int(vector[6] * 10),
        )
    
    def mutate(self, mutation_rate: float = 0.1) -> 'AttackParameters':
        """Create mutated copy"""
        vector = self.to_vector()
        for i in range(len(vector)):
            if random.random() < mutation_rate:
                vector[i] += random.gauss(0, 0.1)
                vector[i] = max(0, min(1, vector[i]))
        return AttackParameters.from_vector(vector)
    
    def crossover(self, other: 'AttackParameters') -> 'AttackParameters':
        """Crossover with another parameter set"""
        v1 = self.to_vector()
        v2 = other.to_vector()
        child = []
        for i in range(len(v1)):
            if random.random() < 0.5:
                child.append(v1[i])
            else:
                child.append(v2[i])
        return AttackParameters.from_vector(child)


@dataclass
class AttackResult:
    """Result of an attack attempt"""
    parameters: AttackParameters
    throughput_pps: float
    bandwidth_mbps: float
    target_response_time_ms: float
    target_error_rate: float
    detection_score: float  # 0-1, higher = more likely detected
    resource_usage: float   # 0-1, CPU/memory usage
    duration_secs: float
    
    @property
    def fitness(self) -> float:
        """Calculate fitness score"""
        # Weighted combination of metrics
        throughput_score = min(1.0, self.throughput_pps / 1000000)
        impact_score = min(1.0, self.target_response_time_ms / 1000) * (1 + self.target_error_rate)
        stealth_score = 1.0 - self.detection_score
        efficiency_score = 1.0 - self.resource_usage
        
        return (
            0.3 * throughput_score +
            0.3 * impact_score +
            0.2 * stealth_score +
            0.2 * efficiency_score
        )


class Individual:
    """Individual in genetic algorithm population"""
    
    def __init__(self, params: AttackParameters, fitness: float = 0.0):
        self.params = params
        self.fitness = fitness
        self.age = 0
    
    def __lt__(self, other):
        return self.fitness < other.fitness


class GeneticOptimizer:
    """Genetic algorithm for attack optimization"""
    
    def __init__(
        self,
        population_size: int = 50,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.7,
        elite_count: int = 5,
        tournament_size: int = 3
    ):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elite_count = elite_count
        self.tournament_size = tournament_size
        self.population: List[Individual] = []
        self.generation = 0
        self.best_ever: Optional[Individual] = None
        self.history: List[Dict[str, Any]] = []
    
    def initialize_population(self, seed_params: Optional[AttackParameters] = None):
        """Initialize population with random or seeded individuals"""
        self.population = []
        
        # Add seed if provided
        if seed_params:
            self.population.append(Individual(seed_params))
        
        # Fill rest with random individuals
        while len(self.population) < self.population_size:
            params = AttackParameters(
                packet_size=random.randint(64, 65535),
                rate_pps=random.randint(1000, 10000000),
                thread_count=random.randint(1, 64),
                burst_size=random.randint(1, 1000),
                burst_interval_ms=random.randint(1, 1000),
                jitter_percent=random.random(),
                evasion_level=random.randint(0, 10),
            )
            self.population.append(Individual(params))
    
    def evaluate_population(self, fitness_func: Callable[[AttackParameters], float]):
        """Evaluate fitness of all individuals"""
        for individual in self.population:
            individual.fitness = fitness_func(individual.params)
            individual.age += 1
        
        # Update best ever
        best = max(self.population, key=lambda x: x.fitness)
        if self.best_ever is None or best.fitness > self.best_ever.fitness:
            self.best_ever = Individual(best.params, best.fitness)
    
    def select_parent(self) -> Individual:
        """Tournament selection"""
        tournament = random.sample(self.population, self.tournament_size)
        return max(tournament, key=lambda x: x.fitness)
    
    def evolve(self) -> List[Individual]:
        """Create next generation"""
        # Sort by fitness
        self.population.sort(reverse=True, key=lambda x: x.fitness)
        
        new_population = []
        
        # Elitism - keep best individuals
        for i in range(self.elite_count):
            new_population.append(Individual(self.population[i].params, self.population[i].fitness))
        
        # Create offspring
        while len(new_population) < self.population_size:
            parent1 = self.select_parent()
            
            if random.random() < self.crossover_rate:
                parent2 = self.select_parent()
                child_params = parent1.params.crossover(parent2.params)
            else:
                child_params = parent1.params
            
            # Mutation
            if random.random() < self.mutation_rate:
                child_params = child_params.mutate(self.mutation_rate)
            
            new_population.append(Individual(child_params))
        
        self.population = new_population
        self.generation += 1
        
        # Record history
        self.history.append({
            'generation': self.generation,
            'best_fitness': self.population[0].fitness,
            'avg_fitness': sum(i.fitness for i in self.population) / len(self.population),
            'best_params': self.population[0].params,
        })
        
        return self.population
    
    def get_best(self) -> Individual:
        """Get best individual"""
        return max(self.population, key=lambda x: x.fitness)


class ReinforcementLearner:
    """Q-Learning based attack optimizer"""
    
    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        exploration_rate: float = 0.3,
        exploration_decay: float = 0.995
    ):
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.exploration_decay = exploration_decay
        self.q_table: Dict[str, Dict[str, float]] = {}
        self.episode = 0
    
    def _state_key(self, params: AttackParameters) -> str:
        """Convert parameters to state key"""
        # Discretize parameters
        size_bucket = params.packet_size // 1000
        rate_bucket = params.rate_pps // 100000
        thread_bucket = params.thread_count // 4
        return f"{size_bucket}_{rate_bucket}_{thread_bucket}"
    
    def _get_actions(self) -> List[str]:
        """Get available actions"""
        return [
            'increase_rate', 'decrease_rate',
            'increase_size', 'decrease_size',
            'increase_threads', 'decrease_threads',
            'increase_burst', 'decrease_burst',
            'increase_evasion', 'decrease_evasion',
            'no_change'
        ]
    
    def _apply_action(self, params: AttackParameters, action: str) -> AttackParameters:
        """Apply action to parameters"""
        new_params = AttackParameters(
            packet_size=params.packet_size,
            rate_pps=params.rate_pps,
            thread_count=params.thread_count,
            burst_size=params.burst_size,
            burst_interval_ms=params.burst_interval_ms,
            jitter_percent=params.jitter_percent,
            evasion_level=params.evasion_level,
        )
        
        if action == 'increase_rate':
            new_params.rate_pps = min(10000000, int(params.rate_pps * 1.2))
        elif action == 'decrease_rate':
            new_params.rate_pps = max(1000, int(params.rate_pps * 0.8))
        elif action == 'increase_size':
            new_params.packet_size = min(65535, params.packet_size + 100)
        elif action == 'decrease_size':
            new_params.packet_size = max(64, params.packet_size - 100)
        elif action == 'increase_threads':
            new_params.thread_count = min(64, params.thread_count + 1)
        elif action == 'decrease_threads':
            new_params.thread_count = max(1, params.thread_count - 1)
        elif action == 'increase_burst':
            new_params.burst_size = min(1000, params.burst_size + 10)
        elif action == 'decrease_burst':
            new_params.burst_size = max(1, params.burst_size - 10)
        elif action == 'increase_evasion':
            new_params.evasion_level = min(10, params.evasion_level + 1)
        elif action == 'decrease_evasion':
            new_params.evasion_level = max(0, params.evasion_level - 1)
        
        return new_params
    
    def select_action(self, state: str) -> str:
        """Select action using epsilon-greedy"""
        if random.random() < self.exploration_rate:
            return random.choice(self._get_actions())
        
        if state not in self.q_table:
            self.q_table[state] = {a: 0.0 for a in self._get_actions()}
        
        return max(self.q_table[state], key=self.q_table[state].get)
    
    def update(self, state: str, action: str, reward: float, next_state: str):
        """Update Q-value"""
        if state not in self.q_table:
            self.q_table[state] = {a: 0.0 for a in self._get_actions()}
        if next_state not in self.q_table:
            self.q_table[next_state] = {a: 0.0 for a in self._get_actions()}
        
        current_q = self.q_table[state][action]
        max_next_q = max(self.q_table[next_state].values())
        
        new_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_next_q - current_q
        )
        
        self.q_table[state][action] = new_q
    
    def decay_exploration(self):
        """Decay exploration rate"""
        self.exploration_rate *= self.exploration_decay
        self.exploration_rate = max(0.01, self.exploration_rate)
    
    def optimize_step(
        self,
        current_params: AttackParameters,
        evaluate_func: Callable[[AttackParameters], float]
    ) -> Tuple[AttackParameters, float]:
        """Perform one optimization step"""
        state = self._state_key(current_params)
        action = self.select_action(state)
        new_params = self._apply_action(current_params, action)
        
        # Evaluate new parameters
        reward = evaluate_func(new_params)
        next_state = self._state_key(new_params)
        
        # Update Q-table
        self.update(state, action, reward, next_state)
        self.decay_exploration()
        self.episode += 1
        
        return new_params, reward


class BayesianOptimizer:
    """Bayesian optimization for attack parameters"""
    
    def __init__(self, bounds: Dict[str, Tuple[float, float]]):
        self.bounds = bounds
        self.observations: List[Tuple[Dict[str, float], float]] = []
        self.best_params: Optional[Dict[str, float]] = None
        self.best_value: float = float('-inf')
    
    def _acquisition_function(self, params: Dict[str, float], kappa: float = 2.0) -> float:
        """Upper Confidence Bound acquisition function"""
        if not self.observations:
            return random.random()
        
        # Simple UCB approximation
        mean = sum(obs[1] for obs in self.observations) / len(self.observations)
        variance = sum((obs[1] - mean) ** 2 for obs in self.observations) / len(self.observations)
        std = math.sqrt(variance) if variance > 0 else 1.0
        
        return mean + kappa * std
    
    def suggest(self) -> Dict[str, float]:
        """Suggest next parameters to try"""
        if len(self.observations) < 5:
            # Random exploration initially
            return {
                name: random.uniform(low, high)
                for name, (low, high) in self.bounds.items()
            }
        
        # Generate candidates and pick best by acquisition function
        best_candidate = None
        best_acq = float('-inf')
        
        for _ in range(100):
            candidate = {
                name: random.uniform(low, high)
                for name, (low, high) in self.bounds.items()
            }
            acq = self._acquisition_function(candidate)
            if acq > best_acq:
                best_acq = acq
                best_candidate = candidate
        
        return best_candidate
    
    def observe(self, params: Dict[str, float], value: float):
        """Record observation"""
        self.observations.append((params, value))
        
        if value > self.best_value:
            self.best_value = value
            self.best_params = params


class AttackOptimizer:
    """Main attack optimizer combining multiple strategies"""
    
    def __init__(self, goal: OptimizationGoal = OptimizationGoal.BALANCED):
        self.goal = goal
        self.genetic = GeneticOptimizer()
        self.rl = ReinforcementLearner()
        self.bayesian = BayesianOptimizer({
            'packet_size': (64, 65535),
            'rate_pps': (1000, 10000000),
            'thread_count': (1, 64),
            'burst_size': (1, 1000),
            'jitter_percent': (0, 1),
        })
        self.best_params: Optional[AttackParameters] = None
        self.best_fitness: float = 0.0
        self.iteration = 0
    
    async def optimize(
        self,
        evaluate_func: Callable[[AttackParameters], float],
        iterations: int = 100,
        initial_params: Optional[AttackParameters] = None
    ) -> AttackParameters:
        """Run optimization"""
        # Initialize
        self.genetic.initialize_population(initial_params)
        current_params = initial_params or AttackParameters()
        
        for i in range(iterations):
            self.iteration = i
            
            # Genetic algorithm step
            self.genetic.evaluate_population(evaluate_func)
            self.genetic.evolve()
            ga_best = self.genetic.get_best()
            
            # RL step
            rl_params, rl_fitness = self.rl.optimize_step(current_params, evaluate_func)
            
            # Bayesian step
            bayes_suggestion = self.bayesian.suggest()
            bayes_params = AttackParameters(
                packet_size=int(bayes_suggestion['packet_size']),
                rate_pps=int(bayes_suggestion['rate_pps']),
                thread_count=int(bayes_suggestion['thread_count']),
                burst_size=int(bayes_suggestion['burst_size']),
                jitter_percent=bayes_suggestion['jitter_percent'],
            )
            bayes_fitness = evaluate_func(bayes_params)
            self.bayesian.observe(bayes_suggestion, bayes_fitness)
            
            # Select best from all methods
            candidates = [
                (ga_best.params, ga_best.fitness),
                (rl_params, rl_fitness),
                (bayes_params, bayes_fitness),
            ]
            
            best_candidate = max(candidates, key=lambda x: x[1])
            
            if best_candidate[1] > self.best_fitness:
                self.best_fitness = best_candidate[1]
                self.best_params = best_candidate[0]
            
            current_params = best_candidate[0]
            
            logger.info(f"Iteration {i}: Best fitness = {self.best_fitness:.4f}")
        
        return self.best_params or AttackParameters()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get optimization statistics"""
        return {
            'iterations': self.iteration,
            'best_fitness': self.best_fitness,
            'best_params': self.best_params,
            'genetic_generations': self.genetic.generation,
            'rl_episodes': self.rl.episode,
            'bayesian_observations': len(self.bayesian.observations),
        }


__all__ = [
    'OptimizationGoal', 'AttackParameters', 'AttackResult',
    'Individual', 'GeneticOptimizer', 'ReinforcementLearner',
    'BayesianOptimizer', 'AttackOptimizer',
]
