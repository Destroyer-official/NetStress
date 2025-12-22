"""
Adaptive Strategy Engine

Implements reinforcement learning system for strategy adaptation,
genetic algorithms for parameter evolution, and swarm intelligence
for distributed coordination.
"""

import numpy as np
import random
import logging
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
import queue
import json
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

@dataclass
class AttackStrategy:
    """Represents an attack strategy with parameters and performance"""
    strategy_id: str
    parameters: Dict[str, Any]
    performance_score: float = 0.0
    success_rate: float = 0.0
    execution_count: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    fitness: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'strategy_id': self.strategy_id,
            'parameters': self.parameters,
            'performance_score': self.performance_score,
            'success_rate': self.success_rate,
            'execution_count': self.execution_count,
            'last_updated': self.last_updated.isoformat(),
            'fitness': self.fitness
        }

@dataclass
class EnvironmentState:
    """Represents the current environment state for RL"""
    target_response_time: float
    error_rate: float
    bandwidth_utilization: float
    defense_activity: float
    network_congestion: float
    time_of_day: float
    attack_duration: float
    
    def to_vector(self) -> np.ndarray:
        return np.array([
            self.target_response_time,
            self.error_rate,
            self.bandwidth_utilization,
            self.defense_activity,
            self.network_congestion,
            self.time_of_day,
            self.attack_duration
        ])

@dataclass
class ActionSpace:
    """Defines the action space for RL agent"""
    packet_rate_range: Tuple[int, int] = (1000, 100000)
    packet_size_range: Tuple[int, int] = (64, 1500)
    protocol_options: List[str] = field(default_factory=lambda: ['TCP', 'UDP', 'HTTP', 'DNS'])
    evasion_techniques: List[str] = field(default_factory=lambda: ['spoofing', 'fragmentation', 'timing'])
    
    def sample_action(self) -> Dict[str, Any]:
        """Sample a random action from the action space"""
        return {
            'packet_rate': random.randint(*self.packet_rate_range),
            'packet_size': random.randint(*self.packet_size_range),
            'protocol': random.choice(self.protocol_options),
            'evasion_technique': random.choice(self.evasion_techniques),
            'burst_duration': random.uniform(0.1, 5.0),
            'pause_duration': random.uniform(0.1, 2.0)
        }

class ReinforcementLearningAgent:
    """
    Reinforcement learning system for strategy adaptation
    Uses Q-learning with function approximation
    """
    
    def __init__(self, state_dim: int = 7, action_dim: int = 6, learning_rate: float = 0.01):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.learning_rate = learning_rate
        self.epsilon = 0.1  # Exploration rate
        self.gamma = 0.95   # Discount factor
        
        # Q-network weights (simple linear approximation)
        self.q_weights = np.random.randn(state_dim, action_dim) * 0.1
        self.experience_buffer = []
        self.max_buffer_size = 10000
        
        self.action_space = ActionSpace()
        self.last_state = None
        self.last_action = None
        self.total_reward = 0.0
        
    def get_state_from_environment(self, attack_stats: Dict, target_response: Dict, 
                                 network_conditions: Dict) -> EnvironmentState:
        """Convert environment data to state representation"""
        current_time = datetime.now()
        time_of_day = (current_time.hour * 60 + current_time.minute) / 1440.0  # Normalize to [0,1]
        
        return EnvironmentState(
            target_response_time=target_response.get('response_time', 0) / 5000.0,  # Normalize
            error_rate=min(attack_stats.get('errors', 0) / 1000.0, 1.0),
            bandwidth_utilization=min(attack_stats.get('bps', 0) / 1e9, 1.0),  # Normalize to Gbps
            defense_activity=target_response.get('defense_activity', 0),
            network_congestion=network_conditions.get('congestion_level', 0),
            time_of_day=time_of_day,
            attack_duration=attack_stats.get('duration', 0) / 3600.0  # Normalize to hours
        )
    
    def select_action(self, state: EnvironmentState) -> Dict[str, Any]:
        """Select action using epsilon-greedy policy"""
        state_vector = state.to_vector()
        
        if random.random() < self.epsilon:
            # Exploration: random action
            action = self.action_space.sample_action()
        else:
            # Exploitation: best action according to Q-function
            q_values = np.dot(state_vector, self.q_weights)
            best_action_idx = np.argmax(q_values)
            action = self._action_index_to_params(best_action_idx)
        
        self.last_state = state_vector
        self.last_action = action
        
        return action
    
    def update_q_function(self, reward: float, next_state: EnvironmentState, done: bool = False):
        """Update Q-function using temporal difference learning"""
        if self.last_state is None or self.last_action is None:
            return
        
        next_state_vector = next_state.to_vector()
        
        # Calculate target Q-value
        if done:
            target_q = reward
        else:
            next_q_values = np.dot(next_state_vector, self.q_weights)
            target_q = reward + self.gamma * np.max(next_q_values)
        
        # Current Q-value
        current_q_values = np.dot(self.last_state, self.q_weights)
        action_idx = self._params_to_action_index(self.last_action)
        current_q = current_q_values[action_idx]
        
        # TD error
        td_error = target_q - current_q
        
        # Update weights
        gradient = np.outer(self.last_state, np.zeros(self.action_dim))
        gradient[:, action_idx] = self.last_state
        
        self.q_weights += self.learning_rate * td_error * gradient
        
        # Store experience
        experience = {
            'state': self.last_state.copy(),
            'action': self.last_action.copy(),
            'reward': reward,
            'next_state': next_state_vector.copy(),
            'done': done
        }
        
        if len(self.experience_buffer) >= self.max_buffer_size:
            self.experience_buffer.pop(0)
        self.experience_buffer.append(experience)
        
        self.total_reward += reward
        
        # Decay exploration rate
        self.epsilon = max(0.01, self.epsilon * 0.995)
    
    def _action_index_to_params(self, action_idx: int) -> Dict[str, Any]:
        """Convert action index to parameter dictionary"""
        # Simple mapping - in practice would be more sophisticated
        protocols = self.action_space.protocol_options
        evasion_techniques = self.action_space.evasion_techniques
        
        protocol_idx = action_idx % len(protocols)
        evasion_idx = (action_idx // len(protocols)) % len(evasion_techniques)
        
        return {
            'packet_rate': random.randint(*self.action_space.packet_rate_range),
            'packet_size': random.randint(*self.action_space.packet_size_range),
            'protocol': protocols[protocol_idx],
            'evasion_technique': evasion_techniques[evasion_idx],
            'burst_duration': random.uniform(0.1, 5.0),
            'pause_duration': random.uniform(0.1, 2.0)
        }
    
    def _params_to_action_index(self, params: Dict[str, Any]) -> int:
        """Convert parameter dictionary to action index"""
        protocols = self.action_space.protocol_options
        evasion_techniques = self.action_space.evasion_techniques
        
        protocol_idx = protocols.index(params.get('protocol', protocols[0]))
        evasion_idx = evasion_techniques.index(params.get('evasion_technique', evasion_techniques[0]))
        
        return protocol_idx + evasion_idx * len(protocols)
    
    def calculate_reward(self, attack_stats: Dict, target_response: Dict) -> float:
        """Calculate reward based on attack performance"""
        # Multi-objective reward function
        
        # Effectiveness component (higher PPS is better)
        pps_reward = min(attack_stats.get('pps', 0) / 50000.0, 1.0)
        
        # Efficiency component (lower error rate is better)
        error_penalty = -min(attack_stats.get('errors', 0) / 1000.0, 1.0)
        
        # Impact component (higher response time indicates impact)
        impact_reward = min(target_response.get('response_time', 0) / 5000.0, 1.0)
        
        # Stealth component (lower detection rate is better)
        stealth_reward = 1.0 - target_response.get('detection_rate', 0)
        
        # Weighted combination
        total_reward = (0.3 * pps_reward + 0.2 * error_penalty + 
                       0.3 * impact_reward + 0.2 * stealth_reward)
        
        return max(-1.0, min(1.0, total_reward))
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning statistics"""
        return {
            'total_reward': self.total_reward,
            'epsilon': self.epsilon,
            'experience_count': len(self.experience_buffer),
            'q_weights_norm': np.linalg.norm(self.q_weights),
            'avg_reward': self.total_reward / max(1, len(self.experience_buffer))
        }

class GeneticAlgorithmOptimizer:
    """
    Genetic algorithms for parameter evolution
    Evolves attack strategies using genetic operators
    """
    
    def __init__(self, population_size: int = 50, mutation_rate: float = 0.1):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = 0.8
        self.elitism_rate = 0.1
        
        self.population: List[AttackStrategy] = []
        self.generation = 0
        self.best_fitness_history = []
        self.avg_fitness_history = []
        
        self._initialize_population()
    
    def _initialize_population(self):
        """Initialize random population of attack strategies"""
        for i in range(self.population_size):
            strategy = AttackStrategy(
                strategy_id=f"gen0_ind{i}",
                parameters=self._generate_random_parameters(),
                fitness=0.0
            )
            self.population.append(strategy)
    
    def _generate_random_parameters(self) -> Dict[str, Any]:
        """Generate random attack parameters"""
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
        evasion_techniques = ['spoofing', 'fragmentation', 'timing', 'randomization']
        
        return {
            'packet_rate': random.randint(1000, 100000),
            'packet_size': random.randint(64, 1500),
            'protocol': random.choice(protocols),
            'evasion_technique': random.choice(evasion_techniques),
            'burst_duration': random.uniform(0.1, 10.0),
            'pause_duration': random.uniform(0.1, 5.0),
            'concurrency': random.randint(1, 1000),
            'spoofing_rate': random.uniform(0.0, 1.0),
            'fragmentation_size': random.randint(8, 1472),
            'timing_variance': random.uniform(0.0, 1.0)
        }
    
    def evaluate_fitness(self, strategy: AttackStrategy, attack_results: Dict) -> float:
        """Evaluate fitness of a strategy based on attack results"""
        # Multi-objective fitness function
        
        # Performance metrics
        pps_score = min(attack_results.get('pps', 0) / 50000.0, 1.0)
        bandwidth_score = min(attack_results.get('bps', 0) / 1e9, 1.0)  # Normalize to Gbps
        
        # Efficiency metrics
        error_rate = attack_results.get('errors', 0) / max(1, attack_results.get('packets_sent', 1))
        efficiency_score = max(0.0, 1.0 - error_rate)
        
        # Impact metrics
        response_time = attack_results.get('target_response_time', 0)
        impact_score = min(response_time / 5000.0, 1.0)
        
        # Stealth metrics
        detection_rate = attack_results.get('detection_rate', 0)
        stealth_score = max(0.0, 1.0 - detection_rate)
        
        # Resource efficiency
        cpu_usage = attack_results.get('cpu_usage', 0)
        memory_usage = attack_results.get('memory_usage', 0)
        resource_score = max(0.0, 1.0 - (cpu_usage + memory_usage) / 2.0)
        
        # Weighted fitness calculation
        fitness = (0.25 * pps_score + 0.15 * bandwidth_score + 0.20 * efficiency_score +
                  0.20 * impact_score + 0.10 * stealth_score + 0.10 * resource_score)
        
        strategy.fitness = fitness
        strategy.performance_score = fitness
        strategy.execution_count += 1
        strategy.last_updated = datetime.now()
        
        return fitness
    
    def evolve_generation(self) -> List[AttackStrategy]:
        """Evolve population to next generation"""
        # Sort population by fitness
        self.population.sort(key=lambda x: x.fitness, reverse=True)
        
        # Record statistics
        best_fitness = self.population[0].fitness
        avg_fitness = sum(s.fitness for s in self.population) / len(self.population)
        
        self.best_fitness_history.append(best_fitness)
        self.avg_fitness_history.append(avg_fitness)
        
        # Create new generation
        new_population = []
        
        # Elitism: keep best individuals
        elite_count = int(self.population_size * self.elitism_rate)
        for i in range(elite_count):
            elite = self.population[i]
            elite.strategy_id = f"gen{self.generation + 1}_elite{i}"
            new_population.append(elite)
        
        # Generate offspring through crossover and mutation
        while len(new_population) < self.population_size:
            # Selection
            parent1 = self._tournament_selection()
            parent2 = self._tournament_selection()
            
            # Crossover
            if random.random() < self.crossover_rate:
                child1, child2 = self._crossover(parent1, parent2)
            else:
                child1, child2 = parent1, parent2
            
            # Mutation
            child1 = self._mutate(child1)
            child2 = self._mutate(child2)
            
            # Add to new population
            child1.strategy_id = f"gen{self.generation + 1}_ind{len(new_population)}"
            child2.strategy_id = f"gen{self.generation + 1}_ind{len(new_population) + 1}"
            
            new_population.extend([child1, child2])
        
        # Trim to exact population size
        new_population = new_population[:self.population_size]
        
        self.population = new_population
        self.generation += 1
        
        logger.info(f"Generation {self.generation}: Best fitness = {best_fitness:.4f}, "
                   f"Avg fitness = {avg_fitness:.4f}")
        
        return new_population
    
    def _tournament_selection(self, tournament_size: int = 3) -> AttackStrategy:
        """Tournament selection for parent selection"""
        tournament = random.sample(self.population, min(tournament_size, len(self.population)))
        return max(tournament, key=lambda x: x.fitness)
    
    def _crossover(self, parent1: AttackStrategy, parent2: AttackStrategy) -> Tuple[AttackStrategy, AttackStrategy]:
        """Single-point crossover between two parents"""
        # Create copies
        child1_params = parent1.parameters.copy()
        child2_params = parent2.parameters.copy()
        
        # Crossover parameters
        param_keys = list(child1_params.keys())
        crossover_point = random.randint(1, len(param_keys) - 1)
        
        for i in range(crossover_point, len(param_keys)):
            key = param_keys[i]
            child1_params[key], child2_params[key] = child2_params[key], child1_params[key]
        
        child1 = AttackStrategy(
            strategy_id="temp_child1",
            parameters=child1_params,
            fitness=0.0
        )
        
        child2 = AttackStrategy(
            strategy_id="temp_child2", 
            parameters=child2_params,
            fitness=0.0
        )
        
        return child1, child2
    
    def _mutate(self, strategy: AttackStrategy) -> AttackStrategy:
        """Mutate strategy parameters"""
        mutated_params = strategy.parameters.copy()
        
        for key, value in mutated_params.items():
            if random.random() < self.mutation_rate:
                if key == 'packet_rate':
                    mutated_params[key] = max(1000, min(100000, 
                        value + random.randint(-10000, 10000)))
                elif key == 'packet_size':
                    mutated_params[key] = max(64, min(1500, 
                        value + random.randint(-100, 100)))
                elif key == 'protocol':
                    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
                    mutated_params[key] = random.choice(protocols)
                elif key == 'evasion_technique':
                    techniques = ['spoofing', 'fragmentation', 'timing', 'randomization']
                    mutated_params[key] = random.choice(techniques)
                elif isinstance(value, float):
                    mutated_params[key] = max(0.0, value + random.uniform(-0.5, 0.5))
                elif isinstance(value, int):
                    mutated_params[key] = max(1, value + random.randint(-10, 10))
        
        return AttackStrategy(
            strategy_id=strategy.strategy_id,
            parameters=mutated_params,
            fitness=0.0
        )
    
    def get_best_strategy(self) -> AttackStrategy:
        """Get the best strategy from current population"""
        return max(self.population, key=lambda x: x.fitness)
    
    def get_evolution_stats(self) -> Dict[str, Any]:
        """Get evolution statistics"""
        return {
            'generation': self.generation,
            'population_size': len(self.population),
            'best_fitness_history': self.best_fitness_history,
            'avg_fitness_history': self.avg_fitness_history,
            'current_best_fitness': max(s.fitness for s in self.population) if self.population else 0.0,
            'current_avg_fitness': sum(s.fitness for s in self.population) / len(self.population) if self.population else 0.0
        }

class SwarmIntelligenceCoordinator:
    """
    Swarm intelligence for distributed coordination
    Implements particle swarm optimization for coordinated attacks
    """
    
    def __init__(self, swarm_size: int = 30, dimensions: int = 10):
        self.swarm_size = swarm_size
        self.dimensions = dimensions
        
        # PSO parameters
        self.w = 0.7  # Inertia weight
        self.c1 = 1.5  # Cognitive parameter
        self.c2 = 1.5  # Social parameter
        
        # Swarm state
        self.particles = []
        self.global_best_position = None
        self.global_best_fitness = -float('inf')
        self.iteration = 0
        
        # Coordination state
        self.active_attacks = {}
        self.coordination_matrix = np.zeros((swarm_size, swarm_size))
        
        self._initialize_swarm()
    
    def _initialize_swarm(self):
        """Initialize particle swarm"""
        for i in range(self.swarm_size):
            particle = {
                'id': f"particle_{i}",
                'position': np.random.uniform(-1, 1, self.dimensions),
                'velocity': np.random.uniform(-0.1, 0.1, self.dimensions),
                'best_position': None,
                'best_fitness': -float('inf'),
                'fitness': 0.0,
                'attack_params': {},
                'coordination_weight': 1.0 / self.swarm_size
            }
            self.particles.append(particle)
    
    def update_particle_fitness(self, particle_id: str, attack_results: Dict):
        """Update fitness for a specific particle"""
        particle = next((p for p in self.particles if p['id'] == particle_id), None)
        if particle is None:
            return
        
        # Calculate fitness based on attack results
        fitness = self._calculate_swarm_fitness(attack_results)
        particle['fitness'] = fitness
        
        # Update personal best
        if fitness > particle['best_fitness']:
            particle['best_fitness'] = fitness
            particle['best_position'] = particle['position'].copy()
        
        # Update global best
        if fitness > self.global_best_fitness:
            self.global_best_fitness = fitness
            self.global_best_position = particle['position'].copy()
            
            logger.info(f"New global best fitness: {fitness:.4f} by {particle_id}")
    
    def _calculate_swarm_fitness(self, attack_results: Dict) -> float:
        """Calculate fitness for swarm coordination"""
        # Individual performance
        individual_score = min(attack_results.get('pps', 0) / 50000.0, 1.0)
        
        # Coordination bonus (based on synchronized timing)
        coordination_score = attack_results.get('coordination_score', 0.5)
        
        # Resource efficiency
        resource_usage = attack_results.get('resource_usage', 0.5)
        efficiency_score = max(0.0, 1.0 - resource_usage)
        
        # Distributed impact
        distributed_impact = attack_results.get('distributed_impact', 0.5)
        
        # Combined fitness
        fitness = (0.3 * individual_score + 0.3 * coordination_score + 
                  0.2 * efficiency_score + 0.2 * distributed_impact)
        
        return fitness
    
    def optimize_swarm(self) -> List[Dict[str, Any]]:
        """Perform one iteration of PSO optimization"""
        optimized_params = []
        
        for particle in self.particles:
            # Update velocity
            if particle['best_position'] is not None and self.global_best_position is not None:
                r1, r2 = np.random.random(2)
                
                cognitive_component = self.c1 * r1 * (particle['best_position'] - particle['position'])
                social_component = self.c2 * r2 * (self.global_best_position - particle['position'])
                
                particle['velocity'] = (self.w * particle['velocity'] + 
                                      cognitive_component + social_component)
                
                # Velocity clamping
                particle['velocity'] = np.clip(particle['velocity'], -1.0, 1.0)
            
            # Update position
            particle['position'] += particle['velocity']
            particle['position'] = np.clip(particle['position'], -1.0, 1.0)
            
            # Convert position to attack parameters
            attack_params = self._position_to_params(particle['position'])
            particle['attack_params'] = attack_params
            
            optimized_params.append({
                'particle_id': particle['id'],
                'attack_params': attack_params,
                'coordination_weight': particle['coordination_weight']
            })
        
        self.iteration += 1
        return optimized_params
    
    def _position_to_params(self, position: np.ndarray) -> Dict[str, Any]:
        """Convert particle position to attack parameters"""
        # Map normalized position [-1, 1] to parameter ranges
        params = {}
        
        # Packet rate (1000 to 100000)
        params['packet_rate'] = int(1000 + (position[0] + 1) * 49500)
        
        # Packet size (64 to 1500)
        params['packet_size'] = int(64 + (position[1] + 1) * 718)
        
        # Protocol selection (discrete)
        protocols = ['TCP', 'UDP', 'HTTP', 'DNS']
        protocol_idx = int((position[2] + 1) * len(protocols) / 2) % len(protocols)
        params['protocol'] = protocols[protocol_idx]
        
        # Timing parameters
        params['burst_duration'] = 0.1 + (position[3] + 1) * 4.95
        params['pause_duration'] = 0.1 + (position[4] + 1) * 2.45
        
        # Coordination parameters
        params['sync_offset'] = position[5] * 1.0  # Synchronization offset
        params['coordination_strength'] = (position[6] + 1) / 2.0  # 0 to 1
        
        # Evasion parameters
        params['spoofing_rate'] = (position[7] + 1) / 2.0
        params['randomization_level'] = (position[8] + 1) / 2.0
        
        # Resource allocation
        params['resource_allocation'] = (position[9] + 1) / 2.0
        
        return params
    
    def coordinate_distributed_attack(self, target_info: Dict) -> List[Dict[str, Any]]:
        """Coordinate distributed attack across swarm"""
        coordination_plan = []
        
        # Calculate optimal timing for coordinated attack
        base_time = datetime.now()
        
        for i, particle in enumerate(self.particles):
            # Calculate coordination timing
            sync_offset = particle['attack_params'].get('sync_offset', 0)
            start_time = base_time + timedelta(seconds=sync_offset)
            
            # Assign target distribution
            target_assignment = self._assign_target_distribution(i, target_info)
            
            coordination_info = {
                'particle_id': particle['id'],
                'attack_params': particle['attack_params'],
                'start_time': start_time,
                'target_assignment': target_assignment,
                'coordination_weight': particle['coordination_weight'],
                'sync_signal': f"sync_{self.iteration}_{i}"
            }
            
            coordination_plan.append(coordination_info)
        
        return coordination_plan
    
    def _assign_target_distribution(self, particle_idx: int, target_info: Dict) -> Dict[str, Any]:
        """Assign target distribution for coordinated attack"""
        # Simple round-robin distribution
        available_targets = target_info.get('target_list', [target_info.get('primary_target')])
        target_idx = particle_idx % len(available_targets)
        
        return {
            'primary_target': available_targets[target_idx],
            'backup_targets': available_targets,
            'load_distribution': 1.0 / len(available_targets)
        }
    
    def update_coordination_matrix(self, particle_interactions: Dict):
        """Update coordination matrix based on particle interactions"""
        for i, particle_i in enumerate(self.particles):
            for j, particle_j in enumerate(self.particles):
                if i != j:
                    # Calculate coordination strength based on performance correlation
                    correlation = particle_interactions.get(f"{particle_i['id']}_{particle_j['id']}", 0.0)
                    self.coordination_matrix[i, j] = correlation
    
    def get_swarm_stats(self) -> Dict[str, Any]:
        """Get swarm intelligence statistics"""
        return {
            'iteration': self.iteration,
            'swarm_size': self.swarm_size,
            'global_best_fitness': self.global_best_fitness,
            'avg_fitness': sum(p['fitness'] for p in self.particles) / len(self.particles),
            'convergence_rate': self._calculate_convergence_rate(),
            'coordination_efficiency': np.mean(self.coordination_matrix),
            'active_particles': len([p for p in self.particles if p['fitness'] > 0])
        }
    
    def _calculate_convergence_rate(self) -> float:
        """Calculate swarm convergence rate"""
        if len(self.particles) < 2:
            return 0.0
        
        positions = np.array([p['position'] for p in self.particles])
        distances = []
        
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distance = np.linalg.norm(positions[i] - positions[j])
                distances.append(distance)
        
        avg_distance = np.mean(distances) if distances else 0.0
        max_distance = np.sqrt(self.dimensions * 4)  # Maximum possible distance in [-1,1]^d
        
        convergence = 1.0 - (avg_distance / max_distance)
        return max(0.0, min(1.0, convergence))

class AdaptiveStrategyEngine:
    """
    Main adaptive strategy engine that coordinates all AI components
    Integrates RL, GA, and swarm intelligence for optimal attack strategies
    """
    
    def __init__(self):
        self.rl_agent = ReinforcementLearningAgent()
        self.genetic_optimizer = GeneticAlgorithmOptimizer()
        self.swarm_coordinator = SwarmIntelligenceCoordinator()
        
        self.strategy_history = []
        self.performance_metrics = {}
        self.adaptation_mode = 'hybrid'  # 'rl', 'genetic', 'swarm', 'hybrid'
        
        self._lock = threading.Lock()
        
    def adapt_strategy(self, current_stats: Dict, target_response: Dict, 
                      network_conditions: Dict) -> Dict[str, Any]:
        """Adapt attack strategy based on current conditions"""
        with self._lock:
            adapted_strategy = {}
            
            if self.adaptation_mode in ['rl', 'hybrid']:
                # Reinforcement learning adaptation
                state = self.rl_agent.get_state_from_environment(
                    current_stats, target_response, network_conditions
                )
                rl_action = self.rl_agent.select_action(state)
                adapted_strategy.update(rl_action)
                
                # Update RL agent with reward
                reward = self.rl_agent.calculate_reward(current_stats, target_response)
                self.rl_agent.update_q_function(reward, state)
            
            if self.adaptation_mode in ['genetic', 'hybrid']:
                # Genetic algorithm optimization
                best_genetic_strategy = self.genetic_optimizer.get_best_strategy()
                if best_genetic_strategy.fitness > 0:
                    adapted_strategy.update(best_genetic_strategy.parameters)
            
            if self.adaptation_mode in ['swarm', 'hybrid']:
                # Swarm intelligence coordination
                swarm_params = self.swarm_coordinator.optimize_swarm()
                if swarm_params:
                    # Use best particle's parameters
                    best_particle = max(swarm_params, 
                                      key=lambda x: self.swarm_coordinator.particles[
                                          int(x['particle_id'].split('_')[1])]['fitness'])
                    adapted_strategy.update(best_particle['attack_params'])
            
            # Combine strategies if in hybrid mode
            if self.adaptation_mode == 'hybrid':
                adapted_strategy = self._combine_strategies(adapted_strategy)
            
            # Record strategy
            strategy_record = {
                'timestamp': datetime.now(),
                'strategy': adapted_strategy.copy(),
                'current_stats': current_stats.copy(),
                'target_response': target_response.copy(),
                'adaptation_mode': self.adaptation_mode
            }
            self.strategy_history.append(strategy_record)
            
            return adapted_strategy
    
    def _combine_strategies(self, strategies: Dict[str, Any]) -> Dict[str, Any]:
        """Combine multiple strategy recommendations"""
        # Simple averaging for numerical parameters
        combined = {}
        
        numerical_params = ['packet_rate', 'packet_size', 'burst_duration', 'pause_duration']
        for param in numerical_params:
            values = [v for k, v in strategies.items() if param in str(k) and isinstance(v, (int, float))]
            if values:
                combined[param] = sum(values) / len(values)
        
        # Majority voting for categorical parameters
        categorical_params = ['protocol', 'evasion_technique']
        for param in categorical_params:
            values = [v for k, v in strategies.items() if param in str(k) and isinstance(v, str)]
            if values:
                # Simple majority vote
                from collections import Counter
                vote_counts = Counter(values)
                combined[param] = vote_counts.most_common(1)[0][0]
        
        return combined
    
    def update_performance_feedback(self, strategy_id: str, performance_results: Dict):
        """Update performance feedback for all AI components"""
        with self._lock:
            # Update genetic algorithm fitness
            for strategy in self.genetic_optimizer.population:
                if strategy.strategy_id == strategy_id:
                    self.genetic_optimizer.evaluate_fitness(strategy, performance_results)
                    break
            
            # Update swarm intelligence fitness
            if strategy_id.startswith('particle_'):
                self.swarm_coordinator.update_particle_fitness(strategy_id, performance_results)
            
            # Store performance metrics
            self.performance_metrics[strategy_id] = {
                'results': performance_results,
                'timestamp': datetime.now()
            }
    
    def evolve_strategies(self):
        """Trigger evolution in genetic algorithm"""
        with self._lock:
            self.genetic_optimizer.evolve_generation()
    
    def get_adaptation_status(self) -> Dict[str, Any]:
        """Get comprehensive adaptation status"""
        return {
            'adaptation_mode': self.adaptation_mode,
            'rl_stats': self.rl_agent.get_learning_stats(),
            'genetic_stats': self.genetic_optimizer.get_evolution_stats(),
            'swarm_stats': self.swarm_coordinator.get_swarm_stats(),
            'strategy_history_count': len(self.strategy_history),
            'performance_records': len(self.performance_metrics)
        }
    
    def set_adaptation_mode(self, mode: str):
        """Set adaptation mode"""
        valid_modes = ['rl', 'genetic', 'swarm', 'hybrid']
        if mode in valid_modes:
            self.adaptation_mode = mode
            logger.info(f"Adaptation mode set to: {mode}")
        else:
            logger.error(f"Invalid adaptation mode: {mode}. Valid modes: {valid_modes}")
    
    def get_best_strategies(self, count: int = 5) -> List[Dict[str, Any]]:
        """Get top performing strategies"""
        # Combine strategies from all sources
        all_strategies = []
        
        # From genetic algorithm
        genetic_strategies = sorted(self.genetic_optimizer.population, 
                                  key=lambda x: x.fitness, reverse=True)[:count]
        for strategy in genetic_strategies:
            all_strategies.append({
                'source': 'genetic',
                'strategy': strategy.to_dict(),
                'performance': strategy.fitness
            })
        
        # From performance history
        performance_strategies = sorted(self.performance_metrics.items(),
                                      key=lambda x: x[1]['results'].get('pps', 0), 
                                      reverse=True)[:count]
        for strategy_id, perf_data in performance_strategies:
            all_strategies.append({
                'source': 'performance',
                'strategy_id': strategy_id,
                'performance': perf_data['results'].get('pps', 0)
            })
        
        # Sort by performance and return top strategies
        all_strategies.sort(key=lambda x: x.get('performance', 0), reverse=True)
        return all_strategies[:count]