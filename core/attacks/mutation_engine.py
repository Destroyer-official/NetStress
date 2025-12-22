"""
Payload Mutation Engine

Advanced payload mutation for evasion:
- Genetic algorithm-based mutation
- Fitness-based selection
- Crossover and mutation operators
- Adaptive mutation rates
"""

import random
import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class MutationType(Enum):
    """Mutation types"""
    BIT_FLIP = "bit_flip"
    BYTE_SWAP = "byte_swap"
    BYTE_INSERT = "byte_insert"
    BYTE_DELETE = "byte_delete"
    BLOCK_SHUFFLE = "block_shuffle"
    ARITHMETIC = "arithmetic"
    DICTIONARY = "dictionary"
    HAVOC = "havoc"


@dataclass
class MutationConfig:
    """Mutation configuration"""
    mutation_rate: float = 0.1
    crossover_rate: float = 0.7
    population_size: int = 50
    elite_count: int = 5
    max_generations: int = 100
    min_size: int = 1
    max_size: int = 65535


@dataclass
class Individual:
    """Individual in genetic population"""
    payload: bytes
    fitness: float = 0.0
    generation: int = 0
    mutations: List[str] = field(default_factory=list)
    
    def __hash__(self):
        return hash(self.payload)


class FitnessFunction(ABC):
    """Base class for fitness functions"""
    
    @abstractmethod
    def evaluate(self, payload: bytes) -> float:
        """Evaluate payload fitness (higher is better)"""
        pass


class EntropyFitness(FitnessFunction):
    """Fitness based on payload entropy"""
    
    def evaluate(self, payload: bytes) -> float:
        if not payload:
            return 0.0
            
        import math
        from collections import Counter
        
        freq = Counter(payload)
        length = len(payload)
        
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
                
        # Normalize to 0-1 (max entropy is 8 bits)
        return entropy / 8.0


class UniqueFitness(FitnessFunction):
    """Fitness based on unique byte patterns"""
    
    def __init__(self, seen_patterns: set = None):
        self.seen_patterns = seen_patterns or set()
        
    def evaluate(self, payload: bytes) -> float:
        if not payload:
            return 0.0
            
        # Hash payload
        h = hashlib.md5(payload).hexdigest()
        
        if h in self.seen_patterns:
            return 0.1  # Penalty for duplicate
            
        self.seen_patterns.add(h)
        
        # Reward unique patterns
        unique_bytes = len(set(payload))
        return unique_bytes / 256.0


class SizeFitness(FitnessFunction):
    """Fitness based on payload size"""
    
    def __init__(self, target_size: int = 1024):
        self.target_size = target_size
        
    def evaluate(self, payload: bytes) -> float:
        if not payload:
            return 0.0
            
        # Closer to target size is better
        diff = abs(len(payload) - self.target_size)
        return max(0, 1 - diff / self.target_size)


class CompositeFitness(FitnessFunction):
    """Combine multiple fitness functions"""
    
    def __init__(self, functions: List[Tuple[FitnessFunction, float]]):
        self.functions = functions  # (function, weight) pairs
        
    def evaluate(self, payload: bytes) -> float:
        total = 0.0
        total_weight = 0.0
        
        for func, weight in self.functions:
            total += func.evaluate(payload) * weight
            total_weight += weight
            
        return total / total_weight if total_weight > 0 else 0.0


class MutationOperator:
    """Mutation operators for payloads"""
    
    # Dictionary of interesting values
    INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
    INTERESTING_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]
    INTERESTING_32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647, 4294967295]
    
    @staticmethod
    def bit_flip(payload: bytes, count: int = 1) -> bytes:
        """Flip random bits"""
        if not payload:
            return payload
            
        data = bytearray(payload)
        for _ in range(count):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)
        return bytes(data)
        
    @staticmethod
    def byte_swap(payload: bytes) -> bytes:
        """Swap two random bytes"""
        if len(payload) < 2:
            return payload
            
        data = bytearray(payload)
        pos1 = random.randint(0, len(data) - 1)
        pos2 = random.randint(0, len(data) - 1)
        data[pos1], data[pos2] = data[pos2], data[pos1]
        return bytes(data)
        
    @staticmethod
    def byte_insert(payload: bytes, max_insert: int = 16) -> bytes:
        """Insert random bytes"""
        data = bytearray(payload)
        pos = random.randint(0, len(data))
        count = random.randint(1, max_insert)
        insert_data = bytes(random.randint(0, 255) for _ in range(count))
        data[pos:pos] = insert_data
        return bytes(data)
        
    @staticmethod
    def byte_delete(payload: bytes, max_delete: int = 16) -> bytes:
        """Delete random bytes"""
        if len(payload) <= 1:
            return payload
            
        data = bytearray(payload)
        count = min(random.randint(1, max_delete), len(data) - 1)
        pos = random.randint(0, len(data) - count)
        del data[pos:pos + count]
        return bytes(data)
        
    @staticmethod
    def block_shuffle(payload: bytes, block_size: int = 4) -> bytes:
        """Shuffle blocks of bytes"""
        if len(payload) < block_size * 2:
            return payload
            
        blocks = [payload[i:i+block_size] for i in range(0, len(payload), block_size)]
        random.shuffle(blocks)
        return b''.join(blocks)
        
    @staticmethod
    def arithmetic(payload: bytes) -> bytes:
        """Apply arithmetic operations"""
        if not payload:
            return payload
            
        data = bytearray(payload)
        pos = random.randint(0, len(data) - 1)
        op = random.choice(['+', '-', '*', '^'])
        value = random.randint(1, 35)
        
        if op == '+':
            data[pos] = (data[pos] + value) & 0xFF
        elif op == '-':
            data[pos] = (data[pos] - value) & 0xFF
        elif op == '*':
            data[pos] = (data[pos] * value) & 0xFF
        elif op == '^':
            data[pos] ^= value
            
        return bytes(data)
        
    @staticmethod
    def dictionary_replace(payload: bytes) -> bytes:
        """Replace with interesting values"""
        if not payload:
            return payload
            
        data = bytearray(payload)
        pos = random.randint(0, len(data) - 1)
        
        # Choose replacement type
        choice = random.randint(0, 2)
        
        if choice == 0:
            # 8-bit interesting value
            data[pos] = random.choice(MutationOperator.INTERESTING_8)
        elif choice == 1 and pos < len(data) - 1:
            # 16-bit interesting value
            value = random.choice(MutationOperator.INTERESTING_16)
            data[pos:pos+2] = struct.pack('>H', value)
        elif choice == 2 and pos < len(data) - 3:
            # 32-bit interesting value
            value = random.choice(MutationOperator.INTERESTING_32)
            data[pos:pos+4] = struct.pack('>I', value)
            
        return bytes(data)
        
    @staticmethod
    def havoc(payload: bytes, iterations: int = 5) -> bytes:
        """Apply multiple random mutations"""
        mutations = [
            MutationOperator.bit_flip,
            MutationOperator.byte_swap,
            MutationOperator.byte_insert,
            MutationOperator.byte_delete,
            MutationOperator.arithmetic,
            MutationOperator.dictionary_replace,
        ]
        
        data = payload
        for _ in range(iterations):
            mutation = random.choice(mutations)
            data = mutation(data)
            
        return data


class CrossoverOperator:
    """Crossover operators for payloads"""
    
    @staticmethod
    def single_point(parent1: bytes, parent2: bytes) -> Tuple[bytes, bytes]:
        """Single-point crossover"""
        if not parent1 or not parent2:
            return parent1, parent2
            
        min_len = min(len(parent1), len(parent2))
        point = random.randint(1, min_len - 1) if min_len > 1 else 1
        
        child1 = parent1[:point] + parent2[point:]
        child2 = parent2[:point] + parent1[point:]
        
        return child1, child2
        
    @staticmethod
    def two_point(parent1: bytes, parent2: bytes) -> Tuple[bytes, bytes]:
        """Two-point crossover"""
        if not parent1 or not parent2:
            return parent1, parent2
            
        min_len = min(len(parent1), len(parent2))
        if min_len < 3:
            return CrossoverOperator.single_point(parent1, parent2)
            
        point1 = random.randint(1, min_len - 2)
        point2 = random.randint(point1 + 1, min_len - 1)
        
        child1 = parent1[:point1] + parent2[point1:point2] + parent1[point2:]
        child2 = parent2[:point1] + parent1[point1:point2] + parent2[point2:]
        
        return child1, child2
        
    @staticmethod
    def uniform(parent1: bytes, parent2: bytes) -> Tuple[bytes, bytes]:
        """Uniform crossover"""
        if not parent1 or not parent2:
            return parent1, parent2
            
        min_len = min(len(parent1), len(parent2))
        
        child1 = bytearray()
        child2 = bytearray()
        
        for i in range(min_len):
            if random.random() < 0.5:
                child1.append(parent1[i])
                child2.append(parent2[i])
            else:
                child1.append(parent2[i])
                child2.append(parent1[i])
                
        # Append remaining bytes
        if len(parent1) > min_len:
            child1.extend(parent1[min_len:])
        if len(parent2) > min_len:
            child2.extend(parent2[min_len:])
            
        return bytes(child1), bytes(child2)


class MutationEngine:
    """
    Genetic Algorithm-based Mutation Engine
    
    Evolves payloads to maximize fitness (evasion, uniqueness, etc.)
    """
    
    def __init__(self, config: MutationConfig, fitness: FitnessFunction = None):
        self.config = config
        self.fitness = fitness or EntropyFitness()
        self.population: List[Individual] = []
        self.generation = 0
        self.best_individual: Optional[Individual] = None
        self._history: List[float] = []  # Best fitness per generation
        
    def initialize(self, seed_payloads: List[bytes] = None):
        """Initialize population"""
        self.population = []
        self.generation = 0
        
        if seed_payloads:
            for payload in seed_payloads[:self.config.population_size]:
                self.population.append(Individual(payload=payload))
                
        # Fill remaining with random payloads
        while len(self.population) < self.config.population_size:
            size = random.randint(self.config.min_size, min(1024, self.config.max_size))
            payload = bytes(random.randint(0, 255) for _ in range(size))
            self.population.append(Individual(payload=payload))
            
        # Evaluate initial fitness
        self._evaluate_population()
        
    def evolve(self, generations: int = None) -> Individual:
        """Evolve population for specified generations"""
        generations = generations or self.config.max_generations
        
        for _ in range(generations):
            self._evolve_generation()
            
        return self.best_individual
        
    def _evolve_generation(self):
        """Evolve one generation"""
        self.generation += 1
        
        # Selection
        parents = self._select_parents()
        
        # Crossover
        offspring = self._crossover(parents)
        
        # Mutation
        offspring = self._mutate(offspring)
        
        # Evaluate offspring
        for ind in offspring:
            ind.fitness = self.fitness.evaluate(ind.payload)
            ind.generation = self.generation
            
        # Elitism - keep best individuals
        self.population.sort(key=lambda x: x.fitness, reverse=True)
        elite = self.population[:self.config.elite_count]
        
        # Replace population
        self.population = elite + offspring[:self.config.population_size - self.config.elite_count]
        
        # Update best
        if self.population:
            current_best = max(self.population, key=lambda x: x.fitness)
            if self.best_individual is None or current_best.fitness > self.best_individual.fitness:
                self.best_individual = current_best
                
        self._history.append(self.best_individual.fitness if self.best_individual else 0)
        
    def _evaluate_population(self):
        """Evaluate fitness of all individuals"""
        for ind in self.population:
            ind.fitness = self.fitness.evaluate(ind.payload)
            
        # Update best
        if self.population:
            self.best_individual = max(self.population, key=lambda x: x.fitness)
            
    def _select_parents(self) -> List[Individual]:
        """Tournament selection"""
        parents = []
        tournament_size = 3
        
        for _ in range(self.config.population_size):
            tournament = random.sample(self.population, min(tournament_size, len(self.population)))
            winner = max(tournament, key=lambda x: x.fitness)
            parents.append(winner)
            
        return parents
        
    def _crossover(self, parents: List[Individual]) -> List[Individual]:
        """Apply crossover to parents"""
        offspring = []
        
        for i in range(0, len(parents) - 1, 2):
            if random.random() < self.config.crossover_rate:
                child1_payload, child2_payload = CrossoverOperator.single_point(
                    parents[i].payload, parents[i + 1].payload
                )
                offspring.append(Individual(payload=child1_payload))
                offspring.append(Individual(payload=child2_payload))
            else:
                offspring.append(Individual(payload=parents[i].payload))
                offspring.append(Individual(payload=parents[i + 1].payload))
                
        return offspring
        
    def _mutate(self, offspring: List[Individual]) -> List[Individual]:
        """Apply mutations to offspring"""
        for ind in offspring:
            if random.random() < self.config.mutation_rate:
                mutation_type = random.choice(list(MutationType))
                
                if mutation_type == MutationType.BIT_FLIP:
                    ind.payload = MutationOperator.bit_flip(ind.payload)
                elif mutation_type == MutationType.BYTE_SWAP:
                    ind.payload = MutationOperator.byte_swap(ind.payload)
                elif mutation_type == MutationType.BYTE_INSERT:
                    ind.payload = MutationOperator.byte_insert(ind.payload)
                elif mutation_type == MutationType.BYTE_DELETE:
                    ind.payload = MutationOperator.byte_delete(ind.payload)
                elif mutation_type == MutationType.BLOCK_SHUFFLE:
                    ind.payload = MutationOperator.block_shuffle(ind.payload)
                elif mutation_type == MutationType.ARITHMETIC:
                    ind.payload = MutationOperator.arithmetic(ind.payload)
                elif mutation_type == MutationType.DICTIONARY:
                    ind.payload = MutationOperator.dictionary_replace(ind.payload)
                elif mutation_type == MutationType.HAVOC:
                    ind.payload = MutationOperator.havoc(ind.payload)
                    
                ind.mutations.append(mutation_type.value)
                
                # Enforce size limits
                if len(ind.payload) > self.config.max_size:
                    ind.payload = ind.payload[:self.config.max_size]
                elif len(ind.payload) < self.config.min_size:
                    padding = bytes(random.randint(0, 255) 
                                   for _ in range(self.config.min_size - len(ind.payload)))
                    ind.payload = ind.payload + padding
                    
        return offspring
        
    def get_best_payloads(self, count: int = 10) -> List[bytes]:
        """Get top N payloads"""
        sorted_pop = sorted(self.population, key=lambda x: x.fitness, reverse=True)
        return [ind.payload for ind in sorted_pop[:count]]
        
    def get_stats(self) -> Dict[str, Any]:
        """Get evolution statistics"""
        return {
            'generation': self.generation,
            'population_size': len(self.population),
            'best_fitness': self.best_individual.fitness if self.best_individual else 0,
            'avg_fitness': sum(ind.fitness for ind in self.population) / len(self.population) if self.population else 0,
            'fitness_history': self._history[-100:],  # Last 100 generations
        }


class AdaptiveMutationEngine(MutationEngine):
    """
    Adaptive Mutation Engine
    
    Automatically adjusts mutation rates based on progress.
    """
    
    def __init__(self, config: MutationConfig, fitness: FitnessFunction = None):
        super().__init__(config, fitness)
        self._stagnation_count = 0
        self._last_best_fitness = 0.0
        
    def _evolve_generation(self):
        """Evolve with adaptive mutation rate"""
        super()._evolve_generation()
        
        # Check for stagnation
        current_best = self.best_individual.fitness if self.best_individual else 0
        
        if abs(current_best - self._last_best_fitness) < 0.001:
            self._stagnation_count += 1
        else:
            self._stagnation_count = 0
            
        self._last_best_fitness = current_best
        
        # Adapt mutation rate
        if self._stagnation_count > 10:
            # Increase mutation rate to escape local optima
            self.config.mutation_rate = min(0.5, self.config.mutation_rate * 1.2)
        elif self._stagnation_count == 0:
            # Decrease mutation rate when making progress
            self.config.mutation_rate = max(0.01, self.config.mutation_rate * 0.95)
