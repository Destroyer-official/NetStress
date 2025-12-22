"""
State Management Module

Implements StateManager with observer pattern for application state.
"""

import json
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from enum import Enum


class AttackStatus(Enum):
    """Attack status enumeration."""
    IDLE = "idle"
    PREPARING = "preparing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class TargetState:
    """State for target configuration."""
    url: str = ""
    ip_address: str = ""
    port_range: str = "80,443"
    discovered_services: List[Dict[str, Any]] = field(default_factory=list)
    detected_defenses: List[str] = field(default_factory=list)
    profile_name: str = ""


@dataclass
class AttackState:
    """State for active attacks."""
    status: AttackStatus = AttackStatus.IDLE
    active_vectors: List[str] = field(default_factory=list)
    packets_sent: int = 0
    bytes_sent: int = 0
    current_pps: float = 0.0
    current_bandwidth: float = 0.0
    error_rate: float = 0.0
    start_time: Optional[float] = None
    duration: float = 0.0


@dataclass
class AIState:
    """State for AI optimization."""
    enabled: bool = True
    active_models: List[str] = field(default_factory=list)
    current_recommendation: str = ""
    recommendation_confidence: float = 0.0
    learning_progress: float = 0.0
    detected_defenses: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SafetyState:
    """State for safety monitoring."""
    status: str = "normal"  # normal, warning, critical
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    network_usage: float = 0.0
    warnings: List[str] = field(default_factory=list)
    emergency_stop_triggered: bool = False


@dataclass
class ApplicationState:
    """Complete application state."""
    target: TargetState = field(default_factory=TargetState)
    attack: AttackState = field(default_factory=AttackState)
    ai: AIState = field(default_factory=AIState)
    safety: SafetyState = field(default_factory=SafetyState)
    current_tab: str = "dashboard"
    selected_protocols: List[str] = field(default_factory=list)


class StateManager:
    """
    Manages application state with observer pattern.
    
    Provides thread-safe state updates and notifies observers
    when state changes occur.
    """
    
    def __init__(self):
        self._state = ApplicationState()
        self._observers: Dict[str, List[Callable]] = {}
        self._lock = threading.RLock()
    
    @property
    def state(self) -> ApplicationState:
        """Get current application state."""
        with self._lock:
            return self._state
    
    def subscribe(self, event: str, callback: Callable) -> None:
        """Subscribe to state change events."""
        with self._lock:
            if event not in self._observers:
                self._observers[event] = []
            self._observers[event].append(callback)
    
    def unsubscribe(self, event: str, callback: Callable) -> None:
        """Unsubscribe from state change events."""
        with self._lock:
            if event in self._observers:
                self._observers[event].remove(callback)
    
    def _notify(self, event: str, data: Any = None) -> None:
        """Notify observers of state change."""
        observers = []
        with self._lock:
            if event in self._observers:
                observers = self._observers[event].copy()
        
        for callback in observers:
            try:
                callback(data)
            except Exception as e:
                print(f"Observer error: {e}")
    
    def update_target(self, **kwargs) -> None:
        """Update target state."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._state.target, key):
                    setattr(self._state.target, key, value)
        self._notify('target_changed', self._state.target)
    
    def update_attack(self, **kwargs) -> None:
        """Update attack state."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._state.attack, key):
                    setattr(self._state.attack, key, value)
        self._notify('attack_changed', self._state.attack)
    
    def update_ai(self, **kwargs) -> None:
        """Update AI state."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._state.ai, key):
                    setattr(self._state.ai, key, value)
        self._notify('ai_changed', self._state.ai)
    
    def update_safety(self, **kwargs) -> None:
        """Update safety state."""
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._state.safety, key):
                    setattr(self._state.safety, key, value)
        self._notify('safety_changed', self._state.safety)
    
    def set_current_tab(self, tab: str) -> None:
        """Set current active tab."""
        with self._lock:
            self._state.current_tab = tab
        self._notify('tab_changed', tab)
    
    def set_selected_protocols(self, protocols: List[str]) -> None:
        """Set selected protocols."""
        with self._lock:
            self._state.selected_protocols = protocols.copy()
        self._notify('protocols_changed', protocols)
    
    def save_state(self, path: Optional[Path] = None) -> None:
        """Save current state to file."""
        state_path = path or (Path.home() / '.netstress' / 'gui_state.json')
        state_path.parent.mkdir(parents=True, exist_ok=True)
        
        with self._lock:
            state_dict = {
                'target': asdict(self._state.target),
                'current_tab': self._state.current_tab,
                'selected_protocols': self._state.selected_protocols,
            }
        
        with open(state_path, 'w') as f:
            json.dump(state_dict, f, indent=2)
    
    def load_state(self, path: Optional[Path] = None) -> None:
        """Load state from file."""
        state_path = path or (Path.home() / '.netstress' / 'gui_state.json')
        
        if not state_path.exists():
            return
        
        try:
            with open(state_path, 'r') as f:
                state_dict = json.load(f)
            
            with self._lock:
                if 'target' in state_dict:
                    self._state.target = TargetState(**state_dict['target'])
                if 'current_tab' in state_dict:
                    self._state.current_tab = state_dict['current_tab']
                if 'selected_protocols' in state_dict:
                    self._state.selected_protocols = state_dict['selected_protocols']
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Warning: Could not load state: {e}")
    
    def reset(self) -> None:
        """Reset state to defaults."""
        with self._lock:
            self._state = ApplicationState()
        self._notify('state_reset', None)
