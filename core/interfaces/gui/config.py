"""
GUI Configuration Module

Defines configuration dataclass and loading/saving functionality.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any


@dataclass
class GUIConfig:
    """Configuration settings for the DDoS GUI application."""
    
    # Window settings
    window_width: int = 1400
    window_height: int = 900
    window_x: int = 100
    window_y: int = 100
    maximized: bool = False
    
    # Theme settings
    theme: str = "dark"  # "dark" or "light"
    font_size: int = 14
    accent_color: str = "#00A8E8"
    
    # Refresh rates (milliseconds)
    metrics_refresh_rate: int = 100
    chart_refresh_rate: int = 250
    status_refresh_rate: int = 500
    
    # Performance settings
    max_chart_points: int = 500
    enable_animations: bool = True
    enable_3d_visualization: bool = True
    
    # Safety settings
    show_safety_warnings: bool = True
    auto_throttle_enabled: bool = True
    emergency_stop_confirmation: bool = False
    
    # Recent files
    recent_targets: list = field(default_factory=list)
    recent_profiles: list = field(default_factory=list)
    recent_workflows: list = field(default_factory=list)
    
    # Panel visibility
    visible_panels: Dict[str, bool] = field(default_factory=lambda: {
        'target_config': True,
        'protocol_selection': True,
        'ai_control': True,
        'safety_monitor': True,
        'real_time_visualizer': True,
        'report_generator': True,
        'workflow_designer': True,
    })
    
    @classmethod
    def get_config_path(cls) -> Path:
        """Get the configuration file path."""
        config_dir = Path.home() / '.netstress'
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / 'gui_config.json'
    
    @classmethod
    def load(cls, path: Optional[Path] = None) -> 'GUIConfig':
        """Load configuration from JSON file."""
        config_path = path or cls.get_config_path()
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                return cls(**data)
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Warning: Could not load config: {e}")
        
        return cls()
    
    def save(self, path: Optional[Path] = None) -> None:
        """Save configuration to JSON file."""
        config_path = path or self.get_config_path()
        
        with open(config_path, 'w') as f:
            json.dump(asdict(self), f, indent=2)
    
    def add_recent_target(self, target: str, max_items: int = 10) -> None:
        """Add a target to recent targets list."""
        if target in self.recent_targets:
            self.recent_targets.remove(target)
        self.recent_targets.insert(0, target)
        self.recent_targets = self.recent_targets[:max_items]
    
    def add_recent_profile(self, profile: str, max_items: int = 10) -> None:
        """Add a profile to recent profiles list."""
        if profile in self.recent_profiles:
            self.recent_profiles.remove(profile)
        self.recent_profiles.insert(0, profile)
        self.recent_profiles = self.recent_profiles[:max_items]
    
    def add_recent_workflow(self, workflow: str, max_items: int = 10) -> None:
        """Add a workflow to recent workflows list."""
        if workflow in self.recent_workflows:
            self.recent_workflows.remove(workflow)
        self.recent_workflows.insert(0, workflow)
        self.recent_workflows = self.recent_workflows[:max_items]
