"""
NetStress DDoS GUI Interface Module

A comprehensive Dear PyGui-based graphical user interface for the 
Advanced DDoS Testing Framework. Provides intuitive access to all 
framework capabilities including AI optimization, multi-vector attacks,
real-time analytics, and safety controls.
"""

from .config import GUIConfig
from .state import StateManager
from .app import DDoSGUIApp

__all__ = [
    'GUIConfig',
    'StateManager', 
    'DDoSGUIApp',
]

__version__ = '1.0.0'
