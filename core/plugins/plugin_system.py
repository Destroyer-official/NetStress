"""
Plugin System

Extensible plugin architecture for NetStress:
- Dynamic plugin loading
- Plugin lifecycle management
- Hook system for extending functionality
- Plugin configuration
- Plugin marketplace integration
"""

import os
import sys
import json
import importlib
import importlib.util
import inspect
import threading
from typing import Dict, List, Optional, Any, Callable, Type
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Types of plugins"""
    ATTACK = auto()       # New attack vectors
    EVASION = auto()      # Evasion techniques
    RECON = auto()        # Reconnaissance modules
    REPORTING = auto()    # Report generators
    INTEGRATION = auto()  # External integrations
    PROTOCOL = auto()     # Protocol handlers
    TRANSFORM = auto()    # Data transformers
    UI = auto()           # UI extensions


class HookType(Enum):
    """Available hook points"""
    PRE_ATTACK = auto()
    POST_ATTACK = auto()
    ON_PACKET_SEND = auto()
    ON_PACKET_RECEIVE = auto()
    ON_ERROR = auto()
    ON_TARGET_RESPONSE = auto()
    ON_STATS_UPDATE = auto()
    ON_SESSION_START = auto()
    ON_SESSION