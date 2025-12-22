"""Cross-platform abstraction and detection."""

from .detection import PlatformDetector
from .abstraction import (
    PlatformEngine,
    PlatformAbstraction,
    PlatformAdapter,
    WindowsAdapter,
    LinuxAdapter,
    MacOSAdapter,
    SocketConfig,
    SystemInfo,
)
from .capabilities import CapabilityMapper

__all__ = [
    "PlatformDetector",
    "PlatformEngine",
    "PlatformAbstraction",
    "PlatformAdapter",
    "WindowsAdapter",
    "LinuxAdapter",
    "MacOSAdapter",
    "SocketConfig",
    "SystemInfo",
    "CapabilityMapper",
]
