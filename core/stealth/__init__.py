"""Stealth capabilities for evasion and anti-detection."""

from .reflective_loader import (
    ReflectiveLoader,
    MemoryModule,
    load_module_from_memory,
    is_reflective_loading_available,
    REFLECTIVE_LOADING_AVAILABLE,
)

__all__ = [
    "ReflectiveLoader",
    "MemoryModule",
    "load_module_from_memory",
    "is_reflective_loading_available",
    "REFLECTIVE_LOADING_AVAILABLE",
]
