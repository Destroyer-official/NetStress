"""NetStress Core Module."""

from .native_engine import (
    NativePacketEngine,
    EngineConfig,
    EngineStats,
    EngineBackend,
    start_flood,
    build_packet,
    get_capabilities,
    is_native_available,
)

__version__ = "3.0.0"
__codename__ = "Titan"

__all__ = [
    "NativePacketEngine",
    "EngineConfig",
    "EngineStats",
    "EngineBackend",
    "start_flood",
    "build_packet",
    "get_capabilities",
    "is_native_available",
    "__version__",
    "__codename__",
]
