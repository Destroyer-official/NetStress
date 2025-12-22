"""Performance optimization module."""

try:
    from .hardware_acceleration import HardwareAccelerator
    from .kernel_optimizations import KernelOptimizer
    from .performance_validator import PerformanceValidator
    from .zero_copy import ZeroCopyEngine
except ImportError:
    KernelOptimizer = None
    HardwareAccelerator = None
    ZeroCopyEngine = None
    PerformanceValidator = None

try:
    from .real_kernel_opts import CapabilityReport, RealKernelOptimizer, get_optimizer
    from .real_zero_copy import RealZeroCopy, ZeroCopyStatus, get_zero_copy
except ImportError:
    RealKernelOptimizer = None
    RealZeroCopy = None
    get_optimizer = None
    get_zero_copy = None
    CapabilityReport = None
    ZeroCopyStatus = None

try:
    from .ultra_engine import (
        BatchSender,
        EngineMode,
        IOUringEngine,
        MultiProtocolEngine,
        PacketBuffer,
        RateLimiter,
        UltraConfig,
        UltraEngine,
        UltraStats,
        create_ultra_engine,
    )
except ImportError:
    UltraEngine = None
    create_ultra_engine = None
    EngineMode = None
    UltraConfig = None
    UltraStats = None
    PacketBuffer = None
    BatchSender = None
    IOUringEngine = None
    RateLimiter = None
    MultiProtocolEngine = None

__all__ = [
    'KernelOptimizer',
    'HardwareAccelerator',
    'ZeroCopyEngine',
    'PerformanceValidator',
    'RealKernelOptimizer',
    'RealZeroCopy',
    'get_optimizer',
    'get_zero_copy',
    'CapabilityReport',
    'ZeroCopyStatus',
    'EngineMode',
    'UltraConfig',
    'UltraStats',
    'PacketBuffer',
    'BatchSender',
    'IOUringEngine',
    'UltraEngine',
    'RateLimiter',
    'MultiProtocolEngine',
    'create_ultra_engine',
]
