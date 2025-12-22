"""Memory pools and lock-free data structures."""

from .pool_manager import MemoryPoolManager, PacketBufferPool
from .lockfree import LockFreeQueue, LockFreeStack, LockFreeCounter, AtomicReference
from .gc_optimizer import GarbageCollectionOptimizer

__all__ = [
    "MemoryPoolManager",
    "PacketBufferPool",
    "LockFreeQueue",
    "LockFreeStack",
    "LockFreeCounter",
    "AtomicReference",
    "GarbageCollectionOptimizer",
]
