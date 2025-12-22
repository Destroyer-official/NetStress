"""
Health Check System for NetStress 2.0

Provides comprehensive system health monitoring, diagnostics,
and self-healing capabilities for production deployments.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import asyncio
import time
import platform
import socket
import logging
import psutil
import os

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentType(Enum):
    """Types of system components"""
    NETWORK = "network"
    MEMORY = "memory"
    CPU = "cpu"
    DISK = "disk"
    ENGINE = "engine"
    NATIVE = "native"
    DEPENDENCY = "dependency"


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    component_type: ComponentType
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "type": self.component_type.value,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "latency_ms": round(self.latency_ms, 2),
            "timestamp": self.timestamp
        }


@dataclass
class SystemHealth:
    """Overall system health status"""
    status: HealthStatus
    checks: List[HealthCheckResult]
    uptime_seconds: float
    version: str
    platform: str
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "checks": [c.to_dict() for c in self.checks],
            "uptime_seconds": round(self.uptime_seconds, 2),
            "version": self.version,
            "platform": self.platform,
            "timestamp": self.timestamp,
            "summary": {
                "total": len(self.checks),
                "healthy": sum(1 for c in self.checks if c.status == HealthStatus.HEALTHY),
                "degraded": sum(1 for c in self.checks if c.status == HealthStatus.DEGRADED),
                "unhealthy": sum(1 for c in self.checks if c.status == HealthStatus.UNHEALTHY)
            }
        }


class HealthChecker:
    """
    Comprehensive health checking system for NetStress.
    
    Monitors all system components and provides diagnostics.
    """
    
    def __init__(self):
        self.start_time = time.time()
        self._custom_checks: Dict[str, Callable] = {}
        self._check_history: List[SystemHealth] = []
        self._max_history = 100
        
    def register_check(self, name: str, check_func: Callable) -> None:
        """Register a custom health check"""
        self._custom_checks[name] = check_func
        
    async def check_all(self) -> SystemHealth:
        """Run all health checks and return system health"""
        checks = []
        
        # Core system checks
        checks.append(await self._check_cpu())
        checks.append(await self._check_memory())
        checks.append(await self._check_disk())
        checks.append(await self._check_network())
        checks.append(await self._check_engine())
        checks.append(await self._check_native_engine())
        checks.append(await self._check_dependencies())
        
        # Custom checks
        for name, check_func in self._custom_checks.items():
            try:
                result = await self._run_check(name, check_func)
                checks.append(result)
            except Exception as e:
                checks.append(HealthCheckResult(
                    component=name,
                    component_type=ComponentType.DEPENDENCY,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed: {e}"
                ))
        
        # Determine overall status
        overall_status = self._calculate_overall_status(checks)
        
        health = SystemHealth(
            status=overall_status,
            checks=checks,
            uptime_seconds=time.time() - self.start_time,
            version="2.0.0",
            platform=f"{platform.system()} {platform.release()}"
        )
        
        # Store in history
        self._check_history.append(health)
        if len(self._check_history) > self._max_history:
            self._check_history.pop(0)
            
        return health
    
    async def _run_check(self, name: str, check_func: Callable) -> HealthCheckResult:
        """Run a single check with timing"""
        start = time.perf_counter()
        try:
            if asyncio.iscoroutinefunction(check_func):
                result = await check_func()
            else:
                result = check_func()
            latency = (time.perf_counter() - start) * 1000
            result.latency_ms = latency
            return result
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return HealthCheckResult(
                component=name,
                component_type=ComponentType.DEPENDENCY,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                latency_ms=latency
            )
    
    async def _check_cpu(self) -> HealthCheckResult:
        """Check CPU health"""
        start = time.perf_counter()
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            
            status = HealthStatus.HEALTHY
            message = f"CPU usage: {cpu_percent}%"
            
            if cpu_percent > 90:
                status = HealthStatus.UNHEALTHY
                message = f"CPU critically high: {cpu_percent}%"
            elif cpu_percent > 70:
                status = HealthStatus.DEGRADED
                message = f"CPU elevated: {cpu_percent}%"
                
            return HealthCheckResult(
                component="cpu",
                component_type=ComponentType.CPU,
                status=status,
                message=message,
                details={
                    "usage_percent": cpu_percent,
                    "core_count": cpu_count,
                    "load_average": load_avg
                },
                latency_ms=(time.perf_counter() - start) * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                component="cpu",
                component_type=ComponentType.CPU,
                status=HealthStatus.UNKNOWN,
                message=f"Failed to check CPU: {e}",
                latency_ms=(time.perf_counter() - start) * 1000
            )
    
    async def _check_memory(self) -> HealthCheckResult:
        """Check memory health"""
        start = time.perf_counter()
        try:
            mem = psutil.virtual_memory()
            
            status = HealthStatus.HEALTHY
            message = f"Memory usage: {mem.percent}%"
            
            if mem.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Memory critically high: {mem.percent}%"
            elif mem.percent > 80:
                status = HealthStatus.DEGRADED
                message = f"Memory elevated: {mem.percent}%"
                
            return HealthCheckResult(
                component="memory",
                component_type=ComponentType.MEMORY,
                status=status,
                message=message,
                details={
                    "total_gb": round(mem.total / (1024**3), 2),
                    "available_gb": round(mem.available / (1024**3), 2),
                    "used_percent": mem.percent
                },
                latency_ms=(time.perf_counter() - start) * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                component="memory",
                component_type=ComponentType.MEMORY,
                status=HealthStatus.UNKNOWN,
                message=f"Failed to check memory: {e}",
                latency_ms=(time.perf_counter() - start) * 1000
            )
    
    async def _check_disk(self) -> HealthCheckResult:
        """Check disk health"""
        start = time.perf_counter()
        try:
            disk = psutil.disk_usage('/')
            
            status = HealthStatus.HEALTHY
            message = f"Disk usage: {disk.percent}%"
            
            if disk.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Disk critically full: {disk.percent}%"
            elif disk.percent > 85:
                status = HealthStatus.DEGRADED
                message = f"Disk space low: {disk.percent}%"
                
            return HealthCheckResult(
                component="disk",
                component_type=ComponentType.DISK,
                status=status,
                message=message,
                details={
                    "total_gb": round(disk.total / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "used_percent": disk.percent
                },
                latency_ms=(time.perf_counter() - start) * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                component="disk",
                component_type=ComponentType.DISK,
                status=HealthStatus.UNKNOWN,
                message=f"Failed to check disk: {e}",
                latency_ms=(time.perf_counter() - start) * 1000
            )
    
    async def _check_network(self) -> HealthCheckResult:
        """Check network health"""
        start = time.perf_counter()
        try:
            # Check if we can create sockets
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.close()
            
            # Get network stats
            net_io = psutil.net_io_counters()
            
            return HealthCheckResult(
                component="network",
                component_type=ComponentType.NETWORK,
                status=HealthStatus.HEALTHY,
                message="Network interfaces operational",
                details={
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "errors_in": net_io.errin,
                    "errors_out": net_io.errout
                },
                latency_ms=(time.perf_counter() - start) * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                component="network",
                component_type=ComponentType.NETWORK,
                status=HealthStatus.UNHEALTHY,
                message=f"Network check failed: {e}",
                latency_ms=(time.perf_counter() - start) * 1000
            )
    
    async def _check_engine(self) -> HealthCheckResult:
        """Check Python engine health"""
        start = time.perf_counter()
        try:
            from core.native_engine import NativePacketEngine, EngineConfig
            
            config = EngineConfig(target="127.0.0.1", port=1, protocol="udp")
            engine = NativePacketEngine(config)
            
            return HealthCheckResult(
                component="python_engine",
                component_type=ComponentType.ENGINE,
                status=HealthStatus.HEALTHY,
                message="Packet engine available",
                details={"backend": "auto"},
                latency_ms=(time.perf_counter() - start) * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                component="python_engine",
                component_type=ComponentType.ENGINE,
                status=HealthStatus.UNHEALTHY,
                message=f"Packet engine failed: {e}",
                latency_ms=(time.perf_counter() - start) * 1000
            )
    
    async def _check_native_engine(self) -> HealthCheckResult:
        """Check native Rust engine health"""
        start = time.perf_counter()
        try:
            from core.native_engine import is_native_available, get_capabilities
            
            if is_native_available():
                caps = get_capabilities()
                return HealthCheckResult(
                    component="native_engine",
                    component_type=ComponentType.NATIVE,
                    status=HealthStatus.HEALTHY,
                    message="Native Rust engine available",
                    details=caps,
                    latency_ms=(time.perf_counter() - start) * 1000
                )
            else:
                return HealthCheckResult(
                    component="native_engine",
                    component_type=ComponentType.NATIVE,
                    status=HealthStatus.DEGRADED,
                    message="Native engine not compiled (using Python fallback)",
                    details={"available": False},
                    latency_ms=(time.perf_counter() - start) * 1000
                )
        except Exception as e:
            return HealthCheckResult(
                component="native_engine",
                component_type=ComponentType.NATIVE,
                status=HealthStatus.DEGRADED,
                message=f"Native engine check: {e}",
                latency_ms=(time.perf_counter() - start) * 1000
            )
    
    async def _check_dependencies(self) -> HealthCheckResult:
        """Check required dependencies"""
        start = time.perf_counter()
        missing = []
        available = []
        
        deps = [
            ("psutil", "psutil"),
            ("asyncio", "asyncio"),
            ("socket", "socket"),
            ("ssl", "ssl"),
            ("json", "json"),
        ]
        
        for name, module in deps:
            try:
                __import__(module)
                available.append(name)
            except ImportError:
                missing.append(name)
        
        if missing:
            return HealthCheckResult(
                component="dependencies",
                component_type=ComponentType.DEPENDENCY,
                status=HealthStatus.UNHEALTHY,
                message=f"Missing dependencies: {', '.join(missing)}",
                details={"missing": missing, "available": available},
                latency_ms=(time.perf_counter() - start) * 1000
            )
        
        return HealthCheckResult(
            component="dependencies",
            component_type=ComponentType.DEPENDENCY,
            status=HealthStatus.HEALTHY,
            message="All dependencies available",
            details={"available": available},
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    def _calculate_overall_status(self, checks: List[HealthCheckResult]) -> HealthStatus:
        """Calculate overall system status from individual checks"""
        unhealthy = sum(1 for c in checks if c.status == HealthStatus.UNHEALTHY)
        degraded = sum(1 for c in checks if c.status == HealthStatus.DEGRADED)
        
        if unhealthy > 0:
            return HealthStatus.UNHEALTHY
        elif degraded > 0:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY
    
    def get_history(self) -> List[Dict[str, Any]]:
        """Get health check history"""
        return [h.to_dict() for h in self._check_history]


# Global health checker instance
_health_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get or create the global health checker"""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


async def check_health() -> SystemHealth:
    """Convenience function to check system health"""
    return await get_health_checker().check_all()


__all__ = [
    'HealthStatus',
    'ComponentType', 
    'HealthCheckResult',
    'SystemHealth',
    'HealthChecker',
    'get_health_checker',
    'check_health'
]
