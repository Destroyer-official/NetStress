"""
Self-Healing System for NetStress 2.0

Provides automatic recovery and remediation capabilities
for production deployments.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import asyncio
import time
import logging
import gc

from . import HealthStatus, HealthCheckResult, get_health_checker

logger = logging.getLogger(__name__)


class RemediationAction(Enum):
    """Types of remediation actions"""
    RESTART_ENGINE = "restart_engine"
    CLEAR_MEMORY = "clear_memory"
    REDUCE_RATE = "reduce_rate"
    RECONNECT = "reconnect"
    CLEANUP = "cleanup"
    ALERT = "alert"
    NONE = "none"


@dataclass
class RemediationResult:
    """Result of a remediation action"""
    action: RemediationAction
    success: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class HealingPolicy:
    """Policy for automatic healing"""
    component: str
    condition: Callable[[HealthCheckResult], bool]
    action: RemediationAction
    cooldown_seconds: float = 60.0
    max_attempts: int = 3
    enabled: bool = True


class SelfHealingSystem:
    """
    Automatic self-healing system for NetStress.
    
    Monitors health and automatically remediates issues.
    """
    
    def __init__(self):
        self._policies: List[HealingPolicy] = []
        self._action_history: List[RemediationResult] = []
        self._last_action_time: Dict[str, float] = {}
        self._action_counts: Dict[str, int] = {}
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._check_interval = 10.0  # seconds
        
        # Register default policies
        self._register_default_policies()
        
    def _register_default_policies(self):
        """Register default healing policies"""
        # Memory pressure policy
        self.add_policy(HealingPolicy(
            component="memory",
            condition=lambda r: r.status == HealthStatus.DEGRADED and 
                              r.details.get("used_percent", 0) > 80,
            action=RemediationAction.CLEAR_MEMORY,
            cooldown_seconds=30.0
        ))
        
        # High CPU policy
        self.add_policy(HealingPolicy(
            component="cpu",
            condition=lambda r: r.status == HealthStatus.DEGRADED and
                              r.details.get("usage_percent", 0) > 85,
            action=RemediationAction.REDUCE_RATE,
            cooldown_seconds=60.0
        ))
        
        # Engine failure policy
        self.add_policy(HealingPolicy(
            component="python_engine",
            condition=lambda r: r.status == HealthStatus.UNHEALTHY,
            action=RemediationAction.RESTART_ENGINE,
            cooldown_seconds=120.0,
            max_attempts=3
        ))
        
    def add_policy(self, policy: HealingPolicy) -> None:
        """Add a healing policy"""
        self._policies.append(policy)
        logger.debug(f"Added healing policy for {policy.component}")
        
    def remove_policy(self, component: str) -> bool:
        """Remove policies for a component"""
        initial_count = len(self._policies)
        self._policies = [p for p in self._policies if p.component != component]
        return len(self._policies) < initial_count
        
    async def start(self) -> None:
        """Start the self-healing monitor"""
        if self._running:
            return
            
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Self-healing system started")
        
    async def stop(self) -> None:
        """Stop the self-healing monitor"""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Self-healing system stopped")
        
    async def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self._running:
            try:
                await self._check_and_heal()
                await asyncio.sleep(self._check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in healing loop: {e}")
                await asyncio.sleep(self._check_interval)
                
    async def _check_and_heal(self) -> None:
        """Check health and apply remediation if needed"""
        checker = get_health_checker()
        health = await checker.check_all()
        
        for check in health.checks:
            await self._evaluate_policies(check)
            
    async def _evaluate_policies(self, check: HealthCheckResult) -> None:
        """Evaluate policies for a health check result"""
        for policy in self._policies:
            if not policy.enabled:
                continue
                
            if policy.component != check.component:
                continue
                
            # Check if condition is met
            try:
                if not policy.condition(check):
                    continue
            except Exception as e:
                logger.warning(f"Policy condition error: {e}")
                continue
                
            # Check cooldown
            key = f"{policy.component}:{policy.action.value}"
            last_time = self._last_action_time.get(key, 0)
            if time.time() - last_time < policy.cooldown_seconds:
                continue
                
            # Check max attempts
            count = self._action_counts.get(key, 0)
            if count >= policy.max_attempts:
                logger.warning(f"Max attempts reached for {key}")
                continue
                
            # Execute remediation
            result = await self._execute_action(policy.action, check)
            
            # Update tracking
            self._last_action_time[key] = time.time()
            self._action_counts[key] = count + 1
            self._action_history.append(result)
            
            # Trim history
            if len(self._action_history) > 1000:
                self._action_history = self._action_history[-500:]
                
    async def _execute_action(
        self, 
        action: RemediationAction, 
        check: HealthCheckResult
    ) -> RemediationResult:
        """Execute a remediation action"""
        logger.info(f"Executing remediation: {action.value} for {check.component}")
        
        try:
            if action == RemediationAction.CLEAR_MEMORY:
                return await self._action_clear_memory()
            elif action == RemediationAction.REDUCE_RATE:
                return await self._action_reduce_rate()
            elif action == RemediationAction.RESTART_ENGINE:
                return await self._action_restart_engine()
            elif action == RemediationAction.CLEANUP:
                return await self._action_cleanup()
            elif action == RemediationAction.ALERT:
                return await self._action_alert(check)
            else:
                return RemediationResult(
                    action=action,
                    success=False,
                    message="Unknown action"
                )
        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            return RemediationResult(
                action=action,
                success=False,
                message=str(e)
            )
            
    async def _action_clear_memory(self) -> RemediationResult:
        """Clear memory by forcing garbage collection"""
        before = gc.get_count()
        gc.collect()
        after = gc.get_count()
        
        return RemediationResult(
            action=RemediationAction.CLEAR_MEMORY,
            success=True,
            message="Garbage collection completed",
            details={
                "before": before,
                "after": after,
                "collected": sum(before) - sum(after)
            }
        )
        
    async def _action_reduce_rate(self) -> RemediationResult:
        """Signal to reduce attack rate"""
        # This would integrate with the rate controller
        return RemediationResult(
            action=RemediationAction.REDUCE_RATE,
            success=True,
            message="Rate reduction signaled",
            details={"reduction_percent": 25}
        )
        
    async def _action_restart_engine(self) -> RemediationResult:
        """Restart the packet engine"""
        # This would integrate with the engine manager
        return RemediationResult(
            action=RemediationAction.RESTART_ENGINE,
            success=True,
            message="Engine restart signaled"
        )
        
    async def _action_cleanup(self) -> RemediationResult:
        """General cleanup action"""
        gc.collect()
        return RemediationResult(
            action=RemediationAction.CLEANUP,
            success=True,
            message="Cleanup completed"
        )
        
    async def _action_alert(self, check: HealthCheckResult) -> RemediationResult:
        """Send an alert"""
        logger.warning(f"ALERT: {check.component} is {check.status.value}: {check.message}")
        return RemediationResult(
            action=RemediationAction.ALERT,
            success=True,
            message=f"Alert sent for {check.component}",
            details=check.to_dict()
        )
        
    def get_history(self) -> List[Dict[str, Any]]:
        """Get remediation history"""
        return [
            {
                "action": r.action.value,
                "success": r.success,
                "message": r.message,
                "details": r.details,
                "timestamp": r.timestamp
            }
            for r in self._action_history
        ]
        
    def reset_counts(self) -> None:
        """Reset action attempt counts"""
        self._action_counts.clear()
        logger.info("Action counts reset")


# Global self-healing instance
_self_healing: Optional[SelfHealingSystem] = None


def get_self_healing() -> SelfHealingSystem:
    """Get or create the global self-healing system"""
    global _self_healing
    if _self_healing is None:
        _self_healing = SelfHealingSystem()
    return _self_healing


__all__ = [
    'RemediationAction',
    'RemediationResult',
    'HealingPolicy',
    'SelfHealingSystem',
    'get_self_healing'
]
