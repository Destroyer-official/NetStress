"""
Tests for the Health Check System
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock

# Import health module
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.health import (
    HealthStatus,
    ComponentType,
    HealthCheckResult,
    SystemHealth,
    HealthChecker,
    get_health_checker,
    check_health
)
from core.health.self_healing import (
    RemediationAction,
    RemediationResult,
    HealingPolicy,
    SelfHealingSystem,
    get_self_healing
)


class TestHealthStatus:
    """Test HealthStatus enum"""
    
    def test_health_status_values(self):
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestComponentType:
    """Test ComponentType enum"""
    
    def test_component_types(self):
        assert ComponentType.NETWORK.value == "network"
        assert ComponentType.MEMORY.value == "memory"
        assert ComponentType.CPU.value == "cpu"
        assert ComponentType.ENGINE.value == "engine"


class TestHealthCheckResult:
    """Test HealthCheckResult dataclass"""
    
    def test_result_creation(self):
        result = HealthCheckResult(
            component="test",
            component_type=ComponentType.NETWORK,
            status=HealthStatus.HEALTHY,
            message="Test passed"
        )
        assert result.component == "test"
        assert result.status == HealthStatus.HEALTHY
        
    def test_result_to_dict(self):
        result = HealthCheckResult(
            component="test",
            component_type=ComponentType.CPU,
            status=HealthStatus.DEGRADED,
            message="High usage",
            details={"usage": 85}
        )
        d = result.to_dict()
        assert d["component"] == "test"
        assert d["type"] == "cpu"
        assert d["status"] == "degraded"
        assert d["details"]["usage"] == 85


class TestSystemHealth:
    """Test SystemHealth dataclass"""
    
    def test_system_health_creation(self):
        checks = [
            HealthCheckResult(
                component="cpu",
                component_type=ComponentType.CPU,
                status=HealthStatus.HEALTHY,
                message="OK"
            )
        ]
        health = SystemHealth(
            status=HealthStatus.HEALTHY,
            checks=checks,
            uptime_seconds=100.0,
            version="2.0.0",
            platform="Test"
        )
        assert health.status == HealthStatus.HEALTHY
        assert len(health.checks) == 1
        
    def test_system_health_to_dict(self):
        checks = [
            HealthCheckResult(
                component="cpu",
                component_type=ComponentType.CPU,
                status=HealthStatus.HEALTHY,
                message="OK"
            ),
            HealthCheckResult(
                component="memory",
                component_type=ComponentType.MEMORY,
                status=HealthStatus.DEGRADED,
                message="High"
            )
        ]
        health = SystemHealth(
            status=HealthStatus.DEGRADED,
            checks=checks,
            uptime_seconds=100.0,
            version="2.0.0",
            platform="Test"
        )
        d = health.to_dict()
        assert d["status"] == "degraded"
        assert d["summary"]["total"] == 2
        assert d["summary"]["healthy"] == 1
        assert d["summary"]["degraded"] == 1


class TestHealthChecker:
    """Test HealthChecker class"""
    
    def test_checker_creation(self):
        checker = HealthChecker()
        assert checker is not None
        assert checker.start_time > 0
        
    def test_register_custom_check(self):
        checker = HealthChecker()
        
        def custom_check():
            return HealthCheckResult(
                component="custom",
                component_type=ComponentType.DEPENDENCY,
                status=HealthStatus.HEALTHY,
                message="Custom OK"
            )
        
        checker.register_check("custom", custom_check)
        assert "custom" in checker._custom_checks
        
    @pytest.mark.asyncio
    async def test_check_all(self):
        checker = HealthChecker()
        health = await checker.check_all()
        
        assert health is not None
        assert isinstance(health, SystemHealth)
        assert len(health.checks) > 0
        assert health.version == "2.0.0"
        
    @pytest.mark.asyncio
    async def test_cpu_check(self):
        checker = HealthChecker()
        result = await checker._check_cpu()
        
        assert result.component == "cpu"
        assert result.component_type == ComponentType.CPU
        assert result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.UNHEALTHY]
        assert "usage_percent" in result.details
        
    @pytest.mark.asyncio
    async def test_memory_check(self):
        checker = HealthChecker()
        result = await checker._check_memory()
        
        assert result.component == "memory"
        assert result.component_type == ComponentType.MEMORY
        assert "total_gb" in result.details
        assert "available_gb" in result.details
        
    @pytest.mark.asyncio
    async def test_network_check(self):
        checker = HealthChecker()
        result = await checker._check_network()
        
        assert result.component == "network"
        assert result.component_type == ComponentType.NETWORK
        
    @pytest.mark.asyncio
    async def test_engine_check(self):
        checker = HealthChecker()
        result = await checker._check_engine()
        
        assert result.component == "python_engine"
        assert result.component_type == ComponentType.ENGINE
        
    @pytest.mark.asyncio
    async def test_dependencies_check(self):
        checker = HealthChecker()
        result = await checker._check_dependencies()
        
        assert result.component == "dependencies"
        assert "available" in result.details
        
    def test_calculate_overall_status_healthy(self):
        checker = HealthChecker()
        checks = [
            HealthCheckResult("a", ComponentType.CPU, HealthStatus.HEALTHY, "OK"),
            HealthCheckResult("b", ComponentType.MEMORY, HealthStatus.HEALTHY, "OK")
        ]
        assert checker._calculate_overall_status(checks) == HealthStatus.HEALTHY
        
    def test_calculate_overall_status_degraded(self):
        checker = HealthChecker()
        checks = [
            HealthCheckResult("a", ComponentType.CPU, HealthStatus.HEALTHY, "OK"),
            HealthCheckResult("b", ComponentType.MEMORY, HealthStatus.DEGRADED, "High")
        ]
        assert checker._calculate_overall_status(checks) == HealthStatus.DEGRADED
        
    def test_calculate_overall_status_unhealthy(self):
        checker = HealthChecker()
        checks = [
            HealthCheckResult("a", ComponentType.CPU, HealthStatus.HEALTHY, "OK"),
            HealthCheckResult("b", ComponentType.MEMORY, HealthStatus.UNHEALTHY, "Critical")
        ]
        assert checker._calculate_overall_status(checks) == HealthStatus.UNHEALTHY
        
    @pytest.mark.asyncio
    async def test_check_history(self):
        checker = HealthChecker()
        await checker.check_all()
        await checker.check_all()
        
        history = checker.get_history()
        assert len(history) >= 2


class TestGlobalHealthChecker:
    """Test global health checker functions"""
    
    def test_get_health_checker(self):
        checker1 = get_health_checker()
        checker2 = get_health_checker()
        # Should return same instance
        assert checker1 is checker2
        
    @pytest.mark.asyncio
    async def test_check_health_function(self):
        health = await check_health()
        assert isinstance(health, SystemHealth)


class TestRemediationAction:
    """Test RemediationAction enum"""
    
    def test_remediation_actions(self):
        assert RemediationAction.RESTART_ENGINE.value == "restart_engine"
        assert RemediationAction.CLEAR_MEMORY.value == "clear_memory"
        assert RemediationAction.REDUCE_RATE.value == "reduce_rate"


class TestRemediationResult:
    """Test RemediationResult dataclass"""
    
    def test_result_creation(self):
        result = RemediationResult(
            action=RemediationAction.CLEAR_MEMORY,
            success=True,
            message="Memory cleared"
        )
        assert result.action == RemediationAction.CLEAR_MEMORY
        assert result.success is True


class TestHealingPolicy:
    """Test HealingPolicy dataclass"""
    
    def test_policy_creation(self):
        policy = HealingPolicy(
            component="memory",
            condition=lambda r: r.status == HealthStatus.DEGRADED,
            action=RemediationAction.CLEAR_MEMORY
        )
        assert policy.component == "memory"
        assert policy.action == RemediationAction.CLEAR_MEMORY
        assert policy.enabled is True


class TestSelfHealingSystem:
    """Test SelfHealingSystem class"""
    
    def test_system_creation(self):
        system = SelfHealingSystem()
        assert system is not None
        assert len(system._policies) > 0  # Default policies
        
    def test_add_policy(self):
        system = SelfHealingSystem()
        initial_count = len(system._policies)
        
        policy = HealingPolicy(
            component="test",
            condition=lambda r: True,
            action=RemediationAction.ALERT
        )
        system.add_policy(policy)
        
        assert len(system._policies) == initial_count + 1
        
    def test_remove_policy(self):
        system = SelfHealingSystem()
        
        policy = HealingPolicy(
            component="test_remove",
            condition=lambda r: True,
            action=RemediationAction.ALERT
        )
        system.add_policy(policy)
        
        removed = system.remove_policy("test_remove")
        assert removed is True
        
    @pytest.mark.asyncio
    async def test_clear_memory_action(self):
        system = SelfHealingSystem()
        result = await system._action_clear_memory()
        
        assert result.action == RemediationAction.CLEAR_MEMORY
        assert result.success is True
        
    @pytest.mark.asyncio
    async def test_cleanup_action(self):
        system = SelfHealingSystem()
        result = await system._action_cleanup()
        
        assert result.action == RemediationAction.CLEANUP
        assert result.success is True
        
    @pytest.mark.asyncio
    async def test_alert_action(self):
        system = SelfHealingSystem()
        check = HealthCheckResult(
            component="test",
            component_type=ComponentType.CPU,
            status=HealthStatus.UNHEALTHY,
            message="Test alert"
        )
        result = await system._action_alert(check)
        
        assert result.action == RemediationAction.ALERT
        assert result.success is True
        
    def test_get_history(self):
        system = SelfHealingSystem()
        history = system.get_history()
        assert isinstance(history, list)
        
    def test_reset_counts(self):
        system = SelfHealingSystem()
        system._action_counts["test"] = 5
        system.reset_counts()
        assert len(system._action_counts) == 0
        
    @pytest.mark.asyncio
    async def test_start_stop(self):
        system = SelfHealingSystem()
        system._check_interval = 0.1  # Fast for testing
        
        await system.start()
        assert system._running is True
        
        await asyncio.sleep(0.2)
        
        await system.stop()
        assert system._running is False


class TestGlobalSelfHealing:
    """Test global self-healing functions"""
    
    def test_get_self_healing(self):
        system1 = get_self_healing()
        system2 = get_self_healing()
        # Should return same instance
        assert system1 is system2


class TestIntegration:
    """Integration tests for health system"""
    
    @pytest.mark.asyncio
    async def test_full_health_check_cycle(self):
        """Test complete health check cycle"""
        checker = get_health_checker()
        health = await checker.check_all()
        
        # Should have multiple checks
        assert len(health.checks) >= 5
        
        # Should have valid status
        assert health.status in [
            HealthStatus.HEALTHY,
            HealthStatus.DEGRADED,
            HealthStatus.UNHEALTHY
        ]
        
        # Should have version and platform
        assert health.version == "2.0.0"
        assert len(health.platform) > 0
        
        # Should be serializable
        d = health.to_dict()
        assert "status" in d
        assert "checks" in d
        assert "summary" in d
