"""
Load Balancer for Distributed Attacks

Handles detection of agent failures and redistribution of load
to remaining agents for fault-tolerant distributed testing.

Implements Requirement 7.4: Load redistribution
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AgentHealth(Enum):
    """Health status of an agent"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # High latency or errors
    UNRESPONSIVE = "unresponsive"  # Missed heartbeats
    FAILED = "failed"  # Confirmed failure
    RECOVERING = "recovering"  # Coming back online


@dataclass
class AgentLoadInfo:
    """Load information for an agent"""
    agent_id: str
    current_rate: int = 0  # Current PPS
    max_rate: int = 1000000  # Maximum PPS capacity
    target_rate: int = 0  # Assigned target rate
    error_rate: float = 0.0  # Errors per second
    latency_ms: float = 0.0  # Average latency
    last_heartbeat: float = 0.0
    health: AgentHealth = AgentHealth.HEALTHY
    consecutive_failures: int = 0
    
    @property
    def load_percentage(self) -> float:
        """Current load as percentage of capacity"""
        if self.max_rate <= 0:
            return 0.0
        return (self.current_rate / self.max_rate) * 100
    
    @property
    def available_capacity(self) -> int:
        """Available capacity in PPS"""
        return max(0, self.max_rate - self.current_rate)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'agent_id': self.agent_id,
            'current_rate': self.current_rate,
            'max_rate': self.max_rate,
            'target_rate': self.target_rate,
            'load_percentage': self.load_percentage,
            'available_capacity': self.available_capacity,
            'error_rate': self.error_rate,
            'latency_ms': self.latency_ms,
            'health': self.health.value,
        }


@dataclass
class RedistributionEvent:
    """Record of a load redistribution event"""
    timestamp: float
    reason: str
    failed_agents: List[str]
    affected_agents: List[str]
    rate_changes: Dict[str, int]  # agent_id -> new rate
    success: bool
    error: Optional[str] = None


class LoadBalancer:
    """
    Load balancer for distributed attack coordination.
    
    Features:
    - Agent health monitoring
    - Automatic failure detection
    - Load redistribution on failure
    - Capacity-aware load assignment
    """
    
    def __init__(self,
                 heartbeat_timeout: float = 15.0,
                 degraded_threshold: float = 0.8,  # 80% load = degraded
                 error_threshold: float = 0.1,  # 10% error rate = degraded
                 max_consecutive_failures: int = 3,
                 check_interval: float = 5.0):
        self.heartbeat_timeout = heartbeat_timeout
        self.degraded_threshold = degraded_threshold
        self.error_threshold = error_threshold
        self.max_consecutive_failures = max_consecutive_failures
        self.check_interval = check_interval
        
        # Agent tracking
        self._agents: Dict[str, AgentLoadInfo] = {}
        self._failed_agents: List[str] = []
        
        # Redistribution history
        self._redistribution_history: List[RedistributionEvent] = []
        
        # Callbacks
        self._on_failure_callbacks: List[Callable] = []
        self._on_redistribution_callbacks: List[Callable] = []
        
        # State
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
    
    async def start(self):
        """Start the load balancer"""
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Load balancer started")
    
    async def stop(self):
        """Stop the load balancer"""
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Load balancer stopped")
    
    async def register_agent(self, agent_id: str, max_rate: int = 1000000):
        """Register an agent with the load balancer"""
        async with self._lock:
            self._agents[agent_id] = AgentLoadInfo(
                agent_id=agent_id,
                max_rate=max_rate,
                last_heartbeat=time.time(),
                health=AgentHealth.HEALTHY,
            )
            logger.info(f"Agent {agent_id} registered with capacity {max_rate} PPS")
    
    async def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        async with self._lock:
            self._agents.pop(agent_id, None)
            if agent_id in self._failed_agents:
                self._failed_agents.remove(agent_id)
            logger.info(f"Agent {agent_id} unregistered")
    
    async def update_agent_stats(self, agent_id: str, 
                                  current_rate: int,
                                  error_rate: float = 0.0,
                                  latency_ms: float = 0.0):
        """Update agent statistics"""
        async with self._lock:
            if agent_id not in self._agents:
                return
            
            agent = self._agents[agent_id]
            agent.current_rate = current_rate
            agent.error_rate = error_rate
            agent.latency_ms = latency_ms
            agent.last_heartbeat = time.time()
            
            # Update health based on metrics
            self._update_agent_health(agent)
    
    def _update_agent_health(self, agent: AgentLoadInfo):
        """Update agent health status based on metrics"""
        old_health = agent.health
        
        # Check for degraded conditions
        if agent.load_percentage >= self.degraded_threshold * 100:
            agent.health = AgentHealth.DEGRADED
        elif agent.error_rate >= self.error_threshold:
            agent.health = AgentHealth.DEGRADED
        elif agent.health == AgentHealth.RECOVERING:
            # Stay in recovering until confirmed healthy
            agent.consecutive_failures = 0
            agent.health = AgentHealth.HEALTHY
        elif agent.health in [AgentHealth.UNRESPONSIVE, AgentHealth.FAILED]:
            # Agent is back, mark as recovering
            agent.health = AgentHealth.RECOVERING
            agent.consecutive_failures = 0
        else:
            agent.health = AgentHealth.HEALTHY
            agent.consecutive_failures = 0
        
        if old_health != agent.health:
            logger.info(f"Agent {agent.agent_id} health: {old_health.value} -> {agent.health.value}")
    
    async def _monitor_loop(self):
        """Monitor agent health and trigger redistribution"""
        while self._running:
            try:
                await asyncio.sleep(self.check_interval)
                
                # Check for failed agents
                failed = await self._detect_failures()
                
                if failed:
                    logger.warning(f"Detected {len(failed)} failed agent(s)")
                    await self._handle_failures(failed)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
    
    async def _detect_failures(self) -> List[str]:
        """Detect agents that have failed"""
        failed = []
        now = time.time()
        
        async with self._lock:
            for agent_id, agent in self._agents.items():
                if agent_id in self._failed_agents:
                    continue
                
                # Check heartbeat timeout
                if now - agent.last_heartbeat > self.heartbeat_timeout:
                    agent.consecutive_failures += 1
                    
                    if agent.consecutive_failures >= self.max_consecutive_failures:
                        agent.health = AgentHealth.FAILED
                        failed.append(agent_id)
                        logger.warning(f"Agent {agent_id} marked as FAILED "
                                     f"(no heartbeat for {now - agent.last_heartbeat:.1f}s)")
                    else:
                        agent.health = AgentHealth.UNRESPONSIVE
                        logger.warning(f"Agent {agent_id} unresponsive "
                                     f"({agent.consecutive_failures}/{self.max_consecutive_failures})")
        
        return failed
    
    async def _handle_failures(self, failed_agents: List[str]):
        """Handle agent failures by redistributing load"""
        # Notify failure callbacks
        for callback in self._on_failure_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(failed_agents)
                else:
                    callback(failed_agents)
            except Exception as e:
                logger.error(f"Failure callback error: {e}")
        
        # Mark as failed
        self._failed_agents.extend(failed_agents)
        
        # Calculate redistribution
        redistribution = await self._calculate_redistribution(failed_agents)
        
        if redistribution:
            # Record event
            event = RedistributionEvent(
                timestamp=time.time(),
                reason="agent_failure",
                failed_agents=failed_agents,
                affected_agents=list(redistribution.keys()),
                rate_changes=redistribution,
                success=True,
            )
            self._redistribution_history.append(event)
            
            # Notify redistribution callbacks
            for callback in self._on_redistribution_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(redistribution)
                    else:
                        callback(redistribution)
                except Exception as e:
                    logger.error(f"Redistribution callback error: {e}")
    
    async def _calculate_redistribution(self, failed_agents: List[str]) -> Dict[str, int]:
        """Calculate new rate assignments after failures"""
        async with self._lock:
            # Get healthy agents
            healthy = [
                a for a in self._agents.values()
                if a.agent_id not in self._failed_agents
                and a.health in [AgentHealth.HEALTHY, AgentHealth.DEGRADED]
            ]
            
            if not healthy:
                logger.error("No healthy agents available for redistribution")
                return {}
            
            # Calculate total rate from failed agents
            failed_rate = sum(
                self._agents[aid].target_rate
                for aid in failed_agents
                if aid in self._agents
            )
            
            if failed_rate == 0:
                return {}
            
            # Distribute based on available capacity
            total_capacity = sum(a.available_capacity for a in healthy)
            
            redistribution = {}
            remaining_rate = failed_rate
            
            for agent in healthy:
                if total_capacity > 0:
                    # Proportional distribution based on capacity
                    share = (agent.available_capacity / total_capacity) * failed_rate
                else:
                    # Equal distribution
                    share = failed_rate / len(healthy)
                
                new_rate = agent.target_rate + int(share)
                # Cap at max rate
                new_rate = min(new_rate, agent.max_rate)
                
                redistribution[agent.agent_id] = new_rate
                agent.target_rate = new_rate
                remaining_rate -= int(share)
            
            logger.info(f"Redistributed {failed_rate} PPS from {len(failed_agents)} failed agent(s) "
                       f"to {len(healthy)} healthy agent(s)")
            
            return redistribution
    
    async def assign_initial_load(self, total_rate: int) -> Dict[str, int]:
        """Assign initial load distribution across all agents"""
        async with self._lock:
            healthy = [
                a for a in self._agents.values()
                if a.health in [AgentHealth.HEALTHY, AgentHealth.RECOVERING]
            ]
            
            if not healthy:
                return {}
            
            # Distribute based on capacity
            total_capacity = sum(a.max_rate for a in healthy)
            
            assignments = {}
            for agent in healthy:
                if total_capacity > 0:
                    share = (agent.max_rate / total_capacity) * total_rate
                else:
                    share = total_rate / len(healthy)
                
                rate = min(int(share), agent.max_rate)
                assignments[agent.agent_id] = rate
                agent.target_rate = rate
            
            return assignments
    
    def on_failure(self, callback: Callable):
        """Register callback for agent failures"""
        self._on_failure_callbacks.append(callback)
    
    def on_redistribution(self, callback: Callable):
        """Register callback for load redistribution"""
        self._on_redistribution_callbacks.append(callback)
    
    def get_agent_info(self, agent_id: str) -> Optional[AgentLoadInfo]:
        """Get info for a specific agent"""
        return self._agents.get(agent_id)
    
    def get_all_agents(self) -> List[AgentLoadInfo]:
        """Get info for all agents"""
        return list(self._agents.values())
    
    def get_healthy_agents(self) -> List[AgentLoadInfo]:
        """Get info for healthy agents only"""
        return [
            a for a in self._agents.values()
            if a.health in [AgentHealth.HEALTHY, AgentHealth.DEGRADED]
            and a.agent_id not in self._failed_agents
        ]
    
    def get_failed_agents(self) -> List[str]:
        """Get list of failed agent IDs"""
        return list(self._failed_agents)
    
    def get_redistribution_history(self) -> List[RedistributionEvent]:
        """Get history of redistribution events"""
        return list(self._redistribution_history)
    
    async def recover_agent(self, agent_id: str):
        """Mark a previously failed agent as recovering"""
        async with self._lock:
            if agent_id in self._failed_agents:
                self._failed_agents.remove(agent_id)
            
            if agent_id in self._agents:
                self._agents[agent_id].health = AgentHealth.RECOVERING
                self._agents[agent_id].consecutive_failures = 0
                self._agents[agent_id].last_heartbeat = time.time()
                logger.info(f"Agent {agent_id} marked as recovering")
