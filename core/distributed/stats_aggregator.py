"""
Real-Time Statistics Aggregator

Provides real-time aggregation of statistics from distributed agents
with streaming support and historical analysis.

Implements Requirement 7.3: Real-time aggregation
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, AsyncIterator
from collections import defaultdict
import logging
import json

logger = logging.getLogger(__name__)


@dataclass
class AgentStats:
    """Statistics from a single agent"""
    agent_id: str
    timestamp: float
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    pps: float = 0.0
    bps: float = 0.0
    cpu_usage: float = 0.0
    memory_mb: float = 0.0
    sync_error_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'agent_id': self.agent_id,
            'timestamp': self.timestamp,
            'packets_sent': self.packets_sent,
            'bytes_sent': self.bytes_sent,
            'errors': self.errors,
            'pps': self.pps,
            'bps': self.bps,
            'cpu_usage': self.cpu_usage,
            'memory_mb': self.memory_mb,
            'sync_error_ms': self.sync_error_ms,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentStats':
        return cls(
            agent_id=data.get('agent_id', ''),
            timestamp=data.get('timestamp', time.time()),
            packets_sent=data.get('packets_sent', 0),
            bytes_sent=data.get('bytes_sent', 0),
            errors=data.get('errors', 0),
            pps=data.get('pps', 0.0),
            bps=data.get('bps', 0.0),
            cpu_usage=data.get('cpu_usage', 0.0),
            memory_mb=data.get('memory_mb', 0.0),
            sync_error_ms=data.get('sync_error_ms', 0.0),
        )


@dataclass
class AggregatedStats:
    """Aggregated statistics from all agents"""
    timestamp: float
    total_packets_sent: int = 0
    total_bytes_sent: int = 0
    total_errors: int = 0
    total_pps: float = 0.0
    total_bps: float = 0.0
    total_gbps: float = 0.0
    active_agents: int = 0
    total_agents: int = 0
    avg_cpu_usage: float = 0.0
    avg_memory_mb: float = 0.0
    max_sync_error_ms: float = 0.0
    avg_sync_error_ms: float = 0.0
    per_agent: Dict[str, AgentStats] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'total_packets_sent': self.total_packets_sent,
            'total_bytes_sent': self.total_bytes_sent,
            'total_errors': self.total_errors,
            'total_pps': self.total_pps,
            'total_bps': self.total_bps,
            'total_gbps': self.total_gbps,
            'active_agents': self.active_agents,
            'total_agents': self.total_agents,
            'avg_cpu_usage': self.avg_cpu_usage,
            'avg_memory_mb': self.avg_memory_mb,
            'max_sync_error_ms': self.max_sync_error_ms,
            'avg_sync_error_ms': self.avg_sync_error_ms,
            'per_agent': {k: v.to_dict() for k, v in self.per_agent.items()},
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    def to_prometheus(self) -> str:
        """Export stats in Prometheus format"""
        lines = [
            f'# HELP netstress_packets_total Total packets sent',
            f'# TYPE netstress_packets_total counter',
            f'netstress_packets_total {self.total_packets_sent}',
            f'# HELP netstress_bytes_total Total bytes sent',
            f'# TYPE netstress_bytes_total counter',
            f'netstress_bytes_total {self.total_bytes_sent}',
            f'# HELP netstress_errors_total Total errors',
            f'# TYPE netstress_errors_total counter',
            f'netstress_errors_total {self.total_errors}',
            f'# HELP netstress_pps Current packets per second',
            f'# TYPE netstress_pps gauge',
            f'netstress_pps {self.total_pps}',
            f'# HELP netstress_gbps Current gigabits per second',
            f'# TYPE netstress_gbps gauge',
            f'netstress_gbps {self.total_gbps}',
            f'# HELP netstress_active_agents Number of active agents',
            f'# TYPE netstress_active_agents gauge',
            f'netstress_active_agents {self.active_agents}',
            f'# HELP netstress_sync_error_ms Maximum sync error in milliseconds',
            f'# TYPE netstress_sync_error_ms gauge',
            f'netstress_sync_error_ms {self.max_sync_error_ms}',
        ]
        
        # Per-agent metrics
        for agent_id, stats in self.per_agent.items():
            safe_id = agent_id.replace('-', '_')
            lines.extend([
                f'netstress_agent_pps{{agent="{agent_id}"}} {stats.pps}',
                f'netstress_agent_errors{{agent="{agent_id}"}} {stats.errors}',
            ])
        
        return '\n'.join(lines)


class StatsAggregator:
    """
    Real-time statistics aggregator for distributed attacks.
    
    Features:
    - Streaming stats from multiple agents
    - Historical data storage
    - Multiple export formats (JSON, Prometheus)
    - Async iteration support
    """
    
    def __init__(self, 
                 update_interval: float = 0.1,
                 history_size: int = 1000,
                 history_interval: float = 1.0):
        self.update_interval = update_interval
        self.history_size = history_size
        self.history_interval = history_interval
        
        # Current stats per agent
        self._agent_stats: Dict[str, AgentStats] = {}
        self._agent_active: Dict[str, bool] = {}
        
        # Aggregated stats
        self._current: Optional[AggregatedStats] = None
        self._history: List[AggregatedStats] = []
        self._last_history_time: float = 0.0
        
        # Streaming
        self._subscribers: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        
        # State
        self._running = False
        self._aggregate_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start the aggregator"""
        self._running = True
        self._aggregate_task = asyncio.create_task(self._aggregate_loop())
        logger.info("Stats aggregator started")
    
    async def stop(self):
        """Stop the aggregator"""
        self._running = False
        
        if self._aggregate_task:
            self._aggregate_task.cancel()
            try:
                await self._aggregate_task
            except asyncio.CancelledError:
                pass
        
        # Close all subscriber queues
        for queue in self._subscribers:
            await queue.put(None)  # Signal end of stream
        
        logger.info("Stats aggregator stopped")
    
    async def update_agent_stats(self, agent_id: str, stats: Dict[str, Any], 
                                  active: bool = True):
        """Update statistics for an agent"""
        async with self._lock:
            self._agent_stats[agent_id] = AgentStats(
                agent_id=agent_id,
                timestamp=time.time(),
                packets_sent=stats.get('packets_sent', 0),
                bytes_sent=stats.get('bytes_sent', 0),
                errors=stats.get('errors', 0),
                pps=stats.get('pps', 0.0),
                bps=stats.get('bytes_sent', 0) * 8 / max(1, stats.get('duration', 1)),
                cpu_usage=stats.get('cpu_usage', 0.0),
                memory_mb=stats.get('memory_mb', 0.0),
                sync_error_ms=stats.get('sync_error_ms', 0.0),
            )
            self._agent_active[agent_id] = active
    
    async def remove_agent(self, agent_id: str):
        """Remove an agent from tracking"""
        async with self._lock:
            self._agent_stats.pop(agent_id, None)
            self._agent_active.pop(agent_id, None)
    
    async def _aggregate_loop(self):
        """Periodically aggregate stats and notify subscribers"""
        while self._running:
            try:
                await asyncio.sleep(self.update_interval)
                
                # Aggregate current stats
                aggregated = await self._aggregate()
                
                # Store in history at configured interval
                now = time.time()
                if now - self._last_history_time >= self.history_interval:
                    async with self._lock:
                        self._history.append(aggregated)
                        if len(self._history) > self.history_size:
                            self._history = self._history[-self.history_size:]
                        self._last_history_time = now
                
                # Notify subscribers
                for queue in self._subscribers:
                    try:
                        queue.put_nowait(aggregated)
                    except asyncio.QueueFull:
                        # Drop old stats if queue is full
                        try:
                            queue.get_nowait()
                            queue.put_nowait(aggregated)
                        except asyncio.QueueEmpty:
                            pass
                            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Aggregation error: {e}")
    
    async def _aggregate(self) -> AggregatedStats:
        """Aggregate stats from all agents"""
        async with self._lock:
            now = time.time()
            
            total_packets = 0
            total_bytes = 0
            total_errors = 0
            total_pps = 0.0
            total_bps = 0.0
            total_cpu = 0.0
            total_memory = 0.0
            sync_errors = []
            active_count = 0
            
            per_agent = {}
            
            for agent_id, stats in self._agent_stats.items():
                total_packets += stats.packets_sent
                total_bytes += stats.bytes_sent
                total_errors += stats.errors
                total_pps += stats.pps
                total_bps += stats.bps
                total_cpu += stats.cpu_usage
                total_memory += stats.memory_mb
                sync_errors.append(abs(stats.sync_error_ms))
                
                if self._agent_active.get(agent_id, False):
                    active_count += 1
                
                per_agent[agent_id] = stats
            
            agent_count = len(self._agent_stats)
            
            aggregated = AggregatedStats(
                timestamp=now,
                total_packets_sent=total_packets,
                total_bytes_sent=total_bytes,
                total_errors=total_errors,
                total_pps=total_pps,
                total_bps=total_bps,
                total_gbps=total_bps / 1_000_000_000,
                active_agents=active_count,
                total_agents=agent_count,
                avg_cpu_usage=total_cpu / max(1, agent_count),
                avg_memory_mb=total_memory / max(1, agent_count),
                max_sync_error_ms=max(sync_errors) if sync_errors else 0.0,
                avg_sync_error_ms=sum(sync_errors) / max(1, len(sync_errors)),
                per_agent=per_agent,
            )
            
            self._current = aggregated
            return aggregated
    
    def get_current(self) -> Optional[AggregatedStats]:
        """Get current aggregated stats"""
        return self._current
    
    async def get_history(self, count: int = 100) -> List[AggregatedStats]:
        """Get historical stats"""
        async with self._lock:
            return self._history[-count:]
    
    async def subscribe(self) -> asyncio.Queue:
        """Subscribe to stats stream"""
        queue = asyncio.Queue(maxsize=100)
        self._subscribers.append(queue)
        return queue
    
    async def unsubscribe(self, queue: asyncio.Queue):
        """Unsubscribe from stats stream"""
        if queue in self._subscribers:
            self._subscribers.remove(queue)
    
    async def stream(self) -> AsyncIterator[AggregatedStats]:
        """Async iterator for streaming stats"""
        queue = await self.subscribe()
        try:
            while True:
                stats = await queue.get()
                if stats is None:  # End of stream
                    break
                yield stats
        finally:
            await self.unsubscribe(queue)
    
    def get_prometheus_metrics(self) -> str:
        """Get current stats in Prometheus format"""
        if self._current:
            return self._current.to_prometheus()
        return ""
    
    def get_json_metrics(self) -> str:
        """Get current stats in JSON format"""
        if self._current:
            return self._current.to_json()
        return "{}"


class AdvancedStatsAggregator(StatsAggregator):
    """
    Advanced statistics aggregator with ML-powered analysis.
    
    Features:
    - Anomaly detection in agent performance
    - Predictive scaling recommendations
    - Performance trend analysis
    - Automatic bottleneck detection
    """
    
    def __init__(self, 
                 update_interval: float = 0.1,
                 history_size: int = 1000,
                 history_interval: float = 1.0):
        super().__init__(update_interval, history_size, history_interval)
        
        # Advanced analytics
        self._performance_baselines: Dict[str, Dict[str, float]] = {}
        self._anomaly_history: List[Dict[str, Any]] = []
        self._trend_data: Dict[str, List[float]] = defaultdict(list)
        self._bottleneck_scores: Dict[str, float] = {}
        
        # Thresholds
        self._anomaly_threshold = 2.5  # Standard deviations
        self._trend_window = 60  # Seconds
    
    async def _aggregate(self) -> AggregatedStats:
        """Enhanced aggregation with analytics"""
        base_stats = await super()._aggregate()
        
        # Perform advanced analytics
        await self._detect_anomalies(base_stats)
        await self._analyze_trends(base_stats)
        await self._detect_bottlenecks(base_stats)
        
        return base_stats
    
    async def _detect_anomalies(self, stats: AggregatedStats):
        """Detect performance anomalies across agents"""
        anomalies = []
        
        for agent_id, agent_stats in stats.per_agent.items():
            # Get or create baseline
            if agent_id not in self._performance_baselines:
                self._performance_baselines[agent_id] = {
                    'pps_mean': agent_stats.pps,
                    'pps_std': agent_stats.pps * 0.1,
                    'error_rate_mean': agent_stats.errors / max(1, agent_stats.packets_sent),
                    'samples': 1
                }
                continue
            
            baseline = self._performance_baselines[agent_id]
            
            # Check PPS anomaly
            if baseline['pps_std'] > 0:
                z_score = abs(agent_stats.pps - baseline['pps_mean']) / baseline['pps_std']
                if z_score > self._anomaly_threshold:
                    anomalies.append({
                        'agent_id': agent_id,
                        'type': 'pps_anomaly',
                        'value': agent_stats.pps,
                        'expected': baseline['pps_mean'],
                        'z_score': z_score,
                        'timestamp': time.time()
                    })
            
            # Check error rate anomaly
            current_error_rate = agent_stats.errors / max(1, agent_stats.packets_sent)
            if current_error_rate > baseline['error_rate_mean'] * 3:
                anomalies.append({
                    'agent_id': agent_id,
                    'type': 'error_rate_anomaly',
                    'value': current_error_rate,
                    'expected': baseline['error_rate_mean'],
                    'timestamp': time.time()
                })
            
            # Update baseline with exponential moving average
            alpha = 0.1
            baseline['pps_mean'] = alpha * agent_stats.pps + (1 - alpha) * baseline['pps_mean']
            baseline['pps_std'] = alpha * abs(agent_stats.pps - baseline['pps_mean']) + (1 - alpha) * baseline['pps_std']
            baseline['error_rate_mean'] = alpha * current_error_rate + (1 - alpha) * baseline['error_rate_mean']
            baseline['samples'] += 1
        
        if anomalies:
            self._anomaly_history.extend(anomalies)
            # Keep only recent anomalies
            cutoff = time.time() - 300  # 5 minutes
            self._anomaly_history = [a for a in self._anomaly_history if a['timestamp'] > cutoff]
    
    async def _analyze_trends(self, stats: AggregatedStats):
        """Analyze performance trends"""
        # Store trend data
        self._trend_data['total_pps'].append(stats.total_pps)
        self._trend_data['total_gbps'].append(stats.total_gbps)
        self._trend_data['active_agents'].append(stats.active_agents)
        self._trend_data['avg_sync_error'].append(stats.avg_sync_error_ms)
        
        # Keep only recent data
        max_samples = int(self._trend_window / self.update_interval)
        for key in self._trend_data:
            if len(self._trend_data[key]) > max_samples:
                self._trend_data[key] = self._trend_data[key][-max_samples:]
    
    async def _detect_bottlenecks(self, stats: AggregatedStats):
        """Detect performance bottlenecks"""
        self._bottleneck_scores = {}
        
        if stats.active_agents == 0:
            return
        
        # CPU bottleneck
        if stats.avg_cpu_usage > 0.9:
            self._bottleneck_scores['cpu'] = stats.avg_cpu_usage
        
        # Memory bottleneck
        if stats.avg_memory_mb > 1000:  # > 1GB average
            self._bottleneck_scores['memory'] = stats.avg_memory_mb / 2000
        
        # Sync bottleneck
        if stats.max_sync_error_ms > 100:
            self._bottleneck_scores['sync'] = min(1.0, stats.max_sync_error_ms / 500)
        
        # Network bottleneck (if PPS is low relative to agents)
        expected_pps = stats.active_agents * 100000  # 100k PPS per agent baseline
        if stats.total_pps < expected_pps * 0.5:
            self._bottleneck_scores['network'] = 1.0 - (stats.total_pps / expected_pps)
    
    def get_trend_analysis(self) -> Dict[str, Any]:
        """Get trend analysis results"""
        analysis = {}
        
        for metric, values in self._trend_data.items():
            if len(values) < 10:
                analysis[metric] = {'trend': 'insufficient_data', 'change': 0}
                continue
            
            # Calculate trend
            recent = values[-10:]
            older = values[-20:-10] if len(values) >= 20 else values[:10]
            
            recent_avg = sum(recent) / len(recent)
            older_avg = sum(older) / len(older)
            
            if older_avg > 0:
                change = (recent_avg - older_avg) / older_avg
            else:
                change = 0
            
            if change > 0.1:
                trend = 'increasing'
            elif change < -0.1:
                trend = 'decreasing'
            else:
                trend = 'stable'
            
            analysis[metric] = {
                'trend': trend,
                'change': change,
                'current': recent_avg,
                'previous': older_avg
            }
        
        return analysis
    
    def get_anomalies(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """Get recent anomalies"""
        cutoff = time.time() - (minutes * 60)
        return [a for a in self._anomaly_history if a['timestamp'] > cutoff]
    
    def get_bottlenecks(self) -> Dict[str, float]:
        """Get current bottleneck scores"""
        return self._bottleneck_scores.copy()
    
    def get_scaling_recommendations(self) -> List[str]:
        """Get scaling recommendations based on analysis"""
        recommendations = []
        
        # Check bottlenecks
        if self._bottleneck_scores.get('cpu', 0) > 0.8:
            recommendations.append("Consider adding more agents - CPU bottleneck detected")
        
        if self._bottleneck_scores.get('memory', 0) > 0.8:
            recommendations.append("Memory pressure high - reduce packet buffer sizes or add agents")
        
        if self._bottleneck_scores.get('sync', 0) > 0.5:
            recommendations.append("High sync error - check network latency between agents")
        
        if self._bottleneck_scores.get('network', 0) > 0.5:
            recommendations.append("Network bottleneck - check bandwidth or target capacity")
        
        # Check trends
        trends = self.get_trend_analysis()
        
        if trends.get('total_pps', {}).get('trend') == 'decreasing':
            recommendations.append("PPS declining - investigate agent health or target defenses")
        
        if trends.get('active_agents', {}).get('trend') == 'decreasing':
            recommendations.append("Agents dropping - check agent connectivity and health")
        
        # Check anomalies
        recent_anomalies = self.get_anomalies(minutes=2)
        if len(recent_anomalies) > 5:
            recommendations.append(f"Multiple anomalies detected ({len(recent_anomalies)}) - system may be unstable")
        
        return recommendations
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Get comprehensive analytics report"""
        current = self.get_current()
        
        return {
            'current_stats': current.to_dict() if current else {},
            'trends': self.get_trend_analysis(),
            'anomalies': self.get_anomalies(),
            'bottlenecks': self.get_bottlenecks(),
            'recommendations': self.get_scaling_recommendations(),
            'agent_baselines': {
                agent_id: {
                    'pps_mean': baseline['pps_mean'],
                    'samples': baseline['samples']
                }
                for agent_id, baseline in self._performance_baselines.items()
            }
        }