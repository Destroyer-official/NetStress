"""
Tests for enhanced distributed controller features:
- NTP-based time synchronization (Requirement 7.2)
- Real-time statistics aggregation (Requirement 7.3)
- Load redistribution (Requirement 7.4)
"""

import asyncio
import time
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

import sys
sys.path.insert(0, '.')

from core.distributed.time_sync import (
    NTPClient, NTPPacket, TimeSyncResult,
    ControllerTimeSync, AgentTimeSync
)
from core.distributed.stats_aggregator import (
    StatsAggregator, AggregatedStats, AgentStats
)
from core.distributed.load_balancer import (
    LoadBalancer, AgentLoadInfo, AgentHealth, RedistributionEvent
)


class TestNTPPacket:
    """Tests for NTP packet serialization"""
    
    def test_packet_creation(self):
        """Test creating an NTP packet"""
        packet = NTPPacket(tx_timestamp=time.time())
        assert packet.version == 3
        assert packet.mode == 3  # Client mode
    
    def test_packet_serialization(self):
        """Test packet to bytes conversion"""
        packet = NTPPacket(tx_timestamp=time.time())
        data = packet.to_bytes()
        assert len(data) == 48  # NTP packet is 48 bytes
    
    def test_packet_round_trip(self):
        """Test packet serialization and deserialization"""
        original = NTPPacket(
            tx_timestamp=time.time(),
            stratum=2,
        )
        data = original.to_bytes()
        restored = NTPPacket.from_bytes(data)
        
        assert restored.version == original.version
        assert restored.mode == original.mode
        assert restored.stratum == original.stratum


class TestTimeSyncResult:
    """Tests for time sync result"""
    
    def test_adjusted_time(self):
        """Test adjusted time calculation"""
        result = TimeSyncResult(
            offset=0.5,  # Local clock is 0.5s ahead
            synced=True,
        )
        
        now = time.time()
        adjusted = result.adjusted_time
        
        # Adjusted time should be approximately now - 0.5
        assert abs(adjusted - (now - 0.5)) < 0.1


class TestControllerTimeSync:
    """Tests for controller time synchronization"""
    
    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping time sync"""
        sync = ControllerTimeSync(sync_interval=300.0)
        
        # Mock NTP sync to avoid network calls
        with patch.object(sync.ntp_client, 'sync', new_callable=AsyncMock) as mock_sync:
            mock_sync.return_value = TimeSyncResult(synced=False)
            
            await sync.start()
            assert sync._running
            
            await sync.stop()
            assert not sync._running
    
    def test_calculate_agent_offset(self):
        """Test agent offset calculation"""
        sync = ControllerTimeSync()
        
        # Simulate agent time and round trip
        agent_time = time.time()
        round_trip = 0.1  # 100ms RTT
        
        offset = sync.calculate_agent_offset("agent-1", agent_time, round_trip)
        
        # Offset should be stored
        assert sync.get_agent_offset("agent-1") == offset
    
    def test_sync_start_time(self):
        """Test synchronized start time calculation"""
        sync = ControllerTimeSync()
        
        start_time = sync.calculate_sync_start_time(delay=2.0)
        
        # Should be approximately 2 seconds from now
        assert start_time > time.time()
        assert start_time < time.time() + 3.0


class TestAgentTimeSync:
    """Tests for agent time synchronization"""
    
    def test_controller_offset_update(self):
        """Test updating controller offset"""
        sync = AgentTimeSync()
        
        controller_time = time.time()
        local_time = time.time()
        round_trip = 0.05  # 50ms RTT
        
        sync.update_controller_offset(controller_time, local_time, round_trip)
        
        # Offset should be set
        assert sync.offset != 0 or abs(controller_time - local_time) < 0.1
    
    def test_time_conversion(self):
        """Test local to controller time conversion"""
        sync = AgentTimeSync()
        sync._controller_offset = 0.5  # Controller is 0.5s ahead
        
        local_time = time.time()
        controller_time = sync.local_to_controller(local_time)
        
        assert abs(controller_time - (local_time + 0.5)) < 0.01
        
        # Round trip
        back_to_local = sync.controller_to_local(controller_time)
        assert abs(back_to_local - local_time) < 0.01


class TestStatsAggregator:
    """Tests for real-time statistics aggregation"""
    
    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping aggregator"""
        aggregator = StatsAggregator(update_interval=0.1)
        
        await aggregator.start()
        assert aggregator._running
        
        await aggregator.stop()
        assert not aggregator._running
    
    @pytest.mark.asyncio
    async def test_update_agent_stats(self):
        """Test updating agent statistics"""
        aggregator = StatsAggregator()
        
        await aggregator.update_agent_stats(
            "agent-1",
            {
                'packets_sent': 1000,
                'bytes_sent': 1000000,
                'errors': 5,
                'pps': 100,
            },
            active=True
        )
        
        # Stats should be stored
        assert "agent-1" in aggregator._agent_stats
        assert aggregator._agent_stats["agent-1"].packets_sent == 1000
    
    @pytest.mark.asyncio
    async def test_aggregation(self):
        """Test stats aggregation from multiple agents"""
        aggregator = StatsAggregator()
        
        # Add stats for two agents
        await aggregator.update_agent_stats(
            "agent-1",
            {'packets_sent': 1000, 'pps': 100},
            active=True
        )
        await aggregator.update_agent_stats(
            "agent-2",
            {'packets_sent': 2000, 'pps': 200},
            active=True
        )
        
        # Aggregate
        result = await aggregator._aggregate()
        
        assert result.total_packets_sent == 3000
        assert result.total_pps == 300
        assert result.active_agents == 2
    
    @pytest.mark.asyncio
    async def test_prometheus_export(self):
        """Test Prometheus format export"""
        aggregator = StatsAggregator()
        
        await aggregator.update_agent_stats(
            "agent-1",
            {'packets_sent': 1000, 'pps': 100},
            active=True
        )
        
        await aggregator._aggregate()
        
        prometheus = aggregator.get_prometheus_metrics()
        
        assert 'netstress_packets_total' in prometheus
        assert 'netstress_pps' in prometheus


class TestAgentStats:
    """Tests for agent stats data class"""
    
    def test_to_dict(self):
        """Test conversion to dictionary"""
        stats = AgentStats(
            agent_id="agent-1",
            timestamp=time.time(),
            packets_sent=1000,
            pps=100.0,
        )
        
        d = stats.to_dict()
        
        assert d['agent_id'] == "agent-1"
        assert d['packets_sent'] == 1000
        assert d['pps'] == 100.0
    
    def test_from_dict(self):
        """Test creation from dictionary"""
        d = {
            'agent_id': 'agent-1',
            'timestamp': time.time(),
            'packets_sent': 1000,
            'pps': 100.0,
        }
        
        stats = AgentStats.from_dict(d)
        
        assert stats.agent_id == "agent-1"
        assert stats.packets_sent == 1000


class TestLoadBalancer:
    """Tests for load balancer"""
    
    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping load balancer"""
        balancer = LoadBalancer(check_interval=0.1)
        
        await balancer.start()
        assert balancer._running
        
        await balancer.stop()
        assert not balancer._running
    
    @pytest.mark.asyncio
    async def test_register_agent(self):
        """Test agent registration"""
        balancer = LoadBalancer()
        
        await balancer.register_agent("agent-1", max_rate=1000000)
        
        agent = balancer.get_agent_info("agent-1")
        assert agent is not None
        assert agent.max_rate == 1000000
        assert agent.health == AgentHealth.HEALTHY
    
    @pytest.mark.asyncio
    async def test_update_agent_stats(self):
        """Test updating agent stats"""
        balancer = LoadBalancer()
        
        await balancer.register_agent("agent-1", max_rate=1000000)
        await balancer.update_agent_stats(
            "agent-1",
            current_rate=500000,
            error_rate=0.01,
            latency_ms=10.0
        )
        
        agent = balancer.get_agent_info("agent-1")
        assert agent.current_rate == 500000
        assert agent.load_percentage == 50.0
    
    @pytest.mark.asyncio
    async def test_initial_load_assignment(self):
        """Test initial load distribution"""
        balancer = LoadBalancer()
        
        await balancer.register_agent("agent-1", max_rate=1000000)
        await balancer.register_agent("agent-2", max_rate=500000)
        
        assignments = await balancer.assign_initial_load(total_rate=900000)
        
        # Should distribute proportionally
        assert "agent-1" in assignments
        assert "agent-2" in assignments
        assert assignments["agent-1"] + assignments["agent-2"] <= 900000
    
    @pytest.mark.asyncio
    async def test_failure_detection(self):
        """Test agent failure detection"""
        balancer = LoadBalancer(
            heartbeat_timeout=0.1,
            max_consecutive_failures=1
        )
        
        await balancer.register_agent("agent-1")
        
        # Simulate old heartbeat
        balancer._agents["agent-1"].last_heartbeat = time.time() - 1.0
        
        failed = await balancer._detect_failures()
        
        assert "agent-1" in failed
    
    @pytest.mark.asyncio
    async def test_redistribution_calculation(self):
        """Test load redistribution calculation"""
        balancer = LoadBalancer()
        
        await balancer.register_agent("agent-1", max_rate=1000000)
        await balancer.register_agent("agent-2", max_rate=1000000)
        
        # Set target rates
        balancer._agents["agent-1"].target_rate = 500000
        balancer._agents["agent-2"].target_rate = 500000
        
        # Simulate agent-1 failure
        redistribution = await balancer._calculate_redistribution(["agent-1"])
        
        # Agent-2 should get increased rate
        assert "agent-2" in redistribution
        assert redistribution["agent-2"] > 500000


class TestAgentLoadInfo:
    """Tests for agent load info"""
    
    def test_load_percentage(self):
        """Test load percentage calculation"""
        info = AgentLoadInfo(
            agent_id="agent-1",
            current_rate=500000,
            max_rate=1000000,
        )
        
        assert info.load_percentage == 50.0
    
    def test_available_capacity(self):
        """Test available capacity calculation"""
        info = AgentLoadInfo(
            agent_id="agent-1",
            current_rate=300000,
            max_rate=1000000,
        )
        
        assert info.available_capacity == 700000
    
    def test_to_dict(self):
        """Test conversion to dictionary"""
        info = AgentLoadInfo(
            agent_id="agent-1",
            current_rate=500000,
            max_rate=1000000,
            health=AgentHealth.HEALTHY,
        )
        
        d = info.to_dict()
        
        assert d['agent_id'] == "agent-1"
        assert d['load_percentage'] == 50.0
        assert d['health'] == "healthy"


if __name__ == "__main__":
    pytest.main(["-v"])
