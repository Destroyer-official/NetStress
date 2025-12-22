"""
Tests for the Distributed Testing Module
"""

import pytest
import asyncio
import time
from core.distributed import (
    DistributedController, ControllerConfig,
    DistributedAgent, AgentConfig,
    ControlMessage, MessageType, AgentStatus,
    AttackCoordinator, CoordinatedAttack
)
from core.distributed.protocol import (
    AgentInfo, AttackConfig, MessageBuilder
)


class TestProtocol:
    """Tests for the communication protocol"""
    
    def test_message_serialization(self):
        """Test message serialization/deserialization"""
        msg = ControlMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="test-agent",
            sequence=1,
            payload={'status': 'idle', 'stats': {'pps': 1000}}
        )
        
        # Serialize
        data = msg.to_bytes()
        assert len(data) > 0
        
        # Deserialize
        restored = ControlMessage.from_bytes(data)
        assert restored.msg_type == msg.msg_type
        assert restored.sender_id == msg.sender_id
        assert restored.sequence == msg.sequence
        assert restored.payload == msg.payload
        
    def test_message_with_signature(self):
        """Test message with HMAC signature"""
        secret = b"test-secret-key"
        
        msg = ControlMessage(
            msg_type=MessageType.START_ATTACK,
            sender_id="controller",
            payload={'target': '192.168.1.1'}
        )
        
        # Serialize with signature
        data = msg.to_bytes(secret)
        
        # Deserialize and verify
        restored = ControlMessage.from_bytes(data, secret)
        assert restored.msg_type == msg.msg_type
        
    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected"""
        secret = b"correct-key"
        wrong_secret = b"wrong-key"
        
        msg = ControlMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="test",
        )
        
        data = msg.to_bytes(secret)
        
        with pytest.raises(ValueError, match="Invalid message signature"):
            ControlMessage.from_bytes(data, wrong_secret)
            
    def test_agent_info(self):
        """Test AgentInfo serialization"""
        agent = AgentInfo(
            agent_id="agent-1",
            hostname="test-host",
            ip_address="192.168.1.10",
            port=12345,
            status=AgentStatus.IDLE,
            capabilities={'max_pps': 100000}
        )
        
        # To dict
        d = agent.to_dict()
        assert d['agent_id'] == "agent-1"
        assert d['status'] == "idle"
        
        # From dict
        restored = AgentInfo.from_dict(d)
        assert restored.agent_id == agent.agent_id
        assert restored.status == agent.status
        
    def test_attack_config(self):
        """Test AttackConfig serialization"""
        config = AttackConfig(
            target="192.168.1.100",
            port=80,
            protocol="HTTP",
            duration=60,
            use_evasion=True,
            shaping_profile="stealthy"
        )
        
        d = config.to_dict()
        restored = AttackConfig.from_dict(d)
        
        assert restored.target == config.target
        assert restored.port == config.port
        assert restored.use_evasion == config.use_evasion
        
    def test_message_builder(self):
        """Test MessageBuilder helper"""
        builder = MessageBuilder("agent-1")
        
        # Register message
        msg = builder.register("hostname", {'cpu': 4})
        assert msg.msg_type == MessageType.REGISTER
        assert msg.sender_id == "agent-1"
        assert msg.payload['hostname'] == "hostname"
        
        # Heartbeat message
        msg = builder.heartbeat(AgentStatus.ATTACKING, {'pps': 1000})
        assert msg.msg_type == MessageType.HEARTBEAT
        assert msg.payload['status'] == "attacking"
        
        # Sequence increments
        assert builder._sequence == 2


class TestController:
    """Tests for DistributedController"""
    
    @pytest.fixture
    def controller(self):
        """Create a controller for testing"""
        config = ControllerConfig(
            bind_address="127.0.0.1",
            bind_port=0,  # Random port
            heartbeat_interval=1.0,
            heartbeat_timeout=3.0
        )
        return DistributedController(config)
        
    @pytest.mark.asyncio
    async def test_controller_start_stop(self, controller):
        """Test controller can start and stop"""
        await controller.start()
        assert controller._running
        assert controller._server is not None
        
        await controller.stop()
        assert not controller._running
        
    @pytest.mark.asyncio
    async def test_get_agents_empty(self, controller):
        """Test getting agents when none connected"""
        await controller.start()
        
        agents = controller.get_agents()
        assert len(agents) == 0
        
        await controller.stop()
        
    @pytest.mark.asyncio
    async def test_get_stats_empty(self, controller):
        """Test getting stats with no agents"""
        await controller.start()
        
        stats = controller.get_stats()
        assert stats['total_agents'] == 0
        assert stats['active_agents'] == 0
        
        await controller.stop()


class TestAgent:
    """Tests for DistributedAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create an agent for testing"""
        config = AgentConfig(
            controller_host="127.0.0.1",
            controller_port=9999,
            heartbeat_interval=1.0,
            max_reconnect_attempts=1
        )
        return DistributedAgent(config)
        
    def test_agent_creation(self, agent):
        """Test agent is created with correct defaults"""
        assert agent.agent_id.startswith("agent-")
        assert agent.status == AgentStatus.OFFLINE
        assert agent.hostname is not None
        
    def test_get_capabilities(self, agent):
        """Test capability detection"""
        caps = agent._get_capabilities()
        
        assert 'platform' in caps
        assert 'cpu_count' in caps
        assert 'memory_gb' in caps
        assert 'protocols' in caps
        assert 'TCP' in caps['protocols']
        
    def test_update_stats(self, agent):
        """Test stats update"""
        agent.update_stats(packets_sent=1000, bytes_sent=1000000)
        
        assert agent.stats['packets_sent'] == 1000
        assert agent.stats['bytes_sent'] == 1000000


class TestCoordinator:
    """Tests for AttackCoordinator"""
    
    def test_coordinated_attack_config(self):
        """Test CoordinatedAttack configuration"""
        attack = CoordinatedAttack(
            name="test_attack",
            target="192.168.1.100",
            port=80,
            protocol="HTTP",
            duration=60,
            agents_required=3,
            total_rate=100000,
            use_evasion=True
        )
        
        assert attack.name == "test_attack"
        assert attack.agents_required == 3
        assert attack.total_rate == 100000
        
    def test_multi_phase_attack(self):
        """Test multi-phase attack configuration"""
        attack = CoordinatedAttack(
            name="multi_phase",
            target="192.168.1.100",
            port=80,
            protocol="HTTP",
            phases=[
                {'protocol': 'UDP', 'duration': 30, 'rate': 50000},
                {'protocol': 'HTTP', 'duration': 30, 'rate': 100000},
                {'protocol': 'TCP', 'duration': 30, 'rate': 75000},
            ]
        )
        
        assert len(attack.phases) == 3
        assert attack.phases[0]['protocol'] == 'UDP'
        
    @pytest.mark.asyncio
    async def test_coordinator_without_controller(self):
        """Test coordinator fails gracefully without controller"""
        coordinator = AttackCoordinator()
        
        attack = CoordinatedAttack(
            name="test",
            target="192.168.1.100",
            port=80,
            protocol="HTTP"
        )
        
        with pytest.raises(RuntimeError, match="Controller not started"):
            await coordinator.execute_attack(attack)
            
    @pytest.mark.asyncio
    async def test_wait_for_agents_timeout(self):
        """Test waiting for agents times out correctly"""
        coordinator = AttackCoordinator()
        await coordinator.start_controller(ControllerConfig(
            bind_address="127.0.0.1",
            bind_port=0
        ))
        
        try:
            # Should timeout quickly
            result = await coordinator.wait_for_agents(count=1, timeout=0.5)
            assert result is False
        finally:
            await coordinator.stop_controller()


class TestIntegration:
    """Integration tests for controller-agent communication"""
    
    @pytest.mark.asyncio
    async def test_agent_connects_to_controller(self):
        """Test agent can connect to controller"""
        # Start controller
        controller_config = ControllerConfig(
            bind_address="127.0.0.1",
            bind_port=0,
            heartbeat_interval=0.5,
            use_ssl=False,
            use_mutual_tls=False
        )
        controller = DistributedController(controller_config)
        await controller.start()
        
        # Wait for controller to be ready
        await asyncio.sleep(0.1)
        
        # Get actual port
        port = controller._server.sockets[0].getsockname()[1]
        
        # Create and start agent with more retries and no SSL
        agent_config = AgentConfig(
            controller_host="127.0.0.1",
            controller_port=port,
            heartbeat_interval=0.5,
            max_reconnect_attempts=3,
            reconnect_interval=0.1,
            use_ssl=False,
            use_mutual_tls=False
        )
        agent = DistributedAgent(agent_config)
        
        try:
            # Start agent with timeout
            connected = await asyncio.wait_for(agent.start(), timeout=5.0)
            assert connected, "Agent failed to connect to controller"
            
            # Wait for registration with longer timeout
            await asyncio.sleep(1.0)
            
            # Check controller sees agent
            agents = controller.get_agents()
            assert len(agents) == 1, f"Expected 1 agent, got {len(agents)}"
            assert agents[0].status in [AgentStatus.IDLE, AgentStatus.READY], f"Agent status: {agents[0].status}"
            
        except asyncio.TimeoutError:
            pytest.fail("Agent connection timed out")
        finally:
            await agent.stop()
            await controller.stop()
