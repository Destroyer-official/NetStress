"""
Botnet Simulation Module

Simulates distributed botnet behavior for testing:
- Bot coordination and command distribution
- Hierarchical C2 structure simulation
- Attack synchronization
- Bot behavior patterns
"""

import asyncio
import random
import time
import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Set
from enum import Enum
from collections import deque
import logging

logger = logging.getLogger(__name__)


class BotState(Enum):
    """Bot states"""
    IDLE = "idle"
    ACTIVE = "active"
    ATTACKING = "attacking"
    SLEEPING = "sleeping"
    DEAD = "dead"


class CommandType(Enum):
    """C2 command types"""
    ATTACK = "attack"
    STOP = "stop"
    UPDATE = "update"
    SLEEP = "sleep"
    REPORT = "report"
    SPREAD = "spread"
    SELF_DESTRUCT = "self_destruct"


@dataclass
class BotConfig:
    """Bot configuration"""
    bot_id: str = field(default_factory=lambda: hashlib.md5(str(time.time() + random.random()).encode()).hexdigest()[:12])
    capabilities: List[str] = field(default_factory=lambda: ['http', 'tcp', 'udp'])
    max_rate: int = 1000
    jitter: float = 0.2  # Timing randomization
    sleep_interval: float = 60.0
    heartbeat_interval: float = 30.0


@dataclass
class Command:
    """C2 command"""
    cmd_type: CommandType
    target: Optional[str] = None
    port: Optional[int] = None
    duration: int = 60
    rate: int = 100
    attack_type: str = "http"
    params: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    cmd_id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8])


class SimulatedBot:
    """
    Simulated Bot Instance
    
    Represents a single bot in the botnet simulation.
    """
    
    def __init__(self, config: BotConfig):
        self.config = config
        self.state = BotState.IDLE
        self._running = False
        self._current_task: Optional[asyncio.Task] = None
        self._stats = {
            'requests_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'uptime': 0,
        }
        self._start_time = time.time()
        self._command_queue: deque = deque(maxlen=100)
        self._callbacks: List[Callable] = []
        
    @property
    def bot_id(self) -> str:
        return self.config.bot_id
        
    def add_callback(self, callback: Callable):
        """Add status callback"""
        self._callbacks.append(callback)
        
    async def start(self):
        """Start bot"""
        self._running = True
        self.state = BotState.ACTIVE
        self._start_time = time.time()
        
        # Start heartbeat
        asyncio.create_task(self._heartbeat_loop())
        
        # Start command processor
        asyncio.create_task(self._command_loop())
        
        logger.info(f"Bot {self.bot_id} started")
        
    async def stop(self):
        """Stop bot"""
        self._running = False
        self.state = BotState.DEAD
        
        if self._current_task:
            self._current_task.cancel()
            
        logger.info(f"Bot {self.bot_id} stopped")
        
    def queue_command(self, command: Command):
        """Queue command for execution"""
        self._command_queue.append(command)
        
    async def execute_command(self, command: Command):
        """Execute a command"""
        logger.debug(f"Bot {self.bot_id} executing: {command.cmd_type.value}")
        
        if command.cmd_type == CommandType.ATTACK:
            await self._execute_attack(command)
        elif command.cmd_type == CommandType.STOP:
            await self._stop_attack()
        elif command.cmd_type == CommandType.SLEEP:
            await self._sleep(command.params.get('duration', 60))
        elif command.cmd_type == CommandType.REPORT:
            return self.get_stats()
        elif command.cmd_type == CommandType.SELF_DESTRUCT:
            await self.stop()
            
    async def _execute_attack(self, command: Command):
        """Execute attack command"""
        self.state = BotState.ATTACKING
        
        target = command.target
        port = command.port or 80
        duration = command.duration
        rate = min(command.rate, self.config.max_rate)
        
        start = time.time()
        interval = 1.0 / rate
        
        while self._running and (time.time() - start) < duration:
            try:
                # Simulate attack request
                await self._send_attack_request(target, port, command.attack_type)
                self._stats['requests_sent'] += 1
                self._stats['bytes_sent'] += random.randint(100, 1500)
                
            except Exception as e:
                self._stats['errors'] += 1
                
            # Add jitter
            jitter = random.uniform(-self.config.jitter, self.config.jitter)
            await asyncio.sleep(interval * (1 + jitter))
            
        self.state = BotState.ACTIVE
        
    async def _send_attack_request(self, target: str, port: int, attack_type: str):
        """Send single attack request (simulated)"""
        # In real implementation, this would send actual traffic
        # For simulation, we just track the attempt
        await asyncio.sleep(0.001)  # Simulate network latency
        
    async def _stop_attack(self):
        """Stop current attack"""
        if self._current_task:
            self._current_task.cancel()
        self.state = BotState.ACTIVE
        
    async def _sleep(self, duration: float):
        """Enter sleep mode"""
        self.state = BotState.SLEEPING
        await asyncio.sleep(duration)
        self.state = BotState.ACTIVE
        
    async def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        while self._running:
            await asyncio.sleep(self.config.heartbeat_interval)
            
            for callback in self._callbacks:
                try:
                    callback('heartbeat', self.bot_id, self.get_stats())
                except Exception:
                    pass
                    
    async def _command_loop(self):
        """Process queued commands"""
        while self._running:
            if self._command_queue:
                command = self._command_queue.popleft()
                await self.execute_command(command)
            else:
                await asyncio.sleep(0.1)
                
    def get_stats(self) -> Dict[str, Any]:
        """Get bot statistics"""
        self._stats['uptime'] = time.time() - self._start_time
        return {
            'bot_id': self.bot_id,
            'state': self.state.value,
            'capabilities': self.config.capabilities,
            **self._stats
        }


class BotnetController:
    """
    Botnet Controller (C2 Simulation)
    
    Coordinates multiple bots for distributed attacks.
    """
    
    def __init__(self, bot_count: int = 10):
        self.bot_count = bot_count
        self.bots: Dict[str, SimulatedBot] = {}
        self._running = False
        self._attack_history: List[Dict] = []
        
    async def initialize(self):
        """Initialize botnet"""
        logger.info(f"Initializing botnet with {self.bot_count} bots")
        
        for i in range(self.bot_count):
            config = BotConfig(
                max_rate=random.randint(500, 2000),
                capabilities=random.sample(['http', 'tcp', 'udp', 'dns', 'ssl'], k=random.randint(2, 5))
            )
            bot = SimulatedBot(config)
            bot.add_callback(self._bot_callback)
            self.bots[bot.bot_id] = bot
            
        self._running = True
        
    async def start_all(self):
        """Start all bots"""
        tasks = [bot.start() for bot in self.bots.values()]
        await asyncio.gather(*tasks)
        
    async def stop_all(self):
        """Stop all bots"""
        self._running = False
        tasks = [bot.stop() for bot in self.bots.values()]
        await asyncio.gather(*tasks)
        
    def broadcast_command(self, command: Command):
        """Broadcast command to all bots"""
        for bot in self.bots.values():
            if bot.state != BotState.DEAD:
                bot.queue_command(command)
                
    def send_command(self, bot_id: str, command: Command):
        """Send command to specific bot"""
        if bot_id in self.bots:
            self.bots[bot_id].queue_command(command)
            
    async def launch_attack(self, target: str, port: int = 80, duration: int = 60,
                           rate_per_bot: int = 100, attack_type: str = "http"):
        """Launch coordinated attack"""
        command = Command(
            cmd_type=CommandType.ATTACK,
            target=target,
            port=port,
            duration=duration,
            rate=rate_per_bot,
            attack_type=attack_type
        )
        
        self._attack_history.append({
            'target': target,
            'port': port,
            'duration': duration,
            'total_rate': rate_per_bot * len(self.bots),
            'timestamp': time.time()
        })
        
        self.broadcast_command(command)
        
        logger.info(f"Launched attack on {target}:{port} with {len(self.bots)} bots")
        
    async def stop_attack(self):
        """Stop all attacks"""
        command = Command(cmd_type=CommandType.STOP)
        self.broadcast_command(command)
        
    def _bot_callback(self, event: str, bot_id: str, data: Dict):
        """Handle bot callbacks"""
        if event == 'heartbeat':
            logger.debug(f"Heartbeat from {bot_id}: {data['state']}")
            
    def get_stats(self) -> Dict[str, Any]:
        """Get botnet statistics"""
        active_bots = sum(1 for b in self.bots.values() if b.state != BotState.DEAD)
        attacking_bots = sum(1 for b in self.bots.values() if b.state == BotState.ATTACKING)
        
        total_requests = sum(b._stats['requests_sent'] for b in self.bots.values())
        total_bytes = sum(b._stats['bytes_sent'] for b in self.bots.values())
        
        return {
            'total_bots': len(self.bots),
            'active_bots': active_bots,
            'attacking_bots': attacking_bots,
            'total_requests': total_requests,
            'total_bytes': total_bytes,
            'attack_history': self._attack_history[-10:]
        }


class HierarchicalBotnet:
    """
    Hierarchical Botnet Structure
    
    Simulates multi-tier C2 architecture:
    - Master controller
    - Regional controllers
    - Bot clusters
    """
    
    def __init__(self, regions: int = 3, bots_per_region: int = 10):
        self.regions = regions
        self.bots_per_region = bots_per_region
        self.master = None
        self.regional_controllers: Dict[str, BotnetController] = {}
        
    async def initialize(self):
        """Initialize hierarchical structure"""
        logger.info(f"Initializing hierarchical botnet: {self.regions} regions, {self.bots_per_region} bots each")
        
        for i in range(self.regions):
            region_id = f"region_{i}"
            controller = BotnetController(self.bots_per_region)
            await controller.initialize()
            self.regional_controllers[region_id] = controller
            
    async def start_all(self):
        """Start all regional controllers"""
        tasks = [ctrl.start_all() for ctrl in self.regional_controllers.values()]
        await asyncio.gather(*tasks)
        
    async def stop_all(self):
        """Stop all controllers"""
        tasks = [ctrl.stop_all() for ctrl in self.regional_controllers.values()]
        await asyncio.gather(*tasks)
        
    async def coordinated_attack(self, target: str, port: int = 80, duration: int = 60,
                                 stagger: float = 0.0):
        """Launch coordinated attack from all regions"""
        for i, (region_id, controller) in enumerate(self.regional_controllers.items()):
            if stagger > 0:
                await asyncio.sleep(stagger)
                
            await controller.launch_attack(target, port, duration)
            logger.info(f"Region {region_id} joined attack")
            
    def get_total_stats(self) -> Dict[str, Any]:
        """Get combined statistics"""
        total_bots = 0
        total_requests = 0
        total_bytes = 0
        
        region_stats = {}
        for region_id, controller in self.regional_controllers.items():
            stats = controller.get_stats()
            region_stats[region_id] = stats
            total_bots += stats['total_bots']
            total_requests += stats['total_requests']
            total_bytes += stats['total_bytes']
            
        return {
            'total_bots': total_bots,
            'total_requests': total_requests,
            'total_bytes': total_bytes,
            'regions': region_stats
        }


class AttackWave:
    """
    Attack Wave Pattern
    
    Coordinates attack waves with different patterns.
    """
    
    def __init__(self, botnet: BotnetController):
        self.botnet = botnet
        
    async def pulse_attack(self, target: str, port: int, pulses: int = 5,
                          pulse_duration: int = 10, rest_duration: int = 5):
        """Pulse attack pattern"""
        for i in range(pulses):
            logger.info(f"Pulse {i+1}/{pulses}")
            await self.botnet.launch_attack(target, port, pulse_duration)
            await asyncio.sleep(pulse_duration + rest_duration)
            
    async def ramp_attack(self, target: str, port: int, duration: int = 60,
                         start_rate: int = 10, end_rate: int = 1000, steps: int = 10):
        """Ramping attack pattern"""
        step_duration = duration // steps
        rate_step = (end_rate - start_rate) // steps
        
        for i in range(steps):
            rate = start_rate + (rate_step * i)
            logger.info(f"Ramp step {i+1}/{steps} - Rate: {rate}")
            
            command = Command(
                cmd_type=CommandType.ATTACK,
                target=target,
                port=port,
                duration=step_duration,
                rate=rate
            )
            self.botnet.broadcast_command(command)
            await asyncio.sleep(step_duration)
            
    async def random_attack(self, target: str, port: int, duration: int = 60,
                           min_rate: int = 100, max_rate: int = 1000):
        """Random intensity attack"""
        start = time.time()
        
        while (time.time() - start) < duration:
            rate = random.randint(min_rate, max_rate)
            burst_duration = random.randint(5, 15)
            
            command = Command(
                cmd_type=CommandType.ATTACK,
                target=target,
                port=port,
                duration=burst_duration,
                rate=rate
            )
            self.botnet.broadcast_command(command)
            
            await asyncio.sleep(burst_duration + random.uniform(1, 5))
