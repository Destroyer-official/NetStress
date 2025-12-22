"""
Timing Pattern Module

Implements sophisticated timing patterns to evade time-based detection:
- Human-like timing
- Circadian patterns
- Random walk timing
- Adaptive timing based on response
"""

import asyncio
import random
import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, List
from collections import deque
import logging

logger = logging.getLogger(__name__)


class TimingPattern(Enum):
    """Available timing patterns"""
    CONSTANT = "constant"           # Fixed interval
    HUMAN = "human"                 # Human-like with think time
    POISSON = "poisson"             # Poisson distribution (natural events)
    CIRCADIAN = "circadian"         # Day/night pattern
    RANDOM_WALK = "random_walk"     # Gradually changing rate
    ADAPTIVE = "adaptive"           # Adapts to target response
    BROWNIAN = "brownian"           # Brownian motion timing
    HEARTBEAT = "heartbeat"         # Regular with occasional skips


@dataclass
class TimingConfig:
    """Configuration for timing patterns"""
    pattern: TimingPattern = TimingPattern.CONSTANT
    base_interval: float = 0.001    # Base interval in seconds
    min_interval: float = 0.0001    # Minimum interval
    max_interval: float = 1.0       # Maximum interval
    human_think_time: float = 0.5   # Average human think time
    poisson_lambda: float = 100.0   # Events per second for Poisson
    walk_step_size: float = 0.1     # Step size for random walk
    adaptation_rate: float = 0.1    # How fast to adapt


class TimingController:
    """
    Advanced timing controller for evasion.
    
    Controls packet timing to avoid detection patterns:
    - Avoids constant-rate detection
    - Mimics human behavior
    - Adapts to target responses
    """
    
    def __init__(self, config: Optional[TimingConfig] = None):
        self.config = config or TimingConfig()
        self.current_interval = self.config.base_interval
        self._last_time = time.monotonic()
        self._walk_position = 0.5  # For random walk (0-1 range)
        self._response_times = deque(maxlen=100)
        self._success_rate = 1.0
        self._iteration = 0
        
    async def wait(self):
        """Wait for the next timing interval"""
        interval = self.get_interval()
        if interval > 0:
            await asyncio.sleep(interval)
        self._last_time = time.monotonic()
        self._iteration += 1
        
    def get_interval(self) -> float:
        """Calculate next interval based on pattern"""
        pattern = self.config.pattern
        
        if pattern == TimingPattern.CONSTANT:
            interval = self._constant_timing()
        elif pattern == TimingPattern.HUMAN:
            interval = self._human_timing()
        elif pattern == TimingPattern.POISSON:
            interval = self._poisson_timing()
        elif pattern == TimingPattern.CIRCADIAN:
            interval = self._circadian_timing()
        elif pattern == TimingPattern.RANDOM_WALK:
            interval = self._random_walk_timing()
        elif pattern == TimingPattern.ADAPTIVE:
            interval = self._adaptive_timing()
        elif pattern == TimingPattern.BROWNIAN:
            interval = self._brownian_timing()
        elif pattern == TimingPattern.HEARTBEAT:
            interval = self._heartbeat_timing()
        else:
            interval = self.config.base_interval
            
        # Clamp to configured bounds
        interval = max(self.config.min_interval, min(self.config.max_interval, interval))
        self.current_interval = interval
        return interval
        
    def _constant_timing(self) -> float:
        """Constant interval timing"""
        return self.config.base_interval
        
    def _human_timing(self) -> float:
        """
        Human-like timing with:
        - Think time between actions
        - Occasional pauses
        - Burst of rapid actions
        """
        # Base interval
        interval = self.config.base_interval
        
        # Add think time (log-normal distribution mimics human reaction)
        think_time = random.lognormvariate(
            math.log(self.config.human_think_time), 
            0.5
        )
        
        # Occasional longer pause (checking something)
        if random.random() < 0.05:
            think_time += random.uniform(1.0, 3.0)
            
        # Occasional rapid burst (copy-paste, form fill)
        if random.random() < 0.1:
            think_time = random.uniform(0.01, 0.1)
            
        return interval + think_time
        
    def _poisson_timing(self) -> float:
        """
        Poisson process timing.
        Natural for independent random events.
        
        Uses exponential distribution for inter-arrival times,
        which is the correct distribution for Poisson processes.
        Lambda parameter controls the rate (events per second).
        """
        # Exponential inter-arrival time
        # For Poisson process with rate λ, inter-arrival times follow Exp(λ)
        return random.expovariate(self.config.poisson_lambda)
        
    def _circadian_timing(self) -> float:
        """
        Circadian rhythm - varies by time of day.
        Higher activity during "work hours".
        """
        # Get current hour (0-23)
        current_hour = time.localtime().tm_hour
        
        # Activity multiplier based on hour
        # Peak: 9-17 (work hours)
        # Low: 0-6 (night)
        if 9 <= current_hour <= 17:
            activity = 1.0
        elif 7 <= current_hour <= 8 or 18 <= current_hour <= 22:
            activity = 0.5
        else:
            activity = 0.1
            
        # Adjust interval inversely to activity
        base = self.config.base_interval
        return base / activity
        
    def _random_walk_timing(self) -> float:
        """
        Random walk timing.
        Rate gradually drifts up and down.
        """
        # Take a random step
        step = random.gauss(0, self.config.walk_step_size)
        self._walk_position += step
        
        # Bounce off boundaries
        if self._walk_position < 0:
            self._walk_position = -self._walk_position
        elif self._walk_position > 1:
            self._walk_position = 2 - self._walk_position
            
        # Map position to interval
        interval_range = self.config.max_interval - self.config.min_interval
        return self.config.min_interval + interval_range * self._walk_position
        
    def _adaptive_timing(self) -> float:
        """
        Adaptive timing based on target response.
        Slows down if errors increase, speeds up if successful.
        """
        base = self.config.base_interval
        
        # Adjust based on success rate
        if self._success_rate < 0.5:
            # High error rate - slow down significantly
            multiplier = 2.0 + (0.5 - self._success_rate) * 4
        elif self._success_rate < 0.9:
            # Some errors - slow down slightly
            multiplier = 1.0 + (0.9 - self._success_rate)
        else:
            # Good success rate - can speed up
            multiplier = 0.8
            
        # Add some randomness
        multiplier *= random.uniform(0.8, 1.2)
        
        return base * multiplier
        
    def _brownian_timing(self) -> float:
        """
        Brownian motion timing.
        Continuous random fluctuation around base.
        """
        # Wiener process increment
        dt = 0.01
        dW = random.gauss(0, math.sqrt(dt))
        
        # Update interval with drift and diffusion
        drift = 0  # No systematic drift
        diffusion = self.config.base_interval * 0.5
        
        self.current_interval += drift * dt + diffusion * dW
        
        # Keep positive
        if self.current_interval < self.config.min_interval:
            self.current_interval = self.config.min_interval
            
        return self.current_interval
        
    def _heartbeat_timing(self) -> float:
        """
        Heartbeat pattern - regular with occasional variations.
        Like a heartbeat: lub-dub, pause, lub-dub, pause...
        """
        cycle_position = self._iteration % 10
        
        if cycle_position < 2:
            # Rapid double-beat
            return self.config.min_interval
        elif cycle_position < 4:
            # Short pause
            return self.config.base_interval * 2
        elif cycle_position == 5 and random.random() < 0.1:
            # Occasional skipped beat
            return self.config.base_interval * 5
        else:
            # Normal interval
            return self.config.base_interval
            
    def record_response(self, response_time: float, success: bool):
        """Record target response for adaptive timing"""
        self._response_times.append(response_time)
        
        # Update success rate with exponential moving average
        alpha = self.config.adaptation_rate
        self._success_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * self._success_rate
        
    def get_stats(self) -> dict:
        """Get timing statistics"""
        avg_response = sum(self._response_times) / len(self._response_times) if self._response_times else 0
        return {
            'pattern': self.config.pattern.value,
            'current_interval': self.current_interval,
            'success_rate': self._success_rate,
            'avg_response_time': avg_response,
            'iterations': self._iteration,
        }
    
    def validate_distribution(self, samples: List[float], expected_pattern: TimingPattern) -> dict:
        """
        Validate that timing samples follow the expected distribution.
        
        Returns statistical test results including:
        - mean: Sample mean
        - variance: Sample variance
        - valid: Whether distribution matches expected pattern
        - p_value: Statistical significance (if applicable)
        """
        if not samples or len(samples) < 2:
            return {'valid': False, 'error': 'Insufficient samples'}
        
        n = len(samples)
        mean = sum(samples) / n
        variance = sum((x - mean) ** 2 for x in samples) / (n - 1) if n > 1 else 0
        
        result = {
            'pattern': expected_pattern.value,
            'n_samples': n,
            'mean': mean,
            'variance': variance,
            'std_dev': math.sqrt(variance) if variance > 0 else 0,
        }
        
        # For Poisson process (exponential inter-arrival times):
        # Mean should equal 1/lambda
        # Variance should equal 1/lambda^2
        if expected_pattern == TimingPattern.POISSON:
            expected_mean = 1.0 / self.config.poisson_lambda
            expected_variance = 1.0 / (self.config.poisson_lambda ** 2)
            
            # Use statistical confidence intervals instead of fixed percentages
            # For exponential distribution, standard error of mean = mean / sqrt(n)
            se_mean = expected_mean / math.sqrt(n) if n > 0 else 0
            # 95% confidence interval is approximately ±2.5 standard errors
            mean_lower = expected_mean - 2.5 * se_mean
            mean_upper = expected_mean + 2.5 * se_mean
            
            # For variance, use wider confidence interval (variance has higher variation)
            se_variance = math.sqrt(2 * expected_variance ** 2 / (n - 1)) if n > 1 else 0
            var_lower = max(0, expected_variance - 3 * se_variance)
            var_upper = expected_variance + 3 * se_variance
            
            result['expected_mean'] = expected_mean
            result['expected_variance'] = expected_variance
            result['mean_in_ci'] = mean_lower <= mean <= mean_upper
            result['variance_in_ci'] = var_lower <= variance <= var_upper
            result['valid'] = (mean_lower <= mean <= mean_upper) and (var_lower <= variance <= var_upper)
            
        # For constant timing: variance should be near zero
        elif expected_pattern == TimingPattern.CONSTANT:
            result['valid'] = variance < (mean * 0.1) ** 2  # CV < 10%
            
        # For human timing: should have higher variance
        elif expected_pattern == TimingPattern.HUMAN:
            # Human timing should have coefficient of variation > 0.3
            cv = (math.sqrt(variance) / mean) if mean > 0 else 0
            result['coefficient_of_variation'] = cv
            result['valid'] = cv > 0.3
            
        else:
            result['valid'] = True  # Other patterns don't have strict validation
            
        return result


class CompositeTimingController:
    """
    Combines multiple timing patterns for complex evasion.
    """
    
    def __init__(self, patterns: List[TimingPattern], weights: Optional[List[float]] = None):
        self.controllers = [
            TimingController(TimingConfig(pattern=p)) 
            for p in patterns
        ]
        self.weights = weights or [1.0] * len(patterns)
        
        # Normalize weights
        total = sum(self.weights)
        self.weights = [w / total for w in self.weights]
        
    async def wait(self):
        """Wait using weighted combination of patterns"""
        intervals = [c.get_interval() for c in self.controllers]
        
        # Weighted average
        interval = sum(i * w for i, w in zip(intervals, self.weights))
        
        if interval > 0:
            await asyncio.sleep(interval)
            
    def record_response(self, response_time: float, success: bool):
        """Record response to all controllers"""
        for controller in self.controllers:
            controller.record_response(response_time, success)
