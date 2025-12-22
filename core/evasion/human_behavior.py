"""
Human Behavior Simulation Module

Simulates realistic human interaction patterns:
- Mouse movement timing
- Scroll behavior patterns
- Click timing distributions
- Keyboard typing patterns
"""

import random
import math
import time
from dataclasses import dataclass
from typing import List, Tuple, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class MouseMovementPattern(Enum):
    """Mouse movement patterns"""
    LINEAR = "linear"           # Straight line movement
    BEZIER = "bezier"           # Curved bezier path
    JITTERY = "jittery"         # Small random movements
    OVERSHOOT = "overshoot"     # Overshoot then correct
    HUMAN = "human"             # Realistic human movement


class ScrollPattern(Enum):
    """Scroll behavior patterns"""
    SMOOTH = "smooth"           # Smooth continuous scroll
    STEPPED = "stepped"         # Discrete scroll steps
    READING = "reading"         # Pause-scroll-pause pattern
    SCANNING = "scanning"       # Quick scroll through content


@dataclass
class MousePosition:
    """Mouse position coordinates"""
    x: float
    y: float
    timestamp: float = 0.0


@dataclass
class HumanBehaviorConfig:
    """Configuration for human behavior simulation"""
    mouse_speed: float = 1.0            # Pixels per millisecond
    mouse_acceleration: float = 0.5     # Acceleration factor
    jitter_amount: float = 2.0          # Pixel jitter
    scroll_speed: float = 100.0         # Pixels per scroll
    reading_pause_min: float = 0.5      # Min reading pause (seconds)
    reading_pause_max: float = 3.0      # Max reading pause (seconds)
    click_delay_min: float = 0.1        # Min delay before click
    click_delay_max: float = 0.3        # Max delay before click
    double_click_interval: float = 0.25 # Double-click interval


class MouseMovementSimulator:
    """
    Simulates realistic mouse movement patterns.
    
    Generates timing and trajectory data that mimics human mouse movement:
    - Acceleration and deceleration
    - Curved paths (Bezier curves)
    - Small jitter and corrections
    - Overshoot and correction
    """
    
    def __init__(self, config: Optional[HumanBehaviorConfig] = None):
        self.config = config or HumanBehaviorConfig()
        self._current_pos = MousePosition(0, 0, time.monotonic())
        
    def generate_movement_timing(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float],
        pattern: MouseMovementPattern = MouseMovementPattern.HUMAN
    ) -> List[Tuple[float, float, float]]:
        """
        Generate mouse movement timing from start to end position.
        
        Returns list of (x, y, delay) tuples representing movement path.
        """
        if pattern == MouseMovementPattern.LINEAR:
            return self._linear_movement(start, end)
        elif pattern == MouseMovementPattern.BEZIER:
            return self._bezier_movement(start, end)
        elif pattern == MouseMovementPattern.JITTERY:
            return self._jittery_movement(start, end)
        elif pattern == MouseMovementPattern.OVERSHOOT:
            return self._overshoot_movement(start, end)
        else:  # HUMAN
            return self._human_movement(start, end)
            
    def _linear_movement(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float]
    ) -> List[Tuple[float, float, float]]:
        """Linear movement from start to end"""
        distance = math.sqrt((end[0] - start[0])**2 + (end[1] - start[1])**2)
        duration = distance / (self.config.mouse_speed * 1000)  # Convert to seconds
        
        steps = max(int(distance / 10), 5)  # At least 5 steps
        path = []
        
        for i in range(steps + 1):
            t = i / steps
            x = start[0] + (end[0] - start[0]) * t
            y = start[1] + (end[1] - start[1]) * t
            delay = duration / steps
            path.append((x, y, delay))
            
        return path
        
    def _bezier_movement(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float]
    ) -> List[Tuple[float, float, float]]:
        """Curved Bezier path movement"""
        # Generate random control points for cubic Bezier
        mid_x = (start[0] + end[0]) / 2
        mid_y = (start[1] + end[1]) / 2
        
        # Add perpendicular offset for curve
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        distance = math.sqrt(dx**2 + dy**2)
        
        if distance < 1:
            return self._linear_movement(start, end)
            
        # Perpendicular vector
        perp_x = -dy / distance
        perp_y = dx / distance
        
        # Random curve amount (10-30% of distance)
        curve_amount = random.uniform(0.1, 0.3) * distance
        
        # Control points
        cp1_x = start[0] + dx * 0.25 + perp_x * curve_amount * random.uniform(-1, 1)
        cp1_y = start[1] + dy * 0.25 + perp_y * curve_amount * random.uniform(-1, 1)
        cp2_x = start[0] + dx * 0.75 + perp_x * curve_amount * random.uniform(-1, 1)
        cp2_y = start[1] + dy * 0.75 + perp_y * curve_amount * random.uniform(-1, 1)
        
        # Generate path along Bezier curve
        steps = max(int(distance / 10), 10)
        path = []
        
        for i in range(steps + 1):
            t = i / steps
            # Cubic Bezier formula
            x = (1-t)**3 * start[0] + 3*(1-t)**2*t * cp1_x + 3*(1-t)*t**2 * cp2_x + t**3 * end[0]
            y = (1-t)**3 * start[1] + 3*(1-t)**2*t * cp1_y + 3*(1-t)*t**2 * cp2_y + t**3 * end[1]
            
            # Variable speed (accelerate then decelerate)
            speed_factor = 1.0 - abs(2*t - 1)  # Peaks at t=0.5
            speed_factor = 0.5 + speed_factor * 0.5  # Range [0.5, 1.0]
            
            delay = (1.0 / (self.config.mouse_speed * 1000 * speed_factor)) * (distance / steps)
            path.append((x, y, delay))
            
        return path
        
    def _jittery_movement(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float]
    ) -> List[Tuple[float, float, float]]:
        """Movement with small random jitter"""
        base_path = self._linear_movement(start, end)
        
        # Add jitter to intermediate points
        jittered_path = [base_path[0]]  # Keep start point
        
        for x, y, delay in base_path[1:-1]:
            jitter_x = random.gauss(0, self.config.jitter_amount)
            jitter_y = random.gauss(0, self.config.jitter_amount)
            jittered_path.append((x + jitter_x, y + jitter_y, delay))
            
        jittered_path.append(base_path[-1])  # Keep end point
        return jittered_path
        
    def _overshoot_movement(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float]
    ) -> List[Tuple[float, float, float]]:
        """Movement that overshoots then corrects"""
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        
        # Overshoot by 5-15%
        overshoot_factor = random.uniform(1.05, 1.15)
        overshoot_x = start[0] + dx * overshoot_factor
        overshoot_y = start[1] + dy * overshoot_factor
        
        # Move to overshoot point
        path = self._linear_movement(start, (overshoot_x, overshoot_y))
        
        # Correct back to target
        correction = self._linear_movement((overshoot_x, overshoot_y), end)
        path.extend(correction[1:])  # Skip duplicate point
        
        return path
        
    def _human_movement(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float]
    ) -> List[Tuple[float, float, float]]:
        """Realistic human mouse movement combining multiple patterns"""
        distance = math.sqrt((end[0] - start[0])**2 + (end[1] - start[1])**2)
        
        # Short distances: more linear
        # Long distances: more curved with possible overshoot
        if distance < 100:
            base_path = self._linear_movement(start, end)
        elif distance < 300:
            base_path = self._bezier_movement(start, end)
        else:
            # Long distance: might overshoot
            if random.random() < 0.3:
                base_path = self._overshoot_movement(start, end)
            else:
                base_path = self._bezier_movement(start, end)
                
        # Add subtle jitter to all movements
        jittered_path = [base_path[0]]
        for x, y, delay in base_path[1:-1]:
            jitter_x = random.gauss(0, self.config.jitter_amount * 0.5)
            jitter_y = random.gauss(0, self.config.jitter_amount * 0.5)
            jittered_path.append((x + jitter_x, y + jitter_y, delay))
        jittered_path.append(base_path[-1])
        
        return jittered_path


class ScrollBehaviorSimulator:
    """
    Simulates realistic scroll behavior patterns.
    
    Models different scrolling behaviors:
    - Reading: scroll, pause to read, scroll again
    - Scanning: quick scrolling through content
    - Smooth: continuous smooth scrolling
    """
    
    def __init__(self, config: Optional[HumanBehaviorConfig] = None):
        self.config = config or HumanBehaviorConfig()
        self._current_scroll = 0.0
        
    def generate_scroll_timing(
        self,
        total_distance: float,
        pattern: ScrollPattern = ScrollPattern.READING
    ) -> List[Tuple[float, float]]:
        """
        Generate scroll timing pattern.
        
        Returns list of (scroll_amount, delay) tuples.
        """
        if pattern == ScrollPattern.SMOOTH:
            return self._smooth_scroll(total_distance)
        elif pattern == ScrollPattern.STEPPED:
            return self._stepped_scroll(total_distance)
        elif pattern == ScrollPattern.READING:
            return self._reading_scroll(total_distance)
        else:  # SCANNING
            return self._scanning_scroll(total_distance)
            
    def _smooth_scroll(self, distance: float) -> List[Tuple[float, float]]:
        """Smooth continuous scrolling"""
        steps = max(int(abs(distance) / 20), 5)
        scroll_per_step = distance / steps
        delay_per_step = 0.016  # ~60 FPS
        
        return [(scroll_per_step, delay_per_step) for _ in range(steps)]
        
    def _stepped_scroll(self, distance: float) -> List[Tuple[float, float]]:
        """Discrete scroll wheel steps"""
        scroll_per_step = self.config.scroll_speed
        steps = int(abs(distance) / scroll_per_step)
        direction = 1 if distance > 0 else -1
        
        timing = []
        for _ in range(steps):
            # Variable delay between scroll steps (100-300ms)
            delay = random.uniform(0.1, 0.3)
            timing.append((scroll_per_step * direction, delay))
            
        return timing
        
    def _reading_scroll(self, distance: float) -> List[Tuple[float, float]]:
        """Reading pattern: scroll, pause, scroll, pause"""
        timing = []
        remaining = abs(distance)
        direction = 1 if distance > 0 else -1
        
        while remaining > 0:
            # Scroll a chunk (200-500 pixels)
            chunk_size = min(random.uniform(200, 500), remaining)
            scroll_steps = self._smooth_scroll(chunk_size * direction)
            timing.extend(scroll_steps)
            
            remaining -= chunk_size
            
            # Pause to "read" (0.5-3 seconds)
            if remaining > 0:
                pause = random.uniform(
                    self.config.reading_pause_min,
                    self.config.reading_pause_max
                )
                timing.append((0, pause))
                
        return timing
        
    def _scanning_scroll(self, distance: float) -> List[Tuple[float, float]]:
        """Quick scanning through content"""
        # Faster scrolling with shorter pauses
        timing = []
        remaining = abs(distance)
        direction = 1 if distance > 0 else -1
        
        while remaining > 0:
            # Larger chunks (400-800 pixels)
            chunk_size = min(random.uniform(400, 800), remaining)
            scroll_steps = self._smooth_scroll(chunk_size * direction)
            
            # Speed up the scrolling
            scroll_steps = [(amt, delay * 0.5) for amt, delay in scroll_steps]
            timing.extend(scroll_steps)
            
            remaining -= chunk_size
            
            # Brief pause (0.1-0.5 seconds)
            if remaining > 0:
                pause = random.uniform(0.1, 0.5)
                timing.append((0, pause))
                
        return timing


class ClickTimingSimulator:
    """
    Simulates realistic click timing patterns.
    
    Models:
    - Delay before clicking (aim time)
    - Double-click timing
    - Click-and-hold duration
    """
    
    def __init__(self, config: Optional[HumanBehaviorConfig] = None):
        self.config = config or HumanBehaviorConfig()
        self._last_click_time = 0.0
        
    def get_click_delay(self) -> float:
        """
        Get realistic delay before clicking.
        
        Humans don't click instantly when mouse reaches target.
        There's a small delay for visual confirmation.
        """
        # Log-normal distribution for reaction time
        mean_delay = (self.config.click_delay_min + self.config.click_delay_max) / 2
        sigma = 0.3
        
        delay = random.lognormvariate(math.log(mean_delay), sigma)
        
        # Clamp to configured bounds
        delay = max(self.config.click_delay_min, min(self.config.click_delay_max, delay))
        
        return delay
        
    def get_double_click_timing(self) -> Tuple[float, float]:
        """
        Get timing for double-click.
        
        Returns (first_click_delay, second_click_delay).
        """
        first_delay = self.get_click_delay()
        
        # Second click is faster (already aimed)
        # But not instant - humans need time to process and click again
        second_delay = random.uniform(
            self.config.double_click_interval * 0.8,
            self.config.double_click_interval * 1.2
        )
        
        return (first_delay, second_delay)
        
    def get_hold_duration(self, min_duration: float = 0.05, max_duration: float = 0.15) -> float:
        """
        Get realistic click-and-hold duration.
        
        Humans don't release mouse button instantly.
        """
        return random.uniform(min_duration, max_duration)
        
    def should_double_click(self, probability: float = 0.05) -> bool:
        """
        Determine if this should be a double-click.
        
        Some actions naturally trigger double-clicks.
        """
        return random.random() < probability


class HumanBehaviorOrchestrator:
    """
    Orchestrates multiple human behavior patterns.
    
    Combines mouse movement, scrolling, and clicking into
    realistic interaction sequences.
    """
    
    def __init__(self, config: Optional[HumanBehaviorConfig] = None):
        self.config = config or HumanBehaviorConfig()
        self.mouse = MouseMovementSimulator(config)
        self.scroll = ScrollBehaviorSimulator(config)
        self.click = ClickTimingSimulator(config)
        
    def generate_page_interaction(
        self,
        num_clicks: int = 3,
        scroll_distance: float = 1000.0
    ) -> List[dict]:
        """
        Generate a realistic page interaction sequence.
        
        Returns list of actions with timing:
        [
            {'action': 'move', 'path': [...], 'duration': 0.5},
            {'action': 'click', 'delay': 0.15},
            {'action': 'scroll', 'timing': [...], 'duration': 2.0},
            ...
        ]
        """
        actions = []
        current_pos = (random.uniform(100, 500), random.uniform(100, 300))
        
        for i in range(num_clicks):
            # Move to random position
            target_pos = (random.uniform(100, 800), random.uniform(100, 600))
            movement_path = self.mouse.generate_movement_timing(
                current_pos, 
                target_pos,
                MouseMovementPattern.HUMAN
            )
            
            movement_duration = sum(delay for _, _, delay in movement_path)
            actions.append({
                'action': 'move',
                'path': movement_path,
                'duration': movement_duration
            })
            
            # Click
            click_delay = self.click.get_click_delay()
            actions.append({
                'action': 'click',
                'delay': click_delay,
                'position': target_pos
            })
            
            current_pos = target_pos
            
            # Sometimes scroll after clicking
            if i < num_clicks - 1 and random.random() < 0.7:
                scroll_amount = random.uniform(200, 500)
                scroll_timing = self.scroll.generate_scroll_timing(
                    scroll_amount,
                    ScrollPattern.READING
                )
                scroll_duration = sum(delay for _, delay in scroll_timing)
                
                actions.append({
                    'action': 'scroll',
                    'timing': scroll_timing,
                    'duration': scroll_duration
                })
                
        return actions
        
    def get_total_interaction_time(self, actions: List[dict]) -> float:
        """Calculate total time for interaction sequence"""
        total = 0.0
        for action in actions:
            if 'duration' in action:
                total += action['duration']
            if 'delay' in action:
                total += action['delay']
        return total
