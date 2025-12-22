"""
Behavioral Mimicry Module

Simulates human-like behavior:
- Realistic timing patterns
- Session management
- Mouse/keyboard simulation patterns
- Natural browsing behavior
"""

import asyncio
import random
import time
import math
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class BehaviorProfile(Enum):
    """Behavior profiles"""
    CASUAL = "casual"      # Slow, irregular
    BUSINESS = "business"  # Regular, focused
    POWER = "power"        # Fast, efficient
    BOT = "bot"            # Consistent timing (for comparison)


@dataclass
class BehaviorConfig:
    """Behavior configuration"""
    profile: BehaviorProfile = BehaviorProfile.CASUAL
    min_delay: float = 0.5
    max_delay: float = 5.0
    typing_speed: float = 0.1  # seconds per character
    reading_speed: float = 250  # words per minute
    click_variance: float = 0.2


@dataclass
class SessionState:
    """Session state tracking"""
    session_id: str = ""
    start_time: float = field(default_factory=time.time)
    requests: int = 0
    pages_visited: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    referrer: Optional[str] = None
    last_action: float = field(default_factory=time.time)


class HumanSimulator:
    """
    Human Behavior Simulator
    
    Generates human-like timing and interaction patterns.
    """
    
    # Timing distributions by profile
    PROFILES = {
        BehaviorProfile.CASUAL: {
            'think_time': (2.0, 10.0),
            'read_time': (3.0, 30.0),
            'click_time': (0.3, 1.5),
            'scroll_time': (0.5, 3.0),
            'typing_speed': (0.08, 0.2),
        },
        BehaviorProfile.BUSINESS: {
            'think_time': (0.5, 3.0),
            'read_time': (1.0, 10.0),
            'click_time': (0.1, 0.5),
            'scroll_time': (0.2, 1.0),
            'typing_speed': (0.05, 0.1),
        },
        BehaviorProfile.POWER: {
            'think_time': (0.1, 1.0),
            'read_time': (0.5, 5.0),
            'click_time': (0.05, 0.2),
            'scroll_time': (0.1, 0.5),
            'typing_speed': (0.03, 0.08),
        },
        BehaviorProfile.BOT: {
            'think_time': (0.1, 0.1),
            'read_time': (0.1, 0.1),
            'click_time': (0.01, 0.01),
            'scroll_time': (0.01, 0.01),
            'typing_speed': (0.001, 0.001),
        },
    }
    
    def __init__(self, config: BehaviorConfig):
        self.config = config
        self.profile = self.PROFILES[config.profile]
        self._last_action = time.time()
        
    async def think(self):
        """Simulate thinking time"""
        delay = self._get_delay('think_time')
        await asyncio.sleep(delay)
        
    async def read(self, content_length: int = 1000):
        """Simulate reading time based on content length"""
        words = content_length / 5  # Approximate words
        base_time = (words / self.config.reading_speed) * 60
        
        min_time, max_time = self.profile['read_time']
        delay = min(max(base_time, min_time), max_time)
        delay *= random.uniform(0.8, 1.2)  # Add variance
        
        await asyncio.sleep(delay)
        
    async def click(self):
        """Simulate click timing"""
        delay = self._get_delay('click_time')
        await asyncio.sleep(delay)
        
    async def scroll(self):
        """Simulate scroll timing"""
        delay = self._get_delay('scroll_time')
        await asyncio.sleep(delay)
        
    async def type_text(self, text: str):
        """Simulate typing with realistic timing"""
        min_speed, max_speed = self.profile['typing_speed']
        
        for char in text:
            # Vary typing speed
            delay = random.uniform(min_speed, max_speed)
            
            # Slower for special characters
            if char in '!@#$%^&*()':
                delay *= 1.5
                
            # Occasional pause (thinking)
            if random.random() < 0.05:
                delay += random.uniform(0.5, 2.0)
                
            await asyncio.sleep(delay)
            
    def _get_delay(self, action: str) -> float:
        """Get delay for action with variance"""
        min_delay, max_delay = self.profile[action]
        
        # Use log-normal distribution for more realistic timing
        mean = (min_delay + max_delay) / 2
        sigma = (max_delay - min_delay) / 4
        
        delay = random.lognormvariate(math.log(mean), sigma / mean)
        return max(min_delay, min(delay, max_delay * 2))
        
    def get_mouse_path(self, start: tuple, end: tuple, steps: int = 20) -> List[tuple]:
        """Generate realistic mouse movement path"""
        path = []
        
        for i in range(steps + 1):
            t = i / steps
            
            # Bezier curve with random control points
            ctrl1 = (
                start[0] + random.uniform(-50, 50),
                start[1] + random.uniform(-50, 50)
            )
            ctrl2 = (
                end[0] + random.uniform(-50, 50),
                end[1] + random.uniform(-50, 50)
            )
            
            # Cubic bezier
            x = (1-t)**3 * start[0] + 3*(1-t)**2*t * ctrl1[0] + 3*(1-t)*t**2 * ctrl2[0] + t**3 * end[0]
            y = (1-t)**3 * start[1] + 3*(1-t)**2*t * ctrl1[1] + 3*(1-t)*t**2 * ctrl2[1] + t**3 * end[1]
            
            # Add small random jitter
            x += random.uniform(-2, 2)
            y += random.uniform(-2, 2)
            
            path.append((int(x), int(y)))
            
        return path


class SessionManager:
    """
    Session Manager
    
    Manages realistic browsing sessions.
    """
    
    def __init__(self, max_sessions: int = 100):
        self.max_sessions = max_sessions
        self._sessions: Dict[str, SessionState] = {}
        self._lock = asyncio.Lock()
        
    async def create_session(self) -> SessionState:
        """Create new session"""
        async with self._lock:
            # Clean old sessions
            await self._cleanup()
            
            session_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:16]
            session = SessionState(session_id=session_id)
            
            self._sessions[session_id] = session
            return session
            
    async def get_session(self, session_id: str) -> Optional[SessionState]:
        """Get existing session"""
        return self._sessions.get(session_id)
        
    async def update_session(self, session: SessionState, page: str):
        """Update session with new page visit"""
        session.requests += 1
        session.pages_visited.append(page)
        session.referrer = session.pages_visited[-2] if len(session.pages_visited) > 1 else None
        session.last_action = time.time()
        
    async def end_session(self, session_id: str):
        """End session"""
        async with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                
    async def _cleanup(self):
        """Clean up old sessions"""
        now = time.time()
        expired = [
            sid for sid, session in self._sessions.items()
            if now - session.last_action > 1800  # 30 min timeout
        ]
        for sid in expired:
            del self._sessions[sid]
            
        # Remove oldest if over limit
        while len(self._sessions) >= self.max_sessions:
            oldest = min(self._sessions.items(), key=lambda x: x[1].last_action)
            del self._sessions[oldest[0]]
            
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        return {
            'active_sessions': len(self._sessions),
            'total_requests': sum(s.requests for s in self._sessions.values()),
            'avg_pages_per_session': sum(len(s.pages_visited) for s in self._sessions.values()) / max(len(self._sessions), 1),
        }


class BehavioralMimicry:
    """
    Behavioral Mimicry
    
    Combines all behavioral simulation for realistic traffic.
    """
    
    def __init__(self, config: BehaviorConfig = None):
        self.config = config or BehaviorConfig()
        self.simulator = HumanSimulator(self.config)
        self.session_manager = SessionManager()
        
    async def browse_page(self, session: SessionState, url: str, content_length: int = 5000):
        """Simulate browsing a page"""
        # Click to navigate
        await self.simulator.click()
        
        # Update session
        await self.session_manager.update_session(session, url)
        
        # Read content
        await self.simulator.read(content_length)
        
        # Maybe scroll
        if random.random() < 0.7:
            scroll_count = random.randint(1, 5)
            for _ in range(scroll_count):
                await self.simulator.scroll()
                
        # Think before next action
        await self.simulator.think()
        
    async def fill_form(self, session: SessionState, fields: Dict[str, str]):
        """Simulate filling a form"""
        for field_name, value in fields.items():
            # Click field
            await self.simulator.click()
            
            # Type value
            await self.simulator.type_text(value)
            
            # Small pause between fields
            await asyncio.sleep(random.uniform(0.2, 0.5))
            
        # Click submit
        await self.simulator.click()
        
    async def search(self, session: SessionState, query: str):
        """Simulate search behavior"""
        # Click search box
        await self.simulator.click()
        
        # Type query
        await self.simulator.type_text(query)
        
        # Think briefly
        await asyncio.sleep(random.uniform(0.3, 1.0))
        
        # Submit
        await self.simulator.click()
        
    def get_realistic_headers(self, session: SessionState) -> Dict[str, str]:
        """Get headers that match session state"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        
        if session.referrer:
            headers['Referer'] = session.referrer
            
        if session.cookies:
            headers['Cookie'] = '; '.join(f"{k}={v}" for k, v in session.cookies.items())
            
        return headers
