"""Traffic shaping and protocol obfuscation for evasion."""

import random
import time

from .protocol_obfuscation import ProtocolObfuscator, ObfuscationMethod, ObfuscationConfig
from .timing_patterns import TimingController, TimingPattern, TimingConfig
from .ja4_engine import JA4Engine, JA4Morpher, BrowserProfile, ClientHelloBuilder

try:
    from core.native_engine import TrafficShaper, ShapingProfile, ShapingConfig, AdaptiveShaper
except ImportError:

    class ShapingProfile:
        AGGRESSIVE = "aggressive"
        STEALTHY = "stealthy"
        BURST = "burst"
        RANDOM = "random"

    class ShapingConfig:
        def __init__(self, **kwargs):
            self.profile = kwargs.get("profile", ShapingProfile.AGGRESSIVE)
            self.max_rate = kwargs.get("max_rate", 1000)
            self.base_rate = kwargs.get("base_rate", 1000)
            self.burst_size = kwargs.get("burst_size", 10)
            self.burst_interval = kwargs.get("burst_interval", 1.0)
            self.jitter_percent = kwargs.get("jitter_percent", 0.1)
            for k, v in kwargs.items():
                setattr(self, k, v)

    class TrafficShaper:
        def __init__(self, config=None):
            self.config = config or ShapingConfig()
            self.packets_sent = 0
            self.burst_count = 0
            self.last_burst_time = time.time()

        def get_delay(self) -> float:
            profile = getattr(self.config, "profile", ShapingProfile.AGGRESSIVE)

            if profile == ShapingProfile.AGGRESSIVE:
                max_rate = getattr(self.config, "max_rate", 100000)
                return 0.5 / max_rate if max_rate > 0 else 0.0001

            elif profile == ShapingProfile.STEALTHY:
                base_rate = getattr(self.config, "base_rate", 100)
                return 1.0 / base_rate if base_rate > 0 else 0.01

            elif profile == ShapingProfile.BURST:
                burst_size = getattr(self.config, "burst_size", 10)
                burst_interval = getattr(self.config, "burst_interval", 1.0)
                current_time = time.time()

                if current_time - self.last_burst_time >= burst_interval:
                    self.burst_count = 0
                    self.last_burst_time = current_time

                if self.burst_count < burst_size:
                    self.burst_count += 1
                    return 0.001
                return burst_interval / burst_size

            elif profile == ShapingProfile.RANDOM:
                base_rate = getattr(self.config, "base_rate", 1000)
                jitter_percent = getattr(self.config, "jitter_percent", 0.5)
                base_delay = 1.0 / base_rate if base_rate > 0 else 0.001
                jitter = random.uniform(-jitter_percent, jitter_percent)
                return base_delay * (1 + jitter)

            return 0.001

        def record_send(self, count: int) -> None:
            self.packets_sent += count

        def get_stats(self) -> dict:
            return {
                "packets_sent": self.packets_sent,
                "profile": getattr(self.config, "profile", "fallback"),
                "target_rate": getattr(self.config, "base_rate", 1000),
            }

    class AdaptiveShaper(TrafficShaper):
        pass


__all__ = [
    "TrafficShaper",
    "ShapingProfile",
    "ShapingConfig",
    "AdaptiveShaper",
    "ProtocolObfuscator",
    "ObfuscationMethod",
    "ObfuscationConfig",
    "TimingController",
    "TimingPattern",
    "TimingConfig",
    "JA4Engine",
    "JA4Morpher",
    "BrowserProfile",
    "ClientHelloBuilder",
]
