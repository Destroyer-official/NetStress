"""Real-time target monitoring for AI feedback optimization."""

import asyncio
import socket
import time
import random
import statistics
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Deque
from collections import deque

import aiohttp

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
]


@dataclass
class ProbeResult:
    """Single probe attempt result."""
    timestamp: float
    response_time_ms: float
    status_code: int
    success: bool
    error: Optional[str] = None
    bytes_received: int = 0


@dataclass
class NetworkConditions:
    """Network conditions from measurements."""
    latency_ms: float = 0.0
    latency_jitter_ms: float = 0.0
    packet_loss_percent: float = 0.0
    estimated_bandwidth_bps: float = 0.0
    last_updated: float = field(default_factory=time.time)


@dataclass
class TargetResponse:
    """Aggregated target response metrics."""
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    success_rate: float = 0.0
    last_status_code: int = 0
    samples: int = 0
    target_degraded: bool = False
    target_down: bool = False


class SideChannelProber:
    """Target monitoring with stealth timing jitter."""

    def __init__(
        self,
        target: str,
        probe_interval: float = 2.0,
        window_size: int = 30,
        timeout: float = 5.0,
        stealth_mode: bool = True,
        jitter_range: float = 0.5,
    ):
        self.target = target
        self.probe_interval = probe_interval
        self.window_size = window_size
        self.timeout = timeout
        self.stealth_mode = stealth_mode
        self.jitter_range = jitter_range

        self._parse_target()

        self._results: Deque[ProbeResult] = deque(maxlen=window_size)
        self._latency_samples: Deque[float] = deque(maxlen=window_size)
        self._target_response = TargetResponse()
        self._network_conditions = NetworkConditions()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._baseline_latency: Optional[float] = None
        self._baseline_response_time: Optional[float] = None

    def _parse_target(self) -> None:
        """Parse target URL into components."""
        target = self.target
        self.protocol = "http"
        self.port = 80

        if "://" in target:
            proto, rest = target.split("://", 1)
            self.protocol = proto.lower()
            target = rest

        if self.protocol == "https":
            self.port = 443

        if ":" in target:
            host_part, port_part = target.rsplit(":", 1)
            if "]" in target:
                host_part = target.rsplit("]:", 1)[0] + "]"
                port_part = target.rsplit("]:", 1)[1] if "]:" in target else "80"
            try:
                self.port = int(port_part.split("/")[0])
                target = host_part
            except ValueError:
                pass

        self.host = target.split("/")[0].strip("[]")
        self.path = "/" + "/".join(target.split("/")[1:]) if "/" in target else "/"
        self.probe_url = f"{self.protocol}://{self.host}:{self.port}{self.path}"

    def _get_jittered_interval(self) -> float:
        """Get probe interval with random jitter."""
        if self.stealth_mode:
            jitter = random.uniform(-self.jitter_range, self.jitter_range)
            return max(0.5, self.probe_interval * (1 + jitter))
        return self.probe_interval

    async def start(self) -> None:
        """Start the prober."""
        if self._running:
            return
        self._running = True
        logger.info(f"Starting prober for {self.probe_url}")
        await self._measure_baseline()
        self._task = asyncio.create_task(self._probe_loop())

    async def stop(self) -> None:
        """Stop the prober."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Prober stopped")

    async def _measure_baseline(self) -> None:
        """Measure baseline metrics."""
        baseline_times: List[float] = []
        baseline_latencies: List[float] = []

        for _ in range(5):
            result = await self._http_probe()
            if result.success:
                baseline_times.append(result.response_time_ms)
            latency = await self._tcp_latency_probe()
            if latency > 0:
                baseline_latencies.append(latency)
            await asyncio.sleep(0.5)

        if baseline_times:
            self._baseline_response_time = statistics.mean(baseline_times)
        if baseline_latencies:
            self._baseline_latency = statistics.mean(baseline_latencies)

    async def _probe_loop(self) -> None:
        """Main probe loop."""
        while self._running:
            try:
                result = await self._http_probe()
                self._results.append(result)

                latency = await self._tcp_latency_probe()
                if latency > 0:
                    self._latency_samples.append(latency)

                self._update_metrics()
                await asyncio.sleep(self._get_jittered_interval())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Probe error: {e}")
                await asyncio.sleep(self._get_jittered_interval())

    async def _http_probe(self) -> ProbeResult:
        """HTTP probe with stealth headers."""
        start_time = time.time()

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {}
            if self.stealth_mode:
                headers = {
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                }

            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(
                    self.probe_url, ssl=False, allow_redirects=False
                ) as response:
                    data = await response.read()
                    elapsed = (time.time() - start_time) * 1000
                    return ProbeResult(
                        timestamp=start_time,
                        response_time_ms=elapsed,
                        status_code=response.status,
                        success=True,
                        bytes_received=len(data),
                    )
        except asyncio.TimeoutError:
            elapsed = (time.time() - start_time) * 1000
            return ProbeResult(
                timestamp=start_time,
                response_time_ms=elapsed,
                status_code=0,
                success=False,
                error="timeout",
            )
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return ProbeResult(
                timestamp=start_time,
                response_time_ms=elapsed,
                status_code=0,
                success=False,
                error=str(e),
            )

    async def _tcp_latency_probe(self) -> float:
        """Measure TCP SYN-ACK latency."""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            loop = asyncio.get_event_loop()

            try:
                await asyncio.wait_for(
                    loop.sock_connect(sock, (self.host, self.port)),
                    timeout=self.timeout,
                )
                return (time.time() - start_time) * 1000
            except asyncio.TimeoutError:
                return -1
            finally:
                sock.close()
        except Exception:
            return -1

    def _update_metrics(self) -> None:
        """Update aggregated metrics."""
        if not self._results:
            return

        successful = [r for r in self._results if r.success]

        if successful:
            response_times = [r.response_time_ms for r in successful]
            self._target_response = TargetResponse(
                avg_response_time_ms=statistics.mean(response_times),
                min_response_time_ms=min(response_times),
                max_response_time_ms=max(response_times),
                success_rate=len(successful) / len(self._results),
                last_status_code=successful[-1].status_code,
                samples=len(self._results),
                target_degraded=self._is_degraded(response_times),
                target_down=False,
            )
        else:
            self._target_response = TargetResponse(
                avg_response_time_ms=self.timeout * 1000,
                success_rate=0.0,
                samples=len(self._results),
                target_degraded=True,
                target_down=True,
            )

        if self._latency_samples:
            latencies = list(self._latency_samples)
            self._network_conditions = NetworkConditions(
                latency_ms=statistics.mean(latencies),
                latency_jitter_ms=statistics.stdev(latencies) if len(latencies) > 1 else 0,
                packet_loss_percent=(1 - len(successful) / len(self._results)) * 100,
                estimated_bandwidth_bps=self._estimate_bandwidth(),
                last_updated=time.time(),
            )

    def _is_degraded(self, response_times: List[float]) -> bool:
        """Check if target is degraded vs baseline."""
        if not self._baseline_response_time:
            return False
        return statistics.mean(response_times) > (self._baseline_response_time * 3)

    def _estimate_bandwidth(self) -> float:
        """Estimate bandwidth from probe data."""
        successful = [r for r in self._results if r.success and r.bytes_received > 0]
        if not successful:
            return 0.0
        total_bytes = sum(r.bytes_received for r in successful)
        total_time = sum(r.response_time_ms for r in successful) / 1000
        return (total_bytes * 8) / total_time if total_time > 0 else 0.0

    def get_target_response(self) -> Dict:
        """Get target response metrics."""
        return {
            "response_time": self._target_response.avg_response_time_ms,
            "status_code": self._target_response.last_status_code,
            "success_rate": self._target_response.success_rate,
            "target_degraded": self._target_response.target_degraded,
            "target_down": self._target_response.target_down,
            "min_response_time": self._target_response.min_response_time_ms,
            "max_response_time": self._target_response.max_response_time_ms,
            "samples": self._target_response.samples,
        }

    def get_network_conditions(self) -> Dict:
        """Get network conditions."""
        return {
            "latency": self._network_conditions.latency_ms,
            "jitter": self._network_conditions.latency_jitter_ms,
            "packet_loss": self._network_conditions.packet_loss_percent,
            "bandwidth": self._network_conditions.estimated_bandwidth_bps,
            "last_updated": self._network_conditions.last_updated,
        }

    def get_effectiveness_score(self) -> float:
        """Calculate attack effectiveness (0-100)."""
        if self._target_response.target_down:
            return 100.0
        if not self._baseline_response_time:
            return 50.0

        current = self._target_response.avg_response_time_ms
        baseline = self._baseline_response_time
        if baseline <= 0:
            return 50.0

        ratio = current / baseline
        if ratio <= 1:
            return 0.0
        elif ratio <= 2:
            return (ratio - 1) * 50
        elif ratio <= 5:
            return 50 + ((ratio - 2) / 3) * 30
        elif ratio <= 10:
            return 80 + ((ratio - 5) / 5) * 15
        return min(95 + (ratio - 10), 100)

    @property
    def is_running(self) -> bool:
        return self._running


_prober: Optional[SideChannelProber] = None


async def start_prober(target: str, **kwargs) -> SideChannelProber:
    """Start global prober."""
    global _prober
    if _prober and _prober.is_running:
        await _prober.stop()
    _prober = SideChannelProber(target, **kwargs)
    await _prober.start()
    return _prober


async def stop_prober() -> None:
    """Stop global prober."""
    global _prober
    if _prober:
        await _prober.stop()
        _prober = None


def get_prober() -> Optional[SideChannelProber]:
    """Get global prober instance."""
    return _prober


def get_real_target_response() -> Dict:
    """Get target response data."""
    if _prober and _prober.is_running:
        return _prober.get_target_response()
    return {
        "response_time": 0,
        "status_code": 0,
        "success_rate": 0,
        "target_degraded": False,
        "target_down": False,
    }


def get_real_network_conditions() -> Dict:
    """Get network conditions."""
    if _prober and _prober.is_running:
        return _prober.get_network_conditions()
    return {"latency": 0, "jitter": 0, "packet_loss": 0, "bandwidth": 0}
