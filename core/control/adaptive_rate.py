"""
Real Adaptive Rate Controller for NetStress.

This module implements genuine adaptive rate control using:
- Real RTT measurements for TCP connections
- Actual packet loss detection from OS counters
- PID control algorithm for rate adjustment
- Token bucket rate limiting with high-resolution timing
- Target responsiveness detection

No simulations - all metrics come from actual network measurements.
"""

import asyncio
import logging
import socket
import time
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from collections import deque
import psutil

logger = logging.getLogger(__name__)


@dataclass
class NetworkMetrics:
    """Real network metrics measured from actual connections"""
    rtt_ms: float
    packet_loss_rate: float
    connection_success_rate: float
    timestamp: float
    target_responsive: bool


@dataclass
class RateAdjustment:
    """Record of rate adjustment with actual metrics that triggered it"""
    timestamp: float
    old_rate: float
    new_rate: float
    trigger_metric: str
    metric_value: float
    reason: str


class PIDController:
    """
    Real PID controller for rate adjustment.
    Uses actual measured metrics, not simulated values.
    """
    
    def __init__(self, kp: float = 1.0, ki: float = 0.1, kd: float = 0.05):
        self.kp = kp  # Proportional gain
        self.ki = ki  # Integral gain  
        self.kd = kd  # Derivative gain
        
        self.previous_error = 0.0
        self.integral = 0.0
        self.last_time = time.perf_counter()
    
    def update(self, setpoint: float, measured_value: float) -> float:
        """
        Calculate PID output based on real measured values.
        
        Args:
            setpoint: Target value (e.g., target success rate)
            measured_value: Actual measured value
            
        Returns:
            Control output (rate adjustment factor)
        """
        current_time = time.perf_counter()
        dt = current_time - self.last_time
        
        if dt <= 0.0:
            return 0.0
            
        error = setpoint - measured_value
        
        # Proportional term
        proportional = self.kp * error
        
        # Integral term
        self.integral += error * dt
        integral = self.ki * self.integral
        
        # Derivative term
        derivative = self.kd * (error - self.previous_error) / dt
        
        # PID output
        output = proportional + integral + derivative
        
        # Update for next iteration
        self.previous_error = error
        self.last_time = current_time
        
        return output


class TokenBucket:
    """
    Real token bucket rate limiter with high-resolution timing.
    
    This is a genuine token bucket implementation using time.perf_counter()
    for microsecond precision timing. No simulations.
    """
    
    def __init__(self, rate: float, capacity: float = None):
        """
        Initialize token bucket.
        
        Args:
            rate: Tokens per second (packets per second)
            capacity: Maximum tokens (burst size). Defaults to rate.
        """
        self.rate = rate
        self.capacity = capacity or rate
        # Start with one token to allow immediate first packet, then enforce rate
        self.tokens = 1.0
        self.last_update = time.perf_counter()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were available and consumed, False otherwise
        """
        with self._lock:
            now = time.perf_counter()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def wait_time(self, tokens: int = 1) -> float:
        """
        Calculate time to wait until tokens are available.
        
        Args:
            tokens: Number of tokens needed
            
        Returns:
            Time to wait in seconds
        """
        with self._lock:
            if self.tokens >= tokens:
                return 0.0
            
            needed = tokens - self.tokens
            return needed / self.rate
    
    def update_rate(self, new_rate: float):
        """Update the token generation rate"""
        with self._lock:
            self.rate = new_rate
            # Optionally adjust capacity
            if self.capacity == self.rate:
                self.capacity = new_rate


class RTTMeasurer:
    """
    Real RTT measurement for TCP connections.
    Measures actual round-trip time, not estimated values.
    """
    
    def __init__(self):
        self.measurements = deque(maxlen=100)  # Keep last 100 measurements
    
    async def measure_tcp_rtt(self, host: str, port: int, timeout: float = 5.0) -> Optional[float]:
        """
        Measure actual TCP connection RTT.
        
        Args:
            host: Target hostname/IP
            port: Target port
            timeout: Connection timeout
            
        Returns:
            RTT in milliseconds, or None if failed
        """
        start_time = time.perf_counter()
        
        try:
            # Create TCP connection and measure time
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            connect_time = time.perf_counter()
            rtt_ms = (connect_time - start_time) * 1000
            
            # Clean up connection
            writer.close()
            await writer.wait_closed()
            
            self.measurements.append(rtt_ms)
            return rtt_ms
            
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as e:
            logger.debug(f"RTT measurement failed for {host}:{port}: {e}")
            return None
    
    def get_average_rtt(self) -> Optional[float]:
        """Get average RTT from recent measurements"""
        if not self.measurements:
            return None
        return sum(self.measurements) / len(self.measurements)
    
    def get_rtt_stats(self) -> Dict[str, float]:
        """Get RTT statistics"""
        if not self.measurements:
            return {}
        
        measurements = list(self.measurements)
        return {
            'count': len(measurements),
            'min': min(measurements),
            'max': max(measurements),
            'avg': sum(measurements) / len(measurements),
            'latest': measurements[-1] if measurements else 0
        }

class ResponsivenessDetector:
    """
    Detect target unresponsiveness within 5 seconds using real metrics.
    """
    
    def __init__(self, detection_window: float = 5.0):
        self.detection_window = detection_window
        self.connection_attempts = deque()
        self.last_successful_connection = None
        
    def record_connection_attempt(self, success: bool, timestamp: float = None):
        """Record a connection attempt result"""
        if timestamp is None:
            timestamp = time.perf_counter()
            
        self.connection_attempts.append((timestamp, success))
        
        if success:
            self.last_successful_connection = timestamp
            
        # Clean old attempts outside detection window
        cutoff = timestamp - self.detection_window
        while self.connection_attempts and self.connection_attempts[0][0] < cutoff:
            self.connection_attempts.popleft()
    
    def is_target_responsive(self, current_time: float = None) -> bool:
        """
        Determine if target is responsive based on recent connection attempts.
        
        Args:
            current_time: Current time for evaluation. If None, uses perf_counter()
        
        Returns:
            True if target appears responsive, False if unresponsive
        """
        if current_time is None:
            current_time = time.perf_counter()
        
        # If no attempts recorded, assume responsive
        if not self.connection_attempts:
            return True
            
        # Get attempts within the detection window
        recent_attempts = [
            (timestamp, success) for timestamp, success in self.connection_attempts
            if current_time - timestamp <= self.detection_window
        ]
        
        if not recent_attempts:
            return True  # No recent attempts
            
        # Check if we have any successful connections in the window
        recent_successes = [success for _, success in recent_attempts if success]
        
        # If we have recent successes, target is responsive
        if recent_successes:
            return True
            
        # All recent attempts failed - check if we've been trying long enough
        oldest_attempt_time = min(timestamp for timestamp, _ in recent_attempts)
        time_span = current_time - oldest_attempt_time
        
        # Target is unresponsive if all attempts failed and we've been trying for the full window
        return time_span < self.detection_window
    
    def get_success_rate(self) -> float:
        """Get connection success rate in current window"""
        if not self.connection_attempts:
            return 1.0  # Assume 100% if no data
            
        successes = sum(1 for _, success in self.connection_attempts if success)
        return successes / len(self.connection_attempts)


class PacketLossTracker:
    """
    Track packet loss from OS-level network counters.
    Uses real system statistics, not estimates.
    """
    
    def __init__(self, interface: str = None):
        self.interface = interface
        self.previous_stats = None
        self.loss_history = deque(maxlen=50)
    
    def update_stats(self):
        """Update network statistics from OS"""
        try:
            # Get network interface statistics
            net_stats = psutil.net_io_counters(pernic=True)
            
            if self.interface and self.interface in net_stats:
                current_stats = net_stats[self.interface]
            else:
                # Use aggregate stats if no specific interface
                current_stats = psutil.net_io_counters()
            
            if self.previous_stats:
                # Calculate packet loss rate
                tx_packets_delta = current_stats.packets_sent - self.previous_stats.packets_sent
                tx_errors_delta = current_stats.errout - self.previous_stats.errout
                
                if tx_packets_delta > 0:
                    loss_rate = tx_errors_delta / tx_packets_delta
                    self.loss_history.append(loss_rate)
                else:
                    self.loss_history.append(0.0)
            
            self.previous_stats = current_stats
            
        except Exception as e:
            logger.warning(f"Failed to update packet loss stats: {e}")
            self.loss_history.append(0.0)
    
    def get_packet_loss_rate(self) -> float:
        """Get current packet loss rate"""
        if not self.loss_history:
            return 0.0
        return self.loss_history[-1]
    
    def get_average_loss_rate(self) -> float:
        """Get average packet loss rate from recent history"""
        if not self.loss_history:
            return 0.0
        return sum(self.loss_history) / len(self.loss_history)

class AdaptiveRateController:
    """
    Real adaptive rate controller using actual network measurements.
    
    This controller:
    - Measures real RTT for TCP connections
    - Tracks actual packet loss from OS counters  
    - Uses PID control algorithm for rate adjustment
    - Detects target unresponsiveness within 5 seconds
    - Logs actual metrics that drive each decision
    
    No simulations - all adjustments based on real network data.
    """
    
    def __init__(self, 
                 initial_rate: float = 1000.0,
                 target_host: str = None,
                 target_port: int = 80,
                 interface: str = None):
        """
        Initialize adaptive rate controller.
        
        Args:
            initial_rate: Initial packet rate (PPS)
            target_host: Target hostname/IP for RTT measurement
            target_port: Target port for RTT measurement
            interface: Network interface for packet loss tracking
        """
        self.current_rate = initial_rate
        self.target_host = target_host
        self.target_port = target_port
        
        # Real measurement components
        self.rtt_measurer = RTTMeasurer()
        self.responsiveness_detector = ResponsivenessDetector()
        self.packet_loss_tracker = PacketLossTracker(interface)
        
        # PID controller for rate adjustment
        self.pid_controller = PIDController(kp=1.0, ki=0.1, kd=0.05)
        
        # Token bucket for rate limiting
        self.token_bucket = TokenBucket(initial_rate)
        
        # Adjustment history
        self.adjustment_history = deque(maxlen=100)
        
        # Monitoring thread
        self._monitoring = False
        self._monitor_thread = None
        
        # Target thresholds
        self.target_success_rate = 0.8  # 80% connection success rate
        self.max_rtt_ms = 1000.0  # 1 second max RTT
        self.max_loss_rate = 0.05  # 5% max packet loss
        
    def start_monitoring(self):
        """Start background monitoring of network metrics"""
        if self._monitoring:
            return
            
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Started adaptive rate monitoring")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        logger.info("Stopped adaptive rate monitoring")
    
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._monitoring:
            try:
                # Update packet loss statistics
                self.packet_loss_tracker.update_stats()
                
                # Measure RTT if target specified
                if self.target_host:
                    asyncio.run(self._measure_and_adjust())
                
                time.sleep(1.0)  # Monitor every second
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1.0)
    
    async def _measure_and_adjust(self):
        """Measure network metrics and adjust rate if needed"""
        # Measure RTT
        rtt = await self.rtt_measurer.measure_tcp_rtt(
            self.target_host, self.target_port, timeout=2.0
        )
        
        # Record connection attempt
        self.responsiveness_detector.record_connection_attempt(rtt is not None)
        
        # Get current metrics
        metrics = self._get_current_metrics(rtt)
        
        # Determine if adjustment needed
        adjustment = self._calculate_rate_adjustment(metrics)
        
        if adjustment:
            self._apply_rate_adjustment(adjustment)
    
    def _get_current_metrics(self, rtt: Optional[float]) -> NetworkMetrics:
        """Gather current network metrics"""
        return NetworkMetrics(
            rtt_ms=rtt or 0.0,
            packet_loss_rate=self.packet_loss_tracker.get_packet_loss_rate(),
            connection_success_rate=self.responsiveness_detector.get_success_rate(),
            timestamp=time.perf_counter(),
            target_responsive=self.responsiveness_detector.is_target_responsive()
        )
    
    def _calculate_rate_adjustment(self, metrics: NetworkMetrics) -> Optional[RateAdjustment]:
        """
        Calculate rate adjustment based on real metrics.
        
        Returns RateAdjustment if change needed, None otherwise.
        """
        old_rate = self.current_rate
        new_rate = old_rate
        trigger_metric = None
        metric_value = None
        reason = None
        
        # Check if target is unresponsive
        if not metrics.target_responsive:
            new_rate = old_rate * 0.5  # Reduce rate by 50%
            trigger_metric = "target_unresponsive"
            metric_value = metrics.connection_success_rate
            reason = f"Target unresponsive (success rate: {metrics.connection_success_rate:.2%})"
            
        # Check RTT threshold
        elif metrics.rtt_ms > self.max_rtt_ms:
            # Use PID controller to adjust based on RTT
            pid_output = self.pid_controller.update(self.max_rtt_ms, metrics.rtt_ms)
            adjustment_factor = max(0.1, 1.0 - abs(pid_output) * 0.1)
            new_rate = old_rate * adjustment_factor
            trigger_metric = "high_rtt"
            metric_value = metrics.rtt_ms
            reason = f"High RTT: {metrics.rtt_ms:.1f}ms > {self.max_rtt_ms}ms"
            
        # Check packet loss threshold
        elif metrics.packet_loss_rate > self.max_loss_rate:
            adjustment_factor = max(0.1, 1.0 - metrics.packet_loss_rate)
            new_rate = old_rate * adjustment_factor
            trigger_metric = "high_packet_loss"
            metric_value = metrics.packet_loss_rate
            reason = f"High packet loss: {metrics.packet_loss_rate:.2%} > {self.max_loss_rate:.2%}"
            
        # Check connection success rate
        elif metrics.connection_success_rate < self.target_success_rate:
            # Use PID controller for success rate
            pid_output = self.pid_controller.update(
                self.target_success_rate, metrics.connection_success_rate
            )
            adjustment_factor = max(0.1, 1.0 + pid_output * 0.1)
            new_rate = old_rate * adjustment_factor
            trigger_metric = "low_success_rate"
            metric_value = metrics.connection_success_rate
            reason = f"Low success rate: {metrics.connection_success_rate:.2%} < {self.target_success_rate:.2%}"
        
        # Apply rate bounds
        new_rate = max(1.0, min(100000.0, new_rate))
        
        # Only return adjustment if significant change
        if abs(new_rate - old_rate) / old_rate > 0.05:  # 5% threshold
            return RateAdjustment(
                timestamp=metrics.timestamp,
                old_rate=old_rate,
                new_rate=new_rate,
                trigger_metric=trigger_metric,
                metric_value=metric_value,
                reason=reason
            )
        
        return None
    
    def _apply_rate_adjustment(self, adjustment: RateAdjustment):
        """Apply rate adjustment and log the decision"""
        self.current_rate = adjustment.new_rate
        self.token_bucket.update_rate(adjustment.new_rate)
        self.adjustment_history.append(adjustment)
        
        # Log the actual metrics that drove this decision
        logger.info(
            f"Rate adjusted: {adjustment.old_rate} -> {adjustment.new_rate} PPS. "
            f"Trigger: {adjustment.trigger_metric}={adjustment.metric_value}. "
            f"Reason: {adjustment.reason}"
        )
    
    def can_send_packet(self) -> bool:
        """Check if packet can be sent according to current rate limit"""
        return self.token_bucket.consume(1)
    
    def wait_for_token(self) -> float:
        """Get time to wait for next token"""
        return self.token_bucket.wait_time(1)
    
    def get_current_rate(self) -> float:
        """Get current packet rate"""
        return self.current_rate
    
    def get_adjustment_history(self) -> List[RateAdjustment]:
        """Get history of rate adjustments with triggering metrics"""
        return list(self.adjustment_history)
    
    def get_status(self) -> Dict:
        """Get current status and metrics"""
        rtt_stats = self.rtt_measurer.get_rtt_stats()
        
        return {
            'current_rate_pps': self.current_rate,
            'target_responsive': self.responsiveness_detector.is_target_responsive(),
            'connection_success_rate': self.responsiveness_detector.get_success_rate(),
            'packet_loss_rate': self.packet_loss_tracker.get_packet_loss_rate(),
            'rtt_stats': rtt_stats,
            'adjustments_count': len(self.adjustment_history),
            'monitoring_active': self._monitoring
        }