"""
Proxy Chain Module

Implements proxy chaining and rotation:
- SOCKS4/5 proxy support
- HTTP/HTTPS proxy support
- Proxy chain building
- Automatic rotation
"""

import asyncio
import socket
import struct
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    """Proxy types"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    host: str
    port: int
    proxy_type: ProxyType = ProxyType.SOCKS5
    username: Optional[str] = None
    password: Optional[str] = None
    timeout: float = 10.0


@dataclass
class ProxyStats:
    """Proxy statistics"""
    requests: int = 0
    successes: int = 0
    failures: int = 0
    avg_latency: float = 0.0
    last_used: float = 0.0
    
    @property
    def success_rate(self) -> float:
        return self.successes / self.requests if self.requests > 0 else 0.0


class Proxy(ABC):
    """Base proxy class"""
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.stats = ProxyStats()
        
    @abstractmethod
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to target through proxy"""
        pass
        
    async def test(self) -> bool:
        """Test proxy connectivity"""
        try:
            reader, writer = await self.connect('httpbin.org', 80)
            writer.write(b'GET /ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            return b'200' in response
        except Exception:
            return False


class SOCKSProxy(Proxy):
    """SOCKS4/5 Proxy"""
    
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect through SOCKS proxy"""
        start = time.monotonic()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=self.config.timeout
            )
            
            if self.config.proxy_type == ProxyType.SOCKS5:
                await self._socks5_handshake(reader, writer, target_host, target_port)
            else:
                await self._socks4_handshake(reader, writer, target_host, target_port)
                
            self.stats.requests += 1
            self.stats.successes += 1
            self.stats.last_used = time.time()
            
            latency = time.monotonic() - start
            self.stats.avg_latency = (self.stats.avg_latency * (self.stats.successes - 1) + latency) / self.stats.successes
            
            return reader, writer
            
        except Exception as e:
            self.stats.requests += 1
            self.stats.failures += 1
            raise
            
    async def _socks5_handshake(self, reader, writer, host: str, port: int):
        """SOCKS5 handshake"""
        # Greeting
        if self.config.username:
            writer.write(b'\x05\x02\x00\x02')  # Version, 2 methods, no auth + user/pass
        else:
            writer.write(b'\x05\x01\x00')  # Version, 1 method, no auth
        await writer.drain()
        
        response = await reader.read(2)
        if response[0] != 0x05:
            raise Exception("Invalid SOCKS5 response")
            
        # Authentication if required
        if response[1] == 0x02:
            if not self.config.username:
                raise Exception("Proxy requires authentication")
            auth = bytes([0x01, len(self.config.username)]) + self.config.username.encode()
            auth += bytes([len(self.config.password or '')]) + (self.config.password or '').encode()
            writer.write(auth)
            await writer.drain()
            
            auth_response = await reader.read(2)
            if auth_response[1] != 0x00:
                raise Exception("Authentication failed")
                
        # Connect request
        request = b'\x05\x01\x00'  # Version, connect, reserved
        
        try:
            # Try as IP address
            ip = socket.inet_aton(host)
            request += b'\x01' + ip  # IPv4
        except socket.error:
            # Domain name
            request += b'\x03' + bytes([len(host)]) + host.encode()
            
        request += struct.pack('>H', port)
        
        writer.write(request)
        await writer.drain()
        
        response = await reader.read(10)
        if response[1] != 0x00:
            raise Exception(f"SOCKS5 connect failed: {response[1]}")
            
    async def _socks4_handshake(self, reader, writer, host: str, port: int):
        """SOCKS4 handshake"""
        try:
            ip = socket.inet_aton(host)
        except socket.error:
            # SOCKS4a for domain names
            ip = b'\x00\x00\x00\x01'
            
        request = struct.pack('>BBH', 0x04, 0x01, port) + ip + b'\x00'
        
        if ip == b'\x00\x00\x00\x01':
            request += host.encode() + b'\x00'
            
        writer.write(request)
        await writer.drain()
        
        response = await reader.read(8)
        if response[1] != 0x5a:
            raise Exception(f"SOCKS4 connect failed: {response[1]}")


class HTTPProxy(Proxy):
    """HTTP/HTTPS Proxy"""
    
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect through HTTP proxy using CONNECT method"""
        start = time.monotonic()
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=self.config.timeout
            )
            
            # CONNECT request
            request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            request += f"Host: {target_host}:{target_port}\r\n"
            
            if self.config.username:
                import base64
                auth = base64.b64encode(f"{self.config.username}:{self.config.password or ''}".encode()).decode()
                request += f"Proxy-Authorization: Basic {auth}\r\n"
                
            request += "\r\n"
            
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            response = await reader.readline()
            if b'200' not in response:
                raise Exception(f"HTTP proxy connect failed: {response.decode()}")
                
            # Read remaining headers
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                    
            self.stats.requests += 1
            self.stats.successes += 1
            self.stats.last_used = time.time()
            
            latency = time.monotonic() - start
            self.stats.avg_latency = (self.stats.avg_latency * (self.stats.successes - 1) + latency) / self.stats.successes
            
            return reader, writer
            
        except Exception as e:
            self.stats.requests += 1
            self.stats.failures += 1
            raise


class ProxyChain:
    """
    Proxy Chain
    
    Routes traffic through multiple proxies.
    """
    
    def __init__(self, proxies: List[ProxyConfig]):
        self.proxies = proxies
        self._proxy_objects: List[Proxy] = []
        
        for config in proxies:
            if config.proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
                self._proxy_objects.append(SOCKSProxy(config))
            else:
                self._proxy_objects.append(HTTPProxy(config))
                
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect through proxy chain"""
        if not self._proxy_objects:
            return await asyncio.open_connection(target_host, target_port)
            
        # Connect through first proxy
        reader, writer = await self._proxy_objects[0].connect(
            self.proxies[1].host if len(self.proxies) > 1 else target_host,
            self.proxies[1].port if len(self.proxies) > 1 else target_port
        )
        
        # Chain through remaining proxies
        for i, proxy in enumerate(self._proxy_objects[1:], 1):
            next_host = self.proxies[i + 1].host if i + 1 < len(self.proxies) else target_host
            next_port = self.proxies[i + 1].port if i + 1 < len(self.proxies) else target_port
            
            # Perform handshake through existing connection
            if isinstance(proxy, SOCKSProxy):
                await proxy._socks5_handshake(reader, writer, next_host, next_port)
            else:
                # HTTP CONNECT through tunnel
                request = f"CONNECT {next_host}:{next_port} HTTP/1.1\r\nHost: {next_host}\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                response = await reader.readline()
                while (await reader.readline()) != b'\r\n':
                    pass
                    
        return reader, writer


class ProxyRotator:
    """
    Proxy Rotator
    
    Automatically rotates through proxy list.
    """
    
    def __init__(self, proxies: List[ProxyConfig], strategy: str = 'round_robin'):
        self.proxies = proxies
        self.strategy = strategy
        self._proxy_objects: List[Proxy] = []
        self._current_index = 0
        self._lock = asyncio.Lock()
        
        for config in proxies:
            if config.proxy_type in (ProxyType.SOCKS4, ProxyType.SOCKS5):
                self._proxy_objects.append(SOCKSProxy(config))
            else:
                self._proxy_objects.append(HTTPProxy(config))
                
    async def get_proxy(self) -> Proxy:
        """Get next proxy based on strategy"""
        async with self._lock:
            if self.strategy == 'round_robin':
                proxy = self._proxy_objects[self._current_index]
                self._current_index = (self._current_index + 1) % len(self._proxy_objects)
                return proxy
                
            elif self.strategy == 'random':
                return random.choice(self._proxy_objects)
                
            elif self.strategy == 'least_used':
                return min(self._proxy_objects, key=lambda p: p.stats.requests)
                
            elif self.strategy == 'best_latency':
                working = [p for p in self._proxy_objects if p.stats.success_rate > 0.5]
                if working:
                    return min(working, key=lambda p: p.stats.avg_latency)
                return random.choice(self._proxy_objects)
                
            elif self.strategy == 'best_success':
                return max(self._proxy_objects, key=lambda p: p.stats.success_rate)
                
            return self._proxy_objects[0]
            
    async def connect(self, target_host: str, target_port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect using rotated proxy"""
        proxy = await self.get_proxy()
        return await proxy.connect(target_host, target_port)
        
    async def test_all(self) -> Dict[str, Any]:
        """Test all proxies"""
        results = {'working': 0, 'failed': 0, 'proxies': []}
        
        for i, proxy in enumerate(self._proxy_objects):
            working = await proxy.test()
            results['proxies'].append({
                'index': i,
                'host': self.proxies[i].host,
                'port': self.proxies[i].port,
                'working': working,
                'latency': proxy.stats.avg_latency,
            })
            if working:
                results['working'] += 1
            else:
                results['failed'] += 1
                
        return results
        
    def remove_failed(self, threshold: float = 0.3):
        """Remove proxies with low success rate"""
        to_remove = []
        for i, proxy in enumerate(self._proxy_objects):
            if proxy.stats.requests > 10 and proxy.stats.success_rate < threshold:
                to_remove.append(i)
                
        for i in reversed(to_remove):
            del self._proxy_objects[i]
            del self.proxies[i]
