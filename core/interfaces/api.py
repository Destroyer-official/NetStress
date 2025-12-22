"""
REST and GraphQL APIs for DDoS Testing Framework

This module provides:
- Comprehensive REST API for all functionality
- GraphQL API for flexible data querying
- WebSocket support for real-time updates
- API authentication and rate limiting
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Any, Union
import threading
from dataclasses import dataclass, asdict

try:
    from flask import Flask, request, jsonify, g
    from flask_restful import Api, Resource, reqparse
    from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask_cors import CORS
    import graphene
    from graphene import ObjectType, String, Int, Float, Boolean, List as GrapheneList, Field, Schema
    from flask_graphql import GraphQLView
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create dummy classes when Flask is not available
    class Resource:
        pass
    class ObjectType:
        pass
    String = Int = Float = Boolean = Field = None
    GrapheneList = list

try:
    import websockets
    import asyncio
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class APIResponse:
    """Standard API response format"""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    message: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class AttackInfo:
    """Attack information data structure"""
    id: str
    target: str
    port: int
    protocol: str
    status: str
    started_at: str
    duration: int = 0
    pps: int = 0
    bandwidth: float = 0.0
    packets_sent: int = 0
    errors: int = 0

@dataclass
class TargetInfo:
    """Target information data structure"""
    ip: str
    hostname: Optional[str]
    ports: List[int]
    services: List[str]
    response_time: float
    last_scanned: str

@dataclass
class SystemMetrics:
    """System metrics data structure"""
    cpu_usage: float
    memory_usage: float
    network_usage: float
    active_attacks: int
    total_pps: int
    total_bandwidth: float
    timestamp: str

class APIAuthentication:
    """Handles API authentication and authorization"""
    
    def __init__(self):
        self.api_keys = {}
        self.jwt_tokens = {}
        self.rate_limits = {}
        self._init_default_keys()
    
    def _init_default_keys(self):
        """Initialize default API keys"""
        self.api_keys['admin'] = {
            'key': 'ddos_admin_key_12345',
            'permissions': ['read', 'write', 'admin'],
            'rate_limit': 1000,  # requests per hour
            'created_at': datetime.now()
        }
        
        self.api_keys['readonly'] = {
            'key': 'ddos_readonly_key_67890',
            'permissions': ['read'],
            'rate_limit': 100,
            'created_at': datetime.now()
        }
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate API key and return user info"""
        for user, info in self.api_keys.items():
            if info['key'] == api_key:
                return {
                    'user': user,
                    'permissions': info['permissions'],
                    'rate_limit': info['rate_limit']
                }
        return None
    
    def create_jwt_token(self, user: str, permissions: List[str]) -> str:
        """Create JWT token for user"""
        token_data = {
            'user': user,
            'permissions': permissions,
            'created_at': datetime.now().isoformat()
        }
        
        # In a real implementation, use proper JWT library
        token = f"jwt_{user}_{int(time.time())}"
        self.jwt_tokens[token] = token_data
        return token
    
    def validate_jwt_token(self, token: str) -> Optional[Dict]:
        """Validate JWT token"""
        return self.jwt_tokens.get(token)
    
    def check_rate_limit(self, user: str) -> bool:
        """Check if user has exceeded rate limit"""
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        if user not in self.rate_limits:
            self.rate_limits[user] = []
        
        # Remove old requests
        self.rate_limits[user] = [
            req_time for req_time in self.rate_limits[user]
            if req_time > hour_ago
        ]
        
        user_info = None
        for info in self.api_keys.values():
            if info.get('user') == user:
                user_info = info
                break
        
        if not user_info:
            return False
        
        # Check if under rate limit
        if len(self.rate_limits[user]) < user_info['rate_limit']:
            self.rate_limits[user].append(now)
            return True
        
        return False

def require_auth(permissions: List[str] = None):
    """Decorator for API authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check API key in header
            api_key = request.headers.get('X-API-Key')
            jwt_token = request.headers.get('Authorization')
            
            user_info = None
            
            if api_key:
                auth = APIAuthentication()
                user_info = auth.validate_api_key(api_key)
            elif jwt_token and jwt_token.startswith('Bearer '):
                auth = APIAuthentication()
                token = jwt_token[7:]  # Remove 'Bearer ' prefix
                user_info = auth.validate_jwt_token(token)
            
            if not user_info:
                return jsonify(APIResponse(
                    success=False,
                    error="Invalid or missing authentication"
                ).to_dict()), 401
            
            # Check permissions
            if permissions:
                user_permissions = user_info.get('permissions', [])
                if not any(perm in user_permissions for perm in permissions):
                    return jsonify(APIResponse(
                        success=False,
                        error="Insufficient permissions"
                    ).to_dict()), 403
            
            # Check rate limit
            auth = APIAuthentication()
            if not auth.check_rate_limit(user_info['user']):
                return jsonify(APIResponse(
                    success=False,
                    error="Rate limit exceeded"
                ).to_dict()), 429
            
            # Store user info in request context
            g.user = user_info
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class AttackResource(Resource):
    """REST API resource for attack management"""
    
    @require_auth(['read'])
    def get(self, attack_id=None):
        """Get attack information"""
        if attack_id:
            # Get specific attack
            attack = self._get_attack_by_id(attack_id)
            if not attack:
                return APIResponse(
                    success=False,
                    error="Attack not found"
                ).to_dict(), 404
            
            return APIResponse(
                success=True,
                data=asdict(attack)
            ).to_dict()
        else:
            # Get all attacks
            attacks = self._get_all_attacks()
            return APIResponse(
                success=True,
                data=[asdict(attack) for attack in attacks]
            ).to_dict()
    
    @require_auth(['write'])
    def post(self):
        """Start new attack"""
        parser = reqparse.RequestParser()
        parser.add_argument('target', required=True, help='Target IP or domain')
        parser.add_argument('port', type=int, required=True, help='Target port')
        parser.add_argument('protocol', required=True, choices=['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP'])
        parser.add_argument('duration', type=int, default=0, help='Attack duration in seconds')
        parser.add_argument('processes', type=int, default=1, help='Number of processes')
        parser.add_argument('packet_size', type=int, default=1460, help='Packet size')
        
        args = parser.parse_args()
        
        # Validate target
        if not self._validate_target(args['target']):
            return APIResponse(
                success=False,
                error="Invalid or unsafe target"
            ).to_dict(), 400
        
        # Start attack
        attack_id = self._start_attack(args)
        
        return APIResponse(
            success=True,
            data={'attack_id': attack_id},
            message="Attack started successfully"
        ).to_dict(), 201
    
    @require_auth(['write'])
    def delete(self, attack_id):
        """Stop attack"""
        if not self._attack_exists(attack_id):
            return APIResponse(
                success=False,
                error="Attack not found"
            ).to_dict(), 404
        
        success = self._stop_attack(attack_id)
        
        if success:
            return APIResponse(
                success=True,
                message="Attack stopped successfully"
            ).to_dict()
        else:
            return APIResponse(
                success=False,
                error="Failed to stop attack"
            ).to_dict(), 500
    
    def _get_attack_by_id(self, attack_id: str) -> Optional[AttackInfo]:
        """Get attack by ID (mock implementation)"""
        # In real implementation, this would query the attack engine
        return AttackInfo(
            id=attack_id,
            target="192.168.1.100",
            port=80,
            protocol="HTTP",
            status="active",
            started_at=datetime.now().isoformat(),
            duration=120,
            pps=5000,
            bandwidth=250.5,
            packets_sent=600000,
            errors=5
        )
    
    def _get_all_attacks(self) -> List[AttackInfo]:
        """Get all attacks (mock implementation)"""
        return [
            AttackInfo(
                id="attack_001",
                target="192.168.1.100",
                port=80,
                protocol="HTTP",
                status="active",
                started_at=datetime.now().isoformat(),
                pps=5000
            ),
            AttackInfo(
                id="attack_002",
                target="192.168.1.101",
                port=443,
                protocol="HTTPS",
                status="completed",
                started_at=(datetime.now() - timedelta(hours=1)).isoformat(),
                pps=0
            )
        ]
    
    def _validate_target(self, target: str) -> bool:
        """Validate target is safe for testing"""
        # Implement safety checks
        return True
    
    def _start_attack(self, params: Dict) -> str:
        """Start attack with given parameters"""
        attack_id = f"attack_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        # In real implementation, integrate with attack engine
        return attack_id
    
    def _stop_attack(self, attack_id: str) -> bool:
        """Stop attack by ID"""
        # In real implementation, integrate with attack engine
        return True
    
    def _attack_exists(self, attack_id: str) -> bool:
        """Check if attack exists"""
        return True

class TargetResource(Resource):
    """REST API resource for target analysis"""
    
    @require_auth(['read'])
    def get(self, target=None):
        """Get target information"""
        if not target:
            return APIResponse(
                success=False,
                error="Target parameter required"
            ).to_dict(), 400
        
        target_info = self._analyze_target(target)
        
        return APIResponse(
            success=True,
            data=asdict(target_info)
        ).to_dict()
    
    @require_auth(['write'])
    def post(self):
        """Perform target analysis"""
        parser = reqparse.RequestParser()
        parser.add_argument('target', required=True, help='Target IP or domain')
        parser.add_argument('deep_scan', type=bool, default=False, help='Perform deep scan')
        parser.add_argument('timeout', type=int, default=30, help='Scan timeout')
        
        args = parser.parse_args()
        
        # Perform analysis
        analysis_id = self._start_analysis(args)
        
        return APIResponse(
            success=True,
            data={'analysis_id': analysis_id},
            message="Target analysis started"
        ).to_dict(), 202
    
    def _analyze_target(self, target: str) -> TargetInfo:
        """Analyze target (mock implementation)"""
        return TargetInfo(
            ip="192.168.1.100",
            hostname=target if not target.replace('.', '').isdigit() else None,
            ports=[22, 80, 443, 8080],
            services=['SSH', 'HTTP', 'HTTPS', 'HTTP-Alt'],
            response_time=0.025,
            last_scanned=datetime.now().isoformat()
        )
    
    def _start_analysis(self, params: Dict) -> str:
        """Start target analysis"""
        analysis_id = f"analysis_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        return analysis_id

class MetricsResource(Resource):
    """REST API resource for system metrics"""
    
    @require_auth(['read'])
    def get(self):
        """Get current system metrics"""
        metrics = self._get_current_metrics()
        
        return APIResponse(
            success=True,
            data=asdict(metrics)
        ).to_dict()
    
    def _get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics (mock implementation)"""
        return SystemMetrics(
            cpu_usage=45.2,
            memory_usage=62.8,
            network_usage=78.5,
            active_attacks=3,
            total_pps=15000,
            total_bandwidth=750.5,
            timestamp=datetime.now().isoformat()
        )

class ConfigResource(Resource):
    """REST API resource for configuration management"""
    
    @require_auth(['read'])
    def get(self):
        """Get current configuration"""
        config = self._get_config()
        
        return APIResponse(
            success=True,
            data=config
        ).to_dict()
    
    @require_auth(['admin'])
    def post(self):
        """Update configuration"""
        parser = reqparse.RequestParser()
        parser.add_argument('key', required=True, help='Configuration key')
        parser.add_argument('value', required=True, help='Configuration value')
        
        args = parser.parse_args()
        
        success = self._set_config(args['key'], args['value'])
        
        if success:
            return APIResponse(
                success=True,
                message="Configuration updated successfully"
            ).to_dict()
        else:
            return APIResponse(
                success=False,
                error="Failed to update configuration"
            ).to_dict(), 500
    
    def _get_config(self) -> Dict:
        """Get current configuration"""
        return {
            'max_processes': 8,
            'default_timeout': 30,
            'auto_optimize': True,
            'log_level': 'INFO',
            'rate_limit': 1000
        }
    
    def _set_config(self, key: str, value: Any) -> bool:
        """Set configuration value"""
        # In real implementation, update actual configuration
        return True

# GraphQL Schema Definitions
# Only define GraphQL types if graphene is available
if FLASK_AVAILABLE:
    class AttackType(ObjectType):
        """GraphQL type for attack information"""
        id = String()
        target = String()
        port = Int()
        protocol = String()
        status = String()
        started_at = String()
        duration = Int()
        pps = Int()
        bandwidth = Float()
        packets_sent = Int()
        errors = Int()

    class TargetType(ObjectType):
        """GraphQL type for target information"""
        ip = String()
        hostname = String()
        ports = GrapheneList(Int)
        services = GrapheneList(String)
        response_time = Float()
        last_scanned = String()

    class MetricsType(ObjectType):
        """GraphQL type for system metrics"""
        cpu_usage = Float()
        memory_usage = Float()
        network_usage = Float()
        active_attacks = Int()
        total_pps = Int()
        total_bandwidth = Float()
        timestamp = String()

    class Query(ObjectType):
        """GraphQL query root"""
        
        # Attack queries
        attack = Field(AttackType, id=String(required=True))
        attacks = GrapheneList(AttackType, status=String(), protocol=String())
        
        # Target queries
        target = Field(TargetType, target=String(required=True))
        
        # Metrics queries
        metrics = Field(MetricsType)
        historical_metrics = GrapheneList(MetricsType, 
                                        start_time=String(), 
                                        end_time=String(),
                                        interval=String())
        
        def resolve_attack(self, info, id):
            """Resolve single attack query"""
            # Mock implementation
            return AttackInfo(
                id=id,
                target="192.168.1.100",
                port=80,
                protocol="HTTP",
                status="active",
                started_at=datetime.now().isoformat(),
                pps=5000
            )
        
        def resolve_attacks(self, info, status=None, protocol=None):
            """Resolve attacks list query"""
            attacks = [
                AttackInfo(
                    id="attack_001",
                    target="192.168.1.100",
                    port=80,
                    protocol="HTTP",
                    status="active",
                    started_at=datetime.now().isoformat(),
                    pps=5000
                ),
                AttackInfo(
                    id="attack_002",
                    target="192.168.1.101",
                    port=443,
                    protocol="HTTPS",
                    status="completed",
                    started_at=(datetime.now() - timedelta(hours=1)).isoformat(),
                    pps=0
                )
            ]
            
            # Filter by status and protocol if provided
            if status:
                attacks = [a for a in attacks if a.status == status]
            if protocol:
                attacks = [a for a in attacks if a.protocol == protocol]
            
            return attacks
        
        def resolve_target(self, info, target):
            """Resolve target analysis query"""
            return TargetInfo(
                ip="192.168.1.100",
                hostname=target if not target.replace('.', '').isdigit() else None,
                ports=[22, 80, 443, 8080],
                services=['SSH', 'HTTP', 'HTTPS', 'HTTP-Alt'],
                response_time=0.025,
                last_scanned=datetime.now().isoformat()
            )
        
        def resolve_metrics(self, info):
            """Resolve current metrics query"""
            return SystemMetrics(
                cpu_usage=45.2,
                memory_usage=62.8,
                network_usage=78.5,
                active_attacks=3,
                total_pps=15000,
                total_bandwidth=750.5,
                timestamp=datetime.now().isoformat()
            )
        
        def resolve_historical_metrics(self, info, start_time=None, end_time=None, interval='1m'):
            """Resolve historical metrics query"""
            # Generate mock historical data
            metrics = []
            base_time = datetime.now() - timedelta(hours=1)
            
            for i in range(60):  # 60 data points
                timestamp = base_time + timedelta(minutes=i)
                metrics.append(SystemMetrics(
                    cpu_usage=40 + (i % 20),
                    memory_usage=60 + (i % 15),
                    network_usage=70 + (i % 25),
                    active_attacks=2 + (i % 3),
                    total_pps=10000 + (i * 100),
                    total_bandwidth=500 + (i * 5),
                    timestamp=timestamp.isoformat()
                ))
            
            return metrics

    class Mutation(ObjectType):
        """GraphQL mutation root"""
        
        start_attack = Field(String, 
                            target=String(required=True),
                            port=Int(required=True),
                            protocol=String(required=True),
                            duration=Int(),
                            processes=Int())
        
        stop_attack = Field(Boolean, id=String(required=True))
        
        def resolve_start_attack(self, info, target, port, protocol, duration=0, processes=1):
            """Resolve start attack mutation"""
            # In real implementation, integrate with attack engine
            attack_id = f"attack_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            return attack_id
        
        def resolve_stop_attack(self, info, id):
            """Resolve stop attack mutation"""
            # In real implementation, integrate with attack engine
            return True
else:
    # Dummy classes when Flask/graphene is not available
    AttackType = None
    TargetType = None
    MetricsType = None
    Query = None
    Mutation = None

class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.connections = set()
        self.subscriptions = {}
        self.running = False
        
    async def register_connection(self, websocket, path):
        """Register new WebSocket connection"""
        self.connections.add(websocket)
        logger.info(f"WebSocket connection registered: {websocket.remote_address}")
        
        try:
            await self.handle_connection(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
        finally:
            self.connections.discard(websocket)
            logger.info(f"WebSocket connection closed: {websocket.remote_address}")
    
    async def handle_connection(self, websocket):
        """Handle WebSocket connection messages"""
        async for message in websocket:
            try:
                data = json.loads(message)
                await self.process_message(websocket, data)
            except json.JSONDecodeError:
                await websocket.send(json.dumps({
                    'error': 'Invalid JSON format'
                }))
            except Exception as e:
                await websocket.send(json.dumps({
                    'error': str(e)
                }))
    
    async def process_message(self, websocket, data):
        """Process incoming WebSocket message"""
        message_type = data.get('type')
        
        if message_type == 'subscribe':
            await self.handle_subscription(websocket, data)
        elif message_type == 'unsubscribe':
            await self.handle_unsubscription(websocket, data)
        elif message_type == 'ping':
            await websocket.send(json.dumps({'type': 'pong'}))
        else:
            await websocket.send(json.dumps({
                'error': f'Unknown message type: {message_type}'
            }))
    
    async def handle_subscription(self, websocket, data):
        """Handle subscription request"""
        subscription_type = data.get('subscription')
        
        if subscription_type not in ['metrics', 'attacks', 'logs']:
            await websocket.send(json.dumps({
                'error': f'Invalid subscription type: {subscription_type}'
            }))
            return
        
        if websocket not in self.subscriptions:
            self.subscriptions[websocket] = set()
        
        self.subscriptions[websocket].add(subscription_type)
        
        await websocket.send(json.dumps({
            'type': 'subscription_confirmed',
            'subscription': subscription_type
        }))
    
    async def handle_unsubscription(self, websocket, data):
        """Handle unsubscription request"""
        subscription_type = data.get('subscription')
        
        if websocket in self.subscriptions:
            self.subscriptions[websocket].discard(subscription_type)
        
        await websocket.send(json.dumps({
            'type': 'unsubscription_confirmed',
            'subscription': subscription_type
        }))
    
    async def broadcast_update(self, update_type: str, data: Dict):
        """Broadcast update to subscribed connections"""
        if not self.connections:
            return
        
        message = json.dumps({
            'type': 'update',
            'update_type': update_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
        
        # Send to subscribed connections
        disconnected = set()
        for websocket in self.connections:
            if websocket in self.subscriptions and update_type in self.subscriptions[websocket]:
                try:
                    await websocket.send(message)
                except Exception as e:
                    logger.error(f"Failed to send update to {websocket.remote_address}: {e}")
                    disconnected.add(websocket)
        
        # Clean up disconnected connections
        for websocket in disconnected:
            self.connections.discard(websocket)
            self.subscriptions.pop(websocket, None)
    
    async def start_background_updates(self):
        """Start background task for periodic updates"""
        self.running = True
        
        while self.running:
            try:
                # Send metrics updates
                metrics = SystemMetrics(
                    cpu_usage=45.2,
                    memory_usage=62.8,
                    network_usage=78.5,
                    active_attacks=3,
                    total_pps=15000,
                    total_bandwidth=750.5,
                    timestamp=datetime.now().isoformat()
                )
                
                await self.broadcast_update('metrics', asdict(metrics))
                
                # Wait before next update
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in background updates: {e}")
                await asyncio.sleep(5)
    
    def stop(self):
        """Stop the WebSocket manager"""
        self.running = False

class RESTAPIServer:
    """REST API server implementation"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8081, debug: bool = False):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask and related packages are required for REST API")
        
        self.host = host
        self.port = port
        self.debug = debug
        
        # Initialize Flask app
        self.app = Flask(__name__)
        self.app.config['JWT_SECRET_KEY'] = 'ddos-framework-jwt-secret'  # Change in production
        
        # Initialize extensions
        self.api = Api(self.app)
        self.jwt = JWTManager(self.app)
        self.limiter = Limiter(
            app=self.app,
            key_func=get_remote_address,
            default_limits=["1000 per hour"]
        )
        
        # Enable CORS
        CORS(self.app)
        
        # Setup routes
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        # Authentication endpoint
        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            """Login endpoint"""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            # Validate credentials (mock implementation)
            if username == 'admin' and password == 'admin123':
                access_token = create_access_token(identity=username)
                return jsonify(APIResponse(
                    success=True,
                    data={'access_token': access_token},
                    message="Login successful"
                ).to_dict())
            else:
                return jsonify(APIResponse(
                    success=False,
                    error="Invalid credentials"
                ).to_dict()), 401
        
        # API info endpoint
        @self.app.route('/api/info')
        def api_info():
            """API information endpoint"""
            return jsonify(APIResponse(
                success=True,
                data={
                    'name': 'DDoS Testing Framework API',
                    'version': '1.0.0',
                    'endpoints': {
                        'attacks': '/api/attacks',
                        'targets': '/api/targets',
                        'metrics': '/api/metrics',
                        'config': '/api/config'
                    },
                    'websocket': f'ws://{self.host}:8082',
                    'graphql': '/api/graphql'
                }
            ).to_dict())
        
        # Register REST resources
        self.api.add_resource(AttackResource, 
                            '/api/attacks', 
                            '/api/attacks/<string:attack_id>')
        self.api.add_resource(TargetResource, 
                            '/api/targets', 
                            '/api/targets/<string:target>')
        self.api.add_resource(MetricsResource, '/api/metrics')
        self.api.add_resource(ConfigResource, '/api/config')
    
    def run(self):
        """Run the REST API server"""
        logger.info(f"Starting REST API server on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=self.debug)

class GraphQLAPIServer:
    """GraphQL API server implementation"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8083, debug: bool = False):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask and related packages are required for GraphQL API")
        
        self.host = host
        self.port = port
        self.debug = debug
        
        # Initialize Flask app
        self.app = Flask(__name__)
        
        # Create GraphQL schema
        self.schema = Schema(query=Query, mutation=Mutation)
        
        # Setup GraphQL endpoint
        self._setup_graphql()
    
    def _setup_graphql(self):
        """Setup GraphQL endpoint"""
        
        # GraphQL endpoint
        self.app.add_url_rule('/graphql', 
                            view_func=GraphQLView.as_view(
                                'graphql',
                                schema=self.schema,
                                graphiql=True  # Enable GraphiQL interface
                            ))
        
        # GraphQL info endpoint
        @self.app.route('/api/graphql/schema')
        def schema_info():
            """GraphQL schema information"""
            return jsonify({
                'schema': str(self.schema),
                'endpoint': '/graphql',
                'graphiql': True,
                'queries': [
                    'attack(id: String!)',
                    'attacks(status: String, protocol: String)',
                    'target(target: String!)',
                    'metrics',
                    'historicalMetrics(startTime: String, endTime: String, interval: String)'
                ],
                'mutations': [
                    'startAttack(target: String!, port: Int!, protocol: String!, duration: Int, processes: Int)',
                    'stopAttack(id: String!)'
                ]
            })
    
    def run(self):
        """Run the GraphQL API server"""
        logger.info(f"Starting GraphQL API server on {self.host}:{self.port}")
        logger.info(f"GraphiQL interface available at http://{self.host}:{self.port}/graphql")
        self.app.run(host=self.host, port=self.port, debug=self.debug)

async def run_websocket_server():
    """Run WebSocket server"""
    if not WEBSOCKETS_AVAILABLE:
        logger.error("websockets library not available")
        return
    
    manager = WebSocketManager()
    
    # Start background updates
    asyncio.create_task(manager.start_background_updates())
    
    # Start WebSocket server
    logger.info("Starting WebSocket server on 0.0.0.0:8082")
    
    async with websockets.serve(manager.register_connection, "0.0.0.0", 8082):
        await asyncio.Future()  # Run forever

def main():
    """Main entry point for API servers"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python api.py [rest|graphql|websocket|all]")
        sys.exit(1)
    
    server_type = sys.argv[1].lower()
    
    if server_type == 'rest':
        server = RESTAPIServer(debug=True)
        server.run()
    elif server_type == 'graphql':
        server = GraphQLAPIServer(debug=True)
        server.run()
    elif server_type == 'websocket':
        asyncio.run(run_websocket_server())
    elif server_type == 'all':
        # Run all servers in separate threads
        import threading
        
        # REST API thread
        rest_server = RESTAPIServer(port=8081, debug=False)
        rest_thread = threading.Thread(target=rest_server.run, daemon=True)
        rest_thread.start()
        
        # GraphQL API thread
        graphql_server = GraphQLAPIServer(port=8083, debug=False)
        graphql_thread = threading.Thread(target=graphql_server.run, daemon=True)
        graphql_thread.start()
        
        # WebSocket server
        asyncio.run(run_websocket_server())
    else:
        print(f"Unknown server type: {server_type}")
        sys.exit(1)

if __name__ == "__main__":
    main()