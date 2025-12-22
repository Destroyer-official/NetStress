"""
Mobile API Gateway and Remote Management Service

This module provides:
- Mobile-optimized API endpoints
- Remote management capabilities
- Push notifications for mobile apps
- Lightweight data formats for mobile consumption
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    from flask import Flask, request, jsonify
    from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class MobileSession:
    """Mobile session information"""
    session_id: str
    device_id: str
    device_type: str  # ios, android, web
    app_version: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    push_token: Optional[str] = None
    preferences: Dict = None

@dataclass
class MobileNotification:
    """Mobile push notification"""
    id: str
    title: str
    message: str
    type: str  # info, warning, error, success
    data: Dict
    created_at: datetime
    sent_at: Optional[datetime] = None

@dataclass
class LightweightAttackInfo:
    """Lightweight attack info for mobile"""
    id: str
    target: str
    port: int
    protocol: str
    status: str
    pps: int
    duration: int

@dataclass
class MobileMetrics:
    """Simplified metrics for mobile display"""
    active_attacks: int
    total_pps: int
    bandwidth_mbps: float
    cpu_percent: float
    memory_percent: float
    status: str  # healthy, warning, critical

class PushNotificationService:
    """Handles push notifications for mobile devices"""
    
    def __init__(self):
        self.notification_queue = []
        self.device_tokens = {}
        self.notification_history = {}
    
    def register_device(self, device_id: str, push_token: str, device_type: str):
        """Register device for push notifications"""
        self.device_tokens[device_id] = {
            'token': push_token,
            'type': device_type,
            'registered_at': datetime.now(),
            'active': True
        }
        logger.info(f"Registered device {device_id} for push notifications")
    
    def send_notification(self, device_id: str, notification: MobileNotification) -> bool:
        """Send push notification to device"""
        if device_id not in self.device_tokens:
            logger.warning(f"Device {device_id} not registered for notifications")
            return False
        
        device_info = self.device_tokens[device_id]
        
        # In a real implementation, this would integrate with FCM/APNS
        logger.info(f"Sending notification to {device_id}: {notification.title}")
        
        # Store in history
        if device_id not in self.notification_history:
            self.notification_history[device_id] = []
        
        notification.sent_at = datetime.now()
        self.notification_history[device_id].append(notification)
        
        # Keep only last 100 notifications per device
        if len(self.notification_history[device_id]) > 100:
            self.notification_history[device_id] = self.notification_history[device_id][-100:]
        
        return True
    
    def broadcast_notification(self, notification: MobileNotification, device_types: List[str] = None):
        """Broadcast notification to all registered devices"""
        sent_count = 0
        
        for device_id, device_info in self.device_tokens.items():
            if device_types and device_info['type'] not in device_types:
                continue
            
            if self.send_notification(device_id, notification):
                sent_count += 1
        
        logger.info(f"Broadcast notification sent to {sent_count} devices")
        return sent_count
    
    def get_notification_history(self, device_id: str, limit: int = 50) -> List[MobileNotification]:
        """Get notification history for device"""
        history = self.notification_history.get(device_id, [])
        return history[-limit:] if limit else history

class MobileSessionManager:
    """Manages mobile app sessions"""
    
    def __init__(self):
        self.sessions = {}
        self.device_sessions = {}
    
    def create_session(self, device_id: str, device_type: str, app_version: str, user_id: str) -> MobileSession:
        """Create new mobile session"""
        session_id = f"mobile_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        session = MobileSession(
            session_id=session_id,
            device_id=device_id,
            device_type=device_type,
            app_version=app_version,
            user_id=user_id,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            preferences={}
        )
        
        self.sessions[session_id] = session
        self.device_sessions[device_id] = session_id
        
        logger.info(f"Created mobile session {session_id} for device {device_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[MobileSession]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def get_session_by_device(self, device_id: str) -> Optional[MobileSession]:
        """Get session by device ID"""
        session_id = self.device_sessions.get(device_id)
        return self.sessions.get(session_id) if session_id else None
    
    def update_activity(self, session_id: str):
        """Update session last activity"""
        if session_id in self.sessions:
            self.sessions[session_id].last_activity = datetime.now()
    
    def end_session(self, session_id: str):
        """End mobile session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            del self.sessions[session_id]
            self.device_sessions.pop(session.device_id, None)
            logger.info(f"Ended mobile session {session_id}")
    
    def cleanup_expired_sessions(self, timeout_hours: int = 24):
        """Clean up expired sessions"""
        cutoff_time = datetime.now() - timedelta(hours=timeout_hours)
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if session.last_activity < cutoff_time:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.end_session(session_id)
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired mobile sessions")

class MobileDataOptimizer:
    """Optimizes data for mobile consumption"""
    
    @staticmethod
    def optimize_attack_list(attacks: List[Dict]) -> List[LightweightAttackInfo]:
        """Convert full attack data to lightweight format"""
        lightweight_attacks = []
        
        for attack in attacks:
            lightweight = LightweightAttackInfo(
                id=attack.get('id', ''),
                target=attack.get('target', ''),
                port=attack.get('port', 0),
                protocol=attack.get('protocol', ''),
                status=attack.get('status', ''),
                pps=attack.get('pps', 0),
                duration=attack.get('duration', 0)
            )
            lightweight_attacks.append(lightweight)
        
        return lightweight_attacks
    
    @staticmethod
    def optimize_metrics(full_metrics: Dict) -> MobileMetrics:
        """Convert full metrics to mobile-friendly format"""
        # Determine overall status
        cpu = full_metrics.get('cpu_usage', 0)
        memory = full_metrics.get('memory_usage', 0)
        
        if cpu > 90 or memory > 90:
            status = 'critical'
        elif cpu > 70 or memory > 70:
            status = 'warning'
        else:
            status = 'healthy'
        
        return MobileMetrics(
            active_attacks=full_metrics.get('active_attacks', 0),
            total_pps=full_metrics.get('total_pps', 0),
            bandwidth_mbps=full_metrics.get('total_bandwidth', 0.0),
            cpu_percent=cpu,
            memory_percent=memory,
            status=status
        )
    
    @staticmethod
    def create_summary_dashboard(attacks: List[Dict], metrics: Dict) -> Dict:
        """Create summary dashboard for mobile"""
        active_attacks = [a for a in attacks if a.get('status') == 'active']
        
        return {
            'summary': {
                'active_attacks': len(active_attacks),
                'total_attacks': len(attacks),
                'total_pps': sum(a.get('pps', 0) for a in active_attacks),
                'system_status': MobileDataOptimizer.optimize_metrics(metrics).status
            },
            'recent_attacks': MobileDataOptimizer.optimize_attack_list(attacks[-5:]),
            'quick_metrics': asdict(MobileDataOptimizer.optimize_metrics(metrics))
        }

class RemoteManagementService:
    """Provides remote management capabilities"""
    
    def __init__(self):
        self.remote_commands = {}
        self.command_history = []
        self.authorized_devices = set()
    
    def authorize_device(self, device_id: str, user_id: str) -> bool:
        """Authorize device for remote management"""
        # In real implementation, check user permissions
        self.authorized_devices.add(device_id)
        logger.info(f"Authorized device {device_id} for remote management")
        return True
    
    def revoke_device_authorization(self, device_id: str):
        """Revoke device authorization"""
        self.authorized_devices.discard(device_id)
        logger.info(f"Revoked authorization for device {device_id}")
    
    def execute_remote_command(self, device_id: str, command: str, params: Dict) -> Dict:
        """Execute remote command"""
        if device_id not in self.authorized_devices:
            return {
                'success': False,
                'error': 'Device not authorized for remote management'
            }
        
        command_id = f"cmd_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        # Log command
        command_record = {
            'id': command_id,
            'device_id': device_id,
            'command': command,
            'params': params,
            'timestamp': datetime.now().isoformat(),
            'status': 'executing'
        }
        
        self.command_history.append(command_record)
        
        # Execute command based on type
        try:
            if command == 'start_attack':
                result = self._execute_start_attack(params)
            elif command == 'stop_attack':
                result = self._execute_stop_attack(params)
            elif command == 'get_status':
                result = self._execute_get_status(params)
            elif command == 'emergency_stop':
                result = self._execute_emergency_stop(params)
            else:
                result = {
                    'success': False,
                    'error': f'Unknown command: {command}'
                }
            
            # Update command status
            command_record['status'] = 'completed' if result['success'] else 'failed'
            command_record['result'] = result
            
            return {
                'success': True,
                'command_id': command_id,
                'result': result
            }
            
        except Exception as e:
            command_record['status'] = 'error'
            command_record['error'] = str(e)
            
            return {
                'success': False,
                'command_id': command_id,
                'error': str(e)
            }
    
    def _execute_start_attack(self, params: Dict) -> Dict:
        """Execute start attack command"""
        # Validate required parameters
        required = ['target', 'port', 'protocol']
        for param in required:
            if param not in params:
                return {
                    'success': False,
                    'error': f'Missing required parameter: {param}'
                }
        
        # In real implementation, integrate with attack engine
        attack_id = f"remote_attack_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        return {
            'success': True,
            'attack_id': attack_id,
            'message': 'Attack started successfully'
        }
    
    def _execute_stop_attack(self, params: Dict) -> Dict:
        """Execute stop attack command"""
        attack_id = params.get('attack_id')
        if not attack_id:
            return {
                'success': False,
                'error': 'Missing attack_id parameter'
            }
        
        # In real implementation, integrate with attack engine
        return {
            'success': True,
            'message': f'Attack {attack_id} stopped successfully'
        }
    
    def _execute_get_status(self, params: Dict) -> Dict:
        """Execute get status command"""
        # Return current system status
        return {
            'success': True,
            'status': {
                'active_attacks': 2,
                'total_pps': 10000,
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'system_health': 'healthy'
            }
        }
    
    def _execute_emergency_stop(self, params: Dict) -> Dict:
        """Execute emergency stop command"""
        # In real implementation, stop all attacks immediately
        return {
            'success': True,
            'message': 'Emergency stop executed - all attacks terminated'
        }
    
    def get_command_history(self, device_id: str, limit: int = 50) -> List[Dict]:
        """Get command history for device"""
        device_commands = [
            cmd for cmd in self.command_history
            if cmd['device_id'] == device_id
        ]
        
        return device_commands[-limit:] if limit else device_commands

class MobileAPIGateway:
    """Mobile API Gateway - optimized endpoints for mobile apps"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8084, debug: bool = False):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is required for Mobile API Gateway")
        
        self.host = host
        self.port = port
        self.debug = debug
        
        # Initialize Flask app
        self.app = Flask(__name__)
        self.app.config['JWT_SECRET_KEY'] = 'mobile-api-jwt-secret'
        
        # Initialize extensions
        self.jwt = JWTManager(self.app)
        CORS(self.app)
        
        # Initialize services
        self.session_manager = MobileSessionManager()
        self.push_service = PushNotificationService()
        self.remote_service = RemoteManagementService()
        self.data_optimizer = MobileDataOptimizer()
        
        # Setup routes
        self._setup_routes()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _setup_routes(self):
        """Setup mobile API routes"""
        
        @self.app.route('/mobile/auth/login', methods=['POST'])
        def mobile_login():
            """Mobile login endpoint"""
            data = request.get_json()
            
            username = data.get('username')
            password = data.get('password')
            device_id = data.get('device_id')
            device_type = data.get('device_type', 'unknown')
            app_version = data.get('app_version', '1.0.0')
            push_token = data.get('push_token')
            
            # Validate credentials (mock implementation)
            if username == 'admin' and password == 'admin123':
                # Create JWT token
                access_token = create_access_token(identity=username)
                
                # Create mobile session
                session = self.session_manager.create_session(
                    device_id, device_type, app_version, username
                )
                
                # Register for push notifications if token provided
                if push_token:
                    self.push_service.register_device(device_id, push_token, device_type)
                    session.push_token = push_token
                
                return jsonify({
                    'success': True,
                    'access_token': access_token,
                    'session_id': session.session_id,
                    'user': {
                        'username': username,
                        'permissions': ['read', 'write', 'admin']
                    }
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid credentials'
                }), 401
        
        @self.app.route('/mobile/dashboard')
        @jwt_required()
        def mobile_dashboard():
            """Mobile dashboard endpoint"""
            # Get current attacks and metrics (mock data)
            attacks = [
                {
                    'id': 'attack_001',
                    'target': '192.168.1.100',
                    'port': 80,
                    'protocol': 'HTTP',
                    'status': 'active',
                    'pps': 5000,
                    'duration': 120
                },
                {
                    'id': 'attack_002',
                    'target': '192.168.1.101',
                    'port': 443,
                    'protocol': 'HTTPS',
                    'status': 'completed',
                    'pps': 0,
                    'duration': 300
                }
            ]
            
            metrics = {
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'active_attacks': 1,
                'total_pps': 5000,
                'total_bandwidth': 250.5
            }
            
            # Create optimized dashboard
            dashboard = self.data_optimizer.create_summary_dashboard(attacks, metrics)
            
            return jsonify({
                'success': True,
                'data': dashboard
            })
        
        @self.app.route('/mobile/attacks')
        @jwt_required()
        def mobile_attacks():
            """Mobile attacks list endpoint"""
            # Get attacks (mock data)
            attacks = [
                {
                    'id': 'attack_001',
                    'target': '192.168.1.100',
                    'port': 80,
                    'protocol': 'HTTP',
                    'status': 'active',
                    'pps': 5000,
                    'duration': 120
                }
            ]
            
            # Optimize for mobile
            lightweight_attacks = self.data_optimizer.optimize_attack_list(attacks)
            
            return jsonify({
                'success': True,
                'data': [asdict(attack) for attack in lightweight_attacks]
            })
        
        @self.app.route('/mobile/attacks/start', methods=['POST'])
        @jwt_required()
        def mobile_start_attack():
            """Mobile start attack endpoint"""
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['target', 'port', 'protocol']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        'success': False,
                        'error': f'Missing field: {field}'
                    }), 400
            
            # Start attack (mock implementation)
            attack_id = f"mobile_attack_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            
            # Send push notification
            notification = MobileNotification(
                id=str(uuid.uuid4()),
                title="Attack Started",
                message=f"Attack on {data['target']}:{data['port']} started successfully",
                type="success",
                data={'attack_id': attack_id},
                created_at=datetime.now()
            )
            
            device_id = request.headers.get('X-Device-ID')
            if device_id:
                self.push_service.send_notification(device_id, notification)
            
            return jsonify({
                'success': True,
                'attack_id': attack_id,
                'message': 'Attack started successfully'
            })
        
        @self.app.route('/mobile/attacks/<attack_id>/stop', methods=['POST'])
        @jwt_required()
        def mobile_stop_attack(attack_id):
            """Mobile stop attack endpoint"""
            # Stop attack (mock implementation)
            
            # Send push notification
            notification = MobileNotification(
                id=str(uuid.uuid4()),
                title="Attack Stopped",
                message=f"Attack {attack_id} has been stopped",
                type="info",
                data={'attack_id': attack_id},
                created_at=datetime.now()
            )
            
            device_id = request.headers.get('X-Device-ID')
            if device_id:
                self.push_service.send_notification(device_id, notification)
            
            return jsonify({
                'success': True,
                'message': 'Attack stopped successfully'
            })
        
        @self.app.route('/mobile/metrics')
        @jwt_required()
        def mobile_metrics():
            """Mobile metrics endpoint"""
            # Get current metrics (mock data)
            full_metrics = {
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'active_attacks': 1,
                'total_pps': 5000,
                'total_bandwidth': 250.5
            }
            
            # Optimize for mobile
            mobile_metrics = self.data_optimizer.optimize_metrics(full_metrics)
            
            return jsonify({
                'success': True,
                'data': asdict(mobile_metrics)
            })
        
        @self.app.route('/mobile/remote/execute', methods=['POST'])
        @jwt_required()
        def mobile_remote_execute():
            """Mobile remote command execution"""
            data = request.get_json()
            device_id = request.headers.get('X-Device-ID')
            
            if not device_id:
                return jsonify({
                    'success': False,
                    'error': 'Device ID required'
                }), 400
            
            command = data.get('command')
            params = data.get('params', {})
            
            if not command:
                return jsonify({
                    'success': False,
                    'error': 'Command required'
                }), 400
            
            # Execute remote command
            result = self.remote_service.execute_remote_command(device_id, command, params)
            
            return jsonify(result)
        
        @self.app.route('/mobile/notifications')
        @jwt_required()
        def mobile_notifications():
            """Get notification history"""
            device_id = request.headers.get('X-Device-ID')
            limit = request.args.get('limit', 50, type=int)
            
            if not device_id:
                return jsonify({
                    'success': False,
                    'error': 'Device ID required'
                }), 400
            
            notifications = self.push_service.get_notification_history(device_id, limit)
            
            return jsonify({
                'success': True,
                'data': [asdict(notif) for notif in notifications]
            })
        
        @self.app.route('/mobile/session/heartbeat', methods=['POST'])
        @jwt_required()
        def mobile_heartbeat():
            """Mobile session heartbeat"""
            session_id = request.headers.get('X-Session-ID')
            
            if session_id:
                self.session_manager.update_activity(session_id)
            
            return jsonify({
                'success': True,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/mobile/info')
        def mobile_api_info():
            """Mobile API information"""
            return jsonify({
                'name': 'DDoS Framework Mobile API',
                'version': '1.0.0',
                'endpoints': {
                    'login': '/mobile/auth/login',
                    'dashboard': '/mobile/dashboard',
                    'attacks': '/mobile/attacks',
                    'metrics': '/mobile/metrics',
                    'remote': '/mobile/remote/execute',
                    'notifications': '/mobile/notifications'
                },
                'features': [
                    'Push notifications',
                    'Remote management',
                    'Optimized data formats',
                    'Real-time updates'
                ]
            })
    
    def _start_background_tasks(self):
        """Start background tasks"""
        import threading
        
        def cleanup_task():
            """Background cleanup task"""
            while True:
                try:
                    # Clean up expired sessions
                    self.session_manager.cleanup_expired_sessions()
                    
                    # Sleep for 1 hour
                    time.sleep(3600)
                    
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")
                    time.sleep(300)  # Sleep 5 minutes on error
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
    
    def run(self):
        """Run the mobile API gateway"""
        logger.info(f"Starting Mobile API Gateway on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=self.debug)

def main():
    """Main entry point for mobile API gateway"""
    gateway = MobileAPIGateway(debug=True)
    gateway.run()

if __name__ == "__main__":
    main()