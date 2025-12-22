"""
Modern Web-Based GUI for DDoS Testing Framework

This module provides:
- Responsive web interface with real-time updates
- Advanced visualization and control panels
- Collaborative features and multi-user support
- Interactive dashboards and monitoring
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import threading
import weakref

try:
    from flask import Flask, render_template, request, jsonify, session, redirect, url_for
    from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
    from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
    from werkzeug.security import generate_password_hash, check_password_hash
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    # Create dummy classes when Flask is not available
    class UserMixin:
        pass

logger = logging.getLogger(__name__)

class User(UserMixin):
    """User model for authentication"""
    def __init__(self, user_id: str, username: str, password_hash: str, role: str = 'user'):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.created_at = datetime.now()
        self.last_login = None
        self.active_sessions = set()

class UserManager:
    """Manages user authentication and sessions"""
    
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self._init_default_users()
    
    def _init_default_users(self):
        """Initialize default admin user"""
        admin_id = str(uuid.uuid4())
        admin_hash = generate_password_hash('admin123')  # Change in production
        self.users[admin_id] = User(admin_id, 'admin', admin_hash, 'admin')
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user credentials"""
        for user in self.users.values():
            if user.username == username and check_password_hash(user.password_hash, password):
                user.last_login = datetime.now()
                return user
        return None
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def create_user(self, username: str, password: str, role: str = 'user') -> User:
        """Create new user"""
        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)
        user = User(user_id, username, password_hash, role)
        self.users[user_id] = user
        return user
    
    def add_session(self, user_id: str, session_id: str):
        """Add active session for user"""
        if user_id in self.users:
            self.users[user_id].active_sessions.add(session_id)
    
    def remove_session(self, user_id: str, session_id: str):
        """Remove session for user"""
        if user_id in self.users:
            self.users[user_id].active_sessions.discard(session_id)

class DashboardManager:
    """Manages dashboard layouts and widgets"""
    
    def __init__(self):
        self.dashboards = {}
        self.widgets = {}
        self._init_default_dashboards()
    
    def _init_default_dashboards(self):
        """Initialize default dashboard layouts"""
        self.dashboards['main'] = {
            'id': 'main',
            'name': 'Main Dashboard',
            'layout': {
                'rows': [
                    {
                        'columns': [
                            {'widget': 'attack_status', 'width': 6},
                            {'widget': 'system_metrics', 'width': 6}
                        ]
                    },
                    {
                        'columns': [
                            {'widget': 'real_time_chart', 'width': 8},
                            {'widget': 'target_list', 'width': 4}
                        ]
                    },
                    {
                        'columns': [
                            {'widget': 'network_topology', 'width': 12}
                        ]
                    }
                ]
            }
        }
        
        self.dashboards['monitoring'] = {
            'id': 'monitoring',
            'name': 'Monitoring Dashboard',
            'layout': {
                'rows': [
                    {
                        'columns': [
                            {'widget': 'performance_metrics', 'width': 4},
                            {'widget': 'error_rates', 'width': 4},
                            {'widget': 'bandwidth_usage', 'width': 4}
                        ]
                    },
                    {
                        'columns': [
                            {'widget': 'attack_timeline', 'width': 12}
                        ]
                    }
                ]
            }
        }
    
    def get_dashboard(self, dashboard_id: str) -> Optional[Dict]:
        """Get dashboard configuration"""
        return self.dashboards.get(dashboard_id)
    
    def create_dashboard(self, name: str, layout: Dict) -> str:
        """Create new dashboard"""
        dashboard_id = str(uuid.uuid4())
        self.dashboards[dashboard_id] = {
            'id': dashboard_id,
            'name': name,
            'layout': layout,
            'created_at': datetime.now().isoformat()
        }
        return dashboard_id
    
    def update_dashboard(self, dashboard_id: str, layout: Dict) -> bool:
        """Update dashboard layout"""
        if dashboard_id in self.dashboards:
            self.dashboards[dashboard_id]['layout'] = layout
            self.dashboards[dashboard_id]['updated_at'] = datetime.now().isoformat()
            return True
        return False

class VisualizationEngine:
    """Handles data visualization and chart generation"""
    
    def __init__(self):
        self.chart_configs = {}
        self.data_sources = {}
        self._init_chart_configs()
    
    def _init_chart_configs(self):
        """Initialize default chart configurations"""
        self.chart_configs = {
            'attack_status': {
                'type': 'donut',
                'title': 'Attack Status',
                'data_source': 'attack_metrics',
                'config': {
                    'labels': ['Active', 'Completed', 'Failed'],
                    'colors': ['#28a745', '#007bff', '#dc3545']
                }
            },
            'real_time_chart': {
                'type': 'line',
                'title': 'Real-time Metrics',
                'data_source': 'real_time_metrics',
                'config': {
                    'x_axis': 'timestamp',
                    'y_axes': ['pps', 'bandwidth', 'connections'],
                    'colors': ['#007bff', '#28a745', '#ffc107'],
                    'update_interval': 1000
                }
            },
            'performance_metrics': {
                'type': 'gauge',
                'title': 'Performance Metrics',
                'data_source': 'system_performance',
                'config': {
                    'metrics': ['cpu_usage', 'memory_usage', 'network_usage'],
                    'thresholds': [70, 85, 95]
                }
            },
            'network_topology': {
                'type': '3d_network',
                'title': 'Network Topology',
                'data_source': 'network_topology',
                'config': {
                    'node_types': ['target', 'attacker', 'amplifier'],
                    'edge_types': ['attack', 'reflection', 'response'],
                    'physics_enabled': True
                }
            },
            'attack_timeline': {
                'type': 'timeline',
                'title': 'Attack Timeline',
                'data_source': 'attack_history',
                'config': {
                    'time_range': '24h',
                    'event_types': ['start', 'stop', 'error', 'milestone']
                }
            }
        }
    
    def get_chart_data(self, chart_id: str) -> Dict:
        """Get data for specific chart"""
        config = self.chart_configs.get(chart_id)
        if not config:
            return {'error': 'Chart not found'}
        
        data_source = config['data_source']
        
        # Generate mock data based on chart type
        if chart_id == 'attack_status':
            return {
                'labels': ['Active', 'Completed', 'Failed'],
                'data': [3, 15, 2],
                'colors': ['#28a745', '#007bff', '#dc3545']
            }
        elif chart_id == 'real_time_chart':
            # Generate time series data
            now = time.time()
            timestamps = [now - i for i in range(60, 0, -1)]
            return {
                'timestamps': timestamps,
                'datasets': [
                    {
                        'label': 'PPS',
                        'data': [1000 + i * 10 for i in range(60)],
                        'color': '#007bff'
                    },
                    {
                        'label': 'Bandwidth (Mbps)',
                        'data': [50 + i * 2 for i in range(60)],
                        'color': '#28a745'
                    }
                ]
            }
        elif chart_id == 'performance_metrics':
            return {
                'cpu_usage': 45.2,
                'memory_usage': 62.8,
                'network_usage': 78.5
            }
        elif chart_id == 'network_topology':
            return {
                'nodes': [
                    {'id': 'attacker', 'type': 'attacker', 'x': 0, 'y': 0, 'z': 0},
                    {'id': 'target1', 'type': 'target', 'x': 100, 'y': 0, 'z': 0},
                    {'id': 'target2', 'type': 'target', 'x': 50, 'y': 87, 'z': 0},
                    {'id': 'amp1', 'type': 'amplifier', 'x': -50, 'y': 50, 'z': 50}
                ],
                'edges': [
                    {'from': 'attacker', 'to': 'target1', 'type': 'attack', 'weight': 1000},
                    {'from': 'attacker', 'to': 'amp1', 'type': 'reflection', 'weight': 500},
                    {'from': 'amp1', 'to': 'target1', 'type': 'amplified', 'weight': 5000}
                ]
            }
        
        return {'error': 'No data available'}
    
    def get_chart_config(self, chart_id: str) -> Dict:
        """Get chart configuration"""
        return self.chart_configs.get(chart_id, {})

class CollaborationManager:
    """Manages collaborative features and multi-user support"""
    
    def __init__(self):
        self.active_users = {}
        self.shared_sessions = {}
        self.chat_rooms = {}
        self.user_cursors = {}
    
    def add_user_to_session(self, user_id: str, session_id: str, username: str):
        """Add user to collaborative session"""
        if session_id not in self.shared_sessions:
            self.shared_sessions[session_id] = {
                'users': {},
                'created_at': datetime.now(),
                'last_activity': datetime.now()
            }
        
        self.shared_sessions[session_id]['users'][user_id] = {
            'username': username,
            'joined_at': datetime.now(),
            'cursor_position': None,
            'active': True
        }
        
        self.active_users[user_id] = session_id
    
    def remove_user_from_session(self, user_id: str, session_id: str):
        """Remove user from collaborative session"""
        if session_id in self.shared_sessions:
            self.shared_sessions[session_id]['users'].pop(user_id, None)
            
            # Clean up empty sessions
            if not self.shared_sessions[session_id]['users']:
                del self.shared_sessions[session_id]
        
        self.active_users.pop(user_id, None)
    
    def update_user_cursor(self, user_id: str, cursor_data: Dict):
        """Update user cursor position for collaborative editing"""
        session_id = self.active_users.get(user_id)
        if session_id and session_id in self.shared_sessions:
            if user_id in self.shared_sessions[session_id]['users']:
                self.shared_sessions[session_id]['users'][user_id]['cursor_position'] = cursor_data
                self.shared_sessions[session_id]['last_activity'] = datetime.now()
    
    def get_session_users(self, session_id: str) -> List[Dict]:
        """Get all users in a session"""
        if session_id not in self.shared_sessions:
            return []
        
        return [
            {
                'user_id': user_id,
                'username': user_data['username'],
                'cursor_position': user_data['cursor_position'],
                'active': user_data['active']
            }
            for user_id, user_data in self.shared_sessions[session_id]['users'].items()
        ]
    
    def add_chat_message(self, session_id: str, user_id: str, username: str, message: str):
        """Add chat message to session"""
        if session_id not in self.chat_rooms:
            self.chat_rooms[session_id] = []
        
        chat_message = {
            'id': str(uuid.uuid4()),
            'user_id': user_id,
            'username': username,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        self.chat_rooms[session_id].append(chat_message)
        
        # Keep only last 100 messages
        if len(self.chat_rooms[session_id]) > 100:
            self.chat_rooms[session_id] = self.chat_rooms[session_id][-100:]
        
        return chat_message
    
    def get_chat_messages(self, session_id: str, limit: int = 50) -> List[Dict]:
        """Get chat messages for session"""
        messages = self.chat_rooms.get(session_id, [])
        return messages[-limit:] if limit else messages

class WebGUI:
    """Main web GUI application"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
        if not FLASK_AVAILABLE:
            raise ImportError("Flask and related packages are required for web GUI")
        
        self.host = host
        self.port = port
        self.debug = debug
        
        # Initialize Flask app
        self.app = Flask(__name__, 
                        template_folder=self._get_template_dir(),
                        static_folder=self._get_static_dir())
        self.app.secret_key = os.urandom(24)
        
        # Initialize SocketIO for real-time updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize managers
        self.user_manager = UserManager()
        self.dashboard_manager = DashboardManager()
        self.visualization_engine = VisualizationEngine()
        self.collaboration_manager = CollaborationManager()
        
        # Initialize login manager
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'login'
        
        # Setup routes and socket handlers
        self._setup_routes()
        self._setup_socket_handlers()
        
        # Background tasks
        self._setup_background_tasks()
    
    def _get_template_dir(self) -> str:
        """Get templates directory"""
        return str(Path(__file__).parent / 'templates')
    
    def _get_static_dir(self) -> str:
        """Get static files directory"""
        return str(Path(__file__).parent / 'static')
    
    @property
    def login_manager_user_loader(self):
        """User loader for Flask-Login"""
        @self.login_manager.user_loader
        def load_user(user_id):
            return self.user_manager.get_user(user_id)
        return load_user
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        @login_required
        def index():
            """Main dashboard page"""
            dashboard = self.dashboard_manager.get_dashboard('main')
            return render_template('dashboard.html', 
                                 dashboard=dashboard,
                                 user=current_user)
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Login page"""
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                
                user = self.user_manager.authenticate_user(username, password)
                if user:
                    login_user(user)
                    session_id = str(uuid.uuid4())
                    self.user_manager.add_session(user.id, session_id)
                    session['session_id'] = session_id
                    
                    return redirect(url_for('index'))
                else:
                    return render_template('login.html', error='Invalid credentials')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        @login_required
        def logout():
            """Logout user"""
            if 'session_id' in session:
                self.user_manager.remove_session(current_user.id, session['session_id'])
            logout_user()
            return redirect(url_for('login'))
        
        @self.app.route('/dashboard/<dashboard_id>')
        @login_required
        def dashboard(dashboard_id):
            """Specific dashboard page"""
            dashboard = self.dashboard_manager.get_dashboard(dashboard_id)
            if not dashboard:
                return "Dashboard not found", 404
            
            return render_template('dashboard.html', 
                                 dashboard=dashboard,
                                 user=current_user)
        
        @self.app.route('/api/attack/start', methods=['POST'])
        @login_required
        def start_attack():
            """Start attack API endpoint"""
            data = request.get_json()
            
            # Validate required fields
            required_fields = ['target', 'port', 'protocol']
            for field in required_fields:
                if field not in data:
                    return jsonify({'success': False, 'error': f'Missing field: {field}'}), 400
            
            # Start attack (integrate with actual attack engine)
            attack_id = str(uuid.uuid4())
            
            # Emit real-time update
            self.socketio.emit('attack_started', {
                'attack_id': attack_id,
                'target': data['target'],
                'port': data['port'],
                'protocol': data['protocol'],
                'user': current_user.username
            })
            
            return jsonify({
                'success': True,
                'attack_id': attack_id,
                'message': 'Attack started successfully'
            })
        
        @self.app.route('/api/attack/stop', methods=['POST'])
        @login_required
        def stop_attack():
            """Stop attack API endpoint"""
            data = request.get_json()
            attack_id = data.get('attack_id')
            
            if not attack_id:
                return jsonify({'success': False, 'error': 'Missing attack_id'}), 400
            
            # Stop attack (integrate with actual attack engine)
            
            # Emit real-time update
            self.socketio.emit('attack_stopped', {
                'attack_id': attack_id,
                'user': current_user.username
            })
            
            return jsonify({
                'success': True,
                'message': 'Attack stopped successfully'
            })
        
        @self.app.route('/api/chart/<chart_id>')
        @login_required
        def get_chart_data(chart_id):
            """Get chart data API endpoint"""
            data = self.visualization_engine.get_chart_data(chart_id)
            config = self.visualization_engine.get_chart_config(chart_id)
            
            return jsonify({
                'data': data,
                'config': config
            })
        
        @self.app.route('/api/dashboard/<dashboard_id>')
        @login_required
        def get_dashboard_config(dashboard_id):
            """Get dashboard configuration"""
            dashboard = self.dashboard_manager.get_dashboard(dashboard_id)
            if not dashboard:
                return jsonify({'error': 'Dashboard not found'}), 404
            
            return jsonify(dashboard)
        
        @self.app.route('/api/dashboard', methods=['POST'])
        @login_required
        def create_dashboard():
            """Create new dashboard"""
            data = request.get_json()
            name = data.get('name')
            layout = data.get('layout')
            
            if not name or not layout:
                return jsonify({'success': False, 'error': 'Missing name or layout'}), 400
            
            dashboard_id = self.dashboard_manager.create_dashboard(name, layout)
            
            return jsonify({
                'success': True,
                'dashboard_id': dashboard_id
            })
        
        @self.app.route('/api/users/online')
        @login_required
        def get_online_users():
            """Get list of online users"""
            session_id = session.get('session_id')
            if not session_id:
                return jsonify([])
            
            users = self.collaboration_manager.get_session_users(session_id)
            return jsonify(users)
    
    def _setup_socket_handlers(self):
        """Setup SocketIO event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            if current_user.is_authenticated:
                session_id = session.get('session_id')
                if session_id:
                    join_room(session_id)
                    self.collaboration_manager.add_user_to_session(
                        current_user.id, session_id, current_user.username
                    )
                    
                    # Notify other users
                    emit('user_joined', {
                        'user_id': current_user.id,
                        'username': current_user.username
                    }, room=session_id, include_self=False)
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            if current_user.is_authenticated:
                session_id = session.get('session_id')
                if session_id:
                    leave_room(session_id)
                    self.collaboration_manager.remove_user_from_session(
                        current_user.id, session_id
                    )
                    
                    # Notify other users
                    emit('user_left', {
                        'user_id': current_user.id,
                        'username': current_user.username
                    }, room=session_id)
        
        @self.socketio.on('cursor_update')
        def handle_cursor_update(data):
            """Handle cursor position updates"""
            if current_user.is_authenticated:
                session_id = session.get('session_id')
                if session_id:
                    self.collaboration_manager.update_user_cursor(current_user.id, data)
                    
                    # Broadcast cursor position to other users
                    emit('cursor_moved', {
                        'user_id': current_user.id,
                        'username': current_user.username,
                        'cursor_data': data
                    }, room=session_id, include_self=False)
        
        @self.socketio.on('chat_message')
        def handle_chat_message(data):
            """Handle chat messages"""
            if current_user.is_authenticated:
                session_id = session.get('session_id')
                message = data.get('message', '').strip()
                
                if session_id and message:
                    chat_message = self.collaboration_manager.add_chat_message(
                        session_id, current_user.id, current_user.username, message
                    )
                    
                    # Broadcast message to all users in session
                    emit('new_chat_message', chat_message, room=session_id)
        
        @self.socketio.on('request_chart_update')
        def handle_chart_update_request(data):
            """Handle chart update requests"""
            chart_id = data.get('chart_id')
            if chart_id:
                chart_data = self.visualization_engine.get_chart_data(chart_id)
                emit('chart_data_update', {
                    'chart_id': chart_id,
                    'data': chart_data
                })
        
        @self.socketio.on('join_collaboration')
        def handle_join_collaboration(data):
            """Handle joining collaborative session"""
            if current_user.is_authenticated:
                collab_session_id = data.get('session_id')
                if collab_session_id:
                    join_room(collab_session_id)
                    self.collaboration_manager.add_user_to_session(
                        current_user.id, collab_session_id, current_user.username
                    )
    
    def _setup_background_tasks(self):
        """Setup background tasks for real-time updates"""
        
        def real_time_metrics_updater():
            """Background task to push real-time metrics"""
            while True:
                try:
                    # Get current metrics (integrate with actual monitoring system)
                    metrics = {
                        'timestamp': time.time(),
                        'active_attacks': 3,
                        'total_pps': 15000,
                        'total_bandwidth': 750.5,
                        'cpu_usage': 45.2,
                        'memory_usage': 62.8,
                        'network_usage': 78.5
                    }
                    
                    # Emit to all connected clients
                    self.socketio.emit('metrics_update', metrics)
                    
                    time.sleep(1)  # Update every second
                    
                except Exception as e:
                    logger.error(f"Error in metrics updater: {e}")
                    time.sleep(5)
        
        # Start background thread
        metrics_thread = threading.Thread(target=real_time_metrics_updater, daemon=True)
        metrics_thread.start()
    
    def run(self):
        """Run the web GUI server"""
        logger.info(f"Starting web GUI on {self.host}:{self.port}")
        
        # Create template and static directories if they don't exist
        os.makedirs(self._get_template_dir(), exist_ok=True)
        os.makedirs(self._get_static_dir(), exist_ok=True)
        
        # Create basic templates if they don't exist
        self._create_default_templates()
        
        # Run the server
        self.socketio.run(self.app, 
                         host=self.host, 
                         port=self.port, 
                         debug=self.debug,
                         allow_unsafe_werkzeug=True)
    
    def _create_default_templates(self):
        """Create default HTML templates"""
        template_dir = Path(self._get_template_dir())
        
        # Base template
        base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}DDoS Testing Framework{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        .sidebar { min-height: 100vh; background-color: #343a40; }
        .main-content { padding: 20px; }
        .widget { margin-bottom: 20px; }
        .chart-container { position: relative; height: 300px; }
        .user-cursor { position: absolute; pointer-events: none; z-index: 1000; }
        .chat-container { height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <nav class="col-md-2 d-none d-md-block sidebar">
                <div class="sidebar-sticky pt-3">
                    <h5 class="text-white">DDoS Framework</h5>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link text-white" href="/">
                                <i class="fas fa-tachometer-alt"></i> Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link text-white" href="/dashboard/monitoring">
                                <i class="fas fa-chart-line"></i> Monitoring
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link text-white" href="#" onclick="startAttack()">
                                <i class="fas fa-play"></i> Start Attack
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link text-white" href="/logout">
                                <i class="fas fa-sign-out-alt"></i> Logout
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>
            
            <main class="col-md-10 ml-sm-auto col-lg-10 px-md-4 main-content">
                {% block content %}{% endblock %}
            </main>
        </div>
    </div>
    
    <script>
        const socket = io();
        
        socket.on('metrics_update', function(data) {
            updateMetrics(data);
        });
        
        socket.on('attack_started', function(data) {
            showNotification('Attack started by ' + data.user, 'success');
        });
        
        socket.on('attack_stopped', function(data) {
            showNotification('Attack stopped by ' + data.user, 'info');
        });
        
        function updateMetrics(data) {
            // Update dashboard metrics
            document.getElementById('active-attacks').textContent = data.active_attacks;
            document.getElementById('total-pps').textContent = data.total_pps.toLocaleString();
            document.getElementById('total-bandwidth').textContent = data.total_bandwidth.toFixed(1) + ' Mbps';
        }
        
        function showNotification(message, type) {
            // Show bootstrap alert
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);
            
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);
        }
        
        function startAttack() {
            // Show attack configuration modal
            const target = prompt('Enter target IP or domain:');
            const port = prompt('Enter target port:');
            const protocol = prompt('Enter protocol (TCP/UDP/HTTP):');
            
            if (target && port && protocol) {
                fetch('/api/attack/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target: target,
                        port: parseInt(port),
                        protocol: protocol
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showNotification('Attack started successfully', 'success');
                    } else {
                        showNotification('Failed to start attack: ' + data.error, 'danger');
                    }
                });
            }
        }
    </script>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>'''
        
        # Dashboard template
        dashboard_template = '''{% extends "base.html" %}

{% block title %}Dashboard - DDoS Testing Framework{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">{{ dashboard.name }}</h1>
    <div class="btn-toolbar mb-2 mb-md-0">
        <div class="btn-group me-2">
            <button type="button" class="btn btn-sm btn-outline-secondary">Share</button>
            <button type="button" class="btn btn-sm btn-outline-secondary">Export</button>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-3">
        <div class="card widget">
            <div class="card-body">
                <h5 class="card-title">Active Attacks</h5>
                <h2 class="text-primary" id="active-attacks">0</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card widget">
            <div class="card-body">
                <h5 class="card-title">Total PPS</h5>
                <h2 class="text-success" id="total-pps">0</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card widget">
            <div class="card-body">
                <h5 class="card-title">Bandwidth</h5>
                <h2 class="text-info" id="total-bandwidth">0 Mbps</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card widget">
            <div class="card-body">
                <h5 class="card-title">Online Users</h5>
                <h2 class="text-warning" id="online-users">1</h2>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-8">
        <div class="card widget">
            <div class="card-header">
                <h5>Real-time Metrics</h5>
            </div>
            <div class="card-body">
                <div class="chart-container">
                    <canvas id="realTimeChart"></canvas>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card widget">
            <div class="card-header">
                <h5>Collaboration Chat</h5>
            </div>
            <div class="card-body">
                <div class="chat-container" id="chatContainer">
                    <!-- Chat messages will appear here -->
                </div>
                <div class="input-group mt-2">
                    <input type="text" class="form-control" id="chatInput" placeholder="Type a message...">
                    <button class="btn btn-primary" onclick="sendChatMessage()">Send</button>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Initialize real-time chart
const ctx = document.getElementById('realTimeChart').getContext('2d');
const realTimeChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'PPS',
            data: [],
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

// Chat functionality
socket.on('new_chat_message', function(data) {
    addChatMessage(data);
});

function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (message) {
        socket.emit('chat_message', { message: message });
        input.value = '';
    }
}

function addChatMessage(data) {
    const container = document.getElementById('chatContainer');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'mb-2';
    messageDiv.innerHTML = `
        <small class="text-muted">${new Date(data.timestamp).toLocaleTimeString()}</small>
        <strong>${data.username}:</strong> ${data.message}
    `;
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

// Handle Enter key in chat input
document.getElementById('chatInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        sendChatMessage();
    }
});
</script>
{% endblock %}'''
        
        # Login template
        login_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - DDoS Testing Framework</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .login-container { max-width: 400px; margin: 100px auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="card">
                <div class="card-header text-center">
                    <h3>DDoS Testing Framework</h3>
                </div>
                <div class="card-body">
                    {% if error %}
                    <div class="alert alert-danger">{{ error }}</div>
                    {% endif %}
                    
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                    
                    <div class="mt-3 text-center">
                        <small class="text-muted">Default: admin / admin123</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>'''
        
        # Write templates
        (template_dir / 'base.html').write_text(base_template)
        (template_dir / 'dashboard.html').write_text(dashboard_template)
        (template_dir / 'login.html').write_text(login_template)

def main():
    """Main entry point for web GUI"""
    gui = WebGUI(debug=True)
    gui.run()

if __name__ == "__main__":
    main()