"""
Real-time Web Dashboard

Advanced web-based monitoring and control interface:
- Real-time attack statistics
- Live performance graphs
- Target status monitoring
- Attack configuration
- Multi-attack coordination
- Historical data analysis
"""

import asyncio
import json
import time
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import deque
import logging
import http.server
import socketserver
import urllib.parse

logger = logging.getLogger(__name__)


@dataclass
class AttackSession:
    """Active attack session data"""
    session_id: str
    target: str
    port: int
    protocol: str
    start_time: float
    duration: int
    status: str  # running, paused, stopped, completed
    packets_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    pps: float = 0.0
    bps: float = 0.0
    connections: int = 0


@dataclass
class DashboardMetrics:
    """Dashboard metrics snapshot"""
    timestamp: float
    active_attacks: int
    total_pps: float
    total_bps: float
    total_packets: int
    total_bytes: int
    total_errors: int
    cpu_usage: float
    memory_usage: float
    network_usage: float


class MetricsCollector:
    """Collects and aggregates metrics from all attack sessions"""
    
    def __init__(self, history_size: int = 3600):
        self.history_size = history_size
        self.metrics_history: deque = deque(maxlen=history_size)
        self.sessions: Dict[str, AttackSession] = {}
        self._lock = threading.Lock()
        
    def register_session(self, session: AttackSession):
        """Register new attack session"""
        with self._lock:
            self.sessions[session.session_id] = session
    
    def update_session(self, session_id: str, **kwargs):
        """Update session metrics"""
        with self._lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                for key, value in kwargs.items():
                    if hasattr(session, key):
                        setattr(session, key, value)
    
    def remove_session(self, session_id: str):
        """Remove session"""
        with self._lock:
            self.sessions.pop(session_id, None)
    
    def collect_metrics(self) -> DashboardMetrics:
        """Collect current metrics"""
        with self._lock:
            active = [s for s in self.sessions.values() if s.status == 'running']
            
            metrics = DashboardMetrics(
                timestamp=time.time(),
                active_attacks=len(active),
                total_pps=sum(s.pps for s in active),
                total_bps=sum(s.bps for s in active),
                total_packets=sum(s.packets_sent for s in self.sessions.values()),
                total_bytes=sum(s.bytes_sent for s in self.sessions.values()),
                total_errors=sum(s.errors for s in self.sessions.values()),
                cpu_usage=self._get_cpu_usage(),
                memory_usage=self._get_memory_usage(),
                network_usage=self._get_network_usage()
            )
            
            self.metrics_history.append(metrics)
            return metrics
    
    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        try:
            import psutil
            return psutil.cpu_percent()
        except ImportError:
            return 0.0
    
    def _get_memory_usage(self) -> float:
        """Get memory usage percentage"""
        try:
            import psutil
            return psutil.virtual_memory().percent
        except ImportError:
            return 0.0
    
    def _get_network_usage(self) -> float:
        """Get network usage (bytes/sec)"""
        try:
            import psutil
            net = psutil.net_io_counters()
            return (net.bytes_sent + net.bytes_recv) / 1024 / 1024  # MB/s
        except ImportError:
            return 0.0
    
    def get_history(self, seconds: int = 60) -> List[DashboardMetrics]:
        """Get metrics history for last N seconds"""
        cutoff = time.time() - seconds
        return [m for m in self.metrics_history if m.timestamp > cutoff]
    
    def get_sessions(self) -> List[AttackSession]:
        """Get all sessions"""
        with self._lock:
            return list(self.sessions.values())


class DashboardAPI:
    """REST API for dashboard"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.routes: Dict[str, Callable] = {
            '/api/status': self.get_status,
            '/api/metrics': self.get_metrics,
            '/api/metrics/history': self.get_metrics_history,
            '/api/sessions': self.get_sessions,
            '/api/session/start': self.start_session,
            '/api/session/stop': self.stop_session,
            '/api/session/pause': self.pause_session,
            '/api/capabilities': self.get_capabilities,
        }
        self._attack_callback: Optional[Callable] = None
        self._stop_callback: Optional[Callable] = None
    
    def set_attack_callback(self, callback: Callable):
        """Set callback for starting attacks"""
        self._attack_callback = callback
    
    def set_stop_callback(self, callback: Callable):
        """Set callback for stopping attacks"""
        self._stop_callback = callback
    
    def handle_request(self, path: str, method: str = 'GET', 
                      body: Optional[str] = None) -> Dict[str, Any]:
        """Handle API request"""
        # Parse path and query
        parsed = urllib.parse.urlparse(path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        
        handler = self.routes.get(route)
        if handler:
            try:
                if method == 'POST' and body:
                    data = json.loads(body)
                    return handler(data=data, query=query)
                return handler(query=query)
            except Exception as e:
                return {'error': str(e), 'status': 500}
        
        return {'error': 'Not found', 'status': 404}
    
    def get_status(self, **kwargs) -> Dict[str, Any]:
        """Get overall status"""
        metrics = self.metrics.collect_metrics()
        return {
            'status': 'ok',
            'timestamp': metrics.timestamp,
            'active_attacks': metrics.active_attacks,
            'total_pps': metrics.total_pps,
            'total_bps': metrics.total_bps,
            'cpu_usage': metrics.cpu_usage,
            'memory_usage': metrics.memory_usage
        }
    
    def get_metrics(self, **kwargs) -> Dict[str, Any]:
        """Get current metrics"""
        metrics = self.metrics.collect_metrics()
        return asdict(metrics)
    
    def get_metrics_history(self, query: Dict = None, **kwargs) -> Dict[str, Any]:
        """Get metrics history"""
        seconds = int(query.get('seconds', [60])[0]) if query else 60
        history = self.metrics.get_history(seconds)
        return {
            'history': [asdict(m) for m in history],
            'count': len(history)
        }
    
    def get_sessions(self, **kwargs) -> Dict[str, Any]:
        """Get all sessions"""
        sessions = self.metrics.get_sessions()
        return {
            'sessions': [asdict(s) for s in sessions],
            'count': len(sessions)
        }
    
    def start_session(self, data: Dict = None, **kwargs) -> Dict[str, Any]:
        """Start new attack session"""
        if not data:
            return {'error': 'No data provided', 'status': 400}
        
        if self._attack_callback:
            try:
                session_id = self._attack_callback(
                    target=data.get('target'),
                    port=data.get('port', 80),
                    protocol=data.get('protocol', 'TCP'),
                    duration=data.get('duration', 60),
                    rate=data.get('rate', 1000)
                )
                return {'session_id': session_id, 'status': 'started'}
            except Exception as e:
                return {'error': str(e), 'status': 500}
        
        return {'error': 'Attack callback not configured', 'status': 500}
    
    def stop_session(self, data: Dict = None, **kwargs) -> Dict[str, Any]:
        """Stop attack session"""
        if not data or 'session_id' not in data:
            return {'error': 'session_id required', 'status': 400}
        
        session_id = data['session_id']
        self.metrics.update_session(session_id, status='stopped')
        
        if self._stop_callback:
            self._stop_callback(session_id)
        
        return {'session_id': session_id, 'status': 'stopped'}
    
    def pause_session(self, data: Dict = None, **kwargs) -> Dict[str, Any]:
        """Pause attack session"""
        if not data or 'session_id' not in data:
            return {'error': 'session_id required', 'status': 400}
        
        session_id = data['session_id']
        self.metrics.update_session(session_id, status='paused')
        
        return {'session_id': session_id, 'status': 'paused'}
    
    def get_capabilities(self, **kwargs) -> Dict[str, Any]:
        """Get system capabilities"""
        try:
            from core.native_engine import get_capabilities, is_native_available
            caps = get_capabilities()
            caps['native_available'] = is_native_available()
        except ImportError:
            caps = {'native_available': False}
        
        return {
            'capabilities': caps,
            'protocols': ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP'],
            'attack_types': [
                'flood', 'slowloris', 'syn_flood', 'amplification',
                'http_flood', 'ssl_exhaustion'
            ]
        }


class DashboardServer:
    """HTTP server for dashboard"""
    
    HTML_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <title>NetStress Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a; color: #e0e0e0; 
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { 
            display: flex; justify-content: space-between; align-items: center;
            padding: 20px 0; border-bottom: 1px solid #333;
        }
        .header h1 { color: #00ff88; font-size: 24px; }
        .status-badge { 
            padding: 8px 16px; border-radius: 20px; font-size: 14px;
            background: #1a3a1a; color: #00ff88;
        }
        .status-badge.warning { background: #3a3a1a; color: #ffaa00; }
        .status-badge.error { background: #3a1a1a; color: #ff4444; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .card { 
            background: #1a1a1a; border-radius: 12px; padding: 20px;
            border: 1px solid #333;
        }
        .card h3 { color: #888; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }
        .card .value { font-size: 32px; font-weight: bold; color: #00ff88; }
        .card .unit { font-size: 14px; color: #666; }
        .chart-container { 
            background: #1a1a1a; border-radius: 12px; padding: 20px;
            border: 1px solid #333; margin: 20px 0;
        }
        .chart { height: 200px; position: relative; }
        .chart canvas { width: 100% !important; height: 100% !important; }
        .sessions { margin: 20px 0; }
        .session-card { 
            background: #1a1a1a; border-radius: 8px; padding: 16px;
            border: 1px solid #333; margin: 10px 0;
            display: flex; justify-content: space-between; align-items: center;
        }
        .session-info h4 { color: #fff; margin-bottom: 4px; }
        .session-info p { color: #888; font-size: 14px; }
        .session-stats { display: flex; gap: 20px; }
        .session-stat { text-align: center; }
        .session-stat .value { font-size: 18px; color: #00ff88; }
        .session-stat .label { font-size: 12px; color: #666; }
        .btn { 
            padding: 8px 16px; border-radius: 6px; border: none;
            cursor: pointer; font-size: 14px; transition: all 0.2s;
        }
        .btn-primary { background: #00ff88; color: #000; }
        .btn-primary:hover { background: #00cc6a; }
        .btn-danger { background: #ff4444; color: #fff; }
        .btn-danger:hover { background: #cc3333; }
        .controls { 
            display: flex; gap: 10px; padding: 20px 0;
            border-bottom: 1px solid #333;
        }
        input, select { 
            padding: 10px 14px; border-radius: 6px; border: 1px solid #333;
            background: #1a1a1a; color: #fff; font-size: 14px;
        }
        input:focus, select:focus { outline: none; border-color: #00ff88; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ NetStress Dashboard</h1>
            <span class="status-badge" id="status">Connecting...</span>
        </div>
        
        <div class="controls">
            <input type="text" id="target" placeholder="Target IP/Host" style="width: 200px;">
            <input type="number" id="port" placeholder="Port" value="80" style="width: 100px;">
            <select id="protocol">
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="HTTP">HTTP</option>
                <option value="HTTPS">HTTPS</option>
            </select>
            <input type="number" id="duration" placeholder="Duration (s)" value="60" style="width: 120px;">
            <input type="number" id="rate" placeholder="Rate (pps)" value="10000" style="width: 120px;">
            <button class="btn btn-primary" onclick="startAttack()">Start Attack</button>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>Active Attacks</h3>
                <div class="value" id="active-attacks">0</div>
            </div>
            <div class="card">
                <h3>Packets/Second</h3>
                <div class="value" id="total-pps">0</div>
                <span class="unit">pps</span>
            </div>
            <div class="card">
                <h3>Bandwidth</h3>
                <div class="value" id="total-bps">0</div>
                <span class="unit">Mbps</span>
            </div>
            <div class="card">
                <h3>Total Packets</h3>
                <div class="value" id="total-packets">0</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3 style="color: #888; margin-bottom: 10px;">Performance Over Time</h3>
            <div class="chart">
                <canvas id="chart"></canvas>
            </div>
        </div>
        
        <div class="sessions">
            <h3 style="color: #888; margin-bottom: 10px;">Active Sessions</h3>
            <div id="sessions-list"></div>
        </div>
        
        <div class="footer">
            NetStress Dashboard v1.0 | For authorized testing only
        </div>
    </div>
    
    <script>
        let chart = null;
        let chartData = { labels: [], pps: [], bps: [] };
        
        function formatNumber(num) {
            if (num >= 1e9) return (num / 1e9).toFixed(2) + 'G';
            if (num >= 1e6) return (num / 1e6).toFixed(2) + 'M';
            if (num >= 1e3) return (num / 1e3).toFixed(2) + 'K';
            return num.toFixed(0);
        }
        
        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('status').textContent = 'Connected';
                document.getElementById('status').className = 'status-badge';
                document.getElementById('active-attacks').textContent = data.active_attacks;
                document.getElementById('total-pps').textContent = formatNumber(data.total_pps);
                document.getElementById('total-bps').textContent = formatNumber(data.total_bps * 8 / 1e6);
                
                // Update chart
                const now = new Date().toLocaleTimeString();
                chartData.labels.push(now);
                chartData.pps.push(data.total_pps);
                chartData.bps.push(data.total_bps * 8 / 1e6);
                
                if (chartData.labels.length > 60) {
                    chartData.labels.shift();
                    chartData.pps.shift();
                    chartData.bps.shift();
                }
                
                drawChart();
            } catch (e) {
                document.getElementById('status').textContent = 'Disconnected';
                document.getElementById('status').className = 'status-badge error';
            }
        }
        
        async function fetchSessions() {
            try {
                const res = await fetch('/api/sessions');
                const data = await res.json();
                
                const list = document.getElementById('sessions-list');
                if (data.sessions.length === 0) {
                    list.innerHTML = '<p style="color: #666; padding: 20px;">No active sessions</p>';
                    return;
                }
                
                list.innerHTML = data.sessions.map(s => `
                    <div class="session-card">
                        <div class="session-info">
                            <h4>${s.target}:${s.port}</h4>
                            <p>${s.protocol} | ${s.status}</p>
                        </div>
                        <div class="session-stats">
                            <div class="session-stat">
                                <div class="value">${formatNumber(s.pps)}</div>
                                <div class="label">PPS</div>
                            </div>
                            <div class="session-stat">
                                <div class="value">${formatNumber(s.packets_sent)}</div>
                                <div class="label">Packets</div>
                            </div>
                            <div class="session-stat">
                                <div class="value">${s.errors}</div>
                                <div class="label">Errors</div>
                            </div>
                        </div>
                        <button class="btn btn-danger" onclick="stopSession('${s.session_id}')">Stop</button>
                    </div>
                `).join('');
                
                document.getElementById('total-packets').textContent = 
                    formatNumber(data.sessions.reduce((a, s) => a + s.packets_sent, 0));
            } catch (e) {
                console.error('Failed to fetch sessions:', e);
            }
        }
        
        async function startAttack() {
            const target = document.getElementById('target').value;
            const port = parseInt(document.getElementById('port').value);
            const protocol = document.getElementById('protocol').value;
            const duration = parseInt(document.getElementById('duration').value);
            const rate = parseInt(document.getElementById('rate').value);
            
            if (!target) {
                alert('Please enter a target');
                return;
            }
            
            try {
                const res = await fetch('/api/session/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, port, protocol, duration, rate })
                });
                const data = await res.json();
                
                if (data.error) {
                    alert('Error: ' + data.error);
                } else {
                    fetchSessions();
                }
            } catch (e) {
                alert('Failed to start attack: ' + e.message);
            }
        }
        
        async function stopSession(sessionId) {
            try {
                await fetch('/api/session/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId })
                });
                fetchSessions();
            } catch (e) {
                console.error('Failed to stop session:', e);
            }
        }
        
        function drawChart() {
            const canvas = document.getElementById('chart');
            const ctx = canvas.getContext('2d');
            const width = canvas.parentElement.clientWidth;
            const height = 200;
            
            canvas.width = width;
            canvas.height = height;
            
            ctx.fillStyle = '#1a1a1a';
            ctx.fillRect(0, 0, width, height);
            
            if (chartData.pps.length < 2) return;
            
            const maxPps = Math.max(...chartData.pps, 1);
            const maxBps = Math.max(...chartData.bps, 1);
            
            // Draw PPS line
            ctx.strokeStyle = '#00ff88';
            ctx.lineWidth = 2;
            ctx.beginPath();
            chartData.pps.forEach((v, i) => {
                const x = (i / (chartData.pps.length - 1)) * width;
                const y = height - (v / maxPps) * (height - 20);
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();
            
            // Draw BPS line
            ctx.strokeStyle = '#0088ff';
            ctx.beginPath();
            chartData.bps.forEach((v, i) => {
                const x = (i / (chartData.bps.length - 1)) * width;
                const y = height - (v / maxBps) * (height - 20);
                if (i === 0) ctx.moveTo(x, y);
                else ctx.lineTo(x, y);
            });
            ctx.stroke();
            
            // Legend
            ctx.fillStyle = '#00ff88';
            ctx.fillRect(10, 10, 12, 12);
            ctx.fillStyle = '#888';
            ctx.font = '12px sans-serif';
            ctx.fillText('PPS', 28, 20);
            
            ctx.fillStyle = '#0088ff';
            ctx.fillRect(70, 10, 12, 12);
            ctx.fillStyle = '#888';
            ctx.fillText('Mbps', 88, 20);
        }
        
        // Start polling
        setInterval(fetchStatus, 1000);
        setInterval(fetchSessions, 2000);
        fetchStatus();
        fetchSessions();
    </script>
</body>
</html>'''
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8080):
        self.host = host
        self.port = port
        self.metrics = MetricsCollector()
        self.api = DashboardAPI(self.metrics)
        self._server = None
        self._thread = None
        
    def start(self):
        """Start dashboard server"""
        handler = self._create_handler()
        self._server = socketserver.TCPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(f"Dashboard started at http://{self.host}:{self.port}")
    
    def stop(self):
        """Stop dashboard server"""
        if self._server:
            self._server.shutdown()
            self._server = None
    
    def _create_handler(self):
        """Create HTTP request handler"""
        dashboard = self
        
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logging
            
            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    self.wfile.write(dashboard.HTML_TEMPLATE.encode())
                elif self.path.startswith('/api/'):
                    result = dashboard.api.handle_request(self.path, 'GET')
                    self.send_response(result.get('status', 200))
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(result).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length).decode() if content_length else None
                
                result = dashboard.api.handle_request(self.path, 'POST', body)
                self.send_response(result.get('status', 200))
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
        
        return Handler


# Global dashboard instance
dashboard_server = DashboardServer()


__all__ = [
    'AttackSession',
    'DashboardMetrics',
    'MetricsCollector',
    'DashboardAPI',
    'DashboardServer',
    'dashboard_server',
]
