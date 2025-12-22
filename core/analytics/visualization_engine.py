#!/usr/bin/env python3
"""
Advanced Visualization Engine

This module provides comprehensive visualization capabilities for the DDoS testing
framework, including 3D network topology visualization, real-time dashboards,
heatmaps, and interactive attack flow visualization.
"""

import asyncio
import time
import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
import threading
import base64
import io
import math

logger = logging.getLogger(__name__)

@dataclass
class VisualizationConfig:
    """Configuration for visualization components"""
    width: int = 1920
    height: int = 1080
    refresh_rate: float = 1.0  # seconds
    color_scheme: str = "dark"
    animation_enabled: bool = True
    max_data_points: int = 1000

@dataclass
class NetworkNode:
    """Represents a node in network topology"""
    id: str
    label: str
    x: float
    y: float
    z: float = 0.0
    node_type: str = "unknown"  # target, attacker, router, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    connections: List[str] = field(default_factory=list)

@dataclass
class NetworkEdge:
    """Represents a connection between network nodes"""
    source: str
    target: str
    weight: float = 1.0
    edge_type: str = "connection"
    properties: Dict[str, Any] = field(default_factory=dict)
    traffic_volume: float = 0.0
    latency: float = 0.0

@dataclass
class AttackFlow:
    """Represents an attack flow visualization"""
    flow_id: str
    source_nodes: List[str]
    target_nodes: List[str]
    protocol: str
    intensity: float
    timestamp: float
    duration: float = 0.0
    properties: Dict[str, Any] = field(default_factory=dict)

class NetworkTopologyVisualizer:
    """3D Network topology visualization component"""
    
    def __init__(self, config: VisualizationConfig):
        self.config = config
        self.nodes = {}
        self.edges = {}
        self.layout_algorithm = "force_directed"
        self.update_lock = threading.Lock()
        
    def add_node(self, node: NetworkNode):
        """Add a node to the topology"""
        with self.update_lock:
            self.nodes[node.id] = node
            logger.debug(f"Added network node: {node.id}")
    
    def add_edge(self, edge: NetworkEdge):
        """Add an edge to the topology"""
        with self.update_lock:
            edge_id = f"{edge.source}-{edge.target}"
            self.edges[edge_id] = edge
            
            # Update node connections
            if edge.source in self.nodes:
                if edge.target not in self.nodes[edge.source].connections:
                    self.nodes[edge.source].connections.append(edge.target)
            
            if edge.target in self.nodes:
                if edge.source not in self.nodes[edge.target].connections:
                    self.nodes[edge.target].connections.append(edge.source)
    
    def update_node_position(self, node_id: str, x: float, y: float, z: float = 0.0):
        """Update node position"""
        with self.update_lock:
            if node_id in self.nodes:
                self.nodes[node_id].x = x
                self.nodes[node_id].y = y
                self.nodes[node_id].z = z
    
    def calculate_force_directed_layout(self, iterations: int = 100):
        """Calculate force-directed layout for nodes"""
        if len(self.nodes) < 2:
            return
        
        # Physics simulation parameters
        k = math.sqrt((self.config.width * self.config.height) / len(self.nodes))
        dt = 0.1
        
        for iteration in range(iterations):
            # Calculate repulsive forces
            forces = defaultdict(lambda: {'x': 0, 'y': 0, 'z': 0})
            
            nodes_list = list(self.nodes.values())
            for i, node1 in enumerate(nodes_list):
                for node2 in nodes_list[i+1:]:
                    dx = node1.x - node2.x
                    dy = node1.y - node2.y
                    dz = node1.z - node2.z
                    
                    distance = math.sqrt(dx*dx + dy*dy + dz*dz)
                    if distance < 0.01:
                        distance = 0.01
                    
                    # Repulsive force
                    force = k * k / distance
                    fx = force * dx / distance
                    fy = force * dy / distance
                    fz = force * dz / distance
                    
                    forces[node1.id]['x'] += fx
                    forces[node1.id]['y'] += fy
                    forces[node1.id]['z'] += fz
                    
                    forces[node2.id]['x'] -= fx
                    forces[node2.id]['y'] -= fy
                    forces[node2.id]['z'] -= fz
            
            # Calculate attractive forces for connected nodes
            for edge in self.edges.values():
                if edge.source in self.nodes and edge.target in self.nodes:
                    node1 = self.nodes[edge.source]
                    node2 = self.nodes[edge.target]
                    
                    dx = node1.x - node2.x
                    dy = node1.y - node2.y
                    dz = node1.z - node2.z
                    
                    distance = math.sqrt(dx*dx + dy*dy + dz*dz)
                    if distance < 0.01:
                        continue
                    
                    # Attractive force
                    force = distance * distance / k
                    fx = force * dx / distance
                    fy = force * dy / distance
                    fz = force * dz / distance
                    
                    forces[node1.id]['x'] -= fx
                    forces[node1.id]['y'] -= fy
                    forces[node1.id]['z'] -= fz
                    
                    forces[node2.id]['x'] += fx
                    forces[node2.id]['y'] += fy
                    forces[node2.id]['z'] += fz
            
            # Apply forces and update positions
            for node_id, node in self.nodes.items():
                force = forces[node_id]
                
                # Limit force magnitude
                force_magnitude = math.sqrt(force['x']**2 + force['y']**2 + force['z']**2)
                if force_magnitude > k:
                    force['x'] = force['x'] / force_magnitude * k
                    force['y'] = force['y'] / force_magnitude * k
                    force['z'] = force['z'] / force_magnitude * k
                
                # Update position
                node.x += force['x'] * dt
                node.y += force['y'] * dt
                node.z += force['z'] * dt
                
                # Keep nodes within bounds
                node.x = max(0, min(self.config.width, node.x))
                node.y = max(0, min(self.config.height, node.y))
                node.z = max(-100, min(100, node.z))
    
    def generate_topology_data(self) -> Dict[str, Any]:
        """Generate topology data for visualization"""
        with self.update_lock:
            return {
                'nodes': [
                    {
                        'id': node.id,
                        'label': node.label,
                        'x': node.x,
                        'y': node.y,
                        'z': node.z,
                        'type': node.node_type,
                        'properties': node.properties,
                        'connections': node.connections
                    }
                    for node in self.nodes.values()
                ],
                'edges': [
                    {
                        'source': edge.source,
                        'target': edge.target,
                        'weight': edge.weight,
                        'type': edge.edge_type,
                        'traffic_volume': edge.traffic_volume,
                        'latency': edge.latency,
                        'properties': edge.properties
                    }
                    for edge in self.edges.values()
                ],
                'timestamp': time.time()
            }

class RealTimeDashboard:
    """Real-time dashboard component"""
    
    def __init__(self, config: VisualizationConfig):
        self.config = config
        self.widgets = {}
        self.data_sources = {}
        self.update_callbacks = []
        
    def add_widget(self, widget_id: str, widget_type: str, 
                  position: Tuple[int, int], size: Tuple[int, int],
                  config: Dict[str, Any] = None):
        """Add a widget to the dashboard"""
        self.widgets[widget_id] = {
            'type': widget_type,
            'position': position,
            'size': size,
            'config': config or {},
            'data': {},
            'last_update': 0.0
        }
        logger.debug(f"Added dashboard widget: {widget_id} ({widget_type})")
    
    def update_widget_data(self, widget_id: str, data: Dict[str, Any]):
        """Update data for a specific widget"""
        if widget_id in self.widgets:
            self.widgets[widget_id]['data'] = data
            self.widgets[widget_id]['last_update'] = time.time()
    
    def generate_dashboard_data(self) -> Dict[str, Any]:
        """Generate complete dashboard data"""
        return {
            'widgets': self.widgets,
            'config': {
                'width': self.config.width,
                'height': self.config.height,
                'color_scheme': self.config.color_scheme,
                'animation_enabled': self.config.animation_enabled
            },
            'timestamp': time.time()
        }

class HeatmapGenerator:
    """Heatmap visualization generator"""
    
    def __init__(self, config: VisualizationConfig):
        self.config = config
        self.data_matrix = {}
        self.color_scales = {
            'viridis': ['#440154', '#31688e', '#35b779', '#fde725'],
            'plasma': ['#0d0887', '#7e03a8', '#cc4778', '#f89441', '#f0f921'],
            'hot': ['#000000', '#ff0000', '#ffff00', '#ffffff']
        }
    
    def update_data_matrix(self, x_labels: List[str], y_labels: List[str],
                          values: List[List[float]]):
        """Update the heatmap data matrix"""
        self.data_matrix = {
            'x_labels': x_labels,
            'y_labels': y_labels,
            'values': values,
            'timestamp': time.time()
        }
    
    def generate_heatmap_data(self, color_scale: str = 'viridis') -> Dict[str, Any]:
        """Generate heatmap visualization data"""
        if not self.data_matrix:
            return {}
        
        # Normalize values to 0-1 range
        flat_values = [val for row in self.data_matrix['values'] for val in row]
        if flat_values:
            min_val = min(flat_values)
            max_val = max(flat_values)
            value_range = max_val - min_val if max_val != min_val else 1
            
            normalized_values = [
                [(val - min_val) / value_range for val in row]
                for row in self.data_matrix['values']
            ]
        else:
            normalized_values = self.data_matrix['values']
        
        return {
            'x_labels': self.data_matrix['x_labels'],
            'y_labels': self.data_matrix['y_labels'],
            'values': self.data_matrix['values'],
            'normalized_values': normalized_values,
            'color_scale': self.color_scales.get(color_scale, self.color_scales['viridis']),
            'min_value': min(flat_values) if flat_values else 0,
            'max_value': max(flat_values) if flat_values else 0,
            'timestamp': self.data_matrix['timestamp']
        }

class AttackFlowVisualizer:
    """Interactive attack flow visualization"""
    
    def __init__(self, config: VisualizationConfig):
        self.config = config
        self.active_flows = {}
        self.flow_history = deque(maxlen=1000)
        self.flow_lock = threading.Lock()
        
    def add_attack_flow(self, flow: AttackFlow):
        """Add a new attack flow"""
        with self.flow_lock:
            self.active_flows[flow.flow_id] = flow
            logger.debug(f"Added attack flow: {flow.flow_id}")
    
    def update_flow_intensity(self, flow_id: str, intensity: float):
        """Update the intensity of an attack flow"""
        with self.flow_lock:
            if flow_id in self.active_flows:
                self.active_flows[flow_id].intensity = intensity
    
    def end_attack_flow(self, flow_id: str):
        """End an attack flow and move it to history"""
        with self.flow_lock:
            if flow_id in self.active_flows:
                flow = self.active_flows.pop(flow_id)
                flow.duration = time.time() - flow.timestamp
                self.flow_history.append(flow)
    
    def generate_flow_data(self) -> Dict[str, Any]:
        """Generate attack flow visualization data"""
        with self.flow_lock:
            return {
                'active_flows': [
                    {
                        'id': flow.flow_id,
                        'source_nodes': flow.source_nodes,
                        'target_nodes': flow.target_nodes,
                        'protocol': flow.protocol,
                        'intensity': flow.intensity,
                        'timestamp': flow.timestamp,
                        'duration': time.time() - flow.timestamp,
                        'properties': flow.properties
                    }
                    for flow in self.active_flows.values()
                ],
                'flow_history': [
                    {
                        'id': flow.flow_id,
                        'source_nodes': flow.source_nodes,
                        'target_nodes': flow.target_nodes,
                        'protocol': flow.protocol,
                        'intensity': flow.intensity,
                        'timestamp': flow.timestamp,
                        'duration': flow.duration,
                        'properties': flow.properties
                    }
                    for flow in list(self.flow_history)[-100:]  # Last 100 flows
                ],
                'timestamp': time.time()
            }

class AdvancedVisualizationEngine:
    """Main advanced visualization engine"""
    
    def __init__(self, config: VisualizationConfig = None):
        self.config = config or VisualizationConfig()
        
        # Visualization components
        self.topology_visualizer = NetworkTopologyVisualizer(self.config)
        self.dashboard = RealTimeDashboard(self.config)
        self.heatmap_generator = HeatmapGenerator(self.config)
        self.attack_flow_visualizer = AttackFlowVisualizer(self.config)
        
        # Data management
        self.visualization_data = {}
        self.update_queue = asyncio.Queue()
        
        # Background tasks
        self.running = False
        self.update_task = None
        self.render_task = None
        
        # Performance tracking
        self.frames_rendered = 0
        self.last_fps_update = time.time()
        self.current_fps = 0.0
        
        # Initialize default dashboard widgets
        self._setup_default_dashboard()
    
    def _setup_default_dashboard(self):
        """Setup default dashboard widgets"""
        # Performance metrics widget
        self.dashboard.add_widget(
            'performance_metrics',
            'line_chart',
            (0, 0),
            (600, 300),
            {
                'title': 'Performance Metrics',
                'metrics': ['pps', 'bps', 'cpu_usage', 'memory_usage'],
                'time_window': 300
            }
        )
        
        # Attack statistics widget
        self.dashboard.add_widget(
            'attack_stats',
            'bar_chart',
            (620, 0),
            (400, 300),
            {
                'title': 'Attack Statistics',
                'metrics': ['tcp_pps', 'udp_pps', 'http_rps', 'dns_qps']
            }
        )
        
        # System status widget
        self.dashboard.add_widget(
            'system_status',
            'gauge',
            (0, 320),
            (300, 200),
            {
                'title': 'System Status',
                'metric': 'overall_health',
                'thresholds': {'good': 0.8, 'warning': 0.6, 'critical': 0.4}
            }
        )
        
        # Network topology widget
        self.dashboard.add_widget(
            'network_topology',
            '3d_network',
            (320, 320),
            (700, 400),
            {
                'title': 'Network Topology',
                'show_traffic': True,
                'show_labels': True
            }
        )
    
    def update_performance_data(self, metrics: Dict[str, Any]):
        """Update performance visualization data"""
        # Update dashboard widgets
        self.dashboard.update_widget_data('performance_metrics', {
            'data_points': [
                {'timestamp': time.time(), 'value': metrics.get('pps', 0), 'metric': 'pps'},
                {'timestamp': time.time(), 'value': metrics.get('bps', 0), 'metric': 'bps'},
                {'timestamp': time.time(), 'value': metrics.get('cpu_usage', 0), 'metric': 'cpu_usage'},
                {'timestamp': time.time(), 'value': metrics.get('memory_usage', 0), 'metric': 'memory_usage'}
            ]
        })
        
        self.dashboard.update_widget_data('attack_stats', {
            'data_points': [
                {'label': 'TCP', 'value': metrics.get('tcp_pps', 0)},
                {'label': 'UDP', 'value': metrics.get('udp_pps', 0)},
                {'label': 'HTTP', 'value': metrics.get('http_rps', 0)},
                {'label': 'DNS', 'value': metrics.get('dns_qps', 0)}
            ]
        })
        
        # Calculate overall health score
        health_score = self._calculate_health_score(metrics)
        self.dashboard.update_widget_data('system_status', {
            'value': health_score,
            'status': 'good' if health_score > 0.8 else 'warning' if health_score > 0.6 else 'critical'
        })
    
    def _calculate_health_score(self, metrics: Dict[str, Any]) -> float:
        """Calculate overall system health score"""
        factors = []
        
        # CPU usage factor (lower is better)
        cpu_usage = metrics.get('cpu_usage', 0)
        cpu_factor = max(0, 1 - (cpu_usage / 100))
        factors.append(cpu_factor)
        
        # Memory usage factor (lower is better)
        memory_usage = metrics.get('memory_usage', 0)
        memory_factor = max(0, 1 - (memory_usage / 100))
        factors.append(memory_factor)
        
        # Error rate factor (lower is better)
        error_rate = metrics.get('error_rate', 0)
        error_factor = max(0, 1 - error_rate)
        factors.append(error_factor)
        
        # Performance factor (higher is better, normalized)
        pps = metrics.get('pps', 0)
        performance_factor = min(1.0, pps / 100000)  # Normalize to 100k pps
        factors.append(performance_factor)
        
        return sum(factors) / len(factors) if factors else 0.0
    
    def update_network_topology(self, nodes: List[Dict[str, Any]], 
                              edges: List[Dict[str, Any]]):
        """Update network topology visualization"""
        # Clear existing topology
        self.topology_visualizer.nodes.clear()
        self.topology_visualizer.edges.clear()
        
        # Add nodes
        for node_data in nodes:
            node = NetworkNode(
                id=node_data['id'],
                label=node_data.get('label', node_data['id']),
                x=node_data.get('x', 0),
                y=node_data.get('y', 0),
                z=node_data.get('z', 0),
                node_type=node_data.get('type', 'unknown'),
                properties=node_data.get('properties', {})
            )
            self.topology_visualizer.add_node(node)
        
        # Add edges
        for edge_data in edges:
            edge = NetworkEdge(
                source=edge_data['source'],
                target=edge_data['target'],
                weight=edge_data.get('weight', 1.0),
                edge_type=edge_data.get('type', 'connection'),
                traffic_volume=edge_data.get('traffic_volume', 0.0),
                latency=edge_data.get('latency', 0.0),
                properties=edge_data.get('properties', {})
            )
            self.topology_visualizer.add_edge(edge)
        
        # Recalculate layout
        self.topology_visualizer.calculate_force_directed_layout()
        
        # Update dashboard widget
        topology_data = self.topology_visualizer.generate_topology_data()
        self.dashboard.update_widget_data('network_topology', topology_data)
    
    def create_performance_heatmap(self, metrics_data: Dict[str, List[float]],
                                 time_labels: List[str]):
        """Create a performance heatmap"""
        metric_names = list(metrics_data.keys())
        values = [metrics_data[metric] for metric in metric_names]
        
        self.heatmap_generator.update_data_matrix(
            x_labels=time_labels,
            y_labels=metric_names,
            values=values
        )
    
    def add_attack_flow(self, source_nodes: List[str], target_nodes: List[str],
                       protocol: str, intensity: float, properties: Dict[str, Any] = None):
        """Add a new attack flow visualization"""
        flow_id = f"flow_{int(time.time() * 1000)}"
        flow = AttackFlow(
            flow_id=flow_id,
            source_nodes=source_nodes,
            target_nodes=target_nodes,
            protocol=protocol,
            intensity=intensity,
            timestamp=time.time(),
            properties=properties or {}
        )
        
        self.attack_flow_visualizer.add_attack_flow(flow)
        return flow_id
    
    def generate_complete_visualization(self) -> Dict[str, Any]:
        """Generate complete visualization data"""
        return {
            'dashboard': self.dashboard.generate_dashboard_data(),
            'topology': self.topology_visualizer.generate_topology_data(),
            'heatmap': self.heatmap_generator.generate_heatmap_data(),
            'attack_flows': self.attack_flow_visualizer.generate_flow_data(),
            'metadata': {
                'timestamp': time.time(),
                'fps': self.current_fps,
                'frames_rendered': self.frames_rendered,
                'config': {
                    'width': self.config.width,
                    'height': self.config.height,
                    'refresh_rate': self.config.refresh_rate,
                    'color_scheme': self.config.color_scheme
                }
            }
        }
    
    def export_visualization(self, format_type: str = 'json') -> str:
        """Export visualization data in specified format"""
        data = self.generate_complete_visualization()
        
        if format_type.lower() == 'json':
            return json.dumps(data, indent=2, default=str)
        elif format_type.lower() == 'html':
            return self._generate_html_visualization(data)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _generate_html_visualization(self, data: Dict[str, Any]) -> str:
        """Generate HTML visualization"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>DDoS Framework Visualization</title>
            <script src="https://d3js.org/d3.v7.min.js"></script>
            <script src="https://unpkg.com/three@0.150.0/build/three.min.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: white; }}
                .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
                .widget {{ background: #2a2a2a; border-radius: 8px; padding: 15px; }}
                .widget h3 {{ margin-top: 0; color: #4CAF50; }}
                #topology {{ width: 100%; height: 400px; border: 1px solid #444; }}
            </style>
        </head>
        <body>
            <h1>DDoS Framework Real-Time Visualization</h1>
            <div class="dashboard">
                <div class="widget">
                    <h3>Performance Metrics</h3>
                    <div id="performance-chart"></div>
                </div>
                <div class="widget">
                    <h3>Attack Statistics</h3>
                    <div id="attack-stats"></div>
                </div>
                <div class="widget">
                    <h3>Network Topology</h3>
                    <div id="topology"></div>
                </div>
            </div>
            
            <script>
                const visualizationData = {data_json};
                
                // Initialize visualizations
                function initializeVisualizations() {{
                    // Performance chart
                    const perfData = visualizationData.dashboard.widgets.performance_metrics.data;
                    // Add D3.js chart implementation here
                    
                    // Attack statistics
                    const attackData = visualizationData.dashboard.widgets.attack_stats.data;
                    // Add attack stats visualization here
                    
                    // Network topology
                    const topoData = visualizationData.topology;
                    // Add Three.js 3D topology visualization here
                }}
                
                // Auto-refresh functionality
                setInterval(() => {{
                    // Fetch updated data and refresh visualizations
                    location.reload();
                }}, {refresh_rate} * 1000);
                
                // Initialize on page load
                window.onload = initializeVisualizations;
            </script>
        </body>
        </html>
        """
        
        return html_template.format(
            data_json=json.dumps(data, default=str),
            refresh_rate=self.config.refresh_rate
        )
    
    async def update_loop(self):
        """Background update loop for visualizations"""
        while self.running:
            try:
                # Update FPS counter
                current_time = time.time()
                if current_time - self.last_fps_update >= 1.0:
                    self.current_fps = self.frames_rendered / (current_time - self.last_fps_update)
                    self.frames_rendered = 0
                    self.last_fps_update = current_time
                
                # Process any pending updates
                try:
                    update_data = await asyncio.wait_for(
                        self.update_queue.get(),
                        timeout=0.1
                    )
                    # Process update_data here
                except asyncio.TimeoutError:
                    pass
                
                await asyncio.sleep(self.config.refresh_rate)
                
            except Exception as e:
                logger.error(f"Error in visualization update loop: {e}")
                await asyncio.sleep(1.0)
    
    async def render_loop(self):
        """Background render loop for visualizations"""
        while self.running:
            try:
                # Perform rendering operations
                self.frames_rendered += 1
                
                # Update topology layout if needed
                if len(self.topology_visualizer.nodes) > 1:
                    self.topology_visualizer.calculate_force_directed_layout(iterations=1)
                
                await asyncio.sleep(1.0 / 60.0)  # 60 FPS target
                
            except Exception as e:
                logger.error(f"Error in visualization render loop: {e}")
                await asyncio.sleep(1.0)
    
    async def start(self):
        """Start the visualization engine"""
        if self.running:
            logger.warning("Visualization engine already running")
            return
        
        self.running = True
        logger.info("Starting advanced visualization engine")
        
        # Start background tasks
        self.update_task = asyncio.create_task(self.update_loop())
        self.render_task = asyncio.create_task(self.render_loop())
        
        logger.info("Advanced visualization engine started")
    
    async def stop(self):
        """Stop the visualization engine"""
        if not self.running:
            return
        
        logger.info("Stopping advanced visualization engine")
        self.running = False
        
        # Cancel background tasks
        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
        
        if self.render_task:
            self.render_task.cancel()
            try:
                await self.render_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Advanced visualization engine stopped")

# Global visualization engine instance
_global_engine = None

def get_visualization_engine() -> AdvancedVisualizationEngine:
    """Get the global visualization engine instance"""
    global _global_engine
    if _global_engine is None:
        _global_engine = AdvancedVisualizationEngine()
    return _global_engine

def update_visualization_data(data_type: str, data: Dict[str, Any]):
    """Convenience function to update visualization data"""
    engine = get_visualization_engine()
    
    if data_type == 'performance':
        engine.update_performance_data(data)
    elif data_type == 'topology':
        nodes = data.get('nodes', [])
        edges = data.get('edges', [])
        engine.update_network_topology(nodes, edges)
    elif data_type == 'attack_flow':
        engine.add_attack_flow(
            source_nodes=data.get('source_nodes', []),
            target_nodes=data.get('target_nodes', []),
            protocol=data.get('protocol', 'unknown'),
            intensity=data.get('intensity', 0.0),
            properties=data.get('properties', {})
        )