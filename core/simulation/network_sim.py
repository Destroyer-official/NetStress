"""
Network Simulation Module

Simulates network conditions for testing:
- Latency simulation
- Packet loss simulation
- Bandwidth throttling
- Network topology simulation
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Tuple
from enum import Enum
from collections import deque
import logging

logger = logging.getLogger(__name__)


class NetworkCondition(Enum):
    """Network condition presets"""
    PERFECT = "perfect"
    GOOD = "good"
    MODERATE = "moderate"
    POOR = "poor"
    TERRIBLE = "terrible"
    SATELLITE = "satellite"
    MOBILE_3G = "mobile_3g"
    MOBILE_4G = "mobile_4g"
    CONGESTED = "congested"


@dataclass
class NetworkProfile:
    """Network condition profile"""
    name: str = "default"
    latency_ms: float = 0.0
    latency_jitter_ms: float = 0.0
    packet_loss: float = 0.0
    bandwidth_kbps: float = float('inf')
    duplicate_rate: float = 0.0
    reorder_rate: float = 0.0
    corruption_rate: float = 0.0


# Predefined network profiles
NETWORK_PROFILES = {
    NetworkCondition.PERFECT: NetworkProfile("perfect", 0, 0, 0, float('inf')),
    NetworkCondition.GOOD: NetworkProfile("good", 20, 5, 0.001, 100000),
    NetworkCondition.MODERATE: NetworkProfile("moderate", 50, 20, 0.01, 50000),
    NetworkCondition.POOR: NetworkProfile("poor", 150, 50, 0.05, 10000),
    NetworkCondition.TERRIBLE: NetworkProfile("terrible", 500, 200, 0.15, 1000),
    NetworkCondition.SATELLITE: NetworkProfile("satellite", 600, 100, 0.02, 5000),
    NetworkCondition.MOBILE_3G: NetworkProfile("mobile_3g", 100, 50, 0.03, 2000),
    NetworkCondition.MOBILE_4G: NetworkProfile("mobile_4g", 50, 20, 0.01, 20000),
    NetworkCondition.CONGESTED: NetworkProfile("congested", 200, 100, 0.1, 5000),
}


class NetworkSimulator:
    """
    Network Condition Simulator
    
    Simulates various network conditions for testing.
    """
    
    def __init__(self, profile: NetworkProfile = None):
        self.profile = profile or NETWORK_PROFILES[NetworkCondition.PERFECT]
        self._packet_queue: deque = deque()
        self._bytes_sent = 0
        self._last_send_time = time.time()
        self._running = False
        
    def set_profile(self, condition: NetworkCondition):
        """Set network condition profile"""
        self.profile = NETWORK_PROFILES[condition]
        
    def set_custom_profile(self, profile: NetworkProfile):
        """Set custom network profile"""
        self.profile = profile
        
    async def simulate_send(self, data: bytes) -> Tuple[bool, bytes, float]:
        """
        Simulate sending data through network.
        
        Returns: (success, data, latency)
        """
        # Check packet loss
        if random.random() < self.profile.packet_loss:
            return (False, b'', 0)
            
        # Calculate latency
        latency = self.profile.latency_ms / 1000
        if self.profile.latency_jitter_ms > 0:
            jitter = random.gauss(0, self.profile.latency_jitter_ms / 1000)
            latency = max(0, latency + jitter)
            
        # Bandwidth throttling
        if self.profile.bandwidth_kbps < float('inf'):
            bytes_per_second = self.profile.bandwidth_kbps * 1000 / 8
            send_time = len(data) / bytes_per_second
            
            # Check if we need to wait
            elapsed = time.time() - self._last_send_time
            if elapsed < send_time:
                await asyncio.sleep(send_time - elapsed)
                
            self._last_send_time = time.time()
            
        # Simulate latency
        await asyncio.sleep(latency)
        
        # Check corruption
        if random.random() < self.profile.corruption_rate:
            data = self._corrupt_data(data)
            
        # Check duplication
        if random.random() < self.profile.duplicate_rate:
            # Return duplicate (caller should handle)
            pass
            
        return (True, data, latency * 1000)
        
    def _corrupt_data(self, data: bytes) -> bytes:
        """Corrupt random bytes in data"""
        if not data:
            return data
            
        data = bytearray(data)
        num_corruptions = max(1, len(data) // 100)
        
        for _ in range(num_corruptions):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
            
        return bytes(data)
        
    def get_stats(self) -> Dict[str, Any]:
        """Get simulation statistics"""
        return {
            'profile': self.profile.name,
            'latency_ms': self.profile.latency_ms,
            'packet_loss': self.profile.packet_loss,
            'bandwidth_kbps': self.profile.bandwidth_kbps,
        }


class TopologyNode:
    """Network topology node"""
    
    def __init__(self, node_id: str, node_type: str = "host"):
        self.node_id = node_id
        self.node_type = node_type  # host, router, switch, firewall
        self.connections: Dict[str, NetworkProfile] = {}
        self.properties: Dict[str, Any] = {}
        
    def connect(self, other_id: str, profile: NetworkProfile = None):
        """Connect to another node"""
        self.connections[other_id] = profile or NetworkProfile()
        
    def disconnect(self, other_id: str):
        """Disconnect from another node"""
        if other_id in self.connections:
            del self.connections[other_id]


class NetworkTopology:
    """
    Network Topology Simulator
    
    Simulates network topology for distributed testing.
    """
    
    def __init__(self):
        self.nodes: Dict[str, TopologyNode] = {}
        self._path_cache: Dict[Tuple[str, str], List[str]] = {}
        
    def add_node(self, node_id: str, node_type: str = "host") -> TopologyNode:
        """Add node to topology"""
        node = TopologyNode(node_id, node_type)
        self.nodes[node_id] = node
        self._path_cache.clear()
        return node
        
    def add_link(self, node1_id: str, node2_id: str, profile: NetworkProfile = None):
        """Add bidirectional link between nodes"""
        if node1_id in self.nodes and node2_id in self.nodes:
            self.nodes[node1_id].connect(node2_id, profile)
            self.nodes[node2_id].connect(node1_id, profile)
            self._path_cache.clear()
            
    def remove_link(self, node1_id: str, node2_id: str):
        """Remove link between nodes"""
        if node1_id in self.nodes:
            self.nodes[node1_id].disconnect(node2_id)
        if node2_id in self.nodes:
            self.nodes[node2_id].disconnect(node1_id)
        self._path_cache.clear()
        
    def find_path(self, src: str, dst: str) -> List[str]:
        """Find path between nodes (BFS)"""
        cache_key = (src, dst)
        if cache_key in self._path_cache:
            return self._path_cache[cache_key]
            
        if src not in self.nodes or dst not in self.nodes:
            return []
            
        visited = {src}
        queue = [(src, [src])]
        
        while queue:
            current, path = queue.pop(0)
            
            if current == dst:
                self._path_cache[cache_key] = path
                return path
                
            for neighbor in self.nodes[current].connections:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
                    
        return []
        
    def calculate_path_latency(self, path: List[str]) -> float:
        """Calculate total latency along path"""
        total_latency = 0.0
        
        for i in range(len(path) - 1):
            node = self.nodes[path[i]]
            if path[i + 1] in node.connections:
                profile = node.connections[path[i + 1]]
                if profile:
                    total_latency += profile.latency_ms
                    
        return total_latency
        
    def calculate_path_loss(self, path: List[str]) -> float:
        """Calculate cumulative packet loss probability"""
        success_prob = 1.0
        
        for i in range(len(path) - 1):
            node = self.nodes[path[i]]
            if path[i + 1] in node.connections:
                profile = node.connections[path[i + 1]]
                if profile:
                    success_prob *= (1 - profile.packet_loss)
                    
        return 1 - success_prob
        
    def create_star_topology(self, center: str, endpoints: List[str], 
                            profile: NetworkProfile = None):
        """Create star topology"""
        self.add_node(center, "switch")
        for endpoint in endpoints:
            self.add_node(endpoint, "host")
            self.add_link(center, endpoint, profile)
            
    def create_mesh_topology(self, nodes: List[str], profile: NetworkProfile = None):
        """Create full mesh topology"""
        for node_id in nodes:
            self.add_node(node_id, "host")
            
        for i, node1 in enumerate(nodes):
            for node2 in nodes[i + 1:]:
                self.add_link(node1, node2, profile)
                
    def create_ring_topology(self, nodes: List[str], profile: NetworkProfile = None):
        """Create ring topology"""
        for node_id in nodes:
            self.add_node(node_id, "host")
            
        for i in range(len(nodes)):
            self.add_link(nodes[i], nodes[(i + 1) % len(nodes)], profile)


class LoadBalancer:
    """
    Load Balancer Simulator
    
    Simulates load balancing behavior.
    """
    
    def __init__(self, algorithm: str = "round_robin"):
        self.algorithm = algorithm
        self.backends: List[str] = []
        self.weights: Dict[str, int] = {}
        self._current_index = 0
        self._connection_counts: Dict[str, int] = {}
        
    def add_backend(self, backend_id: str, weight: int = 1):
        """Add backend server"""
        self.backends.append(backend_id)
        self.weights[backend_id] = weight
        self._connection_counts[backend_id] = 0
        
    def remove_backend(self, backend_id: str):
        """Remove backend server"""
        if backend_id in self.backends:
            self.backends.remove(backend_id)
            del self.weights[backend_id]
            del self._connection_counts[backend_id]
            
    def get_backend(self) -> Optional[str]:
        """Get next backend based on algorithm"""
        if not self.backends:
            return None
            
        if self.algorithm == "round_robin":
            backend = self.backends[self._current_index % len(self.backends)]
            self._current_index += 1
            
        elif self.algorithm == "weighted_round_robin":
            # Build weighted list
            weighted = []
            for backend in self.backends:
                weighted.extend([backend] * self.weights[backend])
            backend = weighted[self._current_index % len(weighted)]
            self._current_index += 1
            
        elif self.algorithm == "least_connections":
            backend = min(self.backends, key=lambda b: self._connection_counts[b])
            
        elif self.algorithm == "random":
            backend = random.choice(self.backends)
            
        else:
            backend = self.backends[0]
            
        self._connection_counts[backend] += 1
        return backend
        
    def release_connection(self, backend_id: str):
        """Release connection from backend"""
        if backend_id in self._connection_counts:
            self._connection_counts[backend_id] = max(0, self._connection_counts[backend_id] - 1)


class FirewallSimulator:
    """
    Firewall Simulator
    
    Simulates firewall rules and rate limiting.
    """
    
    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
        self._rate_limits: Dict[str, deque] = {}
        self._blocked_ips: set = set()
        
    def add_rule(self, action: str, src_ip: str = "*", dst_port: int = None,
                 protocol: str = "*", rate_limit: int = None):
        """Add firewall rule"""
        self.rules.append({
            'action': action,  # allow, deny, rate_limit
            'src_ip': src_ip,
            'dst_port': dst_port,
            'protocol': protocol,
            'rate_limit': rate_limit,
        })
        
    def block_ip(self, ip: str):
        """Block IP address"""
        self._blocked_ips.add(ip)
        
    def unblock_ip(self, ip: str):
        """Unblock IP address"""
        self._blocked_ips.discard(ip)
        
    def check_packet(self, src_ip: str, dst_port: int, protocol: str = "tcp") -> bool:
        """Check if packet is allowed"""
        # Check blocked IPs
        if src_ip in self._blocked_ips:
            return False
            
        # Check rules
        for rule in self.rules:
            if self._rule_matches(rule, src_ip, dst_port, protocol):
                if rule['action'] == 'deny':
                    return False
                elif rule['action'] == 'rate_limit':
                    return self._check_rate_limit(src_ip, rule['rate_limit'])
                elif rule['action'] == 'allow':
                    return True
                    
        # Default allow
        return True
        
    def _rule_matches(self, rule: Dict, src_ip: str, dst_port: int, protocol: str) -> bool:
        """Check if rule matches packet"""
        if rule['src_ip'] != "*" and rule['src_ip'] != src_ip:
            return False
        if rule['dst_port'] is not None and rule['dst_port'] != dst_port:
            return False
        if rule['protocol'] != "*" and rule['protocol'] != protocol:
            return False
        return True
        
    def _check_rate_limit(self, src_ip: str, limit: int) -> bool:
        """Check rate limit for IP"""
        current_time = time.time()
        
        if src_ip not in self._rate_limits:
            self._rate_limits[src_ip] = deque()
            
        # Remove old entries
        while self._rate_limits[src_ip] and self._rate_limits[src_ip][0] < current_time - 1:
            self._rate_limits[src_ip].popleft()
            
        # Check limit
        if len(self._rate_limits[src_ip]) >= limit:
            return False
            
        self._rate_limits[src_ip].append(current_time)
        return True


class TargetSimulator:
    """
    Target Server Simulator
    
    Simulates target server behavior under load.
    """
    
    def __init__(self, max_connections: int = 1000, max_rps: int = 10000):
        self.max_connections = max_connections
        self.max_rps = max_rps
        self._current_connections = 0
        self._request_times: deque = deque(maxlen=10000)
        self._health = 1.0
        
    async def handle_request(self) -> Tuple[bool, float, int]:
        """
        Handle incoming request.
        
        Returns: (success, response_time_ms, status_code)
        """
        current_time = time.time()
        self._request_times.append(current_time)
        
        # Calculate current RPS
        recent = [t for t in self._request_times if t > current_time - 1]
        current_rps = len(recent)
        
        # Calculate load factor
        load = current_rps / self.max_rps
        
        # Update health
        if load > 1.0:
            self._health = max(0, self._health - 0.01)
        else:
            self._health = min(1.0, self._health + 0.001)
            
        # Check if overloaded
        if load > 1.5 or self._health < 0.2:
            return (False, 0, 503)  # Service Unavailable
            
        # Calculate response time based on load
        base_response = 10  # 10ms base
        response_time = base_response * (1 + load * 2)
        
        # Add jitter
        response_time += random.gauss(0, response_time * 0.1)
        response_time = max(1, response_time)
        
        # Simulate processing
        await asyncio.sleep(response_time / 1000)
        
        # Determine status code
        if random.random() < (1 - self._health) * 0.5:
            return (False, response_time, 500)
            
        return (True, response_time, 200)
        
    def get_health(self) -> float:
        """Get current health (0-1)"""
        return self._health
        
    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        current_time = time.time()
        recent = [t for t in self._request_times if t > current_time - 1]
        
        return {
            'health': self._health,
            'current_rps': len(recent),
            'max_rps': self.max_rps,
            'load_factor': len(recent) / self.max_rps,
        }
