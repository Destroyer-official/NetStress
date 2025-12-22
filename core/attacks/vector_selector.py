"""
Intelligent Vector Selection Module

Maps target services to optimal attack vectors based on reconnaissance data.

Requirements:
- 11.3: Service-to-vector mapping (Nginx → Slowloris, Apache → Slow POST, UDP → Amplification)
- 11.4: Intelligent vector selection based on target profile
- 21.2: Intelligent vector selection based on target profile
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum

logger = logging.getLogger(__name__)


class VectorType(Enum):
    """Attack vector types"""
    # Layer 7 HTTP
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"
    SLOW_POST = "slow_post"
    RUDY = "rudy"
    HTTP2_PING = "http2_ping"
    HTTP_SMUGGLING = "http_smuggling"
    CACHE_BYPASS = "cache_bypass"
    
    # Layer 4
    TCP_SYN_FLOOD = "tcp_syn_flood"
    TCP_ACK_FLOOD = "tcp_ack_flood"
    TCP_RST_FLOOD = "tcp_rst_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    
    # Amplification
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    SSDP_AMPLIFICATION = "ssdp_amplification"
    MEMCACHED_AMPLIFICATION = "memcached_amplification"
    
    # SSL/TLS
    SSL_EXHAUSTION = "ssl_exhaustion"
    SSL_RENEGOTIATION = "ssl_renegotiation"
    
    # Application-specific
    WORDPRESS_XMLRPC = "wordpress_xmlrpc"
    GRAPHQL_DEPTH = "graphql_depth"
    WEBSOCKET_FLOOD = "websocket_flood"
    
    # Database
    MYSQL_FLOOD = "mysql_flood"
    REDIS_FLOOD = "redis_flood"
    POSTGRESQL_FLOOD = "postgresql_flood"
    MONGODB_FLOOD = "mongodb_flood"


@dataclass
class VectorRecommendation:
    """
    Attack vector recommendation with metadata.
    
    Requirements: 21.2 - Intelligent vector selection based on target profile
    """
    vector: VectorType
    effectiveness: float  # 0.0 - 1.0
    description: str
    target_ports: List[int]
    prerequisites: List[str] = field(default_factory=list)
    estimated_impact: str = "medium"  # low, medium, high, critical
    resource_cost: str = "medium"  # low, medium, high
    stealth_level: str = "medium"  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'vector': self.vector.value,
            'effectiveness': self.effectiveness,
            'description': self.description,
            'target_ports': self.target_ports,
            'prerequisites': self.prerequisites,
            'estimated_impact': self.estimated_impact,
            'resource_cost': self.resource_cost,
            'stealth_level': self.stealth_level,
        }


class ServiceVectorMapper:
    """
    Maps services to optimal attack vectors.
    
    Requirements:
    - 11.3: Nginx → Slowloris, HTTP/2 attacks; Apache → Slow POST, Range attacks; UDP → Amplification
    - 11.4: Intelligent vector selection based on target profile
    - 21.2: Intelligent vector selection based on target profile
    """
    
    # Service-to-vector mapping database
    SERVICE_MAPPINGS = {
        # Web servers
        'nginx': {
            'primary': [VectorType.SLOWLORIS, VectorType.HTTP2_PING],
            'secondary': [VectorType.HTTP_FLOOD, VectorType.CACHE_BYPASS],
            'effectiveness': 0.9,
            'reason': 'Nginx vulnerable to slow HTTP attacks and HTTP/2 exploitation'
        },
        'apache': {
            'primary': [VectorType.SLOW_POST, VectorType.RUDY],
            'secondary': [VectorType.HTTP_FLOOD, VectorType.HTTP_SMUGGLING],
            'effectiveness': 0.85,
            'reason': 'Apache vulnerable to slow POST and range header attacks'
        },
        'iis': {
            'primary': [VectorType.HTTP_FLOOD, VectorType.SSL_EXHAUSTION],
            'secondary': [VectorType.SLOW_POST, VectorType.HTTP_SMUGGLING],
            'effectiveness': 0.75,
            'reason': 'IIS vulnerable to volumetric attacks and SSL exhaustion'
        },
        'lighttpd': {
            'primary': [VectorType.SLOWLORIS, VectorType.HTTP_FLOOD],
            'secondary': [VectorType.SLOW_POST],
            'effectiveness': 0.8,
            'reason': 'Lighttpd vulnerable to connection exhaustion'
        },
        
        # DNS servers
        'bind': {
            'primary': [VectorType.DNS_AMPLIFICATION],
            'secondary': [VectorType.UDP_FLOOD],
            'effectiveness': 0.95,
            'reason': 'DNS servers excellent for amplification attacks'
        },
        'dns': {
            'primary': [VectorType.DNS_AMPLIFICATION],
            'secondary': [VectorType.UDP_FLOOD],
            'effectiveness': 0.95,
            'reason': 'Generic DNS service for amplification'
        },
        
        # Database servers
        'mysql': {
            'primary': [VectorType.MYSQL_FLOOD],
            'secondary': [VectorType.TCP_SYN_FLOOD],
            'effectiveness': 0.7,
            'reason': 'MySQL connection pool exhaustion'
        },
        'postgresql': {
            'primary': [VectorType.POSTGRESQL_FLOOD],
            'secondary': [VectorType.TCP_SYN_FLOOD],
            'effectiveness': 0.7,
            'reason': 'PostgreSQL connection exhaustion'
        },
        'redis': {
            'primary': [VectorType.REDIS_FLOOD],
            'secondary': [VectorType.TCP_SYN_FLOOD],
            'effectiveness': 0.75,
            'reason': 'Redis command flooding'
        },
        'mongodb': {
            'primary': [VectorType.MONGODB_FLOOD],
            'secondary': [VectorType.TCP_SYN_FLOOD],
            'effectiveness': 0.7,
            'reason': 'MongoDB query flooding'
        },
        
        # Application servers
        'wordpress': {
            'primary': [VectorType.WORDPRESS_XMLRPC],
            'secondary': [VectorType.HTTP_FLOOD, VectorType.SLOW_POST],
            'effectiveness': 0.85,
            'reason': 'WordPress XML-RPC pingback amplification'
        },
        
        # Amplification services
        'ntp': {
            'primary': [VectorType.NTP_AMPLIFICATION],
            'secondary': [VectorType.UDP_FLOOD],
            'effectiveness': 0.95,
            'reason': 'NTP monlist command amplification'
        },
        'ssdp': {
            'primary': [VectorType.SSDP_AMPLIFICATION],
            'secondary': [VectorType.UDP_FLOOD],
            'effectiveness': 0.9,
            'reason': 'SSDP M-SEARCH amplification'
        },
        'memcached': {
            'primary': [VectorType.MEMCACHED_AMPLIFICATION],
            'secondary': [VectorType.UDP_FLOOD],
            'effectiveness': 0.95,
            'reason': 'Memcached stats command amplification'
        },
    }
    
    # Port-to-service mapping for generic services
    PORT_MAPPINGS = {
        # Web
        80: {'service': 'http', 'vectors': [VectorType.HTTP_FLOOD, VectorType.SLOWLORIS]},
        443: {'service': 'https', 'vectors': [VectorType.HTTP_FLOOD, VectorType.SSL_EXHAUSTION]},
        8080: {'service': 'http-proxy', 'vectors': [VectorType.HTTP_FLOOD, VectorType.SLOWLORIS]},
        8443: {'service': 'https-alt', 'vectors': [VectorType.HTTP_FLOOD, VectorType.SSL_EXHAUSTION]},
        
        # DNS
        53: {'service': 'dns', 'vectors': [VectorType.DNS_AMPLIFICATION, VectorType.UDP_FLOOD]},
        
        # Database
        3306: {'service': 'mysql', 'vectors': [VectorType.MYSQL_FLOOD, VectorType.TCP_SYN_FLOOD]},
        5432: {'service': 'postgresql', 'vectors': [VectorType.POSTGRESQL_FLOOD, VectorType.TCP_SYN_FLOOD]},
        6379: {'service': 'redis', 'vectors': [VectorType.REDIS_FLOOD, VectorType.TCP_SYN_FLOOD]},
        27017: {'service': 'mongodb', 'vectors': [VectorType.MONGODB_FLOOD, VectorType.TCP_SYN_FLOOD]},
        
        # Amplification
        123: {'service': 'ntp', 'vectors': [VectorType.NTP_AMPLIFICATION, VectorType.UDP_FLOOD]},
        1900: {'service': 'ssdp', 'vectors': [VectorType.SSDP_AMPLIFICATION, VectorType.UDP_FLOOD]},
        11211: {'service': 'memcached', 'vectors': [VectorType.MEMCACHED_AMPLIFICATION, VectorType.UDP_FLOOD]},
    }
    
    def __init__(self):
        """Initialize vector mapper"""
        self.recommendations: List[VectorRecommendation] = []
        
    def map_service_to_vectors(self, service_name: str, port: int, 
                               version: Optional[str] = None) -> List[VectorRecommendation]:
        """
        Map a specific service to attack vectors.
        
        Requirements: 11.3 - Service-to-vector mapping
        
        Args:
            service_name: Service name (e.g., 'nginx', 'apache', 'mysql')
            port: Service port
            version: Optional service version
            
        Returns:
            List of recommended attack vectors
        """
        recommendations = []
        service_lower = service_name.lower()
        
        # Check for exact service match
        for service_key, mapping in self.SERVICE_MAPPINGS.items():
            if service_key in service_lower:
                # Primary vectors
                for vector in mapping['primary']:
                    recommendations.append(VectorRecommendation(
                        vector=vector,
                        effectiveness=mapping['effectiveness'],
                        description=f"{vector.value} - {mapping['reason']}",
                        target_ports=[port],
                        estimated_impact="high",
                        resource_cost="medium",
                        stealth_level="medium"
                    ))
                
                # Secondary vectors
                for vector in mapping['secondary']:
                    recommendations.append(VectorRecommendation(
                        vector=vector,
                        effectiveness=mapping['effectiveness'] * 0.7,
                        description=f"{vector.value} - Secondary option for {service_key}",
                        target_ports=[port],
                        estimated_impact="medium",
                        resource_cost="medium",
                        stealth_level="medium"
                    ))
                
                logger.info(f"Mapped {service_name} to {len(recommendations)} vectors")
                return recommendations
        
        # Fallback to port-based mapping
        if port in self.PORT_MAPPINGS:
            port_mapping = self.PORT_MAPPINGS[port]
            for vector in port_mapping['vectors']:
                recommendations.append(VectorRecommendation(
                    vector=vector,
                    effectiveness=0.6,
                    description=f"{vector.value} - Generic attack for port {port}",
                    target_ports=[port],
                    estimated_impact="medium",
                    resource_cost="medium",
                    stealth_level="medium"
                ))
        
        # Generic fallback
        if not recommendations:
            if port in [80, 443, 8080, 8443]:
                recommendations.append(VectorRecommendation(
                    vector=VectorType.HTTP_FLOOD,
                    effectiveness=0.5,
                    description="Generic HTTP flood",
                    target_ports=[port],
                    estimated_impact="medium",
                    resource_cost="low",
                    stealth_level="low"
                ))
            else:
                recommendations.append(VectorRecommendation(
                    vector=VectorType.TCP_SYN_FLOOD,
                    effectiveness=0.4,
                    description="Generic TCP SYN flood",
                    target_ports=[port],
                    estimated_impact="low",
                    resource_cost="low",
                    stealth_level="low"
                ))
        
        return recommendations
    
    def select_vectors_from_profile(self, target_profile: Dict[str, Any]) -> List[VectorRecommendation]:
        """
        Select optimal attack vectors from target profile.
        
        Requirements:
        - 11.4: Intelligent vector selection based on target profile
        - 21.2: Intelligent vector selection based on target profile
        
        Args:
            target_profile: Target profile from reconnaissance (TargetProfile.to_dict())
            
        Returns:
            Prioritized list of attack vector recommendations
        """
        all_recommendations = []
        seen_vectors: Set[VectorType] = set()
        
        # Extract services from profile
        services = target_profile.get('services', {})
        
        logger.info(f"Analyzing {len(services)} services for vector selection")
        
        # Map each service to vectors
        for port_str, service_info in services.items():
            port = int(port_str)
            service_name = service_info.get('service', 'unknown')
            version = service_info.get('version')
            
            # Get recommendations for this service
            service_recs = self.map_service_to_vectors(service_name, port, version)
            
            # Add unique recommendations
            for rec in service_recs:
                if rec.vector not in seen_vectors:
                    all_recommendations.append(rec)
                    seen_vectors.add(rec.vector)
        
        # Check for web-specific technologies
        web_info = target_profile.get('web', {})
        if web_info:
            web_server = web_info.get('server', '').lower()
            web_cms = web_info.get('cms', '').lower()
            
            # Web server specific
            if web_server:
                for service_key in ['nginx', 'apache', 'iis', 'lighttpd']:
                    if service_key in web_server:
                        mapping = self.SERVICE_MAPPINGS.get(service_key, {})
                        for vector in mapping.get('primary', []):
                            if vector not in seen_vectors:
                                all_recommendations.append(VectorRecommendation(
                                    vector=vector,
                                    effectiveness=mapping.get('effectiveness', 0.7),
                                    description=f"{vector.value} - Detected {service_key}",
                                    target_ports=[80, 443],
                                    estimated_impact="high",
                                    resource_cost="medium",
                                    stealth_level="medium"
                                ))
                                seen_vectors.add(vector)
            
            # CMS specific
            if 'wordpress' in web_cms:
                if VectorType.WORDPRESS_XMLRPC not in seen_vectors:
                    all_recommendations.append(VectorRecommendation(
                        vector=VectorType.WORDPRESS_XMLRPC,
                        effectiveness=0.85,
                        description="WordPress XML-RPC pingback attack",
                        target_ports=[80, 443],
                        estimated_impact="high",
                        resource_cost="low",
                        stealth_level="high"
                    ))
                    seen_vectors.add(VectorType.WORDPRESS_XMLRPC)
        
        # Check for TLS/SSL
        tls_info = target_profile.get('tls', {})
        if tls_info and tls_info.get('protocols'):
            if VectorType.SSL_EXHAUSTION not in seen_vectors:
                all_recommendations.append(VectorRecommendation(
                    vector=VectorType.SSL_EXHAUSTION,
                    effectiveness=0.75,
                    description="SSL/TLS connection exhaustion",
                    target_ports=[443],
                    estimated_impact="high",
                    resource_cost="high",
                    stealth_level="low"
                ))
                seen_vectors.add(VectorType.SSL_EXHAUSTION)
        
        # Add generic fallback vectors
        open_ports = target_profile.get('ports', {}).get('open', [])
        if open_ports and not all_recommendations:
            # Generic TCP SYN flood
            all_recommendations.append(VectorRecommendation(
                vector=VectorType.TCP_SYN_FLOOD,
                effectiveness=0.5,
                description="Generic TCP SYN flood",
                target_ports=open_ports[:5],  # Top 5 ports
                estimated_impact="medium",
                resource_cost="low",
                stealth_level="low"
            ))
            
            # Generic UDP flood if UDP ports detected
            all_recommendations.append(VectorRecommendation(
                vector=VectorType.UDP_FLOOD,
                effectiveness=0.4,
                description="Generic UDP flood",
                target_ports=open_ports[:5],
                estimated_impact="low",
                resource_cost="low",
                stealth_level="low"
            ))
        
        # Sort by effectiveness
        all_recommendations.sort(key=lambda x: x.effectiveness, reverse=True)
        
        logger.info(f"Selected {len(all_recommendations)} attack vectors")
        self.recommendations = all_recommendations
        
        return all_recommendations
    
    def get_top_vectors(self, n: int = 5) -> List[VectorRecommendation]:
        """Get top N recommended vectors"""
        return self.recommendations[:n]
    
    def get_vectors_by_impact(self, impact: str) -> List[VectorRecommendation]:
        """Get vectors filtered by estimated impact"""
        return [r for r in self.recommendations if r.estimated_impact == impact]
    
    def get_vectors_by_stealth(self, stealth: str) -> List[VectorRecommendation]:
        """Get vectors filtered by stealth level"""
        return [r for r in self.recommendations if r.stealth_level == stealth]
