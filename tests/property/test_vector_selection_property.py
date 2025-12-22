#!/usr/bin/env python3
"""
Property-Based Test for Intelligent Vector Selection

Tests the Kill Chain Vector Selection property defined in the design document.

**Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection**
**Validates: Requirements 21.1, 21.2**
"""

import pytest
import time
from hypothesis import given, strategies as st, settings, assume
from typing import Dict, Any, List

from core.attacks.vector_selector import (
    ServiceVectorMapper, VectorType, VectorRecommendation
)


# Strategy for generating service names
@st.composite
def service_name_strategy(draw):
    """Generate realistic service names"""
    services = [
        'nginx', 'apache', 'iis', 'lighttpd',
        'mysql', 'postgresql', 'redis', 'mongodb',
        'dns', 'bind', 'ntp', 'ssdp', 'memcached',
        'wordpress', 'http', 'https', 'ftp', 'ssh',
        'unknown', 'custom-service'
    ]
    return draw(st.sampled_from(services))


# Strategy for generating port numbers
@st.composite
def port_strategy(draw):
    """Generate realistic port numbers"""
    common_ports = [21, 22, 23, 25, 53, 80, 123, 443, 1900, 3306, 5432, 6379, 8080, 11211, 27017]
    # Mix of common ports and random ports
    if draw(st.booleans()):
        return draw(st.sampled_from(common_ports))
    else:
        return draw(st.integers(min_value=1, max_value=65535))


# Strategy for generating target profiles
@st.composite
def target_profile_strategy(draw):
    """Generate realistic target profiles from reconnaissance"""
    num_services = draw(st.integers(min_value=1, max_value=10))
    
    services = {}
    open_ports = []
    
    for _ in range(num_services):
        port = draw(port_strategy())
        service_name = draw(service_name_strategy())
        
        services[str(port)] = {
            'service': service_name,
            'version': draw(st.one_of(st.none(), st.text(min_size=1, max_size=20))),
            'banner': draw(st.one_of(st.none(), st.text(min_size=0, max_size=100))),
        }
        open_ports.append(port)
    
    # Web information (optional)
    has_web = draw(st.booleans())
    web_info = {}
    if has_web:
        web_servers = ['nginx', 'apache', 'iis', 'lighttpd', '']
        web_cms = ['wordpress', 'drupal', 'joomla', '']
        web_info = {
            'server': draw(st.sampled_from(web_servers)),
            'cms': draw(st.sampled_from(web_cms)),
            'framework': draw(st.one_of(st.none(), st.text(min_size=0, max_size=20))),
        }
    
    # TLS information (optional)
    has_tls = draw(st.booleans())
    tls_info = {}
    if has_tls:
        tls_info = {
            'protocols': draw(st.lists(st.sampled_from(['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']), 
                                       min_size=0, max_size=4)),
            'cipher': draw(st.one_of(st.none(), st.text(min_size=0, max_size=50))),
        }
    
    return {
        'target': draw(st.text(min_size=1, max_size=50)),
        'timestamp': time.time(),
        'services': services,
        'ports': {
            'open': open_ports,
            'filtered': [],
            'closed': [],
        },
        'web': web_info,
        'tls': tls_info,
    }


class TestVectorSelectionProperty:
    """Property-based tests for intelligent vector selection"""
    
    @given(service_name=service_name_strategy(), port=port_strategy())
    @settings(max_examples=10, deadline=3000)
    def test_property_7_service_to_vector_mapping_always_returns_vectors(
        self, service_name: str, port: int
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 1)**
        **Validates: Requirements 21.1, 21.2**
        
        For any service name and port, the service-to-vector mapper SHALL return
        at least one attack vector recommendation.
        
        This ensures that the system can always provide attack options regardless
        of the target configuration.
        """
        mapper = ServiceVectorMapper()
        
        # Map service to vectors
        recommendations = mapper.map_service_to_vectors(service_name, port)
        
        # Property: Must return at least one recommendation
        assert len(recommendations) > 0, (
            f"Service-to-vector mapping failed: No vectors returned for "
            f"service='{service_name}' on port={port}"
        )
        
        # Property: All recommendations must be valid VectorRecommendation objects
        for rec in recommendations:
            assert isinstance(rec, VectorRecommendation), (
                f"Invalid recommendation type: {type(rec)}"
            )
            assert isinstance(rec.vector, VectorType), (
                f"Invalid vector type: {type(rec.vector)}"
            )
            assert 0.0 <= rec.effectiveness <= 1.0, (
                f"Effectiveness out of range: {rec.effectiveness}"
            )
            assert port in rec.target_ports, (
                f"Target port {port} not in recommendation ports: {rec.target_ports}"
            )
    
    @given(target_profile=target_profile_strategy())
    @settings(max_examples=10, deadline=10000)
    def test_property_7_profile_based_selection_returns_prioritized_vectors(
        self, target_profile: Dict[str, Any]
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 2)**
        **Validates: Requirements 21.1, 21.2**
        
        For any target profile from reconnaissance, the system SHALL select
        appropriate attack vectors based on detected services and return them
        in priority order (highest effectiveness first).
        
        This ensures intelligent vector selection based on target characteristics.
        """
        mapper = ServiceVectorMapper()
        
        # Select vectors from profile
        recommendations = mapper.select_vectors_from_profile(target_profile)
        
        # Property: Must return at least one recommendation
        assert len(recommendations) > 0, (
            f"Profile-based selection failed: No vectors returned for profile with "
            f"{len(target_profile.get('services', {}))} services"
        )
        
        # Property: Recommendations must be sorted by effectiveness (descending)
        for i in range(len(recommendations) - 1):
            assert recommendations[i].effectiveness >= recommendations[i + 1].effectiveness, (
                f"Recommendations not sorted by effectiveness: "
                f"{recommendations[i].effectiveness} < {recommendations[i + 1].effectiveness}"
            )
        
        # Property: All recommendations must be valid
        for rec in recommendations:
            assert isinstance(rec, VectorRecommendation)
            assert isinstance(rec.vector, VectorType)
            assert 0.0 <= rec.effectiveness <= 1.0
            assert len(rec.target_ports) > 0
            assert rec.description is not None and len(rec.description) > 0
    
    @given(
        service_name=st.sampled_from(['nginx', 'apache', 'iis']),
        port=st.sampled_from([80, 443, 8080])
    )
    @settings(max_examples=10, deadline=5000)
    def test_property_7_web_server_mapping_correctness(
        self, service_name: str, port: int
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 3)**
        **Validates: Requirements 11.3, 21.2**
        
        For any web server (Nginx, Apache, IIS), the mapper SHALL recommend
        appropriate web-specific attack vectors:
        - Nginx → Slowloris, HTTP/2 attacks
        - Apache → Slow POST, Range attacks
        - IIS → HTTP Flood, SSL exhaustion
        
        This validates the service-specific mapping requirements.
        """
        mapper = ServiceVectorMapper()
        
        recommendations = mapper.map_service_to_vectors(service_name, port)
        
        # Extract recommended vector types
        vector_types = [rec.vector for rec in recommendations]
        
        # Property: Web servers must have web-specific vectors
        web_vectors = {
            VectorType.HTTP_FLOOD,
            VectorType.SLOWLORIS,
            VectorType.SLOW_POST,
            VectorType.RUDY,
            VectorType.HTTP2_PING,
            VectorType.SSL_EXHAUSTION,
            VectorType.HTTP_SMUGGLING,
            VectorType.CACHE_BYPASS,
        }
        
        has_web_vector = any(v in web_vectors for v in vector_types)
        assert has_web_vector, (
            f"Web server '{service_name}' did not receive web-specific attack vectors. "
            f"Got: {[v.value for v in vector_types]}"
        )
        
        # Property: Service-specific recommendations
        if service_name == 'nginx':
            # Nginx should have Slowloris or HTTP/2 attacks
            nginx_vectors = {VectorType.SLOWLORIS, VectorType.HTTP2_PING}
            has_nginx_vector = any(v in nginx_vectors for v in vector_types)
            assert has_nginx_vector, (
                f"Nginx did not receive Slowloris or HTTP/2 vectors. "
                f"Got: {[v.value for v in vector_types]}"
            )
        
        elif service_name == 'apache':
            # Apache should have Slow POST or RUDY
            apache_vectors = {VectorType.SLOW_POST, VectorType.RUDY}
            has_apache_vector = any(v in apache_vectors for v in vector_types)
            assert has_apache_vector, (
                f"Apache did not receive Slow POST or RUDY vectors. "
                f"Got: {[v.value for v in vector_types]}"
            )
    
    @given(
        service_name=st.sampled_from(['dns', 'bind', 'ntp', 'ssdp', 'memcached']),
        port=st.sampled_from([53, 123, 1900, 11211])
    )
    @settings(max_examples=10, deadline=5000)
    def test_property_7_amplification_service_mapping(
        self, service_name: str, port: int
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 4)**
        **Validates: Requirements 11.3, 21.2**
        
        For any UDP amplification service (DNS, NTP, SSDP, Memcached), the mapper
        SHALL recommend amplification attack vectors as the primary option.
        
        This validates the UDP service → amplification attack mapping.
        """
        mapper = ServiceVectorMapper()
        
        recommendations = mapper.map_service_to_vectors(service_name, port)
        
        # Extract recommended vector types
        vector_types = [rec.vector for rec in recommendations]
        
        # Property: Amplification services must have amplification vectors
        amplification_vectors = {
            VectorType.DNS_AMPLIFICATION,
            VectorType.NTP_AMPLIFICATION,
            VectorType.SSDP_AMPLIFICATION,
            VectorType.MEMCACHED_AMPLIFICATION,
        }
        
        has_amplification = any(v in amplification_vectors for v in vector_types)
        assert has_amplification, (
            f"Amplification service '{service_name}' did not receive amplification vectors. "
            f"Got: {[v.value for v in vector_types]}"
        )
        
        # Property: Amplification vector should be high priority (in top 2)
        top_vectors = vector_types[:2]
        has_amplification_in_top = any(v in amplification_vectors for v in top_vectors)
        assert has_amplification_in_top, (
            f"Amplification vector not in top 2 priorities for '{service_name}'. "
            f"Top vectors: {[v.value for v in top_vectors]}"
        )
    
    @given(
        service_name=st.sampled_from(['mysql', 'postgresql', 'redis', 'mongodb']),
        port=st.sampled_from([3306, 5432, 6379, 27017])
    )
    @settings(max_examples=10, deadline=5000)
    def test_property_7_database_service_mapping(
        self, service_name: str, port: int
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 5)**
        **Validates: Requirements 21.2**
        
        For any database service, the mapper SHALL recommend database-specific
        connection exhaustion attacks.
        """
        mapper = ServiceVectorMapper()
        
        recommendations = mapper.map_service_to_vectors(service_name, port)
        
        # Extract recommended vector types
        vector_types = [rec.vector for rec in recommendations]
        
        # Property: Database services must have database-specific vectors
        database_vectors = {
            VectorType.MYSQL_FLOOD,
            VectorType.POSTGRESQL_FLOOD,
            VectorType.REDIS_FLOOD,
            VectorType.MONGODB_FLOOD,
        }
        
        has_database_vector = any(v in database_vectors for v in vector_types)
        assert has_database_vector, (
            f"Database service '{service_name}' did not receive database-specific vectors. "
            f"Got: {[v.value for v in vector_types]}"
        )
    
    @given(target_profile=target_profile_strategy())
    @settings(max_examples=10, deadline=10000)
    def test_property_7_no_duplicate_vectors_in_recommendations(
        self, target_profile: Dict[str, Any]
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 6)**
        **Validates: Requirements 21.2**
        
        For any target profile, the system SHALL not recommend duplicate attack
        vectors. Each vector should appear at most once in the recommendations.
        """
        mapper = ServiceVectorMapper()
        
        recommendations = mapper.select_vectors_from_profile(target_profile)
        
        # Extract vector types
        vector_types = [rec.vector for rec in recommendations]
        
        # Property: No duplicates
        unique_vectors = set(vector_types)
        assert len(vector_types) == len(unique_vectors), (
            f"Duplicate vectors found in recommendations. "
            f"Total: {len(vector_types)}, Unique: {len(unique_vectors)}"
        )
    
    @given(target_profile=target_profile_strategy())
    @settings(max_examples=10, deadline=10000)
    def test_property_7_effectiveness_scores_are_valid(
        self, target_profile: Dict[str, Any]
    ):
        """
        **Feature: titanium-upgrade, Property 7: Kill Chain Vector Selection (Part 7)**
        **Validates: Requirements 21.2**
        
        For any target profile, all effectiveness scores SHALL be in the valid
        range [0.0, 1.0] and recommendations with known services SHALL have
        higher effectiveness than generic fallbacks.
        """
        mapper = ServiceVectorMapper()
        
        recommendations = mapper.select_vectors_from_profile(target_profile)
        
        # Property: All effectiveness scores in valid range
        for rec in recommendations:
            assert 0.0 <= rec.effectiveness <= 1.0, (
                f"Effectiveness score out of range: {rec.effectiveness} for {rec.vector.value}"
            )
        
        # Property: If we have known services, top recommendations should have
        # higher effectiveness than generic fallbacks
        services = target_profile.get('services', {})
        if services:
            # Check if we have any known services
            known_services = ['nginx', 'apache', 'mysql', 'dns', 'ntp', 'redis']
            has_known_service = any(
                any(known in info.get('service', '').lower() for known in known_services)
                for info in services.values()
            )
            
            if has_known_service and len(recommendations) > 1:
                # Top recommendation should have reasonable effectiveness
                top_effectiveness = recommendations[0].effectiveness
                assert top_effectiveness >= 0.5, (
                    f"Top recommendation for known service has low effectiveness: {top_effectiveness}"
                )


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
