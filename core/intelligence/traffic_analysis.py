"""
Traffic Intelligence Module

Advanced traffic analysis and intelligence gathering:
- Deep packet inspection simulation
- Traffic pattern analysis
- Anomaly detection
- Protocol fingerprinting
"""

import asyncio
import time
import random
import statistics
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set
from enum import Enum
from collections import deque, Counter
import logging

logger = logging.getLogger(__name__)


class TrafficType(Enum):
    """Traffic classification types"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    UNKNOWN = "unknown"
    MALICIOUS = "malicious"


class AnomalyType(Enum):
    """Anomaly types"""
    RATE_SPIKE = "rate_spike"
    PATTERN_CHANGE = "pattern_change"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    SIZE_ANOMALY = "size_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    SOURCE_ANOMALY = "source_anomaly"


@dataclass
class PacketInfo:
    """Packet information"""
    timestamp: float = field(default_factory=time.time)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    size: int = 0
    payload_hash: str = ""
    flags: int = 0
    ttl: int = 64


@dataclass
class FlowInfo:
    """Network flow information"""
    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    packets: int = 0
    bytes_total: int = 0
    start_time: float = 0
    last_time: float = 0
    flags_seen: Set[int] = field(default_factory=set)


@dataclass
class Anomaly:
    """Detected anomaly"""
    anomaly_type: AnomalyType
    severity: float  # 0-1
    timestamp: float
    description: str
    source: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class PacketAnalyzer:
    """
    Deep Packet Analyzer
    
    Analyzes packet contents and patterns.
    """
    
    # Protocol signatures
    SIGNATURES = {
        TrafficType.HTTP: [b'GET ', b'POST ', b'HTTP/', b'HEAD ', b'PUT ', b'DELETE '],
        TrafficType.HTTPS: [b'\x16\x03\x01', b'\x16\x03\x03'],  # TLS handshake
        TrafficType.DNS: [],  # Port-based
        TrafficType.SSH: [b'SSH-'],
        TrafficType.FTP: [b'220 ', b'USER ', b'PASS ', b'LIST'],
        TrafficType.SMTP: [b'EHLO ', b'HELO ', b'MAIL FROM:', b'RCPT TO:'],
    }
    
    def __init__(self):
        self._packet_history: deque = deque(maxlen=10000)
        self._payload_cache: Dict[str, int] = {}  # hash -> count
        
    def analyze_packet(self, data: bytes, packet_info: PacketInfo) -> Dict[str, Any]:
        """Analyze a single packet"""
        result = {
            'traffic_type': self._classify_traffic(data, packet_info),
            'payload_size': len(data),
            'entropy': self._calculate_entropy(data),
            'is_encrypted': False,
            'protocol_valid': True,
            'suspicious_patterns': [],
        }
        
        # Check for encryption
        if result['entropy'] > 7.5:
            result['is_encrypted'] = True
            
        # Check for suspicious patterns
        result['suspicious_patterns'] = self._detect_suspicious_patterns(data)
        
        # Check protocol validity
        result['protocol_valid'] = self._validate_protocol(data, result['traffic_type'])
        
        # Track payload
        payload_hash = hashlib.md5(data[:100] if len(data) > 100 else data).hexdigest()
        packet_info.payload_hash = payload_hash
        self._payload_cache[payload_hash] = self._payload_cache.get(payload_hash, 0) + 1
        
        # Store packet
        self._packet_history.append(packet_info)
        
        return result
        
    def _classify_traffic(self, data: bytes, packet_info: PacketInfo) -> TrafficType:
        """Classify traffic type"""
        # Port-based classification
        port_map = {
            80: TrafficType.HTTP,
            443: TrafficType.HTTPS,
            53: TrafficType.DNS,
            22: TrafficType.SSH,
            21: TrafficType.FTP,
            25: TrafficType.SMTP,
        }
        
        if packet_info.dst_port in port_map:
            return port_map[packet_info.dst_port]
            
        # Signature-based classification
        for traffic_type, signatures in self.SIGNATURES.items():
            for sig in signatures:
                if data.startswith(sig):
                    return traffic_type
                    
        return TrafficType.UNKNOWN
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        import math
        
        if not data:
            return 0.0
            
        freq = Counter(data)
        length = len(data)
        
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
                
        return entropy
        
    def _detect_suspicious_patterns(self, data: bytes) -> List[str]:
        """Detect suspicious patterns in payload"""
        patterns = []
        
        # Check for common attack patterns
        attack_signatures = [
            (b'<script', 'xss_attempt'),
            (b'SELECT ', 'sql_injection'),
            (b'UNION ', 'sql_injection'),
            (b'../..', 'path_traversal'),
            (b'/etc/passwd', 'path_traversal'),
            (b'cmd.exe', 'command_injection'),
            (b'/bin/sh', 'command_injection'),
            (b'\x00' * 100, 'null_byte_injection'),
            (b'%00', 'null_byte_injection'),
        ]
        
        data_lower = data.lower()
        for sig, pattern_name in attack_signatures:
            if sig.lower() in data_lower:
                patterns.append(pattern_name)
                
        # Check for repeated patterns (potential DoS)
        if len(data) > 100:
            chunk = data[:10]
            if data.count(chunk) > len(data) // 20:
                patterns.append('repeated_pattern')
                
        return patterns
        
    def _validate_protocol(self, data: bytes, traffic_type: TrafficType) -> bool:
        """Validate protocol conformance"""
        if traffic_type == TrafficType.HTTP:
            # Basic HTTP validation
            try:
                text = data.decode('utf-8', errors='ignore')
                if text.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ')):
                    return 'HTTP/' in text
            except Exception:
                pass
            return False
            
        elif traffic_type == TrafficType.DNS:
            # Basic DNS validation
            return len(data) >= 12  # Minimum DNS header size
            
        return True
        
    def get_payload_frequency(self) -> Dict[str, int]:
        """Get payload frequency distribution"""
        return dict(sorted(self._payload_cache.items(), key=lambda x: x[1], reverse=True)[:100])


class FlowTracker:
    """
    Network Flow Tracker
    
    Tracks and analyzes network flows.
    """
    
    def __init__(self, flow_timeout: float = 60.0):
        self.flow_timeout = flow_timeout
        self._flows: Dict[str, FlowInfo] = {}
        self._completed_flows: deque = deque(maxlen=1000)
        
    def _get_flow_id(self, packet: PacketInfo) -> str:
        """Generate flow ID"""
        # Bidirectional flow ID
        endpoints = sorted([
            (packet.src_ip, packet.src_port),
            (packet.dst_ip, packet.dst_port)
        ])
        return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}-{packet.protocol}"
        
    def track_packet(self, packet: PacketInfo) -> FlowInfo:
        """Track packet in flow"""
        flow_id = self._get_flow_id(packet)
        
        if flow_id not in self._flows:
            self._flows[flow_id] = FlowInfo(
                flow_id=flow_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp
            )
            
        flow = self._flows[flow_id]
        flow.packets += 1
        flow.bytes_total += packet.size
        flow.last_time = packet.timestamp
        flow.flags_seen.add(packet.flags)
        
        return flow
        
    def expire_flows(self) -> List[FlowInfo]:
        """Expire old flows"""
        current_time = time.time()
        expired = []
        
        for flow_id, flow in list(self._flows.items()):
            if (current_time - flow.last_time) > self.flow_timeout:
                expired.append(flow)
                self._completed_flows.append(flow)
                del self._flows[flow_id]
                
        return expired
        
    def get_active_flows(self) -> List[FlowInfo]:
        """Get active flows"""
        return list(self._flows.values())
        
    def get_flow_stats(self) -> Dict[str, Any]:
        """Get flow statistics"""
        active = self.get_active_flows()
        
        if not active:
            return {'active_flows': 0}
            
        return {
            'active_flows': len(active),
            'total_packets': sum(f.packets for f in active),
            'total_bytes': sum(f.bytes_total for f in active),
            'avg_packets_per_flow': statistics.mean(f.packets for f in active),
            'avg_bytes_per_flow': statistics.mean(f.bytes_total for f in active),
        }


class AnomalyDetector:
    """
    Traffic Anomaly Detector
    
    Detects anomalies in network traffic patterns.
    """
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self._rate_history: deque = deque(maxlen=window_size)
        self._size_history: deque = deque(maxlen=window_size)
        self._source_history: deque = deque(maxlen=window_size)
        self._anomalies: List[Anomaly] = []
        self._baseline_rate: Optional[float] = None
        self._baseline_size: Optional[float] = None
        
    def analyze(self, packet: PacketInfo) -> List[Anomaly]:
        """Analyze packet for anomalies"""
        anomalies = []
        current_time = time.time()
        
        # Track metrics
        self._rate_history.append(current_time)
        self._size_history.append(packet.size)
        self._source_history.append(packet.src_ip)
        
        # Calculate current rate
        if len(self._rate_history) >= 10:
            time_span = self._rate_history[-1] - self._rate_history[0]
            if time_span > 0:
                current_rate = len(self._rate_history) / time_span
                
                # Update baseline
                if self._baseline_rate is None:
                    self._baseline_rate = current_rate
                else:
                    self._baseline_rate = 0.95 * self._baseline_rate + 0.05 * current_rate
                    
                # Check for rate spike
                if current_rate > self._baseline_rate * 3:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.RATE_SPIKE,
                        severity=min(1.0, (current_rate / self._baseline_rate - 1) / 10),
                        timestamp=current_time,
                        description=f"Rate spike detected: {current_rate:.1f} pps vs baseline {self._baseline_rate:.1f}",
                        details={'current_rate': current_rate, 'baseline': self._baseline_rate}
                    ))
                    
        # Check for size anomaly
        if len(self._size_history) >= 100:
            avg_size = statistics.mean(self._size_history)
            std_size = statistics.stdev(self._size_history) if len(self._size_history) > 1 else 0
            
            if std_size > 0 and abs(packet.size - avg_size) > 3 * std_size:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.SIZE_ANOMALY,
                    severity=min(1.0, abs(packet.size - avg_size) / (3 * std_size) - 1),
                    timestamp=current_time,
                    description=f"Unusual packet size: {packet.size} bytes",
                    details={'size': packet.size, 'avg': avg_size, 'std': std_size}
                ))
                
        # Check for source concentration
        if len(self._source_history) >= 100:
            source_counts = Counter(self._source_history)
            top_source, top_count = source_counts.most_common(1)[0]
            concentration = top_count / len(self._source_history)
            
            if concentration > 0.5:  # Single source > 50% of traffic
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.SOURCE_ANOMALY,
                    severity=concentration,
                    timestamp=current_time,
                    description=f"High traffic concentration from {top_source}",
                    source=top_source,
                    details={'concentration': concentration, 'count': top_count}
                ))
                
        self._anomalies.extend(anomalies)
        return anomalies
        
    def get_anomalies(self, since: float = None) -> List[Anomaly]:
        """Get detected anomalies"""
        if since is None:
            return self._anomalies.copy()
        return [a for a in self._anomalies if a.timestamp >= since]
        
    def get_threat_level(self) -> float:
        """Calculate current threat level (0-1)"""
        recent = self.get_anomalies(time.time() - 60)
        
        if not recent:
            return 0.0
            
        # Weight by severity and recency
        total_severity = sum(a.severity for a in recent)
        return min(1.0, total_severity / 5)


class ProtocolFingerprinter:
    """
    Protocol Fingerprinting
    
    Identifies protocols and implementations.
    """
    
    def __init__(self):
        self._fingerprints: Dict[str, Dict[str, Any]] = {}
        
    def fingerprint_http(self, response: bytes) -> Dict[str, Any]:
        """Fingerprint HTTP server"""
        result = {
            'server': None,
            'powered_by': None,
            'framework': None,
            'version': None,
        }
        
        try:
            text = response.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            for line in lines:
                lower = line.lower()
                if lower.startswith('server:'):
                    result['server'] = line.split(':', 1)[1].strip()
                elif lower.startswith('x-powered-by:'):
                    result['powered_by'] = line.split(':', 1)[1].strip()
                elif lower.startswith('x-aspnet-version:'):
                    result['framework'] = 'ASP.NET'
                    result['version'] = line.split(':', 1)[1].strip()
                    
        except Exception:
            pass
            
        return result
        
    def fingerprint_ssh(self, banner: bytes) -> Dict[str, Any]:
        """Fingerprint SSH server"""
        result = {
            'version': None,
            'software': None,
            'os_hint': None,
        }
        
        try:
            text = banner.decode('utf-8', errors='ignore').strip()
            
            if text.startswith('SSH-'):
                parts = text.split('-')
                if len(parts) >= 3:
                    result['version'] = parts[1]
                    result['software'] = parts[2].split()[0] if parts[2] else None
                    
                    # OS hints
                    if 'Ubuntu' in text:
                        result['os_hint'] = 'Ubuntu Linux'
                    elif 'Debian' in text:
                        result['os_hint'] = 'Debian Linux'
                    elif 'OpenSSH' in text:
                        result['os_hint'] = 'Unix/Linux'
                        
        except Exception:
            pass
            
        return result
        
    def fingerprint_tls(self, client_hello: bytes) -> Dict[str, Any]:
        """Fingerprint TLS client (JA3-like)"""
        result = {
            'tls_version': None,
            'cipher_suites': [],
            'extensions': [],
            'fingerprint': None,
        }
        
        try:
            if len(client_hello) < 5:
                return result
                
            # Parse TLS record
            if client_hello[0] == 0x16:  # Handshake
                version = (client_hello[1] << 8) | client_hello[2]
                result['tls_version'] = f"0x{version:04x}"
                
                # Generate simple fingerprint
                result['fingerprint'] = hashlib.md5(client_hello[:50]).hexdigest()
                
        except Exception:
            pass
            
        return result


class TrafficIntelligence:
    """
    Traffic Intelligence Engine
    
    Combines all analysis components for comprehensive traffic intelligence.
    """
    
    def __init__(self):
        self.packet_analyzer = PacketAnalyzer()
        self.flow_tracker = FlowTracker()
        self.anomaly_detector = AnomalyDetector()
        self.fingerprinter = ProtocolFingerprinter()
        self._running = False
        
    def analyze_packet(self, data: bytes, src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int, protocol: str = "tcp") -> Dict[str, Any]:
        """Comprehensive packet analysis"""
        packet = PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=len(data)
        )
        
        # Analyze packet
        packet_analysis = self.packet_analyzer.analyze_packet(data, packet)
        
        # Track flow
        flow = self.flow_tracker.track_packet(packet)
        
        # Detect anomalies
        anomalies = self.anomaly_detector.analyze(packet)
        
        return {
            'packet': packet_analysis,
            'flow': {
                'id': flow.flow_id,
                'packets': flow.packets,
                'bytes': flow.bytes_total,
            },
            'anomalies': [
                {'type': a.anomaly_type.value, 'severity': a.severity, 'description': a.description}
                for a in anomalies
            ],
            'threat_level': self.anomaly_detector.get_threat_level(),
        }
        
    def get_intelligence_report(self) -> Dict[str, Any]:
        """Generate intelligence report"""
        return {
            'flow_stats': self.flow_tracker.get_flow_stats(),
            'active_flows': len(self.flow_tracker.get_active_flows()),
            'threat_level': self.anomaly_detector.get_threat_level(),
            'recent_anomalies': [
                {'type': a.anomaly_type.value, 'severity': a.severity, 'time': a.timestamp}
                for a in self.anomaly_detector.get_anomalies(time.time() - 300)
            ],
            'payload_patterns': len(self.packet_analyzer.get_payload_frequency()),
        }
