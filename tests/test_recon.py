"""
Tests for Reconnaissance Module

Tests for:
- Port scanning
- Service detection
- OS fingerprinting
- Web fingerprinting
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock


class TestPortScanner:
    """Tests for port scanner"""
    
    def test_tcp_scanner_init(self):
        """Test TCP scanner initialization"""
        from core.recon.scanner import TCPScanner, ScanConfig
        
        config = ScanConfig(target='127.0.0.1', ports=[80, 443, 22])
        scanner = TCPScanner(config)
        
        assert scanner.config.target == '127.0.0.1'
        assert len(scanner.config.ports) == 3
        
    def test_udp_scanner_init(self):
        """Test UDP scanner initialization"""
        from core.recon.scanner import UDPScanner, ScanConfig
        
        config = ScanConfig(target='127.0.0.1', ports=[53, 123])
        scanner = UDPScanner(config)
        
        assert scanner.config.target == '127.0.0.1'
        
    def test_udp_probe_dns(self):
        """Test UDP probe for DNS"""
        from core.recon.scanner import UDPScanner, ScanConfig
        
        config = ScanConfig(target='127.0.0.1', ports=[53])
        scanner = UDPScanner(config)
        
        probe = scanner._get_probe(53)
        
        assert len(probe) > 0
        
    def test_syn_scanner_init(self):
        """Test SYN scanner initialization"""
        from core.recon.scanner import SYNScanner, ScanConfig
        
        config = ScanConfig(target='127.0.0.1', ports=[80])
        scanner = SYNScanner(config)
        
        assert scanner.config.target == '127.0.0.1'
        
    def test_service_detector_init(self):
        """Test service detector initialization"""
        from core.recon.scanner import ServiceDetector
        
        detector = ServiceDetector('127.0.0.1', timeout=5.0)
        
        assert detector.target == '127.0.0.1'
        assert detector.timeout == 5.0


class TestFingerprinting:
    """Tests for fingerprinting"""
    
    def test_os_fingerprint_init(self):
        """Test OS fingerprint initialization"""
        from core.recon.fingerprint import OSFingerprint
        
        fp = OSFingerprint('127.0.0.1', timeout=5.0)
        
        assert fp.target == '127.0.0.1'
        assert fp.timeout == 5.0
        
    def test_os_fingerprint_ttl_analysis(self):
        """Test OS fingerprint TTL analysis"""
        from core.recon.fingerprint import OSFingerprint, OSType
        
        fp = OSFingerprint('127.0.0.1')
        
        # Test TTL analysis
        results = {'ttl': 64, 'window': None, 'os_hints': []}
        os_type, confidence = fp._analyze_results(results)
        
        assert os_type in [OSType.LINUX, OSType.MACOS]
        
    def test_web_fingerprint_init(self):
        """Test web fingerprint initialization"""
        from core.recon.fingerprint import WebFingerprint
        
        fp = WebFingerprint('example.com', port=80, ssl=False)
        
        assert fp.target == 'example.com'
        assert fp.port == 80
        assert fp.use_ssl == False
        
    def test_web_fingerprint_framework_detection(self):
        """Test web framework detection"""
        from core.recon.fingerprint import WebFingerprint
        
        fp = WebFingerprint('example.com')
        
        # Test Django detection
        headers = {}
        body = '<input name="csrfmiddlewaretoken" value="test">'
        
        framework = fp._detect_framework(headers, body)
        
        assert framework == 'django'
        
    def test_web_fingerprint_cms_detection(self):
        """Test CMS detection"""
        from core.recon.fingerprint import WebFingerprint
        
        fp = WebFingerprint('example.com')
        
        # Test WordPress detection
        body = '<link rel="stylesheet" href="/wp-content/themes/test/style.css">'
        
        cms = fp._detect_cms(body)
        
        assert cms == 'wordpress'
        
    def test_tls_fingerprint_init(self):
        """Test TLS fingerprint initialization"""
        from core.recon.fingerprint import TLSFingerprint
        
        fp = TLSFingerprint('example.com', port=443)
        
        assert fp.target == 'example.com'
        assert fp.port == 443
        
    def test_http_fingerprint_init(self):
        """Test HTTP fingerprint initialization"""
        from core.recon.fingerprint import HTTPFingerprint
        
        fp = HTTPFingerprint('example.com', port=80, ssl=False)
        
        assert fp.target == 'example.com'
        
    def test_service_fingerprint_banner_parsing(self):
        """Test service banner parsing"""
        from core.recon.fingerprint import ServiceFingerprint
        
        fp = ServiceFingerprint('127.0.0.1')
        
        # Test SSH banner
        service, version = fp._parse_banner('SSH-2.0-OpenSSH_8.0')
        assert service == 'ssh'
        
        # Test FTP banner
        service, version = fp._parse_banner('220 FTP Server Ready')
        assert service == 'ftp'


class TestAnalyzer:
    """Tests for target analyzer"""
    
    def test_host_discovery_init(self):
        """Test host discovery initialization"""
        from core.recon.analyzer import HostDiscovery
        
        discovery = HostDiscovery(timeout=2.0, max_concurrent=50)
        
        assert discovery.timeout == 2.0
        assert discovery.max_concurrent == 50
        
    def test_network_mapper_init(self):
        """Test network mapper initialization"""
        from core.recon.analyzer import NetworkMapper
        
        mapper = NetworkMapper(timeout=5.0)
        
        assert mapper.timeout == 5.0
        
    def test_vulnerability_scanner_init(self):
        """Test vulnerability scanner initialization"""
        from core.recon.analyzer import VulnerabilityScanner
        
        scanner = VulnerabilityScanner('127.0.0.1', timeout=5.0)
        
        assert scanner.target == '127.0.0.1'
        assert scanner.timeout == 5.0
        
    def test_target_analyzer_init(self):
        """Test target analyzer initialization"""
        from core.recon.analyzer import TargetAnalyzer
        
        analyzer = TargetAnalyzer('example.com')
        
        assert analyzer.target == 'example.com'
