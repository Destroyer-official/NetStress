#!/usr/bin/env python3
"""
Environment Detection and Restrictions
Detects virtual environments and enforces usage restrictions
"""

import os
import sys
import platform
import subprocess
import logging
import socket
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class EnvironmentInfo:
    """Information about the current environment"""
    is_virtual: bool
    virtualization_type: str
    confidence_level: float  # 0.0 to 1.0
    indicators: List[str]
    restrictions: List[str]
    risk_level: str  # 'safe', 'caution', 'danger'

@dataclass
class UsageRestriction:
    """Usage restriction definition"""
    name: str
    description: str
    check_function: callable
    severity: str  # 'warning', 'error', 'critical'
    bypass_code: Optional[str] = None

class EnvironmentDetector:
    """Detects virtual environments and enforces usage restrictions"""
    
    def __init__(self):
        self.detection_methods = []
        self.usage_restrictions = []
        self.legal_warnings_shown = set()
        
        # Initialize detection methods
        self._init_detection_methods()
        
        # Initialize usage restrictions
        self._init_usage_restrictions()
    
    def _init_detection_methods(self):
        """Initialize virtualization detection methods"""
        self.detection_methods = [
            self._detect_vmware,
            self._detect_virtualbox,
            self._detect_hyper_v,
            self._detect_kvm_qemu,
            self._detect_xen,
            self._detect_docker,
            self._detect_wsl,
            self._detect_cloud_providers,
            self._detect_sandbox_environments
        ]
    
    def _init_usage_restrictions(self):
        """Initialize usage restrictions"""
        
        # Production network restriction
        def check_production_network():
            try:
                # Check if connected to corporate/production networks
                hostname = socket.gethostname()
                domain = socket.getfqdn()
                
                production_indicators = [
                    '.corp.', '.company.', '.enterprise.',
                    '.prod.', '.production.', '.live.'
                ]
                
                for indicator in production_indicators:
                    if indicator in domain.lower():
                        return False, f"Connected to production network: {domain}"
                
                return True, "Network check passed"
            except Exception as e:
                return True, f"Network check failed: {e}"
        
        self.usage_restrictions.append(UsageRestriction(
            name="production_network",
            description="Prevent usage on production networks",
            check_function=check_production_network,
            severity="critical"
        ))
        
        # Educational use restriction
        def check_educational_use():
            # Check for educational environment indicators
            educational_paths = [
                '/home/student', '/Users/student',
                'C:\\Users\\student', 'C:\\Student'
            ]
            
            for path in educational_paths:
                if os.path.exists(path):
                    return True, "Educational environment detected"
            
            # Check environment variables
            if os.getenv('EDUCATIONAL_USE') == 'true':
                return True, "Educational use flag set"
            
            return False, "Educational use not confirmed"
        
        self.usage_restrictions.append(UsageRestriction(
            name="educational_use",
            description="Require educational use confirmation",
            check_function=check_educational_use,
            severity="warning",
            bypass_code="EDUCATIONAL_RESEARCH_PURPOSES_ONLY"
        ))
        
        # Time-based restriction
        def check_time_restrictions():
            # Restrict usage during business hours (example)
            current_hour = datetime.now().hour
            if 9 <= current_hour <= 17:  # 9 AM to 5 PM
                return False, "Usage restricted during business hours (9 AM - 5 PM)"
            return True, "Time restriction check passed"
        
        self.usage_restrictions.append(UsageRestriction(
            name="time_based",
            description="Restrict usage during business hours",
            check_function=check_time_restrictions,
            severity="warning",
            bypass_code="AFTER_HOURS_TESTING_APPROVED"
        ))
    
    def detect_environment(self) -> EnvironmentInfo:
        """Detect the current environment"""
        indicators = []
        virtualization_types = []
        confidence_scores = []
        
        # Run all detection methods
        for method in self.detection_methods:
            try:
                result = method()
                if result:
                    virt_type, confidence, method_indicators = result
                    virtualization_types.append(virt_type)
                    confidence_scores.append(confidence)
                    indicators.extend(method_indicators)
            except Exception as e:
                logger.error(f"Detection method error: {e}")
        
        # Determine overall result
        is_virtual = len(virtualization_types) > 0
        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        
        # Determine primary virtualization type
        if virtualization_types:
            # Use the type with highest confidence
            max_idx = confidence_scores.index(max(confidence_scores))
            primary_type = virtualization_types[max_idx]
        else:
            primary_type = "physical"
        
        # Determine risk level
        if is_virtual and overall_confidence > 0.8:
            risk_level = "safe"
        elif is_virtual and overall_confidence > 0.5:
            risk_level = "caution"
        else:
            risk_level = "danger"
        
        # Check usage restrictions
        restrictions = self._check_usage_restrictions()
        
        return EnvironmentInfo(
            is_virtual=is_virtual,
            virtualization_type=primary_type,
            confidence_level=overall_confidence,
            indicators=indicators,
            restrictions=restrictions,
            risk_level=risk_level
        )
    
    def _detect_vmware(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect VMware virtualization"""
        indicators = []
        confidence = 0.0
        
        # Check DMI information
        try:
            if platform.system() == "Linux":
                with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                    vendor = f.read().strip()
                if 'VMware' in vendor:
                    indicators.append("DMI vendor: VMware")
                    confidence += 0.9
            elif platform.system() == "Windows":
                result = subprocess.run(['wmic', 'computersystem', 'get', 'manufacturer'],
                                      capture_output=True, text=True)
                if 'VMware' in result.stdout:
                    indicators.append("WMI manufacturer: VMware")
                    confidence += 0.9
        except Exception:
            pass
        
        # Check for VMware-specific files/devices
        vmware_paths = [
            '/proc/scsi/vmware-vmscsi',
            '/sys/bus/pci/devices/0000:00:0f.0',  # VMware SVGA
            'C:\\Program Files\\VMware\\VMware Tools'
        ]
        
        for path in vmware_paths:
            if os.path.exists(path):
                indicators.append(f"VMware path found: {path}")
                confidence += 0.3
        
        # Check MAC address (VMware OUI)
        try:
            import uuid
            mac = uuid.getnode()
            mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
            if mac_str.startswith('00:0C:29') or mac_str.startswith('00:50:56'):
                indicators.append(f"VMware MAC address: {mac_str}")
                confidence += 0.7
        except Exception:
            pass
        
        if confidence > 0:
            return "VMware", min(confidence, 1.0), indicators
        return None
    
    def _detect_virtualbox(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect VirtualBox virtualization"""
        indicators = []
        confidence = 0.0
        
        # Check DMI information
        try:
            if platform.system() == "Linux":
                with open('/sys/class/dmi/id/product_name', 'r') as f:
                    product = f.read().strip()
                if 'VirtualBox' in product:
                    indicators.append("DMI product: VirtualBox")
                    confidence += 0.9
        except Exception:
            pass
        
        # Check for VirtualBox-specific files
        vbox_paths = [
            '/proc/modules',  # Check for vboxguest module
            'C:\\Program Files\\Oracle\\VirtualBox Guest Additions'
        ]
        
        for path in vbox_paths:
            if os.path.exists(path):
                try:
                    if 'vboxguest' in open(path).read():
                        indicators.append("VirtualBox guest module found")
                        confidence += 0.8
                except Exception:
                    pass
        
        # Check MAC address (VirtualBox OUI)
        try:
            import uuid
            mac = uuid.getnode()
            mac_str = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
            if mac_str.startswith('08:00:27'):
                indicators.append(f"VirtualBox MAC address: {mac_str}")
                confidence += 0.7
        except Exception:
            pass
        
        if confidence > 0:
            return "VirtualBox", min(confidence, 1.0), indicators
        return None
    
    def _detect_hyper_v(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect Hyper-V virtualization"""
        indicators = []
        confidence = 0.0
        
        if platform.system() == "Windows":
            try:
                # Check for Hyper-V services
                result = subprocess.run(['sc', 'query', 'vmicheartbeat'],
                                      capture_output=True, text=True)
                if 'RUNNING' in result.stdout:
                    indicators.append("Hyper-V integration services running")
                    confidence += 0.8
                
                # Check WMI
                result = subprocess.run(['wmic', 'computersystem', 'get', 'model'],
                                      capture_output=True, text=True)
                if 'Virtual Machine' in result.stdout:
                    indicators.append("WMI model: Virtual Machine")
                    confidence += 0.6
            except Exception:
                pass
        
        if confidence > 0:
            return "Hyper-V", min(confidence, 1.0), indicators
        return None
    
    def _detect_kvm_qemu(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect KVM/QEMU virtualization"""
        indicators = []
        confidence = 0.0
        
        # Check CPU info
        try:
            if platform.system() == "Linux":
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                if 'QEMU' in cpuinfo or 'KVM' in cpuinfo:
                    indicators.append("QEMU/KVM detected in CPU info")
                    confidence += 0.8
        except Exception:
            pass
        
        # Check DMI information
        try:
            if platform.system() == "Linux":
                with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                    vendor = f.read().strip()
                if 'QEMU' in vendor:
                    indicators.append("DMI vendor: QEMU")
                    confidence += 0.9
        except Exception:
            pass
        
        if confidence > 0:
            return "KVM/QEMU", min(confidence, 1.0), indicators
        return None
    
    def _detect_xen(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect Xen virtualization"""
        indicators = []
        confidence = 0.0
        
        # Check for Xen-specific files
        xen_paths = [
            '/proc/xen',
            '/sys/hypervisor/type'
        ]
        
        for path in xen_paths:
            if os.path.exists(path):
                try:
                    if 'xen' in open(path).read().lower():
                        indicators.append(f"Xen detected in {path}")
                        confidence += 0.8
                except Exception:
                    pass
        
        if confidence > 0:
            return "Xen", min(confidence, 1.0), indicators
        return None
    
    def _detect_docker(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect Docker container"""
        indicators = []
        confidence = 0.0
        
        # Check for Docker-specific files
        docker_indicators = [
            '/.dockerenv',
            '/proc/1/cgroup'  # Check if running in container
        ]
        
        for path in docker_indicators:
            if os.path.exists(path):
                indicators.append(f"Docker indicator found: {path}")
                confidence += 0.7
                
                # Additional check for cgroup
                if path == '/proc/1/cgroup':
                    try:
                        with open(path, 'r') as f:
                            content = f.read()
                        if 'docker' in content or 'containerd' in content:
                            indicators.append("Docker/containerd in cgroup")
                            confidence += 0.3
                    except Exception:
                        pass
        
        if confidence > 0:
            return "Docker", min(confidence, 1.0), indicators
        return None
    
    def _detect_wsl(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect Windows Subsystem for Linux"""
        indicators = []
        confidence = 0.0
        
        if platform.system() == "Linux":
            # Check for WSL-specific indicators
            wsl_indicators = [
                '/proc/version',  # Contains Microsoft
                '/mnt/c'  # Windows C: drive mount
            ]
            
            for path in wsl_indicators:
                if os.path.exists(path):
                    try:
                        if path == '/proc/version':
                            with open(path, 'r') as f:
                                version = f.read()
                            if 'Microsoft' in version or 'WSL' in version:
                                indicators.append("WSL detected in /proc/version")
                                confidence += 0.9
                        elif path == '/mnt/c':
                            indicators.append("Windows C: drive mounted")
                            confidence += 0.5
                    except Exception:
                        pass
        
        if confidence > 0:
            return "WSL", min(confidence, 1.0), indicators
        return None
    
    def _detect_cloud_providers(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect cloud provider environments"""
        indicators = []
        confidence = 0.0
        
        # Check metadata services (common in cloud environments)
        cloud_metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/',           # GCP
            'http://169.254.169.254/metadata/instance'    # Azure
        ]
        
        for url in cloud_metadata_urls:
            try:
                import urllib.request
                req = urllib.request.Request(url, headers={'Metadata-Flavor': 'Google'})
                response = urllib.request.urlopen(req, timeout=2)
                if response.status == 200:
                    if 'amazonaws' in url:
                        indicators.append("AWS metadata service accessible")
                        confidence += 0.9
                    elif 'google' in url:
                        indicators.append("GCP metadata service accessible")
                        confidence += 0.9
                    elif 'azure' in url:
                        indicators.append("Azure metadata service accessible")
                        confidence += 0.9
            except Exception:
                pass
        
        if confidence > 0:
            return "Cloud", min(confidence, 1.0), indicators
        return None
    
    def _detect_sandbox_environments(self) -> Optional[Tuple[str, float, List[str]]]:
        """Detect sandbox/analysis environments"""
        indicators = []
        confidence = 0.0
        
        # Check for common sandbox indicators
        sandbox_indicators = [
            # File system indicators
            'C:\\analysis',
            'C:\\sandbox',
            '/tmp/analysis',
            
            # Process indicators (would need psutil)
            # 'wireshark', 'tcpdump', 'procmon'
        ]
        
        for indicator in sandbox_indicators:
            if os.path.exists(indicator):
                indicators.append(f"Sandbox indicator: {indicator}")
                confidence += 0.6
        
        # Check for analysis tools
        try:
            import psutil
            analysis_processes = ['wireshark', 'tcpdump', 'procmon', 'ollydbg']
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in analysis_processes:
                    indicators.append(f"Analysis tool running: {proc.info['name']}")
                    confidence += 0.4
        except ImportError:
            pass
        except Exception:
            pass
        
        if confidence > 0:
            return "Sandbox", min(confidence, 1.0), indicators
        return None
    
    def _check_usage_restrictions(self) -> List[str]:
        """Check all usage restrictions"""
        violations = []
        
        for restriction in self.usage_restrictions:
            try:
                passed, message = restriction.check_function()
                if not passed:
                    violations.append(f"{restriction.severity.upper()}: {message}")
                    
                    # Show legal warning if needed
                    if restriction.name not in self.legal_warnings_shown:
                        self._show_legal_warning(restriction)
                        self.legal_warnings_shown.add(restriction.name)
            
            except Exception as e:
                logger.error(f"Error checking restriction {restriction.name}: {e}")
        
        return violations
    
    def _show_legal_warning(self, restriction: UsageRestriction):
        """Show legal warning for restriction violation"""
        warning_text = f"""
        
        ⚠️  LEGAL WARNING - {restriction.name.upper()} ⚠️
        
        {restriction.description}
        
        This tool is intended for:
        - Educational purposes only
        - Authorized penetration testing
        - Security research in controlled environments
        - Testing your own systems and networks
        
        UNAUTHORIZED USE IS ILLEGAL and may violate:
        - Computer Fraud and Abuse Act (CFAA)
        - Local and international cybersecurity laws
        - Terms of service of target systems
        
        By continuing, you acknowledge that you have proper authorization
        and accept full legal responsibility for your actions.
        
        """
        
        print(warning_text)
        logger.warning(f"Legal warning shown for: {restriction.name}")
    
    def bypass_restriction(self, restriction_name: str, bypass_code: str) -> bool:
        """Attempt to bypass a usage restriction with code"""
        for restriction in self.usage_restrictions:
            if restriction.name == restriction_name:
                if restriction.bypass_code and restriction.bypass_code == bypass_code:
                    logger.warning(f"Restriction bypassed: {restriction_name}")
                    return True
                else:
                    logger.error(f"Invalid bypass code for restriction: {restriction_name}")
                    return False
        
        logger.error(f"Unknown restriction: {restriction_name}")
        return False
    
    def get_environment_report(self) -> Dict:
        """Get comprehensive environment report"""
        env_info = self.detect_environment()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            },
            'virtualization': {
                'is_virtual': env_info.is_virtual,
                'type': env_info.virtualization_type,
                'confidence': env_info.confidence_level,
                'indicators': env_info.indicators
            },
            'restrictions': {
                'violations': env_info.restrictions,
                'risk_level': env_info.risk_level
            },
            'safety_status': 'SAFE' if env_info.is_virtual and not env_info.restrictions else 'UNSAFE'
        }
    
    def is_safe_environment(self) -> Tuple[bool, str]:
        """Check if current environment is safe for testing"""
        env_info = self.detect_environment()
        
        # Must be virtual environment
        if not env_info.is_virtual:
            return False, "Not running in virtual environment"
        
        # Must have high confidence in virtualization detection
        if env_info.confidence_level < 0.7:
            return False, f"Low confidence in virtualization detection: {env_info.confidence_level:.2f}"
        
        # Check for critical restrictions
        critical_violations = [r for r in env_info.restrictions if 'CRITICAL:' in r]
        if critical_violations:
            return False, f"Critical restrictions violated: {'; '.join(critical_violations)}"
        
        return True, "Environment is safe for testing"