"""
Network Detection Module

Detects network interface characteristics including NIC speed, capabilities
(checksum offload, TSO, RSS), and multiple NICs for bonding.

Implements Requirements 11.1: Network detection for adaptive scaling.
"""

import os
import platform
import subprocess
import socket
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class NicSpeed(Enum):
    """Network interface speeds"""
    UNKNOWN = 0
    MBPS_10 = 10
    MBPS_100 = 100
    GBPS_1 = 1000
    GBPS_10 = 10000
    GBPS_25 = 25000
    GBPS_40 = 40000
    GBPS_100 = 100000
    GBPS_200 = 200000
    GBPS_400 = 400000


@dataclass
class NicCapabilities:
    """Network interface capabilities"""
    checksum_offload: bool = False
    tso: bool = False  # TCP Segmentation Offload
    gso: bool = False  # Generic Segmentation Offload
    gro: bool = False  # Generic Receive Offload
    rss: bool = False  # Receive Side Scaling
    lro: bool = False  # Large Receive Offload
    scatter_gather: bool = False
    vlan_offload: bool = False
    jumbo_frames: bool = False
    sr_iov: bool = False  # Single Root I/O Virtualization
    
    def get_offload_score(self) -> int:
        """Calculate offload capability score (0-10)"""
        score = 0
        if self.checksum_offload: score += 1
        if self.tso: score += 2
        if self.gso: score += 1
        if self.gro: score += 1
        if self.rss: score += 2
        if self.lro: score += 1
        if self.scatter_gather: score += 1
        if self.jumbo_frames: score += 1
        return score


@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str
    speed_mbps: int
    speed_enum: NicSpeed
    is_up: bool
    has_link: bool
    mtu: int
    mac_address: str
    ip_addresses: List[str]
    capabilities: NicCapabilities
    driver: str = "Unknown"
    pci_id: str = ""
    numa_node: int = -1
    queue_count: int = 1
    
    @property
    def speed_gbps(self) -> float:
        """Speed in Gbps"""
        return self.speed_mbps / 1000.0
    
    @property
    def is_high_speed(self) -> bool:
        """Whether this is a high-speed interface (>=10Gbps)"""
        return self.speed_mbps >= 10000
    
    @property
    def supports_bonding(self) -> bool:
        """Whether interface supports bonding/teaming"""
        return self.is_up and self.has_link and self.speed_mbps >= 1000


@dataclass
class NetworkInfo:
    """Comprehensive network information"""
    interfaces: List[NetworkInterface]
    total_bandwidth_mbps: int
    fastest_interface: Optional[NetworkInterface]
    bondable_interfaces: List[NetworkInterface]
    has_high_speed_nic: bool
    supports_kernel_bypass: bool = False
    
    @property
    def total_bandwidth_gbps(self) -> float:
        """Total bandwidth in Gbps"""
        return self.total_bandwidth_mbps / 1000.0
    
    @property
    def interface_count(self) -> int:
        """Number of network interfaces"""
        return len(self.interfaces)
    
    @property
    def active_interface_count(self) -> int:
        """Number of active (up and linked) interfaces"""
        return len([iface for iface in self.interfaces if iface.is_up and iface.has_link])


class NetworkDetector:
    """
    Network interface detection and capability analysis.
    
    Provides comprehensive network information for adaptive performance scaling.
    """
    
    @staticmethod
    def get_interface_list() -> List[str]:
        """
        Get list of network interface names.
        
        Returns:
            List of interface names
        """
        interfaces = []
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Read from /sys/class/net
                try:
                    net_path = '/sys/class/net'
                    if os.path.exists(net_path):
                        interfaces = [name for name in os.listdir(net_path) 
                                    if name != 'lo']  # Exclude loopback
                except OSError:
                    logger.debug("Could not read /sys/class/net")
                
                # Fallback: parse /proc/net/dev
                if not interfaces:
                    try:
                        with open('/proc/net/dev', 'r') as f:
                            lines = f.readlines()[2:]  # Skip header lines
                            for line in lines:
                                interface = line.split(':')[0].strip()
                                if interface and interface != 'lo':
                                    interfaces.append(interface)
                    except FileNotFoundError:
                        logger.debug("/proc/net/dev not available")
            
            elif system == "Windows":
                try:
                    result = subprocess.run(
                        ['netsh', 'interface', 'show', 'interface'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')[3:]  # Skip header
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 4 and parts[0] in ['Enabled', 'Disabled']:
                                interface = ' '.join(parts[3:])
                                if interface and 'Loopback' not in interface:
                                    interfaces.append(interface)
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not get interfaces from netsh")
            
            elif system == "Darwin":
                try:
                    result = subprocess.run(
                        ['ifconfig', '-l'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        all_interfaces = result.stdout.strip().split()
                        interfaces = [iface for iface in all_interfaces if iface != 'lo0']
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug("Could not get interfaces from ifconfig")
        
        except Exception as e:
            logger.warning(f"Error getting interface list: {e}")
        
        logger.info(f"Found {len(interfaces)} network interfaces: {interfaces}")
        return interfaces
    
    @staticmethod
    def detect_interface_speed(interface_name: str) -> tuple[int, NicSpeed]:
        """
        Detect interface speed in Mbps.
        
        Args:
            interface_name: Name of the network interface
        
        Returns:
            Tuple of (speed_mbps, speed_enum)
        """
        speed_mbps = 0
        speed_enum = NicSpeed.UNKNOWN
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Try ethtool first (most accurate)
                try:
                    result = subprocess.run(
                        ['ethtool', interface_name],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'Speed:' in line:
                                speed_str = line.split(':')[1].strip()
                                if 'Mb/s' in speed_str:
                                    speed_mbps = int(speed_str.split('Mb/s')[0])
                                elif 'Gb/s' in speed_str:
                                    speed_gbps = float(speed_str.split('Gb/s')[0])
                                    speed_mbps = int(speed_gbps * 1000)
                                break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                    logger.debug(f"ethtool not available for {interface_name}")
                
                # Fallback: check sysfs
                if speed_mbps == 0:
                    try:
                        speed_path = f'/sys/class/net/{interface_name}/speed'
                        with open(speed_path, 'r') as f:
                            speed_mbps = int(f.read().strip())
                    except (FileNotFoundError, ValueError):
                        logger.debug(f"Could not read speed from sysfs for {interface_name}")
            
            elif system == "Windows":
                try:
                    # Use netsh to get interface speed
                    result = subprocess.run(
                        ['netsh', 'interface', 'show', 'interface', f'name="{interface_name}"'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        # Windows netsh doesn't directly show speed, try WMI
                        result = subprocess.run(
                            ['wmic', 'path', 'Win32_NetworkAdapter', 'where', 
                             f'NetConnectionID="{interface_name}"', 'get', 'Speed', '/format:value'],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if line.startswith('Speed=') and line.split('=')[1].strip():
                                    speed_bps = int(line.split('=')[1].strip())
                                    speed_mbps = speed_bps // 1000000
                                    break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug(f"Could not get speed for {interface_name} via WMI")
            
            elif system == "Darwin":
                try:
                    # macOS doesn't easily expose link speed, try system_profiler
                    result = subprocess.run(
                        ['system_profiler', 'SPNetworkDataType'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        # Parse system_profiler output for interface speed
                        # This is complex and interface-name dependent
                        lines = result.stdout.split('\n')
                        in_interface = False
                        for line in lines:
                            if interface_name in line:
                                in_interface = True
                            elif in_interface and 'Speed:' in line:
                                speed_str = line.split(':')[1].strip()
                                if 'Mb/s' in speed_str:
                                    speed_mbps = int(speed_str.split()[0])
                                elif 'Gb/s' in speed_str:
                                    speed_gbps = float(speed_str.split()[0])
                                    speed_mbps = int(speed_gbps * 1000)
                                break
                            elif in_interface and line.strip() == '':
                                break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug(f"Could not get speed for {interface_name} via system_profiler")
            
            # Map speed to enum
            if speed_mbps >= 400000:
                speed_enum = NicSpeed.GBPS_400
            elif speed_mbps >= 200000:
                speed_enum = NicSpeed.GBPS_200
            elif speed_mbps >= 100000:
                speed_enum = NicSpeed.GBPS_100
            elif speed_mbps >= 40000:
                speed_enum = NicSpeed.GBPS_40
            elif speed_mbps >= 25000:
                speed_enum = NicSpeed.GBPS_25
            elif speed_mbps >= 10000:
                speed_enum = NicSpeed.GBPS_10
            elif speed_mbps >= 1000:
                speed_enum = NicSpeed.GBPS_1
            elif speed_mbps >= 100:
                speed_enum = NicSpeed.MBPS_100
            elif speed_mbps >= 10:
                speed_enum = NicSpeed.MBPS_10
        
        except Exception as e:
            logger.warning(f"Error detecting speed for {interface_name}: {e}")
        
        logger.debug(f"Interface {interface_name} speed: {speed_mbps} Mbps")
        return speed_mbps, speed_enum
    
    @staticmethod
    def detect_interface_status(interface_name: str) -> tuple[bool, bool, int]:
        """
        Detect interface status (up/down, link, MTU).
        
        Args:
            interface_name: Name of the network interface
        
        Returns:
            Tuple of (is_up, has_link, mtu)
        """
        is_up = False
        has_link = False
        mtu = 1500  # Default MTU
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Check operstate and carrier
                try:
                    operstate_path = f'/sys/class/net/{interface_name}/operstate'
                    with open(operstate_path, 'r') as f:
                        operstate = f.read().strip()
                        is_up = operstate == 'up'
                    
                    carrier_path = f'/sys/class/net/{interface_name}/carrier'
                    with open(carrier_path, 'r') as f:
                        carrier = f.read().strip()
                        has_link = carrier == '1'
                    
                    mtu_path = f'/sys/class/net/{interface_name}/mtu'
                    with open(mtu_path, 'r') as f:
                        mtu = int(f.read().strip())
                
                except (FileNotFoundError, ValueError):
                    # Fallback: use ifconfig
                    try:
                        result = subprocess.run(
                            ['ifconfig', interface_name],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            output = result.stdout
                            is_up = 'UP' in output and 'RUNNING' in output
                            has_link = 'RUNNING' in output
                            for line in output.split('\n'):
                                if 'mtu' in line.lower():
                                    mtu_match = line.split('mtu')[1].split()[0]
                                    mtu = int(mtu_match)
                                    break
                    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                        logger.debug(f"Could not get status for {interface_name}")
            
            elif system == "Windows":
                try:
                    result = subprocess.run(
                        ['netsh', 'interface', 'show', 'interface', f'name="{interface_name}"'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        output = result.stdout
                        is_up = 'Enabled' in output
                        has_link = 'Connected' in output
                        
                        # Get MTU via netsh
                        result = subprocess.run(
                            ['netsh', 'interface', 'ipv4', 'show', 'subinterfaces'],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if interface_name in line:
                                    parts = line.split()
                                    if len(parts) >= 1 and parts[0].isdigit():
                                        mtu = int(parts[0])
                                    break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug(f"Could not get status for {interface_name}")
            
            elif system == "Darwin":
                try:
                    result = subprocess.run(
                        ['ifconfig', interface_name],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        output = result.stdout
                        is_up = 'UP' in output
                        has_link = 'active' in output
                        for line in output.split('\n'):
                            if 'mtu' in line:
                                mtu_part = line.split('mtu')[1].split()[0]
                                mtu = int(mtu_part)
                                break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
                    logger.debug(f"Could not get status for {interface_name}")
        
        except Exception as e:
            logger.warning(f"Error detecting status for {interface_name}: {e}")
        
        logger.debug(f"Interface {interface_name} status: up={is_up}, link={has_link}, mtu={mtu}")
        return is_up, has_link, mtu
    
    @staticmethod
    def detect_interface_addresses(interface_name: str) -> tuple[str, List[str]]:
        """
        Detect interface MAC and IP addresses.
        
        Args:
            interface_name: Name of the network interface
        
        Returns:
            Tuple of (mac_address, ip_addresses)
        """
        mac_address = ""
        ip_addresses = []
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Get MAC address
                try:
                    mac_path = f'/sys/class/net/{interface_name}/address'
                    with open(mac_path, 'r') as f:
                        mac_address = f.read().strip()
                except FileNotFoundError:
                    pass
                
                # Get IP addresses via ip command
                try:
                    result = subprocess.run(
                        ['ip', 'addr', 'show', interface_name],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'inet ' in line:
                                ip_part = line.split('inet ')[1].split('/')[0]
                                ip_addresses.append(ip_part)
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                    # Fallback to ifconfig
                    try:
                        result = subprocess.run(
                            ['ifconfig', interface_name],
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'inet ' in line:
                                    parts = line.split()
                                    for i, part in enumerate(parts):
                                        if part == 'inet' and i + 1 < len(parts):
                                            ip_addresses.append(parts[i + 1])
                    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                        pass
            
            elif system in ["Windows", "Darwin"]:
                try:
                    result = subprocess.run(
                        ['ifconfig', interface_name] if system == "Darwin" else 
                        ['ipconfig', '/all'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        output = result.stdout
                        in_interface = system == "Darwin"  # Darwin ifconfig shows one interface
                        
                        for line in output.split('\n'):
                            if system == "Windows":
                                if interface_name in line:
                                    in_interface = True
                                elif in_interface and line.strip() == '':
                                    in_interface = False
                            
                            if in_interface:
                                if 'ether' in line or 'Physical Address' in line:
                                    if system == "Darwin":
                                        mac_address = line.split('ether')[1].strip().split()[0]
                                    else:
                                        mac_address = line.split(':')[1].strip()
                                elif 'inet ' in line or 'IPv4 Address' in line:
                                    if system == "Darwin":
                                        ip = line.split('inet')[1].strip().split()[0]
                                        ip_addresses.append(ip)
                                    else:
                                        ip = line.split(':')[1].strip().split('(')[0]
                                        ip_addresses.append(ip)
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    logger.debug(f"Could not get addresses for {interface_name}")
        
        except Exception as e:
            logger.warning(f"Error detecting addresses for {interface_name}: {e}")
        
        logger.debug(f"Interface {interface_name} addresses: MAC={mac_address}, IPs={ip_addresses}")
        return mac_address, ip_addresses
    
    @staticmethod
    def detect_interface_capabilities(interface_name: str) -> NicCapabilities:
        """
        Detect interface offload capabilities.
        
        Args:
            interface_name: Name of the network interface
        
        Returns:
            NicCapabilities object
        """
        capabilities = NicCapabilities()
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Use ethtool to get offload features
                try:
                    result = subprocess.run(
                        ['ethtool', '-k', interface_name],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        output = result.stdout.lower()
                        
                        capabilities.checksum_offload = (
                            'rx-checksumming: on' in output or 
                            'tx-checksumming: on' in output
                        )
                        capabilities.tso = 'tcp-segmentation-offload: on' in output
                        capabilities.gso = 'generic-segmentation-offload: on' in output
                        capabilities.gro = 'generic-receive-offload: on' in output
                        capabilities.lro = 'large-receive-offload: on' in output
                        capabilities.scatter_gather = 'scatter-gather: on' in output
                        capabilities.vlan_offload = (
                            'rx-vlan-offload: on' in output or
                            'tx-vlan-offload: on' in output
                        )
                
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                    logger.debug(f"ethtool not available for {interface_name}")
                
                # Check for RSS (multi-queue)
                try:
                    queues_path = f'/sys/class/net/{interface_name}/queues'
                    if os.path.exists(queues_path):
                        rx_queues = len([d for d in os.listdir(queues_path) 
                                       if d.startswith('rx-')])
                        capabilities.rss = rx_queues > 1
                except OSError:
                    pass
                
                # Check for jumbo frame support (MTU > 1500)
                try:
                    mtu_path = f'/sys/class/net/{interface_name}/mtu'
                    with open(mtu_path, 'r') as f:
                        mtu = int(f.read().strip())
                        capabilities.jumbo_frames = mtu > 1500
                except (FileNotFoundError, ValueError):
                    pass
                
                # Check for SR-IOV
                try:
                    # Look for SR-IOV in device path
                    device_path = f'/sys/class/net/{interface_name}/device'
                    if os.path.exists(device_path):
                        sriov_path = os.path.join(device_path, 'sriov_totalvfs')
                        if os.path.exists(sriov_path):
                            with open(sriov_path, 'r') as f:
                                vfs = int(f.read().strip())
                                capabilities.sr_iov = vfs > 0
                except (FileNotFoundError, ValueError):
                    pass
            
            elif system == "Windows":
                # Windows capability detection is more limited
                # Most modern NICs support basic offloads
                try:
                    result = subprocess.run(
                        ['netsh', 'interface', 'tcp', 'show', 'global'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        output = result.stdout.lower()
                        capabilities.checksum_offload = 'enabled' in output
                        capabilities.tso = True  # Assume modern Windows supports TSO
                        capabilities.rss = 'enabled' in output
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    # Default assumptions for Windows
                    capabilities.checksum_offload = True
                    capabilities.tso = True
            
            elif system == "Darwin":
                # macOS capability detection is limited
                # Modern Macs generally support basic offloads
                capabilities.checksum_offload = True
                capabilities.tso = True
                capabilities.gso = True
                capabilities.gro = True
        
        except Exception as e:
            logger.warning(f"Error detecting capabilities for {interface_name}: {e}")
        
        logger.debug(f"Interface {interface_name} capabilities: "
                    f"checksum={capabilities.checksum_offload}, "
                    f"TSO={capabilities.tso}, RSS={capabilities.rss}")
        
        return capabilities
    
    @staticmethod
    def detect_interface_driver_info(interface_name: str) -> tuple[str, str, int, int]:
        """
        Detect interface driver, PCI ID, NUMA node, and queue count.
        
        Args:
            interface_name: Name of the network interface
        
        Returns:
            Tuple of (driver, pci_id, numa_node, queue_count)
        """
        driver = "Unknown"
        pci_id = ""
        numa_node = -1
        queue_count = 1
        
        try:
            system = platform.system()
            
            if system == "Linux":
                # Get driver info
                try:
                    driver_path = f'/sys/class/net/{interface_name}/device/driver'
                    if os.path.exists(driver_path):
                        driver = os.path.basename(os.readlink(driver_path))
                except OSError:
                    pass
                
                # Get PCI ID
                try:
                    device_path = f'/sys/class/net/{interface_name}/device'
                    if os.path.exists(device_path):
                        # Read PCI vendor and device IDs
                        vendor_path = os.path.join(device_path, 'vendor')
                        device_id_path = os.path.join(device_path, 'device')
                        
                        if os.path.exists(vendor_path) and os.path.exists(device_id_path):
                            with open(vendor_path, 'r') as f:
                                vendor_id = f.read().strip()
                            with open(device_id_path, 'r') as f:
                                device_id = f.read().strip()
                            pci_id = f"{vendor_id}:{device_id}"
                except (FileNotFoundError, OSError):
                    pass
                
                # Get NUMA node
                try:
                    numa_path = f'/sys/class/net/{interface_name}/device/numa_node'
                    with open(numa_path, 'r') as f:
                        numa_node = int(f.read().strip())
                except (FileNotFoundError, ValueError):
                    pass
                
                # Count queues
                try:
                    queues_path = f'/sys/class/net/{interface_name}/queues'
                    if os.path.exists(queues_path):
                        rx_queues = len([d for d in os.listdir(queues_path) 
                                       if d.startswith('rx-')])
                        tx_queues = len([d for d in os.listdir(queues_path) 
                                       if d.startswith('tx-')])
                        queue_count = max(rx_queues, tx_queues)
                except OSError:
                    pass
            
            elif system == "Windows":
                try:
                    # Get driver info via WMI
                    result = subprocess.run(
                        ['wmic', 'path', 'Win32_NetworkAdapter', 'where', 
                         f'NetConnectionID="{interface_name}"', 'get', 
                         'Name,PNPDeviceID', '/format:value'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('Name='):
                                driver = line.split('=', 1)[1].strip()
                            elif line.startswith('PNPDeviceID='):
                                pci_id = line.split('=', 1)[1].strip()
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError, OSError):
                    # wmic command not available or failed
                    pass
            
            elif system == "Darwin":
                try:
                    # Get driver info via system_profiler
                    result = subprocess.run(
                        ['system_profiler', 'SPNetworkDataType'],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        in_interface = False
                        for line in lines:
                            if interface_name in line:
                                in_interface = True
                            elif in_interface and 'Type:' in line:
                                driver = line.split(':')[1].strip()
                                break
                            elif in_interface and line.strip() == '':
                                break
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    pass
        
        except Exception as e:
            logger.warning(f"Error detecting driver info for {interface_name}: {e}")
        
        logger.debug(f"Interface {interface_name} driver info: "
                    f"driver={driver}, PCI={pci_id}, NUMA={numa_node}, queues={queue_count}")
        
        return driver, pci_id, numa_node, queue_count
    
    @classmethod
    def detect_interface_info(cls, interface_name: str) -> NetworkInterface:
        """
        Detect comprehensive information for a single interface.
        
        Args:
            interface_name: Name of the network interface
        
        Returns:
            NetworkInterface object with all detected information
        """
        speed_mbps, speed_enum = cls.detect_interface_speed(interface_name)
        is_up, has_link, mtu = cls.detect_interface_status(interface_name)
        mac_address, ip_addresses = cls.detect_interface_addresses(interface_name)
        capabilities = cls.detect_interface_capabilities(interface_name)
        driver, pci_id, numa_node, queue_count = cls.detect_interface_driver_info(interface_name)
        
        return NetworkInterface(
            name=interface_name,
            speed_mbps=speed_mbps,
            speed_enum=speed_enum,
            is_up=is_up,
            has_link=has_link,
            mtu=mtu,
            mac_address=mac_address,
            ip_addresses=ip_addresses,
            capabilities=capabilities,
            driver=driver,
            pci_id=pci_id,
            numa_node=numa_node,
            queue_count=queue_count
        )
    
    @classmethod
    def detect_network_info(cls) -> NetworkInfo:
        """
        Detect comprehensive network information for all interfaces.
        
        Returns:
            NetworkInfo object with all detected network characteristics
        """
        logger.info("Starting network detection...")
        
        interface_names = cls.get_interface_list()
        interfaces = []
        
        for name in interface_names:
            try:
                interface = cls.detect_interface_info(name)
                interfaces.append(interface)
                logger.info(f"Detected interface {name}: {interface.speed_gbps:.1f}Gbps, "
                           f"up={interface.is_up}, link={interface.has_link}")
            except Exception as e:
                logger.warning(f"Failed to detect interface {name}: {e}")
        
        # Calculate aggregate information
        total_bandwidth_mbps = sum(iface.speed_mbps for iface in interfaces 
                                 if iface.is_up and iface.has_link)
        
        fastest_interface = None
        if interfaces:
            fastest_interface = max(interfaces, key=lambda x: x.speed_mbps)
        
        bondable_interfaces = [iface for iface in interfaces if iface.supports_bonding]
        has_high_speed_nic = any(iface.is_high_speed for iface in interfaces)
        
        # Check for kernel bypass support (Linux-specific)
        supports_kernel_bypass = False
        if platform.system() == "Linux":
            # Check for DPDK or AF_XDP support
            supports_kernel_bypass = any(
                iface.is_high_speed and iface.capabilities.rss 
                for iface in interfaces
            )
        
        network_info = NetworkInfo(
            interfaces=interfaces,
            total_bandwidth_mbps=total_bandwidth_mbps,
            fastest_interface=fastest_interface,
            bondable_interfaces=bondable_interfaces,
            has_high_speed_nic=has_high_speed_nic,
            supports_kernel_bypass=supports_kernel_bypass
        )
        
        logger.info(f"Network detection complete: {len(interfaces)} interfaces, "
                   f"{network_info.total_bandwidth_gbps:.1f}Gbps total, "
                   f"fastest={fastest_interface.speed_gbps:.1f}Gbps" if fastest_interface else "no interfaces")
        
        return network_info