# Layer 4 Attack Vectors

This document describes the Layer 4 (Transport Layer) attack vectors implemented in NetStress Titanium v3.0.

## Overview

The Layer 4 attack module provides comprehensive transport layer attack capabilities including:

- **UDP Flood**: High-volume UDP packet flooding with configurable payloads
- **TCP Flag Attacks**: Various TCP flag-based attacks (SYN, ACK, RST, FIN, etc.)
- **ICMP Flood**: ICMP-based attacks with multiple message types
- **Connection Exhaustion**: TCP connection-based resource exhaustion

## Features

### Core Capabilities

- **Configurable Payloads**: Multiple payload patterns (random, zeros, ones, sequence, custom)
- **IP Spoofing**: Source IP address spoofing for enhanced evasion (requires raw sockets)
- **High Performance**: Multi-threaded implementation with rate limiting
- **Real Packets**: All attacks send genuine network packets (no simulation)
- **Cross-Platform**: Works on Windows, Linux, and macOS with platform-specific optimizations

### Advanced Features

- **Packet Fragmentation**: ICMP packet fragmentation for evasion
- **Raw Socket Support**: Enhanced capabilities when running with elevated privileges
- **Attack Profiles**: Pre-configured attack profiles for common scenarios
- **Statistics Tracking**: Comprehensive attack statistics and performance metrics

## Attack Types

### 1. UDP Flood

Sends high-volume UDP packets to overwhelm target resources.

```python
from core.attacks.layer4 import create_udp_flood

# Basic UDP flood
attack = create_udp_flood(
    target='192.168.1.100',
    port=80,
    duration=30,
    payload_size=1024,
    payload_pattern='random',
    rate_limit=10000
)

await attack.start()
```

**Profiles Available:**

- `udp_basic`: Standard UDP flood (1024 bytes, 10K PPS)
- `udp_amplification`: Large payload flood (8192 bytes, 5K PPS, spoofed)

### 2. TCP Flag Attacks

Various TCP flag-based attacks for different purposes.

#### SYN Flood

```python
from core.attacks.layer4 import create_syn_flood

attack = create_syn_flood(
    target='192.168.1.100',
    port=80,
    duration=30,
    rate_limit=20000,
    spoof_source=True
)
```

#### Other TCP Flag Attacks

- **ACK Flood**: `create_ack_flood()` - Confuse stateful firewalls
- **RST Flood**: `create_rst_flood()` - Disrupt existing connections
- **FIN Flood**: `create_fin_flood()` - Stealth connection termination
- **XMAS Flood**: `create_xmas_flood()` - FIN+PSH+URG flags (evasion)
- **NULL Flood**: `create_null_flood()` - No flags set (firewall bypass)
- **PUSH-ACK Flood**: `create_push_ack_flood()` - Legitimate-looking traffic

**Profiles Available:**

- `syn_flood_basic`: Standard SYN flood (20K PPS)
- `syn_flood_spoofed`: Spoofed SYN flood (15K PPS, IP range spoofing)
- `ack_flood_basic`: ACK flood (25K PPS)
- `rst_flood_disruption`: RST flood with spoofing (30K PPS)

### 3. ICMP Flood

ICMP-based attacks with various message types.

```python
from core.attacks.layer4 import create_ping_flood, create_icmp_unreachable_flood

# ICMP Echo Request flood
ping_attack = create_ping_flood(
    target='192.168.1.100',
    duration=30,
    payload_size=1500,
    rate_limit=8000
)

# ICMP Destination Unreachable flood
unreachable_attack = create_icmp_unreachable_flood(
    target='192.168.1.100',
    unreachable_code='HOST_UNREACHABLE',
    duration=30
)
```

**ICMP Types Supported:**

- Echo Request/Reply (ping)
- Destination Unreachable (various codes)
- Source Quench
- Redirect
- Time Exceeded
- Timestamp Request/Reply
- Information Request/Reply
- Address Mask Request/Reply
- Router Advertisement/Solicitation

**Profiles Available:**

- `icmp_ping_flood`: Standard ping flood (1500 bytes, 8K PPS)
- `icmp_fragmented`: Fragmented ICMP (4096 bytes, fragmented)
- `icmp_timestamp_flood`: Timestamp request flood
- `icmp_unreachable_flood`: Destination unreachable flood
- `icmp_smurf_amplification`: Smurf attack pattern

### 4. Connection Exhaustion

TCP connection-based resource exhaustion.

```python
from core.attacks.layer4 import create_connection_exhaustion

attack = create_connection_exhaustion(
    target='192.168.1.100',
    port=80,
    duration=60,
    hold_time=30.0,
    max_connections=1000,
    threads=10
)
```

## Configuration Options

### Layer4Config Parameters

- `target`: Target IP address or hostname
- `port`: Target port number
- `duration`: Attack duration in seconds
- `rate_limit`: Maximum packets per second
- `threads`: Number of worker threads
- `payload_size`: Payload size in bytes
- `payload_pattern`: Payload pattern ('random', 'zeros', 'ones', 'sequence', 'custom')
- `custom_payload`: Custom payload bytes (when pattern='custom')
- `spoof_source`: Enable IP spoofing (requires raw sockets)
- `source_ip_range`: IP range for spoofing ('start_ip', 'end_ip')
- `source_port_range`: Source port range (start, end)
- `fragment_packets`: Enable packet fragmentation (ICMP only)
- `fragment_size`: Fragment size in bytes

### Payload Patterns

- **random**: Random bytes
- **zeros**: All zero bytes (0x00)
- **ones**: All one bytes (0xFF)
- **sequence**: Sequential bytes (0, 1, 2, ...)
- **custom**: User-provided payload pattern

## Usage Examples

### Basic Usage

```python
import asyncio
from core.attacks.layer4 import create_udp_flood

async def main():
    # Create UDP flood attack
    attack = create_udp_flood(
        target='127.0.0.1',
        port=80,
        duration=10,
        payload_size=1024,
        rate_limit=5000
    )

    # Start attack
    await attack.start()

    # Get statistics
    stats = attack.get_stats()
    print(f"Packets sent: {stats['packets_sent']}")
    print(f"Rate: {stats['pps']:.1f} PPS")

asyncio.run(main())
```

### Using Attack Profiles

```python
from core.attacks.layer4 import create_syn_flood, get_attack_profile

# Get profile configuration
profile_config = get_attack_profile('syn_flood_spoofed')

# Create attack with profile
attack = create_syn_flood(
    target='192.168.1.100',
    port=80,
    duration=30,
    **profile_config
)
```

### Command Line Demo

```bash
# List available profiles
python examples/layer4_attack_demo.py --list-profiles

# Run UDP flood
python examples/layer4_attack_demo.py --target 127.0.0.1 --attack udp_flood --duration 10

# Run SYN flood
python examples/layer4_attack_demo.py --target 127.0.0.1 --attack syn_flood --port 80

# Run all attacks demo
python examples/layer4_attack_demo.py --target 127.0.0.1 --attack demo_all
```

## Requirements and Limitations

### System Requirements

- Python 3.8+
- Optional: Scapy library for advanced packet crafting
- Optional: Raw socket support (requires root/administrator privileges)

### Platform Support

- **Windows**: Standard sockets (limited spoofing)
- **Linux**: Full raw socket support with root privileges
- **macOS**: Full raw socket support with root privileges

### Limitations

- IP spoofing requires raw sockets (root/administrator privileges)
- Some advanced features require Scapy library
- Rate limits may be constrained by system resources
- Firewall/antivirus software may interfere with operation

## Security Considerations

### Legal and Ethical Use

- Only use against systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Consider impact on network infrastructure
- Use responsibly for legitimate security testing

### Detection and Mitigation

These attacks can be detected and mitigated by:

- Network intrusion detection systems (IDS)
- Rate limiting and traffic shaping
- Stateful firewalls
- DDoS protection services
- Network monitoring tools

## Performance Optimization

### High Performance Tips

1. **Use Raw Sockets**: Enable IP spoofing for maximum performance
2. **Tune Thread Count**: Adjust threads based on CPU cores
3. **Optimize Rate Limits**: Balance between speed and system stability
4. **Use Appropriate Payload Sizes**: Larger payloads = more bandwidth usage
5. **Consider Network Capacity**: Don't exceed available bandwidth

### Monitoring Performance

```python
# Get real-time statistics
stats = attack.get_stats()
print(f"PPS: {stats['pps']:.1f}")
print(f"Mbps: {stats['mbps']:.2f}")
print(f"Errors: {stats['errors']}")
```

## Integration with NetStress

The Layer 4 attacks integrate seamlessly with the broader NetStress framework:

- **Attack Orchestration**: Can be combined with other attack vectors
- **Distributed Attacks**: Support for P2P mesh coordination
- **Adaptive Control**: Integration with RL-based parameter optimization
- **Reporting**: Comprehensive statistics and logging
- **Safety Systems**: Built-in safety checks and rate limiting

## Troubleshooting

### Common Issues

1. **Permission Denied**: Raw sockets require root/administrator privileges
2. **High Error Rate**: Reduce rate limit or check network connectivity
3. **Low Performance**: Increase thread count or optimize system settings
4. **Scapy Import Error**: Install scapy library for advanced features

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

Planned improvements for Layer 4 attacks:

- GPU-accelerated packet generation
- Hardware timestamping support
- Advanced evasion techniques
- Protocol-specific optimizations
- Enhanced statistics and reporting
