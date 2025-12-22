# Safety Systems

Overview of built-in safety and protection mechanisms.

---

## Components

### 1. Target Validation

Prevents attacks on unauthorized systems.

**Features:**

- Blocks localhost and private IP ranges
- Blocks known production domains
- Configurable blocklist (`core/safety/blocked_targets.txt`)
- Production service detection

**Blocked by Default:**

- 127.0.0.0/8 (localhost)
- 10.0.0.0/8 (private)
- 172.16.0.0/12 (private)
- 192.168.0.0/16 (private)
- Major cloud providers and tech companies

### 2. Resource Monitoring

Prevents system overload during testing.

**Limits:**

- CPU: 80% maximum
- Memory: 70% maximum
- Network: 1000 Mbps maximum
- Connections: 50,000 maximum
- Packets/sec: 100,000 maximum

**Behavior:**

- Automatic throttling when limits approached
- Warning messages at 70% of limits
- Emergency shutdown at 100%

### 3. Emergency Shutdown

Immediate attack termination.

**Triggers:**

- Ctrl+C (keyboard interrupt)
- Resource limit exceeded
- Target becomes unresponsive
- Manual API call

**Actions:**

- Stop all attack threads
- Close network connections
- Release system resources
- Log shutdown event

### 4. Audit Logging

Complete activity tracking.

**Logged Events:**

- Attack start/stop
- Target information
- Parameters used
- Performance metrics
- Safety violations
- Errors and warnings

**Storage:**

- `audit_logs/audit.db` - SQLite database
- `audit_logs/audit_*.log` - Daily log files
- Encrypted sensitive data

### 5. Environment Detection

Validates testing environment.

**Detects:**

- Virtual machines (VMware, VirtualBox, Hyper-V, KVM)
- Containers (Docker, WSL)
- Cloud environments (AWS, GCP, Azure)
- Sandbox environments

**Purpose:**

- Encourage use in isolated environments
- Warn when running on production systems
- Provide environment-specific recommendations

---

## Configuration

### Enable/Disable Safety

```python
# In code
safety_manager = SafetyManager(enabled=True)

# Via CLI
python ddos.py -i TARGET -p PORT -t PROTO --skip-safety
```

### Modify Resource Limits

```python
from core.safety import ResourceLimits

limits = ResourceLimits(
    max_cpu=80,
    max_memory=70,
    max_network_mbps=1000,
    max_connections=50000,
    max_pps=100000
)
```

### Add Blocked Targets

Edit `core/safety/blocked_targets.txt`:

```
# Add one target per line
example.com
192.168.1.0/24
```

---

## Files

| File                                   | Purpose            |
| -------------------------------------- | ------------------ |
| `core/safety/protection_mechanisms.py` | Main safety logic  |
| `core/safety/emergency_shutdown.py`    | Emergency stop     |
| `core/safety/environment_detection.py` | Environment checks |
| `core/safety/audit_logging.py`         | Audit system       |
| `core/safety/blocked_targets.txt`      | Blocklist          |

---

## Best Practices

1. **Always use safety systems** - Only disable for specific authorized tests
2. **Test in isolated environments** - VMs, containers, or dedicated test networks
3. **Monitor resource usage** - Watch CPU, memory, and network during tests
4. **Review audit logs** - Check logs after each test session
5. **Keep blocklist updated** - Add any systems that shouldn't be tested

---

## Legal Compliance

The safety systems help ensure legal compliance by:

- Preventing accidental attacks on production systems
- Creating audit trails for accountability
- Enforcing resource limits to prevent damage
- Detecting and warning about risky environments

However, users are ultimately responsible for:

- Obtaining proper authorization
- Following applicable laws
- Using the tool ethically

---

**Last Updated**: December 2025
