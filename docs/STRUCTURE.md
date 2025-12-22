# Project Structure

Overview of the NetStress codebase organization.

---

## Directory Layout

```
NetStress/
├── core/                   # Framework modules
│   ├── ai/                 # AI/ML optimization
│   ├── analytics/          # Performance analytics
│   ├── autonomous/         # Adaptive systems
│   ├── integration/        # Component coordination
│   ├── interfaces/         # CLI/GUI/API interfaces
│   ├── memory/             # Memory management
│   ├── networking/         # Network operations
│   ├── performance/        # Performance tuning
│   ├── platform/           # Cross-platform support
│   ├── safety/             # Safety systems
│   ├── target/             # Target intelligence
│   └── testing/            # Test utilities
│
├── config/                 # Configuration files
│   ├── production.conf     # Production settings
│   └── development.conf    # Development settings
│
├── docs/                   # Documentation
├── tests/                  # Test suite
├── scripts/                # Utility scripts
├── bin/                    # Entry points
│
├── ddos.py                 # Main attack engine
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── setup.py                # Installation config
└── pyproject.toml          # Build config
```

---

## Core Modules

### Safety (`core/safety/`)

Security and protection systems.

- `protection_mechanisms.py` - Target validation, resource limits
- `emergency_shutdown.py` - Emergency stop functionality
- `environment_detection.py` - Environment validation
- `audit_logging.py` - Activity logging

### Networking (`core/networking/`)

Network operations and attack engines.

- Protocol implementations (TCP, UDP, HTTP, etc.)
- Packet generation and transmission
- Connection management

### AI (`core/ai/`)

Machine learning optimization.

- Parameter optimization
- Adaptive strategies
- Performance prediction

### Analytics (`core/analytics/`)

Performance monitoring and analysis.

- Metrics collection
- Real-time visualization
- Data processing

### Autonomous (`core/autonomous/`)

Self-adaptive systems.

- Real-time adaptation
- Resource management
- Performance optimization

### Interfaces (`core/interfaces/`)

User interfaces.

- CLI interface
- GUI interface
- Web API
- Mobile interface

### Platform (`core/platform/`)

Cross-platform compatibility.

- Platform detection
- OS-specific optimizations
- Capability discovery

### Memory (`core/memory/`)

Memory management.

- Buffer management
- Memory optimization
- Resource allocation

### Performance (`core/performance/`)

Performance tuning.

- Optimization algorithms
- Benchmarking
- Profiling

### Target (`core/target/`)

Target analysis.

- Port scanning
- Service detection
- Vulnerability assessment

### Testing (`core/testing/`)

Test utilities.

- Test frameworks
- Mock objects
- Test helpers

### Integration (`core/integration/`)

Component coordination.

- System integration
- Event handling
- Component communication

---

## Key Files

### Entry Points

| File          | Purpose                               |
| ------------- | ------------------------------------- |
| `ddos.py`     | Main attack engine with all protocols |
| `main.py`     | Application entry point               |
| `bin/ddos.py` | CLI entry point                       |
| `bin/gui.py`  | GUI entry point                       |

### Configuration

| File                      | Purpose              |
| ------------------------- | -------------------- |
| `config/production.conf`  | Production settings  |
| `config/development.conf` | Development settings |
| `requirements.txt`        | Python dependencies  |
| `pyproject.toml`          | Build configuration  |

### Documentation

| File                    | Purpose           |
| ----------------------- | ----------------- |
| `README.md`             | Project overview  |
| `docs/QUICK_START.md`   | Quick setup guide |
| `docs/USAGE.md`         | Usage guide       |
| `docs/API_REFERENCE.md` | API documentation |

---

## Import Structure

### From Application Code

```python
# Import safety systems
from core.safety import SafetyManager, TargetValidator

# Import networking
from core.networking import ProtocolManager

# Import analytics
from core.analytics import MetricsCollector
```

### From Tests

```python
# Import modules for testing
from core.safety.protection_mechanisms import SafetyManager
from core.analytics.metrics_collector import MetricsCollector
```

---

## Configuration

### Environment Selection

```bash
# Use production config
export DESTROYER_ENV=production

# Use development config
export DESTROYER_ENV=development
```

### Config File Format

```ini
[logging]
level = INFO
file = attack.log

[safety]
enabled = true
max_cpu = 80
max_memory = 70

[attack]
default_duration = 60
default_threads = 4
```

---

## Development

### Adding New Features

1. Create module in appropriate `core/` subdirectory
2. Add tests in `tests/`
3. Update documentation in `docs/`
4. Run tests: `pytest`

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings
- Write tests

---

## Dependencies

### Core

- `aiohttp` - Async HTTP
- `scapy` - Packet manipulation
- `numpy` - Numerical computing
- `cryptography` - Encryption

### Optional

- `tensorflow` - Deep learning
- `torch` - PyTorch
- `scikit-learn` - ML algorithms
- `dash` - Dashboards

---

**Last Updated**: December 2025
