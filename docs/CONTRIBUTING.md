# Contributing to NetStress

Thank you for your interest in contributing to NetStress! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and considerate
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When reporting a bug, include:

1. **Environment**: OS, Python version, hardware specs
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Logs/Screenshots**: Any relevant output or screenshots

### Suggesting Features

Feature requests are welcome! Please include:

1. **Use Case**: Why is this feature needed?
2. **Proposed Solution**: How should it work?
3. **Alternatives**: Any alternative solutions considered?

### Pull Requests

1. **Fork** the repository
2. **Create a branch** for your feature (`git checkout -b feature/amazing-feature`)
3. **Make your changes** following our coding standards
4. **Write tests** for new functionality
5. **Run the test suite** to ensure nothing is broken
6. **Commit** with clear, descriptive messages
7. **Push** to your fork
8. **Open a Pull Request** with a clear description

## Development Setup

### Prerequisites

- Python 3.10+
- Rust 1.70+ (for native engine)
- Git

### Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/NetStress.git
cd NetStress

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_properties.py -v

# Run with coverage
python -m pytest tests/ --cov=core --cov-report=html
```

## Coding Standards

### Python

- Follow PEP 8 style guide
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use docstrings for all public functions/classes

```python
def calculate_checksum(data: bytes, algorithm: str = "crc32") -> int:
    """
    Calculate checksum for the given data.

    Args:
        data: The data to checksum
        algorithm: Checksum algorithm to use

    Returns:
        The calculated checksum value

    Raises:
        ValueError: If algorithm is not supported
    """
    pass
```

### Rust

- Follow Rust standard style (use `rustfmt`)
- Use `clippy` for linting
- Document public APIs with doc comments

```rust
/// Generates a batch of packets for the specified target.
///
/// # Arguments
///
/// * `target` - The target IP address
/// * `port` - The target port
/// * `count` - Number of packets to generate
///
/// # Returns
///
/// A vector of generated packets
pub fn generate_packets(target: &str, port: u16, count: usize) -> Vec<Packet> {
    // Implementation
}
```

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:

```
feat(engine): add JA4 fingerprint spoofing support

fix(backend): resolve RIO initialization failure on Windows Server 2019

docs(readme): update installation instructions for macOS
```

## Project Structure

```
NetStress/
├── core/                   # Python core modules
│   ├── ai/                 # AI/ML optimization
│   ├── analytics/          # Performance analytics
│   ├── antidetect/         # Evasion techniques
│   ├── attacks/            # Attack implementations
│   ├── distributed/        # P2P coordination
│   ├── hardware/           # Hardware detection
│   ├── platform/           # Platform-specific code
│   └── safety/             # Safety controls
├── native/                 # Native code
│   ├── rust_engine/        # Rust packet engine
│   └── c_driver/           # C hardware drivers
├── tests/                  # Test suite
├── docs/                   # Documentation
├── examples/               # Usage examples
└── scripts/                # Build/install scripts
```

## Testing Guidelines

### Property-Based Tests

We use property-based testing to verify correctness properties. When adding new features:

1. Identify the correctness properties
2. Write property tests using Hypothesis
3. Tag tests with the property number

```python
@given(st.integers(min_value=0, max_value=31))
@settings(max_examples=100)
def test_property_backend_fallback(self, capability_mask):
    """
    **Feature: true-military-grade, Property 1: Backend Fallback Chain Integrity**

    For any platform and hardware configuration, when the preferred backend
    is unavailable, the system SHALL fall back to the next available backend.

    **Validates: Requirements 1.4, 2.4, 3.4**
    """
    # Test implementation
```

### Unit Tests

- Test individual functions/methods in isolation
- Use mocks sparingly and only when necessary
- Aim for high coverage of critical paths

### Integration Tests

- Test component interactions
- Test cross-platform behavior
- Test error handling and recovery

## Documentation

### Code Documentation

- All public APIs must have docstrings
- Include type hints
- Provide usage examples where helpful

### User Documentation

- Update relevant docs when adding features
- Keep examples up to date
- Use clear, concise language

## Review Process

1. All PRs require at least one review
2. CI must pass before merging
3. Documentation must be updated
4. Tests must be included for new features

## Getting Help

- Open an issue for questions
- Join our Discord community
- Check existing documentation

## Recognition

Contributors will be recognized in:

- CHANGELOG.md for significant contributions
- README.md acknowledgments section

Thank you for contributing to NetStress!
