"""
Pytest configuration and shared fixtures for NetStress tests.
"""
import pytest
import sys
import os

# Add the parent directory to the path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sample_target():
    """Provide a safe localhost target for testing."""
    return {
        'host': '127.0.0.1',
        'port': 19999,
        'protocol': 'udp'
    }


@pytest.fixture
def mock_hardware_info():
    """Provide mock hardware information for testing."""
    return {
        'cpu_cores': 4,
        'cpu_threads': 8,
        'ram_gb': 16,
        'nic_speed_mbps': 1000,
        'architecture': 'x86_64',
        'platform': 'windows'
    }


@pytest.fixture
def test_config():
    """Provide a basic test configuration."""
    return {
        'target': '127.0.0.1',
        'port': 19999,
        'protocol': 'udp',
        'threads': 2,
        'duration': 1,
        'packet_size': 64
    }


# Configure pytest markers
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "property: marks tests as property-based tests"
    )
    config.addinivalue_line(
        "markers", "requires_root: marks tests that require root/admin privileges"
    )
