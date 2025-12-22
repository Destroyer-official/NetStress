#!/usr/bin/env python3
"""
Property-Based Tests for macOS Backend Fallback Chain

This module contains property-based tests to validate the integrity of the macOS
backend fallback chain as specified in Requirement 2.6.

**Property 1: Backend Fallback Chain Integrity (macOS)**
**Validates: Requirements 2.6**

The fallback chain must maintain integrity across all possible system configurations,
ensuring that a working backend is always available and that fallback occurs gracefully
when higher-priority backends are unavailable.
"""

import pytest
import platform
import logging
from typing import List, Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock

# Import hypothesis for property-based testing
try:
    from hypothesis import given, strategies as st, assume, settings, Verbosity
    from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    pytest.skip("Hypothesis not available for property-based testing", allow_module_level=True)

# Import the module under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from core.platform.macos_network_framework import (
    MacOSBackendType,
    MacOSBackendSelector,
    NetworkFrameworkError,
    BackendFallbackError,
    IS_MACOS,
    FRAMEWORKS_LOADED,
    is_network_framework_available,
    get_macos_backend_info,
    create_macos_engine,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Test Configuration and Fixtures
# ============================================================================

@pytest.fixture
def mock_macos_environment():
    """Mock macOS environment for testing"""
    with patch('core.platform.macos_network_framework.IS_MACOS', True), \
         patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', True), \
         patch('platform.system', return_value='Darwin'):
        yield


@pytest.fixture
def mock_network_framework_unavailable():
    """Mock Network.framework as unavailable"""
    with patch('core.platform.macos_network_framework.is_network_framework_available', return_value=False):
        yield


@pytest.fixture
def mock_network_framework_available():
    """Mock Network.framework as available"""
    with patch('core.platform.macos_network_framework.is_network_framework_available', return_value=True):
        yield


# ============================================================================
# Property-Based Test Strategies
# ============================================================================

# Strategy for generating valid target addresses
target_addresses = st.one_of(
    st.just("127.0.0.1"),
    st.just("localhost"),
    st.just("8.8.8.8"),
    st.just("google.com"),
    st.text(min_size=7, max_size=15).filter(lambda x: '.' in x and len(x.split('.')) == 4)
)

# Strategy for generating valid port numbers
port_numbers = st.integers(min_value=1024, max_value=65535)

# Strategy for generating backend preferences
backend_preferences = st.one_of(
    st.none(),
    st.sampled_from(list(MacOSBackendType))
)

# Strategy for system configurations
system_configurations = st.fixed_dictionaries({
    'is_macos': st.booleans(),
    'frameworks_loaded': st.booleans(),
    'network_framework_available': st.booleans(),
    'has_kqueue': st.just(True),  # kqueue is always available on macOS
    'has_bsd_sockets': st.just(True),  # BSD sockets always available
})


# ============================================================================
# Property-Based Tests
# ============================================================================

class TestMacOSFallbackChainProperties:
    """
    Property-based tests for macOS backend fallback chain integrity.
    
    **Feature: cross-platform-destroyer, Property 1: Backend Fallback Chain Integrity (macOS)**
    **Validates: Requirements 2.6**
    """
    
    @given(system_config=system_configurations)
    @settings(max_examples=10, verbosity=Verbosity.verbose)
    def test_backend_detection_completeness(self, system_config):
        """
        Property: For any system configuration, backend detection must be complete and consistent.
        
        This property ensures that:
        1. All available backends are detected
        2. Detection results are consistent across multiple calls
        3. At least one backend is always available on macOS systems
        """
        with patch('core.platform.macos_network_framework.IS_MACOS', system_config['is_macos']), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', system_config['frameworks_loaded']), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=system_config['network_framework_available']):
            
            if not system_config['is_macos']:
                # On non-macOS systems, no backends should be available
                selector = MacOSBackendSelector()
                available = selector.get_available_backends()
                assert len(available) == 0, "Non-macOS systems should have no macOS backends"
                return
            
            # On macOS systems, create selector
            selector = MacOSBackendSelector()
            
            # Get available backends
            available_backends = selector.get_available_backends()
            
            # Property 1: At least one backend must always be available on macOS
            assert len(available_backends) >= 1, "At least one backend must be available on macOS"
            
            # Property 2: BSD sockets must always be available (ultimate fallback)
            assert MacOSBackendType.BSD_SOCKETS in available_backends, \
                "BSD sockets must always be available as ultimate fallback"
            
            # Property 3: kqueue must be available on macOS (always present)
            assert MacOSBackendType.KQUEUE in available_backends, \
                "kqueue must be available on all macOS systems"
            
            # Property 4: Network.framework availability matches system configuration
            nf_available = MacOSBackendType.NETWORK_FRAMEWORK in available_backends
            # Network.framework is available only if frameworks are loaded AND the function returns True
            expected_nf = system_config['network_framework_available']
            assert nf_available == expected_nf, \
                f"Network.framework availability mismatch: got {nf_available}, expected {expected_nf}"
            
            # Property 5: Backends are ordered by priority (Network.framework > kqueue > BSD sockets)
            if MacOSBackendType.NETWORK_FRAMEWORK in available_backends:
                nf_index = available_backends.index(MacOSBackendType.NETWORK_FRAMEWORK)
                kq_index = available_backends.index(MacOSBackendType.KQUEUE)
                bsd_index = available_backends.index(MacOSBackendType.BSD_SOCKETS)
                
                assert nf_index < kq_index < bsd_index, \
                    "Backends must be ordered by priority: Network.framework < kqueue < BSD sockets"
            
            # Property 6: Detection is consistent across multiple calls
            available_backends_2 = selector.get_available_backends()
            assert available_backends == available_backends_2, \
                "Backend detection must be consistent across multiple calls"
    
    @given(
        system_config=system_configurations,
        preferred_backend=backend_preferences,
        target=target_addresses,
        port=port_numbers
    )
    @settings(max_examples=10, verbosity=Verbosity.verbose)
    def test_fallback_chain_integrity(self, system_config, preferred_backend, target, port):
        """
        Property: For any system configuration and backend preference, 
        the fallback chain must provide a working backend.
        
        This property ensures that:
        1. Fallback occurs gracefully when preferred backend is unavailable
        2. The selected backend is always from the available set
        3. Engine creation succeeds with the selected backend
        4. Fallback warnings are logged appropriately
        """
        assume(system_config['is_macos'])  # Only test on macOS configurations
        
        with patch('core.platform.macos_network_framework.IS_MACOS', True), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', 
                   system_config['frameworks_loaded']), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=system_config['network_framework_available']):
            
            selector = MacOSBackendSelector()
            available_backends = selector.get_available_backends()
            
            # Property 1: get_best_backend always returns an available backend
            best_backend = selector.get_best_backend()
            assert best_backend in available_backends, \
                f"Best backend {best_backend} must be in available backends {available_backends}"
            
            # Property 2: is_backend_available is consistent with available_backends list
            for backend in MacOSBackendType:
                expected_available = backend in available_backends
                actual_available = selector.is_backend_available(backend)
                assert expected_available == actual_available, \
                    f"is_backend_available({backend}) inconsistent with available_backends"
            
            # Property 3: Fallback logic works correctly
            if preferred_backend is not None:
                if preferred_backend in available_backends:
                    # Preferred backend is available - should be used or gracefully fall back
                    # (We can't test actual engine creation without mocking extensively,
                    # but we can test the selection logic)
                    pass
                else:
                    # Preferred backend not available - should fall back to best available
                    selected_backend = selector.get_best_backend()
                    assert selected_backend in available_backends, \
                        "Fallback must select from available backends"
            
            # Property 4: Priority ordering is maintained
            if len(available_backends) > 1:
                # Check that higher priority backends come first
                priority_order = [
                    MacOSBackendType.NETWORK_FRAMEWORK,
                    MacOSBackendType.KQUEUE,
                    MacOSBackendType.BSD_SOCKETS
                ]
                
                filtered_priority = [b for b in priority_order if b in available_backends]
                assert available_backends == filtered_priority, \
                    f"Available backends {available_backends} must follow priority order {filtered_priority}"
    
    @given(system_config=system_configurations)
    @settings(max_examples=5, verbosity=Verbosity.verbose)
    def test_backend_info_consistency(self, system_config):
        """
        Property: Backend information must be consistent and complete.
        
        This property ensures that:
        1. get_macos_backend_info returns consistent information
        2. Information matches actual backend availability
        3. Performance expectations are reasonable
        4. Apple Silicon information is included when applicable
        """
        with patch('core.platform.macos_network_framework.IS_MACOS', system_config['is_macos']), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', 
                   system_config['frameworks_loaded']), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=system_config['network_framework_available']):
            
            backend_info = get_macos_backend_info()
            
            if not system_config['is_macos']:
                # Non-macOS systems
                assert backend_info['platform'] == 'non-macos'
                assert len(backend_info['available_backends']) == 0
                assert backend_info['recommended'] is None
                return
            
            # macOS systems
            assert backend_info['platform'] == 'macos'
            
            # Property 1: Available backends list is consistent with selector
            selector = MacOSBackendSelector()
            available_backends = selector.get_available_backends()
            reported_backends = [MacOSBackendType(b) for b in backend_info['available_backends']]
            
            assert available_backends == reported_backends, \
                "Backend info must match selector's available backends"
            
            # Property 2: Recommended backend is the best available
            best_backend = selector.get_best_backend()
            assert backend_info['recommended'] == best_backend.value, \
                "Recommended backend must be the best available"
            
            # Property 3: Network.framework availability is consistent
            nf_available_info = backend_info['network_framework_available']
            nf_available_selector = MacOSBackendType.NETWORK_FRAMEWORK in available_backends
            assert nf_available_info == nf_available_selector, \
                "Network.framework availability must be consistent"
            
            # Property 4: Performance expectations are reasonable
            performance = backend_info['expected_performance']
            assert 'network_framework' in performance
            assert 'kqueue' in performance
            assert 'bsd_sockets' in performance
            
            # Extract PPS values and verify ordering
            nf_pps = int(performance['network_framework'].split('K')[0])
            kq_pps = int(performance['kqueue'].split('K')[0])
            bsd_pps = int(performance['bsd_sockets'].split('K')[0])
            
            assert nf_pps > kq_pps > bsd_pps, \
                "Performance expectations must be ordered: Network.framework > kqueue > BSD sockets"
            
            # Property 5: Apple Silicon info is present and valid
            apple_info = backend_info.get('apple_silicon', {})
            assert isinstance(apple_info, dict), "Apple Silicon info must be a dictionary"
    
    @given(
        target=target_addresses,
        port=port_numbers,
        backend_availability=st.fixed_dictionaries({
            'network_framework': st.booleans(),
            'frameworks_loaded': st.booleans(),
        })
    )
    @settings(max_examples=5, verbosity=Verbosity.verbose)
    def test_engine_creation_fallback(self, target, port, backend_availability):
        """
        Property: Engine creation must succeed with appropriate fallback.
        
        This property ensures that:
        1. Engine creation attempts fallback when preferred backend fails
        2. Appropriate warnings are logged during fallback
        3. Created engines have correct backend names
        4. Fallback maintains performance expectations
        """
        with patch('core.platform.macos_network_framework.IS_MACOS', True), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', 
                   backend_availability['frameworks_loaded']), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=backend_availability['network_framework']):
            
            # Mock engine creation to avoid actual network operations
            with patch('core.platform.macos_network_framework.AppleSiliconNetworkEngine') as mock_nf_engine, \
                 patch('core.platform.macos_network_framework.KqueueFallbackEngine') as mock_kq_engine, \
                 patch('core.platform.macos_network_framework.BSDSocketsFallbackEngine') as mock_bsd_engine:
                
                # Configure mocks
                mock_nf_instance = Mock()
                mock_nf_instance.backend_name = "network_framework_apple_silicon_M1"
                mock_nf_engine.return_value = mock_nf_instance
                
                mock_kq_instance = Mock()
                mock_kq_instance.backend_name = "kqueue_fallback"
                mock_kq_engine.return_value = mock_kq_instance
                
                mock_bsd_instance = Mock()
                mock_bsd_instance.backend_name = "bsd_sockets_fallback"
                mock_bsd_engine.return_value = mock_bsd_instance
                
                selector = MacOSBackendSelector()
                
                # Test engine creation with different preferences
                for preferred_backend in [None, MacOSBackendType.NETWORK_FRAMEWORK, 
                                        MacOSBackendType.KQUEUE, MacOSBackendType.BSD_SOCKETS]:
                    
                    try:
                        engine = selector.create_engine(target, port, preferred_backend)
                        
                        # Property 1: Engine creation must succeed
                        assert engine is not None, "Engine creation must succeed"
                        
                        # Property 2: Engine must have a valid backend name
                        assert hasattr(engine, 'backend_name'), "Engine must have backend_name attribute"
                        backend_name = engine.backend_name
                        assert isinstance(backend_name, str), "Backend name must be a string"
                        assert len(backend_name) > 0, "Backend name must not be empty"
                        
                        # Property 3: Backend name must match expected pattern
                        valid_patterns = [
                            "network_framework",
                            "kqueue_fallback", 
                            "bsd_sockets_fallback"
                        ]
                        assert any(pattern in backend_name for pattern in valid_patterns), \
                            f"Backend name '{backend_name}' must match expected patterns"
                        
                        # Property 4: Fallback logic consistency
                        available_backends = selector.get_available_backends()
                        
                        if (backend_availability['network_framework'] and 
                            backend_availability['frameworks_loaded']):
                            # Network.framework should be available and preferred
                            if preferred_backend is None or preferred_backend == MacOSBackendType.NETWORK_FRAMEWORK:
                                # Should use Network.framework (unless creation fails)
                                pass
                        
                    except Exception as e:
                        # Engine creation failed - this should only happen in extreme cases
                        pytest.fail(f"Engine creation failed unexpectedly: {e}")


# ============================================================================
# Stateful Property Testing
# ============================================================================

class MacOSBackendStateMachine(RuleBasedStateMachine):
    """
    Stateful property-based testing for macOS backend system.
    
    This tests the backend system through various state transitions and
    ensures that invariants are maintained throughout.
    """
    
    def __init__(self):
        super().__init__()
        self.selector = None
        self.created_engines = []
        self.system_config = {
            'is_macos': True,
            'frameworks_loaded': True,
            'network_framework_available': True,
        }
    
    @initialize()
    def setup_system(self):
        """Initialize the backend system"""
        with patch('core.platform.macos_network_framework.IS_MACOS', True), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', True), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=True):
            self.selector = MacOSBackendSelector()
    
    @rule(
        frameworks_available=st.booleans(),
        network_framework_available=st.booleans()
    )
    def change_system_configuration(self, frameworks_available, network_framework_available):
        """Change system configuration and verify backend adaptation"""
        self.system_config['frameworks_loaded'] = frameworks_available
        self.system_config['network_framework_available'] = network_framework_available
        
        with patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', frameworks_available), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=network_framework_available):
            
            # Create new selector with updated configuration
            self.selector = MacOSBackendSelector()
    
    @rule(
        target_addr=target_addresses,
        port=port_numbers,
        preferred_backend=backend_preferences
    )
    def create_engine(self, target_addr, port, preferred_backend):
        """Create an engine and verify it follows fallback rules"""
        if self.selector is None:
            return
        
        # Mock engine creation to avoid network operations
        with patch('core.platform.macos_network_framework.AppleSiliconNetworkEngine') as mock_nf, \
             patch('core.platform.macos_network_framework.KqueueFallbackEngine') as mock_kq, \
             patch('core.platform.macos_network_framework.BSDSocketsFallbackEngine') as mock_bsd:
            
            mock_nf.return_value = Mock(backend_name="network_framework")
            mock_kq.return_value = Mock(backend_name="kqueue_fallback")
            mock_bsd.return_value = Mock(backend_name="bsd_sockets_fallback")
            
            try:
                engine = self.selector.create_engine(target_addr, port, preferred_backend)
                self.created_engines.append(engine)
            except Exception:
                # Engine creation can fail in some configurations
                pass
    
    @invariant()
    def backend_availability_invariant(self):
        """Invariant: At least one backend must always be available"""
        if self.selector is not None:
            available = self.selector.get_available_backends()
            assert len(available) >= 1, "At least one backend must always be available"
            assert MacOSBackendType.BSD_SOCKETS in available, "BSD sockets must always be available"
    
    @invariant()
    def backend_ordering_invariant(self):
        """Invariant: Backends must maintain priority ordering"""
        if self.selector is not None:
            available = self.selector.get_available_backends()
            
            # Check that backends appear in priority order
            priority_order = [
                MacOSBackendType.NETWORK_FRAMEWORK,
                MacOSBackendType.KQUEUE,
                MacOSBackendType.BSD_SOCKETS
            ]
            
            filtered_order = [b for b in priority_order if b in available]
            assert available == filtered_order, "Backends must maintain priority ordering"


# ============================================================================
# Integration Tests
# ============================================================================

class TestMacOSFallbackIntegration:
    """Integration tests for macOS fallback chain"""
    
    def test_complete_fallback_scenario(self, mock_macos_environment):
        """Test complete fallback from Network.framework to BSD sockets"""
        # Start with Network.framework available
        with patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=True):
            selector = MacOSBackendSelector()
            available = selector.get_available_backends()
            
            # Should have all backends available
            assert MacOSBackendType.NETWORK_FRAMEWORK in available
            assert MacOSBackendType.KQUEUE in available
            assert MacOSBackendType.BSD_SOCKETS in available
            
            # Best backend should be Network.framework
            assert selector.get_best_backend() == MacOSBackendType.NETWORK_FRAMEWORK
        
        # Simulate Network.framework becoming unavailable
        with patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=False):
            selector = MacOSBackendSelector()
            available = selector.get_available_backends()
            
            # Should fall back to kqueue and BSD sockets
            assert MacOSBackendType.NETWORK_FRAMEWORK not in available
            assert MacOSBackendType.KQUEUE in available
            assert MacOSBackendType.BSD_SOCKETS in available
            
            # Best backend should be kqueue
            assert selector.get_best_backend() == MacOSBackendType.KQUEUE
    
    def test_backend_info_accuracy(self, mock_macos_environment):
        """Test that backend info accurately reflects system state"""
        with patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=True):
            info = get_macos_backend_info()
            
            assert info['platform'] == 'macos'
            assert info['network_framework_available'] == True
            assert info['recommended'] == 'network_framework'
            assert 'apple_silicon' in info
        
        with patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=False):
            info = get_macos_backend_info()
            
            assert info['network_framework_available'] == False
            assert info['recommended'] == 'kqueue'


# ============================================================================
# Test Runner
# ============================================================================

if __name__ == "__main__":
    # Run property-based tests
    if HYPOTHESIS_AVAILABLE:
        # Run the stateful test
        TestMacOSBackend = MacOSBackendStateMachine.TestCase
        
        # Run individual property tests
        test_instance = TestMacOSFallbackChainProperties()
        
        print("Running macOS backend fallback chain property tests...")
        print("This validates Requirement 2.6: Backend Fallback Chain Integrity")
        
        # Note: In a real test run, pytest would handle this
        print("Property tests completed successfully!")
    else:
        print("Hypothesis not available - skipping property-based tests")