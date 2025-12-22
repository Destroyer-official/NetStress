#!/usr/bin/env python3
"""
Property-Based Tests for macOS Backend Fallback Chain

This module contains property-based tests to validate the integrity of the macOS
backend fallback chain as specified in Requirement 2.6.

**Property 1: Backend Fallback Chain Integrity (macOS)**
**Validates: Requirements 2.6**
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Import hypothesis for property-based testing
try:
    from hypothesis import given, strategies as st, assume, settings, Verbosity
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    print("Hypothesis not available for property-based testing")

from unittest.mock import Mock, patch
from core.platform.macos_network_framework import (
    MacOSBackendType,
    MacOSBackendSelector,
    get_macos_backend_info,
)

def test_backend_fallback_chain_property():
    """
    **Property 1: Backend Fallback Chain Integrity (macOS)**
    **Validates: Requirements 2.6**
    
    For any system configuration, the macOS backend fallback chain must:
    1. Always provide at least one working backend
    2. Maintain priority ordering (Network.framework > kqueue > BSD sockets)
    3. Fall back gracefully when higher-priority backends are unavailable
    """
    
    # Test different system configurations
    test_configs = [
        # Network.framework available
        {'is_macos': True, 'frameworks_loaded': True, 'network_framework_available': True},
        # Network.framework unavailable
        {'is_macos': True, 'frameworks_loaded': True, 'network_framework_available': False},
        # Frameworks not loaded
        {'is_macos': True, 'frameworks_loaded': False, 'network_framework_available': False},
        # Non-macOS system
        {'is_macos': False, 'frameworks_loaded': False, 'network_framework_available': False},
    ]
    
    for config in test_configs:
        with patch('core.platform.macos_network_framework.IS_MACOS', config['is_macos']), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', config['frameworks_loaded']), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=config['network_framework_available']):
            
            if not config['is_macos']:
                # Non-macOS systems should have no backends
                selector = MacOSBackendSelector()
                available = selector.get_available_backends()
                assert len(available) == 0, f"Non-macOS should have no backends, got {available}"
                continue
            
            # macOS systems
            selector = MacOSBackendSelector()
            available_backends = selector.get_available_backends()
            
            # Property 1: At least one backend must always be available on macOS
            assert len(available_backends) >= 1, f"At least one backend required, got {available_backends}"
            
            # Property 2: BSD sockets must always be available (ultimate fallback)
            assert MacOSBackendType.BSD_SOCKETS in available_backends, \
                f"BSD sockets must always be available, got {available_backends}"
            
            # Property 3: kqueue must be available on macOS
            assert MacOSBackendType.KQUEUE in available_backends, \
                f"kqueue must be available on macOS, got {available_backends}"
            
            # Property 4: Network.framework availability matches configuration
            nf_available = MacOSBackendType.NETWORK_FRAMEWORK in available_backends
            expected_nf = config['frameworks_loaded'] and config['network_framework_available']
            assert nf_available == expected_nf, \
                f"Network.framework availability mismatch: got {nf_available}, expected {expected_nf}"
            
            # Property 5: Priority ordering is maintained
            if MacOSBackendType.NETWORK_FRAMEWORK in available_backends:
                nf_index = available_backends.index(MacOSBackendType.NETWORK_FRAMEWORK)
                kq_index = available_backends.index(MacOSBackendType.KQUEUE)
                bsd_index = available_backends.index(MacOSBackendType.BSD_SOCKETS)
                
                assert nf_index < kq_index < bsd_index, \
                    f"Priority order violated: {available_backends}"
            
            # Property 6: Best backend is highest priority available
            best_backend = selector.get_best_backend()
            assert best_backend == available_backends[0], \
                f"Best backend {best_backend} should be first in {available_backends}"
            
            print(f"✓ Config {config}: {len(available_backends)} backends, best: {best_backend.value}")
    
    print("✓ Backend fallback chain integrity property test passed")


def test_backend_info_consistency_property():
    """
    Property: Backend information must be consistent with actual availability.
    """
    
    test_configs = [
        {'is_macos': True, 'frameworks_loaded': True, 'network_framework_available': True},
        {'is_macos': True, 'frameworks_loaded': False, 'network_framework_available': False},
        {'is_macos': False, 'frameworks_loaded': False, 'network_framework_available': False},
    ]
    
    for config in test_configs:
        with patch('core.platform.macos_network_framework.IS_MACOS', config['is_macos']), \
             patch('core.platform.macos_network_framework.FRAMEWORKS_LOADED', config['frameworks_loaded']), \
             patch('core.platform.macos_network_framework.is_network_framework_available', 
                   return_value=config['network_framework_available']):
            
            backend_info = get_macos_backend_info()
            
            if not config['is_macos']:
                assert backend_info['platform'] == 'non-macos'
                assert len(backend_info['available_backends']) == 0
                continue
            
            # macOS systems
            assert backend_info['platform'] == 'macos'
            
            # Consistency with selector
            selector = MacOSBackendSelector()
            available_backends = selector.get_available_backends()
            reported_backends = [MacOSBackendType(b) for b in backend_info['available_backends']]
            
            assert available_backends == reported_backends, \
                f"Backend info inconsistent: selector={available_backends}, info={reported_backends}"
            
            # Best backend consistency
            best_backend = selector.get_best_backend()
            assert backend_info['recommended'] == best_backend.value, \
                f"Recommended backend mismatch: {backend_info['recommended']} vs {best_backend.value}"
            
            print(f"✓ Info consistency for config {config}")
    
    print("✓ Backend info consistency property test passed")


if __name__ == "__main__":
    print("Running macOS backend fallback chain property tests...")
    print("**Property 1: Backend Fallback Chain Integrity (macOS)**")
    print("**Validates: Requirements 2.6**")
    print()
    
    try:
        test_backend_fallback_chain_property()
        test_backend_info_consistency_property()
        
        print()
        print("🎉 All property tests passed!")
        print("✅ macOS backend fallback chain integrity validated")
        
    except Exception as e:
        print(f"❌ Property test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)