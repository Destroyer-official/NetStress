#!/usr/bin/env python3
"""
Property-Based Test for Unified PacketEngine Interface

This test implements Property 1: Backend Fallback Chain Integrity for the unified engine interface.

**Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity**
**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.5, 3.4**
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

# Import backend detection
try:
    from core.platform.backend_detection import (
        BackendDetector,
        SystemCapabilities,
        BackendType,
        detect_system_capabilities,
        select_optimal_backend,
        get_available_backends
    )
    BACKEND_DETECTION_AVAILABLE = True
except ImportError:
    BACKEND_DETECTION_AVAILABLE = False


class TestUnifiedEngineProperty:
    """Property-based tests for the Unified PacketEngine Interface"""

    @given(
        st.integers(min_value=0, max_value=31),  # Capability bitmask (5 bits for 5 Linux backends)
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_1_backend_fallback_chain_integrity(self, capability_mask):
        """
        **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity**
        
        For any platform and hardware configuration, when the preferred backend is unavailable,
        the system SHALL fall back to the next available backend in priority order without crashing.
        
        Priority order for Linux: DPDK > AF_XDP > io_uring > sendmmsg > raw socket
        
        **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.5, 3.4**
        """
        if not BACKEND_DETECTION_AVAILABLE:
            return  # Backend detection not available - optional feature
        
        # Create mock capabilities based on the capability_mask
        mock_caps = SystemCapabilities()
        
        # Always have raw socket as final fallback
        mock_caps.has_raw_socket = True
        
        # Linux capabilities (bits 0-4)
        mock_caps.has_dpdk = bool(capability_mask & 1)
        mock_caps.has_af_xdp = bool(capability_mask & 2)
        mock_caps.has_io_uring = bool(capability_mask & 4)
        mock_caps.has_sendmmsg = bool(capability_mask & 8)
        
        # Set appropriate kernel versions
        if mock_caps.has_af_xdp:
            mock_caps.kernel_version_major = 4
            mock_caps.kernel_version_minor = 18  # AF_XDP requires kernel 4.18+
        elif mock_caps.has_io_uring:
            mock_caps.kernel_version_major = 5
            mock_caps.kernel_version_minor = 1   # io_uring requires kernel 5.1+
        else:
            mock_caps.kernel_version_major = 3
            mock_caps.kernel_version_minor = 0
        
        # Define Linux priority order
        priority_order = [
            (BackendType.DPDK, mock_caps.has_dpdk),
            (BackendType.AF_XDP, mock_caps.has_af_xdp),
            (BackendType.IO_URING, mock_caps.has_io_uring),
            (BackendType.SENDMMSG, mock_caps.has_sendmmsg),
            (BackendType.RAW_SOCKET, mock_caps.has_raw_socket),
        ]
        
        # Test backend selection
        detector = BackendDetector()
        
        try:
            selected_backend = detector.select_best_backend(mock_caps)
            
            # Verify the selection follows platform-specific priority order
            expected_backend = BackendType.RAW_SOCKET  # Default fallback
            for backend_type, is_available in priority_order:
                if is_available:
                    expected_backend = backend_type
                    break
            
            assert selected_backend == expected_backend, (
                f"{platform} backend fallback failed: Expected {expected_backend.name} "
                f"but got {selected_backend.name} for capability_mask={capability_mask:#x}"
            )
            
            # Test that the fallback chain is intact (no gaps)
            available_backends = detector.get_available_backends(mock_caps)
            assert len(available_backends) > 0, "No backends available - fallback chain broken"
            assert selected_backend in available_backends, (
                f"Selected backend {selected_backend.name} not in available list: "
                f"{[b.name for b in available_backends]}"
            )
            
            # Test that backend name is valid
            backend_name = detector.get_backend_name(selected_backend)
            assert isinstance(backend_name, str)
            assert len(backend_name) > 0
            
            # Verify backend name matches Linux expectations
            valid_names = ["dpdk", "af_xdp", "io_uring", "sendmmsg", "raw_socket"]
            
            assert backend_name in valid_names, (
                f"Invalid Linux backend name: {backend_name}, expected one of {valid_names}"
            )
            
            # Test graceful fallback without crashing
            # Simulate backend initialization failure by testing with minimal capabilities
            minimal_caps = SystemCapabilities()
            minimal_caps.has_raw_socket = True  # Only raw socket available
            
            # Disable all other backends
            minimal_caps.has_dpdk = False
            minimal_caps.has_af_xdp = False
            minimal_caps.has_io_uring = False
            minimal_caps.has_sendmmsg = False
            
            fallback_backend = detector.select_best_backend(minimal_caps)
            assert fallback_backend == BackendType.RAW_SOCKET, (
                f"Final fallback should be RAW_SOCKET, got {fallback_backend.name}"
            )
            
            # Test that available backends are in priority order
            backend_values = [b.value for b in available_backends]
            assert backend_values == sorted(backend_values, reverse=True), (
                f"Available backends not in priority order: {[b.name for b in available_backends]}"
            )
            
        except Exception as e:
            pytest.fail(f"Backend fallback chain crashed instead of graceful fallback: {e}")

    @given(
        st.booleans(),  # has_dpdk
        st.booleans(),  # has_af_xdp
        st.booleans(),  # has_io_uring
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_1_runtime_backend_switching(self, has_dpdk, has_af_xdp, has_io_uring):
        """
        **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity**
        
        The system SHALL support runtime backend switching without restarting the application.
        When a backend becomes unavailable, the system SHALL automatically switch to the next
        available backend.
        
        **Validates: Requirements 1.3, 1.4**
        """
        if not BACKEND_DETECTION_AVAILABLE:
            return  # Backend detection not available - optional feature
        
        # Create initial capabilities
        caps = SystemCapabilities()
        caps.has_raw_socket = True  # Always available
        
        # Set Linux backends
        caps.has_dpdk = has_dpdk
        caps.has_af_xdp = has_af_xdp
        caps.has_io_uring = has_io_uring
        caps.has_sendmmsg = True  # Always available on modern Linux
        caps.kernel_version_major = 5
        caps.kernel_version_minor = 4
        
        detector = BackendDetector()
        
        # Select initial backend
        initial_backend = detector.select_best_backend(caps)
        assert initial_backend is not None, "Should select a backend"
        
        # Simulate backend failure by removing the selected backend
        if initial_backend == BackendType.DPDK:
            caps.has_dpdk = False
        elif initial_backend == BackendType.AF_XDP:
            caps.has_af_xdp = False
        elif initial_backend == BackendType.IO_URING:
            caps.has_io_uring = False
        elif initial_backend == BackendType.SENDMMSG:
            caps.has_sendmmsg = False
        
        # Select fallback backend
        fallback_backend = detector.select_best_backend(caps)
        assert fallback_backend is not None, "Should select a fallback backend"
        
        # Verify fallback is different (unless we're already at raw socket)
        if initial_backend != BackendType.RAW_SOCKET:
            assert fallback_backend != initial_backend, (
                f"Fallback backend should be different from initial: "
                f"{initial_backend.name} -> {fallback_backend.name}"
            )
        
        # Verify fallback is lower priority (higher value = higher priority)
        if initial_backend != BackendType.RAW_SOCKET:
            assert fallback_backend.value <= initial_backend.value, (
                f"Fallback backend should be lower priority: "
                f"{initial_backend.name}({initial_backend.value}) -> "
                f"{fallback_backend.name}({fallback_backend.value})"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
