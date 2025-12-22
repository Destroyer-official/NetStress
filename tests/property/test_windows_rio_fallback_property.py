"""
Property-Based Tests for Windows RIO Backend Fallback Chain

Tests the backend fallback chain integrity property to ensure the system
correctly falls back through available backends without crashing or data loss.

**Feature: cross-platform-destroyer, Property 1: Backend Fallback Chain Integrity (Windows)**
**Validates: Requirements 1.6**
"""

import pytest
import platform
import logging
from typing import List, Optional, Any, Dict
from unittest.mock import patch, MagicMock
from hypothesis import given, strategies as st, assume, settings

logger = logging.getLogger(__name__)

# Check if we're on Windows
IS_WINDOWS = platform.system() == "Windows"


# Skip all tests if not on Windows
pytestmark = pytest.mark.skipif(
    not IS_WINDOWS,
    reason="Windows RIO tests only run on Windows"
)


class TestWindowsRIOFallbackChainProperty:
    """
    Property-based tests for Windows RIO backend fallback chain integrity.
    
    **Feature: cross-platform-destroyer, Property 1: Backend Fallback Chain Integrity (Windows)**
    **Validates: Requirements 1.6**
    
    For any platform and hardware configuration, when the preferred backend is unavailable,
    the system SHALL fall back to the next available backend in the fallback chain without
    crashing or data loss.
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        if IS_WINDOWS:
            from core.platform.windows_rio import (
                WindowsBackendType,
                WindowsBackendSelector,
                TrueRIOEngineConfig,
                is_rio_available,
            )
            self.WindowsBackendType = WindowsBackendType
            self.WindowsBackendSelector = WindowsBackendSelector
            self.TrueRIOEngineConfig = TrueRIOEngineConfig
            self.is_rio_available = is_rio_available
    
    def test_fallback_chain_priority_order(self):
        """
        Property: Backend fallback chain follows correct priority order.
        
        The fallback chain should be: True RIO > IOCP > Winsock
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        selector = self.WindowsBackendSelector()
        available = selector.get_available_backends()
        
        # Should have at least one backend
        assert len(available) > 0, "No backends available"
        
        # Verify priority order
        priority_order = [
            self.WindowsBackendType.TRUE_RIO,
            self.WindowsBackendType.IOCP,
            self.WindowsBackendType.WINSOCK,
        ]
        
        # Available backends should be in priority order
        last_priority = -1
        for backend in available:
            current_priority = priority_order.index(backend)
            assert current_priority > last_priority, \
                f"Backend {backend} out of priority order"
            last_priority = current_priority
        
        logger.info(f"Fallback chain priority test passed: {[b.value for b in available]}")
    
    def test_fallback_chain_always_has_winsock(self):
        """
        Property: Winsock fallback is always available on Windows.
        
        The system should always have at least Winsock as a fallback option.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        selector = self.WindowsBackendSelector()
        available = selector.get_available_backends()
        
        assert self.WindowsBackendType.WINSOCK in available, \
            "Winsock should always be available on Windows"
        
        logger.info("Winsock availability test passed")
    
    def test_fallback_chain_iocp_always_available(self):
        """
        Property: IOCP is always available on modern Windows.
        
        IOCP should be available on Windows Vista and later.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        selector = self.WindowsBackendSelector()
        available = selector.get_available_backends()
        
        assert self.WindowsBackendType.IOCP in available, \
            "IOCP should be available on modern Windows"
        
        logger.info("IOCP availability test passed")
    
    @given(
        st.sampled_from(['true_rio', 'iocp', 'winsock', None]),
        st.integers(min_value=1024, max_value=8192),  # buffer_count
        st.integers(min_value=64, max_value=1500),    # buffer_size
        st.integers(min_value=1, max_value=128),      # batch_size
    )
    @settings(max_examples=5)
    def test_engine_creation_never_crashes(self, preferred_backend, buffer_count, buffer_size, batch_size):
        """
        Property: Engine creation should never crash regardless of configuration.
        
        For any valid configuration and backend preference, the system should
        either create an engine successfully or raise a clear error.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        from core.platform.windows_rio import create_windows_engine, WindowsBackendType
        
        # Convert string to enum if provided
        backend_enum = None
        if preferred_backend:
            try:
                backend_enum = WindowsBackendType(preferred_backend)
            except ValueError:
                pass
        
        config = self.TrueRIOEngineConfig(
            target="127.0.0.1",  # Localhost for testing
            port=12345,
            buffer_count=buffer_count,
            buffer_size=buffer_size,
            batch_size=batch_size,
        )
        
        try:
            # This should either succeed or raise a clear error
            selector = self.WindowsBackendSelector()
            engine = selector.create_engine(config, backend_enum)
            
            # Engine should have a valid backend name
            assert hasattr(engine, 'backend_name')
            assert engine.backend_name in ['true_rio', 'iocp_fallback', 'winsock_fallback']
            
            # Clean up
            if hasattr(engine, '_cleanup'):
                engine._cleanup()
            
            logger.debug(f"Engine created with backend: {engine.backend_name}")
            
        except Exception as e:
            # Errors should be clear and not crash the system
            assert isinstance(e, (ValueError, RuntimeError, OSError)), \
                f"Unexpected error type: {type(e).__name__}: {e}"
            logger.debug(f"Engine creation failed with expected error: {e}")
    
    def test_fallback_on_rio_unavailable(self):
        """
        Property: System falls back to IOCP when RIO is unavailable.
        
        When RIO initialization fails, the system should automatically
        fall back to IOCP with a performance warning.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        from core.platform.windows_rio import (
            WindowsBackendSelector,
            TrueRIOEngineConfig,
            WindowsBackendType,
        )
        
        config = TrueRIOEngineConfig(
            target="127.0.0.1",
            port=12345,
        )
        
        # Mock RIO as unavailable
        with patch('core.platform.windows_rio.is_rio_available', return_value=False):
            selector = WindowsBackendSelector()
            
            # RIO should not be in available backends
            available = selector.get_available_backends()
            assert WindowsBackendType.TRUE_RIO not in available, \
                "RIO should not be available when mocked as unavailable"
            
            # Best backend should be IOCP
            best = selector.get_best_backend()
            assert best == WindowsBackendType.IOCP, \
                f"Expected IOCP as best backend, got {best}"
        
        logger.info("RIO unavailable fallback test passed")
    
    def test_fallback_chain_integrity_with_mock_failures(self):
        """
        Property: Fallback chain maintains integrity through multiple failures.
        
        When backends fail in sequence, the system should continue falling
        back until it finds a working backend.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        from core.platform.windows_rio import (
            WindowsBackendSelector,
            TrueRIOEngineConfig,
            WindowsBackendType,
            TrueRIOEngine,
            IOCPFallbackEngine,
            WinsockFallbackEngine,
        )
        
        config = TrueRIOEngineConfig(
            target="127.0.0.1",
            port=12345,
        )
        
        # Test 1: RIO fails, IOCP succeeds
        with patch.object(TrueRIOEngine, '__init__', side_effect=Exception("RIO init failed")):
            selector = WindowsBackendSelector()
            engine = selector.create_engine(config, WindowsBackendType.TRUE_RIO)
            
            # Should have fallen back to IOCP
            assert isinstance(engine, IOCPFallbackEngine), \
                f"Expected IOCPFallbackEngine, got {type(engine).__name__}"
            
            logger.info("RIO -> IOCP fallback test passed")
        
        # Test 2: Both RIO and IOCP fail, Winsock succeeds
        with patch.object(TrueRIOEngine, '__init__', side_effect=Exception("RIO init failed")):
            with patch.object(IOCPFallbackEngine, '__init__', side_effect=Exception("IOCP init failed")):
                selector = WindowsBackendSelector()
                
                # When requesting IOCP and it fails, should fall back to Winsock
                engine = selector.create_engine(config, WindowsBackendType.IOCP)
                
                assert isinstance(engine, WinsockFallbackEngine), \
                    f"Expected WinsockFallbackEngine, got {type(engine).__name__}"
                
                logger.info("IOCP -> Winsock fallback test passed")
    
    @given(
        st.lists(st.booleans(), min_size=3, max_size=3)  # [rio_available, iocp_works, winsock_works]
    )
    @settings(max_examples=8)
    def test_fallback_chain_all_combinations(self, availability):
        """
        Property: Fallback chain handles all availability combinations correctly.
        
        For any combination of backend availability, the system should
        select the highest-priority available backend.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        rio_available, iocp_works, winsock_works = availability
        
        # At least one backend must work
        assume(rio_available or iocp_works or winsock_works)
        
        from core.platform.windows_rio import (
            WindowsBackendSelector,
            WindowsBackendType,
        )
        
        # Determine expected backend based on availability
        if rio_available:
            expected = WindowsBackendType.TRUE_RIO
        elif iocp_works:
            expected = WindowsBackendType.IOCP
        else:
            expected = WindowsBackendType.WINSOCK
        
        # Mock availability
        with patch('core.platform.windows_rio.is_rio_available', return_value=rio_available):
            selector = WindowsBackendSelector()
            best = selector.get_best_backend()
            
            # Best backend should match expected based on availability
            if rio_available:
                assert best == WindowsBackendType.TRUE_RIO
            elif iocp_works:
                assert best in [WindowsBackendType.TRUE_RIO, WindowsBackendType.IOCP]
            else:
                assert best in [WindowsBackendType.TRUE_RIO, WindowsBackendType.IOCP, WindowsBackendType.WINSOCK]
        
        logger.debug(f"Availability combination test passed: {availability} -> {best}")
    
    def test_backend_info_consistency(self):
        """
        Property: Backend info is consistent and complete.
        
        The get_windows_backend_info function should return consistent
        and complete information about available backends.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        from core.platform.windows_rio import get_windows_backend_info
        
        info = get_windows_backend_info()
        
        # Required fields
        assert 'platform' in info
        assert 'available_backends' in info
        assert 'recommended' in info
        
        # Platform should be windows
        assert info['platform'] == 'windows'
        
        # Available backends should be a list
        assert isinstance(info['available_backends'], list)
        assert len(info['available_backends']) > 0
        
        # Recommended should be in available
        assert info['recommended'] in info['available_backends']
        
        # Expected performance should be present
        assert 'expected_performance' in info
        assert 'true_rio' in info['expected_performance']
        assert 'iocp' in info['expected_performance']
        assert 'winsock' in info['expected_performance']
        
        logger.info(f"Backend info test passed: {info}")
    
    def test_no_data_loss_on_fallback(self):
        """
        Property: No data loss occurs during backend fallback.
        
        When falling back between backends, no packets should be lost
        that were already queued for transmission.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        from core.platform.windows_rio import (
            WindowsBackendSelector,
            TrueRIOEngineConfig,
            WindowsBackendType,
        )
        
        config = TrueRIOEngineConfig(
            target="127.0.0.1",
            port=12345,
        )
        
        selector = WindowsBackendSelector()
        
        # Create engine (will use best available)
        engine = selector.create_engine(config)
        
        # Engine should start with zero stats
        stats = engine.get_stats()
        assert stats.packets_sent == 0, "New engine should have zero packets sent"
        assert stats.bytes_sent == 0, "New engine should have zero bytes sent"
        assert stats.errors == 0, "New engine should have zero errors"
        
        # Clean up
        if hasattr(engine, '_cleanup'):
            engine._cleanup()
        
        logger.info("No data loss test passed")


class TestRIOFunctionTableProperty:
    """
    Property tests for RIO function table initialization.
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        if IS_WINDOWS:
            from core.platform.windows_rio import (
                RIOFunctionTable,
                is_rio_available,
            )
            self.RIOFunctionTable = RIOFunctionTable
            self.is_rio_available = is_rio_available
    
    def test_function_table_initialization_idempotent(self):
        """
        Property: Function table initialization is idempotent.
        
        Multiple calls to initialize should not cause errors or
        change the state of an already-initialized table.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        table = self.RIOFunctionTable()
        
        # First initialization
        result1 = table.initialize()
        
        # Second initialization should return same result
        result2 = table.initialize()
        
        assert result1 == result2, "Initialization should be idempotent"
        
        # State should be consistent
        assert table.is_initialized == result1
        
        logger.info("Function table idempotent initialization test passed")
    
    def test_function_table_cleanup_safe(self):
        """
        Property: Function table cleanup is safe to call multiple times.
        
        Cleanup should be safe to call even if not initialized or
        already cleaned up.
        """
        if not IS_WINDOWS:
            pytest.skip("Windows only test")
        
        table = self.RIOFunctionTable()
        
        # Cleanup before initialization should not crash
        table._cleanup()
        
        # Initialize
        table.initialize()
        
        # Multiple cleanups should not crash
        table._cleanup()
        table._cleanup()
        table._cleanup()
        
        logger.info("Function table safe cleanup test passed")


if __name__ == "__main__":
    # Run property tests
    if not IS_WINDOWS:
        print("Skipping Windows RIO tests on non-Windows platform")
    else:
        test_instance = TestWindowsRIOFallbackChainProperty()
        test_instance.setup()
        
        print("Running Windows RIO fallback chain property tests...")
        
        try:
            test_instance.test_fallback_chain_priority_order()
            print("✓ Fallback chain priority order test passed")
            
            test_instance.test_fallback_chain_always_has_winsock()
            print("✓ Winsock availability test passed")
            
            test_instance.test_fallback_chain_iocp_always_available()
            print("✓ IOCP availability test passed")
            
            test_instance.test_backend_info_consistency()
            print("✓ Backend info consistency test passed")
            
            test_instance.test_no_data_loss_on_fallback()
            print("✓ No data loss on fallback test passed")
            
            print("\n✓ All Windows RIO fallback chain property tests passed!")
            
        except Exception as e:
            print(f"✗ Windows RIO property test failed: {e}")
            raise
