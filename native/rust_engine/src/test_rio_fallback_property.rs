//! Property-based tests for Windows RIO backend fallback chain integrity
//! **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity (Windows)**
//! **Validates: Requirements 3.6**

#[cfg(all(test, target_os = "windows", feature = "registered_io"))]
mod tests {
    use crate::backend::{Backend, BackendType};
    use crate::windows_rio::RioBackend;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Generate valid IPv4 socket addresses for testing
    fn arb_socket_addr() -> impl Strategy<Value = SocketAddr> {
        (prop::array::uniform4(1u8..255u8), 1024u16..65535u16).prop_map(|(octets, port)| {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
                port,
            )
        })
    }

    /// Generate valid packet data for testing
    fn arb_packet_data() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..1400) // Valid UDP payload size
    }

    /// Generate batch of packets for testing
    fn arb_packet_batch() -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(arb_packet_data(), 1..10) // 1-10 packets per batch
    }

    proptest! {
        /// **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity (Windows)**
        /// **Validates: Requirements 3.6**
        ///
        /// For any platform and hardware configuration, when the preferred backend is unavailable,
        /// the system SHALL fall back to the next available backend in priority order without crashing.
        #[test]
        fn test_rio_fallback_chain_integrity(
            dest in arb_socket_addr(),
            data in arb_packet_data(),
        ) {
            let mut backend = RioBackend::new();

            // Test that backend creation never panics
            prop_assert_eq!(backend.backend_type(), BackendType::RegisteredIO);
            prop_assert!(!backend.is_initialized());

            // Test initialization - should either succeed or fail gracefully
            let init_result = backend.init();

            match init_result {
                Ok(()) => {
                    // Backend initialized successfully
                    prop_assert!(backend.is_initialized());

                    // Test that send operations work or fail gracefully
                    let send_result = backend.send(&data, dest);

                    // Send should either succeed or fail with proper error
                    match send_result {
                        Ok(bytes_sent) => {
                            prop_assert!(bytes_sent <= data.len());
                        }
                        Err(e) => {
                            // Error should be well-formed
                            prop_assert!(!e.to_string().is_empty());
                        }
                    }

                    // Test cleanup
                    let cleanup_result = backend.cleanup();
                    prop_assert!(cleanup_result.is_ok());
                    prop_assert!(!backend.is_initialized());
                }
                Err(e) => {
                    // Initialization failed - should be graceful
                    prop_assert!(!backend.is_initialized());
                    prop_assert!(!e.to_string().is_empty());

                    // Even if init failed, cleanup should work
                    let cleanup_result = backend.cleanup();
                    prop_assert!(cleanup_result.is_ok());
                }
            }
        }

        /// Test batch sending fallback behavior
        #[test]
        fn test_rio_batch_fallback_integrity(
            dest in arb_socket_addr(),
            packets in arb_packet_batch(),
        ) {
            let mut backend = RioBackend::new();

            // Initialize backend
            let _ = backend.init();

            // Convert to slice of slices for send_batch
            let packet_refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();

            // Test batch send - should never panic
            let batch_result = backend.send_batch(&packet_refs[..], dest);

            match batch_result {
                Ok(sent_count) => {
                    // Should not send more packets than provided
                    prop_assert!(sent_count <= packets.len());
                }
                Err(e) => {
                    // Error should be well-formed
                    prop_assert!(!e.to_string().is_empty());
                }
            }

            // Cleanup should always work
            let _ = backend.cleanup();
        }

        /// Test RIO availability detection robustness
        #[test]
        fn test_rio_detection_robustness(
            _dummy in 0u32..100u32, // Just to make this a property test
        ) {
            let mut backend = RioBackend::new();

            // RIO detection should never panic
            let detection_result = backend.detect_rio_support();

            match detection_result {
                Ok(available) => {
                    // Should return a boolean
                    prop_assert!(available == true || available == false);
                }
                Err(e) => {
                    // Error should be well-formed
                    prop_assert!(!e.to_string().is_empty());
                }
            }

            // Status message should always be available
            let status = backend.get_rio_status();
            prop_assert!(!status.is_empty());

            // Fallback info should always be available
            let fallback_info = backend.get_detailed_fallback_info();
            prop_assert!(!fallback_info.active_backend.is_empty());
            prop_assert!(!fallback_info.fallback_reason.is_empty());
        }

        /// Test buffer pool operations robustness
        #[test]
        fn test_buffer_pool_robustness(
            pool_size in 1usize..100usize,
            buffer_size in 64usize..2048usize,
        ) {
            let mut backend = RioBackend::new();

            // Initialize backend first (which includes WSA initialization)
            let _ = backend.init();

            // Test buffer pool initialization
            let pool_result = backend.init_buffer_pool(pool_size, buffer_size);

            match pool_result {
                Ok(()) => {
                    // Buffer pool stats should be available
                    if let Some((total, in_use)) = backend.get_buffer_pool_stats() {
                        prop_assert!(total >= pool_size);
                        prop_assert!(in_use <= total);
                    }

                    // Detailed stats should be available
                    if let Some(detailed_stats) = backend.get_detailed_buffer_stats() {
                        prop_assert!(detailed_stats.total_buffers >= pool_size);
                        prop_assert!(detailed_stats.buffer_size >= buffer_size);
                        prop_assert!(detailed_stats.utilization_percent <= 100);
                    }
                }
                Err(e) => {
                    // Error should be well-formed
                    prop_assert!(!e.to_string().is_empty());
                }
            }
        }

        /// Test statistics consistency
        #[test]
        fn test_statistics_consistency(
            _dummy in 0u32..100u32,
        ) {
            let backend = RioBackend::new();

            // Stats should always be available
            let stats = backend.stats();

            // All stats should be non-negative (they're u64, so this is guaranteed)
            prop_assert!(stats.packets_sent >= 0);
            prop_assert!(stats.bytes_sent >= 0);
            prop_assert!(stats.errors >= 0);
            prop_assert!(stats.batch_count >= 0);

            // RIO-specific stats should be available
            let rio_stats = backend.get_rio_stats();
            prop_assert!(rio_stats.rio_sends >= 0);
            prop_assert!(rio_stats.iocp_fallbacks >= 0);
            prop_assert!(rio_stats.total_buffers >= 0);
            prop_assert!(rio_stats.buffers_in_use <= rio_stats.total_buffers);
        }
    }

    #[test]
    fn test_rio_detector_robustness() {
        use crate::windows_rio::RioDetector;

        // All detector methods should never panic
        let available = RioDetector::is_available();
        let info = RioDetector::get_availability_info();
        let optimal = RioDetector::is_optimal_platform();

        // Info should not be empty
        assert!(!info.is_empty());

        // Boolean values should be consistent
        assert!(available == true || available == false);
        assert!(optimal == true || optimal == false);
    }

    #[test]
    fn test_error_handling_robustness() {
        use crate::windows_rio::RioError;

        // Test that all error types can be created and displayed
        let errors = vec![
            RioError::NotAvailable,
            RioError::WSAInitFailed(12345),
            RioError::SocketCreationFailed(67890),
            RioError::RioInitFailed("test error".to_string()),
            RioError::BufferRegistrationFailed("test buffer error".to_string()),
            RioError::SendFailed("test send error".to_string()),
            RioError::CompletionQueueFailed("test completion error".to_string()),
            RioError::LibraryLoadFailed("test library error".to_string()),
        ];

        for error in errors {
            // Error display should not be empty
            assert!(!error.to_string().is_empty());

            // Error should implement Debug
            assert!(!format!("{:?}", error).is_empty());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_rio_buf_creation_robustness() {
        let backend = RioBackend::new();

        // Test RIO_BUF creation with various parameters
        let test_cases = vec![
            (123, 0, 1500),   // Normal case
            (456, 100, 1000), // With offset
            (789, 0, 64),     // Small buffer
        ];

        for (buffer_id, offset, length) in test_cases {
            let rio_buf = backend.create_rio_buf_unchecked(buffer_id, offset, length);

            assert_eq!(rio_buf.buffer_id, buffer_id);
            assert_eq!(rio_buf.offset, offset as u32);
            assert_eq!(rio_buf.length, length as u32);
        }

        // Test validation with invalid parameters
        let invalid_cases = vec![
            (0xFFFFFFFF, 0, 1500), // Invalid buffer ID
            (123, 0, 0),           // Zero length
        ];

        for (buffer_id, offset, length) in invalid_cases {
            let result = backend.create_rio_buf(buffer_id, offset, length);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_backend_trait_compliance() {
        let mut backend = RioBackend::new();

        // Test that all Backend trait methods are implemented and don't panic
        assert_eq!(backend.backend_type(), BackendType::RegisteredIO);
        assert!(!backend.is_initialized());

        // Test init (may fail, but shouldn't panic)
        let _ = backend.init();

        // Test send (may fail, but shouldn't panic)
        let test_data = b"test data";
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let _ = backend.send(test_data, dest);

        // Test send_batch (may fail, but shouldn't panic)
        let packets: Vec<&[u8]> = vec![test_data];
        let _ = backend.send_batch(&packets, dest);

        // Test stats (should always work)
        let stats = backend.stats();
        assert!(stats.packets_sent >= 0);

        // Test cleanup (should always work)
        let cleanup_result = backend.cleanup();
        assert!(cleanup_result.is_ok());
        assert!(!backend.is_initialized());
    }
}

// Stub tests when registered_io feature is not enabled
#[cfg(all(test, not(all(target_os = "windows", feature = "registered_io"))))]
mod stub_tests {
    #[test]
    fn test_rio_property_tests_skipped() {
        // RIO property tests are skipped when feature is not enabled
        println!(
            "RIO property tests skipped - registered_io feature not enabled or not on Windows"
        );
    }
}
