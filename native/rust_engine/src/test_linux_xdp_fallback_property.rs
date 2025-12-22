//! Property-based tests for Linux XDP backend fallback chain
//!
//! **Task 3.5: Write property test for Linux backend**
//! **Property 1: Backend Fallback Chain Integrity (Linux)**
//! **Validates: Requirements 2.5, 3.4**

#[cfg(all(test, target_os = "linux", feature = "af_xdp"))]
mod tests {
    use crate::backend::{Backend, BackendError};
    use crate::linux_xdp_aya::{AyaXdpBackend, LinuxFallbackSelector};
    use proptest::prelude::*;
    use std::net::SocketAddr;

    /// **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity (Linux)**
    /// **Validates: Requirements 2.5, 3.4**
    ///
    /// Property: For any platform and hardware configuration, when the preferred backend
    /// is unavailable, the system SHALL fall back to the next available backend in
    /// priority order without crashing.
    #[test]
    fn test_property_backend_fallback_chain_integrity() {
        // Test that fallback chain selection is deterministic and safe
        let fallback_chain = AyaXdpBackend::get_fallback_chain();

        // Property 1: Fallback chain is never empty
        assert!(
            !fallback_chain.is_empty(),
            "Fallback chain must never be empty"
        );

        // Property 2: Raw socket is always the final fallback
        assert_eq!(
            fallback_chain.last(),
            Some(&"raw_socket"),
            "Raw socket must always be the final fallback"
        );

        // Property 3: Fallback chain is in priority order (higher performance first)
        let expected_order = ["af_xdp", "io_uring", "sendmmsg", "raw_socket"];
        let mut chain_index = 0;

        for &backend in &fallback_chain {
            // Find this backend in the expected order
            while chain_index < expected_order.len() && expected_order[chain_index] != backend {
                chain_index += 1;
            }
            assert!(
                chain_index < expected_order.len(),
                "Backend {} not found in expected order",
                backend
            );
        }

        // Property 4: Backend selection never panics
        let selected_backend = LinuxFallbackSelector::select_best_backend();
        assert!(
            selected_backend.is_ok(),
            "Backend selection must never panic"
        );

        // Property 5: Selected backend is in the fallback chain
        let selected = selected_backend.unwrap();
        assert!(
            fallback_chain.contains(&selected.as_str()),
            "Selected backend {} must be in fallback chain",
            selected
        );
    }

    /// Property test using proptest for interface names
    proptest! {
        /// **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity (Linux)**
        /// **Validates: Requirements 2.5, 3.4**
        #[test]
        fn test_property_backend_creation_never_panics(
            interface in "[a-zA-Z0-9]{1,15}",  // Valid interface name pattern
            queue_id in 0u32..64u32,           // Valid queue ID range
        ) {
            // Property: Backend creation should never panic, even with invalid interfaces
            let result = AyaXdpBackend::new(&interface, queue_id);

            // Backend creation itself should succeed (actual initialization may fail)
            prop_assert!(result.is_ok(), "Backend creation should never panic");

            let backend = result.unwrap();

            // Property: Backend should report correct type
            prop_assert_eq!(backend.backend_type(), crate::backend::BackendType::AfXdp);

            // Property: Backend should not be initialized initially
            prop_assert!(!backend.is_initialized(), "Backend should not be initialized initially");

            // Property: Initial stats should be zero
            let stats = backend.stats();
            prop_assert_eq!(stats.packets_sent, 0, "Initial packets_sent should be 0");
            prop_assert_eq!(stats.bytes_sent, 0, "Initial bytes_sent should be 0");
            prop_assert_eq!(stats.errors, 0, "Initial errors should be 0");
        }

        /// Test that fallback selection is consistent
        #[test]
        fn test_property_fallback_selection_consistency(
            _seed in any::<u64>(),  // Random seed to ensure multiple runs
        ) {
            // Property: Fallback selection should be deterministic
            let selection1 = LinuxFallbackSelector::select_best_backend();
            let selection2 = LinuxFallbackSelector::select_best_backend();

            prop_assert_eq!(selection1, selection2, "Fallback selection must be deterministic");

            // Property: Capability report should be consistent
            let report1 = LinuxFallbackSelector::get_capability_report();
            let report2 = LinuxFallbackSelector::get_capability_report();

            prop_assert_eq!(report1, report2, "Capability report must be consistent");

            // Property: Report should contain expected sections
            prop_assert!(report1.contains("Linux Backend Capability Report"),
                        "Report must contain header");
            prop_assert!(report1.contains("raw_socket: Always available"),
                        "Report must show raw_socket as always available");
        }

        /// Test backend initialization behavior
        #[test]
        fn test_property_backend_initialization_safety(
            interface in "[a-zA-Z0-9]{1,15}",
            queue_id in 0u32..16u32,  // Smaller range for initialization tests
        ) {
            let mut backend = AyaXdpBackend::new(&interface, queue_id).unwrap();

            // Property: Initialization should handle unavailable backends gracefully
            let init_result = backend.init();

            // Initialization may fail (expected on systems without AF_XDP), but should not panic
            match init_result {
                Ok(()) => {
                    // If initialization succeeds, backend should be initialized
                    prop_assert!(backend.is_initialized(), "Backend should be initialized after successful init");
                }
                Err(BackendError::NotAvailable(_)) => {
                    // Expected failure - AF_XDP not available
                    prop_assert!(!backend.is_initialized(), "Backend should not be initialized after failed init");
                }
                Err(BackendError::InitFailed(_)) => {
                    // Expected failure - initialization failed
                    prop_assert!(!backend.is_initialized(), "Backend should not be initialized after failed init");
                }
                Err(e) => {
                    prop_assert!(false, "Unexpected error type: {:?}", e);
                }
            }

            // Property: Cleanup should always succeed
            let cleanup_result = backend.cleanup();
            prop_assert!(cleanup_result.is_ok(), "Cleanup should always succeed");
        }

        /// Test send operations safety
        #[test]
        fn test_property_send_operations_safety(
            packet_size in 1usize..1500usize,  // Valid packet size range
            dest_port in 1u16..65535u16,       // Valid port range
        ) {
            let backend = AyaXdpBackend::new("eth0", 0).unwrap();
            let packet_data = vec![0u8; packet_size];
            let dest_addr: SocketAddr = format!("192.168.1.1:{}", dest_port).parse().unwrap();

            // Property: Send operations on uninitialized backend should fail gracefully
            let send_result = backend.send(&packet_data, dest_addr);

            match send_result {
                Err(BackendError::NotInitialized) => {
                    // Expected - backend not initialized
                }
                Err(BackendError::SendFailed(_)) => {
                    // Also acceptable - send operation failed
                }
                Ok(_) => {
                    prop_assert!(false, "Send should not succeed on uninitialized backend");
                }
                Err(e) => {
                    prop_assert!(false, "Unexpected error type: {:?}", e);
                }
            }

            // Property: Batch send should also fail gracefully
            let packets: Vec<&[u8]> = vec![&packet_data];
            let batch_result = backend.send_batch(&packets, dest_addr);

            prop_assert!(batch_result.is_err(), "Batch send should fail on uninitialized backend");
        }
    }

    /// Test kernel version detection properties
    #[test]
    fn test_kernel_version_detection_properties() {
        // Property: Kernel version detection should be consistent
        let af_xdp_support1 = AyaXdpBackend::check_kernel_version();
        let af_xdp_support2 = AyaXdpBackend::check_kernel_version();
        assert_eq!(
            af_xdp_support1, af_xdp_support2,
            "Kernel version detection must be consistent"
        );

        let io_uring_support1 = AyaXdpBackend::check_io_uring_available();
        let io_uring_support2 = AyaXdpBackend::check_io_uring_available();
        assert_eq!(
            io_uring_support1, io_uring_support2,
            "io_uring detection must be consistent"
        );

        let sendmmsg_support1 = AyaXdpBackend::check_sendmmsg_available();
        let sendmmsg_support2 = AyaXdpBackend::check_sendmmsg_available();
        assert_eq!(
            sendmmsg_support1, sendmmsg_support2,
            "sendmmsg detection must be consistent"
        );

        // Property: If AF_XDP is supported, io_uring should also be supported (AF_XDP requires 4.18+, io_uring requires 5.1+)
        // This is not always true, so we'll just check that the detection doesn't crash

        // Property: sendmmsg should be supported on any modern Linux (kernel 3.0+)
        // On very old systems this might not be true, so we'll just verify it doesn't crash

        println!("Kernel capabilities detected:");
        println!("  AF_XDP: {}", af_xdp_support1);
        println!("  io_uring: {}", io_uring_support1);
        println!("  sendmmsg: {}", sendmmsg_support1);
    }

    /// Test availability detection properties
    #[test]
    fn test_availability_detection_properties() {
        // Property: Availability detection should be consistent
        let available1 = AyaXdpBackend::is_available();
        let available2 = AyaXdpBackend::is_available();
        assert_eq!(
            available1, available2,
            "Availability detection must be consistent"
        );

        // Property: If AF_XDP is available, kernel version should support it
        if available1 {
            assert!(
                AyaXdpBackend::check_kernel_version(),
                "If AF_XDP is available, kernel version must support it"
            );
        }

        // Property: Availability check should not crash
        // (This is implicitly tested by the above, but good to be explicit)
    }
}
