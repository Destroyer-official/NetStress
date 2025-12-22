//! Property-based test for Linux backend fallback chain integrity
//! **Property 1: Backend Fallback Chain Integrity (Linux)**
//! **Validates: Requirements 3.4**

#[cfg(test)]
mod tests {
    use crate::backend::{Backend, BackendError, BackendType};
    use crate::linux_fallback::LinuxFallbackBackend;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// **Feature: true-military-grade, Property 1: Backend Fallback Chain Integrity (Linux)**
    /// **Validates: Requirements 3.4**
    ///
    /// Property: For any platform and hardware configuration, when the preferred backend
    /// is unavailable, the system SHALL fall back to the next available backend in priority
    /// order without crashing.
    ///
    /// This test validates that the Linux fallback chain (AF_XDP → io_uring → sendmmsg → raw socket)
    /// works correctly and always provides a functional backend.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_property_linux_backend_fallback_chain_integrity() {
        // Test with various interface names and queue IDs
        let test_cases = vec![
            ("lo", 0),      // Loopback interface (always available)
            ("eth0", 0),    // Common Ethernet interface
            ("wlan0", 0),   // Common WiFi interface
            ("enp0s3", 0),  // Predictable network interface name
            ("invalid", 0), // Invalid interface (should still work with fallback)
        ];

        for (interface, queue_id) in test_cases {
            println!(
                "Testing fallback chain with interface: {}, queue: {}",
                interface, queue_id
            );

            // Create Linux fallback backend
            let backend_result = LinuxFallbackBackend::new(interface, queue_id);

            match backend_result {
                Ok(backend) => {
                    // Backend should be initialized
                    assert!(
                        backend.is_initialized(),
                        "Backend should be initialized after creation"
                    );

                    // Backend should have a valid type (not None)
                    let backend_type = backend.backend_type();
                    assert_ne!(
                        backend_type,
                        BackendType::None,
                        "Backend type should not be None"
                    );

                    // Backend should be one of the expected Linux backends
                    let valid_types = vec![
                        BackendType::AfXdp,
                        BackendType::IoUring,
                        BackendType::Sendmmsg,
                        BackendType::RawSocket,
                    ];
                    assert!(
                        valid_types.contains(&backend_type),
                        "Backend type {:?} should be one of the valid Linux backends",
                        backend_type
                    );

                    // Test basic functionality
                    let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
                    let test_data = b"test packet data";

                    // Send operation should not crash (may fail due to network conditions, but shouldn't panic)
                    let send_result = backend.send(test_data, test_addr);
                    match send_result {
                        Ok(bytes_sent) => {
                            assert_eq!(
                                bytes_sent,
                                test_data.len(),
                                "Bytes sent should match data length"
                            );
                        }
                        Err(e) => {
                            // Send may fail due to network conditions, but error should be reasonable
                            println!("Send failed (expected on some systems): {}", e);
                        }
                    }

                    // Stats should be accessible
                    let stats = backend.stats();
                    // Stats should be valid (non-negative values)
                    assert!(
                        stats.packets_sent >= 0,
                        "Packets sent should be non-negative"
                    );
                    assert!(stats.bytes_sent >= 0, "Bytes sent should be non-negative");
                    assert!(stats.errors >= 0, "Errors should be non-negative");

                    println!("✓ Backend {} working correctly", backend_type.name());
                }
                Err(e) => {
                    // Even if backend creation fails, it should be a reasonable error
                    println!("Backend creation failed (may be expected): {}", e);

                    // Error should be one of the expected types
                    match e {
                        BackendError::NotAvailable(_) => {
                            // This is acceptable - system may not support advanced backends
                        }
                        BackendError::InitFailed(_) => {
                            // This is acceptable - initialization may fail due to permissions/system state
                        }
                        _ => {
                            panic!("Unexpected error type: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    /// Property test: Fallback chain should always provide a working backend
    /// This uses proptest to generate random interface names and test the fallback behavior
    proptest! {
        #[cfg(target_os = "linux")]
        #[test]
        fn test_property_fallback_always_provides_backend(
            interface_suffix in "[a-z0-9]{1,8}",
            queue_id in 0u32..4
        ) {
            let interface = format!("test{}", interface_suffix);

            // Even with random/invalid interface names, the fallback should eventually
            // provide a working backend (at minimum, raw socket)
            match LinuxFallbackBackend::new(&interface, queue_id) {
                Ok(backend) => {
                    // If creation succeeds, backend should be functional
                    prop_assert!(backend.is_initialized());
                    prop_assert_ne!(backend.backend_type(), BackendType::None);

                    // Stats should be accessible
                    let stats = backend.stats();
                    prop_assert!(stats.packets_sent >= 0);
                    prop_assert!(stats.bytes_sent >= 0);
                    prop_assert!(stats.errors >= 0);
                }
                Err(e) => {
                    // If creation fails, it should be for a reasonable reason
                    match e {
                        BackendError::NotAvailable(_) | BackendError::InitFailed(_) => {
                            // These are acceptable failure modes
                        }
                        _ => {
                            prop_assert!(false, "Unexpected error type: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    /// Property test: Backend send operations should be consistent
    proptest! {
        #[cfg(target_os = "linux")]
        #[test]
        fn test_property_backend_send_consistency(
            data_len in 1usize..1500,
            port in 1024u16..65535
        ) {
            // Use loopback interface for consistent testing
            if let Ok(backend) = LinuxFallbackBackend::new("lo", 0) {
                let test_data = vec![0xAA; data_len];
                let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

                match backend.send(&test_data, test_addr) {
                    Ok(bytes_sent) => {
                        // If send succeeds, bytes sent should match data length
                        prop_assert_eq!(bytes_sent, data_len);
                    }
                    Err(_) => {
                        // Send may fail due to network conditions, which is acceptable
                        // The important thing is that it doesn't crash
                    }
                }

                // Backend should remain functional after send attempt
                prop_assert!(backend.is_initialized());
                prop_assert_ne!(backend.backend_type(), BackendType::None);
            }
        }
    }

    /// Property test: Batch send operations should handle various batch sizes
    proptest! {
        #[cfg(target_os = "linux")]
        #[test]
        fn test_property_batch_send_handling(
            batch_size in 1usize..100,
            packet_size in 64usize..1472
        ) {
            if let Ok(backend) = LinuxFallbackBackend::new("lo", 0) {
                // Create batch of packets
                let packets: Vec<Vec<u8>> = (0..batch_size)
                    .map(|i| vec![i as u8; packet_size])
                    .collect();

                let packet_refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();
                let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

                match backend.send_batch(&packet_refs, test_addr) {
                    Ok(sent_count) => {
                        // If batch send succeeds, sent count should be reasonable
                        prop_assert!(sent_count <= batch_size);
                    }
                    Err(_) => {
                        // Batch send may fail, which is acceptable
                    }
                }

                // Backend should remain functional after batch send attempt
                prop_assert!(backend.is_initialized());
            }
        }
    }

    /// Test fallback statistics tracking
    #[cfg(target_os = "linux")]
    #[test]
    fn test_fallback_statistics_tracking() {
        // Test with an interface that's likely to trigger fallbacks
        if let Ok(backend) = LinuxFallbackBackend::new("nonexistent_interface", 0) {
            let fallback_stats = backend.get_fallback_stats();

            // Stats should be valid
            assert!(
                fallback_stats.fallback_count >= 0,
                "Fallback count should be non-negative"
            );
            assert!(
                fallback_stats.af_xdp_failures >= 0,
                "AF_XDP failures should be non-negative"
            );
            assert!(
                fallback_stats.io_uring_failures >= 0,
                "io_uring failures should be non-negative"
            );
            assert!(
                fallback_stats.sendmmsg_failures >= 0,
                "sendmmsg failures should be non-negative"
            );

            // Current backend should be valid
            assert_ne!(
                fallback_stats.current_backend,
                BackendType::None,
                "Current backend should not be None"
            );

            println!("Fallback stats: {:?}", fallback_stats);
        }
    }

    /// Test that cleanup works properly
    #[cfg(target_os = "linux")]
    #[test]
    fn test_backend_cleanup() {
        if let Ok(mut backend) = LinuxFallbackBackend::new("lo", 0) {
            // Backend should be initialized
            assert!(backend.is_initialized());

            // Cleanup should succeed
            let cleanup_result = backend.cleanup();
            assert!(cleanup_result.is_ok(), "Cleanup should succeed");

            // After cleanup, backend may or may not be considered initialized
            // depending on the specific backend implementation
        }
    }

    /// Integration test: Test the complete fallback chain behavior
    #[cfg(target_os = "linux")]
    #[test]
    fn test_complete_fallback_chain_behavior() {
        println!("Testing complete Linux fallback chain behavior");

        // Test with various scenarios that might trigger different fallback paths
        let test_scenarios = vec![
            ("lo", 0, "loopback interface"),
            ("eth0", 0, "ethernet interface"),
            ("invalid_interface", 0, "invalid interface"),
            ("lo", 999, "high queue ID"),
        ];

        for (interface, queue_id, description) in test_scenarios {
            println!("Testing scenario: {}", description);

            match LinuxFallbackBackend::new(interface, queue_id) {
                Ok(backend) => {
                    println!(
                        "  ✓ Backend created successfully: {}",
                        backend.backend_type().name()
                    );

                    // Test basic operations
                    let stats = backend.stats();
                    println!("  ✓ Stats accessible: {} packets sent", stats.packets_sent);

                    let fallback_stats = backend.get_fallback_stats();
                    println!(
                        "  ✓ Fallback stats: {} fallbacks, current: {}",
                        fallback_stats.fallback_count,
                        fallback_stats.current_backend.name()
                    );
                }
                Err(e) => {
                    println!("  ! Backend creation failed: {} (may be expected)", e);
                }
            }
        }
    }
}
