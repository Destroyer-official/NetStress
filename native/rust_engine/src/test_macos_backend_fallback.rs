//! Property-based tests for macOS backend fallback chain integrity
//! **Feature: true-military-grade, Property 1: Backend Fallback Chain Integrity (macOS)**
//! **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity (macOS)**
//! **Validates: Requirements 2.4, 4.5**

use crate::backend::{Backend, BackendError, BackendType};
use crate::macos_backend::KqueueBackend;
use crate::macos_network_framework::NetworkFrameworkBackend;
use proptest::prelude::*;
use std::net::{Ipv4Addr, SocketAddr};

/// Test that macOS backend fallback chain works correctly
/// Property: For any platform and hardware configuration, when the preferred backend
/// is unavailable, the system SHALL fall back to the next available backend in priority
/// order without crashing.
#[cfg(test)]
mod tests {
    use super::*;

    proptest! {
        #[test]
        fn test_macos_backend_fallback_chain_integrity(
            target_ip in prop::array::uniform4(0u8..=255u8),
            target_port in 1024u16..=65535u16,
            packet_size in 64usize..=1500usize,
        ) {
            let target_addr = SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(target_ip[0], target_ip[1], target_ip[2], target_ip[3])),
                target_port
            );

            // Test Network.framework backend creation
            let network_framework_result = NetworkFrameworkBackend::new();

            match network_framework_result {
                Ok(mut backend) => {
                    // Network.framework is available, test it works
                    prop_assert_eq!(backend.backend_type(), BackendType::NetworkFramework);
                    prop_assert!(!backend.is_initialized());

                    // Test initialization
                    let init_result = backend.init();
                    if init_result.is_ok() {
                        prop_assert!(backend.is_initialized());

                        // Test sending a packet
                        let test_packet = vec![0u8; packet_size];
                        let send_result = backend.send(&test_packet, target_addr);

                        // Should either succeed or fail gracefully (not panic)
                        match send_result {
                            Ok(sent) => prop_assert!(sent <= packet_size),
                            Err(_) => {
                                // Acceptable - network might not be available in test environment
                            }
                        }

                        // Test cleanup
                        let cleanup_result = backend.cleanup();
                        prop_assert!(cleanup_result.is_ok());
                        prop_assert!(!backend.is_initialized());
                    }
                }
                Err(_) => {
                    // Network.framework not available, should fall back to kqueue
                    let mut kqueue_backend = KqueueBackend::new();
                    prop_assert_eq!(kqueue_backend.backend_type(), BackendType::Kqueue);
                    prop_assert!(!kqueue_backend.is_initialized());

                    // Test kqueue backend initialization
                    let init_result = kqueue_backend.init();
                    if init_result.is_ok() {
                        prop_assert!(kqueue_backend.is_initialized());

                        // Test sending a packet
                        let test_packet = vec![0u8; packet_size];
                        let send_result = kqueue_backend.send(&test_packet, target_addr);

                        // Should either succeed or fail gracefully (not panic)
                        match send_result {
                            Ok(sent) => prop_assert!(sent <= packet_size),
                            Err(_) => {
                                // Acceptable - network might not be available in test environment
                            }
                        }

                        // Test cleanup
                        let cleanup_result = kqueue_backend.cleanup();
                        prop_assert!(cleanup_result.is_ok());
                        prop_assert!(!kqueue_backend.is_initialized());
                    }
                }
            }
        }

        #[test]
        fn test_macos_backend_batch_send_fallback(
            target_ip in prop::array::uniform4(0u8..=255u8),
            target_port in 1024u16..=65535u16,
            batch_size in 1usize..=100usize,
            packet_size in 64usize..=1500usize,
        ) {
            let target_addr = SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(target_ip[0], target_ip[1], target_ip[2], target_ip[3])),
                target_port
            );

            // Create test packets
            let packets: Vec<Vec<u8>> = (0..batch_size)
                .map(|_| vec![0u8; packet_size])
                .collect();
            let packet_refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();

            // Test with Network.framework first
            if let Ok(mut backend) = NetworkFrameworkBackend::new() {
                if backend.init().is_ok() {
                    let batch_result = backend.send_batch(&packet_refs, target_addr);
                    match batch_result {
                        Ok(sent_count) => {
                            prop_assert!(sent_count <= batch_size);
                        }
                        Err(_) => {
                            // Acceptable failure in test environment
                        }
                    }
                    let _ = backend.cleanup();
                }
            } else {
                // Fall back to kqueue
                let mut kqueue_backend = KqueueBackend::new();
                if kqueue_backend.init().is_ok() {
                    let batch_result = kqueue_backend.send_batch(&packet_refs, target_addr);
                    match batch_result {
                        Ok(sent_count) => {
                            prop_assert!(sent_count <= batch_size);
                        }
                        Err(_) => {
                            // Acceptable failure in test environment
                        }
                    }
                    let _ = kqueue_backend.cleanup();
                }
            }
        }

        #[test]
        fn test_apple_silicon_detection_consistency(
            _dummy in 0u8..=255u8, // Dummy parameter to make this a property test
        ) {
            // Test that Apple Silicon detection is consistent
            if let Ok(info1) = crate::macos_network_framework::AppleSiliconInfo::detect() {
                if let Ok(info2) = crate::macos_network_framework::AppleSiliconInfo::detect() {
                    prop_assert_eq!(info1.is_apple_silicon, info2.is_apple_silicon);
                    prop_assert_eq!(info1.chip_type, info2.chip_type);
                    prop_assert_eq!(info1.cpu_cores, info2.cpu_cores);
                    prop_assert_eq!(info1.has_unified_memory, info2.has_unified_memory);

                    // Validate logical constraints
                    if info1.is_apple_silicon {
                        prop_assert!(info1.has_unified_memory);
                        prop_assert!(info1.performance_cores > 0);
                        prop_assert!(info1.cpu_cores >= info1.performance_cores);
                        prop_assert!(info1.efficiency_cores == info1.cpu_cores - info1.performance_cores);
                    }
                }
            }
        }

        #[test]
        fn test_network_framework_config_scaling(
            _dummy in 0u8..=255u8, // Dummy parameter to make this a property test
        ) {
            // Test that Network.framework configuration scales appropriately
            if let Ok(backend) = NetworkFrameworkBackend::new() {
                let config = backend.get_optimal_config();

                // Validate configuration constraints
                prop_assert!(config.thread_count > 0);
                prop_assert!(config.thread_count <= 64); // Reasonable upper bound
                prop_assert!(config.buffer_size >= 64 * 1024); // At least 64KB
                prop_assert!(config.buffer_size <= 16 * 1024 * 1024); // At most 16MB

                // Apple Silicon should have unified memory optimizations
                if backend.is_apple_silicon() {
                    prop_assert!(config.use_unified_memory_optimizations);
                    prop_assert!(config.use_neon_simd);
                    prop_assert!(config.simd_batch_size >= 16); // NEON processes 16-byte vectors
                    prop_assert!(config.memory_alignment >= 16); // NEON alignment requirement
                } else {
                    prop_assert!(!config.use_unified_memory_optimizations);
                    prop_assert!(!config.use_neon_simd);
                    prop_assert!(config.memory_alignment >= 8); // Standard alignment
                }
            }
        }

        /// **Feature: titanium-upgrade, Property 1: Backend Fallback Chain Integrity (macOS)**
        /// **Validates: Requirements 4.5**
        ///
        /// Property: For any macOS system, when Network.framework is unavailable,
        /// the system SHALL automatically fall back to kqueue without crashing.
        #[test]
        fn test_titanium_macos_backend_fallback_chain_integrity(
            target_ip in prop::array::uniform4(0u8..=255u8),
            target_port in 1024u16..=65535u16,
            packet_size in 64usize..=1500usize,
        ) {
            let target_addr = SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(target_ip[0], target_ip[1], target_ip[2], target_ip[3])),
                target_port
            );

            // Test the automatic backend selection
            let backend = NetworkFrameworkBackend::create_best_backend();

            // Backend should be created successfully regardless of Network.framework availability
            prop_assert!(backend.backend_type() == BackendType::NetworkFramework ||
                        backend.backend_type() == BackendType::Kqueue);

            // Test that the selected backend can be initialized
            let mut backend = backend;
            let init_result = backend.init();

            // Initialization should succeed or fail gracefully (not panic)
            match init_result {
                Ok(()) => {
                    prop_assert!(backend.is_initialized());

                    // Test packet sending
                    let test_packet = vec![0u8; packet_size];
                    let send_result = backend.send(&test_packet, target_addr);

                    // Should handle send gracefully
                    match send_result {
                        Ok(sent) => prop_assert!(sent <= packet_size),
                        Err(_) => {
                            // Network errors are acceptable in test environment
                        }
                    }

                    // Cleanup should work
                    let cleanup_result = backend.cleanup();
                    prop_assert!(cleanup_result.is_ok());
                }
                Err(_) => {
                    // Initialization failure is acceptable but should not panic
                }
            }
        }

        #[test]
        fn test_apple_silicon_m4_detection(
            _dummy in 0u8..=255u8,
        ) {
            // Test M4 chip detection and optimization
            if let Ok(info) = crate::macos_network_framework::AppleSiliconInfo::detect() {
                if info.chip_type == crate::macos_network_framework::AppleChipType::M4 {
                    // M4 should have the largest buffer sizes and batch sizes
                    prop_assert!(info.get_optimal_buffer_size() >= 8 * 1024 * 1024); // 8MB
                    prop_assert!(info.get_simd_batch_size() >= 128); // Largest batch size
                    prop_assert!(info.has_unified_memory);
                    prop_assert!(info.has_neon_simd());
                }

                // All Apple Silicon should have unified memory
                if info.is_apple_silicon {
                    prop_assert!(info.has_unified_memory);
                    prop_assert!(info.has_neon_simd());
                    prop_assert!(info.get_simd_alignment() == 16); // NEON alignment
                }
            }
        }

        #[test]
        fn test_network_framework_feature_levels(
            _dummy in 0u8..=255u8,
        ) {
            // Test Network.framework feature level detection
            if let Ok(version) = crate::macos_network_framework::MacOSVersion::detect() {
                let feature_level = version.get_network_framework_feature_level();

                match feature_level {
                    crate::macos_network_framework::NetworkFrameworkFeatureLevel::NotAvailable => {
                        prop_assert!(!version.has_network_framework());
                    }
                    crate::macos_network_framework::NetworkFrameworkFeatureLevel::Basic => {
                        prop_assert!(version.has_network_framework());
                        prop_assert!(!version.is_monterey_or_later());
                    }
                    crate::macos_network_framework::NetworkFrameworkFeatureLevel::Standard => {
                        prop_assert!(version.is_monterey_or_later());
                        prop_assert!(!version.is_ventura_or_later());
                    }
                    crate::macos_network_framework::NetworkFrameworkFeatureLevel::Modern => {
                        prop_assert!(version.is_ventura_or_later());
                        prop_assert!(!version.is_sonoma_or_later());
                    }
                    crate::macos_network_framework::NetworkFrameworkFeatureLevel::Latest => {
                        prop_assert!(version.is_sonoma_or_later());
                    }
                }
            }
        }
    }

    #[test]
    fn test_backend_type_consistency() {
        // Test that backend types are consistent
        if let Ok(nf_backend) = NetworkFrameworkBackend::new() {
            assert_eq!(nf_backend.backend_type(), BackendType::NetworkFramework);
        }

        let kqueue_backend = KqueueBackend::new();
        assert_eq!(kqueue_backend.backend_type(), BackendType::Kqueue);
    }

    #[test]
    fn test_macos_version_detection() {
        // Test that macOS version detection works
        if let Ok(version) = crate::macos_network_framework::MacOSVersion::detect() {
            assert!(version.major >= 10);
            assert!(version.minor >= 0);
            assert!(version.patch >= 0);

            // Test version comparison methods
            let has_nf = version.has_network_framework();
            let is_ventura = version.is_ventura_or_later();
            let is_monterey = version.is_monterey_or_later();

            // Logical consistency
            if version.major >= 13 {
                assert!(is_ventura);
                assert!(is_monterey);
                assert!(has_nf);
            }

            if version.major >= 12 {
                assert!(is_monterey);
                assert!(has_nf);
            }

            if version.major > 10 || (version.major == 10 && version.minor >= 14) {
                assert!(has_nf);
            }
        }
    }
}
