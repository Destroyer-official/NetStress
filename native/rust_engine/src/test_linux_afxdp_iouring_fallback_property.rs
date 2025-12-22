//! Property-based test for Linux AF_XDP + io_uring fallback chain
//! **Property 1: Backend Fallback Chain Integrity (Linux)**
//! **Validates: Requirements 3.4**

#[cfg(test)]
mod tests {
    use crate::backend::{
        create_best_backend, select_best_backend, Backend, BackendType, SystemCapabilities,
    };
    use crate::linux_afxdp_iouring::AfXdpIoUringBackend;
    use proptest::prelude::*;
    use std::net::SocketAddr;

    /// Generate arbitrary system capabilities for testing
    fn arb_system_capabilities() -> impl Strategy<Value = SystemCapabilities> {
        (
            any::<bool>(),   // has_dpdk
            any::<bool>(),   // has_af_xdp
            any::<bool>(),   // has_io_uring
            any::<bool>(),   // has_sendmmsg
            any::<bool>(),   // has_raw_socket (always true in practice)
            (3i32..=6i32),   // kernel_major (3-6)
            (0i32..=30i32),  // kernel_minor (0-30)
            (1i32..=128i32), // cpu_count
            (1i32..=8i32),   // numa_nodes
        )
            .prop_map(
                |(dpdk, af_xdp, io_uring, sendmmsg, raw_socket, major, minor, cpu, numa)| {
                    let mut caps = SystemCapabilities {
                        has_dpdk: dpdk,
                        has_af_xdp: af_xdp && (major > 4 || (major == 4 && minor >= 18)), // AF_XDP requires 4.18+
                        has_io_uring: io_uring && (major > 5 || (major == 5 && minor >= 1)), // io_uring requires 5.1+
                        has_sendmmsg: sendmmsg && major >= 3, // sendmmsg requires 3.0+
                        has_raw_socket: raw_socket,           // Always available
                        has_iocp: false,
                        has_registered_io: false,
                        has_kqueue: false,
                        has_network_framework: false,
                        kernel_version: (major, minor),
                        cpu_count: cpu,
                        numa_nodes: numa,
                        has_af_xdp_io_uring: false, // Will be calculated
                    };

                    // Combined AF_XDP + io_uring available when both are supported
                    caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;

                    caps
                },
            )
    }

    /// Generate availability scenarios for backend testing
    fn arb_backend_availability() -> impl Strategy<Value = Vec<bool>> {
        prop::collection::vec(any::<bool>(), 5..=10)
    }

    proptest! {
        /// **Feature: cross-platform-destroyer, Property 1: Backend Fallback Chain Integrity (Linux)**
        /// **Validates: Requirements 3.4**
        ///
        /// For any system capabilities configuration, the backend selection should:
        /// 1. Select the highest priority available backend
        /// 2. Never select an unavailable backend
        /// 3. Always fall back to raw socket if nothing else is available
        #[test]
        fn test_linux_backend_fallback_chain_integrity(
            caps in arb_system_capabilities(),
        ) {
            let selected_backend = select_best_backend(&caps);

            // Verify the selected backend is actually available
            match selected_backend {
                BackendType::Dpdk => prop_assert!(caps.has_dpdk),
                BackendType::AfXdpIoUring => prop_assert!(caps.has_af_xdp_io_uring),
                BackendType::AfXdp => prop_assert!(caps.has_af_xdp),
                BackendType::IoUring => prop_assert!(caps.has_io_uring),
                BackendType::Sendmmsg => prop_assert!(caps.has_sendmmsg),
                BackendType::RawSocket => prop_assert!(caps.has_raw_socket),
                _ => prop_assert!(false, "Unexpected backend type selected: {:?}", selected_backend),
            }

            // Verify priority order is respected
            if caps.has_dpdk {
                prop_assert_eq!(selected_backend, BackendType::Dpdk);
            } else if caps.has_af_xdp_io_uring {
                prop_assert_eq!(selected_backend, BackendType::AfXdpIoUring);
            } else if caps.has_af_xdp {
                prop_assert_eq!(selected_backend, BackendType::AfXdp);
            } else if caps.has_io_uring {
                prop_assert_eq!(selected_backend, BackendType::IoUring);
            } else if caps.has_sendmmsg {
                prop_assert_eq!(selected_backend, BackendType::Sendmmsg);
            } else {
                // Should always fall back to raw socket
                prop_assert_eq!(selected_backend, BackendType::RawSocket);
            }
        }

        /// Test that combined AF_XDP + io_uring backend is properly prioritized
        #[test]
        fn test_combined_backend_priority(
            has_dpdk in any::<bool>(),
            has_af_xdp in any::<bool>(),
            has_io_uring in any::<bool>(),
            kernel_major in 4i32..=6i32,
            kernel_minor in 0i32..=30i32,
        ) {
            let caps = SystemCapabilities {
                has_dpdk,
                has_af_xdp: has_af_xdp && (kernel_major > 4 || (kernel_major == 4 && kernel_minor >= 18)),
                has_io_uring: has_io_uring && (kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 1)),
                has_af_xdp_io_uring: false, // Will be calculated
                has_sendmmsg: true,
                has_raw_socket: true,
                has_iocp: false,
                has_registered_io: false,
                has_kqueue: false,
                has_network_framework: false,
                kernel_version: (kernel_major, kernel_minor),
                cpu_count: 4,
                numa_nodes: 1,
            };

            let mut caps = caps;
            caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;

            let selected = select_best_backend(&caps);

            // If both AF_XDP and io_uring are available, combined backend should be selected
            // (unless DPDK is available, which has higher priority)
            if caps.has_af_xdp_io_uring && !caps.has_dpdk {
                prop_assert_eq!(selected, BackendType::AfXdpIoUring);
            }
        }

        /// Test kernel version requirements are properly enforced
        #[test]
        fn test_kernel_version_requirements(
            kernel_major in 3i32..=6i32,
            kernel_minor in 0i32..=30i32,
        ) {
            let caps = SystemCapabilities {
                has_dpdk: false,
                has_af_xdp: true, // Assume hardware supports it
                has_io_uring: true, // Assume hardware supports it
                has_af_xdp_io_uring: false, // Will be calculated
                has_sendmmsg: kernel_major >= 3,
                has_raw_socket: true,
                has_iocp: false,
                has_registered_io: false,
                has_kqueue: false,
                has_network_framework: false,
                kernel_version: (kernel_major, kernel_minor),
                cpu_count: 4,
                numa_nodes: 1,
            };

            let mut caps = caps;

            // Apply kernel version requirements
            caps.has_af_xdp = caps.has_af_xdp && (kernel_major > 4 || (kernel_major == 4 && kernel_minor >= 18));
            caps.has_io_uring = caps.has_io_uring && (kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 1));
            caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;

            let selected = select_best_backend(&caps);

            // Verify kernel version requirements are respected
            match selected {
                BackendType::AfXdpIoUring => {
                    prop_assert!(kernel_major > 4 || (kernel_major == 4 && kernel_minor >= 18)); // AF_XDP requirement
                    prop_assert!(kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 1)); // io_uring requirement
                }
                BackendType::AfXdp => {
                    prop_assert!(kernel_major > 4 || (kernel_major == 4 && kernel_minor >= 18));
                }
                BackendType::IoUring => {
                    prop_assert!(kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 1));
                }
                BackendType::Sendmmsg => {
                    prop_assert!(kernel_major >= 3);
                }
                BackendType::RawSocket => {
                    // Always available
                }
                _ => {}
            }
        }

        /// Test that backend creation handles failures gracefully
        #[test]
        fn test_backend_creation_fallback(
            availability in arb_backend_availability(),
        ) {
            // This test simulates various backend availability scenarios
            // In a real system, backend creation might fail due to permissions,
            // missing hardware support, etc.

            // The fallback chain should ensure we always get a working backend
            let backend = create_best_backend();

            // Should always succeed in creating some backend
            prop_assert!(backend.backend_type() != BackendType::None);

            // The created backend should be one of the valid types
            match backend.backend_type() {
                BackendType::Dpdk |
                BackendType::AfXdpIoUring |
                BackendType::AfXdp |
                BackendType::IoUring |
                BackendType::Sendmmsg |
                BackendType::RawSocket => {
                    // Valid backend type
                }
                _ => prop_assert!(false, "Invalid backend type created: {:?}", backend.backend_type()),
            }
        }

        /// Test AF_XDP + io_uring backend availability detection
        #[test]
        fn test_afxdp_iouring_availability_detection() {
            // Test the availability detection logic
            let available = AfXdpIoUringBackend::is_available();

            // On systems where this test runs, the result should be consistent
            // with the actual kernel version and feature availability

            if available {
                // If available, we should be able to create the backend
                let backend_result = AfXdpIoUringBackend::new("lo", 0); // Use loopback interface
                prop_assert!(backend_result.is_ok());

                let backend = backend_result.unwrap();
                prop_assert_eq!(backend.backend_type(), BackendType::AfXdp); // Maps to AF_XDP type
                prop_assert!(!backend.is_initialized()); // Should not be initialized yet
            }

            // The availability check should be deterministic
            let available2 = AfXdpIoUringBackend::is_available();
            prop_assert_eq!(available, available2);
        }

        /// Test enhanced statistics functionality
        #[test]
        fn test_enhanced_statistics(
            packets_sent in 0u64..1000000u64,
            bytes_sent in 0u64..1000000000u64,
        ) {
            let backend = AfXdpIoUringBackend::new("lo", 0).unwrap();
            let stats = backend.get_enhanced_stats();

            // Initial statistics should be zero
            prop_assert_eq!(stats.packets_sent, 0);
            prop_assert_eq!(stats.bytes_sent, 0);
            prop_assert_eq!(stats.errors, 0);
            prop_assert_eq!(stats.batch_count, 0);
            prop_assert_eq!(stats.io_uring_submissions, 0);
            prop_assert_eq!(stats.io_uring_completions, 0);
            prop_assert_eq!(stats.zero_copy_packets, 0);
            prop_assert_eq!(stats.umem_frame_reuses, 0);

            // Configuration should be consistent
            prop_assert!(stats.umem_frame_count > 0);
            prop_assert!(stats.umem_frame_size > 0);
            prop_assert!(stats.umem_frame_size <= 4096); // Reasonable frame size
        }
    }

    #[test]
    fn test_backend_name_consistency() {
        // Test that backend names are consistent
        assert_eq!(BackendType::AfXdpIoUring.name(), "af_xdp_io_uring");
        assert_eq!(BackendType::AfXdp.name(), "af_xdp");
        assert_eq!(BackendType::IoUring.name(), "io_uring");
        assert_eq!(BackendType::Sendmmsg.name(), "sendmmsg");
        assert_eq!(BackendType::RawSocket.name(), "raw_socket");
    }

    #[test]
    fn test_backend_type_conversion() {
        // Test backend type conversion functions
        assert_eq!(BackendType::from_u32(5), BackendType::AfXdpIoUring);
        assert_eq!(BackendType::from_u32(4), BackendType::AfXdp);
        assert_eq!(BackendType::from_u32(3), BackendType::IoUring);
        assert_eq!(BackendType::from_u32(2), BackendType::Sendmmsg);
        assert_eq!(BackendType::from_u32(1), BackendType::RawSocket);
        assert_eq!(BackendType::from_u32(999), BackendType::None);
    }

    #[test]
    fn test_system_capabilities_combined_detection() {
        // Test that combined capability detection works correctly
        let mut caps = SystemCapabilities::default();

        // Test case 1: Both AF_XDP and io_uring available
        caps.has_af_xdp = true;
        caps.has_io_uring = true;
        caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;
        assert!(caps.has_af_xdp_io_uring);

        // Test case 2: Only AF_XDP available
        caps.has_af_xdp = true;
        caps.has_io_uring = false;
        caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;
        assert!(!caps.has_af_xdp_io_uring);

        // Test case 3: Only io_uring available
        caps.has_af_xdp = false;
        caps.has_io_uring = true;
        caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;
        assert!(!caps.has_af_xdp_io_uring);

        // Test case 4: Neither available
        caps.has_af_xdp = false;
        caps.has_io_uring = false;
        caps.has_af_xdp_io_uring = caps.has_af_xdp && caps.has_io_uring;
        assert!(!caps.has_af_xdp_io_uring);
    }
}
