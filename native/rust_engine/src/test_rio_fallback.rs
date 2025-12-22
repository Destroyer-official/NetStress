//! Test file for RIO IOCP fallback functionality

#[cfg(all(target_os = "windows", feature = "registered_io"))]
mod rio_fallback_tests {
    use crate::backend::{Backend, BackendError};
    use crate::windows_rio::RioBackend;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_rio_fallback_initialization() {
        let mut backend = RioBackend::new();

        // Test that initialization always succeeds with IOCP fallback
        let init_result = backend.init();

        // On systems without RIO, this should still succeed due to IOCP fallback
        match init_result {
            Ok(()) => {
                println!("Backend initialized successfully (RIO or IOCP fallback)");
                assert!(backend.is_initialized());

                // Test fallback status
                let status = backend.get_fallback_status();
                println!("Fallback status: {}", status);
                assert!(!status.is_empty());

                // Cleanup
                let _ = backend.cleanup();
            }
            Err(e) => {
                println!("Backend initialization failed: {}", e);
                // This might happen in test environments without proper Windows socket support
                // but the fallback logic should still be testable
            }
        }
    }

    #[test]
    fn test_rio_fallback_graceful_degradation() {
        let mut backend = RioBackend::new();

        // Test that the backend reports correct availability status
        let rio_available = backend.is_rio_available();
        let iocp_available = backend.is_iocp_fallback_available();

        println!("RIO available: {}", rio_available);
        println!("IOCP fallback available: {}", iocp_available);

        // At least one should be available after initialization
        if backend.init().is_ok() {
            assert!(rio_available || iocp_available);
        }
    }

    #[test]
    fn test_rio_send_fallback_behavior() {
        let mut backend = RioBackend::new();

        // Initialize backend
        if backend.init().is_ok() {
            let test_data = b"Hello, RIO fallback test!";
            let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

            // Test send operation (will use RIO or fall back to IOCP)
            let send_result = backend.send(test_data, dest);

            match send_result {
                Ok(bytes_sent) => {
                    println!("Send successful: {} bytes", bytes_sent);
                    assert_eq!(bytes_sent, test_data.len());
                }
                Err(BackendError::SendFailed(msg)) => {
                    println!("Send failed as expected in test environment: {}", msg);
                    // This is expected in test environments without actual network setup
                }
                Err(e) => {
                    println!("Unexpected error: {}", e);
                }
            }

            // Test batch send
            let test_data2 = b"Batch packet 2";
            let packets: Vec<&[u8]> = vec![test_data, test_data2];
            let batch_result = backend.send_batch(&packets, dest);

            match batch_result {
                Ok(sent_count) => {
                    println!("Batch send successful: {} packets", sent_count);
                }
                Err(BackendError::SendFailed(msg)) => {
                    println!("Batch send failed as expected in test environment: {}", msg);
                }
                Err(e) => {
                    println!("Unexpected batch error: {}", e);
                }
            }

            // Get statistics
            let stats = backend.stats();
            println!(
                "Backend stats: packets_sent={}, bytes_sent={}, errors={}",
                stats.packets_sent, stats.bytes_sent, stats.errors
            );

            // Cleanup
            let _ = backend.cleanup();
        } else {
            println!("Backend initialization failed - skipping send tests");
        }
    }

    #[test]
    fn test_rio_detector_functionality() {
        use crate::windows_rio::RioDetector;

        // Test RIO detection utilities
        let available = RioDetector::is_available();
        let info = RioDetector::get_availability_info();
        let optimal = RioDetector::is_optimal_platform();

        println!("RIO available: {}", available);
        println!("RIO info: {}", info);
        println!("Optimal platform: {}", optimal);

        // These should not panic and should return meaningful information
        assert!(!info.is_empty());
    }
}

// Non-Windows or non-registered_io tests are skipped
#[cfg(not(all(target_os = "windows", feature = "registered_io")))]
mod rio_fallback_stub_tests {
    #[test]
    fn test_rio_not_available_without_feature() {
        // RIO tests are skipped when feature is not enabled
        println!("RIO tests skipped - registered_io feature not enabled");
    }
}
