//! Test file for RIO buffer registration functionality

#[cfg(all(target_os = "windows", feature = "registered_io"))]
mod rio_buffer_tests {
    use crate::backend::Backend;
    use crate::windows_rio::RioBackend;

    #[test]
    fn test_rio_backend_creation() {
        let backend = RioBackend::new();
        assert!(!backend.is_initialized());
        assert_eq!(
            backend.backend_type(),
            crate::backend::BackendType::RegisteredIO
        );
    }

    #[test]
    fn test_rio_detection() {
        let mut backend = RioBackend::new();

        // Test RIO detection (may fail on systems without RIO support)
        let detection_result = backend.detect_rio_support();
        println!("RIO detection result: {:?}", detection_result);

        // Test status message
        let status = backend.get_rio_status();
        println!("RIO status: {}", status);
        assert!(!status.is_empty());
    }

    #[test]
    fn test_rio_fallback_status() {
        let backend = RioBackend::new();

        // Test fallback status reporting
        let fallback_status = backend.get_fallback_status();
        println!("Fallback status: {}", fallback_status);
        assert!(!fallback_status.is_empty());

        // Test IOCP fallback availability check
        let iocp_available = backend.is_iocp_fallback_available();
        println!("IOCP fallback available: {}", iocp_available);
    }
}

#[cfg(not(target_os = "windows"))]
mod rio_buffer_tests {
    #[test]
    fn test_rio_not_available() {
        // On non-Windows platforms, RIO should not be available
        assert!(!crate::windows_rio::RioDetector::is_available());
    }
}
