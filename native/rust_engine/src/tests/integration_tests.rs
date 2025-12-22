//! Integration tests for Rust engine components
//!
//! Tests the interaction between different components and validates
//! end-to-end functionality of the Rust engine layer.

use crate::engine::{EngineConfig, FloodEngine};
use crate::packet::Protocol;
use crate::precision_timer::{PrecisionTimer, ShapingConfig, ShapingPattern, TrafficShaper};
use crate::tls_spoof::{JA3Spoofer, TlsProfile};
use proptest::prelude::*;
use std::time::Duration;

/// Test integration between FloodEngine and TLS spoofing
#[test]
fn test_engine_tls_integration() {
    let config = EngineConfig {
        target: "127.0.0.1".to_string(),
        port: 443,
        threads: 1,
        packet_size: 1024,
        protocol: Protocol::TCP,
        rate_limit: Some(100),
        tls_profile: Some("chrome_120".to_string()),
        ..Default::default()
    };

    let mut engine = FloodEngine::new(config).unwrap();

    // Engine should handle TLS profile configuration
    assert!(engine.start().is_ok());
    std::thread::sleep(Duration::from_millis(50));
    assert!(engine.stop().is_ok());

    // Should complete without errors
    let stats = engine.get_stats();
    assert!(stats.duration > Duration::ZERO);
}

/// Test integration between FloodEngine and precision timing
#[test]
fn test_engine_timing_integration() {
    let config = EngineConfig {
        target: "127.0.0.1".to_string(),
        port: 8080,
        threads: 1,
        packet_size: 64,
        protocol: Protocol::UDP,
        rate_limit: Some(1000), // 1000 PPS = 1ms intervals
        ..Default::default()
    };

    let mut engine = FloodEngine::new(config).unwrap();

    let start = std::time::Instant::now();
    engine.start().unwrap();
    std::thread::sleep(Duration::from_millis(100)); // Let it run for 100ms
    engine.stop().unwrap();
    let elapsed = start.elapsed();

    // Should have run for approximately 100ms
    assert!(elapsed.as_millis() > 80);
    assert!(elapsed.as_millis() < 200);

    let stats = engine.get_stats();
    // With rate limiting, should not exceed the rate significantly
    let duration_secs = stats.duration.as_secs_f64();
    if duration_secs > 0.0 && stats.packets_sent > 0 {
        let actual_pps = stats.packets_sent as f64 / duration_secs;
        // Allow some variance but should be roughly limited
        assert!(actual_pps < 5000.0, "Rate limiting should be effective");
    }
}

/// Test TLS profile and Client Hello generation integration
#[test]
fn test_tls_client_hello_integration() {
    let mut spoofer = JA3Spoofer::new();

    // Test multiple profiles in sequence
    let profiles = ["chrome_120", "firefox_121", "safari_17"];
    let mut client_hellos = Vec::new();

    for profile_name in profiles {
        spoofer.set_profile(profile_name).unwrap();
        let hello = spoofer
            .build_client_hello("integration-test.example.com")
            .unwrap();
        client_hellos.push((profile_name, hello));
    }

    // Each Client Hello should be different
    for i in 0..client_hellos.len() {
        for j in i + 1..client_hellos.len() {
            let (name1, hello1) = &client_hellos[i];
            let (name2, hello2) = &client_hellos[j];

            assert_ne!(
                hello1, hello2,
                "Client Hellos for {} and {} should be different",
                name1, name2
            );
        }
    }

    // All should have valid TLS structure
    for (name, hello) in client_hellos {
        assert_eq!(hello[0], 0x16, "{} should have handshake record type", name);
        assert_eq!(hello[5], 0x01, "{} should have Client Hello type", name);
        assert!(
            hello.len() > 100,
            "{} Client Hello should be substantial",
            name
        );
    }
}

/// Test precision timer with traffic shaping integration
#[test]
fn test_timer_shaping_integration() {
    let config = ShapingConfig {
        pattern: ShapingPattern::Sawtooth,
        base_rate: 1000,
        jitter_percent: 0.1,
        cycle_duration_ms: 500,
        ..Default::default()
    };

    let mut shaper = TrafficShaper::with_config(config);
    let timer = PrecisionTimer::new();

    let start = std::time::Instant::now();
    let mut intervals = Vec::new();

    // Measure several intervals
    for _ in 0..10 {
        let interval_start = timer.elapsed_nanos();
        shaper.wait_next();
        let interval_end = timer.elapsed_nanos();
        intervals.push(interval_end - interval_start);
    }

    let total_elapsed = start.elapsed();

    // Should have completed in reasonable time
    assert!(total_elapsed.as_millis() > 5, "Should take some time");
    assert!(total_elapsed.as_millis() < 100, "Should not take too long");

    // Intervals should vary due to sawtooth pattern and jitter
    let min_interval = intervals.iter().min().unwrap();
    let max_interval = intervals.iter().max().unwrap();
    assert!(
        max_interval > min_interval,
        "Intervals should vary with sawtooth pattern"
    );
}

/// Test engine JSON configuration with all features
#[test]
fn test_engine_full_json_integration() {
    let json = r#"{
        "target": "127.0.0.1",
        "port": 8443,
        "threads": 2,
        "packet_size": 1024,
        "protocol": "tcp",
        "rate_limit": 500,
        "backend": "auto",
        "tls_profile": "firefox_121",
        "tunnel_type": "gre"
    }"#;

    let config = EngineConfig::from_json(json).unwrap();

    // Verify all fields parsed correctly
    assert_eq!(config.target, "127.0.0.1");
    assert_eq!(config.port, 8443);
    assert_eq!(config.threads, 2);
    assert_eq!(config.packet_size, 1024);
    assert_eq!(config.protocol, Protocol::TCP);
    assert_eq!(config.rate_limit, Some(500));
    assert_eq!(config.backend, "auto");
    assert_eq!(config.tls_profile, Some("firefox_121".to_string()));
    assert_eq!(config.tunnel_type, Some("gre".to_string()));

    // Should be able to create engine from this config
    let engine = FloodEngine::new(config);
    assert!(engine.is_ok(), "Should create engine from full JSON config");
}

/// Test error propagation through integrated components
#[test]
fn test_error_propagation_integration() {
    // Test with invalid target
    let config = EngineConfig {
        target: "invalid.nonexistent.domain.test".to_string(),
        port: 80,
        threads: 1,
        ..Default::default()
    };

    let engine = FloodEngine::new(config);
    assert!(engine.is_err(), "Should fail with invalid target");

    // Test TLS spoofer with invalid profile
    let mut spoofer = JA3Spoofer::new();
    assert!(spoofer.set_profile("nonexistent_profile").is_err());

    // Should handle gracefully without panicking
    let hello = spoofer.build_client_hello("test.example.com");
    assert!(hello.is_none(), "Should return None with invalid profile");
}

/// Test concurrent usage of integrated components
#[test]
fn test_concurrent_integration() {
    use std::sync::Arc;
    use std::thread;

    let spoofer = Arc::new(std::sync::Mutex::new(JA3Spoofer::new()));
    let mut handles = vec![];

    // Spawn multiple threads using TLS spoofer
    for i in 0..3 {
        let spoofer_clone = Arc::clone(&spoofer);
        let handle = thread::spawn(move || {
            let profile_name = match i {
                0 => "chrome_120",
                1 => "firefox_121",
                _ => "safari_17",
            };

            let mut spoofer = spoofer_clone.lock().unwrap();
            spoofer.set_profile(profile_name).unwrap();
            let hello = spoofer.build_client_hello(&format!("test{}.example.com", i));
            hello.is_some()
        });
        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(
            result,
            "Each thread should generate Client Hello successfully"
        );
    }
}

/// Test memory usage and cleanup integration
#[test]
fn test_memory_cleanup_integration() {
    // Create and destroy multiple engines to test cleanup
    for i in 0..5 {
        let config = EngineConfig {
            target: "127.0.0.1".to_string(),
            port: 9000 + i as u16,
            threads: 1,
            packet_size: 64,
            protocol: Protocol::UDP,
            rate_limit: Some(1000),
            ..Default::default()
        };

        let mut engine = FloodEngine::new(config).unwrap();
        engine.start().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        engine.stop().unwrap();

        // Engine should be properly cleaned up when dropped
        drop(engine);
    }

    // Create and destroy multiple TLS spoofers
    for _ in 0..10 {
        let mut spoofer = JA3Spoofer::new();
        spoofer.set_profile("chrome_120").unwrap();
        let _ = spoofer.build_client_hello("cleanup-test.example.com");
        drop(spoofer);
    }

    // Should not leak memory or resources
}

/// Test performance of integrated components
#[test]
fn test_integrated_performance() {
    // Test TLS Client Hello generation performance
    let profile = TlsProfile::chrome_120_win11();

    let start = std::time::Instant::now();
    for i in 0..100 {
        let _ = profile.build_client_hello(&format!("perf-test-{}.example.com", i));
    }
    let tls_elapsed = start.elapsed();

    // Should be fast (less than 100ms for 100 generations)
    assert!(
        tls_elapsed.as_millis() < 100,
        "TLS generation should be fast: {}ms for 100 generations",
        tls_elapsed.as_millis()
    );

    // Test precision timer performance
    let timer = PrecisionTimer::new();

    let start = std::time::Instant::now();
    for _ in 0..1000 {
        timer.spin_wait_nanos(1000); // 1μs waits
    }
    let timer_elapsed = start.elapsed();

    // Should complete in reasonable time (less than 100ms)
    assert!(
        timer_elapsed.as_millis() < 100,
        "Timer operations should be fast: {}ms for 1000 operations",
        timer_elapsed.as_millis()
    );
}

/// Property-based integration tests
mod property_tests {
    use super::*;

    proptest! {
        /// Test engine creation with various integrated configurations
        #[test]
        fn prop_integrated_engine_configs(
            port in 1024u16..65535,
            threads in 1usize..=4,
            rate_limit in proptest::option::of(100u64..10_000u64),
            protocol in prop::sample::select(vec![Protocol::UDP, Protocol::TCP, Protocol::HTTP]),
            tls_profile in proptest::option::of(prop::sample::select(vec![
                "chrome_120", "firefox_121", "safari_17"
            ]))
        ) {
            let config = EngineConfig {
                target: "127.0.0.1".to_string(),
                port,
                threads,
                packet_size: 1024,
                protocol,
                rate_limit,
                tls_profile: tls_profile.map(|s| s.to_string()),
                ..Default::default()
            };

            let engine = FloodEngine::new(config);
            prop_assert!(engine.is_ok(), "Engine should be created with valid integrated config");
        }

        /// Test TLS spoofer with various server names and profiles
        #[test]
        fn prop_tls_spoofer_integration(
            profile_name in prop::sample::select(vec![
                "chrome_120", "firefox_121", "safari_17", "iphone_15", "android_14", "curl"
            ]),
            server_name in "[a-z0-9-]{1,15}\\.[a-z]{2,4}"
        ) {
            let mut spoofer = JA3Spoofer::new();

            prop_assert!(spoofer.set_profile(&profile_name).is_ok());

            let hello = spoofer.build_client_hello(&server_name);
            prop_assert!(hello.is_some(), "Should generate Client Hello");

            let hello = hello.unwrap();
            prop_assert!(hello.len() > 50, "Client Hello should be substantial");
            prop_assert_eq!(hello[0], 0x16, "Should be handshake record");

            // Should contain the server name
            let contains_sni = hello.windows(server_name.len())
                .any(|w| w == server_name.as_bytes());
            prop_assert!(contains_sni, "Should contain SNI");
        }

        /// Test traffic shaper integration with various patterns
        #[test]
        fn prop_traffic_shaper_integration(
            base_rate in 100u64..5_000u64,
            pattern in prop::sample::select(vec![
                ShapingPattern::Constant,
                ShapingPattern::Sawtooth,
                ShapingPattern::Pulse,
            ]),
            jitter in 0.0f64..0.3f64
        ) {
            let config = ShapingConfig {
                pattern,
                base_rate,
                jitter_percent: jitter,
                cycle_duration_ms: 1000,
                pulse_duty_cycle: 0.5,
                ..Default::default()
            };

            let mut shaper = TrafficShaper::with_config(config);

            // Should be able to wait without errors
            let start = std::time::Instant::now();
            for _ in 0..3 {
                shaper.wait_next();
            }
            let elapsed = start.elapsed();

            // Should complete in reasonable time (less than 100ms for 3 waits)
            prop_assert!(
                elapsed.as_millis() < 100,
                "Traffic shaping should complete quickly: {}ms",
                elapsed.as_millis()
            );
        }

        /// Test JSON round-trip with integrated configurations
        #[test]
        fn prop_json_roundtrip_integration(
            port in 1024u16..65535,
            threads in 1usize..=8,
            packet_size in 64usize..=9000,
            rate_limit in proptest::option::of(100u64..100_000u64)
        ) {
            let original = EngineConfig {
                target: "192.168.1.100".to_string(),
                port,
                threads,
                packet_size,
                protocol: Protocol::TCP,
                rate_limit,
                backend: "auto".to_string(),
                tls_profile: Some("chrome_120".to_string()),
                tunnel_type: Some("gre".to_string()),
                ..Default::default()
            };

            let json = original.to_json();
            let parsed = EngineConfig::from_json(&json);

            prop_assert!(parsed.is_ok(), "JSON parsing should succeed");
            let parsed = parsed.unwrap();

            prop_assert_eq!(original.target, parsed.target);
            prop_assert_eq!(original.port, parsed.port);
            prop_assert_eq!(original.threads, parsed.threads);
            prop_assert_eq!(original.packet_size, parsed.packet_size);
            prop_assert_eq!(original.protocol, parsed.protocol);
            prop_assert_eq!(original.rate_limit, parsed.rate_limit);
        }
    }
}

/// Test engine lifecycle with integrated features
#[test]
fn test_integrated_engine_lifecycle() {
    let config = EngineConfig {
        target: "127.0.0.1".to_string(),
        port: 8888,
        threads: 2,
        packet_size: 512,
        protocol: Protocol::TCP,
        rate_limit: Some(1000),
        tls_profile: Some("chrome_120".to_string()),
        backend: "auto".to_string(),
        ..Default::default()
    };

    let mut engine = FloodEngine::new(config).unwrap();

    // Test multiple start/stop cycles
    for cycle in 0..3 {
        assert!(
            engine.start().is_ok(),
            "Cycle {} start should succeed",
            cycle
        );
        assert!(engine.is_running(), "Should be running in cycle {}", cycle);

        std::thread::sleep(Duration::from_millis(20));

        assert!(engine.stop().is_ok(), "Cycle {} stop should succeed", cycle);
        assert!(
            !engine.is_running(),
            "Should not be running after cycle {}",
            cycle
        );

        // Stats should accumulate across cycles
        let stats = engine.get_stats();
        assert!(stats.duration >= Duration::from_millis(20 * (cycle + 1) as u64 - 10));
    }
}

/// Test error recovery in integrated scenarios
#[test]
fn test_integrated_error_recovery() {
    // Test engine with invalid TLS profile (should handle gracefully)
    let config = EngineConfig {
        target: "127.0.0.1".to_string(),
        port: 8887,
        threads: 1,
        packet_size: 1024,
        protocol: Protocol::TCP,
        tls_profile: Some("invalid_profile".to_string()),
        ..Default::default()
    };

    // Engine creation should succeed even with invalid TLS profile
    let engine = FloodEngine::new(config);
    assert!(
        engine.is_ok(),
        "Engine should handle invalid TLS profile gracefully"
    );

    // Test TLS spoofer recovery after errors
    let mut spoofer = JA3Spoofer::new();

    // Try invalid profile
    assert!(spoofer.set_profile("invalid").is_err());

    // Should be able to recover and use valid profile
    assert!(spoofer.set_profile("chrome_120").is_ok());
    let hello = spoofer.build_client_hello("recovery-test.example.com");
    assert!(hello.is_some(), "Should recover and generate Client Hello");
}

/// Test resource limits and constraints
#[test]
fn test_integrated_resource_limits() {
    // Test with high thread count (should be limited by system)
    let config = EngineConfig {
        target: "127.0.0.1".to_string(),
        port: 8886,
        threads: 1000, // Very high thread count
        packet_size: 64,
        protocol: Protocol::UDP,
        rate_limit: Some(100),
        ..Default::default()
    };

    // Should handle gracefully (may limit threads internally)
    let engine = FloodEngine::new(config);
    assert!(engine.is_ok(), "Should handle high thread count gracefully");

    // Test with very large packet size
    let config = EngineConfig {
        target: "127.0.0.1".to_string(),
        port: 8885,
        threads: 1,
        packet_size: 65536, // Very large packet
        protocol: Protocol::UDP,
        ..Default::default()
    };

    let engine = FloodEngine::new(config);
    assert!(engine.is_ok(), "Should handle large packet size gracefully");
}

/// Test timing precision in integrated scenarios
#[test]
fn test_integrated_timing_precision() {
    let timer = PrecisionTimer::new();
    let mut shaper = TrafficShaper::new();

    // Measure timing precision across multiple operations
    let mut measurements = Vec::new();

    for _ in 0..10 {
        let start = timer.get_tsc_timestamp();
        shaper.wait_next();
        let end = timer.get_tsc_timestamp();

        let elapsed_ticks = end.saturating_sub(start);
        let elapsed_nanos = timer.ticks_to_nanos(elapsed_ticks);
        measurements.push(elapsed_nanos);
    }

    // Measurements should be consistent (within reasonable variance)
    let min_time = measurements.iter().min().unwrap();
    let max_time = measurements.iter().max().unwrap();

    // Allow for some variance but should be reasonably consistent
    assert!(
        *max_time < min_time * 10,
        "Timing measurements should be reasonably consistent: min={}ns, max={}ns",
        min_time,
        max_time
    );
}
