//! Comprehensive test suite for the Rust engine
//!
//! This module contains unit tests for all major components of the Rust engine,
//! validating the requirements from the military-grade-transformation spec.

pub mod engine_tests;
#[cfg(feature = "p2p_mesh")]
pub mod gossipsub_message_integrity_tests;
pub mod gpu_fallback_property_tests;
pub mod gpu_packet_generation_tests;
pub mod integration_tests;
pub mod timer_tests;
pub mod tls_tests;

// Re-export test utilities
pub use engine_tests::*;
#[cfg(feature = "p2p_mesh")]
pub use gossipsub_message_integrity_tests::*;
pub use gpu_fallback_property_tests::*;
pub use gpu_packet_generation_tests::*;
pub use integration_tests::*;
pub use timer_tests::*;
pub use tls_tests::*;
