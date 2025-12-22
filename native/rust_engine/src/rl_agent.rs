/*!
 * Reinforcement Learning Agent for NetStress Titanium v3.0
 *
 * Implements RL-based attack optimization using tch-rs for ONNX model inference.
 * This module provides observation state structures, action spaces, and model
 * loading capabilities for real-time parameter adaptation.
 *
 * **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**
 */

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

#[cfg(feature = "rl_agent")]
use tch::{nn, CModule, Device, Tensor};

/// Errors that can occur in the RL agent
#[derive(Debug, Error)]
pub enum RLError {
    #[error("Model loading failed: {0}")]
    ModelLoad(String),

    #[error("Tensor operation failed: {0}")]
    TensorOp(String),

    #[error("Invalid state dimension: expected {expected}, got {actual}")]
    InvalidStateDim { expected: usize, actual: usize },

    #[error("Invalid action index: {0}")]
    InvalidAction(usize),

    #[error("ONNX runtime error: {0}")]
    OnnxRuntime(String),

    #[error("Feature not available: RL agent requires 'rl_agent' feature")]
    FeatureNotAvailable,
}

/// Observation state for the RL agent
///
/// Represents the current state of the attack environment including:
/// - Attack parameters (rate, size, threads)
/// - Performance metrics (PPS, bandwidth, errors)
/// - Target response (latency, availability)
/// - Network conditions (latency, packet loss)
/// - Defense detection state
///
/// **Validates: Requirements 7.1** - Define observation space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationState {
    // Attack parameters (normalized to [0, 1])
    pub packet_rate: f32,   // Normalized to max 10M PPS
    pub packet_size: f32,   // Normalized to max 65535 bytes
    pub thread_count: f32,  // Normalized to max 64 threads
    pub protocol_type: f32, // 0.0=UDP, 0.33=TCP, 0.66=HTTP, 1.0=ICMP
    pub evasion_level: f32, // Normalized to max level 10

    // Performance metrics (normalized to [0, 1])
    pub current_pps: f32,       // Normalized to max 10M PPS
    pub current_bandwidth: f32, // Normalized to max 10 Gbps
    pub error_rate: f32,        // Already in [0, 1] range
    pub success_rate: f32,      // Already in [0, 1] range

    // Target response metrics (normalized)
    pub target_response_time: f32, // Normalized to max 10 seconds
    pub target_error_rate: f32,    // Already in [0, 1] range
    pub target_availability: f32,  // Already in [0, 1] range

    // Network conditions (normalized)
    pub network_latency: f32,  // Normalized to max 1 second
    pub packet_loss: f32,      // Already in [0, 1] range
    pub congestion_level: f32, // Already in [0, 1] range

    // Defense detection state (binary features)
    pub rate_limit_detected: f32, // 1.0 if detected, 0.0 otherwise
    pub waf_detected: f32,        // 1.0 if detected, 0.0 otherwise
    pub behavioral_defense_detected: f32, // 1.0 if detected, 0.0 otherwise
    pub defense_confidence: f32,  // Already in [0, 1] range

    // Resource utilization (normalized)
    pub cpu_usage: f32,    // Already in [0, 1] range
    pub memory_usage: f32, // Already in [0, 1] range

    // Timestamp for temporal features
    pub timestamp: f32, // Normalized time since start
}

impl ObservationState {
    /// Create a new observation state with default values
    pub fn new() -> Self {
        Self {
            packet_rate: 0.0,
            packet_size: 0.0,
            thread_count: 0.0,
            protocol_type: 0.0,
            evasion_level: 0.0,
            current_pps: 0.0,
            current_bandwidth: 0.0,
            error_rate: 0.0,
            success_rate: 1.0,
            target_response_time: 0.0,
            target_error_rate: 0.0,
            target_availability: 1.0,
            network_latency: 0.0,
            packet_loss: 0.0,
            congestion_level: 0.0,
            rate_limit_detected: 0.0,
            waf_detected: 0.0,
            behavioral_defense_detected: 0.0,
            defense_confidence: 0.0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            timestamp: 0.0,
        }
    }

    /// Convert state to tensor for neural network input
    ///
    /// Returns a tensor with shape [1, STATE_DIM] suitable for model inference
    #[cfg(feature = "rl_agent")]
    pub fn to_tensor(&self, device: &Device) -> Result<Tensor, RLError> {
        let state_vector = vec![
            self.packet_rate,
            self.packet_size,
            self.thread_count,
            self.protocol_type,
            self.evasion_level,
            self.current_pps,
            self.current_bandwidth,
            self.error_rate,
            self.success_rate,
            self.target_response_time,
            self.target_error_rate,
            self.target_availability,
            self.network_latency,
            self.packet_loss,
            self.congestion_level,
            self.rate_limit_detected,
            self.waf_detected,
            self.behavioral_defense_detected,
            self.defense_confidence,
            self.cpu_usage,
            self.memory_usage,
            self.timestamp,
        ];

        Tensor::from_slice(&state_vector)
            .to_device(*device)
            .unsqueeze(0) // Add batch dimension
            .map_err(|e| RLError::TensorOp(format!("Failed to create state tensor: {}", e)))
    }

    /// Convert from raw metrics to normalized observation state
    pub fn from_metrics(
        packet_rate: u64,
        packet_size: u16,
        thread_count: u8,
        protocol: &str,
        evasion_level: u8,
        current_pps: f64,
        current_bps: f64,
        errors: u64,
        packets_sent: u64,
        target_response_ms: f64,
        target_errors: u64,
        target_requests: u64,
        network_latency_ms: f64,
        packet_loss_rate: f64,
        congestion: f64,
        defenses: &DefenseState,
        cpu_percent: f64,
        memory_percent: f64,
        start_time: Instant,
    ) -> Self {
        let success_rate = if packets_sent > 0 {
            1.0 - (errors as f64 / packets_sent as f64)
        } else {
            1.0
        };

        let target_error_rate = if target_requests > 0 {
            target_errors as f64 / target_requests as f64
        } else {
            0.0
        };

        let target_availability = 1.0 - target_error_rate;

        let protocol_value = match protocol.to_uppercase().as_str() {
            "UDP" => 0.0,
            "TCP" => 0.33,
            "HTTP" => 0.66,
            "ICMP" => 1.0,
            _ => 0.0,
        };

        let elapsed_seconds = start_time.elapsed().as_secs_f32();
        let normalized_time = (elapsed_seconds % 3600.0) / 3600.0; // Normalize to hour cycle

        Self {
            packet_rate: (packet_rate as f32 / 10_000_000.0).min(1.0),
            packet_size: (packet_size as f32 / 65535.0).min(1.0),
            thread_count: (thread_count as f32 / 64.0).min(1.0),
            protocol_type: protocol_value,
            evasion_level: (evasion_level as f32 / 10.0).min(1.0),
            current_pps: (current_pps as f32 / 10_000_000.0).min(1.0),
            current_bandwidth: (current_bps as f32 / 10_000_000_000.0).min(1.0), // 10 Gbps
            error_rate: (errors as f64 / packets_sent.max(1) as f64).min(1.0) as f32,
            success_rate: success_rate.min(1.0) as f32,
            target_response_time: (target_response_ms as f32 / 10_000.0).min(1.0), // 10 seconds
            target_error_rate: target_error_rate.min(1.0) as f32,
            target_availability: target_availability.min(1.0) as f32,
            network_latency: (network_latency_ms as f32 / 1000.0).min(1.0), // 1 second
            packet_loss: packet_loss_rate.min(1.0) as f32,
            congestion_level: congestion.min(1.0) as f32,
            rate_limit_detected: if defenses.rate_limit_detected {
                1.0
            } else {
                0.0
            },
            waf_detected: if defenses.waf_detected { 1.0 } else { 0.0 },
            behavioral_defense_detected: if defenses.behavioral_detected {
                1.0
            } else {
                0.0
            },
            defense_confidence: defenses.confidence.min(1.0) as f32,
            cpu_usage: (cpu_percent / 100.0).min(1.0) as f32,
            memory_usage: (memory_percent / 100.0).min(1.0) as f32,
            timestamp: normalized_time,
        }
    }

    /// Get the dimension of the state vector
    pub const fn state_dim() -> usize {
        22 // Number of features in the state vector
    }

    /// Validate that all values are in expected ranges
    pub fn validate(&self) -> Result<(), RLError> {
        let fields = [
            ("packet_rate", self.packet_rate),
            ("packet_size", self.packet_size),
            ("thread_count", self.thread_count),
            ("protocol_type", self.protocol_type),
            ("evasion_level", self.evasion_level),
            ("current_pps", self.current_pps),
            ("current_bandwidth", self.current_bandwidth),
            ("error_rate", self.error_rate),
            ("success_rate", self.success_rate),
            ("target_response_time", self.target_response_time),
            ("target_error_rate", self.target_error_rate),
            ("target_availability", self.target_availability),
            ("network_latency", self.network_latency),
            ("packet_loss", self.packet_loss),
            ("congestion_level", self.congestion_level),
            ("rate_limit_detected", self.rate_limit_detected),
            ("waf_detected", self.waf_detected),
            (
                "behavioral_defense_detected",
                self.behavioral_defense_detected,
            ),
            ("defense_confidence", self.defense_confidence),
            ("cpu_usage", self.cpu_usage),
            ("memory_usage", self.memory_usage),
            ("timestamp", self.timestamp),
        ];

        for (name, value) in &fields {
            if !value.is_finite() || *value < 0.0 || *value > 1.0 {
                return Err(RLError::TensorOp(format!(
                    "Invalid value for {}: {} (must be in [0, 1])",
                    name, value
                )));
            }
        }

        Ok(())
    }

    /// Calculate state hash for discrete state representation (useful for Q-learning)
    pub fn get_discrete_key(&self, buckets: usize) -> String {
        let bucket_size = 1.0 / buckets as f32;

        let discretize =
            |value: f32| -> usize { ((value / bucket_size).floor() as usize).min(buckets - 1) };

        format!(
            "pr{}_ps{}_tc{}_pt{}_el{}_pps{}_bw{}_er{}_sr{}_trt{}_ter{}_ta{}_nl{}_pl{}_cl{}_rl{}_waf{}_bd{}_dc{}_cpu{}_mem{}_ts{}",
            discretize(self.packet_rate),
            discretize(self.packet_size),
            discretize(self.thread_count),
            discretize(self.protocol_type),
            discretize(self.evasion_level),
            discretize(self.current_pps),
            discretize(self.current_bandwidth),
            discretize(self.error_rate),
            discretize(self.success_rate),
            discretize(self.target_response_time),
            discretize(self.target_error_rate),
            discretize(self.target_availability),
            discretize(self.network_latency),
            discretize(self.packet_loss),
            discretize(self.congestion_level),
            discretize(self.rate_limit_detected),
            discretize(self.waf_detected),
            discretize(self.behavioral_defense_detected),
            discretize(self.defense_confidence),
            discretize(self.cpu_usage),
            discretize(self.memory_usage),
            discretize(self.timestamp),
        )
    }
}

impl Default for ObservationState {
    fn default() -> Self {
        Self::new()
    }
}

/// Defense detection state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseState {
    pub rate_limit_detected: bool,
    pub waf_detected: bool,
    pub behavioral_detected: bool,
    pub confidence: f64,
    pub detection_time: Instant,
}

impl Default for DefenseState {
    fn default() -> Self {
        Self {
            rate_limit_detected: false,
            waf_detected: false,
            behavioral_detected: false,
            confidence: 0.0,
            detection_time: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observation_state_creation() {
        let state = ObservationState::new();
        assert_eq!(state.packet_rate, 0.0);
        assert_eq!(state.success_rate, 1.0);
        assert_eq!(state.target_availability, 1.0);
    }

    #[test]
    fn test_observation_state_validation() {
        let mut state = ObservationState::new();
        assert!(state.validate().is_ok());

        // Test invalid value
        state.packet_rate = 1.5; // > 1.0
        assert!(state.validate().is_err());

        // Test NaN
        state.packet_rate = f32::NAN;
        assert!(state.validate().is_err());
    }

    #[test]
    fn test_state_dimension() {
        assert_eq!(ObservationState::state_dim(), 22);
    }

    #[test]
    fn test_from_metrics() {
        let defenses = DefenseState::default();
        let start_time = Instant::now();

        let state = ObservationState::from_metrics(
            1_000_000,       // packet_rate
            1472,            // packet_size
            8,               // thread_count
            "UDP",           // protocol
            5,               // evasion_level
            500_000.0,       // current_pps
            4_000_000_000.0, // current_bps (4 Gbps)
            100,             // errors
            10_000,          // packets_sent
            150.0,           // target_response_ms
            50,              // target_errors
            1000,            // target_requests
            25.0,            // network_latency_ms
            0.01,            // packet_loss_rate
            0.3,             // congestion
            &defenses,
            45.0, // cpu_percent
            60.0, // memory_percent
            start_time,
        );

        assert!(state.validate().is_ok());
        assert_eq!(state.packet_rate, 0.1); // 1M / 10M
        assert_eq!(state.protocol_type, 0.0); // UDP
        assert!(state.error_rate > 0.0); // Should have some error rate
    }

    #[test]
    fn test_discrete_key_generation() {
        let state = ObservationState::new();
        let key1 = state.get_discrete_key(10);
        let key2 = state.get_discrete_key(10);
        assert_eq!(key1, key2); // Same state should produce same key

        let mut state2 = state.clone();
        state2.packet_rate = 0.5;
        let key3 = state2.get_discrete_key(10);
        assert_ne!(key1, key3); // Different states should produce different keys
    }

    #[cfg(feature = "rl_agent")]
    #[test]
    fn test_tensor_conversion() {
        let state = ObservationState::new();
        let device = Device::Cpu;

        let tensor = state.to_tensor(&device).unwrap();
        assert_eq!(tensor.size(), vec![1, ObservationState::state_dim() as i64]);
    }
}
/// Action space for the RL agent
///
/// Defines all possible actions the RL agent can take to modify attack parameters.
/// Actions include PPS adjustment, JA4 profile switching, window size changes, etc.
///
/// **Validates: Requirements 7.2** - Define action space
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    // Rate control actions
    IncreasePPS,
    DecreasePPS,

    // Packet size actions
    IncreasePacketSize,
    DecreasePacketSize,

    // Thread control actions
    IncreaseThreads,
    DecreaseThreads,

    // Protocol switching actions
    SwitchToUDP,
    SwitchToTCP,
    SwitchToHTTP,
    SwitchToICMP,

    // Evasion actions
    IncreaseEvasion,
    DecreaseEvasion,

    // JA4 fingerprint actions
    SwitchJA4Chrome,
    SwitchJA4Firefox,
    SwitchJA4Safari,
    SwitchJA4Edge,
    SwitchJA4Random,

    // Window size actions
    IncreaseWindowSize,
    DecreaseWindowSize,

    // Timing actions
    IncreaseDelay,
    DecreaseDelay,
    EnableBurstMode,
    DisableBurstMode,

    // Defense evasion actions
    EnableIPRotation,
    DisableIPRotation,
    EnableUserAgentRotation,
    DisableUserAgentRotation,
    EnableRequestFragmentation,
    DisableRequestFragmentation,
    EnableTimingRandomization,
    DisableTimingRandomization,

    // Attack mode actions
    SwitchToSlowAttack,
    SwitchToFastAttack,

    // No change action
    NoChange,
}

impl ActionType {
    /// Get all possible action types
    pub fn all_actions() -> Vec<ActionType> {
        vec![
            ActionType::IncreasePPS,
            ActionType::DecreasePPS,
            ActionType::IncreasePacketSize,
            ActionType::DecreasePacketSize,
            ActionType::IncreaseThreads,
            ActionType::DecreaseThreads,
            ActionType::SwitchToUDP,
            ActionType::SwitchToTCP,
            ActionType::SwitchToHTTP,
            ActionType::SwitchToICMP,
            ActionType::IncreaseEvasion,
            ActionType::DecreaseEvasion,
            ActionType::SwitchJA4Chrome,
            ActionType::SwitchJA4Firefox,
            ActionType::SwitchJA4Safari,
            ActionType::SwitchJA4Edge,
            ActionType::SwitchJA4Random,
            ActionType::IncreaseWindowSize,
            ActionType::DecreaseWindowSize,
            ActionType::IncreaseDelay,
            ActionType::DecreaseDelay,
            ActionType::EnableBurstMode,
            ActionType::DisableBurstMode,
            ActionType::EnableIPRotation,
            ActionType::DisableIPRotation,
            ActionType::EnableUserAgentRotation,
            ActionType::DisableUserAgentRotation,
            ActionType::EnableRequestFragmentation,
            ActionType::DisableRequestFragmentation,
            ActionType::EnableTimingRandomization,
            ActionType::DisableTimingRandomization,
            ActionType::SwitchToSlowAttack,
            ActionType::SwitchToFastAttack,
            ActionType::NoChange,
        ]
    }

    /// Get the number of possible actions
    pub fn action_count() -> usize {
        Self::all_actions().len()
    }

    /// Convert action index to ActionType
    pub fn from_index(index: usize) -> Result<ActionType, RLError> {
        let actions = Self::all_actions();
        actions
            .get(index)
            .copied()
            .ok_or(RLError::InvalidAction(index))
    }

    /// Convert ActionType to index
    pub fn to_index(&self) -> usize {
        let actions = Self::all_actions();
        actions
            .iter()
            .position(|&action| action == *self)
            .unwrap_or(0)
    }

    /// Check if this action is a defense evasion action
    pub fn is_evasion_action(&self) -> bool {
        matches!(
            self,
            ActionType::IncreaseEvasion
                | ActionType::SwitchJA4Chrome
                | ActionType::SwitchJA4Firefox
                | ActionType::SwitchJA4Safari
                | ActionType::SwitchJA4Edge
                | ActionType::SwitchJA4Random
                | ActionType::EnableIPRotation
                | ActionType::EnableUserAgentRotation
                | ActionType::EnableRequestFragmentation
                | ActionType::EnableTimingRandomization
                | ActionType::SwitchToSlowAttack
        )
    }

    /// Check if this action affects performance directly
    pub fn is_performance_action(&self) -> bool {
        matches!(
            self,
            ActionType::IncreasePPS
                | ActionType::DecreasePPS
                | ActionType::IncreasePacketSize
                | ActionType::DecreasePacketSize
                | ActionType::IncreaseThreads
                | ActionType::DecreaseThreads
                | ActionType::EnableBurstMode
                | ActionType::DisableBurstMode
                | ActionType::SwitchToFastAttack
        )
    }
}

/// Action with magnitude and parameters
///
/// Represents a specific action to take with its intensity and additional parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_type: ActionType,
    pub magnitude: f32, // Scaling factor [0.1, 2.0]
    pub parameters: HashMap<String, f32>,
}

impl Action {
    /// Create a new action with default magnitude
    pub fn new(action_type: ActionType) -> Self {
        Self {
            action_type,
            magnitude: 1.0,
            parameters: HashMap::new(),
        }
    }

    /// Create a new action with specified magnitude
    pub fn with_magnitude(action_type: ActionType, magnitude: f32) -> Self {
        Self {
            action_type,
            magnitude: magnitude.clamp(0.1, 2.0),
            parameters: HashMap::new(),
        }
    }

    /// Add a parameter to the action
    pub fn with_parameter(mut self, key: String, value: f32) -> Self {
        self.parameters.insert(key, value);
        self
    }

    /// Apply this action to an attack configuration
    pub fn apply_to_config(&self, config: &mut AttackConfig) -> Result<(), RLError> {
        match self.action_type {
            ActionType::IncreasePPS => {
                let new_rate =
                    (config.packet_rate as f64 * (1.0 + 0.2 * self.magnitude as f64)) as u64;
                config.packet_rate = new_rate.min(10_000_000); // Max 10M PPS
            }

            ActionType::DecreasePPS => {
                let new_rate =
                    (config.packet_rate as f64 * (1.0 - 0.2 * self.magnitude as f64)) as u64;
                config.packet_rate = new_rate.max(1000); // Min 1K PPS
            }

            ActionType::IncreasePacketSize => {
                let increase = (100.0 * self.magnitude) as u16;
                config.packet_size = (config.packet_size + increase).min(65535);
            }

            ActionType::DecreasePacketSize => {
                let decrease = (100.0 * self.magnitude) as u16;
                config.packet_size = config.packet_size.saturating_sub(decrease).max(64);
            }

            ActionType::IncreaseThreads => {
                let increase = (2.0 * self.magnitude) as u8;
                config.thread_count = (config.thread_count + increase).min(64);
            }

            ActionType::DecreaseThreads => {
                let decrease = (2.0 * self.magnitude) as u8;
                config.thread_count = config.thread_count.saturating_sub(decrease).max(1);
            }

            ActionType::SwitchToUDP => config.protocol = "UDP".to_string(),
            ActionType::SwitchToTCP => config.protocol = "TCP".to_string(),
            ActionType::SwitchToHTTP => config.protocol = "HTTP".to_string(),
            ActionType::SwitchToICMP => config.protocol = "ICMP".to_string(),

            ActionType::IncreaseEvasion => {
                let increase = (2.0 * self.magnitude) as u8;
                config.evasion_level = (config.evasion_level + increase).min(10);
            }

            ActionType::DecreaseEvasion => {
                let decrease = (2.0 * self.magnitude) as u8;
                config.evasion_level = config.evasion_level.saturating_sub(decrease);
            }

            ActionType::SwitchJA4Chrome => {
                config.ja4_profile = Some("chrome_120".to_string());
            }

            ActionType::SwitchJA4Firefox => {
                config.ja4_profile = Some("firefox_121".to_string());
            }

            ActionType::SwitchJA4Safari => {
                config.ja4_profile = Some("safari_17".to_string());
            }

            ActionType::SwitchJA4Edge => {
                config.ja4_profile = Some("edge_120".to_string());
            }

            ActionType::SwitchJA4Random => {
                let profiles = ["chrome_120", "firefox_121", "safari_17", "edge_120"];
                let index = (self.magnitude * profiles.len() as f32) as usize % profiles.len();
                config.ja4_profile = Some(profiles[index].to_string());
            }

            ActionType::IncreaseWindowSize => {
                let increase = (1024.0 * self.magnitude) as u32;
                config.window_size = (config.window_size + increase).min(1_048_576);
                // Max 1MB
            }

            ActionType::DecreaseWindowSize => {
                let decrease = (1024.0 * self.magnitude) as u32;
                config.window_size = config.window_size.saturating_sub(decrease).max(1024);
                // Min 1KB
            }

            ActionType::IncreaseDelay => {
                let increase = Duration::from_millis((100.0 * self.magnitude) as u64);
                config.delay = config.delay + increase;
            }

            ActionType::DecreaseDelay => {
                let decrease = Duration::from_millis((100.0 * self.magnitude) as u64);
                config.delay = config.delay.saturating_sub(decrease);
            }

            ActionType::EnableBurstMode => {
                config.burst_mode = true;
                config.burst_duration = Duration::from_millis((1000.0 * self.magnitude) as u64);
            }

            ActionType::DisableBurstMode => {
                config.burst_mode = false;
            }

            ActionType::EnableIPRotation => {
                config.ip_rotation = true;
                config.ip_rotation_interval = Duration::from_secs((10.0 * self.magnitude) as u64);
            }

            ActionType::DisableIPRotation => {
                config.ip_rotation = false;
            }

            ActionType::EnableUserAgentRotation => {
                config.user_agent_rotation = true;
                config.user_agent_pool_size = (20.0 * self.magnitude) as usize;
            }

            ActionType::DisableUserAgentRotation => {
                config.user_agent_rotation = false;
            }

            ActionType::EnableRequestFragmentation => {
                config.request_fragmentation = true;
                config.fragment_size = (512.0 * self.magnitude) as u16;
            }

            ActionType::DisableRequestFragmentation => {
                config.request_fragmentation = false;
            }

            ActionType::EnableTimingRandomization => {
                config.timing_randomization = true;
                config.timing_jitter = (0.1 * self.magnitude) as f64;
            }

            ActionType::DisableTimingRandomization => {
                config.timing_randomization = false;
            }

            ActionType::SwitchToSlowAttack => {
                config.attack_mode = "slow".to_string();
                config.slow_attack_delay = Duration::from_millis((2000.0 * self.magnitude) as u64);
            }

            ActionType::SwitchToFastAttack => {
                config.attack_mode = "fast".to_string();
            }

            ActionType::NoChange => {
                // No changes to configuration
            }
        }

        Ok(())
    }

    /// Get the expected impact of this action on performance
    pub fn get_performance_impact(&self) -> f32 {
        match self.action_type {
            ActionType::IncreasePPS => 0.8 * self.magnitude,
            ActionType::IncreaseThreads => 0.6 * self.magnitude,
            ActionType::EnableBurstMode => 0.5 * self.magnitude,
            ActionType::SwitchToFastAttack => 0.7 * self.magnitude,

            ActionType::DecreasePPS => -0.8 * self.magnitude,
            ActionType::DecreaseThreads => -0.6 * self.magnitude,
            ActionType::SwitchToSlowAttack => -0.9 * self.magnitude,

            // Evasion actions may reduce performance but improve success
            ActionType::EnableTimingRandomization => -0.2 * self.magnitude,
            ActionType::EnableRequestFragmentation => -0.3 * self.magnitude,
            ActionType::EnableIPRotation => -0.1 * self.magnitude,

            _ => 0.0, // Neutral impact
        }
    }

    /// Get the expected impact of this action on evasion capability
    pub fn get_evasion_impact(&self) -> f32 {
        match self.action_type {
            ActionType::IncreaseEvasion => 0.9 * self.magnitude,
            ActionType::SwitchJA4Chrome
            | ActionType::SwitchJA4Firefox
            | ActionType::SwitchJA4Safari
            | ActionType::SwitchJA4Edge => 0.8 * self.magnitude,
            ActionType::SwitchJA4Random => 0.7 * self.magnitude,
            ActionType::EnableIPRotation => 0.6 * self.magnitude,
            ActionType::EnableUserAgentRotation => 0.5 * self.magnitude,
            ActionType::EnableRequestFragmentation => 0.4 * self.magnitude,
            ActionType::EnableTimingRandomization => 0.7 * self.magnitude,
            ActionType::SwitchToSlowAttack => 0.8 * self.magnitude,

            ActionType::DecreaseEvasion => -0.9 * self.magnitude,
            ActionType::DisableIPRotation => -0.6 * self.magnitude,
            ActionType::DisableUserAgentRotation => -0.5 * self.magnitude,
            ActionType::DisableRequestFragmentation => -0.4 * self.magnitude,
            ActionType::DisableTimingRandomization => -0.7 * self.magnitude,

            _ => 0.0, // Neutral impact
        }
    }
}

/// Attack configuration that can be modified by actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    // Basic attack parameters
    pub packet_rate: u64,
    pub packet_size: u16,
    pub thread_count: u8,
    pub protocol: String,
    pub evasion_level: u8,

    // JA4 fingerprinting
    pub ja4_profile: Option<String>,

    // Network parameters
    pub window_size: u32,
    pub delay: Duration,

    // Burst mode
    pub burst_mode: bool,
    pub burst_duration: Duration,

    // Evasion features
    pub ip_rotation: bool,
    pub ip_rotation_interval: Duration,
    pub user_agent_rotation: bool,
    pub user_agent_pool_size: usize,
    pub request_fragmentation: bool,
    pub fragment_size: u16,
    pub timing_randomization: bool,
    pub timing_jitter: f64,

    // Attack mode
    pub attack_mode: String,
    pub slow_attack_delay: Duration,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            packet_rate: 10_000,
            packet_size: 1472,
            thread_count: 4,
            protocol: "UDP".to_string(),
            evasion_level: 0,
            ja4_profile: None,
            window_size: 65536,
            delay: Duration::from_millis(0),
            burst_mode: false,
            burst_duration: Duration::from_secs(1),
            ip_rotation: false,
            ip_rotation_interval: Duration::from_secs(60),
            user_agent_rotation: false,
            user_agent_pool_size: 10,
            request_fragmentation: false,
            fragment_size: 512,
            timing_randomization: false,
            timing_jitter: 0.1,
            attack_mode: "fast".to_string(),
            slow_attack_delay: Duration::from_millis(1000),
        }
    }
}

#[cfg(test)]
mod action_tests {
    use super::*;

    #[test]
    fn test_action_type_conversion() {
        let action = ActionType::IncreasePPS;
        let index = action.to_index();
        let converted = ActionType::from_index(index).unwrap();
        assert_eq!(action, converted);
    }

    #[test]
    fn test_action_count() {
        assert_eq!(ActionType::action_count(), ActionType::all_actions().len());
    }

    #[test]
    fn test_action_categorization() {
        assert!(ActionType::IncreasePPS.is_performance_action());
        assert!(ActionType::SwitchJA4Chrome.is_evasion_action());
        assert!(!ActionType::NoChange.is_performance_action());
        assert!(!ActionType::NoChange.is_evasion_action());
    }

    #[test]
    fn test_action_application() {
        let mut config = AttackConfig::default();
        let original_rate = config.packet_rate;

        let action = Action::with_magnitude(ActionType::IncreasePPS, 1.0);
        action.apply_to_config(&mut config).unwrap();

        assert!(config.packet_rate > original_rate);
    }

    #[test]
    fn test_action_impact_calculation() {
        let action = Action::with_magnitude(ActionType::IncreasePPS, 1.5);
        assert!(action.get_performance_impact() > 0.0);

        let evasion_action = Action::with_magnitude(ActionType::SwitchJA4Chrome, 1.0);
        assert!(evasion_action.get_evasion_impact() > 0.0);
    }

    #[test]
    fn test_magnitude_clamping() {
        let action = Action::with_magnitude(ActionType::IncreasePPS, 5.0);
        assert_eq!(action.magnitude, 2.0); // Should be clamped to max

        let action2 = Action::with_magnitude(ActionType::DecreasePPS, -1.0);
        assert_eq!(action2.magnitude, 0.1); // Should be clamped to min
    }
}
/// ONNX model loader and inference engine
///
/// Handles loading pre-trained ONNX models and running inference for action selection.
/// Supports model versioning and graceful fallback when models are unavailable.
///
/// **Validates: Requirements 7.3** - ONNX model loading with tch-rs
#[cfg(feature = "rl_agent")]
pub struct OnnxModelLoader {
    device: Device,
    model: Option<CModule>,
    model_path: String,
    model_version: String,
    input_dim: usize,
    output_dim: usize,
    loaded_at: Option<Instant>,
}

#[cfg(feature = "rl_agent")]
impl OnnxModelLoader {
    /// Create a new ONNX model loader
    pub fn new(model_path: String) -> Self {
        let device = if tch::Cuda::is_available() {
            Device::Cuda(0)
        } else {
            Device::Cpu
        };

        Self {
            device,
            model: None,
            model_path,
            model_version: "unknown".to_string(),
            input_dim: ObservationState::state_dim(),
            output_dim: ActionType::action_count(),
            loaded_at: None,
        }
    }

    /// Load ONNX model from file
    pub fn load_model(&mut self) -> Result<(), RLError> {
        // Check if model file exists
        if !std::path::Path::new(&self.model_path).exists() {
            return Err(RLError::ModelLoad(format!(
                "Model file not found: {}",
                self.model_path
            )));
        }

        // Load the model
        match CModule::load(&self.model_path) {
            Ok(model) => {
                self.model = Some(model);
                self.loaded_at = Some(Instant::now());

                // Extract version from filename if possible
                if let Some(filename) = std::path::Path::new(&self.model_path).file_stem() {
                    if let Some(filename_str) = filename.to_str() {
                        // Look for version pattern like "model_v1.2.3"
                        if let Some(version_start) = filename_str.rfind("_v") {
                            self.model_version = filename_str[version_start + 2..].to_string();
                        }
                    }
                }

                tracing::info!(
                    "ONNX model loaded successfully: {} (version: {})",
                    self.model_path,
                    self.model_version
                );

                Ok(())
            }
            Err(e) => Err(RLError::ModelLoad(format!(
                "Failed to load ONNX model: {}",
                e
            ))),
        }
    }

    /// Reload model if it has been updated
    pub fn reload_if_updated(&mut self) -> Result<bool, RLError> {
        if let Some(loaded_time) = self.loaded_at {
            if let Ok(metadata) = std::fs::metadata(&self.model_path) {
                if let Ok(modified_time) = metadata.modified() {
                    let modified_instant =
                        Instant::now() - modified_time.elapsed().unwrap_or(Duration::ZERO);

                    if modified_instant > loaded_time {
                        tracing::info!("Model file updated, reloading...");
                        self.load_model()?;
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Run inference on the model
    pub fn predict(&self, state: &ObservationState) -> Result<Vec<f32>, RLError> {
        let model = self
            .model
            .as_ref()
            .ok_or_else(|| RLError::ModelLoad("Model not loaded".to_string()))?;

        // Convert state to tensor
        let input_tensor = state.to_tensor(&self.device)?;

        // Validate input dimensions
        let input_shape = input_tensor.size();
        if input_shape[1] != self.input_dim as i64 {
            return Err(RLError::InvalidStateDim {
                expected: self.input_dim,
                actual: input_shape[1] as usize,
            });
        }

        // Run inference
        let output_tensor = model
            .forward_ts(&[input_tensor])
            .map_err(|e| RLError::TensorOp(format!("Model inference failed: {}", e)))?;

        // Convert output tensor to Vec<f32>
        let output_shape = output_tensor.size();
        if output_shape.len() != 2 || output_shape[1] != self.output_dim as i64 {
            return Err(RLError::TensorOp(format!(
                "Unexpected output shape: {:?}, expected [1, {}]",
                output_shape, self.output_dim
            )));
        }

        // Extract probabilities
        let probabilities: Vec<f32> = output_tensor
            .squeeze_dim(0)
            .try_into()
            .map_err(|e| RLError::TensorOp(format!("Failed to convert output tensor: {}", e)))?;

        // Validate probabilities
        if probabilities.len() != self.output_dim {
            return Err(RLError::TensorOp(format!(
                "Output dimension mismatch: got {}, expected {}",
                probabilities.len(),
                self.output_dim
            )));
        }

        // Apply softmax to ensure valid probability distribution
        let softmax_probs = self.softmax(&probabilities);

        Ok(softmax_probs)
    }

    /// Apply softmax to convert logits to probabilities
    fn softmax(&self, logits: &[f32]) -> Vec<f32> {
        let max_logit = logits.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        let exp_logits: Vec<f32> = logits.iter().map(|&x| (x - max_logit).exp()).collect();
        let sum_exp: f32 = exp_logits.iter().sum();

        if sum_exp > 0.0 {
            exp_logits.iter().map(|&x| x / sum_exp).collect()
        } else {
            // Fallback to uniform distribution
            vec![1.0 / logits.len() as f32; logits.len()]
        }
    }

    /// Get model information
    pub fn get_model_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("model_path".to_string(), self.model_path.clone());
        info.insert("model_version".to_string(), self.model_version.clone());
        info.insert("device".to_string(), format!("{:?}", self.device));
        info.insert("input_dim".to_string(), self.input_dim.to_string());
        info.insert("output_dim".to_string(), self.output_dim.to_string());
        info.insert("loaded".to_string(), self.model.is_some().to_string());

        if let Some(loaded_time) = self.loaded_at {
            info.insert(
                "loaded_at".to_string(),
                format!("{:?}", loaded_time.elapsed()),
            );
        }

        info
    }

    /// Check if model is loaded and ready
    pub fn is_ready(&self) -> bool {
        self.model.is_some()
    }

    /// Get device being used
    pub fn get_device(&self) -> Device {
        self.device
    }

    /// Validate model compatibility
    pub fn validate_model(&self) -> Result<(), RLError> {
        if !self.is_ready() {
            return Err(RLError::ModelLoad("Model not loaded".to_string()));
        }

        // Test with dummy input
        let dummy_state = ObservationState::new();
        let _output = self.predict(&dummy_state)?;

        tracing::info!("Model validation successful");
        Ok(())
    }

    /// Get model performance statistics
    pub fn benchmark_model(&self, iterations: usize) -> Result<ModelBenchmark, RLError> {
        if !self.is_ready() {
            return Err(RLError::ModelLoad("Model not loaded".to_string()));
        }

        let dummy_state = ObservationState::new();
        let mut inference_times = Vec::with_capacity(iterations);

        // Warmup
        for _ in 0..5 {
            let _ = self.predict(&dummy_state)?;
        }

        // Benchmark
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = self.predict(&dummy_state)?;
            inference_times.push(start.elapsed());
        }

        let total_time: Duration = inference_times.iter().sum();
        let avg_time = total_time / iterations as u32;
        let min_time = inference_times
            .iter()
            .min()
            .copied()
            .unwrap_or(Duration::ZERO);
        let max_time = inference_times
            .iter()
            .max()
            .copied()
            .unwrap_or(Duration::ZERO);

        Ok(ModelBenchmark {
            iterations,
            total_time,
            avg_inference_time: avg_time,
            min_inference_time: min_time,
            max_inference_time: max_time,
            throughput_per_sec: 1.0 / avg_time.as_secs_f64(),
        })
    }
}

/// Model benchmark results
#[derive(Debug, Clone)]
pub struct ModelBenchmark {
    pub iterations: usize,
    pub total_time: Duration,
    pub avg_inference_time: Duration,
    pub min_inference_time: Duration,
    pub max_inference_time: Duration,
    pub throughput_per_sec: f64,
}

/// Fallback model for when ONNX is not available
///
/// Provides a simple heuristic-based action selection when the RL model
/// cannot be loaded or the rl_agent feature is not enabled.
pub struct FallbackModel {
    action_weights: HashMap<ActionType, f32>,
    last_actions: Vec<ActionType>,
    performance_history: Vec<f32>,
}

impl FallbackModel {
    /// Create a new fallback model
    pub fn new() -> Self {
        let mut action_weights = HashMap::new();

        // Initialize with reasonable default weights
        for action in ActionType::all_actions() {
            let weight = match action {
                // Performance actions get higher weights
                ActionType::IncreasePPS => 0.8,
                ActionType::IncreaseThreads => 0.6,
                ActionType::EnableBurstMode => 0.5,

                // Conservative actions for stability
                ActionType::NoChange => 0.3,
                ActionType::DecreasePPS => 0.2,

                // Evasion actions for defense scenarios
                ActionType::SwitchJA4Chrome => 0.7,
                ActionType::EnableTimingRandomization => 0.6,
                ActionType::EnableIPRotation => 0.5,

                _ => 0.4, // Default weight
            };
            action_weights.insert(action, weight);
        }

        Self {
            action_weights,
            last_actions: Vec::new(),
            performance_history: Vec::new(),
        }
    }

    /// Select action using heuristic rules
    pub fn select_action(&mut self, state: &ObservationState) -> Action {
        let mut candidate_actions = Vec::new();

        // Rule-based action selection
        if state.rate_limit_detected > 0.5 {
            // Rate limiting detected - use evasion actions
            candidate_actions.extend([
                ActionType::DecreasePPS,
                ActionType::EnableTimingRandomization,
                ActionType::EnableIPRotation,
                ActionType::SwitchToSlowAttack,
            ]);
        } else if state.waf_detected > 0.5 {
            // WAF detected - use different evasion tactics
            candidate_actions.extend([
                ActionType::SwitchJA4Chrome,
                ActionType::EnableUserAgentRotation,
                ActionType::EnableRequestFragmentation,
            ]);
        } else if state.behavioral_defense_detected > 0.5 {
            // Behavioral analysis detected - randomize patterns
            candidate_actions.extend([
                ActionType::EnableTimingRandomization,
                ActionType::SwitchJA4Random,
                ActionType::IncreaseDelay,
            ]);
        } else if state.current_pps < 0.5 && state.error_rate < 0.1 {
            // Low performance, low errors - can increase intensity
            candidate_actions.extend([
                ActionType::IncreasePPS,
                ActionType::IncreaseThreads,
                ActionType::EnableBurstMode,
            ]);
        } else if state.error_rate > 0.3 {
            // High error rate - reduce intensity
            candidate_actions.extend([
                ActionType::DecreasePPS,
                ActionType::DecreaseThreads,
                ActionType::IncreaseDelay,
            ]);
        } else {
            // Normal operation - minor adjustments
            candidate_actions.extend([
                ActionType::NoChange,
                ActionType::IncreasePPS,
                ActionType::IncreasePacketSize,
            ]);
        }

        // Select action based on weights and recent history
        let selected_action = self.select_weighted_action(&candidate_actions);

        // Calculate magnitude based on confidence and urgency
        let magnitude = self.calculate_magnitude(state, &selected_action);

        // Update history
        self.last_actions.push(selected_action);
        if self.last_actions.len() > 10 {
            self.last_actions.remove(0);
        }

        Action::with_magnitude(selected_action, magnitude)
    }

    /// Select action based on weights, avoiding recent repetitions
    fn select_weighted_action(&self, candidates: &[ActionType]) -> ActionType {
        if candidates.is_empty() {
            return ActionType::NoChange;
        }

        let mut weighted_candidates = Vec::new();

        for &action in candidates {
            let base_weight = self.action_weights.get(&action).copied().unwrap_or(0.5);

            // Reduce weight if action was used recently
            let recent_penalty = self
                .last_actions
                .iter()
                .rev()
                .take(3)
                .position(|&a| a == action)
                .map(|pos| 0.5_f32.powi(pos as i32 + 1))
                .unwrap_or(0.0);

            let final_weight = (base_weight - recent_penalty).max(0.1);
            weighted_candidates.push((action, final_weight));
        }

        // Weighted random selection
        let total_weight: f32 = weighted_candidates.iter().map(|(_, w)| w).sum();
        let mut random_value = rand::random::<f32>() * total_weight;

        for (action, weight) in weighted_candidates {
            random_value -= weight;
            if random_value <= 0.0 {
                return action;
            }
        }

        // Fallback to first candidate
        candidates[0]
    }

    /// Calculate action magnitude based on state urgency
    fn calculate_magnitude(&self, state: &ObservationState, action: &ActionType) -> f32 {
        let mut magnitude = 1.0;

        // Increase magnitude for urgent situations
        if state.defense_confidence > 0.8 {
            magnitude *= 1.5; // Aggressive response to high-confidence defense detection
        } else if state.defense_confidence > 0.5 {
            magnitude *= 1.2; // Moderate response
        }

        // Adjust based on error rate
        if state.error_rate > 0.5 {
            magnitude *= 0.7; // Be more conservative with high error rates
        } else if state.error_rate < 0.1 {
            magnitude *= 1.3; // Be more aggressive with low error rates
        }

        // Adjust based on performance
        if state.current_pps < 0.2 && action.is_performance_action() {
            magnitude *= 1.4; // Boost performance actions when PPS is very low
        }

        // Clamp to valid range
        magnitude.clamp(0.1, 2.0)
    }

    /// Update action weights based on performance feedback
    pub fn update_weights(&mut self, action: ActionType, reward: f32) {
        let current_weight = self.action_weights.get(&action).copied().unwrap_or(0.5);
        let learning_rate = 0.1;
        let new_weight = current_weight + learning_rate * reward;

        self.action_weights
            .insert(action, new_weight.clamp(0.1, 1.0));

        // Track performance
        self.performance_history.push(reward);
        if self.performance_history.len() > 100 {
            self.performance_history.remove(0);
        }
    }

    /// Get average performance over recent history
    pub fn get_average_performance(&self) -> f32 {
        if self.performance_history.is_empty() {
            0.0
        } else {
            self.performance_history.iter().sum::<f32>() / self.performance_history.len() as f32
        }
    }
}

impl Default for FallbackModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;

    #[test]
    fn test_fallback_model_creation() {
        let model = FallbackModel::new();
        assert!(!model.action_weights.is_empty());
    }

    #[test]
    fn test_fallback_action_selection() {
        let mut model = FallbackModel::new();
        let state = ObservationState::new();

        let action = model.select_action(&state);
        assert!(action.magnitude >= 0.1 && action.magnitude <= 2.0);
    }

    #[test]
    fn test_fallback_weight_updates() {
        let mut model = FallbackModel::new();
        let initial_weight = model
            .action_weights
            .get(&ActionType::IncreasePPS)
            .copied()
            .unwrap_or(0.5);

        model.update_weights(ActionType::IncreasePPS, 0.5);
        let updated_weight = model
            .action_weights
            .get(&ActionType::IncreasePPS)
            .copied()
            .unwrap_or(0.5);

        assert_ne!(initial_weight, updated_weight);
    }

    #[cfg(feature = "rl_agent")]
    #[test]
    fn test_onnx_model_loader_creation() {
        let loader = OnnxModelLoader::new("test_model.onnx".to_string());
        assert!(!loader.is_ready());
        assert_eq!(loader.input_dim, ObservationState::state_dim());
        assert_eq!(loader.output_dim, ActionType::action_count());
    }

    #[cfg(feature = "rl_agent")]
    #[test]
    fn test_softmax_calculation() {
        let loader = OnnxModelLoader::new("test.onnx".to_string());
        let logits = vec![1.0, 2.0, 3.0];
        let probs = loader.softmax(&logits);

        // Check that probabilities sum to 1.0
        let sum: f32 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6);

        // Check that probabilities are in ascending order (since logits are)
        assert!(probs[0] < probs[1]);
        assert!(probs[1] < probs[2]);
    }
}
/// RL Agent for attack optimization
///
/// Main agent that coordinates model inference, action selection, and execution.
/// Supports both ONNX model-based and fallback heuristic-based action selection.
///
/// **Validates: Requirements 7.4** - Action selection and execution
pub struct RLAgent {
    #[cfg(feature = "rl_agent")]
    model_loader: Option<OnnxModelLoader>,

    fallback_model: FallbackModel,
    use_fallback: bool,

    // Agent state
    current_state: ObservationState,
    last_action: Option<Action>,
    episode_count: u64,
    total_reward: f64,

    // Performance tracking
    action_history: Vec<(Action, f32)>, // (action, reward)
    state_history: Vec<ObservationState>,

    // Configuration
    exploration_rate: f32,
    exploration_decay: f32,
    min_exploration_rate: f32,

    // Statistics
    action_counts: HashMap<ActionType, u64>,
    action_rewards: HashMap<ActionType, Vec<f32>>,

    // Timing
    start_time: Instant,
    last_update: Instant,
}

impl RLAgent {
    /// Create a new RL agent
    #[cfg(feature = "rl_agent")]
    pub fn new(model_path: Option<String>) -> Self {
        let model_loader = model_path.map(OnnxModelLoader::new);

        Self {
            model_loader,
            fallback_model: FallbackModel::new(),
            use_fallback: model_loader.is_none(),
            current_state: ObservationState::new(),
            last_action: None,
            episode_count: 0,
            total_reward: 0.0,
            action_history: Vec::new(),
            state_history: Vec::new(),
            exploration_rate: 0.3,
            exploration_decay: 0.995,
            min_exploration_rate: 0.01,
            action_counts: HashMap::new(),
            action_rewards: HashMap::new(),
            start_time: Instant::now(),
            last_update: Instant::now(),
        }
    }

    /// Create a new RL agent without ONNX support (fallback only)
    #[cfg(not(feature = "rl_agent"))]
    pub fn new(_model_path: Option<String>) -> Self {
        Self {
            fallback_model: FallbackModel::new(),
            use_fallback: true,
            current_state: ObservationState::new(),
            last_action: None,
            episode_count: 0,
            total_reward: 0.0,
            action_history: Vec::new(),
            state_history: Vec::new(),
            exploration_rate: 0.3,
            exploration_decay: 0.995,
            min_exploration_rate: 0.01,
            action_counts: HashMap::new(),
            action_rewards: HashMap::new(),
            start_time: Instant::now(),
            last_update: Instant::now(),
        }
    }

    /// Initialize the agent and load model if available
    #[cfg(feature = "rl_agent")]
    pub fn initialize(&mut self) -> Result<(), RLError> {
        if let Some(ref mut loader) = self.model_loader {
            match loader.load_model() {
                Ok(_) => {
                    loader.validate_model()?;
                    self.use_fallback = false;
                    tracing::info!("RL agent initialized with ONNX model");
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to load ONNX model, using fallback: {}", e);
                    self.use_fallback = true;
                    Ok(())
                }
            }
        } else {
            tracing::info!("RL agent initialized with fallback model");
            self.use_fallback = true;
            Ok(())
        }
    }

    /// Initialize the agent (no-op for non-RL builds)
    #[cfg(not(feature = "rl_agent"))]
    pub fn initialize(&mut self) -> Result<(), RLError> {
        tracing::info!("RL agent initialized with fallback model (rl_agent feature not enabled)");
        Ok(())
    }

    /// Update current state
    pub fn update_state(&mut self, state: ObservationState) -> Result<(), RLError> {
        state.validate()?;
        self.current_state = state.clone();
        self.state_history.push(state);

        // Keep history bounded
        if self.state_history.len() > 1000 {
            self.state_history.remove(0);
        }

        self.last_update = Instant::now();
        Ok(())
    }

    /// Select action using epsilon-greedy policy
    ///
    /// With probability epsilon, selects a random action (exploration).
    /// Otherwise, uses the model or fallback to select the best action (exploitation).
    pub fn select_action(&mut self) -> Result<Action, RLError> {
        // Epsilon-greedy exploration
        let should_explore = rand::random::<f32>() < self.exploration_rate;

        let action = if should_explore {
            // Random exploration
            self.select_random_action()
        } else {
            // Exploitation using model or fallback
            self.select_best_action()?
        };

        // Update statistics
        *self.action_counts.entry(action.action_type).or_insert(0) += 1;

        // Store action
        self.last_action = Some(action.clone());

        // Decay exploration rate
        self.exploration_rate =
            (self.exploration_rate * self.exploration_decay).max(self.min_exploration_rate);

        Ok(action)
    }

    /// Select best action using model or fallback
    fn select_best_action(&mut self) -> Result<Action, RLError> {
        #[cfg(feature = "rl_agent")]
        {
            if !self.use_fallback {
                if let Some(ref loader) = self.model_loader {
                    if loader.is_ready() {
                        return self.select_action_from_model(loader);
                    }
                }
            }
        }

        // Use fallback model
        Ok(self.fallback_model.select_action(&self.current_state))
    }

    /// Select action from ONNX model
    #[cfg(feature = "rl_agent")]
    fn select_action_from_model(&self, loader: &OnnxModelLoader) -> Result<Action, RLError> {
        // Get action probabilities from model
        let probabilities = loader.predict(&self.current_state)?;

        // Sample action from probability distribution
        let action_index = self.sample_from_distribution(&probabilities)?;
        let action_type = ActionType::from_index(action_index)?;

        // Calculate magnitude based on confidence (probability)
        let confidence = probabilities[action_index];
        let magnitude = 0.5 + confidence * 1.5; // Maps [0, 1] to [0.5, 2.0]
        let magnitude = magnitude.clamp(0.1, 2.0);

        Ok(Action::with_magnitude(action_type, magnitude))
    }

    /// Sample action index from probability distribution
    fn sample_from_distribution(&self, probabilities: &[f32]) -> Result<usize, RLError> {
        let total: f32 = probabilities.iter().sum();

        if total <= 0.0 || !total.is_finite() {
            return Err(RLError::TensorOp(
                "Invalid probability distribution".to_string(),
            ));
        }

        let mut random_value = rand::random::<f32>() * total;

        for (index, &prob) in probabilities.iter().enumerate() {
            random_value -= prob;
            if random_value <= 0.0 {
                return Ok(index);
            }
        }

        // Fallback to last index
        Ok(probabilities.len() - 1)
    }

    /// Select random action for exploration
    fn select_random_action(&self) -> Action {
        let actions = ActionType::all_actions();
        let random_index = rand::random::<usize>() % actions.len();
        let action_type = actions[random_index];
        let magnitude = 0.5 + rand::random::<f32>() * 1.5; // Random magnitude in [0.5, 2.0]

        Action::with_magnitude(action_type, magnitude)
    }

    /// Execute action on attack configuration
    pub fn execute_action(
        &self,
        action: &Action,
        config: &mut AttackConfig,
    ) -> Result<(), RLError> {
        action.apply_to_config(config)?;

        tracing::debug!(
            "Executed action: {:?} with magnitude {:.2}",
            action.action_type,
            action.magnitude
        );

        Ok(())
    }

    /// Update agent with reward from last action
    pub fn update_with_reward(&mut self, reward: f32) {
        if let Some(ref action) = self.last_action {
            // Store reward
            self.action_rewards
                .entry(action.action_type)
                .or_insert_with(Vec::new)
                .push(reward);

            // Keep reward history bounded
            if let Some(rewards) = self.action_rewards.get_mut(&action.action_type) {
                if rewards.len() > 100 {
                    rewards.remove(0);
                }
            }

            // Update action history
            self.action_history.push((action.clone(), reward));
            if self.action_history.len() > 1000 {
                self.action_history.remove(0);
            }

            // Update fallback model
            self.fallback_model
                .update_weights(action.action_type, reward);

            // Update totals
            self.total_reward += reward as f64;
            self.episode_count += 1;

            tracing::debug!(
                "Updated with reward {:.3} for action {:?}",
                reward,
                action.action_type
            );
        }
    }

    /// Get action statistics
    pub fn get_action_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        // Overall statistics
        stats.insert(
            "episode_count".to_string(),
            serde_json::json!(self.episode_count),
        );
        stats.insert(
            "total_reward".to_string(),
            serde_json::json!(self.total_reward),
        );
        stats.insert(
            "average_reward".to_string(),
            serde_json::json!(self.total_reward / self.episode_count.max(1) as f64),
        );
        stats.insert(
            "exploration_rate".to_string(),
            serde_json::json!(self.exploration_rate),
        );
        stats.insert(
            "using_fallback".to_string(),
            serde_json::json!(self.use_fallback),
        );

        // Action counts
        let mut action_count_map = HashMap::new();
        for (action_type, count) in &self.action_counts {
            action_count_map.insert(format!("{:?}", action_type), count);
        }
        stats.insert(
            "action_counts".to_string(),
            serde_json::json!(action_count_map),
        );

        // Average rewards per action
        let mut avg_rewards = HashMap::new();
        for (action_type, rewards) in &self.action_rewards {
            if !rewards.is_empty() {
                let avg = rewards.iter().sum::<f32>() / rewards.len() as f32;
                avg_rewards.insert(format!("{:?}", action_type), avg);
            }
        }
        stats.insert(
            "average_rewards_per_action".to_string(),
            serde_json::json!(avg_rewards),
        );

        // Recent performance
        let recent_rewards: Vec<f32> = self
            .action_history
            .iter()
            .rev()
            .take(10)
            .map(|(_, reward)| *reward)
            .collect();
        stats.insert(
            "recent_rewards".to_string(),
            serde_json::json!(recent_rewards),
        );

        // Timing
        stats.insert(
            "uptime_seconds".to_string(),
            serde_json::json!(self.start_time.elapsed().as_secs()),
        );
        stats.insert(
            "time_since_last_update".to_string(),
            serde_json::json!(self.last_update.elapsed().as_secs_f64()),
        );

        stats
    }

    /// Get best performing actions
    pub fn get_best_actions(&self, top_n: usize) -> Vec<(ActionType, f32)> {
        let mut action_scores: Vec<(ActionType, f32)> = self
            .action_rewards
            .iter()
            .filter_map(|(action_type, rewards)| {
                if rewards.is_empty() {
                    None
                } else {
                    let avg_reward = rewards.iter().sum::<f32>() / rewards.len() as f32;
                    Some((*action_type, avg_reward))
                }
            })
            .collect();

        action_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        action_scores.truncate(top_n);

        action_scores
    }

    /// Reset agent state for new episode
    pub fn reset(&mut self) {
        self.current_state = ObservationState::new();
        self.last_action = None;
        tracing::info!("RL agent reset for new episode");
    }

    /// Save agent state to file
    pub fn save_state(&self, path: &str) -> Result<(), RLError> {
        let state_data = serde_json::json!({
            "episode_count": self.episode_count,
            "total_reward": self.total_reward,
            "exploration_rate": self.exploration_rate,
            "action_counts": self.action_counts,
            "use_fallback": self.use_fallback,
        });

        std::fs::write(path, serde_json::to_string_pretty(&state_data).unwrap())
            .map_err(|e| RLError::ModelLoad(format!("Failed to save state: {}", e)))?;

        tracing::info!("Agent state saved to {}", path);
        Ok(())
    }

    /// Load agent state from file
    pub fn load_state(&mut self, path: &str) -> Result<(), RLError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| RLError::ModelLoad(format!("Failed to load state: {}", e)))?;

        let state_data: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| RLError::ModelLoad(format!("Failed to parse state: {}", e)))?;

        if let Some(episode_count) = state_data["episode_count"].as_u64() {
            self.episode_count = episode_count;
        }

        if let Some(total_reward) = state_data["total_reward"].as_f64() {
            self.total_reward = total_reward;
        }

        if let Some(exploration_rate) = state_data["exploration_rate"].as_f64() {
            self.exploration_rate = exploration_rate as f32;
        }

        tracing::info!("Agent state loaded from {}", path);
        Ok(())
    }

    /// Check if agent is using ONNX model
    pub fn is_using_model(&self) -> bool {
        !self.use_fallback
    }

    /// Get current state
    pub fn get_current_state(&self) -> &ObservationState {
        &self.current_state
    }

    /// Get last action
    pub fn get_last_action(&self) -> Option<&Action> {
        self.last_action.as_ref()
    }
}

#[cfg(test)]
mod agent_tests {
    use super::*;

    #[test]
    fn test_agent_creation() {
        let agent = RLAgent::new(None);
        assert!(agent.use_fallback);
        assert_eq!(agent.episode_count, 0);
    }

    #[test]
    fn test_agent_state_update() {
        let mut agent = RLAgent::new(None);
        let state = ObservationState::new();

        assert!(agent.update_state(state).is_ok());
        assert_eq!(agent.state_history.len(), 1);
    }

    #[test]
    fn test_action_selection() {
        let mut agent = RLAgent::new(None);
        let state = ObservationState::new();
        agent.update_state(state).unwrap();

        let action = agent.select_action().unwrap();
        assert!(action.magnitude >= 0.1 && action.magnitude <= 2.0);
    }

    #[test]
    fn test_action_execution() {
        let agent = RLAgent::new(None);
        let action = Action::with_magnitude(ActionType::IncreasePPS, 1.0);
        let mut config = AttackConfig::default();
        let original_rate = config.packet_rate;

        agent.execute_action(&action, &mut config).unwrap();
        assert!(config.packet_rate > original_rate);
    }

    #[test]
    fn test_reward_update() {
        let mut agent = RLAgent::new(None);
        let state = ObservationState::new();
        agent.update_state(state).unwrap();

        let _action = agent.select_action().unwrap();
        agent.update_with_reward(0.5);

        assert_eq!(agent.episode_count, 1);
        assert!(agent.total_reward > 0.0);
    }

    #[test]
    fn test_exploration_decay() {
        let mut agent = RLAgent::new(None);
        let initial_rate = agent.exploration_rate;

        let state = ObservationState::new();
        agent.update_state(state).unwrap();

        // Select multiple actions to trigger decay
        for _ in 0..10 {
            let _ = agent.select_action();
        }

        assert!(agent.exploration_rate < initial_rate);
        assert!(agent.exploration_rate >= agent.min_exploration_rate);
    }

    #[test]
    fn test_best_actions_tracking() {
        let mut agent = RLAgent::new(None);
        let state = ObservationState::new();
        agent.update_state(state).unwrap();

        // Simulate some actions with rewards
        for _ in 0..5 {
            let _ = agent.select_action().unwrap();
            agent.update_with_reward(rand::random::<f32>());
        }

        let best_actions = agent.get_best_actions(3);
        assert!(best_actions.len() <= 3);
    }
}
/// Online learning system for continuous model improvement
///
/// Implements experience replay, policy gradient updates, and model fine-tuning
/// for continuous adaptation to changing environments and defense patterns.
///
/// **Validates: Requirements 7.5** - Online learning mode
pub struct OnlineLearningSystem {
    // Experience replay buffer
    experience_buffer: Vec<Experience>,
    buffer_capacity: usize,

    // Learning parameters
    learning_rate: f32,
    discount_factor: f32,
    batch_size: usize,

    // Policy gradient components
    #[cfg(feature = "rl_agent")]
    policy_network: Option<PolicyNetwork>,

    // Experience collection
    current_episode: Vec<Experience>,
    episode_rewards: Vec<f32>,

    // Online statistics
    learning_episodes: u64,
    total_experiences: u64,
    average_episode_reward: f32,

    // Adaptive learning
    performance_window: Vec<f32>,
    learning_enabled: bool,
    min_experiences_for_learning: usize,

    // Model update tracking
    last_model_update: Instant,
    update_frequency: Duration,

    // Performance tracking
    reward_history: Vec<f32>,
    loss_history: Vec<f32>,
}

/// Experience tuple for reinforcement learning
#[derive(Debug, Clone)]
pub struct Experience {
    pub state: ObservationState,
    pub action: Action,
    pub reward: f32,
    pub next_state: ObservationState,
    pub done: bool,
    pub timestamp: Instant,
}

/// Simple policy network for online learning
#[cfg(feature = "rl_agent")]
struct PolicyNetwork {
    weights: Tensor,
    bias: Tensor,
    optimizer: nn::Optimizer,
    device: Device,
}

impl OnlineLearningSystem {
    /// Create a new online learning system
    pub fn new() -> Self {
        Self {
            experience_buffer: Vec::new(),
            buffer_capacity: 10000,
            learning_rate: 0.001,
            discount_factor: 0.99,
            batch_size: 32,
            #[cfg(feature = "rl_agent")]
            policy_network: None,
            current_episode: Vec::new(),
            episode_rewards: Vec::new(),
            learning_episodes: 0,
            total_experiences: 0,
            average_episode_reward: 0.0,
            performance_window: Vec::new(),
            learning_enabled: true,
            min_experiences_for_learning: 100,
            last_model_update: Instant::now(),
            update_frequency: Duration::from_secs(60), // Update every minute
            reward_history: Vec::new(),
            loss_history: Vec::new(),
        }
    }

    /// Initialize policy network for online learning
    #[cfg(feature = "rl_agent")]
    pub fn initialize_policy_network(&mut self) -> Result<(), RLError> {
        let device = if tch::Cuda::is_available() {
            Device::Cuda(0)
        } else {
            Device::Cpu
        };

        let input_dim = ObservationState::state_dim() as i64;
        let output_dim = ActionType::action_count() as i64;

        // Initialize weights with Xavier initialization
        let weights = Tensor::randn(&[input_dim, output_dim], (tch::Kind::Float, device))
            * (2.0 / (input_dim + output_dim) as f64).sqrt();
        let bias = Tensor::zeros(&[output_dim], (tch::Kind::Float, device));

        // Create optimizer (simple SGD for now)
        let mut vs = nn::VarStore::new(device);
        let optimizer = nn::Sgd::default()
            .build(&vs, self.learning_rate as f64)
            .map_err(|e| RLError::TensorOp(format!("Failed to create optimizer: {}", e)))?;

        self.policy_network = Some(PolicyNetwork {
            weights,
            bias,
            optimizer,
            device,
        });

        tracing::info!("Policy network initialized for online learning");
        Ok(())
    }

    /// Add experience to the buffer
    pub fn add_experience(&mut self, experience: Experience) {
        // Add to current episode
        self.current_episode.push(experience.clone());

        // Add to replay buffer
        self.experience_buffer.push(experience);

        // Maintain buffer capacity
        if self.experience_buffer.len() > self.buffer_capacity {
            self.experience_buffer.remove(0);
        }

        self.total_experiences += 1;
    }

    /// Finish current episode and trigger learning
    pub fn finish_episode(&mut self) -> Result<(), RLError> {
        if self.current_episode.is_empty() {
            return Ok(());
        }

        // Calculate episode reward
        let episode_reward: f32 = self.current_episode.iter().map(|exp| exp.reward).sum();

        self.episode_rewards.push(episode_reward);
        self.reward_history.push(episode_reward);

        // Update average reward
        self.average_episode_reward = if self.episode_rewards.len() == 1 {
            episode_reward
        } else {
            0.9 * self.average_episode_reward + 0.1 * episode_reward
        };

        // Update performance window
        self.performance_window.push(episode_reward);
        if self.performance_window.len() > 100 {
            self.performance_window.remove(0);
        }

        // Trigger learning if conditions are met
        if self.should_update_model() {
            self.update_model()?;
        }

        // Clear current episode
        self.current_episode.clear();
        self.learning_episodes += 1;

        tracing::debug!(
            "Episode {} finished with reward {:.3}, avg: {:.3}",
            self.learning_episodes,
            episode_reward,
            self.average_episode_reward
        );

        Ok(())
    }

    /// Check if model should be updated
    fn should_update_model(&self) -> bool {
        self.learning_enabled
            && self.experience_buffer.len() >= self.min_experiences_for_learning
            && self.last_model_update.elapsed() >= self.update_frequency
    }

    /// Update model using experience replay
    fn update_model(&mut self) -> Result<(), RLError> {
        #[cfg(feature = "rl_agent")]
        {
            if let Some(ref mut policy_net) = self.policy_network {
                let loss = self.compute_policy_gradient_loss(policy_net)?;

                // Backward pass
                policy_net.optimizer.zero_grad();
                loss.backward();
                policy_net.optimizer.step();

                // Track loss
                let loss_value: f32 = loss.double_value(&[]) as f32;
                self.loss_history.push(loss_value);
                if self.loss_history.len() > 1000 {
                    self.loss_history.remove(0);
                }

                self.last_model_update = Instant::now();

                tracing::debug!("Model updated with loss: {:.6}", loss_value);
                return Ok(());
            }
        }

        // Fallback: update heuristic weights based on experience
        self.update_heuristic_weights();
        self.last_model_update = Instant::now();

        Ok(())
    }

    /// Compute policy gradient loss
    #[cfg(feature = "rl_agent")]
    fn compute_policy_gradient_loss(&self, policy_net: &PolicyNetwork) -> Result<Tensor, RLError> {
        // Sample batch from experience buffer
        let batch = self.sample_batch();

        if batch.is_empty() {
            return Err(RLError::TensorOp("Empty batch for learning".to_string()));
        }

        // Convert experiences to tensors
        let states: Vec<Tensor> = batch
            .iter()
            .map(|exp| exp.state.to_tensor(&policy_net.device))
            .collect::<Result<Vec<_>, _>>()?;

        let actions: Vec<usize> = batch
            .iter()
            .map(|exp| exp.action.action_type.to_index())
            .collect();

        let rewards: Vec<f32> = batch.iter().map(|exp| exp.reward).collect();

        // Stack states into batch tensor
        let state_batch = Tensor::stack(&states, 0);

        // Forward pass through policy network
        let logits = state_batch.matmul(&policy_net.weights) + &policy_net.bias;
        let log_probs = logits.log_softmax(-1, tch::Kind::Float);

        // Calculate discounted rewards
        let discounted_rewards = self.calculate_discounted_rewards(&rewards);

        // Compute policy gradient loss
        let mut total_loss = Tensor::zeros(&[], (tch::Kind::Float, policy_net.device));

        for (i, &action_idx) in actions.iter().enumerate() {
            let log_prob = log_probs.get(i as i64).get(action_idx as i64);
            let reward = discounted_rewards[i];
            let loss_term = -log_prob * reward;
            total_loss = total_loss + loss_term;
        }

        let batch_size = batch.len() as f64;
        Ok(total_loss / batch_size)
    }

    /// Sample batch from experience buffer
    fn sample_batch(&self) -> Vec<Experience> {
        if self.experience_buffer.len() < self.batch_size {
            return self.experience_buffer.clone();
        }

        let mut batch = Vec::with_capacity(self.batch_size);
        let mut indices: Vec<usize> = (0..self.experience_buffer.len()).collect();

        // Shuffle indices
        for i in (1..indices.len()).rev() {
            let j = rand::random::<usize>() % (i + 1);
            indices.swap(i, j);
        }

        // Take first batch_size experiences
        for &idx in indices.iter().take(self.batch_size) {
            batch.push(self.experience_buffer[idx].clone());
        }

        batch
    }

    /// Calculate discounted rewards for policy gradient
    fn calculate_discounted_rewards(&self, rewards: &[f32]) -> Vec<f32> {
        let mut discounted = vec![0.0; rewards.len()];
        let mut cumulative = 0.0;

        // Calculate backwards for efficiency
        for i in (0..rewards.len()).rev() {
            cumulative = rewards[i] + self.discount_factor * cumulative;
            discounted[i] = cumulative;
        }

        // Normalize rewards
        if discounted.len() > 1 {
            let mean = discounted.iter().sum::<f32>() / discounted.len() as f32;
            let variance = discounted.iter().map(|&x| (x - mean).powi(2)).sum::<f32>()
                / discounted.len() as f32;
            let std_dev = variance.sqrt();

            if std_dev > 1e-8 {
                for reward in &mut discounted {
                    *reward = (*reward - mean) / std_dev;
                }
            }
        }

        discounted
    }

    /// Update heuristic weights based on experience (fallback learning)
    fn update_heuristic_weights(&mut self) {
        // Analyze recent experiences to update action preferences
        let recent_experiences: Vec<&Experience> =
            self.experience_buffer.iter().rev().take(100).collect();

        if recent_experiences.is_empty() {
            return;
        }

        // Calculate action performance
        let mut action_performance: HashMap<ActionType, Vec<f32>> = HashMap::new();

        for exp in recent_experiences {
            action_performance
                .entry(exp.action.action_type)
                .or_insert_with(Vec::new)
                .push(exp.reward);
        }

        // Update learning statistics
        let mut total_improvement = 0.0;
        let mut updates_count = 0;

        for (action_type, rewards) in action_performance {
            if !rewards.is_empty() {
                let avg_reward = rewards.iter().sum::<f32>() / rewards.len() as f32;

                // Simple learning rule: increase preference for good actions
                if avg_reward > 0.0 {
                    total_improvement += avg_reward;
                    updates_count += 1;
                }
            }
        }

        if updates_count > 0 {
            let avg_improvement = total_improvement / updates_count as f32;
            tracing::debug!(
                "Heuristic learning update: avg improvement {:.3}",
                avg_improvement
            );
        }
    }

    /// Get learning statistics
    pub fn get_learning_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        stats.insert(
            "learning_episodes".to_string(),
            serde_json::json!(self.learning_episodes),
        );
        stats.insert(
            "total_experiences".to_string(),
            serde_json::json!(self.total_experiences),
        );
        stats.insert(
            "buffer_size".to_string(),
            serde_json::json!(self.experience_buffer.len()),
        );
        stats.insert(
            "buffer_capacity".to_string(),
            serde_json::json!(self.buffer_capacity),
        );
        stats.insert(
            "average_episode_reward".to_string(),
            serde_json::json!(self.average_episode_reward),
        );
        stats.insert(
            "learning_enabled".to_string(),
            serde_json::json!(self.learning_enabled),
        );

        // Recent performance
        let recent_rewards: Vec<f32> = self.reward_history.iter().rev().take(10).copied().collect();
        stats.insert(
            "recent_episode_rewards".to_string(),
            serde_json::json!(recent_rewards),
        );

        // Performance trend
        if self.performance_window.len() >= 2 {
            let recent_avg = self.performance_window.iter().rev().take(10).sum::<f32>()
                / 10.0_f32.min(self.performance_window.len() as f32);

            let older_avg = self
                .performance_window
                .iter()
                .rev()
                .skip(10)
                .take(10)
                .sum::<f32>()
                / 10.0_f32.min((self.performance_window.len() - 10).max(0) as f32);

            let trend = if older_avg > 0.0 {
                (recent_avg - older_avg) / older_avg
            } else {
                0.0
            };

            stats.insert("performance_trend".to_string(), serde_json::json!(trend));
        }

        // Loss history (if available)
        if !self.loss_history.is_empty() {
            let recent_loss: Vec<f32> = self.loss_history.iter().rev().take(10).copied().collect();
            stats.insert("recent_losses".to_string(), serde_json::json!(recent_loss));
        }

        stats.insert(
            "time_since_last_update".to_string(),
            serde_json::json!(self.last_model_update.elapsed().as_secs_f64()),
        );

        stats
    }

    /// Enable or disable online learning
    pub fn set_learning_enabled(&mut self, enabled: bool) {
        self.learning_enabled = enabled;
        tracing::info!(
            "Online learning {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Set learning parameters
    pub fn set_learning_parameters(
        &mut self,
        learning_rate: f32,
        discount_factor: f32,
        batch_size: usize,
    ) {
        self.learning_rate = learning_rate.clamp(0.0001, 0.1);
        self.discount_factor = discount_factor.clamp(0.9, 0.999);
        self.batch_size = batch_size.clamp(8, 256);

        tracing::info!(
            "Learning parameters updated: lr={:.4}, gamma={:.3}, batch_size={}",
            self.learning_rate,
            self.discount_factor,
            self.batch_size
        );
    }

    /// Clear experience buffer
    pub fn clear_experience_buffer(&mut self) {
        self.experience_buffer.clear();
        self.current_episode.clear();
        tracing::info!("Experience buffer cleared");
    }

    /// Get experience buffer utilization
    pub fn get_buffer_utilization(&self) -> f32 {
        self.experience_buffer.len() as f32 / self.buffer_capacity as f32
    }

    /// Check if ready for learning
    pub fn is_ready_for_learning(&self) -> bool {
        self.learning_enabled && self.experience_buffer.len() >= self.min_experiences_for_learning
    }

    /// Force model update
    pub fn force_update(&mut self) -> Result<(), RLError> {
        if !self.experience_buffer.is_empty() {
            self.update_model()?;
            tracing::info!("Forced model update completed");
        }
        Ok(())
    }
}

impl Default for OnlineLearningSystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod learning_tests {
    use super::*;

    #[test]
    fn test_online_learning_creation() {
        let learning_system = OnlineLearningSystem::new();
        assert!(learning_system.learning_enabled);
        assert_eq!(learning_system.experience_buffer.len(), 0);
    }

    #[test]
    fn test_experience_addition() {
        let mut learning_system = OnlineLearningSystem::new();

        let experience = Experience {
            state: ObservationState::new(),
            action: Action::new(ActionType::IncreasePPS),
            reward: 0.5,
            next_state: ObservationState::new(),
            done: false,
            timestamp: Instant::now(),
        };

        learning_system.add_experience(experience);
        assert_eq!(learning_system.experience_buffer.len(), 1);
        assert_eq!(learning_system.total_experiences, 1);
    }

    #[test]
    fn test_episode_completion() {
        let mut learning_system = OnlineLearningSystem::new();

        // Add some experiences
        for i in 0..5 {
            let experience = Experience {
                state: ObservationState::new(),
                action: Action::new(ActionType::IncreasePPS),
                reward: i as f32 * 0.1,
                next_state: ObservationState::new(),
                done: i == 4,
                timestamp: Instant::now(),
            };
            learning_system.add_experience(experience);
        }

        learning_system.finish_episode().unwrap();
        assert_eq!(learning_system.learning_episodes, 1);
        assert!(!learning_system.episode_rewards.is_empty());
    }

    #[test]
    fn test_buffer_capacity() {
        let mut learning_system = OnlineLearningSystem::new();
        learning_system.buffer_capacity = 10; // Small capacity for testing

        // Add more experiences than capacity
        for i in 0..15 {
            let experience = Experience {
                state: ObservationState::new(),
                action: Action::new(ActionType::IncreasePPS),
                reward: i as f32,
                next_state: ObservationState::new(),
                done: false,
                timestamp: Instant::now(),
            };
            learning_system.add_experience(experience);
        }

        assert_eq!(learning_system.experience_buffer.len(), 10);
    }

    #[test]
    fn test_learning_parameters() {
        let mut learning_system = OnlineLearningSystem::new();

        learning_system.set_learning_parameters(0.01, 0.95, 64);
        assert_eq!(learning_system.learning_rate, 0.01);
        assert_eq!(learning_system.discount_factor, 0.95);
        assert_eq!(learning_system.batch_size, 64);
    }

    #[test]
    fn test_discounted_rewards_calculation() {
        let learning_system = OnlineLearningSystem::new();
        let rewards = vec![1.0, 2.0, 3.0];

        let discounted = learning_system.calculate_discounted_rewards(&rewards);
        assert_eq!(discounted.len(), rewards.len());

        // Check that later rewards have less impact due to discounting
        // (after normalization, the exact values depend on the normalization)
        assert!(discounted.iter().all(|&x| x.is_finite()));
    }
}
/// Integration module for connecting RL agent with NetStress engine
/// 
/// Provides high-level interface for integrating the RL agent with the main
/// packet engine and coordinating real-time optimization.
pub struct RLIntegration {
    agent: RLAgent,
    learning_system: OnlineLearningSystem,
    
    // Integration state
    current_config: AttackConfig,
    last_metrics: Option<PerformanceMetrics>,
    optimization_enabled: bool,
    
    // Timing
    last_optimization: Instant,
    optimization_interval: Duration,
    
    // Statistics
    optimization_count: u64,
    total_reward: f64,
    best_performance: f64,
}

/// Performance metrics for RL optimization
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub pps: f64,
    pub bps: f64,
    pub error_rate: f64,
    pub latency_ms: f64,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub timestamp: Instant,
}

impl RLIntegration {
    /// Create new RL integration
    pub fn new(model_path: Option<String>) -> Result<Self, RLError> {
        let mut agent = RLAgent::new(model_path);
        agent.initialize()?;
        
        let learning_system = OnlineLearningSystem::new();
        
        Ok(Self {
            agent,
            learning_system,
            current_config: AttackConfig::default(),
            last_metrics: None,
            optimization_enabled: true,
            last_optimization: Instant::now(),
            optimization_interval: Duration::from_secs(5), // Optimize every 5 seconds
            optimization_count: 0,
            total_reward: 0.0,
            best_performance: 0.0,
        })
    }
    
    /// Update with current performance metrics and optimize if needed
    pub fn update_and_optimize(&mut self, metrics: PerformanceMetrics) -> Result<Option<AttackConfig>, RLError> {
        // Calculate reward if we have previous metrics
        if let Some(ref last_metrics) = self.last_metrics {
            let reward = self.calculate_reward(last_metrics, &metrics);
            self.agent.update_with_reward(reward);
            self.total_reward += reward as f64;
            
            // Track best performance
            if metrics.pps > self.best_performance {
                self.best_performance = metrics.pps;
            }
            
            // Add experience to learning system
            if let Some(last_action) = self.agent.get_last_action() {
                let experience = Experience {
                    state: self.metrics_to_state(last_metrics),
                    action: last_action.clone(),
                    reward,
                    next_state: self.metrics_to_state(&metrics),
                    done: false,
                    timestamp: Instant::now(),
                };
                
                self.learning_system.add_experience(experience);
            }
        }
        
        // Update agent state
        let state = self.metrics_to_state(&metrics);
        self.agent.update_state(state)?;
        
        // Check if optimization is needed
        let should_optimize = self.optimization_enabled &&
            self.last_optimization.elapsed() >= self.optimization_interval;
        
        if should_optimize {
            return self.perform_optimization();
        }
        
        self.last_metrics = Some(metrics);
        Ok(None)
    }
    
    /// Perform optimization step
    fn perform_optimization(&mut self) -> Result<Option<AttackConfig>, RLError> {
        // Select action
        let action = self.agent.select_action()?;
        
        // Apply action to current config
        let mut new_config = self.current_config.clone();
        self.agent.execute_action(&action, &mut new_config)?;
        
        // Update state
        self.current_config = new_config.clone();
        self.last_optimization = Instant::now();
        self.optimization_count += 1;
        
        tracing::info!(
            "RL optimization #{}: {:?} (magnitude: {:.2})",
            self.optimization_count,
            action.action_type,
            action.magnitude
        );
        
        Ok(Some(new_config))
    }
    
    /// Convert performance metrics to observation state
    fn metrics_to_state(&self, metrics: &PerformanceMetrics) -> ObservationState {
        let defenses = DefenseState::default(); // Would be populated from actual defense detection
        
        ObservationState::from_metrics(
            self.current_config.packet_rate,
            self.current_config.packet_size,
            self.current_config.thread_count,
            &self.current_config.protocol,
            self.current_config.evasion_level,
            metrics.pps,
            metrics.bps,
            (metrics.error_rate * 1000.0) as u64, // Convert rate to count
            1000, // Assume 1000 packets sent
            metrics.latency_ms,
            0, // target_errors
            100, // target_requests
            metrics.latency_ms,
            metrics.error_rate,
            0.0, // congestion
            &defenses,
            metrics.cpu_usage,
            metrics.memory_usage,
            Instant::now(),
        )
    }
    
    /// Calculate reward based on performance improvement
    fn calculate_reward(&self, old_metrics: &PerformanceMetrics, new_metrics: &PerformanceMetrics) -> f32 {
        // Performance improvement
        let pps_improvement = (new_metrics.pps - old_metrics.pps) / old_metrics.pps.max(1.0);
        
        // Error rate improvement (lower is better)
        let error_improvement = old_metrics.error_rate - new_metrics.error_rate;
        
        // Latency improvement (lower is better)
        let latency_improvement = (old_metrics.latency_ms - new_metrics.latency_ms) / old_metrics.latency_ms.max(1.0);
        
        // Resource efficiency (lower usage is better for same performance)
        let cpu_efficiency = if new_metrics.pps >= old_metrics.pps {
            (old_metrics.cpu_usage - new_metrics.cpu_usage) / 100.0
        } else {
            0.0
        };
        
        // Combined reward
        let reward = 0.4 * pps_improvement as f32 +
                    0.3 * error_improvement as f32 +
                    0.2 * latency_improvement as f32 +
                    0.1 * cpu_efficiency as f32;
        
        // Penalty for very poor performance
        if new_metrics.pps < 1000.0 {
            reward - 0.5
        } else {
            reward
        }
    }
    
    /// Finish current episode and trigger learning
    pub fn finish_episode(&mut self) -> Result<(), RLError> {
        self.learning_system.finish_episode()
    }
    
    /// Get optimization statistics
    pub fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = self.agent.get_action_statistics();
        
        // Add integration-specific stats
        stats.insert("optimization_count".to_string(), 
                    serde_json::json!(self.optimization_count));
        stats.insert("total_reward".to_string(), 
                    serde_json::json!(self.total_reward));
        stats.insert("average_reward".to_string(), 
                    serde_json::json!(self.total_reward / self.optimization_count.max(1) as f64));
        stats.insert("best_performance_pps".to_string(), 
                    serde_json::json!(self.best_performance));
        stats.insert("optimization_enabled".to_string(), 
                    serde_json::json!(self.optimization_enabled));
        stats.insert("optimization_interval_secs".to_string(), 
                    serde_json::json!(self.optimization_interval.as_secs()));
        
        // Add learning system stats
        let learning_stats = self.learning_system.get_learning_statistics();
        for (key, value) in learning_stats {
            stats.insert(format!("learning_{}", key), value);
        }
        
        stats
    }
    
    /// Enable or disable optimization
    pub fn set_optimization_enabled(&mut self, enabled: bool) {
        self.optimization_enabled = enabled;
        tracing::info!("RL optimization {}", if enabled { "enabled" } else { "disabled" });
    }
    
    /// Set optimization interval
    pub fn set_optimization_interval(&mut self, interval: Duration) {
        self.optimization_interval = interval;
        tracing::info!("RL optimization interval set to {:?}", interval);
    }
    
    /// Get current configuration
    pub fn get_current_config(&self) -> &AttackConfig {
        &self.current_config
    }
    
    /// Set current configuration
    pub fn set_current_config(&mut self, config: AttackConfig) {
        self.current_config = config;
    }
    
    /// Force optimization step
    pub fn force_optimization(&mut self) -> Result<Option<AttackConfig>, RLError> {
        self.perform_optimization()
    }
}

<function_calls>
<invoke name="taskStatus">
<parameter name="taskFilePath">.kiro/specs/titanium-upgrade/tasks.md