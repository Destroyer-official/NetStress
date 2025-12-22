/*!
 * Property-Based Test for RL Agent Adaptive Scaling
 *
 * **Feature: titanium-upgrade, Property 6: Adaptive Scaling Response**
 * **Validates: Requirements 21.3, 21.6**
 */

#[cfg(test)]
mod tests {
    use super::super::rl_agent::*;
    use proptest::prelude::*;
    use std::time::Instant;

    /// Generate valid observation states for testing
    fn arb_observation_state() -> impl Strategy<Value = ObservationState> {
        (
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
            0.0f32..1.0,
        )
            .prop_map(
                |(
                    packet_rate,
                    packet_size,
                    thread_count,
                    protocol_type,
                    evasion_level,
                    current_pps,
                    current_bandwidth,
                    error_rate,
                    success_rate,
                    target_response_time,
                    target_error_rate,
                    target_availability,
                    network_latency,
                    packet_loss,
                    congestion_level,
                    rate_limit_detected,
                    waf_detected,
                    behavioral_defense_detected,
                    defense_confidence,
                    cpu_usage,
                    memory_usage,
                    timestamp,
                )| {
                    ObservationState {
                        packet_rate,
                        packet_size,
                        thread_count,
                        protocol_type,
                        evasion_level,
                        current_pps,
                        current_bandwidth,
                        error_rate,
                        success_rate,
                        target_response_time,
                        target_error_rate,
                        target_availability,
                        network_latency,
                        packet_loss,
                        congestion_level,
                        rate_limit_detected,
                        waf_detected,
                        behavioral_defense_detected,
                        defense_confidence,
                        cpu_usage,
                        memory_usage,
                        timestamp,
                    }
                },
            )
    }

    proptest! {
        /// **Feature: titanium-upgrade, Property 6: Adaptive Scaling Response**
        /// **Validates: Requirements 21.3, 21.6**
        #[test]
        fn test_adaptive_scaling_response(
            initial_state in arb_observation_state(),
            cpu_constraint in 0.9f32..1.0,
            memory_constraint in 0.9f32..1.0,
        ) {
            let mut fallback_model = FallbackModel::new();

            let constrained_state = ObservationState {
                cpu_usage: cpu_constraint,
                memory_usage: memory_constraint,
                current_pps: initial_state.current_pps * 0.5,
                ..initial_state
            };

            let action = fallback_model.select_action(&constrained_state);

            prop_assert!(
                action.magnitude >= 0.1 && action.magnitude <= 2.0,
                "Action magnitude should be valid: {}",
                action.magnitude
            );
        }

        #[test]
        fn test_action_application_validity(
            action_type in prop::sample::select(ActionType::all_actions()),
            magnitude in 0.1f32..2.0,
        ) {
            let action = Action::with_magnitude(action_type, magnitude);
            let mut config = AttackConfig::default();

            let result = action.apply_to_config(&mut config);
            prop_assert!(result.is_ok(), "Action application should succeed");

            prop_assert!(config.packet_rate >= 1000, "Packet rate should be valid");
            prop_assert!(config.packet_size >= 64, "Packet size should be valid");
            prop_assert!(config.thread_count >= 1, "Thread count should be valid");
        }

        #[test]
        fn test_observation_state_validation(
            state in arb_observation_state(),
        ) {
            prop_assert!(state.validate().is_ok(), "State should be valid");
            prop_assert!(state.cpu_usage >= 0.0 && state.cpu_usage <= 1.0);
            prop_assert!(state.memory_usage >= 0.0 && state.memory_usage <= 1.0);
        }
    }

    #[test]
    fn test_fallback_model_basic() {
        let mut model = FallbackModel::new();
        let state = ObservationState::new();

        let action = model.select_action(&state);
        assert!(action.magnitude >= 0.1 && action.magnitude <= 2.0);

        model.update_weights(ActionType::IncreasePPS, 0.5);
        assert!(model.get_average_performance() >= 0.0);
    }
}
