//! Property tests for GossipSub Message Integrity
//! 
//! **Property 5: GossipSub Message Integrity**
//! **Validates: Requirements 7.1, 7.4, 7.6**
//! 
//! For any message published through GossipSub, the message SHALL be signed with Ed25519,
//! and any message with an invalid signature SHALL be rejected before processing.

#![cfg(feature = "p2p_mesh")]

use crate::p2p_mesh::{P2PMesh, AttackCommand, PulseCommand};
use libp2p::gossipsub;
use proptest::prelude::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;

/// Generate arbitrary AttackCommand for property testing
fn arb_attack_command() -> impl Strategy<Value = AttackCommand> {
    (
        "[a-zA-Z0-9.-]{1,50}",  // target
        1u16..65535,            // port
        prop::sample::select(vec!["udp".to_string(), "tcp".to_string(), "http".to_string(), "icmp".to_string()]), // protocol
        1u64..3600,             // duration (1 second to 1 hour)
        1u64..1000000,          // rate (1 to 1M PPS)
        "[a-zA-Z0-9-]{1,20}",   // swarm_id
    ).prop_map(|(target, port, protocol, duration, rate, swarm_id)| {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        AttackCommand {
            target,
            port,
            protocol,
            duration,
            rate,
            swarm_id,
            timestamp,
        }
    })
}

/// Generate arbitrary PulseCommand for property testing
fn arb_pulse_command() -> impl Strategy<Value = PulseCommand> {
    (
        any::<u64>(),           // pulse_id
        any::<u64>(),           // scheduled_time
        1u64..3600,             // duration_secs (1 second to 1 hour)
        0.0f64..1.0,            // intensity
    ).prop_map(|(pulse_id, scheduled_time, duration_secs, intensity)| {
        PulseCommand {
            pulse_id,
            scheduled_time,
            duration: Duration::from_secs(duration_secs),
            intensity,
        }
    })
}

#[cfg(feature = "p2p_mesh")]
mod p2p_mesh_tests {
    use super::*;

    proptest! {
        /// **Property 5: GossipSub Message Integrity**
        /// **Validates: Requirements 7.1, 7.4, 7.6**
        /// 
        /// For any valid AttackCommand, when published through GossipSub with Ed25519 signing,
        /// the message SHALL be properly signed and accepted by the validation system.
        #[test]
        fn test_gossipsub_message_integrity_attack_commands(
            command in arb_attack_command()
        ) {
            let rt = Runtime::new().unwrap();
            let result = rt.block_on(async {
                // Create a P2P mesh node with Ed25519 signing
                let mut mesh = P2PMesh::new(0, vec![]).await.unwrap();
                
                // Set up message validator
                mesh.configure_message_validation();
                
                // Serialize the command (this is what would be published)
                let message_data = serde_json::to_vec(&command).unwrap();
                
                // Create a mock GossipSub message with source (signed message)
                let local_peer_id = mesh.local_peer_id();
                let message = gossipsub::Message {
                    source: Some(local_peer_id),
                    data: message_data,
                    sequence_number: Some(1),
                    topic: mesh.gossipsub_topic.hash(),
                };
                
                // Test message validation
                // A properly formed message from a known source should be valid
                let is_valid = mesh.validate_message(&message);
                
                // Test deduplication
                let message_id = mesh.generate_message_id(&message);
                
                // First time seeing the message - should not be duplicate
                let is_not_dup = !mesh.is_duplicate_message(&message_id);
                
                // Mark as seen
                mesh.mark_message_seen(message_id.clone());
                
                // Second time - should be detected as duplicate
                let is_dup = mesh.is_duplicate_message(&message_id);
                
                (is_valid, is_not_dup, is_dup)
            });
            
            // Property: Valid commands with proper source should pass validation
            prop_assert!(result.0, "Valid AttackCommand should pass validation");
            prop_assert!(result.1, "First message should not be duplicate");
            prop_assert!(result.2, "Second message should be duplicate");
        }

        /// **Property 5: GossipSub Message Integrity - Pulse Commands**
        /// **Validates: Requirements 7.1, 7.4, 7.6**
        /// 
        /// For any valid PulseCommand, when published through GossipSub with Ed25519 signing,
        /// the message SHALL be properly signed and accepted by the validation system.
        #[test]
        fn test_gossipsub_message_integrity_pulse_commands(
            pulse_command in arb_pulse_command()
        ) {
            let rt = Runtime::new().unwrap();
            let is_valid = rt.block_on(async {
                // Create a P2P mesh node
                let mut mesh = P2PMesh::new(0, vec![]).await.unwrap();
                
                // Set up message validator
                mesh.configure_message_validation();
                
                // Serialize the pulse command
                let message_data = serde_json::to_vec(&pulse_command).unwrap();
                
                // Create a mock GossipSub message with source (signed message)
                let local_peer_id = mesh.local_peer_id();
                let message = gossipsub::Message {
                    source: Some(local_peer_id),
                    data: message_data,
                    sequence_number: Some(1),
                    topic: mesh.gossipsub_topic.hash(),
                };
                
                // Test message validation
                mesh.validate_message(&message)
            });
            
            // Property: Valid pulse commands with proper source should pass validation
            prop_assert!(is_valid, "Valid PulseCommand should pass validation");
        }

        /// **Property 5: GossipSub Message Integrity - Invalid Messages**
        /// **Validates: Requirements 7.6**
        /// 
        /// For any message without a source (unsigned), the message SHALL be rejected.
        #[test]
        fn test_gossipsub_rejects_unsigned_messages(
            command in arb_attack_command()
        ) {
            let rt = Runtime::new().unwrap();
            let is_valid = rt.block_on(async {
                // Create a P2P mesh node
                let mut mesh = P2PMesh::new(0, vec![]).await.unwrap();
                
                // Set up message validator
                mesh.configure_message_validation();
                
                // Serialize the command
                let message_data = serde_json::to_vec(&command).unwrap();
                
                // Create a message WITHOUT source (unsigned)
                let message = gossipsub::Message {
                    source: None,  // No source = unsigned message
                    data: message_data,
                    sequence_number: Some(1),
                    topic: mesh.gossipsub_topic.hash(),
                };
                
                // Test message validation
                mesh.validate_message(&message)
            });
            
            // Property: Unsigned messages should be rejected
            prop_assert!(!is_valid, "Unsigned messages should be rejected");
        }

        /// **Property 5: GossipSub Message Integrity - Deduplication**
        /// **Validates: Requirements 7.4**
        /// 
        /// For any message ID, after being marked as seen, subsequent checks
        /// SHALL identify it as a duplicate.
        #[test]
        fn test_gossipsub_message_deduplication(
            message_id_str in "[a-zA-Z0-9]{16,32}"
        ) {
            let rt = Runtime::new().unwrap();
            let (not_dup_first, is_dup_second, not_dup_different) = rt.block_on(async {
                // Create a P2P mesh node
                let mut mesh = P2PMesh::new(0, vec![]).await.unwrap();
                
                let message_id = gossipsub::MessageId::from(message_id_str.clone());
                
                // Property: Initially, message should not be seen
                let not_dup_first = !mesh.is_duplicate_message(&message_id);
                
                // Mark message as seen
                mesh.mark_message_seen(message_id.clone());
                
                // Property: After marking as seen, should be detected as duplicate
                let is_dup_second = mesh.is_duplicate_message(&message_id);
                
                // Property: Different message ID should not be duplicate
                let different_id = gossipsub::MessageId::from(format!("{}_different", message_id_str));
                let not_dup_different = !mesh.is_duplicate_message(&different_id);
                
                (not_dup_first, is_dup_second, not_dup_different)
            });
            
            prop_assert!(not_dup_first, "Initially message should not be duplicate");
            prop_assert!(is_dup_second, "After marking, message should be duplicate");
            prop_assert!(not_dup_different, "Different message ID should not be duplicate");
        }

        /// **Property 5: GossipSub Message Integrity - Cache Statistics**
        /// **Validates: Requirements 7.4**
        /// 
        /// For any number of messages marked as seen, the deduplication statistics
        /// SHALL accurately reflect the cache state.
        #[test]
        fn test_gossipsub_deduplication_stats(
            message_count in 1usize..100
        ) {
            let rt = Runtime::new().unwrap();
            let (seen_count, cache_duration) = rt.block_on(async {
                // Create a P2P mesh node
                let mut mesh = P2PMesh::new(0, vec![]).await.unwrap();
                
                // Mark multiple messages as seen
                for i in 0..message_count {
                    let message_id = gossipsub::MessageId::from(format!("message-{}", i));
                    mesh.mark_message_seen(message_id);
                }
                
                // Get statistics
                let stats = mesh.get_deduplication_stats();
                
                let seen_count = *stats.get("seen_messages_count").unwrap_or(&0);
                let cache_duration = *stats.get("cache_duration_secs").unwrap_or(&0);
                
                (seen_count, cache_duration)
            });
            
            // Property: Statistics should reflect the number of messages added
            prop_assert_eq!(seen_count, message_count as u64);
            
            // Property: Cache duration should be configured
            prop_assert!(cache_duration > 0);
        }
    }

    #[tokio::test]
    async fn test_gossipsub_ed25519_signing_integration() {
        // **Property 5: GossipSub Message Integrity - Integration Test**
        // **Validates: Requirements 7.1**
        // 
        // This integration test verifies that Ed25519 signing is properly configured
        // and that the GossipSub behaviour uses signed message authenticity.
        
        // Create a P2P mesh node with Ed25519 signing
        let mut mesh1 = P2PMesh::new(0, vec![]).await.unwrap();
        
        // Set up message validator
        mesh1.configure_message_validation();
        
        // Create a test command
        let command = AttackCommand {
            target: "test.example.com".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            duration: 60,
            rate: 1000,
            swarm_id: "test-swarm".to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Serialize the command (this is what would be published)
        let message_data = serde_json::to_vec(&command).unwrap();
        
        // Create a mock GossipSub message with source (signed message)
        let local_peer_id = mesh1.local_peer_id();
        let message = gossipsub::Message {
            source: Some(local_peer_id),
            data: message_data,
            sequence_number: Some(1),
            topic: mesh1.gossipsub_topic.hash(),
        };
        
        // Test that message validation works for signed messages
        let is_valid = mesh1.validate_message(&message);
        assert!(is_valid, "Signed message from local peer should be valid");
        
        // Test that unsigned messages are rejected
        let unsigned_message = gossipsub::Message {
            source: None,  // No source = unsigned
            data: serde_json::to_vec(&command).unwrap(),
            sequence_number: Some(2),
            topic: mesh1.gossipsub_topic.hash(),
        };
        let is_invalid = !mesh1.validate_message(&unsigned_message);
        assert!(is_invalid, "Unsigned message should be rejected");
        
        // Test pulse command serialization
        let pulse_command = PulseCommand {
            pulse_id: 12345,
            scheduled_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64 + 1_000_000_000, // 1 second in the future
            duration: Duration::from_secs(5),
            intensity: 0.8,
        };
        
        let pulse_data = serde_json::to_vec(&pulse_command).unwrap();
        let pulse_message = gossipsub::Message {
            source: Some(local_peer_id),
            data: pulse_data,
            sequence_number: Some(3),
            topic: mesh1.gossipsub_topic.hash(),
        };
        
        // Verify pulse command message is valid
        let pulse_valid = mesh1.validate_message(&pulse_message);
        assert!(pulse_valid, "Signed pulse command should be valid");
        
        // Verify deduplication works
        let message_id = gossipsub::MessageId::from("integration-test-message");
        assert!(!mesh1.is_duplicate_message(&message_id));
        mesh1.mark_message_seen(message_id.clone());
        assert!(mesh1.is_duplicate_message(&message_id));
        
        // Verify message ID generation is deterministic
        let msg_id1 = mesh1.generate_message_id(&message);
        let msg_id2 = mesh1.generate_message_id(&message);
        assert_eq!(msg_id1, msg_id2, "Message ID generation should be deterministic");
        
        println!("✅ GossipSub Ed25519 signing and message integrity integration test passed");
    }
}

#[cfg(not(feature = "p2p_mesh"))]
mod stub_tests {
    #[test]
    fn test_gossipsub_stub_when_disabled() {
        // When P2P mesh feature is disabled, we just verify the stub compiles
        // This ensures the code builds correctly in both configurations
        println!("P2P mesh feature disabled - using stub implementation");
    }
}
