//! Tamper-evident audit logging with hash chains
//! Implements secure logging for compliance and forensics

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write, BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use sha2::{Sha256, Digest};

/// Audit log entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Entry sequence number
    pub sequence: u64,
    /// Timestamp (Unix epoch milliseconds)
    pub timestamp: u64,
    /// Event type
    pub event_type: AuditEventType,
    /// Event details
    pub details: String,
    /// Previous entry hash (for chain integrity)
    pub prev_hash: String,
    /// This entry's hash
    pub hash: String,
}

/// Types of audit events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// Engine started
    EngineStart,
    /// Engine stopped
    EngineStop,
    /// Target authorized
    TargetAuthorized,
    /// Target rejected
    TargetRejected,
    /// Rate limit changed
    RateLimitChanged,
    /// Emergency stop triggered
    EmergencyStop,
    /// Configuration changed
    ConfigChanged,
    /// Error occurred
    Error,
    /// Statistics snapshot
    StatsSnapshot,
    /// Custom event
    Custom,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::EngineStart => "ENGINE_START",
            AuditEventType::EngineStop => "ENGINE_STOP",
            AuditEventType::TargetAuthorized => "TARGET_AUTHORIZED",
            AuditEventType::TargetRejected => "TARGET_REJECTED",
            AuditEventType::RateLimitChanged => "RATE_LIMIT_CHANGED",
            AuditEventType::EmergencyStop => "EMERGENCY_STOP",
            AuditEventType::ConfigChanged => "CONFIG_CHANGED",
            AuditEventType::Error => "ERROR",
            AuditEventType::StatsSnapshot => "STATS_SNAPSHOT",
            AuditEventType::Custom => "CUSTOM",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "ENGINE_START" => AuditEventType::EngineStart,
            "ENGINE_STOP" => AuditEventType::EngineStop,
            "TARGET_AUTHORIZED" => AuditEventType::TargetAuthorized,
            "TARGET_REJECTED" => AuditEventType::TargetRejected,
            "RATE_LIMIT_CHANGED" => AuditEventType::RateLimitChanged,
            "EMERGENCY_STOP" => AuditEventType::EmergencyStop,
            "CONFIG_CHANGED" => AuditEventType::ConfigChanged,
            "ERROR" => AuditEventType::Error,
            "STATS_SNAPSHOT" => AuditEventType::StatsSnapshot,
            _ => AuditEventType::Custom,
        }
    }
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(
        sequence: u64,
        event_type: AuditEventType,
        details: String,
        prev_hash: String,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut entry = Self {
            sequence,
            timestamp,
            event_type,
            details,
            prev_hash,
            hash: String::new(),
        };

        entry.hash = entry.calculate_hash();
        entry
    }

    /// Calculate hash for this entry
    fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.event_type.as_str().as_bytes());
        hasher.update(self.details.as_bytes());
        hasher.update(self.prev_hash.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verify this entry's hash
    pub fn verify(&self) -> bool {
        self.hash == self.calculate_hash()
    }

    /// Serialize to JSON line
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"seq":{},"ts":{},"type":"{}","details":"{}","prev":"{}","hash":"{}"}}"#,
            self.sequence,
            self.timestamp,
            self.event_type.as_str(),
            self.details.replace('"', "\\\""),
            self.prev_hash,
            self.hash
        )
    }

    /// Parse from JSON line
    pub fn from_json(json: &str) -> Option<Self> {
        // Simple JSON parsing (production would use serde)
        let seq = extract_json_u64(json, "seq")?;
        let ts = extract_json_u64(json, "ts")?;
        let event_type = AuditEventType::from_str(&extract_json_str(json, "type")?);
        let details = extract_json_str(json, "details")?;
        let prev_hash = extract_json_str(json, "prev")?;
        let hash = extract_json_str(json, "hash")?;

        Some(Self {
            sequence: seq,
            timestamp: ts,
            event_type,
            details,
            prev_hash,
            hash,
        })
    }
}

/// Tamper-evident audit logger
pub struct AuditLogger {
    /// Log entries in memory
    entries: RwLock<VecDeque<AuditEntry>>,
    /// Current sequence number
    sequence: RwLock<u64>,
    /// Last hash (for chain)
    last_hash: RwLock<String>,
    /// File writer (optional)
    file_writer: RwLock<Option<BufWriter<File>>>,
    /// Maximum entries in memory
    max_memory_entries: usize,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(1000)),
            sequence: RwLock::new(0),
            last_hash: RwLock::new("genesis".to_string()),
            file_writer: RwLock::new(None),
            max_memory_entries: 10000,
        }
    }

    /// Create with file output
    pub fn with_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        
        let logger = Self::new();
        *logger.file_writer.write() = Some(BufWriter::new(file));
        Ok(logger)
    }

    /// Log an event
    pub fn log(&self, event_type: AuditEventType, details: impl Into<String>) {
        let details = details.into();
        
        let mut seq = self.sequence.write();
        let mut last_hash = self.last_hash.write();
        
        *seq += 1;
        let entry = AuditEntry::new(*seq, event_type, details, last_hash.clone());
        *last_hash = entry.hash.clone();
        
        // Write to file if configured
        if let Some(ref mut writer) = *self.file_writer.write() {
            let _ = writeln!(writer, "{}", entry.to_json());
            let _ = writer.flush();
        }
        
        // Store in memory
        let mut entries = self.entries.write();
        entries.push_back(entry);
        
        // Trim if too many
        while entries.len() > self.max_memory_entries {
            entries.pop_front();
        }
    }

    /// Log engine start
    pub fn log_engine_start(&self, target: &str, config: &str) {
        self.log(
            AuditEventType::EngineStart,
            format!("target={}, config={}", target, config),
        );
    }

    /// Log engine stop
    pub fn log_engine_stop(&self, stats: &str) {
        self.log(AuditEventType::EngineStop, format!("stats={}", stats));
    }

    /// Log target authorization
    pub fn log_target_authorized(&self, target: &str) {
        self.log(AuditEventType::TargetAuthorized, format!("target={}", target));
    }

    /// Log target rejection
    pub fn log_target_rejected(&self, target: &str, reason: &str) {
        self.log(
            AuditEventType::TargetRejected,
            format!("target={}, reason={}", target, reason),
        );
    }

    /// Log emergency stop
    pub fn log_emergency_stop(&self, reason: &str) {
        self.log(AuditEventType::EmergencyStop, format!("reason={}", reason));
    }

    /// Log error
    pub fn log_error(&self, error: &str) {
        self.log(AuditEventType::Error, error.to_string());
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.read().iter().cloned().collect()
    }

    /// Get entries since sequence number
    pub fn entries_since(&self, seq: u64) -> Vec<AuditEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.sequence > seq)
            .cloned()
            .collect()
    }

    /// Verify chain integrity
    pub fn verify_chain(&self) -> ChainVerificationResult {
        let entries = self.entries.read();
        
        if entries.is_empty() {
            return ChainVerificationResult {
                valid: true,
                entries_checked: 0,
                first_invalid: None,
                error: None,
            };
        }

        let mut prev_hash = "genesis".to_string();
        let mut checked = 0;

        for entry in entries.iter() {
            checked += 1;
            
            // Verify entry hash
            if !entry.verify() {
                return ChainVerificationResult {
                    valid: false,
                    entries_checked: checked,
                    first_invalid: Some(entry.sequence),
                    error: Some("Entry hash mismatch".to_string()),
                };
            }
            
            // Verify chain link
            if entry.prev_hash != prev_hash {
                return ChainVerificationResult {
                    valid: false,
                    entries_checked: checked,
                    first_invalid: Some(entry.sequence),
                    error: Some("Chain link broken".to_string()),
                };
            }
            
            prev_hash = entry.hash.clone();
        }

        ChainVerificationResult {
            valid: true,
            entries_checked: checked,
            first_invalid: None,
            error: None,
        }
    }

    /// Export to JSON
    pub fn export_json(&self) -> String {
        let entries: Vec<String> = self.entries.read().iter().map(|e| e.to_json()).collect();
        format!("[{}]", entries.join(",\n"))
    }

    /// Load from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let logger = Self::new();
        
        for line in reader.lines() {
            let line = line?;
            if let Some(entry) = AuditEntry::from_json(&line) {
                *logger.sequence.write() = entry.sequence;
                *logger.last_hash.write() = entry.hash.clone();
                logger.entries.write().push_back(entry);
            }
        }
        
        Ok(logger)
    }
}

/// Result of chain verification
#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    pub valid: bool,
    pub entries_checked: u64,
    pub first_invalid: Option<u64>,
    pub error: Option<String>,
}

// Helper functions for simple JSON parsing
fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\":", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].replace("\\\"", "\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_hash() {
        let entry = AuditEntry::new(
            1,
            AuditEventType::EngineStart,
            "test".to_string(),
            "genesis".to_string(),
        );
        
        assert!(entry.verify());
        assert!(!entry.hash.is_empty());
    }

    #[test]
    fn test_audit_chain() {
        let logger = AuditLogger::new();
        
        logger.log(AuditEventType::EngineStart, "Starting");
        logger.log(AuditEventType::TargetAuthorized, "192.168.1.1");
        logger.log(AuditEventType::EngineStop, "Stopping");
        
        let result = logger.verify_chain();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 3);
    }

    #[test]
    fn test_audit_json_roundtrip() {
        let entry = AuditEntry::new(
            42,
            AuditEventType::Error,
            "Test error".to_string(),
            "abc123".to_string(),
        );
        
        let json = entry.to_json();
        let parsed = AuditEntry::from_json(&json).unwrap();
        
        assert_eq!(parsed.sequence, entry.sequence);
        assert_eq!(parsed.hash, entry.hash);
    }

    #[test]
    fn test_tamper_detection() {
        let logger = AuditLogger::new();
        
        logger.log(AuditEventType::EngineStart, "Starting");
        logger.log(AuditEventType::EngineStop, "Stopping");
        
        // Tamper with an entry
        {
            let mut entries = logger.entries.write();
            if let Some(entry) = entries.get_mut(0) {
                entry.details = "TAMPERED".to_string();
            }
        }
        
        let result = logger.verify_chain();
        assert!(!result.valid);
        assert_eq!(result.first_invalid, Some(1));
    }
}
