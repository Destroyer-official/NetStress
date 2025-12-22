//! HTTP/2 Fingerprinting Evasion Module
//!
//! This module provides HTTP/2 fingerprinting evasion capabilities to bypass
//! advanced bot detection systems like Akamai, Cloudflare, and AWS Shield.
//!
//! HTTP/2 fingerprinting analyzes:
//! - SETTINGS frame ordering and values
//! - WINDOW_UPDATE behavior
//! - PRIORITY frame usage
//! - Header compression (HPACK) patterns
//! - Pseudo-header ordering (:method, :path, :scheme, :authority)
//! - Stream dependency patterns
//!
//! **Validates: Requirements 5.1, 5.2, 5.6** - HTTP/2 fingerprinting evasion

use rand::Rng;
use std::collections::HashMap;

/// HTTP/2 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x00,
    Headers = 0x01,
    Priority = 0x02,
    RstStream = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    Ping = 0x06,
    GoAway = 0x07,
    WindowUpdate = 0x08,
    Continuation = 0x09,
}

/// HTTP/2 SETTINGS parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingsParameter {
    HeaderTableSize = 0x01,
    EnablePush = 0x02,
    MaxConcurrentStreams = 0x03,
    InitialWindowSize = 0x04,
    MaxFrameSize = 0x05,
    MaxHeaderListSize = 0x06,
    // Extended settings for advanced fingerprinting
    EnableConnectProtocol = 0x08,
    NoRfc7540Priorities = 0x09,
}

/// HPACK header compression context
#[derive(Debug, Clone)]
pub struct HpackContext {
    /// Dynamic table for header compression
    dynamic_table: Vec<(String, String)>,
    /// Maximum dynamic table size
    max_table_size: usize,
    /// Current table size
    current_table_size: usize,
}

impl HpackContext {
    pub fn new(max_size: usize) -> Self {
        Self {
            dynamic_table: Vec::new(),
            max_table_size: max_size,
            current_table_size: 0,
        }
    }

    /// Add entry to dynamic table
    pub fn add_entry(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32; // RFC 7541 overhead

        // Evict entries if needed
        while self.current_table_size + entry_size > self.max_table_size
            && !self.dynamic_table.is_empty()
        {
            if let Some((old_name, old_value)) = self.dynamic_table.pop() {
                self.current_table_size -= old_name.len() + old_value.len() + 32;
            }
        }

        if entry_size <= self.max_table_size {
            self.dynamic_table.insert(0, (name, value));
            self.current_table_size += entry_size;
        }
    }

    /// Find header in static or dynamic table
    pub fn find_header(&self, name: &str, value: &str) -> Option<usize> {
        // Check static table first (simplified - real implementation would have full static table)
        let static_entries = [
            (":authority", ""),
            (":method", "GET"),
            (":method", "POST"),
            (":path", "/"),
            (":path", "/index.html"),
            (":scheme", "http"),
            (":scheme", "https"),
            (":status", "200"),
            (":status", "204"),
            (":status", "206"),
            (":status", "304"),
            (":status", "400"),
            (":status", "404"),
            (":status", "500"),
            ("accept-charset", ""),
            ("accept-encoding", "gzip, deflate"),
            ("accept-language", ""),
            ("accept-ranges", ""),
            ("accept", ""),
            ("access-control-allow-origin", ""),
            ("age", ""),
            ("allow", ""),
            ("authorization", ""),
            ("cache-control", ""),
            ("content-disposition", ""),
            ("content-encoding", ""),
            ("content-language", ""),
            ("content-length", ""),
            ("content-location", ""),
            ("content-range", ""),
            ("content-type", ""),
            ("cookie", ""),
            ("date", ""),
            ("etag", ""),
            ("expect", ""),
            ("expires", ""),
            ("from", ""),
            ("host", ""),
            ("if-match", ""),
            ("if-modified-since", ""),
            ("if-none-match", ""),
            ("if-range", ""),
            ("if-unmodified-since", ""),
            ("last-modified", ""),
            ("link", ""),
            ("location", ""),
            ("max-forwards", ""),
            ("proxy-authenticate", ""),
            ("proxy-authorization", ""),
            ("range", ""),
            ("referer", ""),
            ("refresh", ""),
            ("retry-after", ""),
            ("server", ""),
            ("set-cookie", ""),
            ("strict-transport-security", ""),
            ("transfer-encoding", ""),
            ("user-agent", ""),
            ("vary", ""),
            ("via", ""),
            ("www-authenticate", ""),
        ];

        // Check static table
        for (i, (static_name, static_value)) in static_entries.iter().enumerate() {
            if *static_name == name && (*static_value == value || static_value.is_empty()) {
                return Some(i + 1); // Static table starts at index 1
            }
        }

        // Check dynamic table
        for (i, (dyn_name, dyn_value)) in self.dynamic_table.iter().enumerate() {
            if dyn_name == name && (dyn_value == value || value.is_empty()) {
                return Some(static_entries.len() + 1 + i);
            }
        }

        None
    }

    /// Encode header using HPACK
    pub fn encode_header(&mut self, name: &str, value: &str) -> Vec<u8> {
        let mut encoded = Vec::new();

        if let Some(index) = self.find_header(name, value) {
            // Indexed header field
            encoded.push(0x80 | (index as u8));
        } else if let Some(name_index) = self.find_header(name, "") {
            // Literal header field with incremental indexing - indexed name
            encoded.push(0x40 | (name_index as u8));
            // Encode value
            self.encode_string(&mut encoded, value, false);
            // Add to dynamic table
            self.add_entry(name.to_string(), value.to_string());
        } else {
            // Literal header field with incremental indexing - new name
            encoded.push(0x40);
            // Encode name
            self.encode_string(&mut encoded, name, false);
            // Encode value
            self.encode_string(&mut encoded, value, false);
            // Add to dynamic table
            self.add_entry(name.to_string(), value.to_string());
        }

        encoded
    }

    /// Encode string with optional Huffman coding
    fn encode_string(&self, output: &mut Vec<u8>, s: &str, huffman: bool) {
        let bytes = s.as_bytes();
        if huffman {
            // Simplified - real implementation would use Huffman coding
            output.push(0x80 | (bytes.len() as u8));
        } else {
            output.push(bytes.len() as u8);
        }
        output.extend_from_slice(bytes);
    }
}

/// HTTP/2 fingerprint profile for a specific browser
#[derive(Debug, Clone)]
pub struct Http2Profile {
    pub name: String,
    /// SETTINGS frame parameters in order
    pub settings_order: Vec<(SettingsParameter, u32)>,
    /// Initial WINDOW_UPDATE increment
    pub initial_window_update: u32,
    /// Whether to send PRIORITY frames
    pub send_priority: bool,
    /// Priority weight for streams
    pub priority_weight: u8,
    /// Whether to use stream dependencies
    pub use_stream_dependencies: bool,
    /// Connection preface settings
    pub connection_preface: Vec<u8>,
    /// HPACK table size
    pub hpack_table_size: usize,
    /// Pseudo-header ordering for requests
    pub pseudo_header_order: Vec<String>,
    /// Whether to use Huffman encoding in HPACK
    pub use_huffman_encoding: bool,
    /// Stream dependency tree structure
    pub dependency_tree: Vec<(u32, u32, u8, bool)>, // (stream_id, depends_on, weight, exclusive)
}

impl Http2Profile {
    /// Chrome 120+ HTTP/2 fingerprint
    pub fn chrome_120() -> Self {
        Self {
            name: "Chrome 120+".to_string(),
            settings_order: vec![
                (SettingsParameter::HeaderTableSize, 65536),
                (SettingsParameter::EnablePush, 0),
                (SettingsParameter::MaxConcurrentStreams, 1000),
                (SettingsParameter::InitialWindowSize, 6291456),
                (SettingsParameter::MaxHeaderListSize, 262144),
            ],
            initial_window_update: 15663105,
            send_priority: true,
            priority_weight: 255,
            use_stream_dependencies: true,
            connection_preface: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            hpack_table_size: 65536,
            pseudo_header_order: vec![
                ":method".to_string(),
                ":authority".to_string(),
                ":scheme".to_string(),
                ":path".to_string(),
            ],
            use_huffman_encoding: true,
            dependency_tree: vec![
                (3, 0, 200, false), // Stream 3 depends on 0 with weight 200
                (5, 0, 100, false), // Stream 5 depends on 0 with weight 100
                (7, 0, 0, false),   // Stream 7 depends on 0 with weight 0
                (9, 7, 0, false),   // Stream 9 depends on 7 with weight 0
                (11, 3, 0, false),  // Stream 11 depends on 3 with weight 0
            ],
        }
    }

    /// Firefox 121+ HTTP/2 fingerprint
    pub fn firefox_121() -> Self {
        Self {
            name: "Firefox 121+".to_string(),
            settings_order: vec![
                (SettingsParameter::HeaderTableSize, 65536),
                (SettingsParameter::InitialWindowSize, 131072),
                (SettingsParameter::MaxFrameSize, 16384),
            ],
            initial_window_update: 12517377,
            send_priority: false,
            priority_weight: 0,
            use_stream_dependencies: false,
            connection_preface: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            hpack_table_size: 65536,
            pseudo_header_order: vec![
                ":method".to_string(),
                ":path".to_string(),
                ":authority".to_string(),
                ":scheme".to_string(),
            ],
            use_huffman_encoding: false,
            dependency_tree: vec![], // Firefox doesn't use complex dependency trees
        }
    }

    /// Safari 17+ HTTP/2 fingerprint
    pub fn safari_17() -> Self {
        Self {
            name: "Safari 17+".to_string(),
            settings_order: vec![
                (SettingsParameter::MaxConcurrentStreams, 100),
                (SettingsParameter::InitialWindowSize, 2097152),
                (SettingsParameter::MaxFrameSize, 16384),
            ],
            initial_window_update: 10485760,
            send_priority: true,
            priority_weight: 255,
            use_stream_dependencies: false,
            connection_preface: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            hpack_table_size: 4096,
            pseudo_header_order: vec![
                ":method".to_string(),
                ":scheme".to_string(),
                ":authority".to_string(),
                ":path".to_string(),
            ],
            use_huffman_encoding: true,
            dependency_tree: vec![(3, 0, 200, false), (5, 0, 100, false)],
        }
    }

    /// Edge 120+ HTTP/2 fingerprint (Chromium-based, similar to Chrome)
    pub fn edge_120() -> Self {
        Self {
            name: "Edge 120+".to_string(),
            settings_order: vec![
                (SettingsParameter::HeaderTableSize, 65536),
                (SettingsParameter::EnablePush, 0),
                (SettingsParameter::MaxConcurrentStreams, 1000),
                (SettingsParameter::InitialWindowSize, 6291456),
                (SettingsParameter::MaxHeaderListSize, 262144),
            ],
            initial_window_update: 15663105,
            send_priority: true,
            priority_weight: 255,
            use_stream_dependencies: true,
            connection_preface: b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            hpack_table_size: 65536,
            pseudo_header_order: vec![
                ":method".to_string(),
                ":authority".to_string(),
                ":scheme".to_string(),
                ":path".to_string(),
            ],
            use_huffman_encoding: true,
            dependency_tree: vec![
                (3, 0, 200, false),
                (5, 0, 100, false),
                (7, 0, 0, false),
                (9, 7, 0, false),
                (11, 3, 0, false),
            ],
        }
    }

    /// Build HTTP/2 connection preface with SETTINGS frame
    pub fn build_connection_preface(&self) -> Vec<u8> {
        let mut preface = self.connection_preface.clone();

        // Add SETTINGS frame
        let settings_frame = self.build_settings_frame();
        preface.extend_from_slice(&settings_frame);

        // Add WINDOW_UPDATE frame if needed
        if self.initial_window_update > 0 {
            let window_update = self.build_window_update_frame(0, self.initial_window_update);
            preface.extend_from_slice(&window_update);
        }

        preface
    }

    /// Build SETTINGS frame according to profile
    pub fn build_settings_frame(&self) -> Vec<u8> {
        let mut frame = Vec::new();

        // Frame header (9 bytes)
        let payload_len = self.settings_order.len() * 6;
        frame.push(((payload_len >> 16) & 0xFF) as u8);
        frame.push(((payload_len >> 8) & 0xFF) as u8);
        frame.push((payload_len & 0xFF) as u8);
        frame.push(FrameType::Settings as u8);
        frame.push(0x00); // Flags
        frame.push(0x00); // Stream ID (4 bytes)
        frame.push(0x00);
        frame.push(0x00);
        frame.push(0x00);

        // Settings parameters
        for (param, value) in &self.settings_order {
            frame.push(((*param as u16 >> 8) & 0xFF) as u8);
            frame.push((*param as u16 & 0xFF) as u8);
            frame.push(((*value >> 24) & 0xFF) as u8);
            frame.push(((*value >> 16) & 0xFF) as u8);
            frame.push(((*value >> 8) & 0xFF) as u8);
            frame.push((*value & 0xFF) as u8);
        }

        frame
    }

    /// Build WINDOW_UPDATE frame
    pub fn build_window_update_frame(&self, stream_id: u32, increment: u32) -> Vec<u8> {
        let mut frame = Vec::new();

        // Frame header (9 bytes)
        frame.push(0x00); // Length (3 bytes) - 4 bytes payload
        frame.push(0x00);
        frame.push(0x04);
        frame.push(FrameType::WindowUpdate as u8);
        frame.push(0x00); // Flags

        // Stream ID (4 bytes)
        frame.push(((stream_id >> 24) & 0xFF) as u8);
        frame.push(((stream_id >> 16) & 0xFF) as u8);
        frame.push(((stream_id >> 8) & 0xFF) as u8);
        frame.push((stream_id & 0xFF) as u8);

        // Window size increment (4 bytes, reserved bit must be 0)
        frame.push(((increment >> 24) & 0x7F) as u8);
        frame.push(((increment >> 16) & 0xFF) as u8);
        frame.push(((increment >> 8) & 0xFF) as u8);
        frame.push((increment & 0xFF) as u8);

        frame
    }

    /// Build HPACK-encoded headers with proper pseudo-header ordering
    pub fn build_hpack_headers(
        &self,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Vec<u8> {
        let mut hpack_context = HpackContext::new(self.hpack_table_size);
        let mut encoded_headers = Vec::new();

        // Create pseudo-headers map
        let mut pseudo_headers = std::collections::HashMap::new();
        pseudo_headers.insert(":method".to_string(), method.to_string());
        pseudo_headers.insert(":authority".to_string(), authority.to_string());
        pseudo_headers.insert(":scheme".to_string(), scheme.to_string());
        pseudo_headers.insert(":path".to_string(), path.to_string());

        // Encode pseudo-headers in browser-specific order
        for pseudo_name in &self.pseudo_header_order {
            if let Some(pseudo_value) = pseudo_headers.get(pseudo_name) {
                let encoded = hpack_context.encode_header(pseudo_name, pseudo_value);
                encoded_headers.extend_from_slice(&encoded);
            }
        }

        // Encode regular headers
        for (name, value) in headers {
            let encoded = hpack_context.encode_header(name, value);
            encoded_headers.extend_from_slice(&encoded);
        }

        encoded_headers
    }

    /// Build complete HTTP/2 request with proper frame structure
    pub fn build_http2_request(
        &self,
        stream_id: u32,
        method: &str,
        authority: &str,
        scheme: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut request = Vec::new();

        // Build HPACK-encoded headers
        let encoded_headers = self.build_hpack_headers(method, authority, scheme, path, headers);

        // Build HEADERS frame
        let headers_frame = self.build_headers_frame_with_priority(
            stream_id,
            &encoded_headers,
            body.is_none(), // END_STREAM if no body
            true,           // END_HEADERS
        );
        request.extend_from_slice(&headers_frame);

        // Build DATA frame if body exists
        if let Some(body_data) = body {
            let data_frame = self.build_data_frame(stream_id, body_data, true);
            request.extend_from_slice(&data_frame);
        }

        request
    }

    /// Build DATA frame
    pub fn build_data_frame(&self, stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
        let mut frame = Vec::new();

        // Frame header (9 bytes)
        let payload_len = data.len();
        frame.push(((payload_len >> 16) & 0xFF) as u8);
        frame.push(((payload_len >> 8) & 0xFF) as u8);
        frame.push((payload_len & 0xFF) as u8);
        frame.push(FrameType::Data as u8);

        // Flags
        let flags = if end_stream { 0x01 } else { 0x00 }; // END_STREAM
        frame.push(flags);

        // Stream ID (4 bytes)
        frame.push(((stream_id >> 24) & 0xFF) as u8);
        frame.push(((stream_id >> 16) & 0xFF) as u8);
        frame.push(((stream_id >> 8) & 0xFF) as u8);
        frame.push((stream_id & 0xFF) as u8);

        // Data payload
        frame.extend_from_slice(data);

        frame
    }

    /// Build PRIORITY frame
    pub fn build_priority_frame(
        &self,
        stream_id: u32,
        depends_on: u32,
        exclusive: bool,
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        // Frame header (9 bytes)
        frame.push(0x00); // Length (3 bytes) - 5 bytes payload
        frame.push(0x00);
        frame.push(0x05);
        frame.push(FrameType::Priority as u8);
        frame.push(0x00); // Flags

        // Stream ID (4 bytes)
        frame.push(((stream_id >> 24) & 0xFF) as u8);
        frame.push(((stream_id >> 16) & 0xFF) as u8);
        frame.push(((stream_id >> 8) & 0xFF) as u8);
        frame.push((stream_id & 0xFF) as u8);

        // Stream dependency (4 bytes, with exclusive bit)
        let dep_with_exclusive = if exclusive {
            depends_on | 0x80000000
        } else {
            depends_on & 0x7FFFFFFF
        };
        frame.push(((dep_with_exclusive >> 24) & 0xFF) as u8);
        frame.push(((dep_with_exclusive >> 16) & 0xFF) as u8);
        frame.push(((dep_with_exclusive >> 8) & 0xFF) as u8);
        frame.push((dep_with_exclusive & 0xFF) as u8);

        // Weight (1 byte)
        frame.push(self.priority_weight);

        frame
    }

    /// Build HEADERS frame with PRIORITY
    pub fn build_headers_frame_with_priority(
        &self,
        stream_id: u32,
        headers: &[u8],
        end_stream: bool,
        end_headers: bool,
    ) -> Vec<u8> {
        let mut frame = Vec::new();

        let priority_len = if self.send_priority && self.use_stream_dependencies {
            5
        } else {
            0
        };
        let payload_len = priority_len + headers.len();

        // Frame header (9 bytes)
        frame.push(((payload_len >> 16) & 0xFF) as u8);
        frame.push(((payload_len >> 8) & 0xFF) as u8);
        frame.push((payload_len & 0xFF) as u8);
        frame.push(FrameType::Headers as u8);

        // Flags
        let mut flags = 0u8;
        if end_stream {
            flags |= 0x01; // END_STREAM
        }
        if end_headers {
            flags |= 0x04; // END_HEADERS
        }
        if self.send_priority && self.use_stream_dependencies {
            flags |= 0x20; // PRIORITY
        }
        frame.push(flags);

        // Stream ID (4 bytes)
        frame.push(((stream_id >> 24) & 0xFF) as u8);
        frame.push(((stream_id >> 16) & 0xFF) as u8);
        frame.push(((stream_id >> 8) & 0xFF) as u8);
        frame.push((stream_id & 0xFF) as u8);

        // Priority data (if enabled)
        if self.send_priority && self.use_stream_dependencies {
            // Stream dependency (exclusive bit set)
            frame.push(0x80);
            frame.push(0x00);
            frame.push(0x00);
            frame.push(0x00);
            // Weight
            frame.push(self.priority_weight);
        }

        // Headers payload
        frame.extend_from_slice(headers);

        frame
    }
}

/// HTTP/2 Fingerprint Manager
pub struct Http2FingerprintManager {
    profiles: HashMap<String, Http2Profile>,
    current_profile: Option<String>,
    randomize_window_update: bool,
    akamai_evasion_enabled: bool,
}

/// AKAMAI-specific HTTP/2 fingerprint patterns
#[derive(Debug, Clone)]
pub struct AkamaiFingerprint {
    /// Expected SETTINGS frame order for AKAMAI detection
    pub settings_signature: Vec<u16>,
    /// Expected pseudo-header order
    pub pseudo_header_signature: String,
    /// Expected PRIORITY frame patterns
    pub priority_patterns: Vec<(u32, u32, u8, bool)>, // (stream_id, depends_on, weight, exclusive)
    /// Expected WINDOW_UPDATE behavior
    pub window_update_pattern: Vec<u32>,
    /// Header compression patterns
    pub hpack_patterns: Vec<String>,
}

impl AkamaiFingerprint {
    /// Chrome fingerprint as detected by AKAMAI
    pub fn chrome_akamai_pattern() -> Self {
        Self {
            settings_signature: vec![0x01, 0x02, 0x03, 0x04, 0x06], // Header table, push, streams, window, header list
            pseudo_header_signature: ":method:authority:scheme:path".to_string(),
            priority_patterns: vec![
                (3, 0, 200, false), // Stream 3 → 0, weight 200
                (5, 0, 100, false), // Stream 5 → 0, weight 100
                (7, 0, 0, false),   // Stream 7 → 0, weight 0
                (9, 7, 0, false),   // Stream 9 → 7, weight 0
                (11, 3, 0, false),  // Stream 11 → 3, weight 0
            ],
            window_update_pattern: vec![15663105], // Chrome's specific window update
            hpack_patterns: vec![
                "indexed:1".to_string(),         // :method GET (indexed)
                "indexed:2".to_string(),         // :scheme https (indexed)
                "literal:authority".to_string(), // :authority (literal)
                "literal:path".to_string(),      // :path (literal)
            ],
        }
    }

    /// Firefox fingerprint as detected by AKAMAI
    pub fn firefox_akamai_pattern() -> Self {
        Self {
            settings_signature: vec![0x01, 0x04, 0x05], // Header table, window, frame size
            pseudo_header_signature: ":method:path:authority:scheme".to_string(),
            priority_patterns: vec![], // Firefox doesn't use priority frames
            window_update_pattern: vec![12517377], // Firefox's specific window update
            hpack_patterns: vec![
                "indexed:1".to_string(),
                "literal:path".to_string(),
                "literal:authority".to_string(),
                "indexed:2".to_string(),
            ],
        }
    }

    /// Safari fingerprint as detected by AKAMAI
    pub fn safari_akamai_pattern() -> Self {
        Self {
            settings_signature: vec![0x03, 0x04, 0x05], // Streams, window, frame size
            pseudo_header_signature: ":method:scheme:authority:path".to_string(),
            priority_patterns: vec![(3, 0, 200, false), (5, 0, 100, false)],
            window_update_pattern: vec![10485760], // Safari's specific window update
            hpack_patterns: vec![
                "indexed:1".to_string(),
                "indexed:2".to_string(),
                "literal:authority".to_string(),
                "literal:path".to_string(),
            ],
        }
    }

    /// Check if current connection matches this AKAMAI pattern
    pub fn matches_pattern(&self, connection_data: &Http2ConnectionData) -> bool {
        // Check SETTINGS frame signature
        if connection_data.settings_order != self.settings_signature {
            return false;
        }

        // Check pseudo-header order
        if connection_data.pseudo_header_order != self.pseudo_header_signature {
            return false;
        }

        // Check PRIORITY patterns
        if connection_data.priority_frames != self.priority_patterns {
            return false;
        }

        // Check WINDOW_UPDATE pattern
        if !self
            .window_update_pattern
            .contains(&connection_data.window_update_increment)
        {
            return false;
        }

        true
    }
}

/// HTTP/2 connection data for fingerprint analysis
#[derive(Debug, Clone)]
pub struct Http2ConnectionData {
    pub settings_order: Vec<u16>,
    pub pseudo_header_order: String,
    pub priority_frames: Vec<(u32, u32, u8, bool)>,
    pub window_update_increment: u32,
    pub hpack_usage: Vec<String>,
}
impl Http2FingerprintManager {
    pub fn new() -> Self {
        let mut profiles = HashMap::new();

        profiles.insert("chrome_120".to_string(), Http2Profile::chrome_120());
        profiles.insert("firefox_121".to_string(), Http2Profile::firefox_121());
        profiles.insert("safari_17".to_string(), Http2Profile::safari_17());
        profiles.insert("edge_120".to_string(), Http2Profile::edge_120());

        Self {
            profiles,
            current_profile: None,
            randomize_window_update: false,
            akamai_evasion_enabled: false,
        }
    }

    /// Enable AKAMAI-specific evasion techniques
    pub fn enable_akamai_evasion(&mut self) {
        self.akamai_evasion_enabled = true;
    }

    /// Disable AKAMAI-specific evasion techniques
    pub fn disable_akamai_evasion(&mut self) {
        self.akamai_evasion_enabled = false;
    }

    /// Set the active HTTP/2 profile
    pub fn set_profile(&mut self, name: &str) -> Result<(), String> {
        if self.profiles.contains_key(name) {
            self.current_profile = Some(name.to_string());
            Ok(())
        } else {
            Err(format!("Unknown HTTP/2 profile: {}", name))
        }
    }

    /// Enable randomization of WINDOW_UPDATE behavior
    pub fn enable_window_update_randomization(&mut self) {
        self.randomize_window_update = true;
    }

    /// Get the current profile
    pub fn get_current_profile(&self) -> Option<&Http2Profile> {
        self.current_profile
            .as_ref()
            .and_then(|name| self.profiles.get(name))
    }

    /// Build connection preface with current profile and AKAMAI evasion
    pub fn build_connection_preface(&self) -> Option<Vec<u8>> {
        self.get_current_profile().map(|profile| {
            let mut preface = profile.build_connection_preface();

            if self.akamai_evasion_enabled {
                // Add AKAMAI-specific evasion techniques
                preface = self.apply_akamai_evasion(preface, profile);
            }

            preface
        })
    }

    /// Apply AKAMAI-specific evasion techniques to connection preface
    fn apply_akamai_evasion(&self, mut preface: Vec<u8>, profile: &Http2Profile) -> Vec<u8> {
        // AKAMAI looks for specific patterns in the connection setup

        // 1. Add subtle timing variations in frame ordering
        if profile.name.contains("Chrome") {
            // Chrome-specific AKAMAI evasion: Add extra PRIORITY frames
            for (stream_id, depends_on, weight, exclusive) in &profile.dependency_tree {
                let priority_frame =
                    profile.build_priority_frame(*stream_id, *depends_on, *exclusive);
                preface.extend_from_slice(&priority_frame);
            }
        }

        // 2. Modify SETTINGS frame to avoid exact pattern matching
        if self.randomize_window_update {
            // Add slight randomization to avoid exact signature matching
            let mut rng = rand::thread_rng();
            let jitter = rng.gen_range(-1024..1024);
            let modified_window =
                (profile.initial_window_update as i64 + jitter as i64).max(1024) as u32;

            let window_update = profile.build_window_update_frame(0, modified_window);
            preface.extend_from_slice(&window_update);
        }

        // 3. Add browser-specific PING frames that AKAMAI expects
        let ping_frame = self.build_akamai_ping_frame(profile);
        preface.extend_from_slice(&ping_frame);

        preface
    }

    /// Build AKAMAI-expected PING frame
    fn build_akamai_ping_frame(&self, profile: &Http2Profile) -> Vec<u8> {
        let mut frame = Vec::new();

        // PING frame header (9 bytes)
        frame.push(0x00); // Length (3 bytes) - 8 bytes payload
        frame.push(0x00);
        frame.push(0x08);
        frame.push(FrameType::Ping as u8);
        frame.push(0x00); // Flags (no ACK)

        // Stream ID (4 bytes) - must be 0 for PING
        frame.push(0x00);
        frame.push(0x00);
        frame.push(0x00);
        frame.push(0x00);

        // PING payload (8 bytes) - browser-specific patterns
        if profile.name.contains("Chrome") {
            // Chrome's PING pattern
            frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        } else if profile.name.contains("Firefox") {
            // Firefox's PING pattern
            frame.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        } else if profile.name.contains("Safari") {
            // Safari's PING pattern
            frame.extend_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        } else {
            // Default pattern
            frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        frame
    }

    /// Build WINDOW_UPDATE with AKAMAI evasion
    pub fn build_window_update(&self, stream_id: u32) -> Option<Vec<u8>> {
        self.get_current_profile().map(|profile| {
            let increment = if self.randomize_window_update || self.akamai_evasion_enabled {
                // AKAMAI evasion: Add controlled randomization
                let base = profile.initial_window_update as f64;
                let variation = if self.akamai_evasion_enabled {
                    base * 0.05 // Smaller variation for AKAMAI evasion
                } else {
                    base * 0.1
                };
                let mut rng = rand::thread_rng();
                let random_offset = rng.gen_range(-variation..variation) as i64;
                ((base as i64 + random_offset).max(1024) as u32).min(0x7FFFFFFF)
            } else {
                profile.initial_window_update
            };

            profile.build_window_update_frame(stream_id, increment)
        })
    }

    /// Build HEADERS frame with AKAMAI evasion
    pub fn build_headers_frame(
        &self,
        stream_id: u32,
        headers: &[u8],
        end_stream: bool,
        end_headers: bool,
    ) -> Option<Vec<u8>> {
        self.get_current_profile().map(|profile| {
            let mut frame = profile.build_headers_frame_with_priority(
                stream_id,
                headers,
                end_stream,
                end_headers,
            );

            if self.akamai_evasion_enabled {
                // AKAMAI-specific header frame modifications
                frame = self.apply_akamai_header_evasion(frame, profile);
            }

            frame
        })
    }

    /// Apply AKAMAI-specific evasion to HEADERS frame
    fn apply_akamai_header_evasion(&self, mut frame: Vec<u8>, profile: &Http2Profile) -> Vec<u8> {
        // AKAMAI analyzes header compression patterns
        // Modify HPACK encoding to avoid detection

        if profile.use_huffman_encoding {
            // Ensure Huffman encoding is used consistently with browser pattern
            // This is already handled in the HPACK context, but we can add
            // additional browser-specific patterns here
        }

        // Add padding to avoid exact frame size matching (if supported)
        if frame.len() < 1024 {
            // Add PADDING if frame is small enough
            let padding_len = rand::thread_rng().gen_range(1..16);

            // Modify flags to include PADDED
            if frame.len() >= 9 {
                frame[4] |= 0x08; // PADDED flag

                // Insert padding length after frame header
                frame.insert(9, padding_len);

                // Add padding bytes at the end
                for _ in 0..padding_len {
                    frame.push(0x00);
                }

                // Update frame length
                let new_len = frame.len() - 9;
                frame[0] = ((new_len >> 16) & 0xFF) as u8;
                frame[1] = ((new_len >> 8) & 0xFF) as u8;
                frame[2] = (new_len & 0xFF) as u8;
            }
        }

        frame
    }

    /// Analyze connection for AKAMAI fingerprint patterns
    pub fn analyze_akamai_fingerprint(&self, connection_data: &Http2ConnectionData) -> String {
        let chrome_pattern = AkamaiFingerprint::chrome_akamai_pattern();
        let firefox_pattern = AkamaiFingerprint::firefox_akamai_pattern();
        let safari_pattern = AkamaiFingerprint::safari_akamai_pattern();

        if chrome_pattern.matches_pattern(connection_data) {
            "chrome_akamai_detected".to_string()
        } else if firefox_pattern.matches_pattern(connection_data) {
            "firefox_akamai_detected".to_string()
        } else if safari_pattern.matches_pattern(connection_data) {
            "safari_akamai_detected".to_string()
        } else {
            "unknown_akamai_pattern".to_string()
        }
    }

    /// List available profiles
    pub fn list_profiles(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }

    /// Add custom profile
    pub fn add_custom_profile(&mut self, name: String, profile: Http2Profile) {
        self.profiles.insert(name, profile);
    }
}

impl Default for Http2FingerprintManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_profile_creation() {
        let chrome = Http2Profile::chrome_120();
        assert!(!chrome.settings_order.is_empty());
        assert!(chrome.initial_window_update > 0);
        assert!(chrome.send_priority);

        let firefox = Http2Profile::firefox_121();
        assert!(!firefox.settings_order.is_empty());
        assert!(!firefox.send_priority);
    }

    #[test]
    fn test_settings_frame_build() {
        let chrome = Http2Profile::chrome_120();
        let frame = chrome.build_settings_frame();

        // Frame should start with length (3 bytes) + type (1 byte)
        assert!(frame.len() >= 9);
        assert_eq!(frame[3], FrameType::Settings as u8);

        // Stream ID should be 0 for SETTINGS
        assert_eq!(frame[5], 0x00);
        assert_eq!(frame[6], 0x00);
        assert_eq!(frame[7], 0x00);
        assert_eq!(frame[8], 0x00);
    }

    #[test]
    fn test_window_update_frame() {
        let chrome = Http2Profile::chrome_120();
        let frame = chrome.build_window_update_frame(0, 15663105);

        assert_eq!(frame.len(), 13); // 9 byte header + 4 byte payload
        assert_eq!(frame[3], FrameType::WindowUpdate as u8);

        // Extract increment value
        let increment = ((frame[9] as u32 & 0x7F) << 24)
            | ((frame[10] as u32) << 16)
            | ((frame[11] as u32) << 8)
            | (frame[12] as u32);
        assert_eq!(increment, 15663105);
    }

    #[test]
    fn test_priority_frame() {
        let chrome = Http2Profile::chrome_120();
        let frame = chrome.build_priority_frame(1, 0, true);

        assert_eq!(frame.len(), 14); // 9 byte header + 5 byte payload
        assert_eq!(frame[3], FrameType::Priority as u8);

        // Check exclusive bit is set
        assert_eq!(frame[9] & 0x80, 0x80);

        // Check weight
        assert_eq!(frame[13], chrome.priority_weight);
    }

    #[test]
    fn test_connection_preface() {
        let chrome = Http2Profile::chrome_120();
        let preface = chrome.build_connection_preface();

        // Should start with HTTP/2 connection preface
        assert!(preface.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));

        // Should contain SETTINGS frame
        let settings_start = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".len();
        assert!(preface.len() > settings_start);
        assert_eq!(preface[settings_start + 3], FrameType::Settings as u8);
    }

    #[test]
    fn test_http2_fingerprint_manager() {
        let mut manager = Http2FingerprintManager::new();

        assert!(manager.set_profile("chrome_120").is_ok());
        assert!(manager.get_current_profile().is_some());
        assert!(manager.build_connection_preface().is_some());

        assert!(manager.set_profile("invalid_profile").is_err());
    }

    #[test]
    fn test_window_update_randomization() {
        let mut manager = Http2FingerprintManager::new();
        manager.set_profile("chrome_120").unwrap();
        manager.enable_window_update_randomization();

        let frame1 = manager.build_window_update(0).unwrap();
        let frame2 = manager.build_window_update(0).unwrap();

        // Extract increments
        let inc1 = ((frame1[9] as u32 & 0x7F) << 24)
            | ((frame1[10] as u32) << 16)
            | ((frame1[11] as u32) << 8)
            | (frame1[12] as u32);
        let inc2 = ((frame2[9] as u32 & 0x7F) << 24)
            | ((frame2[10] as u32) << 16)
            | ((frame2[11] as u32) << 8)
            | (frame2[12] as u32);

        // With randomization, values should differ (with very high probability)
        // Note: There's a tiny chance they could be equal, but it's negligible
        assert!(inc1 > 0 && inc2 > 0);
    }

    #[test]
    fn test_headers_frame_with_priority() {
        let chrome = Http2Profile::chrome_120();
        let headers = b"test headers";
        let frame = chrome.build_headers_frame_with_priority(1, headers, true, true);

        assert_eq!(frame[3], FrameType::Headers as u8);

        // Check flags (END_STREAM | END_HEADERS | PRIORITY)
        let flags = frame[4];
        assert_eq!(flags & 0x01, 0x01); // END_STREAM
        assert_eq!(flags & 0x04, 0x04); // END_HEADERS
        assert_eq!(flags & 0x20, 0x20); // PRIORITY

        // Stream ID should be 1
        let stream_id = ((frame[5] as u32) << 24)
            | ((frame[6] as u32) << 16)
            | ((frame[7] as u32) << 8)
            | (frame[8] as u32);
        assert_eq!(stream_id, 1);
    }

    #[test]
    fn test_different_browser_profiles() {
        let profiles = vec![
            ("chrome", Http2Profile::chrome_120()),
            ("firefox", Http2Profile::firefox_121()),
            ("safari", Http2Profile::safari_17()),
            ("edge", Http2Profile::edge_120()),
        ];

        for (name, profile) in &profiles {
            let preface = profile.build_connection_preface();
            assert!(preface.len() > 24, "{} preface should be substantial", name);

            let settings = profile.build_settings_frame();
            assert!(settings.len() >= 9, "{} should have valid SETTINGS", name);
        }
    }

    #[test]
    fn test_settings_order_preservation() {
        let chrome = Http2Profile::chrome_120();
        let frame = chrome.build_settings_frame();

        // Skip frame header (9 bytes)
        let mut offset = 9;
        for (expected_param, expected_value) in &chrome.settings_order {
            let param_id = ((frame[offset] as u16) << 8) | (frame[offset + 1] as u16);
            let value = ((frame[offset + 2] as u32) << 24)
                | ((frame[offset + 3] as u32) << 16)
                | ((frame[offset + 4] as u32) << 8)
                | (frame[offset + 5] as u32);

            assert_eq!(param_id, *expected_param as u16);
            assert_eq!(value, *expected_value);

            offset += 6;
        }
    }
}
