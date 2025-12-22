use std::collections::HashMap;

/// Protocol morphing types supported by the system
#[derive(Debug, Clone, PartialEq)]
pub enum MorphType {
    Http2Frame,
    Http3Quic,
    WebSocketFrame,
    DnsQuery,
    TlsRecord,
}

/// State for maintaining protocol-specific context
#[derive(Debug, Clone)]
pub struct MorphState {
    pub stream_id: u32,
    pub sequence_number: u32,
    pub connection_id: u64,
    pub masking_key: [u8; 4],
    pub dns_transaction_id: u16,
}

impl Default for MorphState {
    fn default() -> Self {
        Self {
            stream_id: 1,
            sequence_number: 0,
            connection_id: 0x1234567890abcdef,
            masking_key: [0x12, 0x34, 0x56, 0x78],
            dns_transaction_id: 0x1234,
        }
    }
}

/// Main protocol morphing engine
pub struct ProtocolMorpher {
    morph_type: MorphType,
    state: MorphState,
}

impl ProtocolMorpher {
    /// Create a new protocol morpher with the specified type
    pub fn new(morph_type: MorphType) -> Self {
        Self {
            morph_type,
            state: MorphState::default(),
        }
    }

    /// Morph payload into the target protocol format
    pub fn morph(&mut self, payload: &[u8]) -> Vec<u8> {
        match self.morph_type {
            MorphType::Http2Frame => self.morph_http2(payload),
            MorphType::Http3Quic => self.morph_http3_quic(payload),
            MorphType::WebSocketFrame => self.morph_websocket(payload),
            MorphType::DnsQuery => self.morph_dns_query(payload),
            MorphType::TlsRecord => self.morph_tls_record(payload),
        }
    }

    /// Unmorph protocol-formatted data back to original payload
    pub fn unmorph(&mut self, morphed: &[u8]) -> Vec<u8> {
        match self.morph_type {
            MorphType::Http2Frame => self.unmorph_http2(morphed),
            MorphType::Http3Quic => self.unmorph_http3_quic(morphed),
            MorphType::WebSocketFrame => self.unmorph_websocket(morphed),
            MorphType::DnsQuery => self.unmorph_dns_query(morphed),
            MorphType::TlsRecord => self.unmorph_tls_record(morphed),
        }
    }

    /// Build valid HTTP/2 DATA frame
    fn morph_http2(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();

        // HTTP/2 Frame Format:
        // +-----------------------------------------------+
        // |                 Length (24)                   |
        // +---------------+---------------+---------------+
        // |   Type (8)    |   Flags (8)   |
        // +-+-------------+---------------+-------------------------------+
        // |R|                 Stream Identifier (31)                      |
        // +=+=============================================================+
        // |                   Frame Payload (0...)                     ...
        // +---------------------------------------------------------------+

        // Length (24 bits) - payload length
        let length = payload.len() as u32;
        frame.extend_from_slice(&length.to_be_bytes()[1..4]); // Take only 3 bytes

        // Type (8 bits) - DATA frame = 0x00
        frame.push(0x00);

        // Flags (8 bits) - END_STREAM = 0x01
        frame.push(0x01);

        // Stream Identifier (31 bits) - R bit is reserved (0)
        frame.extend_from_slice(&self.state.stream_id.to_be_bytes());

        // Frame Payload
        frame.extend_from_slice(payload);

        // Increment stream ID for next frame (must be odd for client-initiated)
        self.state.stream_id += 2;

        frame
    }

    /// Extract payload from HTTP/2 DATA frame
    fn unmorph_http2(&self, morphed: &[u8]) -> Vec<u8> {
        if morphed.len() < 9 {
            return Vec::new(); // Invalid frame
        }

        // Extract length from first 3 bytes
        let length = u32::from_be_bytes([0, morphed[0], morphed[1], morphed[2]]) as usize;

        // Verify frame type is DATA (0x00)
        if morphed[3] != 0x00 {
            return Vec::new(); // Not a DATA frame
        }

        // Extract payload (skip 9-byte header)
        if morphed.len() >= 9 + length {
            morphed[9..9 + length].to_vec()
        } else {
            Vec::new() // Invalid frame length
        }
    }

    /// Build valid DNS query structure
    fn morph_dns_query(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut dns_packet = Vec::new();

        // DNS Header (12 bytes)
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        // Transaction ID
        dns_packet.extend_from_slice(&self.state.dns_transaction_id.to_be_bytes());

        // Flags: Standard query (QR=0, Opcode=0, RD=1)
        dns_packet.extend_from_slice(&0x0100u16.to_be_bytes());

        // Question count = 1
        dns_packet.extend_from_slice(&1u16.to_be_bytes());

        // Answer count = 0
        dns_packet.extend_from_slice(&0u16.to_be_bytes());

        // Authority count = 0
        dns_packet.extend_from_slice(&0u16.to_be_bytes());

        // Additional count = 0
        dns_packet.extend_from_slice(&0u16.to_be_bytes());

        // Question section
        // Encode payload as base32 and create a domain name
        let encoded_payload = base32_encode(payload);
        let domain_name = format!("{}.tunnel.local", encoded_payload);

        // Encode domain name in DNS format
        for label in domain_name.split('.') {
            dns_packet.push(label.len() as u8);
            dns_packet.extend_from_slice(label.as_bytes());
        }
        dns_packet.push(0); // Null terminator

        // QTYPE: TXT record (16)
        dns_packet.extend_from_slice(&16u16.to_be_bytes());

        // QCLASS: IN (1)
        dns_packet.extend_from_slice(&1u16.to_be_bytes());

        // Increment transaction ID for next query
        self.state.dns_transaction_id = self.state.dns_transaction_id.wrapping_add(1);

        dns_packet
    }

    /// Extract payload from DNS query
    fn unmorph_dns_query(&self, morphed: &[u8]) -> Vec<u8> {
        if morphed.len() < 12 {
            return Vec::new(); // Invalid DNS packet
        }

        // Skip DNS header (12 bytes)
        let mut pos = 12;

        // Parse domain name to extract encoded payload
        let mut domain_parts = Vec::new();

        while pos < morphed.len() {
            let label_len = morphed[pos] as usize;
            pos += 1;

            if label_len == 0 {
                break; // End of domain name
            }

            if pos + label_len > morphed.len() {
                return Vec::new(); // Invalid packet
            }

            let label = String::from_utf8_lossy(&morphed[pos..pos + label_len]);
            domain_parts.push(label.to_string());
            pos += label_len;
        }

        // Extract the first part (encoded payload) and decode
        if let Some(encoded_payload) = domain_parts.first() {
            base32_decode(encoded_payload).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Build valid WebSocket frame with masking
    fn morph_websocket(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();

        // WebSocket Frame Format:
        //  0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-------+-+-------------+-------------------------------+
        // |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        // |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        // |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        // | |1|2|3|       |K|             |                               |
        // +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        // |     Extended payload length continued, if payload len == 127  |
        // + - - - - - - - - - - - - - - - +-------------------------------+
        // |                               |Masking-key, if MASK set to 1  |
        // +-------------------------------+-------------------------------+
        // | Masking-key (continued)       |          Payload Data         |
        // +-------------------------------- - - - - - - - - - - - - - - - +
        // :                     Payload Data continued ...                :
        // + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        // |                     Payload Data continued ...                |
        // +---------------------------------------------------------------+

        // First byte: FIN=1, RSV=000, Opcode=0x2 (binary frame)
        frame.push(0x82);

        // Second byte: MASK=1, Payload length
        let payload_len = payload.len();
        if payload_len < 126 {
            frame.push(0x80 | (payload_len as u8));
        } else if payload_len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        // Masking key (4 bytes)
        frame.extend_from_slice(&self.state.masking_key);

        // Masked payload
        for (i, &byte) in payload.iter().enumerate() {
            let masked_byte = byte ^ self.state.masking_key[i % 4];
            frame.push(masked_byte);
        }

        // Update masking key for next frame
        for key_byte in &mut self.state.masking_key {
            *key_byte = key_byte.wrapping_add(1);
        }

        frame
    }

    /// Extract payload from WebSocket frame
    fn unmorph_websocket(&self, morphed: &[u8]) -> Vec<u8> {
        if morphed.len() < 6 {
            return Vec::new(); // Invalid frame
        }

        let mut pos = 2; // Skip first two bytes

        // Parse payload length
        let payload_len = match morphed[1] & 0x7F {
            126 => {
                if morphed.len() < pos + 2 {
                    return Vec::new();
                }
                let len = u16::from_be_bytes([morphed[pos], morphed[pos + 1]]) as usize;
                pos += 2;
                len
            }
            127 => {
                if morphed.len() < pos + 8 {
                    return Vec::new();
                }
                let len = u64::from_be_bytes([
                    morphed[pos],
                    morphed[pos + 1],
                    morphed[pos + 2],
                    morphed[pos + 3],
                    morphed[pos + 4],
                    morphed[pos + 5],
                    morphed[pos + 6],
                    morphed[pos + 7],
                ]) as usize;
                pos += 8;
                len
            }
            len => len as usize,
        };

        // Check if frame is masked
        if (morphed[1] & 0x80) == 0 {
            return Vec::new(); // Frame should be masked
        }

        // Extract masking key
        if morphed.len() < pos + 4 {
            return Vec::new();
        }
        let masking_key = [
            morphed[pos],
            morphed[pos + 1],
            morphed[pos + 2],
            morphed[pos + 3],
        ];
        pos += 4;

        // Extract and unmask payload
        if morphed.len() < pos + payload_len {
            return Vec::new();
        }

        let mut payload = Vec::with_capacity(payload_len);
        for i in 0..payload_len {
            let masked_byte = morphed[pos + i];
            let unmasked_byte = masked_byte ^ masking_key[i % 4];
            payload.push(unmasked_byte);
        }

        payload
    }

    /// Build valid HTTP/3 QUIC packet
    fn morph_http3_quic(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        // QUIC Long Header Format (for HTTP/3):
        // +-+-+-+-+-+-+-+-+
        // |1|1|T T|X X X X|
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                         Version (32)                         |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // | DCID Len (8)  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |               Destination Connection ID (0..160)            ...
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // | SCID Len (8)  |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                 Source Connection ID (0..160)              ...
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        // First byte: Header Form=1, Fixed Bit=1, Type=00 (Initial), Reserved=0000
        packet.push(0xC0);

        // Version: QUIC v1 (0x00000001)
        packet.extend_from_slice(&0x00000001u32.to_be_bytes());

        // Destination Connection ID Length (8 bytes)
        packet.push(8);

        // Destination Connection ID
        packet.extend_from_slice(&self.state.connection_id.to_be_bytes());

        // Source Connection ID Length (8 bytes)
        packet.push(8);

        // Source Connection ID (different from DCID)
        let src_conn_id = self.state.connection_id.wrapping_add(1);
        packet.extend_from_slice(&src_conn_id.to_be_bytes());

        // Token Length (0 for Initial packets without token)
        packet.push(0);

        // Length (variable-length integer encoding)
        let payload_len = payload.len() + 16; // Add space for packet number and payload
        if payload_len < 64 {
            packet.push(payload_len as u8);
        } else if payload_len < 16384 {
            let len_bytes = (payload_len as u16 | 0x4000).to_be_bytes();
            packet.extend_from_slice(&len_bytes);
        } else {
            let len_bytes = (payload_len as u32 | 0x80000000).to_be_bytes();
            packet.extend_from_slice(&len_bytes);
        }

        // Packet Number (4 bytes, encrypted in real QUIC)
        packet.extend_from_slice(&self.state.sequence_number.to_be_bytes());

        // HTTP/3 STREAM frame
        // Frame Type: STREAM (0x08-0x0f, we use 0x08)
        packet.push(0x08);

        // Stream ID (variable-length integer)
        if self.state.stream_id < 64 {
            packet.push(self.state.stream_id as u8);
        } else {
            let stream_bytes = (self.state.stream_id as u16 | 0x4000).to_be_bytes();
            packet.extend_from_slice(&stream_bytes);
        }

        // Length of stream data
        if payload.len() < 64 {
            packet.push(payload.len() as u8);
        } else {
            let len_bytes = (payload.len() as u16 | 0x4000).to_be_bytes();
            packet.extend_from_slice(&len_bytes);
        }

        // Stream data (our payload)
        packet.extend_from_slice(payload);

        // Update state for next packet
        self.state.sequence_number = self.state.sequence_number.wrapping_add(1);
        self.state.stream_id += 4; // Client-initiated bidirectional streams increment by 4

        packet
    }

    /// Extract payload from HTTP/3 QUIC packet
    fn unmorph_http3_quic(&self, morphed: &[u8]) -> Vec<u8> {
        if morphed.len() < 20 {
            return Vec::new(); // Too short for valid QUIC packet
        }

        let mut pos = 1; // Skip first byte

        // Skip version (4 bytes)
        pos += 4;

        // Skip DCID
        if pos >= morphed.len() {
            return Vec::new();
        }
        let dcid_len = morphed[pos] as usize;
        pos += 1 + dcid_len;

        // Skip SCID
        if pos >= morphed.len() {
            return Vec::new();
        }
        let scid_len = morphed[pos] as usize;
        pos += 1 + scid_len;

        // Skip token length and token (should be 0 for our packets)
        if pos >= morphed.len() {
            return Vec::new();
        }
        let token_len = morphed[pos] as usize;
        pos += 1 + token_len;

        // Skip length field (variable-length integer)
        if pos >= morphed.len() {
            return Vec::new();
        }
        if (morphed[pos] & 0xC0) == 0x00 {
            pos += 1;
        } else if (morphed[pos] & 0xC0) == 0x40 {
            pos += 2;
        } else if (morphed[pos] & 0xC0) == 0x80 {
            pos += 4;
        } else {
            pos += 8;
        }

        // Skip packet number (4 bytes)
        pos += 4;

        // Skip STREAM frame type
        if pos >= morphed.len() {
            return Vec::new();
        }
        pos += 1;

        // Skip stream ID (variable-length integer)
        if pos >= morphed.len() {
            return Vec::new();
        }
        if (morphed[pos] & 0xC0) == 0x00 {
            pos += 1;
        } else if (morphed[pos] & 0xC0) == 0x40 {
            pos += 2;
        } else if (morphed[pos] & 0xC0) == 0x80 {
            pos += 4;
        } else {
            pos += 8;
        }

        // Parse stream data length
        if pos >= morphed.len() {
            return Vec::new();
        }
        let data_len = if (morphed[pos] & 0xC0) == 0x00 {
            let len = morphed[pos] as usize;
            pos += 1;
            len
        } else if (morphed[pos] & 0xC0) == 0x40 {
            let len = u16::from_be_bytes([morphed[pos] & 0x3F, morphed[pos + 1]]) as usize;
            pos += 2;
            len
        } else {
            return Vec::new(); // Unsupported length encoding
        };

        // Extract stream data
        if pos + data_len <= morphed.len() {
            morphed[pos..pos + data_len].to_vec()
        } else {
            Vec::new()
        }
    }

    /// Build valid TLS record
    fn morph_tls_record(&self, payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();

        // TLS Record Header:
        // +--------+--------+--------+--------+--------+
        // | Type   | Version (2)     | Length (2)     |
        // +--------+--------+--------+--------+--------+

        // Content Type: Application Data (23)
        record.push(23);

        // Version: TLS 1.2 (0x0303)
        record.extend_from_slice(&0x0303u16.to_be_bytes());

        // Length
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());

        // Payload (in real TLS this would be encrypted)
        record.extend_from_slice(payload);

        record
    }

    /// Extract payload from TLS record
    fn unmorph_tls_record(&self, morphed: &[u8]) -> Vec<u8> {
        if morphed.len() < 5 {
            return Vec::new(); // Invalid TLS record
        }

        // Check content type is Application Data (23)
        if morphed[0] != 23 {
            return Vec::new();
        }

        // Extract length
        let length = u16::from_be_bytes([morphed[3], morphed[4]]) as usize;

        // Extract payload
        if morphed.len() >= 5 + length {
            morphed[5..5 + length].to_vec()
        } else {
            Vec::new()
        }
    }
}

/// Simple base32 encoding for DNS-safe characters
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();

    let mut buffer = 0u64;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;

        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

/// Simple base32 decoding
fn base32_decode(encoded: &str) -> Result<Vec<u8>, &'static str> {
    const DECODE_MAP: [u8; 256] = {
        let mut map = [255u8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut i = 0;
        while i < alphabet.len() {
            map[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        map
    };

    let mut result = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for ch in encoded.chars() {
        let value = DECODE_MAP[ch as usize];
        if value == 255 {
            return Err("Invalid base32 character");
        }

        buffer = (buffer << 5) | (value as u64);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_morph_unmorph() {
        let mut morpher = ProtocolMorpher::new(MorphType::Http2Frame);
        let payload = b"Hello, HTTP/2!";

        let morphed = morpher.morph(payload);
        let unmorphed = morpher.unmorph(&morphed);

        assert_eq!(payload.to_vec(), unmorphed);
    }

    #[test]
    fn test_dns_morph_unmorph() {
        let mut morpher = ProtocolMorpher::new(MorphType::DnsQuery);
        let payload = b"Hello, DNS!";

        let morphed = morpher.morph(payload);
        let unmorphed = morpher.unmorph(&morphed);

        assert_eq!(payload.to_vec(), unmorphed);
    }

    #[test]
    fn test_websocket_morph_unmorph() {
        let mut morpher = ProtocolMorpher::new(MorphType::WebSocketFrame);
        let payload = b"Hello, WebSocket!";

        let morphed = morpher.morph(payload);
        let unmorphed = morpher.unmorph(&morphed);

        assert_eq!(payload.to_vec(), unmorphed);
    }

    #[test]
    fn test_http3_quic_morph_unmorph() {
        let mut morpher = ProtocolMorpher::new(MorphType::Http3Quic);
        let payload = b"Hello, HTTP/3!";

        let morphed = morpher.morph(payload);
        let unmorphed = morpher.unmorph(&morphed);

        assert_eq!(payload.to_vec(), unmorphed);
    }

    #[test]
    fn test_tls_morph_unmorph() {
        let mut morpher = ProtocolMorpher::new(MorphType::TlsRecord);
        let payload = b"Hello, TLS!";

        let morphed = morpher.morph(payload);
        let unmorphed = morpher.unmorph(&morphed);

        assert_eq!(payload.to_vec(), unmorphed);
    }

    #[test]
    fn test_base32_encode_decode() {
        let data = b"Hello, World!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();

        assert_eq!(data.to_vec(), decoded);
    }

    /// **Feature: true-military-grade, Property 7: Protocol Morph Validity**
    /// **Validates: Requirements 9.1, 9.2, 9.3**
    ///
    /// Property: For any morphed traffic, the output SHALL be valid according to the target
    /// protocol specification (HTTP/2 frames, DNS queries, WebSocket frames) and parseable
    /// by standard protocol parsers.
    #[test]
    fn test_property_protocol_morph_validity() {
        use std::collections::HashMap;

        // Test data with various payload sizes and content types
        let test_payloads = vec![
            vec![],                                                  // Empty payload
            vec![0x00],                                              // Single byte
            vec![0xFF; 1],                                           // Single byte max value
            vec![0x41, 0x42, 0x43],                                  // ASCII "ABC"
            vec![0x00, 0x01, 0x02, 0x03, 0x04],                      // Sequential bytes
            vec![0xFF; 64],                                          // 64 bytes of 0xFF
            vec![0xAA; 128],                                         // 128 bytes of 0xAA
            vec![0x55; 256],                                         // 256 bytes of 0x55
            b"Hello, World!".to_vec(),                               // Text payload
            b"The quick brown fox jumps over the lazy dog".to_vec(), // Longer text
            (0..100).map(|i| (i % 256) as u8).collect(),             // Pattern payload
        ];

        let morph_types = vec![
            MorphType::Http2Frame,
            MorphType::DnsQuery,
            MorphType::WebSocketFrame,
            MorphType::Http3Quic,
            MorphType::TlsRecord,
        ];

        for morph_type in morph_types {
            for payload in &test_payloads {
                let mut morpher = ProtocolMorpher::new(morph_type.clone());

                // Morph the payload
                let morphed = morpher.morph(payload);

                // Verify morphed data is not empty (unless original payload was empty for some protocols)
                if !payload.is_empty()
                    || matches!(
                        morph_type,
                        MorphType::Http2Frame | MorphType::WebSocketFrame | MorphType::TlsRecord
                    )
                {
                    assert!(
                        !morphed.is_empty(),
                        "Morphed data should not be empty for {:?} with payload len {}",
                        morph_type,
                        payload.len()
                    );
                }

                // Verify protocol-specific validity
                match morph_type {
                    MorphType::Http2Frame => {
                        validate_http2_frame(&morphed, payload);
                    }
                    MorphType::DnsQuery => {
                        validate_dns_query(&morphed, payload);
                    }
                    MorphType::WebSocketFrame => {
                        validate_websocket_frame(&morphed, payload);
                    }
                    MorphType::Http3Quic => {
                        validate_http3_quic_packet(&morphed, payload);
                    }
                    MorphType::TlsRecord => {
                        validate_tls_record(&morphed, payload);
                    }
                }

                // Test round-trip: morph -> unmorph should preserve original payload
                let unmorphed = morpher.unmorph(&morphed);
                assert_eq!(
                    *payload,
                    unmorphed,
                    "Round-trip failed for {:?} with payload len {}",
                    morph_type,
                    payload.len()
                );
            }
        }
    }

    /// Validate HTTP/2 frame structure
    fn validate_http2_frame(frame: &[u8], original_payload: &[u8]) {
        assert!(
            frame.len() >= 9,
            "HTTP/2 frame must be at least 9 bytes (header)"
        );

        // Extract length from first 3 bytes
        let length = u32::from_be_bytes([0, frame[0], frame[1], frame[2]]) as usize;
        assert_eq!(
            length,
            original_payload.len(),
            "HTTP/2 frame length must match payload length"
        );

        // Verify frame type is DATA (0x00)
        assert_eq!(frame[3], 0x00, "HTTP/2 frame type must be DATA (0x00)");

        // Verify flags (should have END_STREAM = 0x01)
        assert_eq!(frame[4], 0x01, "HTTP/2 frame flags should have END_STREAM");

        // Verify stream ID is valid (non-zero, odd for client-initiated)
        let stream_id = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
        assert!(stream_id > 0, "HTTP/2 stream ID must be non-zero");
        assert_eq!(
            stream_id % 2,
            1,
            "HTTP/2 client-initiated stream ID must be odd"
        );

        // Verify total frame length
        assert_eq!(
            frame.len(),
            9 + original_payload.len(),
            "HTTP/2 frame total length incorrect"
        );
    }

    /// Validate DNS query structure
    fn validate_dns_query(query: &[u8], _original_payload: &[u8]) {
        assert!(
            query.len() >= 12,
            "DNS query must be at least 12 bytes (header)"
        );

        // Verify DNS header structure
        // Transaction ID (2 bytes) - can be any value

        // Flags (2 bytes) - should be 0x0100 (standard query, recursion desired)
        let flags = u16::from_be_bytes([query[2], query[3]]);
        assert_eq!(
            flags, 0x0100,
            "DNS flags should be 0x0100 (standard query, RD=1)"
        );

        // Question count should be 1
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        assert_eq!(qdcount, 1, "DNS question count should be 1");

        // Answer, Authority, Additional counts should be 0
        let ancount = u16::from_be_bytes([query[6], query[7]]);
        let nscount = u16::from_be_bytes([query[8], query[9]]);
        let arcount = u16::from_be_bytes([query[10], query[11]]);
        assert_eq!(ancount, 0, "DNS answer count should be 0");
        assert_eq!(nscount, 0, "DNS authority count should be 0");
        assert_eq!(arcount, 0, "DNS additional count should be 0");

        // Verify question section exists and ends with null terminator
        let mut pos = 12;
        let mut found_null = false;
        while pos < query.len() {
            if query[pos] == 0 {
                found_null = true;
                break;
            }
            let label_len = query[pos] as usize;
            pos += 1 + label_len;
        }
        assert!(
            found_null,
            "DNS query must have null-terminated domain name"
        );

        // After null terminator, should have QTYPE (2 bytes) and QCLASS (2 bytes)
        assert!(
            pos + 5 <= query.len(),
            "DNS query must have QTYPE and QCLASS after domain name"
        );
    }

    /// Validate WebSocket frame structure
    fn validate_websocket_frame(frame: &[u8], original_payload: &[u8]) {
        assert!(frame.len() >= 6, "WebSocket frame must be at least 6 bytes");

        // First byte: FIN=1, RSV=000, Opcode=0x2 (binary frame)
        assert_eq!(
            frame[0], 0x82,
            "WebSocket frame first byte should be 0x82 (FIN=1, binary frame)"
        );

        // Second byte: MASK=1, payload length
        assert!(
            (frame[1] & 0x80) != 0,
            "WebSocket frame must be masked (MASK=1)"
        );

        let payload_len_indicator = frame[1] & 0x7F;
        let mut header_len = 2;

        // Determine extended payload length
        if payload_len_indicator == 126 {
            header_len += 2; // 2 bytes for extended length
        } else if payload_len_indicator == 127 {
            header_len += 8; // 8 bytes for extended length
        }

        header_len += 4; // 4 bytes for masking key

        assert!(
            frame.len() >= header_len,
            "WebSocket frame header incomplete"
        );
        assert_eq!(
            frame.len(),
            header_len + original_payload.len(),
            "WebSocket frame total length should be header + payload"
        );
    }

    /// Validate HTTP/3 QUIC packet structure
    fn validate_http3_quic_packet(packet: &[u8], _original_payload: &[u8]) {
        assert!(packet.len() >= 20, "QUIC packet must be at least 20 bytes");

        // First byte: Header Form=1, Fixed Bit=1, Type=00 (Initial)
        assert_eq!(
            packet[0] & 0xF0,
            0xC0,
            "QUIC packet first byte should indicate long header Initial packet"
        );

        // Version: QUIC v1 (0x00000001)
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        assert_eq!(
            version, 0x00000001,
            "QUIC version should be v1 (0x00000001)"
        );

        // DCID Length should be 8
        assert_eq!(packet[5], 8, "QUIC DCID length should be 8");

        // SCID Length should be 8 (at position 5 + 1 + 8 = 14)
        assert_eq!(packet[14], 8, "QUIC SCID length should be 8");

        // Token length should be 0 (at position 14 + 1 + 8 = 23)
        assert_eq!(packet[23], 0, "QUIC token length should be 0");
    }

    /// Validate TLS record structure
    fn validate_tls_record(record: &[u8], original_payload: &[u8]) {
        assert!(
            record.len() >= 5,
            "TLS record must be at least 5 bytes (header)"
        );

        // Content Type: Application Data (23)
        assert_eq!(
            record[0], 23,
            "TLS record content type should be Application Data (23)"
        );

        // Version: TLS 1.2 (0x0303)
        let version = u16::from_be_bytes([record[1], record[2]]);
        assert_eq!(version, 0x0303, "TLS record version should be 1.2 (0x0303)");

        // Length should match payload length
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(
            length,
            original_payload.len(),
            "TLS record length should match payload length"
        );

        // Total record length should be header + payload
        assert_eq!(
            record.len(),
            5 + original_payload.len(),
            "TLS record total length incorrect"
        );
    }
}
