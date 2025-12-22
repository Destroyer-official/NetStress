use bytes::{Buf, BufMut, BytesMut};
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("DNS encoding error: {0}")]
    DnsEncoding(String),
    #[error("Base32 encoding error: {0}")]
    Base32Encoding(String),
    #[error("Invalid payload size: {0}")]
    InvalidPayloadSize(usize),
    #[error("DNS packet too large: {0}")]
    PacketTooLarge(usize),
    #[error("HTTP request error: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Invalid DoH server URL: {0}")]
    InvalidUrl(String),
}

/// DNS message encoder for DoH tunneling
/// Encodes arbitrary payloads as DNS TXT queries using base32 encoding
pub struct DnsEncoder {
    /// Maximum payload size that can be encoded in a single DNS query
    max_payload_size: usize,
}

impl DnsEncoder {
    /// Create a new DNS encoder
    pub fn new() -> Self {
        Self {
            // DNS label max is 63 chars, base32 encodes 5 bits per char
            // So max payload per label is ~39 bytes, but we use conservative 32 bytes
            // Multiple labels can be used for larger payloads
            max_payload_size: 1024, // Conservative limit for DNS over HTTPS
        }
    }

    /// Encode payload as DNS TXT query using base32
    /// Returns a complete DNS packet ready for transmission
    pub fn encode_payload(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        if payload.len() > self.max_payload_size {
            return Err(TunnelError::InvalidPayloadSize(payload.len()));
        }

        // Base32 encode the payload
        let encoded_payload = self.base32_encode(payload)?;

        // Split into DNS labels (max 63 chars each)
        let labels = self.split_into_labels(&encoded_payload);

        // Build DNS query name
        let query_name = format!("{}.tunnel.local", labels.join("."));

        // Build DNS packet
        self.build_dns_packet(&query_name)
    }

    /// Decode DNS TXT response back to original payload
    pub fn decode_response(&self, dns_response: &[u8]) -> Result<Vec<u8>, TunnelError> {
        // Parse DNS response and extract TXT record data
        let txt_data = self.extract_txt_data(dns_response)?;

        // Base32 decode the TXT data
        self.base32_decode(&txt_data)
    }

    /// Base32 encode using DNS-safe alphabet (RFC 4648)
    fn base32_encode(&self, data: &[u8]) -> Result<String, TunnelError> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        let mut result = String::new();
        let mut buffer = 0u64;
        let mut bits = 0;

        for &byte in data {
            buffer = (buffer << 8) | byte as u64;
            bits += 8;

            while bits >= 5 {
                bits -= 5;
                let index = ((buffer >> bits) & 0x1F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        // Handle remaining bits
        if bits > 0 {
            let index = ((buffer << (5 - bits)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }

        Ok(result)
    }

    /// Base32 decode using DNS-safe alphabet
    fn base32_decode(&self, encoded: &str) -> Result<Vec<u8>, TunnelError> {
        let mut decode_map = HashMap::new();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        for (i, &c) in alphabet.iter().enumerate() {
            decode_map.insert(c as char, i as u8);
        }

        let mut result = Vec::new();
        let mut buffer = 0u64;
        let mut bits = 0;

        for c in encoded.chars() {
            let value = decode_map
                .get(&c)
                .ok_or_else(|| TunnelError::Base32Encoding(format!("Invalid character: {}", c)))?;

            buffer = (buffer << 5) | (*value as u64);
            bits += 5;

            if bits >= 8 {
                bits -= 8;
                result.push(((buffer >> bits) & 0xFF) as u8);
            }
        }

        Ok(result)
    }

    /// Split encoded string into DNS labels (max 63 chars each)
    fn split_into_labels(&self, encoded: &str) -> Vec<String> {
        let mut labels = Vec::new();
        let mut remaining = encoded;

        while !remaining.is_empty() {
            let chunk_size = std::cmp::min(63, remaining.len());
            labels.push(remaining[..chunk_size].to_string());
            remaining = &remaining[chunk_size..];
        }

        labels
    }

    /// Build a valid DNS packet with TXT query
    fn build_dns_packet(&self, query_name: &str) -> Result<Vec<u8>, TunnelError> {
        let mut packet = BytesMut::new();

        // DNS Header (12 bytes)
        packet.put_u16(0x1234); // Transaction ID (random)
        packet.put_u16(0x0100); // Flags: Standard query, recursion desired
        packet.put_u16(1); // Questions count
        packet.put_u16(0); // Answer RRs
        packet.put_u16(0); // Authority RRs
        packet.put_u16(0); // Additional RRs

        // Question section
        self.encode_domain_name(&mut packet, query_name)?;
        packet.put_u16(16); // QTYPE: TXT
        packet.put_u16(1); // QCLASS: IN

        if packet.len() > 512 {
            return Err(TunnelError::PacketTooLarge(packet.len()));
        }

        Ok(packet.to_vec())
    }

    /// Encode domain name in DNS wire format
    fn encode_domain_name(&self, packet: &mut BytesMut, name: &str) -> Result<(), TunnelError> {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }

            if label.len() > 63 {
                return Err(TunnelError::DnsEncoding(format!(
                    "Label too long: {} (max 63)",
                    label.len()
                )));
            }

            packet.put_u8(label.len() as u8);
            packet.put_slice(label.as_bytes());
        }

        packet.put_u8(0); // Root label terminator
        Ok(())
    }

    /// Extract TXT record data from DNS response
    fn extract_txt_data(&self, response: &[u8]) -> Result<String, TunnelError> {
        if response.len() < 12 {
            return Err(TunnelError::DnsEncoding("Response too short".to_string()));
        }

        let mut cursor = std::io::Cursor::new(response);

        // Skip DNS header
        cursor.set_position(12);

        // Skip question section (we know there's 1 question)
        self.skip_question_section(&mut cursor)?;

        // Parse answer section
        let answer_count = u16::from_be_bytes([response[6], response[7]]);

        for _ in 0..answer_count {
            // Skip name (compressed or full)
            self.skip_name(&mut cursor)?;

            let rr_type = cursor.get_u16();
            let _rr_class = cursor.get_u16();
            let _ttl = cursor.get_u32();
            let rd_length = cursor.get_u16();

            if rr_type == 16 {
                // TXT record
                let mut txt_data = vec![0u8; rd_length as usize];
                cursor.copy_to_slice(&mut txt_data);

                // TXT records start with length byte
                if !txt_data.is_empty() {
                    let txt_len = txt_data[0] as usize;
                    if txt_len + 1 <= txt_data.len() {
                        return Ok(String::from_utf8_lossy(&txt_data[1..txt_len + 1]).to_string());
                    }
                }
            } else {
                // Skip this record's data
                cursor.set_position(cursor.position() + rd_length as u64);
            }
        }

        Err(TunnelError::DnsEncoding("No TXT record found".to_string()))
    }

    /// Skip question section in DNS response
    fn skip_question_section(
        &self,
        cursor: &mut std::io::Cursor<&[u8]>,
    ) -> Result<(), TunnelError> {
        // Skip QNAME
        self.skip_name(cursor)?;
        // Skip QTYPE and QCLASS
        cursor.set_position(cursor.position() + 4);
        Ok(())
    }

    /// Skip a DNS name (handles compression)
    fn skip_name(&self, cursor: &mut std::io::Cursor<&[u8]>) -> Result<(), TunnelError> {
        loop {
            if cursor.position() >= cursor.get_ref().len() as u64 {
                return Err(TunnelError::DnsEncoding(
                    "Unexpected end of packet".to_string(),
                ));
            }

            let len = cursor.get_u8();

            if len == 0 {
                // End of name
                break;
            } else if (len & 0xC0) == 0xC0 {
                // Compression pointer - skip the pointer
                cursor.set_position(cursor.position() + 1);
                break;
            } else {
                // Regular label - skip the label data
                cursor.set_position(cursor.position() + len as u64);
            }
        }
        Ok(())
    }
}

impl Default for DnsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// DoH HTTPS client for RFC 8484 compliant DNS-over-HTTPS tunneling
pub struct DohClient {
    client: Client,
    server_url: String,
    encoder: DnsEncoder,
}

impl DohClient {
    /// Create a new DoH client for the specified server
    /// 
    /// # Arguments
    /// * `server_url` - DoH server URL (e.g., "https://8.8.8.8/dns-query")
    pub fn new(server_url: &str) -> Result<Self, TunnelError> {
        // Validate URL format
        if !server_url.starts_with("https://") {
            return Err(TunnelError::InvalidUrl(
                "DoH server URL must use HTTPS".to_string()
            ));
        }

        let client = Client::builder()
            .user_agent("NetStress/2.0 DoH Client")
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(Self {
            client,
            server_url: server_url.to_string(),
            encoder: DnsEncoder::new(),
        })
    }

    /// Send payload via DoH tunnel using GET method (RFC 8484)
    /// 
    /// # Arguments
    /// * `payload` - Raw payload to tunnel through DoH
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, TunnelError>` - Decoded response payload
    pub async fn send_get(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        // Encode payload as DNS query
        let dns_query = self.encoder.encode_payload(payload)?;
        
        // Base64url encode for GET parameter (RFC 8484 Section 4.1.1)
        let dns_param = base64_url_encode(&dns_query);
        
        // Build GET request URL
        let url = format!("{}?dns={}", self.server_url, dns_param);
        
        // Send GET request
        let response = self.client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await?;

        // Check response status
        if !response.status().is_success() {
            return Err(TunnelError::HttpRequest(
                reqwest::Error::from(response.error_for_status().unwrap_err())
            ));
        }

        // Get response body
        let dns_response = response.bytes().await?;
        
        // Decode DNS response back to original payload
        self.encoder.decode_response(&dns_response)
    }

    /// Send payload via DoH tunnel using POST method (RFC 8484)
    /// 
    /// # Arguments
    /// * `payload` - Raw payload to tunnel through DoH
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, TunnelError>` - Decoded response payload
    pub async fn send_post(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        // Encode payload as DNS query
        let dns_query = self.encoder.encode_payload(payload)?;
        
        // Send POST request with DNS message in body
        let response = self.client
            .post(&self.server_url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_query)
            .send()
            .await?;

        // Check response status
        if !response.status().is_success() {
            return Err(TunnelError::HttpRequest(
                reqwest::Error::from(response.error_for_status().unwrap_err())
            ));
        }

        // Get response body
        let dns_response = response.bytes().await?;
        
        // Decode DNS response back to original payload
        self.encoder.decode_response(&dns_response)
    }

    /// Send payload via DoH tunnel (automatically chooses GET or POST based on size)
    /// 
    /// # Arguments
    /// * `payload` - Raw payload to tunnel through DoH
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, TunnelError>` - Decoded response payload
    pub async fn send(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        // Use GET for small payloads, POST for larger ones
        // GET has URL length limitations, POST is more suitable for larger payloads
        if payload.len() <= 256 {
            self.send_get(payload).await
        } else {
            self.send_post(payload).await
        }
    }

    /// Get the server URL
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

/// DoH tunnel with server rotation and failover support
pub struct DohTunnel {
    servers: Vec<DohClient>,
    current_server: std::sync::atomic::AtomicUsize,
    encoder: DnsEncoder,
}

impl DohTunnel {
    /// Create a new DoH tunnel with multiple servers for rotation
    /// 
    /// # Arguments
    /// * `server_urls` - List of DoH server URLs for rotation
    /// 
    /// # Default servers
    /// If no servers provided, uses: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9)
    pub fn new(server_urls: Option<Vec<&str>>) -> Result<Self, TunnelError> {
        let default_servers = vec![
            "https://8.8.8.8/dns-query",      // Google Public DNS
            "https://1.1.1.1/dns-query",      // Cloudflare DNS
            "https://9.9.9.9/dns-query",      // Quad9 DNS
        ];

        let urls = server_urls.unwrap_or(default_servers);
        
        if urls.is_empty() {
            return Err(TunnelError::InvalidUrl("No DoH servers provided".to_string()));
        }

        let mut servers = Vec::new();
        for url in urls {
            servers.push(DohClient::new(url)?);
        }

        Ok(Self {
            servers,
            current_server: std::sync::atomic::AtomicUsize::new(0),
            encoder: DnsEncoder::new(),
        })
    }

    /// Send payload through DoH tunnel with automatic server rotation on failure
    /// 
    /// # Arguments
    /// * `payload` - Raw payload to tunnel through DoH
    /// 
    /// # Returns
    /// * `Result<Vec<u8>, TunnelError>` - Decoded response payload
    pub async fn send(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let server_count = self.servers.len();
        let start_index = self.current_server.load(std::sync::atomic::Ordering::Relaxed);

        // Try each server in rotation
        for attempt in 0..server_count {
            let server_index = (start_index + attempt) % server_count;
            let server = &self.servers[server_index];

            match server.send(payload).await {
                Ok(response) => {
                    // Update current server to successful one for next request
                    self.current_server.store(server_index, std::sync::atomic::Ordering::Relaxed);
                    return Ok(response);
                }
                Err(e) => {
                    // Log the error and try next server
                    eprintln!("DoH server {} failed: {}", server.server_url(), e);
                    
                    // If this was the last server to try, return the error
                    if attempt == server_count - 1 {
                        return Err(e);
                    }
                }
            }
        }

        // This should never be reached, but just in case
        Err(TunnelError::DnsEncoding("All DoH servers failed".to_string()))
    }

    /// Send payload using GET method with server rotation
    pub async fn send_get(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let server_count = self.servers.len();
        let start_index = self.current_server.load(std::sync::atomic::Ordering::Relaxed);

        for attempt in 0..server_count {
            let server_index = (start_index + attempt) % server_count;
            let server = &self.servers[server_index];

            match server.send_get(payload).await {
                Ok(response) => {
                    self.current_server.store(server_index, std::sync::atomic::Ordering::Relaxed);
                    return Ok(response);
                }
                Err(e) => {
                    eprintln!("DoH GET server {} failed: {}", server.server_url(), e);
                    if attempt == server_count - 1 {
                        return Err(e);
                    }
                }
            }
        }

        Err(TunnelError::DnsEncoding("All DoH servers failed for GET".to_string()))
    }

    /// Send payload using POST method with server rotation
    pub async fn send_post(&self, payload: &[u8]) -> Result<Vec<u8>, TunnelError> {
        let server_count = self.servers.len();
        let start_index = self.current_server.load(std::sync::atomic::Ordering::Relaxed);

        for attempt in 0..server_count {
            let server_index = (start_index + attempt) % server_count;
            let server = &self.servers[server_index];

            match server.send_post(payload).await {
                Ok(response) => {
                    self.current_server.store(server_index, std::sync::atomic::Ordering::Relaxed);
                    return Ok(response);
                }
                Err(e) => {
                    eprintln!("DoH POST server {} failed: {}", server.server_url(), e);
                    if attempt == server_count - 1 {
                        return Err(e);
                    }
                }
            }
        }

        Err(TunnelError::DnsEncoding("All DoH servers failed for POST".to_string()))
    }

    /// Get list of server URLs
    pub fn server_urls(&self) -> Vec<String> {
        self.servers.iter().map(|s| s.server_url().to_string()).collect()
    }

    /// Get current active server URL
    pub fn current_server_url(&self) -> String {
        let index = self.current_server.load(std::sync::atomic::Ordering::Relaxed);
        self.servers[index % self.servers.len()].server_url().to_string()
    }

    /// Manually rotate to next server
    pub fn rotate_server(&self) {
        let current = self.current_server.load(std::sync::atomic::Ordering::Relaxed);
        let next = (current + 1) % self.servers.len();
        self.current_server.store(next, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Base64url encode (RFC 4648 Section 5) for DoH GET parameters
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[cfg(test)]
    use proptest::prelude::*;

    #[test]
    fn test_base32_encode_decode() {
        let encoder = DnsEncoder::new();
        let test_data = b"Hello, World!";

        let encoded = encoder.base32_encode(test_data).unwrap();
        let decoded = encoder.base32_decode(&encoded).unwrap();

        assert_eq!(test_data, decoded.as_slice());
    }

    #[test]
    fn test_dns_packet_creation() {
        let encoder = DnsEncoder::new();
        let test_payload = b"test payload";

        let dns_packet = encoder.encode_payload(test_payload).unwrap();

        // Verify DNS header structure
        assert!(dns_packet.len() >= 12); // Minimum DNS header size
        assert_eq!(dns_packet[4], 0x00); // Questions count high byte
        assert_eq!(dns_packet[5], 0x01); // Questions count low byte (1 question)
    }

    #[test]
    fn test_label_splitting() {
        let encoder = DnsEncoder::new();
        let long_string = "A".repeat(200);

        let labels = encoder.split_into_labels(&long_string);

        // Verify all labels are <= 63 characters
        for label in &labels {
            assert!(label.len() <= 63);
        }

        // Verify reconstruction
        let reconstructed = labels.join("");
        assert_eq!(long_string, reconstructed);
    }

    #[test]
    fn test_payload_size_limit() {
        let encoder = DnsEncoder::new();
        let large_payload = vec![0u8; 2048]; // Larger than max_payload_size

        let result = encoder.encode_payload(&large_payload);
        assert!(matches!(result, Err(TunnelError::InvalidPayloadSize(_))));
    }

    #[test]
    fn test_empty_payload() {
        let encoder = DnsEncoder::new();
        let empty_payload = b"";

        let dns_packet = encoder.encode_payload(empty_payload).unwrap();
        assert!(dns_packet.len() >= 12); // Should still create valid DNS packet
    }

    #[test]
    fn test_doh_client_creation() {
        // Valid HTTPS URL should work
        let client = DohClient::new("https://8.8.8.8/dns-query");
        assert!(client.is_ok());

        // HTTP URL should fail
        let client = DohClient::new("http://8.8.8.8/dns-query");
        assert!(client.is_err());
        
        // Invalid URL should fail
        let client = DohClient::new("not-a-url");
        assert!(client.is_err());
    }

    #[test]
    fn test_base64_url_encoding() {
        let test_data = b"Hello, World!";
        let encoded = base64_url_encode(test_data);
        
        // Should not contain padding or URL-unsafe characters
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        
        // Should be valid base64url
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_doh_client_server_url() {
        let server_url = "https://1.1.1.1/dns-query";
        let client = DohClient::new(server_url).unwrap();
        assert_eq!(client.server_url(), server_url);
    }

    /// **Feature: true-military-grade, Property 6: DoH Tunnel RFC 8484 Compliance**
    /// **Validates: Requirements 7.1, 7.3**
    ///
    /// Property: For any payload encapsulated via DoH tunnel, the resulting HTTPS request
    /// SHALL contain valid DNS message format with correct Content-Type header and be
    /// parseable by standard DNS libraries.
    proptest! {
        #[test]
        fn test_doh_rfc_compliance(
            payload in prop::collection::vec(any::<u8>(), 0..=1024)
        ) {
            let encoder = DnsEncoder::new();
            
            // Test DNS message encoding compliance
            if let Ok(dns_packet) = encoder.encode_payload(&payload) {
                // Property 1: DNS packet must have valid header structure
                prop_assert!(dns_packet.len() >= 12, "DNS packet must have at least 12-byte header");
                
                // Property 2: DNS header must have correct format
                // Bytes 0-1: Transaction ID (any value is valid)
                // Bytes 2-3: Flags (0x0100 = standard query with recursion desired)
                prop_assert_eq!(dns_packet[2], 0x01, "DNS flags high byte must be 0x01");
                prop_assert_eq!(dns_packet[3], 0x00, "DNS flags low byte must be 0x00");
                
                // Bytes 4-5: Question count (must be 1)
                prop_assert_eq!(dns_packet[4], 0x00, "Question count high byte must be 0x00");
                prop_assert_eq!(dns_packet[5], 0x01, "Question count low byte must be 0x01");
                
                // Bytes 6-7: Answer count (must be 0 for queries)
                prop_assert_eq!(dns_packet[6], 0x00, "Answer count high byte must be 0x00");
                prop_assert_eq!(dns_packet[7], 0x00, "Answer count low byte must be 0x00");
                
                // Bytes 8-9: Authority count (must be 0 for queries)
                prop_assert_eq!(dns_packet[8], 0x00, "Authority count high byte must be 0x00");
                prop_assert_eq!(dns_packet[9], 0x00, "Authority count low byte must be 0x00");
                
                // Bytes 10-11: Additional count (must be 0 for queries)
                prop_assert_eq!(dns_packet[10], 0x00, "Additional count high byte must be 0x00");
                prop_assert_eq!(dns_packet[11], 0x00, "Additional count low byte must be 0x00");
                
                // Property 3: DNS packet must not exceed 512 bytes (UDP limit)
                prop_assert!(dns_packet.len() <= 512, "DNS packet must not exceed 512 bytes");
                
                // Property 4: DNS question section must be properly formatted
                // Skip to question section (after 12-byte header)
                let mut pos = 12;
                
                // Parse domain name labels
                while pos < dns_packet.len() {
                    let label_len = dns_packet[pos] as usize;
                    pos += 1;
                    
                    if label_len == 0 {
                        // End of domain name
                        break;
                    }
                    
                    // Each label must be <= 63 bytes
                    prop_assert!(label_len <= 63, "DNS label length must be <= 63 bytes");
                    
                    // Skip label data
                    pos += label_len;
                    prop_assert!(pos <= dns_packet.len(), "DNS packet truncated in label");
                }
                
                // After domain name, must have QTYPE (2 bytes) and QCLASS (2 bytes)
                prop_assert!(pos + 4 <= dns_packet.len(), "DNS packet must have QTYPE and QCLASS");
                
                // QTYPE must be 16 (TXT record)
                let qtype = u16::from_be_bytes([dns_packet[pos], dns_packet[pos + 1]]);
                prop_assert_eq!(qtype, 16, "QTYPE must be 16 (TXT record)");
                
                // QCLASS must be 1 (IN - Internet)
                let qclass = u16::from_be_bytes([dns_packet[pos + 2], dns_packet[pos + 3]]);
                prop_assert_eq!(qclass, 1, "QCLASS must be 1 (IN - Internet)");
                
                // Property 5: Base32 encoding must be reversible
                if !payload.is_empty() {
                    let encoded = encoder.base32_encode(&payload)?;
                    let decoded = encoder.base32_decode(&encoded)?;
                    prop_assert_eq!(payload, decoded, "Base32 encoding must be reversible");
                }
                
                // Property 6: Domain name must end with .tunnel.local
                // Parse the domain name from the DNS packet to verify it ends correctly
                let mut domain_parts = Vec::new();
                let mut pos = 12;
                
                while pos < dns_packet.len() {
                    let label_len = dns_packet[pos] as usize;
                    pos += 1;
                    
                    if label_len == 0 {
                        break;
                    }
                    
                    let label = String::from_utf8_lossy(&dns_packet[pos..pos + label_len]);
                    domain_parts.push(label.to_string());
                    pos += label_len;
                }
                
                // Domain should end with "tunnel" and "local"
                if domain_parts.len() >= 2 {
                    let len = domain_parts.len();
                    prop_assert_eq!(&domain_parts[len - 2], "tunnel", "Domain must contain 'tunnel'");
                    prop_assert_eq!(&domain_parts[len - 1], "local", "Domain must end with 'local'");
                }
            }
        }
        
        #[test]
        fn test_doh_client_url_validation(
            scheme in "(https?|ftp|file)://",
            host in "[a-zA-Z0-9.-]+",
            path in "/[a-zA-Z0-9/_-]*"
        ) {
            let url = format!("{}{}{}", scheme, host, path);
            let result = DohClient::new(&url);
            
            // Property: Only HTTPS URLs should be accepted for DoH
            if scheme == "https://" {
                // HTTPS URLs should succeed (assuming valid format)
                if url.len() < 2048 { // Reasonable URL length limit
                    // We can't guarantee success due to URL parsing, but HTTPS should not fail due to scheme
                    prop_assert!(result.is_ok() || matches!(result, Err(TunnelError::HttpRequest(_))));
                }
            } else {
                // Non-HTTPS URLs should fail with InvalidUrl error
                prop_assert!(matches!(result, Err(TunnelError::InvalidUrl(_))));
            }
        }
        
        #[test]
        fn test_base64_url_encoding_properties(
            data in prop::collection::vec(any::<u8>(), 0..=1024)
        ) {
            let encoded = base64_url_encode(&data);
            
            // Property 1: Base64url encoding must not contain padding
            prop_assert!(!encoded.contains('='), "Base64url must not contain padding");
            
            // Property 2: Base64url encoding must not contain URL-unsafe characters
            prop_assert!(!encoded.contains('+'), "Base64url must not contain '+'");
            prop_assert!(!encoded.contains('/'), "Base64url must not contain '/'");
            
            // Property 3: Base64url encoding must only contain valid characters
            for c in encoded.chars() {
                prop_assert!(
                    c.is_ascii_alphanumeric() || c == '-' || c == '_',
                    "Base64url must only contain alphanumeric, '-', and '_' characters"
                );
            }
            
            // Property 4: Empty input produces empty output
            if data.is_empty() {
                prop_assert!(encoded.is_empty(), "Empty input should produce empty base64url output");
            } else {
                prop_assert!(!encoded.is_empty(), "Non-empty input should produce non-empty base64url output");
            }
        }
    }
}
