//! JA4 Fingerprint Spoofing Module
//!
//! This module provides the ability to spoof JA4 TLS Client Hello fingerprints
//! to bypass modern bot detection systems like Cloudflare, Akamai, and AWS Shield.
//!
//! JA4 is the next-generation TLS fingerprinting method that improves upon JA3:
//! - More robust against evasion
//! - Better handling of TLS 1.3
//! - Includes ALPN protocol information
//! - Uses truncated SHA256 instead of MD5
//!
//! JA4 format: t[ver]d[sni][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash]
//! Example: t13d1516h2_8daaf6152771_b0da82dd1658

use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// JA4 Profile representing a specific browser/device fingerprint
#[derive(Debug, Clone)]
pub struct Ja4Profile {
    pub name: String,
    pub ja4_hash: String,
    pub ja4_raw: String,
    pub tls_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub alpn_protocols: Vec<String>,
}

impl Ja4Profile {
    /// Chrome 120+ on Windows 11
    pub fn chrome_120_win11() -> Self {
        Self {
            name: "Chrome 120+ Windows 11".to_string(),
            ja4_hash: "t13d1516h2_8daaf6152771_b0da82dd1658".to_string(),
            ja4_raw: "t13d1516h2_4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53_0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21_29-23-24".to_string(),
            tls_version: 0x0304, // TLS 1.3
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0x1303, // TLS_CHACHA20_POLY1305_SHA256
                0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions: vec![
                0x0000, // server_name
                0x0017, // extended_master_secret
                0xff01, // renegotiation_info
                0x000a, // supported_groups
                0x000b, // ec_point_formats
                0x0023, // session_ticket
                0x0010, // application_layer_protocol_negotiation
                0x0005, // status_request
                0x000d, // signature_algorithms
                0x0012, // signed_certificate_timestamp
                0x002b, // supported_versions
                0x002d, // psk_key_exchange_modes
                0x0033, // key_share
                0x001b, // compress_certificate
                0x0015, // padding
            ],
            signature_algorithms: vec![
                0x0403, // ecdsa_secp256r1_sha256
                0x0804, // rsa_pss_rsae_sha256
                0x0401, // rsa_pkcs1_sha256
                0x0503, // ecdsa_secp384r1_sha384
                0x0805, // rsa_pss_rsae_sha384
                0x0501, // rsa_pkcs1_sha384
                0x0806, // rsa_pss_rsae_sha512
                0x0601, // rsa_pkcs1_sha512
            ],
            supported_groups: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    /// Firefox 121+ on Windows 11
    pub fn firefox_121_win11() -> Self {
        Self {
            name: "Firefox 121+ Windows 11".to_string(),
            ja4_hash: "t13d1515h2_8daaf6152771_02713d6af862".to_string(),
            ja4_raw: "t13d1515h2_4865-4867-4866-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53_0-23-65281-10-11-35-16-5-13-51-45-43-28".to_string(),
            tls_version: 0x0304,
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0033,
                0x002d, 0x002b, 0x001c,
            ],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805,
                0x0806, 0x0401, 0x0501, 0x0601,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0019],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    /// Safari 17+ on macOS Sonoma
    pub fn safari_17_macos() -> Self {
        Self {
            name: "Safari 17+ macOS Sonoma".to_string(),
            ja4_hash: "t13d1212h2_8daaf6152771_02713d6af862".to_string(),
            ja4_raw: "t13d1212h2_4865-4866-4867-49196-49195-49200-49199-52393-52392-49162-49161-49172-49171-157-156-53-47_0-23-65281-10-11-35-16-5-13-51-45-43".to_string(),
            tls_version: 0x0304,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a,
                0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0033,
                0x002d, 0x002b,
            ],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    /// Edge 120+ on Windows 11
    pub fn edge_120_win11() -> Self {
        Self {
            name: "Edge 120+ Windows 11".to_string(),
            ja4_hash: "t13d1516h2_8daaf6152771_b0da82dd1658".to_string(),
            ja4_raw: "t13d1516h2_4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53_0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21".to_string(),
            tls_version: 0x0304,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
                0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
            ],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }

    /// Calculate JA4 hash from profile
    pub fn calculate_ja4(&self, has_sni: bool) -> String {
        // JA4 format: t[ver]d[sni][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash]

        // TLS version (t13 for TLS 1.3, t12 for TLS 1.2, etc.)
        let tls_ver = match self.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };

        // SNI indicator (d = domain present, i = IP address)
        let sni_indicator = if has_sni { "d" } else { "i" };

        // Cipher count (2 digits, hex)
        let cipher_count = format!("{:02x}", self.cipher_suites.len().min(255));

        // Extension count (2 digits, hex)
        let ext_count = format!("{:02x}", self.extensions.len().min(255));

        // ALPN first value (h2, h1, etc.)
        let alpn = if let Some(first_alpn) = self.alpn_protocols.first() {
            match first_alpn.as_str() {
                "h2" => "h2",
                "http/1.1" => "h1",
                "http/1.0" => "h1",
                _ => "00",
            }
        } else {
            "00"
        };

        // Create cipher suites string for hashing (sorted)
        let mut sorted_ciphers = self.cipher_suites.clone();
        sorted_ciphers.sort_unstable();
        let cipher_str: String = sorted_ciphers
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        // Create extensions string for hashing (sorted, excluding SNI and ALPN)
        let mut sorted_extensions = self.extensions.clone();
        sorted_extensions.retain(|&ext| ext != 0x0000 && ext != 0x0010); // Remove SNI and ALPN
        sorted_extensions.sort_unstable();
        let ext_str: String = sorted_extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        // Calculate truncated SHA256 hashes (first 12 characters)
        let cipher_hash = Self::truncated_sha256(&cipher_str);
        let ext_hash = Self::truncated_sha256(&ext_str);

        format!(
            "t{}{}{}{}{}_{}_{}",
            tls_ver, sni_indicator, cipher_count, ext_count, alpn, cipher_hash, ext_hash
        )
    }

    /// Calculate JA4 raw string (for debugging/analysis)
    pub fn calculate_ja4_raw(&self, has_sni: bool) -> String {
        let tls_ver = match self.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };

        let sni_indicator = if has_sni { "d" } else { "i" };
        let cipher_count = format!("{:02x}", self.cipher_suites.len().min(255));
        let ext_count = format!("{:02x}", self.extensions.len().min(255));

        let alpn = if let Some(first_alpn) = self.alpn_protocols.first() {
            match first_alpn.as_str() {
                "h2" => "h2",
                "http/1.1" => "h1",
                "http/1.0" => "h1",
                _ => "00",
            }
        } else {
            "00"
        };

        let cipher_str: String = self
            .cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ext_str: String = self
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let groups_str: String = self
            .supported_groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "t{}{}{}{}{}_{}_{}_{}",
            tls_ver, sni_indicator, cipher_count, ext_count, alpn, cipher_str, ext_str, groups_str
        )
    }

    /// Calculate truncated SHA256 hash (first 12 characters)
    fn truncated_sha256(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        format!("{:x}", result)[..12].to_string()
    }

    /// Build TLS Client Hello packet with JA4 profile
    pub fn build_client_hello(&self, server_name: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);

        // Record layer header (will be filled later)
        packet.push(0x16); // Handshake
        packet.push(0x03);
        packet.push(0x03); // TLS 1.2 for compatibility (actual version in supported_versions)
        packet.push(0x00);
        packet.push(0x00); // Length placeholder

        // Handshake header
        packet.push(0x01); // Client Hello
        packet.push(0x00);
        packet.push(0x00);
        packet.push(0x00); // Length placeholder

        // Client Version (legacy field, use TLS 1.2)
        packet.push(0x03);
        packet.push(0x03);

        // Random (32 bytes)
        let random: [u8; 32] = rand::random();
        packet.extend_from_slice(&random);

        // Session ID (empty)
        packet.push(0x00);

        // Cipher Suites
        let cipher_len = (self.cipher_suites.len() * 2) as u16;
        packet.push((cipher_len >> 8) as u8);
        packet.push((cipher_len & 0xFF) as u8);
        for cipher in &self.cipher_suites {
            packet.push((*cipher >> 8) as u8);
            packet.push((*cipher & 0xFF) as u8);
        }

        // Compression Methods
        packet.push(0x01); // Length
        packet.push(0x00); // null compression

        // Extensions
        let ext_start = packet.len();
        packet.push(0x00);
        packet.push(0x00); // Extensions length placeholder

        // Add extensions in the order specified by the profile
        for &ext_type in &self.extensions {
            match ext_type {
                0x0000 => self.add_sni_extension(&mut packet, server_name),
                0x000a => self.add_supported_groups_extension(&mut packet),
                0x000b => self.add_ec_point_formats_extension(&mut packet),
                0x000d => self.add_signature_algorithms_extension(&mut packet),
                0x0010 => self.add_alpn_extension(&mut packet),
                0x002b => self.add_supported_versions_extension(&mut packet),
                0x0033 => self.add_key_share_extension(&mut packet),
                _ => self.add_empty_extension(&mut packet, ext_type),
            }
        }

        // Update extensions length
        let ext_len = (packet.len() - ext_start - 2) as u16;
        packet[ext_start] = (ext_len >> 8) as u8;
        packet[ext_start + 1] = (ext_len & 0xFF) as u8;

        // Update handshake length
        let hs_len = (packet.len() - 9) as u32;
        packet[6] = ((hs_len >> 16) & 0xFF) as u8;
        packet[7] = ((hs_len >> 8) & 0xFF) as u8;
        packet[8] = (hs_len & 0xFF) as u8;

        // Update record length
        let rec_len = (packet.len() - 5) as u16;
        packet[3] = (rec_len >> 8) as u8;
        packet[4] = (rec_len & 0xFF) as u8;

        packet
    }

    fn add_sni_extension(&self, packet: &mut Vec<u8>, server_name: &str) {
        let name_bytes = server_name.as_bytes();
        let name_len = name_bytes.len() as u16;

        packet.push(0x00);
        packet.push(0x00); // SNI extension type
        let ext_len = name_len + 5;
        packet.push((ext_len >> 8) as u8);
        packet.push((ext_len & 0xFF) as u8);
        let list_len = name_len + 3;
        packet.push((list_len >> 8) as u8);
        packet.push((list_len & 0xFF) as u8);
        packet.push(0x00); // Host name type
        packet.push((name_len >> 8) as u8);
        packet.push((name_len & 0xFF) as u8);
        packet.extend_from_slice(name_bytes);
    }

    fn add_supported_groups_extension(&self, packet: &mut Vec<u8>) {
        packet.push(0x00);
        packet.push(0x0a); // Supported Groups extension type
        let groups_len = (self.supported_groups.len() * 2) as u16;
        let ext_len = groups_len + 2;
        packet.push((ext_len >> 8) as u8);
        packet.push((ext_len & 0xFF) as u8);
        packet.push((groups_len >> 8) as u8);
        packet.push((groups_len & 0xFF) as u8);
        for group in &self.supported_groups {
            packet.push((*group >> 8) as u8);
            packet.push((*group & 0xFF) as u8);
        }
    }

    fn add_ec_point_formats_extension(&self, packet: &mut Vec<u8>) {
        packet.push(0x00);
        packet.push(0x0b); // EC Point Formats extension type
        packet.push(0x00);
        packet.push(0x02); // Extension length
        packet.push(0x01); // Formats length
        packet.push(0x00); // uncompressed
    }

    fn add_signature_algorithms_extension(&self, packet: &mut Vec<u8>) {
        packet.push(0x00);
        packet.push(0x0d); // Signature Algorithms extension type
        let algs_len = (self.signature_algorithms.len() * 2) as u16;
        let ext_len = algs_len + 2;
        packet.push((ext_len >> 8) as u8);
        packet.push((ext_len & 0xFF) as u8);
        packet.push((algs_len >> 8) as u8);
        packet.push((algs_len & 0xFF) as u8);
        for alg in &self.signature_algorithms {
            packet.push((*alg >> 8) as u8);
            packet.push((*alg & 0xFF) as u8);
        }
    }

    fn add_alpn_extension(&self, packet: &mut Vec<u8>) {
        if self.alpn_protocols.is_empty() {
            return;
        }

        packet.push(0x00);
        packet.push(0x10); // ALPN extension type

        let mut alpn_data = Vec::new();
        for proto in &self.alpn_protocols {
            alpn_data.push(proto.len() as u8);
            alpn_data.extend_from_slice(proto.as_bytes());
        }

        let list_len = alpn_data.len() as u16;
        let ext_len = list_len + 2;
        packet.push((ext_len >> 8) as u8);
        packet.push((ext_len & 0xFF) as u8);
        packet.push((list_len >> 8) as u8);
        packet.push((list_len & 0xFF) as u8);
        packet.extend_from_slice(&alpn_data);
    }

    fn add_supported_versions_extension(&self, packet: &mut Vec<u8>) {
        packet.push(0x00);
        packet.push(0x2b); // Supported Versions extension type
        packet.push(0x00);
        packet.push(0x03); // Extension length
        packet.push(0x02); // Versions length
        packet.push((self.tls_version >> 8) as u8);
        packet.push((self.tls_version & 0xFF) as u8);
    }

    fn add_key_share_extension(&self, packet: &mut Vec<u8>) {
        packet.push(0x00);
        packet.push(0x33); // Key Share extension type

        // For simplicity, add a minimal key share for x25519
        packet.push(0x00);
        packet.push(0x26); // Extension length (38 bytes)
        packet.push(0x00);
        packet.push(0x24); // Key share entries length (36 bytes)
        packet.push(0x00);
        packet.push(0x1d); // x25519 group
        packet.push(0x00);
        packet.push(0x20); // Key length (32 bytes)

        // Random 32-byte key
        let key: [u8; 32] = rand::random();
        packet.extend_from_slice(&key);
    }

    fn add_empty_extension(&self, packet: &mut Vec<u8>, ext_type: u16) {
        packet.push((ext_type >> 8) as u8);
        packet.push((ext_type & 0xFF) as u8);
        packet.push(0x00);
        packet.push(0x00); // Empty extension
    }
}

/// JA4 Fingerprint Spoofer
pub struct Ja4Spoofer {
    profiles: HashMap<String, Ja4Profile>,
    current_profile: Option<String>,
}

impl Ja4Spoofer {
    pub fn new() -> Self {
        let mut profiles = HashMap::new();

        profiles.insert("chrome_120".to_string(), Ja4Profile::chrome_120_win11());
        profiles.insert("firefox_121".to_string(), Ja4Profile::firefox_121_win11());
        profiles.insert("safari_17".to_string(), Ja4Profile::safari_17_macos());
        profiles.insert("edge_120".to_string(), Ja4Profile::edge_120_win11());

        Self {
            profiles,
            current_profile: None,
        }
    }

    pub fn set_profile(&mut self, name: &str) -> Result<(), String> {
        if self.profiles.contains_key(name) {
            self.current_profile = Some(name.to_string());
            Ok(())
        } else {
            Err(format!("Unknown JA4 profile: {}", name))
        }
    }

    pub fn get_profile(&self, name: &str) -> Option<&Ja4Profile> {
        self.profiles.get(name)
    }

    pub fn list_profiles(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }

    pub fn build_client_hello(&self, server_name: &str) -> Option<Vec<u8>> {
        self.current_profile
            .as_ref()
            .and_then(|name| self.profiles.get(name))
            .map(|profile| profile.build_client_hello(server_name))
    }

    pub fn get_ja4_hash(&self) -> Option<String> {
        self.current_profile
            .as_ref()
            .and_then(|name| self.profiles.get(name))
            .map(|profile| profile.calculate_ja4(true))
    }

    pub fn get_ja4_raw(&self) -> Option<String> {
        self.current_profile
            .as_ref()
            .and_then(|name| self.profiles.get(name))
            .map(|profile| profile.calculate_ja4_raw(true))
    }

    pub fn add_custom_profile(&mut self, name: String, profile: Ja4Profile) {
        self.profiles.insert(name, profile);
    }
}

impl Default for Ja4Spoofer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4_profile_creation() {
        let profile = Ja4Profile::chrome_120_win11();
        assert!(!profile.cipher_suites.is_empty());
        assert!(!profile.extensions.is_empty());
        assert!(!profile.alpn_protocols.is_empty());
    }

    #[test]
    fn test_ja4_hash_calculation() {
        let profile = Ja4Profile::chrome_120_win11();
        let hash = profile.calculate_ja4(true);

        // Should start with t13d (TLS 1.3, domain present)
        assert!(hash.starts_with("t13d"));

        // Should have the correct format: t[ver]d[sni][cipher][ext][alpn]_[hash]_[hash]
        let parts: Vec<&str> = hash.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "JA4 hash should have 3 parts separated by underscores"
        );

        // First part should be the header
        assert!(
            parts[0].len() >= 6,
            "JA4 header should be at least 6 characters"
        );

        // Hash parts should be 12 characters each
        assert_eq!(parts[1].len(), 12, "Cipher hash should be 12 characters");
        assert_eq!(parts[2].len(), 12, "Extension hash should be 12 characters");
    }

    #[test]
    fn test_ja4_raw_calculation() {
        let profile = Ja4Profile::chrome_120_win11();
        let raw = profile.calculate_ja4_raw(true);

        // Should contain cipher suites and extensions
        assert!(raw.contains("4865")); // TLS_AES_128_GCM_SHA256
        assert!(raw.contains("4866")); // TLS_AES_256_GCM_SHA384
    }

    #[test]
    fn test_client_hello_build() {
        let profile = Ja4Profile::chrome_120_win11();
        let hello = profile.build_client_hello("example.com");

        assert!(hello.len() > 100);
        assert_eq!(hello[0], 0x16); // Handshake record
        assert_eq!(hello[5], 0x01); // Client Hello
    }

    #[test]
    fn test_ja4_spoofer() {
        let mut spoofer = Ja4Spoofer::new();
        assert!(spoofer.set_profile("chrome_120").is_ok());
        assert!(spoofer.build_client_hello("example.com").is_some());
        assert!(spoofer.get_ja4_hash().is_some());
    }

    #[test]
    fn test_all_browser_profiles() {
        let profiles = vec![
            ("chrome_120", Ja4Profile::chrome_120_win11()),
            ("firefox_121", Ja4Profile::firefox_121_win11()),
            ("safari_17", Ja4Profile::safari_17_macos()),
            ("edge_120", Ja4Profile::edge_120_win11()),
        ];

        for (name, profile) in profiles {
            // Each profile should have required fields
            assert!(
                !profile.cipher_suites.is_empty(),
                "{} has no cipher suites",
                name
            );
            assert!(!profile.extensions.is_empty(), "{} has no extensions", name);
            assert!(
                !profile.signature_algorithms.is_empty(),
                "{} has no signature algorithms",
                name
            );
            assert!(
                !profile.supported_groups.is_empty(),
                "{} has no supported groups",
                name
            );
            assert!(
                !profile.alpn_protocols.is_empty(),
                "{} has no ALPN protocols",
                name
            );

            // JA4 hash should be valid
            let hash = profile.calculate_ja4(true);
            assert!(hash.len() > 20, "{} JA4 hash too short: {}", name, hash);

            // Should contain underscores
            assert!(
                hash.contains('_'),
                "{} JA4 hash should contain underscores",
                name
            );

            // Build should succeed
            let hello = profile.build_client_hello("example.com");
            assert!(hello.len() > 50, "{} Client Hello too short", name);
        }
    }

    #[test]
    fn test_truncated_sha256() {
        let input = "test-input-string";
        let hash = Ja4Profile::truncated_sha256(input);
        assert_eq!(hash.len(), 12, "Truncated SHA256 should be 12 characters");

        // Should be deterministic
        let hash2 = Ja4Profile::truncated_sha256(input);
        assert_eq!(hash, hash2, "SHA256 should be deterministic");
    }

    #[test]
    fn test_sni_vs_no_sni() {
        let profile = Ja4Profile::chrome_120_win11();
        let hash_with_sni = profile.calculate_ja4(true);
        let hash_without_sni = profile.calculate_ja4(false);

        // Should differ in the SNI indicator
        assert!(
            hash_with_sni.contains("d"),
            "Hash with SNI should contain 'd'"
        );
        assert!(
            hash_without_sni.contains("i"),
            "Hash without SNI should contain 'i'"
        );
    }
}
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// **Feature: true-military-grade, Property 5: JA4 Hash Format Validity**
    /// **Validates: Requirements 6.1, 6.2**
    ///
    /// Property: For any browser profile, the generated JA4 hash SHALL match the format
    /// t[ver]d[sni][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash] and be reproducible
    /// for the same profile.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_ja4_hash_format_validity(profile_idx in 0usize..4, has_sni in any::<bool>()) {
            let profiles = vec![
                Ja4Profile::chrome_120_win11(),
                Ja4Profile::firefox_121_win11(),
                Ja4Profile::safari_17_macos(),
                Ja4Profile::edge_120_win11(),
            ];

            let profile = &profiles[profile_idx];
            let hash = profile.calculate_ja4(has_sni);

            // Should have the correct format: t[ver]d[sni][cipher][ext][alpn]_[hash]_[hash]
            let parts: Vec<&str> = hash.split('_').collect();
            prop_assert_eq!(parts.len(), 3, "JA4 hash should have 3 parts separated by underscores");

            // First part should be the header (at least 6 characters)
            prop_assert!(parts[0].len() >= 6, "JA4 header should be at least 6 characters");

            // Should start with 't' for TLS
            prop_assert!(parts[0].starts_with('t'), "JA4 hash should start with 't'");

            // Should contain SNI indicator
            let sni_indicator = if has_sni { 'd' } else { 'i' };
            prop_assert!(parts[0].contains(sni_indicator), "JA4 hash should contain correct SNI indicator");

            // Hash parts should be 12 characters each (truncated SHA256)
            prop_assert_eq!(parts[1].len(), 12, "Cipher hash should be 12 characters");
            prop_assert_eq!(parts[2].len(), 12, "Extension hash should be 12 characters");

            // Hash parts should be hexadecimal
            prop_assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()), "Cipher hash should be hexadecimal");
            prop_assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()), "Extension hash should be hexadecimal");
        }

        /// Property: JA4 calculation is deterministic - same profile and SNI setting
        /// always produces the same hash
        #[test]
        fn prop_ja4_deterministic(profile_idx in 0usize..4, has_sni in any::<bool>(), iterations in 1usize..10) {
            let profiles = vec![
                Ja4Profile::chrome_120_win11(),
                Ja4Profile::firefox_121_win11(),
                Ja4Profile::safari_17_macos(),
                Ja4Profile::edge_120_win11(),
            ];

            let profile = &profiles[profile_idx];
            let first_hash = profile.calculate_ja4(has_sni);

            for _ in 0..iterations {
                let hash = profile.calculate_ja4(has_sni);
                prop_assert_eq!(
                    &hash,
                    &first_hash,
                    "JA4 hash should be deterministic"
                );
            }
        }

        /// Property: Client Hello packets for the same profile should have consistent
        /// structure (excluding random bytes)
        #[test]
        fn prop_client_hello_consistent_structure(
            profile_idx in 0usize..4,
            server_name in "[a-z]{1,10}\\.[a-z]{2,5}"
        ) {
            let profiles = vec![
                Ja4Profile::chrome_120_win11(),
                Ja4Profile::firefox_121_win11(),
                Ja4Profile::safari_17_macos(),
                Ja4Profile::edge_120_win11(),
            ];

            let profile = &profiles[profile_idx];
            let hello1 = profile.build_client_hello(&server_name);
            let hello2 = profile.build_client_hello(&server_name);

            // Length should be the same
            prop_assert_eq!(
                hello1.len(),
                hello2.len(),
                "Client Hello length should be consistent"
            );

            // Record type and version should match
            prop_assert_eq!(&hello1[0..5], &hello2[0..5], "Record header should match");

            // Handshake type should match
            prop_assert_eq!(hello1[5], hello2[5], "Handshake type should match");

            // Must be a handshake record
            prop_assert_eq!(hello1[0], 0x16, "Must be handshake record type");

            // Must be Client Hello
            prop_assert_eq!(hello1[5], 0x01, "Must be Client Hello");

            // Must contain the server name
            let contains_sni = hello1.windows(server_name.len())
                .any(|w| w == server_name.as_bytes());
            prop_assert!(contains_sni, "SNI must be present");
        }

        /// Property: JA4 raw format should contain all expected components
        #[test]
        fn prop_ja4_raw_completeness(profile_idx in 0usize..4, has_sni in any::<bool>()) {
            let profiles = vec![
                Ja4Profile::chrome_120_win11(),
                Ja4Profile::firefox_121_win11(),
                Ja4Profile::safari_17_macos(),
                Ja4Profile::edge_120_win11(),
            ];

            let profile = &profiles[profile_idx];
            let raw = profile.calculate_ja4_raw(has_sni);

            // Should contain cipher suites from the profile
            for cipher in &profile.cipher_suites[..3.min(profile.cipher_suites.len())] {
                prop_assert!(raw.contains(&cipher.to_string()),
                    "JA4 raw should contain cipher suite {}", cipher);
            }

            // Should contain extensions from the profile
            for ext in &profile.extensions[..3.min(profile.extensions.len())] {
                prop_assert!(raw.contains(&ext.to_string()),
                    "JA4 raw should contain extension {}", ext);
            }

            // Should contain supported groups
            for group in &profile.supported_groups[..2.min(profile.supported_groups.len())] {
                prop_assert!(raw.contains(&group.to_string()),
                    "JA4 raw should contain supported group {}", group);
            }
        }

        /// Property: Truncated SHA256 should always produce 12-character hex strings
        #[test]
        fn prop_truncated_sha256_format(input in ".*") {
            let hash = Ja4Profile::truncated_sha256(&input);

            prop_assert_eq!(hash.len(), 12, "Truncated SHA256 should be 12 characters");
            prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()),
                "Truncated SHA256 should be hexadecimal");
        }

        /// Property: Significantly different browser engines should produce different JA4 hashes
        /// Note: Chrome and Edge may produce the same hash since they're both Chromium-based
        #[test]
        fn prop_different_engines_different_hashes(
            engine1_idx in 0usize..3,
            engine2_idx in 0usize..3,
            has_sni in any::<bool>()
        ) {
            prop_assume!(engine1_idx != engine2_idx);

            // Only test significantly different browser engines (Chrome, Firefox, Safari)
            // Exclude Edge since it's Chromium-based and may match Chrome
            let profiles = vec![
                Ja4Profile::chrome_120_win11(),
                Ja4Profile::firefox_121_win11(),
                Ja4Profile::safari_17_macos(),
            ];

            let hash1 = profiles[engine1_idx].calculate_ja4(has_sni);
            let hash2 = profiles[engine2_idx].calculate_ja4(has_sni);

            prop_assert_ne!(hash1, hash2, "Different browser engines should produce different JA4 hashes");
        }
    }
}
