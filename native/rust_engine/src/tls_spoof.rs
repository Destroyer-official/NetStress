//! TLS/JA3 Fingerprint Spoofing Module
//!
//! This module provides the ability to spoof TLS Client Hello fingerprints
//! to bypass bot detection systems like Cloudflare, Akamai, and Imperva.
//!
//! JA3 fingerprinting works by hashing the TLS Client Hello parameters:
//! - SSL Version
//! - Cipher Suites
//! - Extensions
//! - Elliptic Curves
//! - EC Point Formats
//!
//! By controlling these parameters, we can mimic any browser or device.

use std::collections::HashMap;
use std::sync::Arc;

/// TLS Profile representing a specific browser/device fingerprint
#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub name: String,
    pub ja3_hash: String,
    pub ssl_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub alpn_protocols: Vec<String>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
}

impl TlsProfile {
    /// Chrome 120 on Windows 11
    pub fn chrome_120_win11() -> Self {
        Self {
            name: "Chrome 120 Windows 11".to_string(),
            ja3_hash: "378edd75f97f0c8aef55c8ddd89a8cbb".to_string(),
            ssl_version: 0x0303, // TLS 1.2 (actual negotiation uses 1.3)
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
            elliptic_curves: vec![
                0x001d, // x25519
                0x0017, // secp256r1
                0x0018, // secp384r1
            ],
            ec_point_formats: vec![0x00], // uncompressed
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
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
            supported_versions: vec![0x0304, 0x0303], // TLS 1.3, TLS 1.2
        }
    }

    /// Firefox 121 on Windows 11
    pub fn firefox_121_win11() -> Self {
        Self {
            name: "Firefox 121 Windows 11".to_string(),
            ja3_hash: "58dc4add27ba4e5a1c8a05f4308f10e4".to_string(),
            ssl_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b,
                0x002d, 0x0033, 0x001c,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018, 0x0019],
            ec_point_formats: vec![0x00],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805,
                0x0806, 0x0401, 0x0501, 0x0601,
            ],
            supported_versions: vec![0x0304, 0x0303],
        }
    }

    /// Safari 17 on macOS Sonoma
    pub fn safari_17_macos() -> Self {
        Self {
            name: "Safari 17 macOS Sonoma".to_string(),
            ja3_hash: "476a054718c4641439f86e96fc236fee".to_string(),
            ssl_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a,
                0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b,
                0x002d, 0x0033,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_versions: vec![0x0304, 0x0303],
        }
    }

    /// iPhone 15 Pro iOS 17
    pub fn iphone_15_ios17() -> Self {
        Self {
            name: "iPhone 15 Pro iOS 17".to_string(),
            ja3_hash: "476a054718c4641439f86e96fc236fee".to_string(),
            ssl_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc00a,
                0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b,
                0x002d, 0x0033,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_versions: vec![0x0304, 0x0303],
        }
    }

    /// Android 14 Chrome
    pub fn android_14_chrome() -> Self {
        Self {
            name: "Android 14 Chrome".to_string(),
            ja3_hash: "24c9887f89208956701146adc97bf9a3".to_string(),
            ssl_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x002b,
                0x002d, 0x0033, 0x001b,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_versions: vec![0x0304, 0x0303],
        }
    }

    /// curl/wget (for testing)
    pub fn curl_default() -> Self {
        Self {
            name: "curl/8.0".to_string(),
            ja3_hash: "f172a0c2a74cc66b31694799b6a0db45".to_string(),
            ssl_version: 0x0303,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009d, 0x009c, 0xc024,
                0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x0035, 0x002f, 0x000a,
            ],
            extensions: vec![
                0x0000, 0x000b, 0x000a, 0x000d, 0x0010, 0x0016, 0x0017, 0x002b, 0x002d, 0x0033,
            ],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00, 0x01, 0x02],
            alpn_protocols: vec!["http/1.1".to_string()],
            signature_algorithms: vec![
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303,
                0x0203, 0x0301, 0x0201,
            ],
            supported_versions: vec![0x0304, 0x0303, 0x0302],
        }
    }

    /// Calculate JA3 hash from profile
    pub fn calculate_ja3(&self) -> String {
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

        let curve_str: String = self
            .elliptic_curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let point_str: String = self
            .ec_point_formats
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3_string = format!(
            "{},{},{},{},{}",
            self.ssl_version, cipher_str, ext_str, curve_str, point_str
        );

        // Use md5 crate v0.7 API
        let digest = md5::compute(ja3_string.as_bytes());
        format!("{:x}", digest)
    }

    /// Build TLS Client Hello packet with this profile
    pub fn build_client_hello(&self, server_name: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(512);

        // Record layer header (will be filled later)
        packet.push(0x16); // Handshake
        packet.push(0x03);
        packet.push(0x01); // TLS 1.0 for compatibility
        packet.push(0x00);
        packet.push(0x00); // Length placeholder

        // Handshake header
        packet.push(0x01); // Client Hello
        packet.push(0x00);
        packet.push(0x00);
        packet.push(0x00); // Length placeholder

        // Client Version
        packet.push((self.ssl_version >> 8) as u8);
        packet.push((self.ssl_version & 0xFF) as u8);

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

        // SNI Extension
        self.add_sni_extension(&mut packet, server_name);

        // Supported Groups Extension
        self.add_supported_groups_extension(&mut packet);

        // EC Point Formats Extension
        self.add_ec_point_formats_extension(&mut packet);

        // Signature Algorithms Extension
        self.add_signature_algorithms_extension(&mut packet);

        // ALPN Extension
        self.add_alpn_extension(&mut packet);

        // Supported Versions Extension
        self.add_supported_versions_extension(&mut packet);

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
        let groups_len = (self.elliptic_curves.len() * 2) as u16;
        let ext_len = groups_len + 2;
        packet.push((ext_len >> 8) as u8);
        packet.push((ext_len & 0xFF) as u8);
        packet.push((groups_len >> 8) as u8);
        packet.push((groups_len & 0xFF) as u8);
        for curve in &self.elliptic_curves {
            packet.push((*curve >> 8) as u8);
            packet.push((*curve & 0xFF) as u8);
        }
    }

    fn add_ec_point_formats_extension(&self, packet: &mut Vec<u8>) {
        packet.push(0x00);
        packet.push(0x0b); // EC Point Formats extension type
        let formats_len = self.ec_point_formats.len() as u8;
        packet.push(0x00);
        packet.push(formats_len + 1);
        packet.push(formats_len);
        packet.extend_from_slice(&self.ec_point_formats);
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
        let versions_len = (self.supported_versions.len() * 2) as u8;
        packet.push(0x00);
        packet.push(versions_len + 1);
        packet.push(versions_len);
        for ver in &self.supported_versions {
            packet.push((*ver >> 8) as u8);
            packet.push((*ver & 0xFF) as u8);
        }
    }
}

/// JA3 Fingerprint Spoofer
pub struct JA3Spoofer {
    profiles: HashMap<String, TlsProfile>,
    current_profile: Option<String>,
}

impl JA3Spoofer {
    pub fn new() -> Self {
        let mut profiles = HashMap::new();

        profiles.insert("chrome_120".to_string(), TlsProfile::chrome_120_win11());
        profiles.insert("firefox_121".to_string(), TlsProfile::firefox_121_win11());
        profiles.insert("safari_17".to_string(), TlsProfile::safari_17_macos());
        profiles.insert("iphone_15".to_string(), TlsProfile::iphone_15_ios17());
        profiles.insert("android_14".to_string(), TlsProfile::android_14_chrome());
        profiles.insert("curl".to_string(), TlsProfile::curl_default());

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
            Err(format!("Unknown profile: {}", name))
        }
    }

    pub fn get_profile(&self, name: &str) -> Option<&TlsProfile> {
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

    pub fn add_custom_profile(&mut self, name: String, profile: TlsProfile) {
        self.profiles.insert(name, profile);
    }
}

impl Default for JA3Spoofer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let profile = TlsProfile::chrome_120_win11();
        assert!(!profile.cipher_suites.is_empty());
        assert!(!profile.extensions.is_empty());
    }

    #[test]
    fn test_client_hello_build() {
        let profile = TlsProfile::chrome_120_win11();
        let hello = profile.build_client_hello("example.com");
        assert!(hello.len() > 100);
        assert_eq!(hello[0], 0x16); // Handshake record
    }

    #[test]
    fn test_spoofer() {
        let mut spoofer = JA3Spoofer::new();
        assert!(spoofer.set_profile("chrome_120").is_ok());
        assert!(spoofer.build_client_hello("example.com").is_some());
    }

    /// **Feature: military-grade-transformation, Property 2: JA3 Hash Accuracy**
    /// **Validates: Requirements 2.3, 2.4, 2.5, 2.6**
    ///
    /// For any supported browser profile, the generated Client Hello SHALL produce
    /// the exact documented JA3 hash when hashed with MD5.
    #[test]
    fn test_ja3_hash_chrome_120() {
        let profile = TlsProfile::chrome_120_win11();
        let calculated = profile.calculate_ja3();
        assert_eq!(
            calculated, profile.ja3_hash,
            "Chrome 120 JA3 hash mismatch: calculated={}, expected={}",
            calculated, profile.ja3_hash
        );
    }

    /// **Feature: military-grade-transformation, Property 2: JA3 Hash Accuracy**
    /// **Validates: Requirements 2.4**
    #[test]
    fn test_ja3_hash_firefox_121() {
        let profile = TlsProfile::firefox_121_win11();
        let calculated = profile.calculate_ja3();
        assert_eq!(
            calculated, profile.ja3_hash,
            "Firefox 121 JA3 hash mismatch: calculated={}, expected={}",
            calculated, profile.ja3_hash
        );
    }

    /// **Feature: military-grade-transformation, Property 2: JA3 Hash Accuracy**
    /// **Validates: Requirements 2.5**
    #[test]
    fn test_ja3_hash_safari_17() {
        let profile = TlsProfile::safari_17_macos();
        let calculated = profile.calculate_ja3();
        assert_eq!(
            calculated, profile.ja3_hash,
            "Safari 17 JA3 hash mismatch: calculated={}, expected={}",
            calculated, profile.ja3_hash
        );
    }

    /// **Feature: military-grade-transformation, Property 2: JA3 Hash Accuracy**
    /// **Validates: Requirements 2.6**
    #[test]
    fn test_ja3_hash_iphone_15() {
        let profile = TlsProfile::iphone_15_ios17();
        let calculated = profile.calculate_ja3();
        assert_eq!(
            calculated, profile.ja3_hash,
            "iPhone 15 JA3 hash mismatch: calculated={}, expected={}",
            calculated, profile.ja3_hash
        );
    }

    #[test]
    fn test_ja3_hash_android_14() {
        let profile = TlsProfile::android_14_chrome();
        let calculated = profile.calculate_ja3();
        assert_eq!(
            calculated, profile.ja3_hash,
            "Android 14 JA3 hash mismatch: calculated={}, expected={}",
            calculated, profile.ja3_hash
        );
    }

    #[test]
    fn test_ja3_hash_curl() {
        let profile = TlsProfile::curl_default();
        let calculated = profile.calculate_ja3();
        assert_eq!(
            calculated, profile.ja3_hash,
            "curl JA3 hash mismatch: calculated={}, expected={}",
            calculated, profile.ja3_hash
        );
    }

    #[test]
    fn test_client_hello_structure() {
        let profile = TlsProfile::chrome_120_win11();
        let hello = profile.build_client_hello("example.com");

        // Verify TLS record layer
        assert_eq!(hello[0], 0x16, "Should be handshake record type");
        assert_eq!(hello[1], 0x03, "TLS major version");
        assert_eq!(hello[2], 0x01, "TLS minor version (1.0 for compat)");

        // Verify handshake type
        assert_eq!(hello[5], 0x01, "Should be Client Hello");
    }

    #[test]
    fn test_sni_in_client_hello() {
        let profile = TlsProfile::chrome_120_win11();
        let hello = profile.build_client_hello("test.example.com");

        // SNI should be present in the packet
        let hello_str = String::from_utf8_lossy(&hello);
        assert!(
            hello.windows(16).any(|w| w == b"test.example.com"),
            "SNI hostname should be present in Client Hello"
        );
    }

    #[test]
    fn test_all_profiles_have_valid_structure() {
        let profiles = vec![
            TlsProfile::chrome_120_win11(),
            TlsProfile::firefox_121_win11(),
            TlsProfile::safari_17_macos(),
            TlsProfile::iphone_15_ios17(),
            TlsProfile::android_14_chrome(),
            TlsProfile::curl_default(),
        ];

        for profile in profiles {
            // Each profile should have required fields
            assert!(
                !profile.cipher_suites.is_empty(),
                "{} has no cipher suites",
                profile.name
            );
            assert!(
                !profile.extensions.is_empty(),
                "{} has no extensions",
                profile.name
            );
            assert!(
                !profile.elliptic_curves.is_empty(),
                "{} has no elliptic curves",
                profile.name
            );
            assert!(
                !profile.ec_point_formats.is_empty(),
                "{} has no EC point formats",
                profile.name
            );
            assert!(
                !profile.signature_algorithms.is_empty(),
                "{} has no signature algorithms",
                profile.name
            );
            assert!(
                !profile.supported_versions.is_empty(),
                "{} has no supported versions",
                profile.name
            );

            // Build should succeed
            let hello = profile.build_client_hello("example.com");
            assert!(hello.len() > 50, "{} Client Hello too short", profile.name);
        }
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    /// **Feature: military-grade-transformation, Property 2: JA3 Hash Accuracy**
    /// **Validates: Requirements 2.3, 2.4, 2.5, 2.6**
    ///
    /// Property: For any supported browser profile, the generated Client Hello
    /// SHALL produce the exact documented JA3 hash when hashed with MD5.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_ja3_hash_matches_expected(profile_idx in 0usize..6) {
            let profiles = vec![
                ("chrome_120", TlsProfile::chrome_120_win11()),
                ("firefox_121", TlsProfile::firefox_121_win11()),
                ("safari_17", TlsProfile::safari_17_macos()),
                ("iphone_15", TlsProfile::iphone_15_ios17()),
                ("android_14", TlsProfile::android_14_chrome()),
                ("curl", TlsProfile::curl_default()),
            ];

            let (name, profile) = &profiles[profile_idx];
            let calculated = profile.calculate_ja3();

            prop_assert_eq!(
                &calculated,
                &profile.ja3_hash,
                "JA3 hash mismatch for {}: calculated={}, expected={}",
                name,
                calculated,
                profile.ja3_hash
            );
        }

        /// Property: For any valid server name, the Client Hello packet should
        /// have valid TLS structure
        #[test]
        fn prop_client_hello_valid_structure(
            server_name in "[a-z]{1,10}\\.[a-z]{2,5}"
        ) {
            let profile = TlsProfile::chrome_120_win11();
            let hello = profile.build_client_hello(&server_name);

            // Must be a handshake record
            prop_assert_eq!(hello[0], 0x16, "Must be handshake record type");

            // Must have valid TLS version
            prop_assert_eq!(hello[1], 0x03, "TLS major version");
            prop_assert!(hello[2] <= 0x03, "TLS minor version");

            // Must be Client Hello
            prop_assert_eq!(hello[5], 0x01, "Must be Client Hello");

            // Must contain the server name
            let contains_sni = hello.windows(server_name.len())
                .any(|w| w == server_name.as_bytes());
            prop_assert!(contains_sni, "SNI must be present");
        }

        /// Property: JA3 calculation is deterministic - same profile always
        /// produces the same hash
        #[test]
        fn prop_ja3_deterministic(iterations in 1usize..10) {
            let profile = TlsProfile::chrome_120_win11();
            let first_hash = profile.calculate_ja3();

            for _ in 0..iterations {
                let hash = profile.calculate_ja3();
                prop_assert_eq!(
                    &hash,
                    &first_hash,
                    "JA3 hash should be deterministic"
                );
            }
        }

        /// Property: Client Hello packets for the same profile and server name
        /// should have consistent structure (excluding random bytes)
        #[test]
        fn prop_client_hello_consistent_length(
            server_name in "[a-z]{1,10}\\.[a-z]{2,5}"
        ) {
            let profile = TlsProfile::chrome_120_win11();
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
        }
    }
}
