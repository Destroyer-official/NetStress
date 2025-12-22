//! Enhanced protocol builders with IP spoofing and fragmentation
//! Implements advanced packet construction for stress testing

use crate::packet::{PacketBuilder, PacketFlags, Protocol, PacketError};
use crate::simd::checksum_simd;
use rand::Rng;
use std::net::Ipv4Addr;

/// IP spoofing configuration
#[derive(Debug, Clone)]
pub struct SpoofConfig {
    /// Enable IP spoofing
    pub enabled: bool,
    /// IP range start (CIDR notation parsed)
    pub range_start: Ipv4Addr,
    /// IP range end
    pub range_end: Ipv4Addr,
    /// Exclude these IPs from spoofing
    pub exclude: Vec<Ipv4Addr>,
}

impl Default for SpoofConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            range_start: Ipv4Addr::new(10, 0, 0, 1),
            range_end: Ipv4Addr::new(10, 255, 255, 254),
            exclude: vec![],
        }
    }
}

impl SpoofConfig {
    /// Create from CIDR notation (e.g., "10.0.0.0/8")
    pub fn from_cidr(cidr: &str) -> Result<Self, PacketError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(PacketError::InvalidIp("Invalid CIDR format".into()));
        }
        
        let base_ip: Ipv4Addr = parts[0].parse()
            .map_err(|_| PacketError::InvalidIp(parts[0].into()))?;
        let prefix: u8 = parts[1].parse()
            .map_err(|_| PacketError::InvalidIp("Invalid prefix length".into()))?;
        
        if prefix > 32 {
            return Err(PacketError::InvalidIp("Prefix must be <= 32".into()));
        }
        
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        let base = u32::from(base_ip);
        let start = base & mask;
        let end = start | !mask;
        
        Ok(Self {
            enabled: true,
            range_start: Ipv4Addr::from(start + 1), // Skip network address
            range_end: Ipv4Addr::from(end - 1),     // Skip broadcast
            exclude: vec![],
        })
    }

    /// Generate a random IP within the configured range
    pub fn random_ip(&self) -> Ipv4Addr {
        if !self.enabled {
            return Ipv4Addr::new(0, 0, 0, 0);
        }
        
        let mut rng = rand::thread_rng();
        let start = u32::from(self.range_start);
        let end = u32::from(self.range_end);
        
        loop {
            let ip = Ipv4Addr::from(rng.gen_range(start..=end));
            if !self.exclude.contains(&ip) {
                return ip;
            }
        }
    }
}

/// IP fragmentation configuration
#[derive(Debug, Clone)]
pub struct FragmentConfig {
    /// Enable fragmentation
    pub enabled: bool,
    /// Fragment size (must be multiple of 8)
    pub fragment_size: u16,
    /// Fragment offset for attacks
    pub offset_attack: bool,
    /// Overlapping fragments
    pub overlap: bool,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fragment_size: 576, // Minimum MTU
            offset_attack: false,
            overlap: false,
        }
    }
}

/// Enhanced protocol builder with spoofing and fragmentation
pub struct ProtocolBuilder {
    /// Spoofing configuration
    spoof: SpoofConfig,
    /// Fragmentation configuration
    fragment: FragmentConfig,
    /// TTL value
    ttl: u8,
    /// IP identification counter
    id_counter: u16,
}

impl Default for ProtocolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolBuilder {
    pub fn new() -> Self {
        Self {
            spoof: SpoofConfig::default(),
            fragment: FragmentConfig::default(),
            ttl: 64,
            id_counter: rand::random(),
        }
    }

    /// Enable IP spoofing with CIDR range
    pub fn with_spoofing(mut self, cidr: &str) -> Result<Self, PacketError> {
        self.spoof = SpoofConfig::from_cidr(cidr)?;
        Ok(self)
    }

    /// Enable fragmentation
    pub fn with_fragmentation(mut self, fragment_size: u16) -> Self {
        self.fragment.enabled = true;
        self.fragment.fragment_size = (fragment_size / 8) * 8; // Must be multiple of 8
        self
    }

    /// Enable fragment offset attack
    pub fn with_offset_attack(mut self) -> Self {
        self.fragment.enabled = true;
        self.fragment.offset_attack = true;
        self
    }

    /// Set TTL
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Build UDP packet with optional spoofing
    pub fn build_udp(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let src_ip = if self.spoof.enabled {
            self.spoof.random_ip()
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };
        
        let src_port: u16 = rand::random();
        self.id_counter = self.id_counter.wrapping_add(1);
        
        let dst: Ipv4Addr = dst_ip.parse()
            .map_err(|_| PacketError::InvalidIp(dst_ip.into()))?;
        
        if self.fragment.enabled && payload.len() > self.fragment.fragment_size as usize {
            return self.build_fragmented_udp(src_ip, dst, src_port, dst_port, payload);
        }
        
        self.build_udp_packet(src_ip, dst, src_port, dst_port, payload)
    }

    /// Build TCP SYN packet
    pub fn build_tcp_syn(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
    ) -> Result<Vec<u8>, PacketError> {
        let src_ip = if self.spoof.enabled {
            self.spoof.random_ip()
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };
        
        let src_port: u16 = rand::random();
        self.id_counter = self.id_counter.wrapping_add(1);
        
        let dst: Ipv4Addr = dst_ip.parse()
            .map_err(|_| PacketError::InvalidIp(dst_ip.into()))?;
        
        self.build_tcp_packet(src_ip, dst, src_port, dst_port, PacketFlags::syn(), &[])
    }

    /// Build TCP ACK packet
    pub fn build_tcp_ack(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let src_ip = if self.spoof.enabled {
            self.spoof.random_ip()
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };
        
        let src_port: u16 = rand::random();
        self.id_counter = self.id_counter.wrapping_add(1);
        
        let dst: Ipv4Addr = dst_ip.parse()
            .map_err(|_| PacketError::InvalidIp(dst_ip.into()))?;
        
        self.build_tcp_packet(src_ip, dst, src_port, dst_port, PacketFlags::ack(), payload)
    }

    /// Build TCP RST packet
    pub fn build_tcp_rst(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
    ) -> Result<Vec<u8>, PacketError> {
        let src_ip = if self.spoof.enabled {
            self.spoof.random_ip()
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };
        
        let src_port: u16 = rand::random();
        self.id_counter = self.id_counter.wrapping_add(1);
        
        let dst: Ipv4Addr = dst_ip.parse()
            .map_err(|_| PacketError::InvalidIp(dst_ip.into()))?;
        
        self.build_tcp_packet(src_ip, dst, src_port, dst_port, PacketFlags::rst(), &[])
    }

    /// Build ICMP echo request
    pub fn build_icmp_echo(
        &mut self,
        dst_ip: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let src_ip = if self.spoof.enabled {
            self.spoof.random_ip()
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };
        
        self.id_counter = self.id_counter.wrapping_add(1);
        
        let dst: Ipv4Addr = dst_ip.parse()
            .map_err(|_| PacketError::InvalidIp(dst_ip.into()))?;
        
        self.build_icmp_packet(src_ip, dst, 8, 0, payload) // Type 8 = Echo Request
    }

    /// Build HTTP GET request packet
    pub fn build_http_get(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
        host: &str,
        path: &str,
    ) -> Result<Vec<u8>, PacketError> {
        let http_payload = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
             Accept-Language: en-US,en;q=0.5\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path, host
        );
        
        self.build_tcp_ack(dst_ip, dst_port, http_payload.as_bytes())
    }

    /// Build HTTP POST request packet
    pub fn build_http_post(
        &mut self,
        dst_ip: &str,
        dst_port: u16,
        host: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let http_payload = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            path, host, body.len()
        );
        
        let mut payload = http_payload.into_bytes();
        payload.extend_from_slice(body);
        
        self.build_tcp_ack(dst_ip, dst_port, &payload)
    }

    /// Build DNS query packet
    pub fn build_dns_query(
        &mut self,
        dst_ip: &str,
        domain: &str,
    ) -> Result<Vec<u8>, PacketError> {
        let mut dns_payload = Vec::with_capacity(512);
        
        // Transaction ID
        let txid: u16 = rand::random();
        dns_payload.extend_from_slice(&txid.to_be_bytes());
        
        // Flags: Standard query
        dns_payload.extend_from_slice(&[0x01, 0x00]);
        
        // Questions: 1
        dns_payload.extend_from_slice(&[0x00, 0x01]);
        
        // Answer RRs: 0
        dns_payload.extend_from_slice(&[0x00, 0x00]);
        
        // Authority RRs: 0
        dns_payload.extend_from_slice(&[0x00, 0x00]);
        
        // Additional RRs: 0
        dns_payload.extend_from_slice(&[0x00, 0x00]);
        
        // Query name (domain)
        for label in domain.split('.') {
            dns_payload.push(label.len() as u8);
            dns_payload.extend_from_slice(label.as_bytes());
        }
        dns_payload.push(0x00); // Null terminator
        
        // Query type: A (1)
        dns_payload.extend_from_slice(&[0x00, 0x01]);
        
        // Query class: IN (1)
        dns_payload.extend_from_slice(&[0x00, 0x01]);
        
        self.build_udp(dst_ip, 53, &dns_payload)
    }

    // Internal packet building methods
    
    fn build_ip_header(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        payload_len: usize,
        flags_offset: u16,
    ) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut header = vec![0u8; 20];
        
        header[0] = 0x45; // Version + IHL
        header[1] = 0x00; // DSCP + ECN
        header[2] = ((total_len >> 8) & 0xFF) as u8;
        header[3] = (total_len & 0xFF) as u8;
        header[4] = ((self.id_counter >> 8) & 0xFF) as u8;
        header[5] = (self.id_counter & 0xFF) as u8;
        header[6] = ((flags_offset >> 8) & 0xFF) as u8;
        header[7] = (flags_offset & 0xFF) as u8;
        header[8] = self.ttl;
        header[9] = protocol;
        header[10] = 0x00; // Checksum (calculated below)
        header[11] = 0x00;
        header[12..16].copy_from_slice(&src.octets());
        header[16..20].copy_from_slice(&dst.octets());
        
        // Calculate checksum using SIMD
        let checksum = checksum_simd(&header);
        header[10] = ((checksum >> 8) & 0xFF) as u8;
        header[11] = (checksum & 0xFF) as u8;
        
        header
    }

    fn build_udp_packet(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let udp_len = 8 + payload.len();
        let mut udp_header = vec![0u8; 8];
        
        udp_header[0] = ((src_port >> 8) & 0xFF) as u8;
        udp_header[1] = (src_port & 0xFF) as u8;
        udp_header[2] = ((dst_port >> 8) & 0xFF) as u8;
        udp_header[3] = (dst_port & 0xFF) as u8;
        udp_header[4] = ((udp_len >> 8) & 0xFF) as u8;
        udp_header[5] = (udp_len & 0xFF) as u8;
        udp_header[6] = 0x00; // Checksum optional for IPv4
        udp_header[7] = 0x00;
        
        let ip_header = self.build_ip_header(src, dst, 17, udp_len, 0x4000); // Don't fragment
        
        let mut packet = ip_header;
        packet.extend(udp_header);
        packet.extend_from_slice(payload);
        
        Ok(packet)
    }

    fn build_tcp_packet(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: PacketFlags,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let tcp_header_len = 20;
        let mut tcp_header = vec![0u8; tcp_header_len];
        
        tcp_header[0] = ((src_port >> 8) & 0xFF) as u8;
        tcp_header[1] = (src_port & 0xFF) as u8;
        tcp_header[2] = ((dst_port >> 8) & 0xFF) as u8;
        tcp_header[3] = (dst_port & 0xFF) as u8;
        
        // Sequence number
        let seq: u32 = rand::random();
        tcp_header[4..8].copy_from_slice(&seq.to_be_bytes());
        
        // Acknowledgment number
        tcp_header[8..12].copy_from_slice(&0u32.to_be_bytes());
        
        // Data offset (5 words) + reserved
        tcp_header[12] = 0x50;
        
        // Flags
        tcp_header[13] = flags.to_byte();
        
        // Window size
        tcp_header[14] = 0xFF;
        tcp_header[15] = 0xFF;
        
        // Checksum (calculated with pseudo-header)
        tcp_header[16] = 0x00;
        tcp_header[17] = 0x00;
        
        // Urgent pointer
        tcp_header[18] = 0x00;
        tcp_header[19] = 0x00;
        
        // Calculate TCP checksum
        let checksum = self.tcp_checksum(&tcp_header, payload, src, dst);
        tcp_header[16] = ((checksum >> 8) & 0xFF) as u8;
        tcp_header[17] = (checksum & 0xFF) as u8;
        
        let ip_header = self.build_ip_header(src, dst, 6, tcp_header_len + payload.len(), 0x4000);
        
        let mut packet = ip_header;
        packet.extend(tcp_header);
        packet.extend_from_slice(payload);
        
        Ok(packet)
    }

    fn build_icmp_packet(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: u8,
        icmp_code: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let mut icmp_header = vec![0u8; 8];
        
        icmp_header[0] = icmp_type;
        icmp_header[1] = icmp_code;
        icmp_header[2] = 0x00; // Checksum
        icmp_header[3] = 0x00;
        icmp_header[4] = ((self.id_counter >> 8) & 0xFF) as u8;
        icmp_header[5] = (self.id_counter & 0xFF) as u8;
        icmp_header[6] = 0x00; // Sequence
        icmp_header[7] = 0x01;
        
        // Calculate ICMP checksum
        let mut data = icmp_header.clone();
        data.extend_from_slice(payload);
        let checksum = checksum_simd(&data);
        icmp_header[2] = ((checksum >> 8) & 0xFF) as u8;
        icmp_header[3] = (checksum & 0xFF) as u8;
        
        let ip_header = self.build_ip_header(src, dst, 1, 8 + payload.len(), 0x4000);
        
        let mut packet = ip_header;
        packet.extend(icmp_header);
        packet.extend_from_slice(payload);
        
        Ok(packet)
    }

    fn build_fragmented_udp(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, PacketError> {
        let frag_size = self.fragment.fragment_size as usize;
        let mut fragments = Vec::new();
        
        // Build UDP header for first fragment
        let udp_len = 8 + payload.len();
        let mut udp_header = vec![0u8; 8];
        udp_header[0] = ((src_port >> 8) & 0xFF) as u8;
        udp_header[1] = (src_port & 0xFF) as u8;
        udp_header[2] = ((dst_port >> 8) & 0xFF) as u8;
        udp_header[3] = (dst_port & 0xFF) as u8;
        udp_header[4] = ((udp_len >> 8) & 0xFF) as u8;
        udp_header[5] = (udp_len & 0xFF) as u8;
        
        // First fragment includes UDP header
        let mut first_payload = udp_header;
        let first_data_len = (frag_size - 8).min(payload.len());
        first_payload.extend_from_slice(&payload[..first_data_len]);
        
        // MF (More Fragments) flag set
        let ip_header = self.build_ip_header(src, dst, 17, first_payload.len(), 0x2000);
        let mut first_frag = ip_header;
        first_frag.extend(first_payload);
        fragments.extend(first_frag);
        
        // Subsequent fragments
        let mut offset = first_data_len;
        while offset < payload.len() {
            let chunk_len = frag_size.min(payload.len() - offset);
            let frag_offset = (8 + offset) / 8; // Fragment offset in 8-byte units
            
            let flags_offset = if offset + chunk_len < payload.len() {
                0x2000 | (frag_offset as u16) // MF set
            } else {
                frag_offset as u16 // Last fragment
            };
            
            let ip_header = self.build_ip_header(src, dst, 17, chunk_len, flags_offset);
            fragments.extend(ip_header);
            fragments.extend_from_slice(&payload[offset..offset + chunk_len]);
            
            offset += chunk_len;
        }
        
        Ok(fragments)
    }

    fn tcp_checksum(&self, tcp_header: &[u8], payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let tcp_len = tcp_header.len() + payload.len();
        
        let mut pseudo = Vec::with_capacity(12 + tcp_len);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6); // TCP
        pseudo.push(((tcp_len >> 8) & 0xFF) as u8);
        pseudo.push((tcp_len & 0xFF) as u8);
        pseudo.extend_from_slice(tcp_header);
        pseudo.extend_from_slice(payload);
        
        checksum_simd(&pseudo)
    }
}

/// Batch packet generator for high-throughput scenarios
pub struct BatchPacketGenerator {
    builder: ProtocolBuilder,
    dst_ip: String,
    dst_port: u16,
    protocol: Protocol,
    payload_size: usize,
}

impl BatchPacketGenerator {
    pub fn new(dst_ip: &str, dst_port: u16, protocol: Protocol, payload_size: usize) -> Self {
        Self {
            builder: ProtocolBuilder::new(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            protocol,
            payload_size,
        }
    }

    /// Enable spoofing
    pub fn with_spoofing(mut self, cidr: &str) -> Result<Self, PacketError> {
        self.builder = self.builder.with_spoofing(cidr)?;
        Ok(self)
    }

    /// Generate a batch of packets
    pub fn generate_batch(&mut self, count: usize) -> Vec<Vec<u8>> {
        let payload = vec![0xAA; self.payload_size];
        let mut packets = Vec::with_capacity(count);
        
        for _ in 0..count {
            let packet = match self.protocol {
                Protocol::UDP => self.builder.build_udp(&self.dst_ip, self.dst_port, &payload),
                Protocol::TCP => self.builder.build_tcp_syn(&self.dst_ip, self.dst_port),
                Protocol::ICMP => self.builder.build_icmp_echo(&self.dst_ip, &payload),
                Protocol::HTTP => self.builder.build_http_get(&self.dst_ip, self.dst_port, &self.dst_ip, "/"),
                Protocol::RAW => Ok(payload.clone()),
            };
            
            if let Ok(p) = packet {
                packets.push(p);
            }
        }
        
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spoof_config_from_cidr() {
        let config = SpoofConfig::from_cidr("192.168.1.0/24").unwrap();
        assert!(config.enabled);
        
        let ip = config.random_ip();
        let octets = ip.octets();
        assert_eq!(octets[0], 192);
        assert_eq!(octets[1], 168);
        assert_eq!(octets[2], 1);
    }

    #[test]
    fn test_build_udp() {
        let mut builder = ProtocolBuilder::new();
        let packet = builder.build_udp("192.168.1.1", 80, b"test").unwrap();
        assert!(packet.len() >= 32);
    }

    #[test]
    fn test_build_tcp_syn() {
        let mut builder = ProtocolBuilder::new();
        let packet = builder.build_tcp_syn("192.168.1.1", 80).unwrap();
        assert!(packet.len() >= 40);
    }

    #[test]
    fn test_build_with_spoofing() {
        let mut builder = ProtocolBuilder::new()
            .with_spoofing("10.0.0.0/8")
            .unwrap();
        
        let packet = builder.build_udp("192.168.1.1", 80, b"test").unwrap();
        
        // Check source IP is in spoofed range
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        assert_eq!(src_ip.octets()[0], 10);
    }

    #[test]
    fn test_batch_generator() {
        let mut gen = BatchPacketGenerator::new("192.168.1.1", 80, Protocol::UDP, 100);
        let packets = gen.generate_batch(10);
        assert_eq!(packets.len(), 10);
    }
}
