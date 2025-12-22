//! Packet building module
//! High-performance packet construction with zero-copy where possible

use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    UDP,
    TCP,
    ICMP,
    HTTP,
    RAW,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::UDP
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PacketFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl PacketFlags {
    pub fn syn() -> Self {
        Self {
            syn: true,
            ..Default::default()
        }
    }

    pub fn ack() -> Self {
        Self {
            ack: true,
            ..Default::default()
        }
    }

    pub fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            ..Default::default()
        }
    }

    pub fn fin() -> Self {
        Self {
            fin: true,
            ..Default::default()
        }
    }

    pub fn rst() -> Self {
        Self {
            rst: true,
            ..Default::default()
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin {
            flags |= 0x01;
        }
        if self.syn {
            flags |= 0x02;
        }
        if self.rst {
            flags |= 0x04;
        }
        if self.psh {
            flags |= 0x08;
        }
        if self.ack {
            flags |= 0x10;
        }
        if self.urg {
            flags |= 0x20;
        }
        flags
    }
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Invalid port: {0}")]
    InvalidPort(u16),
    #[error("Payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("Build error: {0}")]
    BuildError(String),
}

/// High-performance packet builder
pub struct PacketBuilder {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
    flags: PacketFlags,
    payload: Vec<u8>,
    ttl: u8,
    id: u16,
}

impl Default for PacketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self {
            src_ip: None,
            dst_ip: None,
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::UDP,
            flags: PacketFlags::default(),
            payload: Vec::new(),
            ttl: 64,
            id: rand::random(),
        }
    }

    pub fn src_ip(mut self, ip: &str) -> Self {
        self.src_ip = ip.parse().ok();
        self
    }

    pub fn dst_ip(mut self, ip: &str) -> Self {
        self.dst_ip = ip.parse().ok();
        self
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = port;
        self
    }

    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    pub fn protocol(mut self, proto: Protocol) -> Self {
        self.protocol = proto;
        self
    }

    pub fn flags(mut self, flags: PacketFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Build the packet
    pub fn build(self) -> Result<Vec<u8>, PacketError> {
        let src_ip = self.src_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
        let dst_ip = self
            .dst_ip
            .ok_or_else(|| PacketError::InvalidIp("No destination IP".into()))?;

        match self.protocol {
            Protocol::UDP => self.build_udp(src_ip, dst_ip),
            Protocol::TCP => self.build_tcp(src_ip, dst_ip),
            Protocol::ICMP => self.build_icmp(src_ip, dst_ip),
            Protocol::HTTP => self.build_http(src_ip, dst_ip),
            Protocol::RAW => Ok(self.payload),
        }
    }

    fn build_ip_header(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        payload_len: usize,
    ) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut header = vec![0u8; 20];

        // Version (4) + IHL (5)
        header[0] = 0x45;
        // DSCP + ECN
        header[1] = 0x00;
        // Total length
        header[2] = ((total_len >> 8) & 0xFF) as u8;
        header[3] = (total_len & 0xFF) as u8;
        // Identification
        header[4] = ((self.id >> 8) & 0xFF) as u8;
        header[5] = (self.id & 0xFF) as u8;
        // Flags + Fragment offset
        header[6] = 0x40; // Don't fragment
        header[7] = 0x00;
        // TTL
        header[8] = self.ttl;
        // Protocol
        header[9] = protocol;
        // Checksum (calculated later)
        header[10] = 0x00;
        header[11] = 0x00;
        // Source IP
        header[12..16].copy_from_slice(&src.octets());
        // Destination IP
        header[16..20].copy_from_slice(&dst.octets());

        // Calculate checksum
        let checksum = Self::ip_checksum(&header);
        header[10] = ((checksum >> 8) & 0xFF) as u8;
        header[11] = (checksum & 0xFF) as u8;

        header
    }

    fn build_udp(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Result<Vec<u8>, PacketError> {
        let udp_len = 8 + self.payload.len();
        let mut udp_header = vec![0u8; 8];

        // Source port
        udp_header[0] = ((self.src_port >> 8) & 0xFF) as u8;
        udp_header[1] = (self.src_port & 0xFF) as u8;
        // Destination port
        udp_header[2] = ((self.dst_port >> 8) & 0xFF) as u8;
        udp_header[3] = (self.dst_port & 0xFF) as u8;
        // Length
        udp_header[4] = ((udp_len >> 8) & 0xFF) as u8;
        udp_header[5] = (udp_len & 0xFF) as u8;
        // Checksum (optional for UDP over IPv4)
        udp_header[6] = 0x00;
        udp_header[7] = 0x00;

        let ip_header = self.build_ip_header(src, dst, 17, udp_len);

        let mut packet = ip_header;
        packet.extend(udp_header);
        packet.extend(&self.payload);

        Ok(packet)
    }

    fn build_tcp(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Result<Vec<u8>, PacketError> {
        let tcp_header_len = 20;
        let mut tcp_header = vec![0u8; tcp_header_len];

        // Source port
        tcp_header[0] = ((self.src_port >> 8) & 0xFF) as u8;
        tcp_header[1] = (self.src_port & 0xFF) as u8;
        // Destination port
        tcp_header[2] = ((self.dst_port >> 8) & 0xFF) as u8;
        tcp_header[3] = (self.dst_port & 0xFF) as u8;
        // Sequence number
        let seq: u32 = rand::random();
        tcp_header[4..8].copy_from_slice(&seq.to_be_bytes());
        // Acknowledgment number
        tcp_header[8..12].copy_from_slice(&0u32.to_be_bytes());
        // Data offset (5 words = 20 bytes) + reserved
        tcp_header[12] = 0x50;
        // Flags
        tcp_header[13] = self.flags.to_byte();
        // Window size
        tcp_header[14] = 0xFF;
        tcp_header[15] = 0xFF;
        // Checksum (calculated with pseudo-header)
        tcp_header[16] = 0x00;
        tcp_header[17] = 0x00;
        // Urgent pointer
        tcp_header[18] = 0x00;
        tcp_header[19] = 0x00;

        // Calculate TCP checksum with pseudo-header
        let checksum = Self::tcp_checksum(&tcp_header, &self.payload, src, dst);
        tcp_header[16] = ((checksum >> 8) & 0xFF) as u8;
        tcp_header[17] = (checksum & 0xFF) as u8;

        let ip_header = self.build_ip_header(src, dst, 6, tcp_header_len + self.payload.len());

        let mut packet = ip_header;
        packet.extend(tcp_header);
        packet.extend(&self.payload);

        Ok(packet)
    }

    fn build_icmp(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Result<Vec<u8>, PacketError> {
        let mut icmp_header = vec![0u8; 8];

        // Type (8 = Echo Request)
        icmp_header[0] = 8;
        // Code
        icmp_header[1] = 0;
        // Checksum (calculated later)
        icmp_header[2] = 0;
        icmp_header[3] = 0;
        // Identifier
        icmp_header[4] = ((self.id >> 8) & 0xFF) as u8;
        icmp_header[5] = (self.id & 0xFF) as u8;
        // Sequence number
        icmp_header[6] = 0;
        icmp_header[7] = 1;

        // Calculate ICMP checksum
        let mut data = icmp_header.clone();
        data.extend(&self.payload);
        let checksum = Self::ip_checksum(&data);
        icmp_header[2] = ((checksum >> 8) & 0xFF) as u8;
        icmp_header[3] = (checksum & 0xFF) as u8;

        let ip_header = self.build_ip_header(src, dst, 1, 8 + self.payload.len());

        let mut packet = ip_header;
        packet.extend(icmp_header);
        packet.extend(&self.payload);

        Ok(packet)
    }

    fn build_http(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Result<Vec<u8>, PacketError> {
        // HTTP is just TCP with HTTP payload
        let http_payload = if self.payload.is_empty() {
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: NetStress/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
                dst
            ).into_bytes()
        } else {
            self.payload.clone()
        };

        let builder = PacketBuilder {
            payload: http_payload,
            flags: PacketFlags::ack(),
            ..self.clone_config()
        };

        builder.build_tcp(src, dst)
    }

    fn clone_config(&self) -> Self {
        Self {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            protocol: Protocol::TCP,
            flags: self.flags,
            payload: Vec::new(),
            ttl: self.ttl,
            id: self.id,
        }
    }

    fn ip_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;

        while i < data.len() - 1 {
            sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
            i += 2;
        }

        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    fn tcp_checksum(tcp_header: &[u8], payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
        let tcp_len = tcp_header.len() + payload.len();

        // Build pseudo-header
        let mut pseudo = Vec::with_capacity(12 + tcp_len);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6); // TCP protocol
        pseudo.push(((tcp_len >> 8) & 0xFF) as u8);
        pseudo.push((tcp_len & 0xFF) as u8);
        pseudo.extend_from_slice(tcp_header);
        pseudo.extend_from_slice(payload);

        Self::ip_checksum(&pseudo)
    }
}

/// Pre-built packet templates for high-speed generation
pub struct PacketTemplates;

impl PacketTemplates {
    /// Generate a UDP flood packet
    pub fn udp_flood(dst_ip: &str, dst_port: u16, size: usize) -> Result<Vec<u8>, PacketError> {
        let payload = vec![0xAA; size.saturating_sub(28)]; // IP + UDP headers
        PacketBuilder::new()
            .src_ip("0.0.0.0")
            .dst_ip(dst_ip)
            .src_port(rand::random())
            .dst_port(dst_port)
            .protocol(Protocol::UDP)
            .payload(&payload)
            .build()
    }

    /// Generate a SYN flood packet
    pub fn syn_flood(dst_ip: &str, dst_port: u16) -> Result<Vec<u8>, PacketError> {
        PacketBuilder::new()
            .src_ip("0.0.0.0")
            .dst_ip(dst_ip)
            .src_port(rand::random())
            .dst_port(dst_port)
            .protocol(Protocol::TCP)
            .flags(PacketFlags::syn())
            .build()
    }

    /// Generate an ICMP echo request
    pub fn icmp_echo(dst_ip: &str, size: usize) -> Result<Vec<u8>, PacketError> {
        let payload = vec![0x00; size.saturating_sub(28)];
        PacketBuilder::new()
            .src_ip("0.0.0.0")
            .dst_ip(dst_ip)
            .protocol(Protocol::ICMP)
            .payload(&payload)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_udp_packet() {
        let packet = PacketBuilder::new()
            .src_ip("192.168.1.1")
            .dst_ip("192.168.1.2")
            .src_port(12345)
            .dst_port(80)
            .protocol(Protocol::UDP)
            .payload(b"test")
            .build()
            .unwrap();

        assert!(packet.len() >= 32); // IP + UDP + payload

        // Check IP header version
        assert_eq!(packet[0] >> 4, 4); // IPv4

        // Check protocol field in IP header
        assert_eq!(packet[9], 17); // UDP protocol

        // Check destination IP
        assert_eq!(&packet[16..20], &[192, 168, 1, 2]);
    }

    #[test]
    fn test_tcp_syn() {
        let packet = PacketBuilder::new()
            .src_ip("192.168.1.1")
            .dst_ip("192.168.1.2")
            .src_port(12345)
            .dst_port(80)
            .protocol(Protocol::TCP)
            .flags(PacketFlags::syn())
            .build()
            .unwrap();

        assert!(packet.len() >= 40); // IP + TCP

        // Check IP header version
        assert_eq!(packet[0] >> 4, 4); // IPv4

        // Check protocol field in IP header
        assert_eq!(packet[9], 6); // TCP protocol

        // Check TCP flags (SYN = 0x02)
        assert_eq!(packet[33], 0x02);
    }

    #[test]
    fn test_icmp_packet() {
        let packet = PacketBuilder::new()
            .src_ip("192.168.1.1")
            .dst_ip("192.168.1.2")
            .protocol(Protocol::ICMP)
            .payload(b"ping")
            .build()
            .unwrap();

        assert!(packet.len() >= 32); // IP + ICMP + payload

        // Check protocol field in IP header
        assert_eq!(packet[9], 1); // ICMP protocol

        // Check ICMP type (Echo Request = 8)
        assert_eq!(packet[20], 8);
    }

    #[test]
    fn test_packet_flags() {
        let flags = PacketFlags::syn_ack();
        assert_eq!(flags.to_byte(), 0x12); // SYN (0x02) + ACK (0x10)

        let syn_flags = PacketFlags::syn();
        assert_eq!(syn_flags.to_byte(), 0x02);

        let ack_flags = PacketFlags::ack();
        assert_eq!(ack_flags.to_byte(), 0x10);

        let fin_flags = PacketFlags::fin();
        assert_eq!(fin_flags.to_byte(), 0x01);

        let rst_flags = PacketFlags::rst();
        assert_eq!(rst_flags.to_byte(), 0x04);
    }

    #[test]
    fn test_packet_builder_defaults() {
        let builder = PacketBuilder::new();
        assert_eq!(builder.protocol, Protocol::UDP);
        assert_eq!(builder.src_port, 0);
        assert_eq!(builder.dst_port, 0);
        assert_eq!(builder.ttl, 64);
        assert!(builder.payload.is_empty());
    }

    #[test]
    fn test_packet_builder_chaining() {
        let packet = PacketBuilder::new()
            .src_ip("10.0.0.1")
            .dst_ip("10.0.0.2")
            .src_port(1234)
            .dst_port(5678)
            .protocol(Protocol::UDP)
            .ttl(32)
            .payload(b"hello")
            .build()
            .unwrap();

        assert!(packet.len() > 0);

        // Check TTL
        assert_eq!(packet[8], 32);
    }

    #[test]
    fn test_packet_templates_udp_flood() {
        let packet = PacketTemplates::udp_flood("8.8.8.8", 53, 1024).unwrap();
        assert!(packet.len() >= 1024);

        // Check it's UDP
        assert_eq!(packet[9], 17);

        // Check destination port (53)
        assert_eq!(packet[22], 0);
        assert_eq!(packet[23], 53);
    }

    #[test]
    fn test_packet_templates_syn_flood() {
        let packet = PacketTemplates::syn_flood("1.1.1.1", 443).unwrap();
        assert!(packet.len() >= 40);

        // Check it's TCP
        assert_eq!(packet[9], 6);

        // Check SYN flag
        assert_eq!(packet[33], 0x02);

        // Check destination port (443)
        assert_eq!(packet[22], 0x01);
        assert_eq!(packet[23], 0xBB);
    }

    #[test]
    fn test_packet_templates_icmp_echo() {
        let packet = PacketTemplates::icmp_echo("127.0.0.1", 64).unwrap();
        assert!(packet.len() >= 64);

        // Check it's ICMP
        assert_eq!(packet[9], 1);

        // Check ICMP type (Echo Request = 8)
        assert_eq!(packet[20], 8);
    }

    #[test]
    fn test_invalid_destination_ip() {
        let result = PacketBuilder::new()
            .src_ip("192.168.1.1")
            .protocol(Protocol::UDP)
            .build();

        assert!(result.is_err());
        match result.unwrap_err() {
            PacketError::InvalidIp(_) => {}
            _ => panic!("Expected InvalidIp error"),
        }
    }

    #[test]
    fn test_http_packet() {
        let packet = PacketBuilder::new()
            .src_ip("192.168.1.1")
            .dst_ip("192.168.1.2")
            .src_port(12345)
            .dst_port(80)
            .protocol(Protocol::HTTP)
            .build()
            .unwrap();

        assert!(packet.len() > 40); // Should have HTTP payload

        // Should be TCP
        assert_eq!(packet[9], 6);

        // Should have ACK flag
        assert_eq!(packet[33], 0x10);
    }

    #[test]
    fn test_ip_checksum() {
        let data = vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let checksum = PacketBuilder::ip_checksum(&data);
        assert_ne!(checksum, 0); // Should calculate a non-zero checksum
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_udp_packet_with_random_ips(
            src_a in 1u8..255, src_b in 0u8..255, src_c in 0u8..255, src_d in 1u8..255,
            dst_a in 1u8..255, dst_b in 0u8..255, dst_c in 0u8..255, dst_d in 1u8..255,
            src_port in 1u16..65535,
            dst_port in 1u16..65535
        ) {
            let src_ip = format!("{}.{}.{}.{}", src_a, src_b, src_c, src_d);
            let dst_ip = format!("{}.{}.{}.{}", dst_a, dst_b, dst_c, dst_d);

            let packet = PacketBuilder::new()
                .src_ip(&src_ip)
                .dst_ip(&dst_ip)
                .src_port(src_port)
                .dst_port(dst_port)
                .protocol(Protocol::UDP)
                .build();

            prop_assert!(packet.is_ok());
            let packet = packet.unwrap();
            prop_assert!(packet.len() >= 28); // IP + UDP headers
            prop_assert_eq!(packet[0] >> 4, 4); // IPv4
            prop_assert_eq!(packet[9], 17); // UDP protocol
        }

        #[test]
        fn test_tcp_packet_with_random_flags(
            syn in proptest::bool::ANY,
            ack in proptest::bool::ANY,
            fin in proptest::bool::ANY,
            rst in proptest::bool::ANY,
            psh in proptest::bool::ANY,
            urg in proptest::bool::ANY
        ) {
            let flags = PacketFlags { syn, ack, fin, rst, psh, urg };

            let packet = PacketBuilder::new()
                .src_ip("10.0.0.1")
                .dst_ip("10.0.0.2")
                .src_port(1234)
                .dst_port(80)
                .protocol(Protocol::TCP)
                .flags(flags)
                .build();

            prop_assert!(packet.is_ok());
            let packet = packet.unwrap();
            prop_assert!(packet.len() >= 40); // IP + TCP headers
            prop_assert_eq!(packet[0] >> 4, 4); // IPv4
            prop_assert_eq!(packet[9], 6); // TCP protocol

            // Check flags byte
            let expected_flags = flags.to_byte();
            prop_assert_eq!(packet[33], expected_flags);
        }

        #[test]
        fn test_packet_with_random_payload(payload_size in 0usize..1400) {
            let payload = vec![0xAA; payload_size];

            let packet = PacketBuilder::new()
                .src_ip("192.168.1.1")
                .dst_ip("192.168.1.2")
                .src_port(12345)
                .dst_port(80)
                .protocol(Protocol::UDP)
                .payload(&payload)
                .build();

            prop_assert!(packet.is_ok());
            let packet = packet.unwrap();
            prop_assert_eq!(packet.len(), 28 + payload_size); // IP + UDP + payload
        }

        #[test]
        fn test_packet_with_random_ttl(ttl in 1u8..255) {
            let packet = PacketBuilder::new()
                .src_ip("192.168.1.1")
                .dst_ip("192.168.1.2")
                .protocol(Protocol::UDP)
                .ttl(ttl)
                .build();

            prop_assert!(packet.is_ok());
            let packet = packet.unwrap();
            prop_assert_eq!(packet[8], ttl); // TTL field in IP header
        }
    }
}
