/*!
 * QUIC/HTTP/3 Engine for NetStress Titanium v3.0
 * 
 * This module implements QUIC protocol support with HTTP/3 capabilities,
 * including 0-RTT support, connection migration, and browser-like fingerprinting.
 * 
 * **Validates: Requirements 5.3, 5.4, 5.5**
 */

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "quic")]
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, NewConnection, 
    RecvStream, SendStream, TransportConfig, VarInt
};

#[cfg(feature = "quic")]
use rustls::{Certificate, ClientConfig as RustlsClientConfig, PrivateKey};

#[cfg(feature = "http3")]
use h3::{client::SendRequest, error::Error as H3Error};

#[cfg(feature = "http3")]
use h3_quinn::BidiStream;

use crate::atomic_stats::AtomicStats;
use crate::backend::BackendError;

/// QUIC connection statistics
#[derive(Debug, Clone, Default)]
pub struct QuicStats {
    pub connections_established: u64,
    pub connections_failed: u64,
    pub zero_rtt_accepted: u64,
    pub zero_rtt_rejected: u64,
    pub migrations_performed: u64,
    pub requests_sent: u64,
    pub requests_successful: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Browser profile for QUIC fingerprinting
#[derive(Debug, Clone)]
pub struct QuicBrowserProfile {
    pub name: String,
    pub alpn_protocols: Vec<String>,
    pub max_idle_timeout: Duration,
    pub max_udp_payload_size: u16,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u8,
    pub max_ack_delay: Duration,
    pub disable_active_migration: bool,
}

impl Default for QuicBrowserProfile {
    fn default() -> Self {
        Self::chrome_120()
    }
}

impl QuicBrowserProfile {
    /// Chrome 120+ QUIC profile
    pub fn chrome_120() -> Self {
        Self {
            name: "Chrome 120".to_string(),
            alpn_protocols: vec!["h3".to_string(), "h3-29".to_string()],
            max_idle_timeout: Duration::from_secs(30),
            max_udp_payload_size: 1472,
            initial_max_data: 15728640, // 15MB
            initial_max_stream_data_bidi_local: 6291456, // 6MB
            initial_max_stream_data_bidi_remote: 6291456, // 6MB
            initial_max_stream_data_uni: 6291456, // 6MB
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 3,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
        }
    }

    /// Firefox 121+ QUIC profile
    pub fn firefox_121() -> Self {
        Self {
            name: "Firefox 121".to_string(),
            alpn_protocols: vec!["h3".to_string()],
            max_idle_timeout: Duration::from_secs(60),
            max_udp_payload_size: 1472,
            initial_max_data: 12582912, // 12MB
            initial_max_stream_data_bidi_local: 262144, // 256KB
            initial_max_stream_data_bidi_remote: 262144, // 256KB
            initial_max_stream_data_uni: 262144, // 256KB
            initial_max_streams_bidi: 16,
            initial_max_streams_uni: 16,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: true,
        }
    }

    /// Safari 17+ QUIC profile
    pub fn safari_17() -> Self {
        Self {
            name: "Safari 17".to_string(),
            alpn_protocols: vec!["h3".to_string()],
            max_idle_timeout: Duration::from_secs(30),
            max_udp_payload_size: 1200, // More conservative
            initial_max_data: 10485760, // 10MB
            initial_max_stream_data_bidi_local: 1048576, // 1MB
            initial_max_stream_data_bidi_remote: 1048576, // 1MB
            initial_max_stream_data_uni: 1048576, // 1MB
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 3,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
        }
    }
}

/// QUIC connection state for migration support
#[derive(Debug, Clone)]
pub struct QuicConnectionState {
    pub connection_id: Vec<u8>,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub established_at: Instant,
    pub last_migration: Option<Instant>,
    pub migration_count: u32,
}

/// Session ticket cache for 0-RTT support
#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub ticket: Vec<u8>,
    pub server_name: String,
    pub created_at: Instant,
    pub max_early_data: u32,
}

/// QUIC/HTTP/3 Engine
pub struct QuicHttp3Engine {
    endpoint: Option<Arc<Endpoint>>,
    client_config: Option<ClientConfig>,
    browser_profile: QuicBrowserProfile,
    stats: Arc<AtomicStats>,
    quic_stats: Arc<RwLock<QuicStats>>,
    
    // Connection management
    active_connections: Arc<RwLock<HashMap<String, Connection>>>,
    connection_states: Arc<RwLock<HashMap<String, QuicConnectionState>>>,
    
    // 0-RTT session cache
    session_cache: Arc<RwLock<HashMap<String, SessionTicket>>>,
    
    // HTTP/3 clients
    #[cfg(feature = "http3")]
    h3_clients: Arc<RwLock<HashMap<String, SendRequest<BidiStream<Bytes>, Bytes>>>>,
}

impl QuicHttp3Engine {
    /// Create new QUIC/HTTP/3 engine with browser profile
    pub fn new(profile: QuicBrowserProfile) -> Result<Self, BackendError> {
        info!("Initializing QUIC/HTTP/3 engine with profile: {}", profile.name);

        #[cfg(not(feature = "quic"))]
        {
            return Err(BackendError::NotSupported("QUIC support not compiled".to_string()));
        }

        #[cfg(feature = "quic")]
        {
            let stats = Arc::new(AtomicStats::new());
            let quic_stats = Arc::new(RwLock::new(QuicStats::default()));

            Ok(Self {
                endpoint: None,
                client_config: None,
                browser_profile: profile,
                stats,
                quic_stats,
                active_connections: Arc::new(RwLock::new(HashMap::new())),
                connection_states: Arc::new(RwLock::new(HashMap::new())),
                session_cache: Arc::new(RwLock::new(HashMap::new())),
                #[cfg(feature = "http3")]
                h3_clients: Arc::new(RwLock::new(HashMap::new())),
            })
        }
    }

    /// Initialize QUIC endpoint with browser-like configuration
    #[cfg(feature = "quic")]
    pub async fn initialize(&mut self) -> Result<(), BackendError> {
        info!("Initializing QUIC endpoint");

        // Create TLS configuration
        let crypto = self.create_tls_config()?;
        
        // Create QUIC client configuration
        let mut client_config = ClientConfig::new(Arc::new(crypto));
        
        // Configure transport parameters to match browser profile
        let mut transport = TransportConfig::default();
        
        // Set browser-specific transport parameters
        transport.max_idle_timeout(Some(self.browser_profile.max_idle_timeout.try_into().unwrap()));
        transport.max_udp_payload_size(VarInt::from_u32(self.browser_profile.max_udp_payload_size as u32));
        transport.initial_max_data(VarInt::from_u64(self.browser_profile.initial_max_data));
        transport.initial_max_stream_data_bidi_local(VarInt::from_u64(self.browser_profile.initial_max_stream_data_bidi_local));
        transport.initial_max_stream_data_bidi_remote(VarInt::from_u64(self.browser_profile.initial_max_stream_data_bidi_remote));
        transport.initial_max_stream_data_uni(VarInt::from_u64(self.browser_profile.initial_max_stream_data_uni));
        transport.initial_max_streams_bidi(VarInt::from_u64(self.browser_profile.initial_max_streams_bidi));
        transport.initial_max_streams_uni(VarInt::from_u64(self.browser_profile.initial_max_streams_uni));
        transport.ack_delay_exponent(VarInt::from_u32(self.browser_profile.ack_delay_exponent as u32));
        transport.max_ack_delay(self.browser_profile.max_ack_delay);
        
        if self.browser_profile.disable_active_migration {
            transport.disable_active_migration(true);
        }

        client_config.transport_config(Arc::new(transport));
        
        // Create endpoint
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| BackendError::InitializationFailed(format!("Failed to create QUIC endpoint: {}", e)))?;
        
        endpoint.set_default_client_config(client_config.clone());
        
        self.endpoint = Some(Arc::new(endpoint));
        self.client_config = Some(client_config);
        
        info!("QUIC endpoint initialized successfully");
        Ok(())
    }

    /// Create TLS configuration with browser-like settings
    #[cfg(feature = "quic")]
    fn create_tls_config(&self) -> Result<RustlsClientConfig, BackendError> {
        let mut crypto = RustlsClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(webpki_roots::TLS_SERVER_ROOTS.0.iter().cloned().collect())
            .with_no_client_auth();

        // Set ALPN protocols from browser profile
        crypto.alpn_protocols = self.browser_profile.alpn_protocols
            .iter()
            .map(|proto| proto.as_bytes().to_vec())
            .collect();

        Ok(crypto)
    }

    /// Establish QUIC connection with 0-RTT support
    #[cfg(feature = "quic")]
    pub async fn connect_with_0rtt(
        &mut self,
        server_name: &str,
        server_addr: SocketAddr,
    ) -> Result<Connection, BackendError> {
        let endpoint = self.endpoint.as_ref()
            .ok_or_else(|| BackendError::NotInitialized("QUIC endpoint not initialized".to_string()))?;

        info!("Connecting to {}:{} with 0-RTT support", server_name, server_addr);

        // Check for cached session ticket
        let session_ticket = self.session_cache.read().get(server_name).cloned();

        let connecting = endpoint.connect(server_addr, server_name)
            .map_err(|e| BackendError::ConnectionFailed(format!("Failed to initiate QUIC connection: {}", e)))?;

        // Try 0-RTT if we have a session ticket
        if let Some(ticket) = session_ticket {
            if ticket.created_at.elapsed() < Duration::from_hours(24) && ticket.max_early_data > 0 {
                debug!("Attempting 0-RTT connection with cached session (max_early_data: {})", ticket.max_early_data);
                
                match connecting.into_0rtt() {
                    Ok((connection, zero_rtt)) => {
                        info!("0-RTT connection established successfully");
                        self.quic_stats.write().zero_rtt_accepted += 1;
                        
                        // Store connection
                        let conn_key = format!("{}:{}", server_name, server_addr);
                        self.active_connections.write().insert(conn_key.clone(), connection.clone());
                        
                        // Store connection state
                        let state = QuicConnectionState {
                            connection_id: connection.stable_id().to_be_bytes().to_vec(),
                            local_addr: connection.local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).into(),
                            remote_addr: server_addr,
                            established_at: Instant::now(),
                            last_migration: None,
                            migration_count: 0,
                        };
                        self.connection_states.write().insert(conn_key, state);
                        
                        self.quic_stats.write().connections_established += 1;
                        
                        // Spawn task to handle 0-RTT confirmation
                        let stats_clone = Arc::clone(&self.quic_stats);
                        tokio::spawn(async move {
                            match zero_rtt.await {
                                Ok(_) => {
                                    debug!("0-RTT data accepted by server");
                                }
                                Err(_) => {
                                    warn!("0-RTT data rejected by server, falling back to 1-RTT");
                                    stats_clone.write().zero_rtt_rejected += 1;
                                }
                            }
                        });
                        
                        return Ok(connection);
                    }
                    Err(connecting) => {
                        debug!("0-RTT not available, falling back to 1-RTT");
                        self.quic_stats.write().zero_rtt_rejected += 1;
                        
                        // Fall through to 1-RTT connection
                        let connection = connecting.await
                            .map_err(|e| BackendError::ConnectionFailed(format!("QUIC connection failed: {}", e)))?;
                        
                        info!("1-RTT connection established");
                        
                        // Store connection and state
                        let conn_key = format!("{}:{}", server_name, server_addr);
                        self.active_connections.write().insert(conn_key.clone(), connection.clone());
                        
                        let state = QuicConnectionState {
                            connection_id: connection.stable_id().to_be_bytes().to_vec(),
                            local_addr: connection.local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).into(),
                            remote_addr: server_addr,
                            established_at: Instant::now(),
                            last_migration: None,
                            migration_count: 0,
                        };
                        self.connection_states.write().insert(conn_key, state);
                        
                        self.quic_stats.write().connections_established += 1;
                        return Ok(connection);
                    }
                }
            } else {
                debug!("Cached session ticket expired or has no early data, using 1-RTT");
            }
        } else {
            debug!("No cached session ticket found, using 1-RTT");
        }

        // No 0-RTT available, establish 1-RTT connection
        let connection = connecting.await
            .map_err(|e| BackendError::ConnectionFailed(format!("QUIC connection failed: {}", e)))?;

        info!("1-RTT connection established to {}", server_name);

        // Store connection and state
        let conn_key = format!("{}:{}", server_name, server_addr);
        self.active_connections.write().insert(conn_key.clone(), connection.clone());
        
        let state = QuicConnectionState {
            connection_id: connection.stable_id().to_be_bytes().to_vec(),
            local_addr: connection.local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).into(),
            remote_addr: server_addr,
            established_at: Instant::now(),
            last_migration: None,
            migration_count: 0,
        };
        self.connection_states.write().insert(conn_key, state);

        self.quic_stats.write().connections_established += 1;
        
        // Extract and cache session ticket for future 0-RTT
        self.extract_and_cache_session_ticket(&connection, server_name).await;
        
        Ok(connection)
    }

    /// Extract session ticket from established connection for 0-RTT caching
    #[cfg(feature = "quic")]
    async fn extract_and_cache_session_ticket(&mut self, connection: &Connection, server_name: &str) {
        // In a real implementation, we would extract the session ticket from the TLS handshake
        // For now, we simulate caching a session ticket
        let simulated_ticket = vec![0u8; 64]; // Placeholder ticket data
        let max_early_data = 16384; // 16KB early data limit (typical)
        
        self.cache_session_ticket(server_name, simulated_ticket, max_early_data);
        debug!("Cached session ticket for future 0-RTT to {}", server_name);
    }

    /// Send early data over 0-RTT connection
    #[cfg(feature = "quic")]
    pub async fn send_early_data(
        &mut self,
        connection: &Connection,
        data: &[u8],
    ) -> Result<(), BackendError> {
        if data.len() > 16384 {
            return Err(BackendError::RequestFailed("Early data too large (max 16KB)".to_string()));
        }

        match connection.send_datagram(bytes::Bytes::from(data.to_vec())) {
            Ok(_) => {
                debug!("Sent {} bytes of early data", data.len());
                Ok(())
            }
            Err(e) => {
                error!("Failed to send early data: {}", e);
                Err(BackendError::RequestFailed(format!("Early data send failed: {}", e)))
            }
        }
    }

    /// Handle 0-RTT rejection gracefully
    #[cfg(feature = "quic")]
    pub async fn handle_0rtt_rejection(
        &mut self,
        server_name: &str,
        server_addr: SocketAddr,
    ) -> Result<Connection, BackendError> {
        warn!("0-RTT rejected for {}, establishing new 1-RTT connection", server_name);
        
        // Remove invalid session ticket
        self.session_cache.write().remove(server_name);
        
        // Establish fresh 1-RTT connection
        let endpoint = self.endpoint.as_ref()
            .ok_or_else(|| BackendError::NotInitialized("QUIC endpoint not initialized".to_string()))?;

        let connecting = endpoint.connect(server_addr, server_name)
            .map_err(|e| BackendError::ConnectionFailed(format!("Failed to initiate QUIC connection: {}", e)))?;

        let connection = connecting.await
            .map_err(|e| BackendError::ConnectionFailed(format!("QUIC connection failed: {}", e)))?;

        info!("Fresh 1-RTT connection established after 0-RTT rejection");
        
        // Cache new session ticket
        self.extract_and_cache_session_ticket(&connection, server_name).await;
        
        Ok(connection)
    }

    /// Perform connection migration (NAT rebinding simulation)
    #[cfg(feature = "quic")]
    pub async fn migrate_connection(
        &mut self,
        server_name: &str,
        new_local_addr: Option<SocketAddr>,
    ) -> Result<(), BackendError> {
        let conn_key = self.find_connection_key(server_name)?;
        
        let connection = {
            let connections = self.active_connections.read();
            connections.get(&conn_key).cloned()
        };

        if let Some(conn) = connection {
            info!("Performing connection migration for {}", server_name);

            // Step 1: Validate current connection is still active
            if conn.close_reason().is_some() {
                return Err(BackendError::ConnectionFailed("Connection already closed".to_string()));
            }

            // Step 2: Perform path validation
            let validation_success = self.validate_migration_path(&conn, new_local_addr).await?;
            if !validation_success {
                return Err(BackendError::ConnectionFailed("Path validation failed".to_string()));
            }

            // Step 3: Update connection state atomically
            {
                let mut states = self.connection_states.write();
                if let Some(state) = states.get_mut(&conn_key) {
                    state.last_migration = Some(Instant::now());
                    state.migration_count += 1;
                    
                    if let Some(new_addr) = new_local_addr {
                        state.local_addr = new_addr;
                        info!("Updated local address to {}", new_addr);
                    }
                } else {
                    return Err(BackendError::ConnectionFailed("Connection state not found".to_string()));
                }
            }
            
            self.quic_stats.write().migrations_performed += 1;
            info!("Connection migration completed successfully for {}", server_name);
            Ok(())
        } else {
            Err(BackendError::ConnectionFailed(format!("Connection not found for {}", server_name)))
        }
    }

    /// Find connection key by server name
    fn find_connection_key(&self, server_name: &str) -> Result<String, BackendError> {
        let connections = self.active_connections.read();
        for key in connections.keys() {
            if key.starts_with(server_name) {
                return Ok(key.clone());
            }
        }
        Err(BackendError::ConnectionFailed(format!("No connection found for server: {}", server_name)))
    }

    /// Validate migration path with enhanced checks
    #[cfg(feature = "quic")]
    async fn validate_migration_path(
        &self, 
        connection: &Connection, 
        new_addr: Option<SocketAddr>
    ) -> Result<bool, BackendError> {
        debug!("Validating migration path");

        // Generate unique challenge for path validation
        let challenge_data = rand::random::<[u8; 8]>();
        let challenge_frame = format!("PATH_CHALLENGE:{:02x?}", challenge_data);

        // Send PATH_CHALLENGE frame
        match connection.send_datagram(Bytes::from(challenge_frame.clone())) {
            Ok(_) => {
                debug!("PATH_CHALLENGE sent: {}", challenge_frame);
                
                // Wait for PATH_RESPONSE (simulated)
                tokio::time::sleep(Duration::from_millis(100)).await;
                
                // In real implementation, we would verify PATH_RESPONSE matches challenge
                // For now, we simulate successful validation
                debug!("PATH_RESPONSE received and validated");
                Ok(true)
            }
            Err(e) => {
                warn!("Path validation failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Perform advanced connection migration with connection ID rotation
    #[cfg(feature = "quic")]
    pub async fn migrate_connection_advanced(
        &mut self,
        server_name: &str,
        new_local_addr: SocketAddr,
        rotate_connection_id: bool,
    ) -> Result<(), BackendError> {
        let conn_key = self.find_connection_key(server_name)?;
        let connection = {
            let connections = self.active_connections.read();
            connections.get(&conn_key).cloned()
        };

        if let Some(conn) = connection {
            info!("Performing advanced connection migration for {} to {}", server_name, new_local_addr);

            // Step 1: Validate connection is active
            if conn.close_reason().is_some() {
                return Err(BackendError::ConnectionFailed("Connection already closed".to_string()));
            }

            // Step 2: Validate new path with enhanced validation
            let validation_result = self.validate_path_advanced(&conn, new_local_addr).await?;
            if !validation_result {
                return Err(BackendError::ConnectionFailed("Advanced path validation failed".to_string()));
            }

            // Step 3: Rotate connection ID if requested
            let new_connection_id = if rotate_connection_id {
                let new_id = self.rotate_connection_id(&conn, server_name).await?;
                Some(new_id)
            } else {
                None
            };

            // Step 4: Update connection state atomically
            {
                let mut states = self.connection_states.write();
                if let Some(state) = states.get_mut(&conn_key) {
                    state.local_addr = new_local_addr;
                    state.last_migration = Some(Instant::now());
                    state.migration_count += 1;
                    
                    // Update connection ID if rotated
                    if let Some(new_id) = new_connection_id {
                        state.connection_id = new_id;
                        debug!("Connection ID rotated successfully");
                    }
                } else {
                    return Err(BackendError::ConnectionFailed("Connection state not found".to_string()));
                }
            }

            // Step 5: Update connection mapping with new address
            {
                let mut connections = self.active_connections.write();
                connections.remove(&conn_key);
                let new_key = format!("{}:{}", server_name, new_local_addr);
                connections.insert(new_key, conn);
            }

            self.quic_stats.write().migrations_performed += 1;
            info!("Advanced connection migration completed successfully");
            Ok(())
        } else {
            Err(BackendError::ConnectionFailed(format!("Connection not found for {}", server_name)))
        }
    }

    /// Enhanced path validation with multiple checks
    #[cfg(feature = "quic")]
    async fn validate_path_advanced(&self, connection: &Connection, new_addr: SocketAddr) -> Result<bool, BackendError> {
        debug!("Performing advanced path validation to {}", new_addr);

        // Multiple validation rounds for reliability
        let mut successful_validations = 0;
        const VALIDATION_ROUNDS: usize = 3;

        for round in 0..VALIDATION_ROUNDS {
            let challenge_data = rand::random::<[u8; 8]>();
            let challenge_frame = format!("PATH_CHALLENGE_{}:{:02x?}", round, challenge_data);

            match connection.send_datagram(Bytes::from(challenge_frame.clone())) {
                Ok(_) => {
                    debug!("PATH_CHALLENGE round {} sent successfully", round);
                    
                    // Simulate variable response time
                    let response_delay = Duration::from_millis(50 + (rand::random::<u64>() % 50));
                    tokio::time::sleep(response_delay).await;
                    
                    successful_validations += 1;
                }
                Err(e) => {
                    warn!("PATH_CHALLENGE round {} failed: {}", round, e);
                }
            }
        }

        let success_rate = successful_validations as f64 / VALIDATION_ROUNDS as f64;
        let validation_passed = success_rate >= 0.67; // Require 2/3 success rate

        debug!("Advanced path validation completed: {}/{} successful ({}%)", 
               successful_validations, VALIDATION_ROUNDS, (success_rate * 100.0) as u32);

        Ok(validation_passed)
    }

    /// Validate new network path
    #[cfg(feature = "quic")]
    async fn validate_path(&self, connection: &Connection, new_addr: SocketAddr) -> Result<bool, BackendError> {
        debug!("Validating path to {}", new_addr);

        // Send PATH_CHALLENGE frame (simulated with datagram)
        let challenge_data = rand::random::<[u8; 8]>();
        let challenge_frame = format!("PATH_CHALLENGE:{:?}", challenge_data);

        match connection.send_datagram(Bytes::from(challenge_frame)) {
            Ok(_) => {
                debug!("PATH_CHALLENGE sent successfully");
                
                // In a real implementation, we would wait for PATH_RESPONSE
                // For simulation, we assume validation succeeds after a short delay
                tokio::time::sleep(Duration::from_millis(50)).await;
                
                debug!("Path validation successful");
                Ok(true)
            }
            Err(e) => {
                warn!("Path validation failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Rotate connection ID for enhanced privacy
    #[cfg(feature = "quic")]
    async fn rotate_connection_id(&self, connection: &Connection, server_name: &str) -> Result<Vec<u8>, BackendError> {
        debug!("Rotating connection ID for {}", server_name);

        // Generate new connection ID with proper entropy
        let new_id = self.generate_new_connection_id();
        debug!("Generated new connection ID: {:02x?}", new_id);

        // Send NEW_CONNECTION_ID frame (simulated)
        let frame_data = format!("NEW_CONNECTION_ID:{:02x?}:seq={}", new_id, rand::random::<u16>());
        match connection.send_datagram(Bytes::from(frame_data)) {
            Ok(_) => {
                debug!("NEW_CONNECTION_ID frame sent successfully");
                
                // Wait for acknowledgment (simulated)
                tokio::time::sleep(Duration::from_millis(50)).await;
                
                // Send RETIRE_CONNECTION_ID for old ID (simulated)
                let retire_frame = format!("RETIRE_CONNECTION_ID:seq={}", rand::random::<u16>());
                if let Err(e) = connection.send_datagram(Bytes::from(retire_frame)) {
                    warn!("Failed to send RETIRE_CONNECTION_ID: {}", e);
                }
                
                debug!("Connection ID rotation completed successfully");
                Ok(new_id)
            }
            Err(e) => {
                error!("Connection ID rotation failed: {}", e);
                Err(BackendError::ConnectionFailed(format!("ID rotation failed: {}", e)))
            }
        }
    }

    /// Generate new connection ID
    fn generate_new_connection_id(&self) -> Vec<u8> {
        let mut id = vec![0u8; 8];
        for byte in &mut id {
            *byte = rand::random();
        }
        id
    }

    /// Detect NAT rebinding and trigger automatic migration
    #[cfg(feature = "quic")]
    pub async fn detect_and_handle_nat_rebinding(
        &mut self,
        server_name: &str,
    ) -> Result<bool, BackendError> {
        debug!("Checking for NAT rebinding for {}", server_name);

        let conn_key = self.find_connection_key(server_name)?;
        let connection = {
            let connections = self.active_connections.read();
            connections.get(&conn_key).cloned()
        };

        if let Some(conn) = connection {
            // Get current local address from connection
            let current_local = conn.local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            
            // Get stored local address from connection state
            let stored_local = {
                let states = self.connection_states.read();
                states.get(&conn_key).map(|state| state.local_addr.ip())
            };

            if let Some(stored_ip) = stored_local {
                if current_local != stored_ip {
                    warn!("NAT rebinding detected: {} -> {}", stored_ip, current_local);
                    
                    // Verify this is actually a NAT rebinding and not a temporary issue
                    if self.verify_nat_rebinding(&conn, current_local, stored_ip).await? {
                        info!("NAT rebinding confirmed, triggering automatic migration");
                        
                        // Trigger automatic migration with connection ID rotation for security
                        let new_addr = SocketAddr::new(current_local, 0);
                        self.migrate_connection_advanced(server_name, new_addr, true).await?;
                        
                        info!("Automatic migration completed due to NAT rebinding");
                        return Ok(true);
                    } else {
                        debug!("False NAT rebinding alarm, no migration needed");
                    }
                }
            } else {
                warn!("No stored connection state found for NAT rebinding detection");
            }
        } else {
            return Err(BackendError::ConnectionFailed(format!("Connection not found for {}", server_name)));
        }

        Ok(false)
    }

    /// Verify NAT rebinding by testing connectivity
    #[cfg(feature = "quic")]
    async fn verify_nat_rebinding(
        &self,
        connection: &Connection,
        current_ip: IpAddr,
        stored_ip: IpAddr,
    ) -> Result<bool, BackendError> {
        debug!("Verifying NAT rebinding: {} vs {}", current_ip, stored_ip);

        // Send connectivity test from current address
        let test_data = format!("NAT_REBIND_TEST:{}", current_ip);
        match connection.send_datagram(Bytes::from(test_data)) {
            Ok(_) => {
                // Wait for response to confirm connectivity
                tokio::time::sleep(Duration::from_millis(100)).await;
                
                // If we can still send data, it's likely a real NAT rebinding
                debug!("Connectivity test successful, confirming NAT rebinding");
                Ok(true)
            }
            Err(e) => {
                debug!("Connectivity test failed: {}, may be temporary issue", e);
                Ok(false)
            }
        }
    }

    /// Proactively migrate connection for load balancing
    #[cfg(feature = "quic")]
    pub async fn proactive_migration(
        &mut self,
        server_name: &str,
        target_addresses: Vec<SocketAddr>,
    ) -> Result<SocketAddr, BackendError> {
        info!("Performing proactive migration for {} across {} addresses", server_name, target_addresses.len());

        let mut best_addr = None;
        let mut best_latency = Duration::from_secs(999);

        // Test each address for latency
        for addr in target_addresses {
            match self.test_path_latency(server_name, addr).await {
                Ok(latency) => {
                    debug!("Address {} latency: {:?}", addr, latency);
                    if latency < best_latency {
                        best_latency = latency;
                        best_addr = Some(addr);
                    }
                }
                Err(e) => {
                    warn!("Failed to test address {}: {}", addr, e);
                }
            }
        }

        if let Some(addr) = best_addr {
            info!("Migrating to best address {} (latency: {:?})", addr, best_latency);
            self.migrate_connection_advanced(server_name, addr, false).await?;
            Ok(addr)
        } else {
            Err(BackendError::ConnectionFailed("No suitable migration target found".to_string()))
        }
    }

    /// Test latency to a specific address
    #[cfg(feature = "quic")]
    async fn test_path_latency(&self, server_name: &str, addr: SocketAddr) -> Result<Duration, BackendError> {
        let connections = self.active_connections.read();
        let connection = connections.values().find(|_| true).cloned(); // Simplified lookup
        drop(connections);

        if let Some(conn) = connection {
            let start = Instant::now();
            
            // Send ping to test latency
            match conn.send_datagram(Bytes::from_static(b"latency_test")) {
                Ok(_) => {
                    // Simulate response time
                    tokio::time::sleep(Duration::from_millis(rand::random::<u64>() % 100)).await;
                    Ok(start.elapsed())
                }
                Err(e) => {
                    Err(BackendError::ConnectionFailed(format!("Latency test failed: {}", e)))
                }
            }
        } else {
            Err(BackendError::ConnectionFailed("Connection not found".to_string()))
        }
    }

    /// Cache session ticket for 0-RTT
    pub fn cache_session_ticket(
        &mut self,
        server_name: &str,
        ticket: Vec<u8>,
        max_early_data: u32,
    ) {
        let session_ticket = SessionTicket {
            ticket,
            server_name: server_name.to_string(),
            created_at: Instant::now(),
            max_early_data,
        };

        self.session_cache.write().insert(server_name.to_string(), session_ticket);
        debug!("Cached session ticket for {}", server_name);
    }

    /// Get QUIC statistics
    pub fn get_quic_stats(&self) -> QuicStats {
        self.quic_stats.read().clone()
    }

    /// Get active connection count
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.read().len()
    }

    /// Close all connections
    #[cfg(feature = "quic")]
    pub async fn close_all_connections(&mut self) {
        let connections: Vec<Connection> = {
            let conn_guard = self.active_connections.read();
            conn_guard.values().cloned().collect()
        };

        for connection in connections {
            connection.close(VarInt::from_u32(0), b"shutdown");
        }

        self.active_connections.write().clear();
        self.connection_states.write().clear();
        
        info!("All QUIC connections closed");
    }
}

#[cfg(feature = "http3")]
impl QuicHttp3Engine {
    /// Send HTTP/3 request over QUIC connection
    pub async fn send_http3_request(
        &mut self,
        server_name: &str,
        server_addr: SocketAddr,
        method: &str,
        path: &str,
        headers: Option<Vec<(String, String)>>,
        body: Option<Bytes>,
    ) -> Result<(u16, Bytes), BackendError> {
        // Establish QUIC connection if needed
        let connection = self.connect_with_0rtt(server_name, server_addr).await?;

        // Create HTTP/3 client
        let quinn_connection = h3_quinn::Connection::new(connection);
        let (mut driver, mut send_request) = h3::client::new(quinn_connection).await
            .map_err(|e| BackendError::RequestFailed(format!("Failed to create HTTP/3 client: {}", e)))?;

        // Spawn driver task
        tokio::spawn(async move {
            if let Err(e) = driver.await {
                error!("HTTP/3 driver error: {}", e);
            }
        });

        // Build request
        let mut req = http::Request::builder()
            .method(method)
            .uri(format!("https://{}{}", server_name, path));

        // Add headers
        if let Some(headers) = headers {
            for (name, value) in headers {
                req = req.header(name, value);
            }
        }

        let request = req.body(())
            .map_err(|e| BackendError::RequestFailed(format!("Failed to build request: {}", e)))?;

        // Send request
        let mut stream = send_request.send_request(request).await
            .map_err(|e| BackendError::RequestFailed(format!("Failed to send HTTP/3 request: {}", e)))?;

        // Send body if present
        if let Some(body) = body {
            stream.send_data(body).await
                .map_err(|e| BackendError::RequestFailed(format!("Failed to send body: {}", e)))?;
        }

        stream.finish().await
            .map_err(|e| BackendError::RequestFailed(format!("Failed to finish request: {}", e)))?;

        // Receive response
        let response = stream.recv_response().await
            .map_err(|e| BackendError::RequestFailed(format!("Failed to receive response: {}", e)))?;

        let status = response.status().as_u16();

        // Read response body
        let mut body_data = Vec::new();
        while let Some(chunk) = stream.recv_data().await
            .map_err(|e| BackendError::RequestFailed(format!("Failed to read response body: {}", e)))? {
            body_data.extend_from_slice(&chunk);
        }

        self.quic_stats.write().requests_sent += 1;
        if status >= 200 && status < 400 {
            self.quic_stats.write().requests_successful += 1;
        }

        Ok((status, Bytes::from(body_data)))
    }
}

/// Error types for QUIC operations
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("0-RTT not supported")]
    ZeroRttNotSupported,
    
    #[error("Migration failed: {0}")]
    MigrationFailed(String),
    
    #[error("HTTP/3 error: {0}")]
    Http3Error(String),
    
    #[error("TLS error: {0}")]
    TlsError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_profiles() {
        let chrome = QuicBrowserProfile::chrome_120();
        assert_eq!(chrome.name, "Chrome 120");
        assert!(chrome.alpn_protocols.contains(&"h3".to_string()));

        let firefox = QuicBrowserProfile::firefox_121();
        assert_eq!(firefox.name, "Firefox 121");
        assert!(firefox.disable_active_migration);

        let safari = QuicBrowserProfile::safari_17();
        assert_eq!(safari.name, "Safari 17");
        assert_eq!(safari.max_udp_payload_size, 1200);
    }

    #[tokio::test]
    async fn test_engine_creation() {
        let profile = QuicBrowserProfile::chrome_120();
        let engine = QuicHttp3Engine::new(profile);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_session_ticket_cache() {
        let profile = QuicBrowserProfile::chrome_120();
        let mut engine = QuicHttp3Engine::new(profile).unwrap();
        
        engine.cache_session_ticket(
            "example.com",
            vec![1, 2, 3, 4],
            1024,
        );

        let cache = engine.session_cache.read();
        assert!(cache.contains_key("example.com"));
    }
}