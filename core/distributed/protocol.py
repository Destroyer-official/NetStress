"""
Distributed Communication Protocol

Defines the message protocol for controller-agent communication.
Uses JSON over TCP with optional encryption.
"""

import json
import hashlib
import hmac
import time
import struct
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of control messages"""
    # Agent registration
    REGISTER = "register"
    REGISTER_ACK = "register_ack"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    
    # Attack control
    START_ATTACK = "start_attack"
    STOP_ATTACK = "stop_attack"
    PAUSE_ATTACK = "pause_attack"
    RESUME_ATTACK = "resume_attack"
    UPDATE_CONFIG = "update_config"
    
    # Status and reporting
    STATUS_REQUEST = "status_request"
    STATUS_REPORT = "status_report"
    STATS_REPORT = "stats_report"
    ERROR_REPORT = "error_report"
    
    # Coordination
    SYNC_TIME = "sync_time"
    SYNC_ACK = "sync_ack"
    READY_CHECK = "ready_check"
    READY_ACK = "ready_ack"
    
    # Shutdown
    SHUTDOWN = "shutdown"
    SHUTDOWN_ACK = "shutdown_ack"


class AgentStatus(Enum):
    """Agent status states"""
    OFFLINE = "offline"
    CONNECTING = "connecting"
    IDLE = "idle"
    READY = "ready"
    ATTACKING = "attacking"
    PAUSED = "paused"
    ERROR = "error"
    SHUTTING_DOWN = "shutting_down"


@dataclass
class AgentInfo:
    """Information about a connected agent"""
    agent_id: str
    hostname: str
    ip_address: str
    port: int
    status: AgentStatus = AgentStatus.OFFLINE
    capabilities: Dict[str, Any] = field(default_factory=dict)
    last_heartbeat: float = 0.0
    registered_at: float = 0.0
    current_stats: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        d = asdict(self)
        d['status'] = self.status.value
        return d
    
    @classmethod
    def from_dict(cls, d: dict) -> 'AgentInfo':
        d['status'] = AgentStatus(d['status'])
        return cls(**d)


@dataclass
class AttackConfig:
    """Configuration for a distributed attack"""
    target: str
    port: int
    protocol: str
    duration: int = 60
    threads: int = 4
    packet_size: int = 1472
    rate_limit: int = 0  # 0 = unlimited
    
    # Evasion settings
    use_evasion: bool = False
    shaping_profile: str = "aggressive"
    obfuscation_method: str = "none"
    timing_pattern: str = "constant"
    
    # Pulse synchronization settings (Requirement 6.3)
    pulse_mode: str = "continuous"  # "continuous" or "pulse"
    pulse_interval_ms: int = 1000   # Pulse interval in milliseconds (10ms, 100ms, 1s)
    pulse_duration_ms: int = 100    # Duration of each pulse burst
    pulse_intensity: float = 1.0    # Pulse intensity (0.0 - 1.0)
    pulse_jitter_ms: int = 0        # Random jitter to add to timing
    
    # Coordination
    start_time: float = 0.0  # Unix timestamp, 0 = immediate
    sync_start: bool = True  # Wait for all agents ready
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: dict) -> 'AttackConfig':
        return cls(**d)
    
    def validate_pulse_config(self) -> None:
        """Validate pulse configuration parameters"""
        if self.pulse_mode not in ["continuous", "pulse"]:
            raise ValueError(f"Invalid pulse mode: {self.pulse_mode}. Must be 'continuous' or 'pulse'")
        
        if self.pulse_interval_ms < 10:
            raise ValueError(f"Pulse interval {self.pulse_interval_ms}ms too small. Minimum is 10ms")
        
        if self.pulse_duration_ms < 1:
            raise ValueError(f"Pulse duration {self.pulse_duration_ms}ms too small. Minimum is 1ms")
        
        if self.pulse_duration_ms > self.pulse_interval_ms:
            raise ValueError(f"Pulse duration {self.pulse_duration_ms}ms cannot exceed interval {self.pulse_interval_ms}ms")
        
        if not 0.0 <= self.pulse_intensity <= 1.0:
            raise ValueError(f"Pulse intensity {self.pulse_intensity} must be between 0.0 and 1.0")
        
        if self.pulse_jitter_ms < 0:
            raise ValueError(f"Pulse jitter {self.pulse_jitter_ms}ms cannot be negative")
    
    def get_supported_pulse_intervals(self) -> List[int]:
        """Get list of supported pulse intervals in milliseconds"""
        return [10, 100, 1000]  # 10ms, 100ms, 1s as per requirements
    
    def is_pulse_interval_supported(self) -> bool:
        """Check if the configured pulse interval is one of the standard supported values"""
        return self.pulse_interval_ms in self.get_supported_pulse_intervals()


@dataclass
class ControlMessage:
    """Control message for distributed communication"""
    msg_type: MessageType
    sender_id: str
    timestamp: float = field(default_factory=time.time)
    sequence: int = 0
    payload: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    
    def to_bytes(self, secret_key: Optional[bytes] = None) -> bytes:
        """Serialize message to bytes"""
        data = {
            'type': self.msg_type.value,
            'sender': self.sender_id,
            'timestamp': self.timestamp,
            'sequence': self.sequence,
            'payload': self.payload,
        }
        
        json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
        
        # Add HMAC signature if key provided
        if secret_key:
            sig = hmac.new(secret_key, json_data, hashlib.sha256).hexdigest()
            data['signature'] = sig
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
        
        # Length-prefixed message
        length = len(json_data)
        return struct.pack('>I', length) + json_data
    
    @classmethod
    def from_bytes(cls, data: bytes, secret_key: Optional[bytes] = None) -> 'ControlMessage':
        """Deserialize message from bytes"""
        # Skip length prefix if present
        if len(data) > 4:
            length = struct.unpack('>I', data[:4])[0]
            if length == len(data) - 4:
                data = data[4:]
        
        parsed = json.loads(data.decode('utf-8'))
        
        # Verify signature if key provided
        if secret_key and 'signature' in parsed:
            received_sig = parsed.pop('signature')
            json_data = json.dumps(parsed, separators=(',', ':')).encode('utf-8')
            expected_sig = hmac.new(secret_key, json_data, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(received_sig, expected_sig):
                raise ValueError("Invalid message signature")
        
        return cls(
            msg_type=MessageType(parsed['type']),
            sender_id=parsed['sender'],
            timestamp=parsed['timestamp'],
            sequence=parsed['sequence'],
            payload=parsed.get('payload', {}),
            signature=parsed.get('signature', ''),
        )
    
    def to_dict(self) -> dict:
        return {
            'type': self.msg_type.value,
            'sender': self.sender_id,
            'timestamp': self.timestamp,
            'sequence': self.sequence,
            'payload': self.payload,
        }


class MessageBuilder:
    """Helper class to build control messages"""
    
    def __init__(self, sender_id: str):
        self.sender_id = sender_id
        self._sequence = 0
        
    def _next_seq(self) -> int:
        self._sequence += 1
        return self._sequence
    
    def register(self, hostname: str, capabilities: Dict[str, Any]) -> ControlMessage:
        """Build registration message"""
        return ControlMessage(
            msg_type=MessageType.REGISTER,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            payload={
                'hostname': hostname,
                'capabilities': capabilities,
            }
        )
    
    def heartbeat(self, status: AgentStatus, stats: Dict[str, Any] = None) -> ControlMessage:
        """Build heartbeat message"""
        return ControlMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            payload={
                'status': status.value,
                'stats': stats or {},
            }
        )
    
    def start_attack(self, config: AttackConfig) -> ControlMessage:
        """Build start attack message"""
        return ControlMessage(
            msg_type=MessageType.START_ATTACK,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            payload={'config': config.to_dict()}
        )
    
    def stop_attack(self) -> ControlMessage:
        """Build stop attack message"""
        return ControlMessage(
            msg_type=MessageType.STOP_ATTACK,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
        )
    
    def status_report(self, status: AgentStatus, stats: Dict[str, Any],
                     error: str = None) -> ControlMessage:
        """Build status report message"""
        payload = {
            'status': status.value,
            'stats': stats,
        }
        if error:
            payload['error'] = error
            
        return ControlMessage(
            msg_type=MessageType.STATUS_REPORT,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            payload=payload
        )
    
    def ready_ack(self, ready: bool) -> ControlMessage:
        """Build ready acknowledgment"""
        return ControlMessage(
            msg_type=MessageType.READY_ACK,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            payload={'ready': ready}
        )
    
    def error_report(self, error: str, details: Dict[str, Any] = None) -> ControlMessage:
        """Build error report message"""
        return ControlMessage(
            msg_type=MessageType.ERROR_REPORT,
            sender_id=self.sender_id,
            sequence=self._next_seq(),
            payload={
                'error': error,
                'details': details or {},
            }
        )
