#!/usr/bin/env python3
"""
Communication Hub - Inter-component communication system
Manages message passing, event distribution, and component coordination
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass
from enum import Enum
import threading
import time
import json
from collections import defaultdict, deque
import uuid

logger = logging.getLogger(__name__)

class MessageType(Enum):
    COMMAND = "command"
    EVENT = "event"
    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"

@dataclass
class Message:
    id: str
    type: MessageType
    source: str
    target: str
    channel: str
    data: Any
    timestamp: float
    correlation_id: Optional[str] = None

@dataclass
class Channel:
    name: str
    source: str
    target: str
    message_queue: asyncio.Queue
    subscribers: Set[str]
    message_history: deque
    created_at: float

class CommunicationHub:
    """Central hub for inter-component communication"""
    
    def __init__(self, max_queue_size: int = 1000, max_history: int = 100):
        self.channels: Dict[str, Channel] = {}
        self.subscribers: Dict[str, Set[str]] = defaultdict(set)
        self.message_handlers: Dict[str, Dict[str, Callable]] = defaultdict(dict)
        self.pending_requests: Dict[str, asyncio.Future] = {}
        
        self.max_queue_size = max_queue_size
        self.max_history = max_history
        self.lock = threading.RLock()
        self.running = False
        
        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'channels_created': 0,
            'failed_deliveries': 0
        }
        
        logger.info("Communication Hub initialized")
    
    async def initialize(self):
        """Initialize the communication hub"""
        try:
            self.running = True
            
            # Start message processing tasks
            asyncio.create_task(self._process_messages())
            asyncio.create_task(self._cleanup_expired_requests())
            
            logger.info("Communication Hub initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Communication Hub: {e}")
            raise
    
    async def create_channel(self, source: str, target: str, channel_name: str) -> bool:
        """Create a communication channel between components"""
        try:
            with self.lock:
                full_channel_name = f"{source}->{target}:{channel_name}"
                
                if full_channel_name in self.channels:
                    logger.warning(f"Channel {full_channel_name} already exists")
                    return True
                
                channel = Channel(
                    name=full_channel_name,
                    source=source,
                    target=target,
                    message_queue=asyncio.Queue(maxsize=self.max_queue_size),
                    subscribers=set(),
                    message_history=deque(maxlen=self.max_history),
                    created_at=time.time()
                )
                
                self.channels[full_channel_name] = channel
                self.stats['channels_created'] += 1
                
                logger.info(f"Created channel: {full_channel_name}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to create channel {source}->{target}:{channel_name}: {e}")
            return False
    
    async def send_message(self, source: str, target: str, channel: str, 
                          message_type: MessageType, data: Any, 
                          correlation_id: Optional[str] = None) -> str:
        """Send a message through a channel"""
        try:
            message_id = str(uuid.uuid4())
            full_channel_name = f"{source}->{target}:{channel}"
            
            if full_channel_name not in self.channels:
                # Try to create the channel automatically
                await self.create_channel(source, target, channel)
            
            message = Message(
                id=message_id,
                type=message_type,
                source=source,
                target=target,
                channel=channel,
                data=data,
                timestamp=time.time(),
                correlation_id=correlation_id
            )
            
            channel_obj = self.channels[full_channel_name]
            
            # Add to queue
            try:
                await channel_obj.message_queue.put(message)
                channel_obj.message_history.append(message)
                self.stats['messages_sent'] += 1
                
                logger.debug(f"Message sent: {source} -> {target} on {channel}")
                return message_id
                
            except asyncio.QueueFull:
                logger.error(f"Channel {full_channel_name} queue is full")
                self.stats['failed_deliveries'] += 1
                raise
                
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.stats['failed_deliveries'] += 1
            raise
    
    async def send_request(self, source: str, target: str, channel: str, 
                          data: Any, timeout: float = 30.0) -> Any:
        """Send a request and wait for response"""
        correlation_id = str(uuid.uuid4())
        
        # Create future for response
        response_future = asyncio.Future()
        self.pending_requests[correlation_id] = response_future
        
        try:
            # Send request
            await self.send_message(
                source, target, channel, MessageType.REQUEST, 
                data, correlation_id
            )
            
            # Wait for response
            response = await asyncio.wait_for(response_future, timeout=timeout)
            return response
            
        except asyncio.TimeoutError:
            logger.error(f"Request timeout: {source} -> {target} on {channel}")
            raise
        finally:
            # Clean up
            self.pending_requests.pop(correlation_id, None)
    
    async def send_response(self, source: str, target: str, channel: str, 
                           data: Any, correlation_id: str):
        """Send a response to a request"""
        await self.send_message(
            source, target, channel, MessageType.RESPONSE, 
            data, correlation_id
        )
    
    async def broadcast(self, source: str, channel: str, data: Any):
        """Broadcast a message to all subscribers"""
        try:
            message_id = str(uuid.uuid4())
            
            message = Message(
                id=message_id,
                type=MessageType.BROADCAST,
                source=source,
                target="*",
                channel=channel,
                data=data,
                timestamp=time.time()
            )
            
            # Send to all subscribers
            subscribers = self.subscribers.get(channel, set())
            for subscriber in subscribers:
                try:
                    await self._deliver_message(subscriber, message)
                except Exception as e:
                    logger.error(f"Failed to deliver broadcast to {subscriber}: {e}")
            
            logger.debug(f"Broadcast sent from {source} on {channel} to {len(subscribers)} subscribers")
            
        except Exception as e:
            logger.error(f"Failed to broadcast message: {e}")
    
    def subscribe(self, component: str, channel: str, handler: Callable):
        """Subscribe to a channel"""
        with self.lock:
            self.subscribers[channel].add(component)
            self.message_handlers[component][channel] = handler
            
            logger.info(f"Component {component} subscribed to channel {channel}")
    
    def unsubscribe(self, component: str, channel: str):
        """Unsubscribe from a channel"""
        with self.lock:
            self.subscribers[channel].discard(component)
            self.message_handlers[component].pop(channel, None)
            
            logger.info(f"Component {component} unsubscribed from channel {channel}")
    
    async def _process_messages(self):
        """Process messages from all channels"""
        while self.running:
            try:
                # Process messages from all channels
                for channel_name, channel in list(self.channels.items()):
                    try:
                        # Process up to 10 messages per channel per iteration
                        for _ in range(10):
                            try:
                                message = channel.message_queue.get_nowait()
                                await self._deliver_message(channel.target, message)
                                self.stats['messages_received'] += 1
                            except asyncio.QueueEmpty:
                                break
                    except Exception as e:
                        logger.error(f"Error processing messages for channel {channel_name}: {e}")
                
                await asyncio.sleep(0.01)  # Small delay to prevent busy waiting
                
            except Exception as e:
                logger.error(f"Message processing error: {e}")
                await asyncio.sleep(1)
    
    async def _deliver_message(self, target: str, message: Message):
        """Deliver a message to a target component"""
        try:
            # Handle responses
            if message.type == MessageType.RESPONSE and message.correlation_id:
                if message.correlation_id in self.pending_requests:
                    future = self.pending_requests[message.correlation_id]
                    if not future.done():
                        future.set_result(message.data)
                    return
            
            # Handle regular messages
            if target in self.message_handlers:
                handler = self.message_handlers[target].get(message.channel)
                if handler:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(message)
                    else:
                        handler(message)
                else:
                    logger.warning(f"No handler for channel {message.channel} in component {target}")
            else:
                logger.warning(f"No message handlers registered for component {target}")
                
        except Exception as e:
            logger.error(f"Failed to deliver message to {target}: {e}")
            self.stats['failed_deliveries'] += 1
    
    async def _cleanup_expired_requests(self):
        """Clean up expired request futures"""
        while self.running:
            try:
                current_time = time.time()
                expired_requests = []
                
                for correlation_id, future in self.pending_requests.items():
                    if future.done() or (current_time - future._created_time > 60):  # 60 second timeout
                        expired_requests.append(correlation_id)
                
                for correlation_id in expired_requests:
                    future = self.pending_requests.pop(correlation_id, None)
                    if future and not future.done():
                        future.set_exception(asyncio.TimeoutError("Request expired"))
                
                await asyncio.sleep(10)  # Clean up every 10 seconds
                
            except Exception as e:
                logger.error(f"Request cleanup error: {e}")
                await asyncio.sleep(10)
    
    async def test_channel(self, channel_name: str) -> bool:
        """Test if a channel is working properly"""
        try:
            if channel_name not in self.channels:
                return False
            
            channel = self.channels[channel_name]
            
            # Test message sending
            test_message = Message(
                id="test",
                type=MessageType.EVENT,
                source="test",
                target=channel.target,
                channel=channel.name.split(':')[-1],
                data={"test": True},
                timestamp=time.time()
            )
            
            # Try to put and get a test message
            await channel.message_queue.put(test_message)
            retrieved_message = await channel.message_queue.get()
            
            return retrieved_message.id == "test"
            
        except Exception as e:
            logger.error(f"Channel test failed for {channel_name}: {e}")
            return False
    
    async def test_all_channels(self) -> Dict[str, bool]:
        """Test all channels"""
        results = {}
        for channel_name in self.channels:
            results[channel_name] = await self.test_channel(channel_name)
        return results
    
    def get_channel_status(self, channel_name: str) -> Dict[str, Any]:
        """Get status of a specific channel"""
        if channel_name not in self.channels:
            return {'error': 'Channel not found'}
        
        channel = self.channels[channel_name]
        
        return {
            'name': channel.name,
            'source': channel.source,
            'target': channel.target,
            'queue_size': channel.message_queue.qsize(),
            'max_queue_size': self.max_queue_size,
            'subscribers': len(channel.subscribers),
            'message_history_count': len(channel.message_history),
            'created_at': channel.created_at,
            'uptime': time.time() - channel.created_at
        }
    
    def get_all_channel_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all channels"""
        return {name: self.get_channel_status(name) for name in self.channels}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get communication hub statistics"""
        return {
            **self.stats,
            'active_channels': len(self.channels),
            'total_subscribers': sum(len(subs) for subs in self.subscribers.values()),
            'pending_requests': len(self.pending_requests)
        }
    
    async def start(self):
        """Start the communication hub"""
        if not self.running:
            await self.initialize()
    
    async def stop(self):
        """Stop the communication hub"""
        logger.info("Stopping Communication Hub...")
        self.running = False
        
        # Cancel all pending requests
        for future in self.pending_requests.values():
            if not future.done():
                future.set_exception(asyncio.CancelledError("Communication hub stopped"))
        
        self.pending_requests.clear()
        
        # Clear all channels
        for channel in self.channels.values():
            while not channel.message_queue.empty():
                try:
                    channel.message_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
        
        logger.info("Communication Hub stopped")