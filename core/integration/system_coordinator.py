#!/usr/bin/env python3
"""
System Coordinator - Central orchestration for all framework components
Integrates all major subsystems and manages inter-component communication
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor

from .component_manager import ComponentManager
from .configuration_manager import ConfigurationManager
from .communication_hub import CommunicationHub

logger = logging.getLogger(__name__)

class SystemState(Enum):
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"

@dataclass
class SystemStatus:
    state: SystemState
    components_loaded: int
    components_active: int
    uptime: float
    last_error: Optional[str] = None
    performance_metrics: Dict[str, Any] = None

class SystemCoordinator:
    """Central coordinator for all framework components"""
    
    def __init__(self):
        self.state = SystemState.INITIALIZING
        self.component_manager = ComponentManager()
        self.config_manager = ConfigurationManager()
        self.communication_hub = CommunicationHub()
        
        self.start_time = time.time()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.shutdown_event = threading.Event()
        
        # Component registry
        self.components = {}
        self.component_dependencies = {}
        
        # Event handlers
        self.event_handlers = {}
        
        logger.info("System Coordinator initialized")
    
    async def initialize_system(self) -> bool:
        """Initialize all framework components in correct order"""
        try:
            logger.info("Starting system initialization...")
            
            # Load configuration
            await self.config_manager.load_configuration()
            
            # Initialize communication hub
            await self.communication_hub.initialize()
            
            # Register core components
            await self._register_core_components()
            
            # Initialize components in dependency order
            await self.component_manager.initialize_all_components()
            
            # Start inter-component communication
            await self._setup_component_communication()
            
            # Verify system integrity
            if await self._verify_system_integrity():
                self.state = SystemState.READY
                logger.info("System initialization completed successfully")
                return True
            else:
                self.state = SystemState.ERROR
                logger.error("System integrity verification failed")
                return False
                
        except Exception as e:
            self.state = SystemState.ERROR
            logger.error(f"System initialization failed: {e}")
            return False
    
    async def _register_core_components(self):
        """Register all core framework components"""
        components_to_register = [
            # Platform layer
            ('platform_detector', 'core.platform.detection', 'PlatformDetector'),
            ('platform_abstraction', 'core.platform.abstraction', 'PlatformAbstraction'),
            
            # Networking layer
            ('socket_factory', 'core.networking.socket_factory', 'SocketFactory'),
            ('tcp_engine', 'core.networking.tcp_engine', 'TCPEngine'),
            ('udp_engine', 'core.networking.udp_engine', 'ExtremeUDPEngine'),
            ('http_engine', 'core.networking.http_engine', 'ModernHTTPEngine'),
            ('dns_engine', 'core.networking.dns_engine', 'DNSWeaponizationEngine'),
            ('multi_vector_coordinator', 'core.networking.multi_vector_coordinator', 'MultiVectorAttackCoordinator'),
            
            # Memory management
            ('memory_manager', 'core.memory.pool_manager', 'MemoryPoolManager'),
            ('buffer_manager', 'core.networking.buffer_manager', 'ZeroCopyBufferManager'),
            
            # Alias for backward compatibility
            # Note: BufferManager is now ZeroCopyBufferManager
            
            # Performance layer
            ('performance_optimizer', 'core.performance.hardware_acceleration', 'HardwareAccelerator'),
            ('zero_copy_manager', 'core.performance.zero_copy', 'ZeroCopyEngine'),
            
            # AI and autonomous systems
            ('ai_orchestrator', 'core.ai.ai_orchestrator', 'AIOrchestrator'),
            ('optimization_engine', 'core.autonomous.optimization_engine', 'ParameterOptimizer'),
            ('resource_manager', 'core.autonomous.resource_manager', 'IntelligentResourceManager'),
            
            # Target intelligence
            ('target_resolver', 'core.target.resolver', 'TargetResolver'),
            ('target_profiler', 'core.target.profiler', 'TargetProfiler'),
            
            # Analytics and monitoring
            ('metrics_collector', 'core.analytics.metrics_collector', 'RealTimeMetricsCollector'),
            ('performance_tracker', 'core.analytics.performance_tracker', 'MultiDimensionalPerformanceTracker'),
            ('visualization_engine', 'core.analytics.visualization_engine', 'AdvancedVisualizationEngine'),
            
            # Safety systems
            ('safety_manager', 'core.safety.protection_mechanisms', 'SafetyManager'),
            ('audit_logger', 'core.safety.audit_logging', 'AuditLogger'),
            ('emergency_shutdown', 'core.safety.emergency_shutdown', 'EmergencyShutdown'),
            
            # User interfaces
            ('cli_interface', 'core.interfaces.cli', 'AdvancedCLI'),
            ('web_gui', 'core.interfaces.web_gui', 'WebGUI'),
            ('api_server', 'core.interfaces.api', 'RESTAPIServer'),
        ]
        
        for component_name, module_path, class_name in components_to_register:
            await self.component_manager.register_component(
                component_name, module_path, class_name
            )
        
        # Set up component dependencies
        self._setup_component_dependencies()
    
    def _setup_component_dependencies(self):
        """Define component initialization order based on dependencies"""
        self.component_dependencies = {
            'platform_detector': [],
            'platform_abstraction': ['platform_detector'],
            'memory_manager': ['platform_abstraction'],
            'buffer_manager': ['memory_manager'],
            'socket_factory': ['platform_abstraction', 'buffer_manager'],
            'tcp_engine': ['socket_factory'],
            'udp_engine': ['socket_factory'],
            'http_engine': ['socket_factory'],
            'dns_engine': ['socket_factory'],
            'performance_optimizer': ['platform_abstraction', 'memory_manager'],
            'zero_copy_manager': ['performance_optimizer', 'buffer_manager'],
            'target_resolver': ['dns_engine'],
            'target_profiler': ['target_resolver'],
            'ai_orchestrator': ['target_profiler'],
            'optimization_engine': ['ai_orchestrator'],
            'resource_manager': ['performance_optimizer'],
            'multi_vector_coordinator': ['tcp_engine', 'udp_engine', 'http_engine', 'dns_engine'],
            'metrics_collector': ['multi_vector_coordinator'],
            'performance_tracker': ['metrics_collector'],
            'visualization_engine': ['performance_tracker'],
            'safety_manager': ['target_resolver'],
            'audit_logger': ['safety_manager'],
            'emergency_shutdown': ['safety_manager'],
            'cli_interface': ['multi_vector_coordinator', 'safety_manager'],
            'web_gui': ['visualization_engine', 'safety_manager'],
            'api_server': ['multi_vector_coordinator', 'safety_manager'],
        }
        
        self.component_manager.set_dependencies(self.component_dependencies)
    
    async def _setup_component_communication(self):
        """Setup inter-component communication channels"""
        # Register communication channels between components
        channels = [
            ('target_resolver', 'target_profiler', 'target_info'),
            ('target_profiler', 'ai_orchestrator', 'profile_data'),
            ('ai_orchestrator', 'optimization_engine', 'optimization_requests'),
            ('optimization_engine', 'multi_vector_coordinator', 'attack_parameters'),
            ('multi_vector_coordinator', 'metrics_collector', 'attack_metrics'),
            ('metrics_collector', 'performance_tracker', 'performance_data'),
            ('performance_tracker', 'visualization_engine', 'visualization_data'),
            ('safety_manager', 'emergency_shutdown', 'safety_alerts'),
            ('emergency_shutdown', 'multi_vector_coordinator', 'shutdown_commands'),
        ]
        
        for source, target, channel_name in channels:
            await self.communication_hub.create_channel(source, target, channel_name)
    
    async def _verify_system_integrity(self) -> bool:
        """Verify all components are properly initialized and communicating"""
        # Optional components that can fail without breaking the system
        optional_components = {
            'cli_interface', 'web_gui', 'api_server', 
            'visualization_engine', 'performance_tracker',
            'ai_orchestrator', 'optimization_engine'
        }
        
        # Core components that must be initialized
        core_components = {
            'platform_detector', 'platform_abstraction', 
            'socket_factory', 'tcp_engine', 'udp_engine',
            'safety_manager', 'emergency_shutdown'
        }
        
        try:
            # Check component status
            component_status = await self.component_manager.get_all_component_status()
            failed_components = [name for name, status in component_status.items() 
                               if not status.get('initialized', False)]
            
            # Check if any core components failed
            failed_core = [c for c in failed_components if c in core_components]
            failed_optional = [c for c in failed_components if c in optional_components]
            
            if failed_core:
                logger.error(f"Failed to initialize core components: {failed_core}")
                return False
            
            if failed_optional:
                logger.warning(f"Optional components not initialized (non-critical): {failed_optional}")
            
            if failed_components and not failed_core:
                # Only optional components failed, log but continue
                other_failed = [c for c in failed_components if c not in optional_components and c not in core_components]
                if other_failed:
                    logger.warning(f"Some components failed to initialize: {other_failed}")
            
            # Test inter-component communication (skip if components not available)
            try:
                test_results = await self.communication_hub.test_all_channels()
                failed_channels = [name for name, result in test_results.items() if not result]
                
                if failed_channels:
                    logger.warning(f"Some communication channels not available: {failed_channels}")
            except Exception as comm_error:
                logger.warning(f"Communication test skipped: {comm_error}")
            
            logger.info("System integrity verification passed")
            return True
            
        except Exception as e:
            logger.error(f"System integrity verification error: {e}")
            return False
    
    async def start_system(self) -> bool:
        """Start the complete system"""
        if self.state != SystemState.READY:
            logger.error("System not ready for startup")
            return False
        
        try:
            self.state = SystemState.RUNNING
            
            # Start all components
            await self.component_manager.start_all_components()
            
            # Start communication hub
            await self.communication_hub.start()
            
            # Start system monitoring
            asyncio.create_task(self._system_monitor())
            
            logger.info("System started successfully")
            return True
            
        except Exception as e:
            self.state = SystemState.ERROR
            logger.error(f"System startup failed: {e}")
            return False
    
    async def stop_system(self):
        """Gracefully stop the entire system"""
        logger.info("Initiating system shutdown...")
        self.state = SystemState.STOPPING
        
        try:
            # Signal shutdown
            self.shutdown_event.set()
            
            # Stop communication hub
            await self.communication_hub.stop()
            
            # Stop all components in reverse dependency order
            await self.component_manager.stop_all_components()
            
            # Shutdown executor
            self.executor.shutdown(wait=True)
            
            self.state = SystemState.STOPPED
            logger.info("System shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during system shutdown: {e}")
            self.state = SystemState.ERROR
    
    async def _system_monitor(self):
        """Monitor system health and performance"""
        while not self.shutdown_event.is_set():
            try:
                # Collect system metrics
                status = await self.get_system_status()
                
                # Check for component failures
                failed_components = await self.component_manager.get_failed_components()
                if failed_components:
                    logger.warning(f"Component failures detected: {failed_components}")
                    # Attempt to restart failed components
                    for component in failed_components:
                        await self.component_manager.restart_component(component)
                
                # Monitor resource usage
                await self._monitor_resources()
                
                await asyncio.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                logger.error(f"System monitor error: {e}")
                await asyncio.sleep(10)
    
    async def _monitor_resources(self):
        """Monitor system resource usage"""
        try:
            resource_manager = self.component_manager.get_component('resource_manager')
            if resource_manager:
                usage = await resource_manager.get_resource_usage()
                
                # Check for resource exhaustion
                if usage.get('memory_usage', 0) > 0.9:
                    logger.warning("High memory usage detected")
                    await self.communication_hub.broadcast('resource_alert', {
                        'type': 'memory_high',
                        'usage': usage['memory_usage']
                    })
                
                if usage.get('cpu_usage', 0) > 0.95:
                    logger.warning("High CPU usage detected")
                    await self.communication_hub.broadcast('resource_alert', {
                        'type': 'cpu_high',
                        'usage': usage['cpu_usage']
                    })
                    
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
    
    async def get_system_status(self) -> SystemStatus:
        """Get current system status"""
        component_status = await self.component_manager.get_all_component_status()
        
        return SystemStatus(
            state=self.state,
            components_loaded=len(component_status),
            components_active=sum(1 for status in component_status.values() 
                                if status.get('running', False)),
            uptime=time.time() - self.start_time,
            performance_metrics=await self._get_performance_metrics()
        )
    
    async def _get_performance_metrics(self) -> Dict[str, Any]:
        """Collect system performance metrics"""
        try:
            metrics_collector = self.component_manager.get_component('metrics_collector')
            if metrics_collector:
                return await metrics_collector.get_current_metrics()
            return {}
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {e}")
            return {}
    
    def get_component(self, component_name: str):
        """Get a specific component instance"""
        return self.component_manager.get_component(component_name)
    
    async def restart_component(self, component_name: str) -> bool:
        """Restart a specific component"""
        return await self.component_manager.restart_component(component_name)
    
    def register_event_handler(self, event_type: str, handler: Callable):
        """Register an event handler"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    async def emit_event(self, event_type: str, data: Any):
        """Emit a system event"""
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    logger.error(f"Event handler error for {event_type}: {e}")