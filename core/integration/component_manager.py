#!/usr/bin/env python3
"""
Component Manager - Manages lifecycle of all framework components
Handles component registration, initialization, and dependency resolution
"""

import asyncio
import importlib
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
import threading
import time

logger = logging.getLogger(__name__)

class ComponentState(Enum):
    REGISTERED = "registered"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"

@dataclass
class ComponentInfo:
    name: str
    module_path: str
    class_name: str
    instance: Optional[Any] = None
    state: ComponentState = ComponentState.REGISTERED
    dependencies: List[str] = None
    last_error: Optional[str] = None
    start_time: Optional[float] = None

class ComponentManager:
    """Manages all framework components and their lifecycle"""
    
    def __init__(self):
        self.components: Dict[str, ComponentInfo] = {}
        self.dependencies: Dict[str, List[str]] = {}
        self.initialization_order: List[str] = []
        self.lock = threading.RLock()
        
        logger.info("Component Manager initialized")
    
    async def register_component(self, name: str, module_path: str, class_name: str, 
                               dependencies: List[str] = None) -> bool:
        """Register a component for management"""
        try:
            with self.lock:
                if name in self.components:
                    logger.warning(f"Component {name} already registered")
                    return False
                
                self.components[name] = ComponentInfo(
                    name=name,
                    module_path=module_path,
                    class_name=class_name,
                    dependencies=dependencies or []
                )
                
                logger.info(f"Registered component: {name}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to register component {name}: {e}")
            return False
    
    def set_dependencies(self, dependencies: Dict[str, List[str]]):
        """Set component dependencies"""
        with self.lock:
            self.dependencies = dependencies.copy()
            self._calculate_initialization_order()
    
    def _calculate_initialization_order(self):
        """Calculate component initialization order based on dependencies"""
        # Topological sort to determine initialization order
        visited = set()
        temp_visited = set()
        order = []
        
        def visit(component_name: str):
            if component_name in temp_visited:
                raise ValueError(f"Circular dependency detected involving {component_name}")
            if component_name in visited:
                return
            
            temp_visited.add(component_name)
            
            # Visit dependencies first
            for dep in self.dependencies.get(component_name, []):
                if dep in self.components:
                    visit(dep)
            
            temp_visited.remove(component_name)
            visited.add(component_name)
            order.append(component_name)
        
        # Visit all components
        for component_name in self.components:
            if component_name not in visited:
                visit(component_name)
        
        self.initialization_order = order
        logger.info(f"Component initialization order: {order}")
    
    async def initialize_component(self, name: str) -> bool:
        """Initialize a specific component"""
        if name not in self.components:
            logger.error(f"Component {name} not registered")
            return False
        
        component = self.components[name]
        
        if component.state != ComponentState.REGISTERED:
            logger.warning(f"Component {name} already initialized or in wrong state: {component.state}")
            return component.state == ComponentState.INITIALIZED
        
        try:
            component.state = ComponentState.INITIALIZING
            logger.info(f"Initializing component: {name}")
            
            # Check dependencies
            for dep_name in self.dependencies.get(name, []):
                if dep_name not in self.components:
                    raise ValueError(f"Dependency {dep_name} not registered")
                
                dep_component = self.components[dep_name]
                if dep_component.state != ComponentState.INITIALIZED:
                    logger.info(f"Initializing dependency {dep_name} for {name}")
                    if not await self.initialize_component(dep_name):
                        raise ValueError(f"Failed to initialize dependency {dep_name}")
            
            # Import and instantiate the component
            module = importlib.import_module(component.module_path)
            component_class = getattr(module, component.class_name)
            
            # Create instance - try with no args first, then with default config
            try:
                component.instance = component_class()
            except TypeError as te:
                # Class requires arguments - try to find and use default config
                if 'missing' in str(te) and 'argument' in str(te):
                    # Look for a default config class in the same module
                    config_class_name = component.class_name.replace('Engine', 'Config').replace('Extreme', '')
                    if hasattr(module, config_class_name):
                        config_class = getattr(module, config_class_name)
                        try:
                            default_config = config_class()
                            component.instance = component_class(default_config)
                        except Exception:
                            # Try with empty config or None
                            component.instance = component_class(None)
                    else:
                        # Try common config patterns
                        for suffix in ['Config', 'Settings', 'Options']:
                            for prefix in ['', 'Attack', 'Default']:
                                try_name = f"{prefix}{suffix}"
                                if hasattr(module, try_name):
                                    config_class = getattr(module, try_name)
                                    try:
                                        default_config = config_class()
                                        component.instance = component_class(default_config)
                                        break
                                    except Exception:
                                        continue
                        else:
                            raise te
                else:
                    raise te
            
            # Initialize if it has an initialize method
            if hasattr(component.instance, 'initialize'):
                if asyncio.iscoroutinefunction(component.instance.initialize):
                    await component.instance.initialize()
                else:
                    component.instance.initialize()
            
            component.state = ComponentState.INITIALIZED
            component.start_time = time.time()
            logger.info(f"Component {name} initialized successfully")
            return True
            
        except Exception as e:
            component.state = ComponentState.FAILED
            component.last_error = str(e)
            logger.error(f"Failed to initialize component {name}: {e}")
            return False
    
    async def initialize_all_components(self) -> bool:
        """Initialize all components in dependency order"""
        try:
            if not self.initialization_order:
                self._calculate_initialization_order()
            
            logger.info("Starting component initialization...")
            
            for component_name in self.initialization_order:
                if not await self.initialize_component(component_name):
                    logger.error(f"Failed to initialize {component_name}, stopping initialization")
                    return False
            
            logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Component initialization failed: {e}")
            return False
    
    async def start_component(self, name: str) -> bool:
        """Start a specific component"""
        if name not in self.components:
            logger.error(f"Component {name} not registered")
            return False
        
        component = self.components[name]
        
        if component.state != ComponentState.INITIALIZED:
            logger.error(f"Component {name} not initialized, current state: {component.state}")
            return False
        
        try:
            component.state = ComponentState.STARTING
            logger.info(f"Starting component: {name}")
            
            # Start if it has a start method
            if hasattr(component.instance, 'start'):
                if asyncio.iscoroutinefunction(component.instance.start):
                    await component.instance.start()
                else:
                    component.instance.start()
            
            component.state = ComponentState.RUNNING
            logger.info(f"Component {name} started successfully")
            return True
            
        except Exception as e:
            component.state = ComponentState.FAILED
            component.last_error = str(e)
            logger.error(f"Failed to start component {name}: {e}")
            return False
    
    async def start_all_components(self) -> bool:
        """Start all initialized components"""
        try:
            logger.info("Starting all components...")
            
            for component_name in self.initialization_order:
                if not await self.start_component(component_name):
                    logger.error(f"Failed to start {component_name}")
                    return False
            
            logger.info("All components started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start components: {e}")
            return False
    
    async def stop_component(self, name: str) -> bool:
        """Stop a specific component"""
        if name not in self.components:
            logger.error(f"Component {name} not registered")
            return False
        
        component = self.components[name]
        
        if component.state not in [ComponentState.RUNNING, ComponentState.FAILED]:
            logger.warning(f"Component {name} not running, current state: {component.state}")
            return True
        
        try:
            component.state = ComponentState.STOPPING
            logger.info(f"Stopping component: {name}")
            
            # Stop if it has a stop method
            if hasattr(component.instance, 'stop'):
                if asyncio.iscoroutinefunction(component.instance.stop):
                    await component.instance.stop()
                else:
                    component.instance.stop()
            
            component.state = ComponentState.STOPPED
            logger.info(f"Component {name} stopped successfully")
            return True
            
        except Exception as e:
            component.state = ComponentState.FAILED
            component.last_error = str(e)
            logger.error(f"Failed to stop component {name}: {e}")
            return False
    
    async def stop_all_components(self) -> bool:
        """Stop all components in reverse dependency order"""
        try:
            logger.info("Stopping all components...")
            
            # Stop in reverse order
            for component_name in reversed(self.initialization_order):
                await self.stop_component(component_name)
            
            logger.info("All components stopped")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop components: {e}")
            return False
    
    async def restart_component(self, name: str) -> bool:
        """Restart a specific component"""
        logger.info(f"Restarting component: {name}")
        
        # Stop the component
        await self.stop_component(name)
        
        # Reset state to registered
        if name in self.components:
            self.components[name].state = ComponentState.REGISTERED
            self.components[name].instance = None
            self.components[name].last_error = None
        
        # Reinitialize and start
        if await self.initialize_component(name):
            return await self.start_component(name)
        
        return False
    
    def get_component(self, name: str) -> Optional[Any]:
        """Get a component instance"""
        with self.lock:
            if name in self.components:
                component = self.components[name]
                if component.state in [ComponentState.INITIALIZED, ComponentState.RUNNING]:
                    return component.instance
        return None
    
    async def get_component_status(self, name: str) -> Dict[str, Any]:
        """Get status of a specific component"""
        if name not in self.components:
            return {'error': 'Component not registered'}
        
        component = self.components[name]
        
        status = {
            'name': component.name,
            'state': component.state.value,
            'initialized': component.state in [ComponentState.INITIALIZED, ComponentState.RUNNING],
            'running': component.state == ComponentState.RUNNING,
            'uptime': time.time() - component.start_time if component.start_time else 0,
            'last_error': component.last_error
        }
        
        # Get component-specific status if available
        if component.instance and hasattr(component.instance, 'get_status'):
            try:
                if asyncio.iscoroutinefunction(component.instance.get_status):
                    component_status = await component.instance.get_status()
                else:
                    component_status = component.instance.get_status()
                status.update(component_status)
            except Exception as e:
                status['status_error'] = str(e)
        
        return status
    
    async def get_all_component_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all components"""
        status = {}
        for name in self.components:
            status[name] = await self.get_component_status(name)
        return status
    
    async def get_failed_components(self) -> List[str]:
        """Get list of failed components"""
        failed = []
        for name, component in self.components.items():
            if component.state == ComponentState.FAILED:
                failed.append(name)
        return failed
    
    def get_component_dependencies(self, name: str) -> List[str]:
        """Get dependencies for a component"""
        return self.dependencies.get(name, [])
    
    def get_dependent_components(self, name: str) -> List[str]:
        """Get components that depend on this component"""
        dependents = []
        for comp_name, deps in self.dependencies.items():
            if name in deps:
                dependents.append(comp_name)
        return dependents