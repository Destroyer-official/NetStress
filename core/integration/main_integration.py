#!/usr/bin/env python3
"""
Main Integration Module - Entry point for integrated system
Provides unified interface to initialize and manage the complete framework
"""

import asyncio
import logging
import signal
import sys
import time
from typing import Dict, Any, Optional
from pathlib import Path

from .system_coordinator import SystemCoordinator, SystemState
from .component_manager import ComponentManager
from .configuration_manager import ConfigurationManager
from .communication_hub import CommunicationHub

logger = logging.getLogger(__name__)

class IntegratedFramework:
    """Main integrated framework class"""
    
    def __init__(self, config_dir: str = "config"):
        self.coordinator = SystemCoordinator()
        self.config_dir = config_dir
        self.shutdown_event = asyncio.Event()
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        logger.info("Integrated Framework initialized")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def initialize(self) -> bool:
        """Initialize the complete framework"""
        try:
            logger.info("Initializing Integrated DDoS Testing Framework...")
            
            # Initialize system coordinator
            if not await self.coordinator.initialize_system():
                logger.error("Failed to initialize system coordinator")
                return False
            
            logger.info("Framework initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Framework initialization failed: {e}")
            return False
    
    async def start(self) -> bool:
        """Start the complete framework"""
        try:
            logger.info("Starting Integrated DDoS Testing Framework...")
            
            # Start system coordinator
            if not await self.coordinator.start_system():
                logger.error("Failed to start system coordinator")
                return False
            
            logger.info("Framework started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Framework startup failed: {e}")
            return False
    
    async def run(self):
        """Run the framework until shutdown"""
        try:
            # Wait for shutdown signal
            await self.shutdown_event.wait()
            
        except Exception as e:
            logger.error(f"Framework runtime error: {e}")
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Gracefully shutdown the framework"""
        try:
            logger.info("Shutting down Integrated DDoS Testing Framework...")
            
            # Signal shutdown
            self.shutdown_event.set()
            
            # Stop system coordinator
            await self.coordinator.stop_system()
            
            logger.info("Framework shutdown completed")
            
        except Exception as e:
            logger.error(f"Framework shutdown error: {e}")
    
    def get_component(self, component_name: str):
        """Get a component instance"""
        return self.coordinator.get_component(component_name)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get complete system status"""
        return await self.coordinator.get_system_status()
    
    def get_configuration(self, key_path: str = None, default: Any = None) -> Any:
        """Get configuration value"""
        config_manager = self.coordinator.get_component('config_manager')
        if config_manager:
            if key_path:
                return config_manager.get(key_path, default)
            else:
                return config_manager.get_all_configuration()
        return default
    
    def set_configuration(self, key_path: str, value: Any):
        """Set configuration value"""
        config_manager = self.coordinator.get_component('config_manager')
        if config_manager:
            config_manager.set(key_path, value)
    
    async def execute_attack(self, target: str, port: int, protocol: str, 
                           duration: int = 0, **kwargs) -> Dict[str, Any]:
        """Execute an attack using the integrated system"""
        try:
            # Get required components
            safety_manager = self.get_component('safety_manager')
            multi_vector_coordinator = self.get_component('multi_vector_coordinator')
            audit_logger = self.get_component('audit_logger')
            
            # Check if required components are available
            if not safety_manager:
                logger.warning("Safety manager not available, skipping validation")
            if not multi_vector_coordinator:
                raise ValueError("Multi-vector coordinator not available")
            
            # Validate attack request if safety manager is available
            if safety_manager:
                is_valid, reason = safety_manager.validate_attack_request(
                    target=target, port=port, protocol=protocol, duration=duration
                )
                
                if not is_valid:
                    logger.error(f"Attack validation failed: {reason}")
                    return {'success': False, 'error': reason}
            
            # Generate session ID
            session_id = f"attack_{int(time.time())}_{id(self) % 10000:04d}"
            
            # Log attack start if audit logger is available
            if audit_logger:
                try:
                    audit_logger.log_attack_start(
                        session_id=session_id,
                        target=target,
                        port=port,
                        protocol=protocol,
                        attack_type=protocol,
                        parameters=kwargs,
                        environment_info={},
                        safety_checks={'validated': bool(safety_manager)}
                    )
                except Exception as log_error:
                    logger.warning(f"Failed to log attack start: {log_error}")
            
            # Execute attack
            attack_config = {
                'target': target,
                'port': port,
                'protocol': protocol,
                'duration': duration,
                **kwargs
            }
            
            result = await multi_vector_coordinator.execute_attack(attack_config)
            
            # Log attack completion if audit logger is available
            if audit_logger:
                try:
                    audit_logger.log_attack_end(session_id, "completed")
                except Exception as log_error:
                    logger.warning(f"Failed to log attack end: {log_error}")
            
            return {'success': True, 'session_id': session_id, 'result': result}
            
        except Exception as e:
            logger.error(f"Attack execution failed: {e}")
            return {'success': False, 'error': str(e)}

# Global framework instance
_framework_instance: Optional[IntegratedFramework] = None

def get_framework() -> IntegratedFramework:
    """Get the global framework instance"""
    global _framework_instance
    if _framework_instance is None:
        _framework_instance = IntegratedFramework()
    return _framework_instance

async def initialize_framework(config_dir: str = "config") -> bool:
    """Initialize the global framework"""
    framework = get_framework()
    return await framework.initialize()

async def start_framework() -> bool:
    """Start the global framework"""
    framework = get_framework()
    return await framework.start()

async def run_framework():
    """Run the global framework"""
    framework = get_framework()
    await framework.run()

async def shutdown_framework():
    """Shutdown the global framework"""
    framework = get_framework()
    await framework.shutdown()

def main():
    """Main entry point for integrated framework"""
    async def async_main():
        try:
            # Initialize framework
            if not await initialize_framework():
                logger.error("Failed to initialize framework")
                return 1
            
            # Start framework
            if not await start_framework():
                logger.error("Failed to start framework")
                return 1
            
            # Run framework
            await run_framework()
            
            return 0
            
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            return 0
        except Exception as e:
            logger.error(f"Framework error: {e}")
            return 1
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run async main
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        return 0

if __name__ == "__main__":
    sys.exit(main())