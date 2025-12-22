#!/usr/bin/env python3
"""
Configuration Manager - Unified configuration system for all components
Handles loading, validation, and distribution of configuration data
"""

import asyncio
import json
import yaml
import os
import logging
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from copy import deepcopy

logger = logging.getLogger(__name__)

@dataclass
class ConfigurationSchema:
    """Schema definition for configuration validation"""
    name: str
    type: str  # 'string', 'integer', 'float', 'boolean', 'dict', 'list'
    required: bool = True
    default: Any = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    allowed_values: Optional[List[Any]] = None
    description: str = ""

class ConfigurationManager:
    """Manages unified configuration for all framework components"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_data: Dict[str, Any] = {}
        self.schemas: Dict[str, List[ConfigurationSchema]] = {}
        self.watchers: Dict[str, List[callable]] = {}
        self.lock = threading.RLock()
        
        # Default configuration structure
        self.default_config = {
            'system': {
                'log_level': 'INFO',
                'max_workers': 4,
                'monitoring_interval': 5.0,
                'shutdown_timeout': 30.0
            },
            'platform': {
                'auto_detect': True,
                'optimization_level': 'high',
                'kernel_optimizations': True
            },
            'networking': {
                'socket_buffer_size': 1024 * 1024 * 256,  # 256MB
                'connection_timeout': 5.0,
                'max_connections': 10000,
                'tcp_nodelay': True,
                'socket_reuse': True
            },
            'performance': {
                'zero_copy_enabled': True,
                'hardware_acceleration': True,
                'numa_aware': True,
                'cpu_affinity': 'auto'
            },
            'memory': {
                'pool_size': 1024 * 1024 * 1024,  # 1GB
                'gc_optimization': True,
                'memory_limit': 8 * 1024 * 1024 * 1024,  # 8GB
                'buffer_count': 1000
            },
            'ai': {
                'enabled': True,
                'model_path': 'models/',
                'optimization_interval': 10.0,
                'learning_rate': 0.001,
                'batch_size': 32
            },
            'autonomous': {
                'enabled': True,
                'adaptation_interval': 5.0,
                'resource_monitoring': True,
                'auto_optimization': True
            },
            'safety': {
                'enabled': True,
                'environment_check': True,
                'target_validation': True,
                'resource_limits': True,
                'audit_logging': True
            },
            'analytics': {
                'enabled': True,
                'metrics_interval': 2.0,
                'visualization_enabled': True,
                'predictive_analytics': True
            },
            'interfaces': {
                'cli_enabled': True,
                'web_gui_enabled': True,
                'api_enabled': True,
                'mobile_enabled': False
            }
        }
        
        logger.info("Configuration Manager initialized")
    
    async def load_configuration(self) -> bool:
        """Load configuration from files and environment"""
        try:
            # Start with default configuration
            self.config_data = deepcopy(self.default_config)
            
            # Load from configuration files
            await self._load_config_files()
            
            # Override with environment variables
            self._load_environment_variables()
            
            # Validate configuration
            if await self._validate_configuration():
                logger.info("Configuration loaded and validated successfully")
                return True
            else:
                logger.error("Configuration validation failed")
                return False
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
    async def _load_config_files(self):
        """Load configuration from YAML and JSON files"""
        config_files = [
            'config.yaml',
            'config.yml', 
            'config.json',
            'ddos_config.yaml',
            'ddos_config.yml',
            'ddos_config.json'
        ]
        
        for config_file in config_files:
            config_path = self.config_dir / config_file
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        if config_file.endswith('.json'):
                            file_config = json.load(f)
                        else:
                            file_config = yaml.safe_load(f)
                    
                    # Merge with existing configuration
                    self._merge_config(self.config_data, file_config)
                    logger.info(f"Loaded configuration from {config_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to load config file {config_path}: {e}")
    
    def _load_environment_variables(self):
        """Load configuration from environment variables"""
        env_prefix = "DDOS_"
        
        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                # Convert environment variable to config path
                config_key = key[len(env_prefix):].lower().replace('_', '.')
                self._set_nested_config(config_key, self._parse_env_value(value))
    
    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type"""
        # Try to parse as JSON first
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
        
        # Try boolean
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _set_nested_config(self, key_path: str, value: Any):
        """Set nested configuration value using dot notation"""
        keys = key_path.split('.')
        current = self.config_data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    async def _validate_configuration(self) -> bool:
        """Validate configuration against schemas"""
        try:
            # Validate each section against its schema
            for section_name, schemas in self.schemas.items():
                section_config = self.config_data.get(section_name, {})
                
                for schema in schemas:
                    if not self._validate_config_item(section_config, schema):
                        return False
            
            # Perform cross-section validation
            return await self._validate_cross_dependencies()
            
        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return False
    
    def _validate_config_item(self, config: Dict[str, Any], schema: ConfigurationSchema) -> bool:
        """Validate a single configuration item against its schema"""
        value = config.get(schema.name)
        
        # Check required fields
        if schema.required and value is None:
            if schema.default is not None:
                config[schema.name] = schema.default
                value = schema.default
            else:
                logger.error(f"Required configuration {schema.name} is missing")
                return False
        
        if value is None:
            return True
        
        # Type validation
        if schema.type == 'string' and not isinstance(value, str):
            logger.error(f"Configuration {schema.name} must be a string")
            return False
        elif schema.type == 'integer' and not isinstance(value, int):
            logger.error(f"Configuration {schema.name} must be an integer")
            return False
        elif schema.type == 'float' and not isinstance(value, (int, float)):
            logger.error(f"Configuration {schema.name} must be a number")
            return False
        elif schema.type == 'boolean' and not isinstance(value, bool):
            logger.error(f"Configuration {schema.name} must be a boolean")
            return False
        elif schema.type == 'dict' and not isinstance(value, dict):
            logger.error(f"Configuration {schema.name} must be a dictionary")
            return False
        elif schema.type == 'list' and not isinstance(value, list):
            logger.error(f"Configuration {schema.name} must be a list")
            return False
        
        # Range validation
        if schema.min_value is not None and isinstance(value, (int, float)):
            if value < schema.min_value:
                logger.error(f"Configuration {schema.name} must be >= {schema.min_value}")
                return False
        
        if schema.max_value is not None and isinstance(value, (int, float)):
            if value > schema.max_value:
                logger.error(f"Configuration {schema.name} must be <= {schema.max_value}")
                return False
        
        # Allowed values validation
        if schema.allowed_values is not None:
            if value not in schema.allowed_values:
                logger.error(f"Configuration {schema.name} must be one of {schema.allowed_values}")
                return False
        
        return True
    
    async def _validate_cross_dependencies(self) -> bool:
        """Validate cross-section configuration dependencies"""
        # Example validations
        
        # If AI is enabled, check model path exists
        if self.get('ai.enabled', False):
            model_path = Path(self.get('ai.model_path', 'models/'))
            if not model_path.exists():
                logger.warning(f"AI model path {model_path} does not exist, creating it")
                model_path.mkdir(parents=True, exist_ok=True)
        
        # Validate memory limits
        memory_limit = self.get('memory.memory_limit', 0)
        pool_size = self.get('memory.pool_size', 0)
        
        if pool_size > memory_limit:
            logger.error("Memory pool size cannot exceed memory limit")
            return False
        
        # Validate networking configuration
        max_connections = self.get('networking.max_connections', 0)
        if max_connections > 65535:
            logger.error("Max connections cannot exceed 65535")
            return False
        
        return True
    
    def register_schema(self, section: str, schemas: List[ConfigurationSchema]):
        """Register configuration schema for validation"""
        with self.lock:
            self.schemas[section] = schemas
            logger.info(f"Registered configuration schema for section: {section}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        with self.lock:
            keys = key_path.split('.')
            current = self.config_data
            
            try:
                for key in keys:
                    current = current[key]
                return current
            except (KeyError, TypeError):
                return default
    
    def set(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        with self.lock:
            keys = key_path.split('.')
            current = self.config_data
            
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            old_value = current.get(keys[-1])
            current[keys[-1]] = value
            
            # Notify watchers
            self._notify_watchers(key_path, old_value, value)
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        with self.lock:
            return deepcopy(self.config_data.get(section, {}))
    
    def set_section(self, section: str, config: Dict[str, Any]):
        """Set entire configuration section"""
        with self.lock:
            old_config = self.config_data.get(section, {})
            self.config_data[section] = deepcopy(config)
            
            # Notify watchers for all changed keys
            for key, value in config.items():
                key_path = f"{section}.{key}"
                old_value = old_config.get(key)
                if old_value != value:
                    self._notify_watchers(key_path, old_value, value)
    
    def watch(self, key_path: str, callback: callable):
        """Watch for configuration changes"""
        with self.lock:
            if key_path not in self.watchers:
                self.watchers[key_path] = []
            self.watchers[key_path].append(callback)
    
    def _notify_watchers(self, key_path: str, old_value: Any, new_value: Any):
        """Notify watchers of configuration changes"""
        if key_path in self.watchers:
            for callback in self.watchers[key_path]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        asyncio.create_task(callback(key_path, old_value, new_value))
                    else:
                        callback(key_path, old_value, new_value)
                except Exception as e:
                    logger.error(f"Configuration watcher error for {key_path}: {e}")
    
    async def save_configuration(self, filename: str = "config.yaml") -> bool:
        """Save current configuration to file"""
        try:
            config_path = self.config_dir / filename
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                if filename.endswith('.json'):
                    json.dump(self.config_data, f, indent=2)
                else:
                    yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration saved to {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get_all_configuration(self) -> Dict[str, Any]:
        """Get complete configuration"""
        with self.lock:
            return deepcopy(self.config_data)
    
    def reload_configuration(self) -> bool:
        """Reload configuration from files"""
        try:
            asyncio.create_task(self.load_configuration())
            return True
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False