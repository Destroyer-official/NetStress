#!/usr/bin/env python3
"""
Emergency Shutdown System
Provides immediate termination capabilities for all attack activities
"""

import os
import sys
import time
import signal
import psutil
import logging
import threading
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class ShutdownTrigger:
    """Represents a shutdown trigger condition"""
    name: str
    condition: Callable[[], bool]
    priority: int  # 1=highest, 10=lowest
    description: str

class EmergencyShutdown:
    """Emergency shutdown system for immediate attack termination"""
    
    def __init__(self):
        self.shutdown_triggered = False
        self.shutdown_reason = ""
        self.shutdown_time = None
        
        # Shutdown triggers and callbacks
        self.triggers: List[ShutdownTrigger] = []
        self.shutdown_callbacks: List[Callable] = []
        self.cleanup_callbacks: List[Callable] = []
        
        # Process tracking
        self.tracked_processes: Dict[int, Dict] = {}
        self.attack_threads: List[threading.Thread] = []
        
        # Monitoring
        self.monitor_thread = None
        self.monitoring_active = False
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Register default triggers
        self._register_default_triggers()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            self.trigger_shutdown(f"Received signal {signal_name}")
        
        # Register handlers for common termination signals
        try:
            signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
            signal.signal(signal.SIGTERM, signal_handler)  # Termination request
            if hasattr(signal, 'SIGBREAK'):  # Windows
                signal.signal(signal.SIGBREAK, signal_handler)
        except Exception as e:
            logger.warning(f"Could not setup signal handlers: {e}")
    
    def _register_default_triggers(self):
        """Register default emergency shutdown triggers"""
        
        # High CPU usage trigger
        def high_cpu_trigger():
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                return cpu_percent > 95.0  # 95% CPU usage
            except:
                return False
        
        self.add_trigger(ShutdownTrigger(
            name="high_cpu",
            condition=high_cpu_trigger,
            priority=3,
            description="CPU usage exceeds 95%"
        ))
        
        # High memory usage trigger
        def high_memory_trigger():
            try:
                memory = psutil.virtual_memory()
                return memory.percent > 90.0  # 90% memory usage
            except:
                return False
        
        self.add_trigger(ShutdownTrigger(
            name="high_memory",
            condition=high_memory_trigger,
            priority=3,
            description="Memory usage exceeds 90%"
        ))
        
        # Disk space trigger
        def low_disk_trigger():
            try:
                disk = psutil.disk_usage('/')
                return (disk.free / disk.total) < 0.05  # Less than 5% free
            except:
                return False
        
        self.add_trigger(ShutdownTrigger(
            name="low_disk",
            condition=low_disk_trigger,
            priority=4,
            description="Disk space below 5%"
        ))
        
        # Process count trigger
        def high_process_count_trigger():
            try:
                return len(psutil.pids()) > 1000  # More than 1000 processes
            except:
                return False
        
        self.add_trigger(ShutdownTrigger(
            name="high_process_count",
            condition=high_process_count_trigger,
            priority=5,
            description="Process count exceeds 1000"
        ))
    
    def add_trigger(self, trigger: ShutdownTrigger):
        """Add a shutdown trigger"""
        self.triggers.append(trigger)
        self.triggers.sort(key=lambda t: t.priority)
        logger.debug(f"Added shutdown trigger: {trigger.name}")
    
    def remove_trigger(self, name: str):
        """Remove a shutdown trigger by name"""
        self.triggers = [t for t in self.triggers if t.name != name]
        logger.debug(f"Removed shutdown trigger: {name}")
    
    def register_shutdown_callback(self, callback: Callable):
        """Register callback to run during shutdown"""
        self.shutdown_callbacks.append(callback)
    
    def register_cleanup_callback(self, callback: Callable):
        """Register callback to run during cleanup"""
        self.cleanup_callbacks.append(callback)
    
    def track_process(self, pid: int, description: str, attack_type: str = "unknown"):
        """Track a process for shutdown"""
        self.tracked_processes[pid] = {
            'description': description,
            'attack_type': attack_type,
            'start_time': time.time(),
            'status': 'active'
        }
        logger.debug(f"Tracking process {pid}: {description}")
    
    def untrack_process(self, pid: int):
        """Stop tracking a process"""
        if pid in self.tracked_processes:
            del self.tracked_processes[pid]
            logger.debug(f"Stopped tracking process {pid}")
    
    def track_thread(self, thread: threading.Thread):
        """Track a thread for shutdown"""
        self.attack_threads.append(thread)
        logger.debug(f"Tracking thread: {thread.name}")
    
    def start_monitoring(self):
        """Start monitoring for shutdown triggers"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Emergency shutdown monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring for shutdown triggers"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Emergency shutdown monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop for shutdown triggers"""
        while self.monitoring_active and not self.shutdown_triggered:
            try:
                # Check all triggers
                for trigger in self.triggers:
                    if trigger.condition():
                        self.trigger_shutdown(f"Trigger activated: {trigger.description}")
                        return
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in shutdown monitoring: {e}")
                time.sleep(5)  # Wait longer on error
    
    def trigger_shutdown(self, reason: str):
        """Trigger emergency shutdown"""
        if self.shutdown_triggered:
            logger.warning(f"Shutdown already triggered, ignoring: {reason}")
            return
        
        self.shutdown_triggered = True
        self.shutdown_reason = reason
        self.shutdown_time = datetime.now()
        
        logger.critical(f"EMERGENCY SHUTDOWN TRIGGERED: {reason}")
        
        # Execute shutdown sequence
        self._execute_shutdown()
    
    def _execute_shutdown(self):
        """Execute the emergency shutdown sequence"""
        try:
            # Phase 1: Run shutdown callbacks
            logger.info("Phase 1: Running shutdown callbacks")
            for callback in self.shutdown_callbacks:
                try:
                    callback(self.shutdown_reason)
                except Exception as e:
                    logger.error(f"Shutdown callback error: {e}")
            
            # Phase 2: Terminate tracked threads
            logger.info("Phase 2: Terminating attack threads")
            self._terminate_threads()
            
            # Phase 3: Terminate tracked processes
            logger.info("Phase 3: Terminating tracked processes")
            self._terminate_processes()
            
            # Phase 4: Force kill remaining attack processes
            logger.info("Phase 4: Force killing remaining processes")
            self._force_kill_attack_processes()
            
            # Phase 5: Run cleanup callbacks
            logger.info("Phase 5: Running cleanup callbacks")
            for callback in self.cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Cleanup callback error: {e}")
            
            # Phase 6: Final system cleanup
            logger.info("Phase 6: Final system cleanup")
            self._final_cleanup()
            
            logger.critical("Emergency shutdown completed successfully")
            
        except Exception as e:
            logger.critical(f"Error during emergency shutdown: {e}")
    
    def _terminate_threads(self):
        """Terminate all tracked threads"""
        for thread in self.attack_threads:
            try:
                if thread.is_alive():
                    logger.debug(f"Waiting for thread {thread.name} to terminate")
                    thread.join(timeout=5)
                    if thread.is_alive():
                        logger.warning(f"Thread {thread.name} did not terminate gracefully")
            except Exception as e:
                logger.error(f"Error terminating thread {thread.name}: {e}")
        
        self.attack_threads.clear()
    
    def _terminate_processes(self):
        """Terminate all tracked processes"""
        for pid, info in list(self.tracked_processes.items()):
            try:
                if psutil.pid_exists(pid):
                    process = psutil.Process(pid)
                    logger.debug(f"Terminating process {pid}: {info['description']}")
                    
                    # Try graceful termination first
                    process.terminate()
                    
                    # Wait for termination
                    try:
                        process.wait(timeout=5)
                    except psutil.TimeoutExpired:
                        # Force kill if graceful termination fails
                        logger.warning(f"Force killing process {pid}")
                        process.kill()
                        process.wait(timeout=2)
                    
                    info['status'] = 'terminated'
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.debug(f"Process {pid} already terminated or access denied: {e}")
            except Exception as e:
                logger.error(f"Error terminating process {pid}: {e}")
    
    def _force_kill_attack_processes(self):
        """Force kill any remaining processes that might be attack-related"""
        try:
            current_pid = os.getpid()
            
            for process in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # Skip our own process
                    if process.info['pid'] == current_pid:
                        continue
                    
                    # Check if process might be attack-related
                    cmdline = ' '.join(process.info['cmdline'] or [])
                    name = process.info['name'] or ''
                    
                    # Look for attack-related keywords
                    attack_keywords = [
                        'ddos', 'flood', 'attack', 'stress', 'load',
                        'scapy', 'hping', 'nmap', 'masscan'
                    ]
                    
                    if any(keyword in cmdline.lower() or keyword in name.lower() 
                           for keyword in attack_keywords):
                        logger.warning(f"Force killing potential attack process {process.info['pid']}: {name}")
                        process.kill()
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    logger.error(f"Error checking process: {e}")
        
        except Exception as e:
            logger.error(f"Error in force kill phase: {e}")
    
    def _final_cleanup(self):
        """Perform final system cleanup"""
        try:
            # Close any remaining sockets
            self._cleanup_sockets()
            
            # Reset network settings if modified
            self._reset_network_settings()
            
            # Clear temporary files
            self._cleanup_temp_files()
            
        except Exception as e:
            logger.error(f"Error in final cleanup: {e}")
    
    def _cleanup_sockets(self):
        """Close any remaining open sockets"""
        try:
            # Get network connections for current process
            connections = psutil.net_connections(kind='inet')
            current_pid = os.getpid()
            
            for conn in connections:
                if conn.pid == current_pid and conn.status == 'ESTABLISHED':
                    logger.debug(f"Found open connection: {conn}")
                    # Note: Can't directly close from here, but log for awareness
            
        except Exception as e:
            logger.error(f"Error checking sockets: {e}")
    
    def _reset_network_settings(self):
        """Reset any network settings that might have been modified"""
        try:
            # This would reset any kernel parameters that were modified
            # Implementation depends on what was changed during attack setup
            pass
        except Exception as e:
            logger.error(f"Error resetting network settings: {e}")
    
    def _cleanup_temp_files(self):
        """Clean up temporary files created during attacks"""
        try:
            import tempfile
            import glob
            
            temp_dir = tempfile.gettempdir()
            attack_files = glob.glob(os.path.join(temp_dir, 'ddos_*'))
            attack_files.extend(glob.glob(os.path.join(temp_dir, 'attack_*')))
            
            for file_path in attack_files:
                try:
                    os.remove(file_path)
                    logger.debug(f"Removed temp file: {file_path}")
                except Exception as e:
                    logger.warning(f"Could not remove temp file {file_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error cleaning temp files: {e}")
    
    def get_shutdown_status(self) -> Dict:
        """Get current shutdown system status"""
        return {
            'shutdown_triggered': self.shutdown_triggered,
            'shutdown_reason': self.shutdown_reason,
            'shutdown_time': self.shutdown_time.isoformat() if self.shutdown_time else None,
            'monitoring_active': self.monitoring_active,
            'tracked_processes': len(self.tracked_processes),
            'tracked_threads': len(self.attack_threads),
            'active_triggers': len(self.triggers)
        }
    
    def manual_shutdown(self):
        """Manually trigger shutdown (for testing or user request)"""
        self.trigger_shutdown("Manual shutdown requested")
    
    def is_shutdown_triggered(self) -> bool:
        """Check if shutdown has been triggered"""
        return self.shutdown_triggered