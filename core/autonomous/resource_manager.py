"""
Intelligent Resource Allocation and Management

Implements intelligent CPU, memory, and network resource allocation,
load balancing across multiple cores and processes, and dynamic scaling
based on performance requirements.
"""

import asyncio
import multiprocessing
import threading
import time
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ResourceType(Enum):
    """Types of system resources"""
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    DISK_IO = "disk_io"
    PROCESS = "process"
    THREAD = "thread"

@dataclass
class ResourceUsage:
    """Current resource usage metrics"""
    cpu_percent: float
    memory_percent: float
    memory_bytes: int
    network_bytes_sent: int
    network_bytes_recv: int
    disk_read_bytes: int
    disk_write_bytes: int
    process_count: int
    thread_count: int
    timestamp: float = field(default_factory=time.time)

@dataclass
class ResourceLimits:
    """Resource allocation limits"""
    max_cpu_percent: float = 80.0
    max_memory_percent: float = 70.0
    max_memory_bytes: Optional[int] = None
    max_processes: int = multiprocessing.cpu_count() * 2
    max_threads_per_process: int = 100
    max_network_bandwidth: Optional[int] = None  # bytes per second

@dataclass
class WorkerProcess:
    """Information about a worker process"""
    process_id: int
    cpu_affinity: List[int]
    memory_limit: int
    current_load: float
    task_count: int
    start_time: float
    last_heartbeat: float

class IntelligentResourceManager:
    """
    Manages system resources intelligently, including CPU, memory, and network allocation.
    Provides dynamic scaling and load balancing capabilities.
    """
    
    def __init__(self, 
                 resource_limits: Optional[ResourceLimits] = None,
                 monitoring_interval: float = 1.0):
        self.resource_limits = resource_limits or ResourceLimits()
        self.monitoring_interval = monitoring_interval
        
        self.resource_history = deque(maxlen=100)
        self.worker_processes = {}
        self.cpu_cores = multiprocessing.cpu_count()
        self.available_cores = list(range(self.cpu_cores))
        self.core_assignments = {}
        
        self.monitoring_active = False
        self.resource_callbacks = {}
        self.scaling_policies = {}
        
        # Resource allocation strategies
        self.allocation_strategies = {
            ResourceType.CPU: self._allocate_cpu_resources,
            ResourceType.MEMORY: self._allocate_memory_resources,
            ResourceType.NETWORK: self._allocate_network_resources,
            ResourceType.PROCESS: self._allocate_process_resources
        }
        
        # Performance metrics for scaling decisions
        self.performance_metrics = deque(maxlen=50)
        self.scaling_cooldown = {}
        
    async def start_monitoring(self):
        """Start resource monitoring and management"""
        self.monitoring_active = True
        logger.info("Resource manager started monitoring")
        
        try:
            while self.monitoring_active:
                # Collect resource usage
                usage = await self._collect_resource_usage()
                self.resource_history.append(usage)
                
                # Check for resource constraints
                await self._check_resource_constraints(usage)
                
                # Update worker process information
                await self._update_worker_processes()
                
                # Perform dynamic scaling if needed
                await self._evaluate_scaling_needs(usage)
                
                await asyncio.sleep(self.monitoring_interval)
                
        except Exception as e:
            logger.error(f"Resource monitoring error: {e}")
        finally:
            self.monitoring_active = False
            logger.info("Resource manager stopped monitoring")
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring_active = False
    
    async def _collect_resource_usage(self) -> ResourceUsage:
        """Collect current system resource usage"""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_bytes = memory.used
            
            # Network usage
            network = psutil.net_io_counters()
            network_bytes_sent = network.bytes_sent
            network_bytes_recv = network.bytes_recv
            
            # Disk usage
            disk = psutil.disk_io_counters()
            disk_read_bytes = disk.read_bytes if disk else 0
            disk_write_bytes = disk.write_bytes if disk else 0
            
            # Process and thread counts
            process_count = len(psutil.pids())
            thread_count = sum(p.num_threads() for p in psutil.process_iter(['num_threads']) 
                             if p.info['num_threads'])
            
        except ImportError:
            # Fallback if psutil not available
            logger.warning("psutil not available, using estimated resource usage")
            cpu_percent = 50.0  # Estimated
            memory_percent = 40.0
            memory_bytes = 1024 * 1024 * 1024  # 1GB estimated
            network_bytes_sent = 0
            network_bytes_recv = 0
            disk_read_bytes = 0
            disk_write_bytes = 0
            process_count = len(self.worker_processes)
            thread_count = process_count * 10  # Estimated
        
        return ResourceUsage(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_bytes=memory_bytes,
            network_bytes_sent=network_bytes_sent,
            network_bytes_recv=network_bytes_recv,
            disk_read_bytes=disk_read_bytes,
            disk_write_bytes=disk_write_bytes,
            process_count=process_count,
            thread_count=thread_count
        )
    
    async def _check_resource_constraints(self, usage: ResourceUsage):
        """Check if resource usage exceeds limits and take action"""
        
        # CPU constraint check
        if usage.cpu_percent > self.resource_limits.max_cpu_percent:
            await self._handle_cpu_constraint(usage.cpu_percent)
        
        # Memory constraint check
        if usage.memory_percent > self.resource_limits.max_memory_percent:
            await self._handle_memory_constraint(usage.memory_percent)
        
        # Process count constraint check
        if usage.process_count > self.resource_limits.max_processes:
            await self._handle_process_constraint(usage.process_count)
    
    async def _handle_cpu_constraint(self, cpu_percent: float):
        """Handle CPU usage constraint"""
        logger.warning(f"CPU usage high: {cpu_percent}%")
        
        # Trigger CPU resource reallocation
        if 'cpu_constraint' in self.resource_callbacks:
            await self.resource_callbacks['cpu_constraint']({
                'cpu_percent': cpu_percent,
                'action': 'reduce_load'
            })
    
    async def _handle_memory_constraint(self, memory_percent: float):
        """Handle memory usage constraint"""
        logger.warning(f"Memory usage high: {memory_percent}%")
        
        # Trigger memory optimization
        if 'memory_constraint' in self.resource_callbacks:
            await self.resource_callbacks['memory_constraint']({
                'memory_percent': memory_percent,
                'action': 'optimize_memory'
            })
    
    async def _handle_process_constraint(self, process_count: int):
        """Handle process count constraint"""
        logger.warning(f"Process count high: {process_count}")
        
        # Trigger process optimization
        if 'process_constraint' in self.resource_callbacks:
            await self.resource_callbacks['process_constraint']({
                'process_count': process_count,
                'action': 'reduce_processes'
            })
    
    async def _update_worker_processes(self):
        """Update information about worker processes"""
        current_time = time.time()
        
        # Remove stale processes
        stale_processes = []
        for pid, worker in self.worker_processes.items():
            if current_time - worker.last_heartbeat > 30.0:  # 30 second timeout
                stale_processes.append(pid)
        
        for pid in stale_processes:
            logger.info(f"Removing stale worker process {pid}")
            del self.worker_processes[pid]
    
    async def _evaluate_scaling_needs(self, usage: ResourceUsage):
        """Evaluate if scaling up or down is needed"""
        
        # Calculate performance score
        performance_score = self._calculate_performance_score(usage)
        self.performance_metrics.append(performance_score)
        
        if len(self.performance_metrics) < 10:
            return  # Need more data
        
        recent_performance = list(self.performance_metrics)[-10:]
        avg_performance = sum(recent_performance) / len(recent_performance)
        
        current_time = time.time()
        
        # Scale up if performance is poor and resources allow
        if (avg_performance < 0.6 and 
            usage.cpu_percent < self.resource_limits.max_cpu_percent * 0.8 and
            usage.memory_percent < self.resource_limits.max_memory_percent * 0.8 and
            len(self.worker_processes) < self.resource_limits.max_processes):
            
            if self._can_scale('up', current_time):
                await self._scale_up()
        
        # Scale down if performance is good and resource usage is low
        elif (avg_performance > 0.8 and 
              usage.cpu_percent < 30.0 and
              len(self.worker_processes) > 1):
            
            if self._can_scale('down', current_time):
                await self._scale_down()
    
    def _calculate_performance_score(self, usage: ResourceUsage) -> float:
        """Calculate overall performance score (0-1, higher is better)"""
        
        # Normalize resource usage (lower usage = better performance for resources)
        cpu_score = max(0, 1.0 - usage.cpu_percent / 100.0)
        memory_score = max(0, 1.0 - usage.memory_percent / 100.0)
        
        # Combine scores with weights
        performance_score = (
            cpu_score * 0.4 +
            memory_score * 0.3 +
            0.3  # Base score for other factors
        )
        
        return max(0.0, min(1.0, performance_score))
    
    def _can_scale(self, direction: str, current_time: float) -> bool:
        """Check if scaling is allowed (cooldown period)"""
        cooldown_key = f"scale_{direction}"
        last_scale_time = self.scaling_cooldown.get(cooldown_key, 0)
        
        # 30 second cooldown between scaling operations
        return current_time - last_scale_time > 30.0
    
    async def _scale_up(self):
        """Scale up by adding more worker processes"""
        logger.info("Scaling up: adding worker process")
        
        # This would trigger the creation of new worker processes
        if 'scale_up' in self.resource_callbacks:
            await self.resource_callbacks['scale_up']({
                'action': 'add_worker',
                'current_workers': len(self.worker_processes)
            })
        
        self.scaling_cooldown['scale_up'] = time.time()
    
    async def _scale_down(self):
        """Scale down by removing worker processes"""
        logger.info("Scaling down: removing worker process")
        
        # This would trigger the removal of worker processes
        if 'scale_down' in self.resource_callbacks:
            await self.resource_callbacks['scale_down']({
                'action': 'remove_worker',
                'current_workers': len(self.worker_processes)
            })
        
        self.scaling_cooldown['scale_down'] = time.time()
    
    def register_resource_callback(self, 
                                 event_type: str,
                                 callback: Callable[[Dict[str, Any]], None]):
        """Register callback for resource events"""
        self.resource_callbacks[event_type] = callback
    
    def allocate_resources(self, 
                         resource_type: ResourceType,
                         requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Allocate resources based on requirements"""
        
        if resource_type in self.allocation_strategies:
            return self.allocation_strategies[resource_type](requirements)
        else:
            logger.warning(f"No allocation strategy for resource type: {resource_type}")
            return {}
    
    def _allocate_cpu_resources(self, requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Allocate CPU resources (cores, affinity)"""
        
        requested_cores = requirements.get('cores', 1)
        priority = requirements.get('priority', 'normal')
        
        # Find available cores
        available_cores = [core for core in self.available_cores 
                          if core not in self.core_assignments]
        
        if len(available_cores) < requested_cores:
            # Not enough cores available, allocate what we can
            allocated_cores = available_cores
        else:
            # Allocate requested number of cores
            allocated_cores = available_cores[:requested_cores]
        
        # Mark cores as assigned
        worker_id = f"worker_{int(time.time())}"
        for core in allocated_cores:
            self.core_assignments[core] = worker_id
        
        return {
            'allocated_cores': allocated_cores,
            'worker_id': worker_id,
            'cpu_affinity': allocated_cores
        }
    
    def _allocate_memory_resources(self, requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Allocate memory resources"""
        
        requested_memory = requirements.get('memory_mb', 512)
        
        # Get current memory usage
        if self.resource_history:
            current_usage = self.resource_history[-1]
            available_memory_percent = 100 - current_usage.memory_percent
            
            # Estimate available memory in MB
            try:
                import psutil
                total_memory = psutil.virtual_memory().total
                available_memory_mb = (available_memory_percent / 100.0) * (total_memory / 1024 / 1024)
            except ImportError:
                available_memory_mb = 2048  # 2GB estimate
            
            if requested_memory > available_memory_mb:
                allocated_memory = int(available_memory_mb * 0.8)  # Leave some buffer
            else:
                allocated_memory = requested_memory
        else:
            allocated_memory = requested_memory
        
        return {
            'allocated_memory_mb': allocated_memory,
            'memory_limit': allocated_memory * 1024 * 1024  # Convert to bytes
        }
    
    def _allocate_network_resources(self, requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Allocate network resources (bandwidth, connections)"""
        
        requested_bandwidth = requirements.get('bandwidth_mbps', 100)
        requested_connections = requirements.get('max_connections', 1000)
        
        # For now, just return the requested values
        # In a real implementation, this would consider network capacity
        return {
            'allocated_bandwidth_mbps': requested_bandwidth,
            'max_connections': requested_connections,
            'network_priority': requirements.get('priority', 'normal')
        }
    
    def _allocate_process_resources(self, requirements: Dict[str, Any]) -> Dict[str, Any]:
        """Allocate process resources"""
        
        requested_processes = requirements.get('processes', 1)
        
        # Check if we can allocate the requested processes
        current_processes = len(self.worker_processes)
        max_processes = self.resource_limits.max_processes
        
        if current_processes + requested_processes > max_processes:
            allocated_processes = max(0, max_processes - current_processes)
        else:
            allocated_processes = requested_processes
        
        return {
            'allocated_processes': allocated_processes,
            'max_threads_per_process': self.resource_limits.max_threads_per_process
        }
    
    def register_worker_process(self, 
                              process_id: int,
                              cpu_affinity: List[int],
                              memory_limit: int) -> str:
        """Register a new worker process"""
        
        worker_id = f"worker_{process_id}_{int(time.time())}"
        
        self.worker_processes[process_id] = WorkerProcess(
            process_id=process_id,
            cpu_affinity=cpu_affinity,
            memory_limit=memory_limit,
            current_load=0.0,
            task_count=0,
            start_time=time.time(),
            last_heartbeat=time.time()
        )
        
        logger.info(f"Registered worker process {process_id} as {worker_id}")
        return worker_id
    
    def update_worker_heartbeat(self, process_id: int, load: float, task_count: int):
        """Update worker process heartbeat and metrics"""
        
        if process_id in self.worker_processes:
            worker = self.worker_processes[process_id]
            worker.last_heartbeat = time.time()
            worker.current_load = load
            worker.task_count = task_count
    
    def get_resource_statistics(self) -> Dict[str, Any]:
        """Get comprehensive resource statistics"""
        
        if not self.resource_history:
            return {"status": "no_data"}
        
        recent_usage = list(self.resource_history)[-10:]
        
        return {
            "current_usage": {
                "cpu_percent": recent_usage[-1].cpu_percent,
                "memory_percent": recent_usage[-1].memory_percent,
                "process_count": recent_usage[-1].process_count,
                "thread_count": recent_usage[-1].thread_count
            },
            "average_usage": {
                "cpu_percent": sum(u.cpu_percent for u in recent_usage) / len(recent_usage),
                "memory_percent": sum(u.memory_percent for u in recent_usage) / len(recent_usage)
            },
            "resource_limits": {
                "max_cpu_percent": self.resource_limits.max_cpu_percent,
                "max_memory_percent": self.resource_limits.max_memory_percent,
                "max_processes": self.resource_limits.max_processes
            },
            "worker_processes": {
                "count": len(self.worker_processes),
                "total_load": sum(w.current_load for w in self.worker_processes.values()),
                "total_tasks": sum(w.task_count for w in self.worker_processes.values())
            },
            "cpu_allocation": {
                "total_cores": self.cpu_cores,
                "assigned_cores": len(self.core_assignments),
                "available_cores": len(self.available_cores) - len(self.core_assignments)
            },
            "performance_metrics": {
                "recent_performance": list(self.performance_metrics)[-5:] if self.performance_metrics else [],
                "avg_performance": sum(self.performance_metrics) / len(self.performance_metrics) if self.performance_metrics else 0
            }
        }

class LoadBalancer:
    """
    Load balancer for distributing work across multiple cores and processes
    """
    
    def __init__(self, 
                 balancing_strategy: str = "round_robin",
                 health_check_interval: float = 5.0):
        self.balancing_strategy = balancing_strategy
        self.health_check_interval = health_check_interval
        
        self.workers = {}
        self.worker_loads = {}
        self.current_worker_index = 0
        self.task_queue = asyncio.Queue()
        self.health_check_active = False
        
        # Load balancing strategies
        self.strategies = {
            'round_robin': self._round_robin_select,
            'least_loaded': self._least_loaded_select,
            'weighted_round_robin': self._weighted_round_robin_select,
            'random': self._random_select
        }
    
    def register_worker(self, 
                       worker_id: str,
                       capacity: int = 100,
                       weight: float = 1.0):
        """Register a worker for load balancing"""
        
        self.workers[worker_id] = {
            'capacity': capacity,
            'weight': weight,
            'active': True,
            'last_health_check': time.time()
        }
        self.worker_loads[worker_id] = 0
        
        logger.info(f"Registered worker {worker_id} with capacity {capacity}")
    
    def unregister_worker(self, worker_id: str):
        """Unregister a worker"""
        
        if worker_id in self.workers:
            del self.workers[worker_id]
            del self.worker_loads[worker_id]
            logger.info(f"Unregistered worker {worker_id}")
    
    def select_worker(self) -> Optional[str]:
        """Select a worker based on the current balancing strategy"""
        
        if not self.workers:
            return None
        
        # Filter active workers
        active_workers = {wid: worker for wid, worker in self.workers.items() 
                         if worker['active']}
        
        if not active_workers:
            return None
        
        strategy_func = self.strategies.get(self.balancing_strategy, self._round_robin_select)
        return strategy_func(active_workers)
    
    def _round_robin_select(self, active_workers: Dict[str, Dict]) -> str:
        """Round-robin worker selection"""
        
        worker_ids = list(active_workers.keys())
        selected_worker = worker_ids[self.current_worker_index % len(worker_ids)]
        self.current_worker_index += 1
        
        return selected_worker
    
    def _least_loaded_select(self, active_workers: Dict[str, Dict]) -> str:
        """Select worker with least load"""
        
        min_load = float('inf')
        selected_worker = None
        
        for worker_id in active_workers.keys():
            load = self.worker_loads.get(worker_id, 0)
            if load < min_load:
                min_load = load
                selected_worker = worker_id
        
        return selected_worker
    
    def _weighted_round_robin_select(self, active_workers: Dict[str, Dict]) -> str:
        """Weighted round-robin selection based on worker weights"""
        
        # Simple implementation: select based on weight probability
        total_weight = sum(worker['weight'] for worker in active_workers.values())
        
        import random
        rand_val = random.uniform(0, total_weight)
        cumulative_weight = 0
        
        for worker_id, worker in active_workers.items():
            cumulative_weight += worker['weight']
            if rand_val <= cumulative_weight:
                return worker_id
        
        # Fallback to first worker
        return list(active_workers.keys())[0]
    
    def _random_select(self, active_workers: Dict[str, Dict]) -> str:
        """Random worker selection"""
        
        import random
        return random.choice(list(active_workers.keys()))
    
    def update_worker_load(self, worker_id: str, load: int):
        """Update worker load information"""
        
        if worker_id in self.worker_loads:
            self.worker_loads[worker_id] = load
    
    def mark_worker_unhealthy(self, worker_id: str):
        """Mark a worker as unhealthy"""
        
        if worker_id in self.workers:
            self.workers[worker_id]['active'] = False
            logger.warning(f"Marked worker {worker_id} as unhealthy")
    
    def mark_worker_healthy(self, worker_id: str):
        """Mark a worker as healthy"""
        
        if worker_id in self.workers:
            self.workers[worker_id]['active'] = True
            self.workers[worker_id]['last_health_check'] = time.time()
            logger.info(f"Marked worker {worker_id} as healthy")
    
    async def start_health_checks(self, health_check_callback: Callable[[str], bool]):
        """Start periodic health checks for workers"""
        
        self.health_check_active = True
        
        while self.health_check_active:
            for worker_id in list(self.workers.keys()):
                try:
                    is_healthy = await asyncio.get_event_loop().run_in_executor(
                        None, health_check_callback, worker_id
                    )
                    
                    if is_healthy:
                        self.mark_worker_healthy(worker_id)
                    else:
                        self.mark_worker_unhealthy(worker_id)
                        
                except Exception as e:
                    logger.error(f"Health check failed for worker {worker_id}: {e}")
                    self.mark_worker_unhealthy(worker_id)
            
            await asyncio.sleep(self.health_check_interval)
    
    def stop_health_checks(self):
        """Stop health checks"""
        self.health_check_active = False
    
    def get_load_balancer_statistics(self) -> Dict[str, Any]:
        """Get load balancer statistics"""
        
        active_workers = sum(1 for w in self.workers.values() if w['active'])
        total_load = sum(self.worker_loads.values())
        
        return {
            "strategy": self.balancing_strategy,
            "total_workers": len(self.workers),
            "active_workers": active_workers,
            "total_load": total_load,
            "average_load": total_load / max(1, active_workers),
            "worker_details": {
                worker_id: {
                    "load": self.worker_loads.get(worker_id, 0),
                    "capacity": worker['capacity'],
                    "weight": worker['weight'],
                    "active": worker['active']
                }
                for worker_id, worker in self.workers.items()
            }
        }