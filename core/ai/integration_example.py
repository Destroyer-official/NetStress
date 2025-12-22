"""
Integration Example

Shows how to integrate the AI Orchestrator with the main DDoS framework.
This demonstrates the AI-driven attack optimization workflow.
"""

import asyncio
import logging
from typing import Dict, Any
from datetime import datetime

from .ai_orchestrator import ai_orchestrator, AIOptimizationResult

logger = logging.getLogger(__name__)

class AIEnhancedAttackEngine:
    """
    Example integration of AI Orchestrator with attack engine
    Demonstrates how to use AI for real-time attack optimization
    """
    
    def __init__(self):
        self.ai_orchestrator = ai_orchestrator
        self.current_params = {
            'packet_rate': 10000,
            'packet_size': 1000,
            'protocol': 'UDP',
            'burst_duration': 2.0,
            'pause_duration': 0.5,
            'concurrency': 100
        }
        self.optimization_interval = 30  # Optimize every 30 seconds
        self.last_optimization = None
        
    async def enhanced_attack_loop(self, target: str, port: int, duration: int):
        """
        Main attack loop with AI optimization
        """
        logger.info(f"Starting AI-enhanced attack on {target}:{port}")
        
        start_time = datetime.now()
        end_time = start_time.timestamp() + duration
        
        while datetime.now().timestamp() < end_time:
            try:
                # Simulate attack execution with current parameters
                attack_stats = await self._execute_attack_burst(target, port)
                
                # Simulate target response monitoring
                target_response = await self._monitor_target_response(target, port)
                
                # Simulate network conditions monitoring
                network_conditions = await self._monitor_network_conditions()
                
                # Check if it's time for AI optimization
                if self._should_optimize():
                    optimization_result = await self._optimize_with_ai(
                        attack_stats, target_response, network_conditions
                    )
                    
                    # Apply optimized parameters
                    self._apply_optimization(optimization_result)
                    
                    # Provide feedback to AI system
                    await self._provide_ai_feedback(optimization_result, attack_stats)
                
                # Wait before next iteration
                await asyncio.sleep(1.0)
                
            except Exception as e:
                logger.error(f"Error in attack loop: {e}")
                await asyncio.sleep(5.0)
        
        logger.info("AI-enhanced attack completed")
    
    async def _execute_attack_burst(self, target: str, port: int) -> Dict[str, Any]:
        """
        Simulate attack execution and return statistics
        In real implementation, this would execute actual attack vectors
        """
        
        # Simulate attack execution based on current parameters
        packet_rate = self.current_params['packet_rate']
        packet_size = self.current_params['packet_size']
        protocol = self.current_params['protocol']
        
        # Simulate some variability in results
        import random
        
        # Simulate packets sent
        packets_sent = packet_rate + random.randint(-1000, 1000)
        bytes_sent = packets_sent * packet_size
        
        # Simulate errors (higher rate for more aggressive attacks)
        error_rate = min(0.2, packet_rate / 100000.0)
        errors = int(packets_sent * error_rate * random.uniform(0.5, 1.5))
        
        # Simulate protocol-specific metrics
        protocol_metrics = {}
        if protocol == 'TCP':
            protocol_metrics.update({
                'tcp_syn_pps': packet_rate * 0.6,
                'tcp_ack_pps': packet_rate * 0.4,
                'connection_success_rate': max(0.1, 1.0 - error_rate)
            })
        elif protocol == 'UDP':
            protocol_metrics.update({
                'udp_pps': packet_rate,
                'udp_packet_loss': error_rate
            })
        elif protocol == 'HTTP':
            protocol_metrics.update({
                'http_rps': packet_rate // 10,  # HTTP requests are slower
                'http_error_rate': error_rate
            })
        
        attack_stats = {
            'pps': packet_rate,
            'bps': bytes_sent * 8,  # Convert to bits per second
            'packets_sent': packets_sent,
            'bytes_sent': bytes_sent,
            'errors': errors,
            'duration': 30.0,  # Simulated 30-second measurement
            'protocol': protocol,
            **protocol_metrics
        }
        
        return attack_stats
    
    async def _monitor_target_response(self, target: str, port: int) -> Dict[str, Any]:
        """
        Simulate target response monitoring
        In real implementation, this would probe target and analyze responses
        """
        
        import random
        
        # Simulate response characteristics
        base_response_time = 100  # Base 100ms response time
        
        # Simulate defense activation based on attack intensity
        attack_intensity = self.current_params['packet_rate'] / 50000.0
        defense_probability = min(0.8, attack_intensity)
        
        defense_active = random.random() < defense_probability
        
        if defense_active:
            # Simulate defense responses
            defense_type = random.choice(['rate_limiting', 'ip_blocking', 'waf', 'captcha'])
            
            response = {
                'response_time': base_response_time * random.uniform(2.0, 10.0),
                'status_code': random.choice([403, 429, 503]),
                'headers': {f'x-{defense_type}': 'active'},
                'connection_drops': random.randint(10, 100),
                'error_rate': random.uniform(0.3, 0.8),
                'defense_activity': random.uniform(0.7, 1.0),
                'detection_rate': random.uniform(0.5, 0.9)
            }
        else:
            # Normal response
            response = {
                'response_time': base_response_time * random.uniform(0.8, 1.5),
                'status_code': 200,
                'headers': {},
                'connection_drops': random.randint(0, 5),
                'error_rate': random.uniform(0.0, 0.1),
                'defense_activity': random.uniform(0.0, 0.3),
                'detection_rate': random.uniform(0.0, 0.2)
            }
        
        return response
    
    async def _monitor_network_conditions(self) -> Dict[str, Any]:
        """
        Simulate network conditions monitoring
        """
        
        import random
        
        return {
            'latency': random.uniform(10, 200),  # ms
            'packet_loss': random.uniform(0.0, 0.05),  # 0-5%
            'jitter': random.uniform(1, 20),  # ms
            'congestion_level': random.uniform(0.0, 0.8),
            'bandwidth_available': random.uniform(100, 1000)  # Mbps
        }
    
    def _should_optimize(self) -> bool:
        """Check if it's time for AI optimization"""
        
        if self.last_optimization is None:
            return True
        
        time_since_last = (datetime.now() - self.last_optimization).total_seconds()
        return time_since_last >= self.optimization_interval
    
    async def _optimize_with_ai(self, attack_stats: Dict[str, Any],
                              target_response: Dict[str, Any],
                              network_conditions: Dict[str, Any]) -> AIOptimizationResult:
        """
        Use AI Orchestrator to optimize attack parameters
        """
        
        logger.info("Requesting AI optimization...")
        
        # Call AI Orchestrator for optimization
        optimization_result = self.ai_orchestrator.optimize_attack_parameters(
            current_params=self.current_params,
            attack_stats=attack_stats,
            target_response=target_response,
            network_conditions=network_conditions
        )
        
        logger.info(f"AI optimization completed - Confidence: {optimization_result.confidence_score:.3f}, "
                   f"Predicted effectiveness: {optimization_result.predicted_effectiveness:.3f}")
        
        # Log recommendations
        for recommendation in optimization_result.recommendations:
            logger.info(f"AI Recommendation: {recommendation}")
        
        self.last_optimization = datetime.now()
        
        return optimization_result
    
    def _apply_optimization(self, optimization_result: AIOptimizationResult):
        """
        Apply AI-optimized parameters to attack configuration
        """
        
        if optimization_result.confidence_score < 0.3:
            logger.warning("Low confidence AI optimization - applying partial changes only")
            # Apply only high-confidence changes
            confidence_threshold = 0.5
        else:
            confidence_threshold = 0.0
        
        optimized_params = optimization_result.optimized_parameters
        
        # Apply optimizations with confidence weighting
        for param, new_value in optimized_params.items():
            if param in self.current_params:
                if optimization_result.confidence_score > confidence_threshold:
                    # High confidence - apply full optimization
                    self.current_params[param] = new_value
                    logger.info(f"Applied AI optimization: {param} = {new_value}")
                else:
                    # Low confidence - apply partial optimization
                    if isinstance(new_value, (int, float)) and isinstance(self.current_params[param], (int, float)):
                        # Weighted average for numerical parameters
                        weight = optimization_result.confidence_score
                        self.current_params[param] = int(
                            weight * new_value + (1 - weight) * self.current_params[param]
                        )
                        logger.info(f"Applied partial AI optimization: {param} = {self.current_params[param]}")
                    else:
                        # Keep original value for categorical parameters with low confidence
                        logger.info(f"Skipped low-confidence optimization for {param}")
    
    async def _provide_ai_feedback(self, optimization_result: AIOptimizationResult,
                                 actual_results: Dict[str, Any]):
        """
        Provide feedback to AI system about optimization performance
        """
        
        # Wait a bit to get results after applying optimization
        await asyncio.sleep(5.0)
        
        # Get updated attack results
        updated_results = await self._execute_attack_burst("target", 80)  # Simplified
        
        # Provide feedback to AI system
        self.ai_orchestrator.update_performance_feedback(optimization_result, updated_results)
        
        logger.info("Provided performance feedback to AI system")
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current attack status including AI information"""
        
        return {
            'current_parameters': self.current_params,
            'last_optimization': self.last_optimization.isoformat() if self.last_optimization else None,
            'ai_status': self.ai_orchestrator.get_ai_status(),
            'optimization_interval': self.optimization_interval
        }

# Example usage function
async def run_ai_enhanced_attack_example():
    """
    Example of running an AI-enhanced attack
    """
    
    logger.info("Starting AI-Enhanced Attack Example")
    
    # Create AI-enhanced attack engine
    attack_engine = AIEnhancedAttackEngine()
    
    # Run attack with AI optimization
    await attack_engine.enhanced_attack_loop(
        target="example.com",
        port=80,
        duration=120  # 2 minutes
    )
    
    # Get final status
    final_status = attack_engine.get_current_status()
    logger.info(f"Final attack status: {final_status}")
    
    # Validate AI models
    validation_results = attack_engine.ai_orchestrator.validate_ai_models()
    logger.info(f"AI model validation results: {validation_results}")

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Run the example
    asyncio.run(run_ai_enhanced_attack_example())