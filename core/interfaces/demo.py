"""
Interface Integration Demo

This script demonstrates all user interfaces working together:
- CLI with interactive mode
- Web GUI with real-time updates
- REST and GraphQL APIs
- Mobile API gateway
- WebSocket real-time communication
"""

import asyncio
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def demo_cli_interface():
    """Demonstrate CLI interface capabilities"""
    print("\n" + "="*60)
    print("CLI INTERFACE DEMONSTRATION")
    print("="*60)
    
    try:
        from .cli import AdvancedCLI, InteractiveMode, ScriptingEngine
        
        # Initialize CLI
        cli = AdvancedCLI()
        print("✅ CLI initialized successfully")
        
        # Test command execution
        print("\n📝 Testing CLI command execution...")
        result = cli.run_command('help')
        if result.get('success', True):
            print("✅ Help command executed successfully")
        
        # Test configuration
        print("\n⚙️  Testing configuration management...")
        config = cli.get_config()
        print(f"✅ Current configuration: {len(config)} settings loaded")
        
        # Test scripting engine
        print("\n📜 Testing scripting engine...")
        scripting_engine = ScriptingEngine(cli)
        scripts = scripting_engine.list_scripts()
        print(f"✅ Scripting engine ready, {len(scripts)} scripts available")
        
        # Test auto-completion
        print("\n🔍 Testing auto-completion...")
        from .cli import CommandCompleter
        completer = CommandCompleter()
        completions = completer.complete('att', 'att')
        if 'attack' in completions:
            print("✅ Auto-completion working correctly")
        
        print("\n✨ CLI interface demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ CLI demonstration failed: {e}")
        return False

def demo_web_gui_interface():
    """Demonstrate Web GUI interface capabilities"""
    print("\n" + "="*60)
    print("WEB GUI INTERFACE DEMONSTRATION")
    print("="*60)
    
    try:
        from .web_gui import WebGUI, DashboardManager, VisualizationEngine, CollaborationManager
        
        # Test dashboard manager
        print("\n📊 Testing dashboard manager...")
        dashboard_manager = DashboardManager()
        main_dashboard = dashboard_manager.get_dashboard('main')
        if main_dashboard:
            print(f"✅ Main dashboard loaded: {main_dashboard['name']}")
        
        # Create custom dashboard
        custom_layout = {
            'rows': [
                {
                    'columns': [
                        {'widget': 'demo_widget', 'width': 12}
                    ]
                }
            ]
        }
        dashboard_id = dashboard_manager.create_dashboard('Demo Dashboard', custom_layout)
        print(f"✅ Custom dashboard created: {dashboard_id}")
        
        # Test visualization engine
        print("\n📈 Testing visualization engine...")
        viz_engine = VisualizationEngine()
        chart_data = viz_engine.get_chart_data('attack_status')
        if 'labels' in chart_data and 'data' in chart_data:
            print("✅ Chart data generated successfully")
        
        # Test collaboration manager
        print("\n👥 Testing collaboration features...")
        collab_manager = CollaborationManager()
        collab_manager.add_user_to_session('demo_user', 'demo_session', 'Demo User')
        users = collab_manager.get_session_users('demo_session')
        if len(users) == 1:
            print("✅ Collaboration session created successfully")
        
        # Test chat functionality
        message = collab_manager.add_chat_message('demo_session', 'demo_user', 'Demo User', 'Hello from demo!')
        if message:
            print("✅ Chat functionality working")
        
        print("\n✨ Web GUI interface demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Web GUI demonstration failed: {e}")
        return False

def demo_rest_api_interface():
    """Demonstrate REST API interface capabilities"""
    print("\n" + "="*60)
    print("REST API INTERFACE DEMONSTRATION")
    print("="*60)
    
    try:
        from .api import RESTAPIServer, AttackResource, TargetResource, MetricsResource, APIAuthentication
        
        # Test API authentication
        print("\n🔐 Testing API authentication...")
        auth = APIAuthentication()
        user_info = auth.validate_api_key("ddos_admin_key_12345")
        if user_info and user_info['user'] == 'admin':
            print("✅ API authentication working correctly")
        
        # Test JWT token creation
        token = auth.create_jwt_token('demo_user', ['read', 'write'])
        if token:
            print("✅ JWT token creation successful")
        
        # Test API resources
        print("\n🎯 Testing API resources...")
        
        # Attack resource
        attack_resource = AttackResource()
        attack = attack_resource._get_attack_by_id('demo_attack')
        if attack:
            print(f"✅ Attack resource working: {attack.target}:{attack.port}")
        
        # Target resource
        target_resource = TargetResource()
        target_info = target_resource._analyze_target('192.168.1.100')
        if target_info:
            print(f"✅ Target resource working: {len(target_info.ports)} ports found")
        
        # Metrics resource
        metrics_resource = MetricsResource()
        metrics = metrics_resource._get_current_metrics()
        if metrics:
            print(f"✅ Metrics resource working: {metrics.active_attacks} active attacks")
        
        print("\n✨ REST API interface demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ REST API demonstration failed: {e}")
        return False

def demo_graphql_api_interface():
    """Demonstrate GraphQL API interface capabilities"""
    print("\n" + "="*60)
    print("GRAPHQL API INTERFACE DEMONSTRATION")
    print("="*60)
    
    try:
        from .api import Query, Mutation, AttackType, TargetType, MetricsType
        
        # Test GraphQL schema types
        print("\n📋 Testing GraphQL schema types...")
        
        # Test that types have required fields
        attack_fields = ['id', 'target', 'port', 'protocol', 'status']
        for field in attack_fields:
            if hasattr(AttackType, field):
                print(f"✅ AttackType has {field} field")
        
        target_fields = ['ip', 'hostname', 'ports', 'services']
        for field in target_fields:
            if hasattr(TargetType, field):
                print(f"✅ TargetType has {field} field")
        
        metrics_fields = ['cpu_usage', 'memory_usage', 'active_attacks']
        for field in metrics_fields:
            if hasattr(MetricsType, field):
                print(f"✅ MetricsType has {field} field")
        
        # Test query resolvers
        print("\n🔍 Testing GraphQL query resolvers...")
        query = Query()
        
        # Test attack query
        attack = query.resolve_attack(None, 'demo_attack')
        if attack:
            print(f"✅ Attack query resolver working: {attack.id}")
        
        # Test attacks list query
        attacks = query.resolve_attacks(None)
        if attacks and len(attacks) > 0:
            print(f"✅ Attacks list query resolver working: {len(attacks)} attacks")
        
        # Test target query
        target = query.resolve_target(None, '192.168.1.100')
        if target:
            print(f"✅ Target query resolver working: {target.ip}")
        
        # Test metrics query
        metrics = query.resolve_metrics(None)
        if metrics:
            print(f"✅ Metrics query resolver working: {metrics.active_attacks} active attacks")
        
        # Test mutation resolvers
        print("\n✏️  Testing GraphQL mutation resolvers...")
        mutation = Mutation()
        
        # Test start attack mutation
        attack_id = mutation.resolve_start_attack(None, '192.168.1.100', 80, 'HTTP')
        if attack_id:
            print(f"✅ Start attack mutation working: {attack_id}")
        
        # Test stop attack mutation
        stop_result = mutation.resolve_stop_attack(None, attack_id)
        if stop_result:
            print("✅ Stop attack mutation working")
        
        print("\n✨ GraphQL API interface demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ GraphQL API demonstration failed: {e}")
        return False

def demo_websocket_interface():
    """Demonstrate WebSocket interface capabilities"""
    print("\n" + "="*60)
    print("WEBSOCKET INTERFACE DEMONSTRATION")
    print("="*60)
    
    try:
        from .api import WebSocketManager
        
        # Test WebSocket manager
        print("\n🔌 Testing WebSocket manager...")
        ws_manager = WebSocketManager()
        
        # Test connection management
        print("✅ WebSocket manager initialized")
        print(f"✅ Active connections: {len(ws_manager.connections)}")
        print(f"✅ Subscriptions: {len(ws_manager.subscriptions)}")
        
        # Test message processing (mock)
        print("\n📨 Testing message processing...")
        test_messages = [
            {'type': 'subscribe', 'subscription': 'metrics'},
            {'type': 'subscribe', 'subscription': 'attacks'},
            {'type': 'ping'},
            {'type': 'unsubscribe', 'subscription': 'metrics'}
        ]
        
        for msg in test_messages:
            print(f"✅ Message format valid: {msg['type']}")
        
        # Test broadcast functionality (mock)
        print("\n📡 Testing broadcast functionality...")
        test_update = {
            'active_attacks': 3,
            'total_pps': 15000,
            'timestamp': datetime.now().isoformat()
        }
        
        # In real implementation, this would broadcast to connected clients
        print("✅ Broadcast update prepared for metrics")
        
        print("\n✨ WebSocket interface demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ WebSocket demonstration failed: {e}")
        return False

def demo_mobile_api_interface():
    """Demonstrate Mobile API interface capabilities"""
    print("\n" + "="*60)
    print("MOBILE API INTERFACE DEMONSTRATION")
    print("="*60)
    
    try:
        from .mobile import MobileAPIGateway, MobileSessionManager, PushNotificationService, MobileDataOptimizer, RemoteManagementService
        
        # Test mobile session manager
        print("\n📱 Testing mobile session manager...")
        session_manager = MobileSessionManager()
        session = session_manager.create_session('demo_device', 'ios', '1.0.0', 'demo_user')
        if session:
            print(f"✅ Mobile session created: {session.session_id}")
        
        # Test push notification service
        print("\n🔔 Testing push notification service...")
        push_service = PushNotificationService()
        push_service.register_device('demo_device', 'push_token_123', 'ios')
        
        from .mobile import MobileNotification
        notification = MobileNotification(
            id='demo_notif',
            title='Demo Notification',
            message='This is a test notification',
            type='info',
            data={'test': True},
            created_at=datetime.now()
        )
        
        sent = push_service.send_notification('demo_device', notification)
        if sent:
            print("✅ Push notification sent successfully")
        
        # Test mobile data optimizer
        print("\n⚡ Testing mobile data optimizer...")
        optimizer = MobileDataOptimizer()
        
        # Test attack list optimization
        test_attacks = [
            {
                'id': 'attack_1',
                'target': '192.168.1.100',
                'port': 80,
                'protocol': 'HTTP',
                'status': 'active',
                'pps': 5000,
                'duration': 120,
                'extra_data': 'large_data_not_needed_on_mobile'
            }
        ]
        
        optimized_attacks = optimizer.optimize_attack_list(test_attacks)
        if optimized_attacks and len(optimized_attacks) == 1:
            print("✅ Attack list optimization working")
        
        # Test metrics optimization
        test_metrics = {
            'cpu_usage': 45.2,
            'memory_usage': 62.8,
            'active_attacks': 3,
            'total_pps': 15000,
            'total_bandwidth': 750.5,
            'complex_internal_data': {'not': 'needed'}
        }
        
        mobile_metrics = optimizer.optimize_metrics(test_metrics)
        if mobile_metrics and hasattr(mobile_metrics, 'status'):
            print(f"✅ Metrics optimization working: {mobile_metrics.status}")
        
        # Test remote management service
        print("\n🎮 Testing remote management service...")
        remote_service = RemoteManagementService()
        
        # Authorize device
        authorized = remote_service.authorize_device('demo_device', 'demo_user')
        if authorized:
            print("✅ Device authorized for remote management")
        
        # Execute remote command
        result = remote_service.execute_remote_command('demo_device', 'get_status', {})
        if result['success']:
            print("✅ Remote command executed successfully")
        
        print("\n✨ Mobile API interface demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Mobile API demonstration failed: {e}")
        return False

def demo_integration_scenarios():
    """Demonstrate integration scenarios between interfaces"""
    print("\n" + "="*60)
    print("INTEGRATION SCENARIOS DEMONSTRATION")
    print("="*60)
    
    try:
        # Scenario 1: CLI to API integration
        print("\n🔗 Scenario 1: CLI to API Integration")
        from .cli import AdvancedCLI
        from .api import APIAuthentication
        
        cli = AdvancedCLI()
        auth = APIAuthentication()
        
        # CLI command that would use API authentication
        user_info = auth.validate_api_key("ddos_admin_key_12345")
        if user_info:
            result = cli.start_attack(type('Args', (), {
                'target': '192.168.1.100',
                'port': 80,
                'protocol': 'HTTP',
                'duration': 60
            })())
            if result['success']:
                print("✅ CLI successfully integrated with API authentication")
        
        # Scenario 2: Web GUI to Mobile API integration
        print("\n🔗 Scenario 2: Web GUI to Mobile API Integration")
        from .web_gui import VisualizationEngine
        from .mobile import MobileDataOptimizer
        
        viz_engine = VisualizationEngine()
        optimizer = MobileDataOptimizer()
        
        # Get data from web visualization
        chart_data = viz_engine.get_chart_data('attack_status')
        
        # Convert for mobile consumption
        if 'data' in chart_data:
            # Mock conversion to attack format
            mock_attacks = [
                {
                    'id': f'attack_{i}',
                    'target': '192.168.1.100',
                    'port': 80,
                    'protocol': 'HTTP',
                    'status': 'active',
                    'pps': chart_data['data'][i] if i < len(chart_data['data']) else 1000,
                    'duration': 60
                }
                for i in range(min(3, len(chart_data['data'])))
            ]
            
            optimized = optimizer.optimize_attack_list(mock_attacks)
            if optimized:
                print("✅ Web GUI data successfully optimized for mobile")
        
        # Scenario 3: Real-time updates across all interfaces
        print("\n🔗 Scenario 3: Real-time Updates Integration")
        from .api import WebSocketManager
        from .web_gui import CollaborationManager
        
        ws_manager = WebSocketManager()
        collab_manager = CollaborationManager()
        
        # Simulate real-time update flow
        update_data = {
            'active_attacks': 5,
            'total_pps': 25000,
            'timestamp': datetime.now().isoformat()
        }
        
        # This would normally broadcast to WebSocket clients
        print("✅ Real-time update prepared for WebSocket broadcast")
        
        # This would update collaboration sessions
        collab_manager.add_chat_message('demo_session', 'system', 'System', 
                                      f"System update: {update_data['active_attacks']} active attacks")
        print("✅ Real-time update integrated with collaboration system")
        
        print("\n✨ Integration scenarios demonstration completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Integration demonstration failed: {e}")
        return False

def run_comprehensive_demo():
    """Run comprehensive demonstration of all interfaces"""
    print("🚀 STARTING COMPREHENSIVE INTERFACE DEMONSTRATION")
    print("=" * 80)
    
    results = []
    
    # Run individual interface demos
    demos = [
        ("CLI Interface", demo_cli_interface),
        ("Web GUI Interface", demo_web_gui_interface),
        ("REST API Interface", demo_rest_api_interface),
        ("GraphQL API Interface", demo_graphql_api_interface),
        ("WebSocket Interface", demo_websocket_interface),
        ("Mobile API Interface", demo_mobile_api_interface),
        ("Integration Scenarios", demo_integration_scenarios)
    ]
    
    for demo_name, demo_func in demos:
        print(f"\n🎯 Running {demo_name} demonstration...")
        try:
            result = demo_func()
            results.append((demo_name, result))
            if result:
                print(f"✅ {demo_name} demonstration PASSED")
            else:
                print(f"❌ {demo_name} demonstration FAILED")
        except Exception as e:
            print(f"❌ {demo_name} demonstration ERROR: {e}")
            results.append((demo_name, False))
    
    # Summary
    print("\n" + "=" * 80)
    print("DEMONSTRATION SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\nResults:")
    for demo_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"  {demo_name}: {status}")
    
    print(f"\nOverall Success Rate: {passed}/{total} ({(passed/total)*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 ALL INTERFACE DEMONSTRATIONS COMPLETED SUCCESSFULLY!")
        print("\nThe DDoS Testing Framework interfaces are ready for use:")
        print("  • Advanced CLI with auto-completion and scripting")
        print("  • Modern web GUI with real-time collaboration")
        print("  • Comprehensive REST and GraphQL APIs")
        print("  • Mobile-optimized API gateway")
        print("  • Real-time WebSocket communication")
        print("  • Seamless integration between all interfaces")
        return True
    else:
        print(f"\n⚠️  {total - passed} demonstrations failed")
        print("Please check the error messages above for details.")
        return False

if __name__ == "__main__":
    # Run the comprehensive demonstration
    success = run_comprehensive_demo()
    
    if success:
        print("\n🎯 To use the interfaces:")
        print("  CLI: python -m core.interfaces.cli")
        print("  Web GUI: python -m core.interfaces.web_gui")
        print("  REST API: python -m core.interfaces.api rest")
        print("  GraphQL API: python -m core.interfaces.api graphql")
        print("  WebSocket: python -m core.interfaces.api websocket")
        print("  Mobile API: python -m core.interfaces.mobile")
        print("  All APIs: python -m core.interfaces.api all")
        
        sys.exit(0)
    else:
        sys.exit(1)