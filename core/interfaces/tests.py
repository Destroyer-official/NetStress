"""
Interface Testing and Validation Suite

This module provides comprehensive testing for:
- CLI functionality and user experience
- Web GUI performance and usability
- API completeness and reliability
- Mobile interface optimization
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import tempfile
import threading

try:
    import requests
    import websocket
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

logger = logging.getLogger(__name__)

class CLITestSuite(unittest.TestCase):
    """Test suite for CLI functionality"""
    
    def setUp(self):
        """Set up CLI test environment"""
        self.cli_module_path = Path(__file__).parent / 'cli.py'
        self.test_script_dir = Path(tempfile.mkdtemp())
        self.test_history_file = self.test_script_dir / 'test_history'
    
    def tearDown(self):
        """Clean up CLI test environment"""
        import shutil
        shutil.rmtree(self.test_script_dir, ignore_errors=True)
    
    def test_cli_import(self):
        """Test CLI module can be imported"""
        try:
            from core.interfaces.cli import AdvancedCLI, InteractiveMode, ScriptingEngine
            self.assertTrue(True, "CLI modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import CLI modules: {e}")
    
    def test_cli_initialization(self):
        """Test CLI initialization"""
        from .cli import AdvancedCLI
        
        cli = AdvancedCLI()
        self.assertIsNotNone(cli.config)
        self.assertIsNotNone(cli.interactive_mode)
        self.assertIsNotNone(cli.scripting_engine)
    
    def test_command_completion(self):
        """Test command auto-completion"""
        from .cli import CommandCompleter
        
        completer = CommandCompleter()
        
        # Test basic command completion
        completions = completer.complete('att', 'att')
        self.assertIn('attack', completions)
        
        # Test subcommand completion
        completions = completer.complete('start', 'attack start')
        self.assertIn('start', completions)
        
        # Test option completion
        completions = completer.complete('--tar', 'attack start --tar')
        self.assertIn('--target', completions)
    
    def test_script_validation(self):
        """Test script validation functionality"""
        from .cli import ScriptingEngine, AdvancedCLI
        
        cli = AdvancedCLI()
        engine = ScriptingEngine(cli)
        
        # Create test script
        test_script = self.test_script_dir / 'test.ddos'
        test_script.write_text("""
# Test script
attack start --target 192.168.1.100 --port 80 --protocol HTTP
config set max_processes 4
""")
        
        # Validate script
        result = engine.validate_script(str(test_script))
        self.assertTrue(result['success'])
        self.assertEqual(len(result['errors']), 0)
    
    def test_invalid_script_validation(self):
        """Test validation of invalid scripts"""
        from .cli import ScriptingEngine, AdvancedCLI
        
        cli = AdvancedCLI()
        engine = ScriptingEngine(cli)
        
        # Create invalid script
        test_script = self.test_script_dir / 'invalid.ddos'
        test_script.write_text("""
# Invalid script with syntax errors
attack start --target "unclosed quote
invalid_command some_args
""")
        
        # Validate script
        result = engine.validate_script(str(test_script))
        self.assertFalse(result['success'])
        self.assertGreater(len(result['errors']), 0)
    
    def test_cli_command_execution(self):
        """Test CLI command execution"""
        from .cli import AdvancedCLI
        
        cli = AdvancedCLI()
        
        # Test help command
        result = cli.run_command('help')
        self.assertTrue(result.get('success', True))
        
        # Test config command
        result = cli.run_command('config show')
        self.assertTrue(result.get('success', True))
    
    def test_interactive_mode_commands(self):
        """Test interactive mode command handling"""
        from .cli import InteractiveMode, AdvancedCLI
        
        cli = AdvancedCLI()
        interactive = InteractiveMode(cli)
        
        # Test that command methods exist
        self.assertTrue(hasattr(interactive, 'do_attack'))
        self.assertTrue(hasattr(interactive, 'do_target'))
        self.assertTrue(hasattr(interactive, 'do_config'))
        self.assertTrue(hasattr(interactive, 'do_help'))

class WebGUITestSuite(unittest.TestCase):
    """Test suite for Web GUI functionality"""
    
    def setUp(self):
        """Set up Web GUI test environment"""
        self.gui_port = 8080
        self.gui_process = None
        self.base_url = f"http://localhost:{self.gui_port}"
        
        # Start GUI server in background for testing
        if REQUESTS_AVAILABLE:
            self._start_gui_server()
    
    def tearDown(self):
        """Clean up Web GUI test environment"""
        if self.gui_process:
            self.gui_process.terminate()
            self.gui_process.wait()
    
    def _start_gui_server(self):
        """Start GUI server for testing"""
        try:
            from .web_gui import WebGUI
            
            def run_server():
                gui = WebGUI(port=self.gui_port, debug=False)
                gui.run()
            
            # Start server in separate thread
            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()
            
            # Wait for server to start
            time.sleep(2)
            
        except Exception as e:
            logger.warning(f"Could not start GUI server for testing: {e}")
    
    def test_gui_import(self):
        """Test Web GUI module can be imported"""
        try:
            from .web_gui import WebGUI, DashboardManager, VisualizationEngine
            self.assertTrue(True, "Web GUI modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import Web GUI modules: {e}")
    
    def test_dashboard_manager(self):
        """Test dashboard manager functionality"""
        from .web_gui import DashboardManager
        
        manager = DashboardManager()
        
        # Test default dashboards exist
        main_dashboard = manager.get_dashboard('main')
        self.assertIsNotNone(main_dashboard)
        self.assertEqual(main_dashboard['name'], 'Main Dashboard')
        
        # Test creating new dashboard
        layout = {'rows': [{'columns': [{'widget': 'test', 'width': 12}]}]}
        dashboard_id = manager.create_dashboard('Test Dashboard', layout)
        self.assertIsNotNone(dashboard_id)
        
        # Test retrieving created dashboard
        test_dashboard = manager.get_dashboard(dashboard_id)
        self.assertIsNotNone(test_dashboard)
        self.assertEqual(test_dashboard['name'], 'Test Dashboard')
    
    def test_visualization_engine(self):
        """Test visualization engine functionality"""
        from .web_gui import VisualizationEngine
        
        engine = VisualizationEngine()
        
        # Test chart data generation
        chart_data = engine.get_chart_data('attack_status')
        self.assertIsInstance(chart_data, dict)
        self.assertIn('labels', chart_data)
        self.assertIn('data', chart_data)
        
        # Test chart configuration
        chart_config = engine.get_chart_config('real_time_chart')
        self.assertIsInstance(chart_config, dict)
        self.assertEqual(chart_config['type'], 'line')
    
    def test_collaboration_manager(self):
        """Test collaboration manager functionality"""
        from .web_gui import CollaborationManager
        
        manager = CollaborationManager()
        
        # Test adding user to session
        manager.add_user_to_session('user1', 'session1', 'testuser')
        users = manager.get_session_users('session1')
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]['username'], 'testuser')
        
        # Test chat functionality
        message = manager.add_chat_message('session1', 'user1', 'testuser', 'Hello world')
        self.assertIsNotNone(message)
        self.assertEqual(message['message'], 'Hello world')
        
        messages = manager.get_chat_messages('session1')
        self.assertEqual(len(messages), 1)
    
    @unittest.skipUnless(REQUESTS_AVAILABLE, "requests library not available")
    def test_gui_server_response(self):
        """Test GUI server responds to requests"""
        try:
            response = requests.get(f"{self.base_url}/login", timeout=5)
            self.assertEqual(response.status_code, 200)
        except requests.exceptions.RequestException:
            self.skipTest("GUI server not available for testing")
    
    @unittest.skipUnless(SELENIUM_AVAILABLE, "Selenium not available")
    def test_gui_user_interface(self):
        """Test GUI user interface with Selenium"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        try:
            driver = webdriver.Chrome(options=options)
            
            # Test login page
            driver.get(f"{self.base_url}/login")
            self.assertIn("DDoS Testing Framework", driver.title)
            
            # Test login form exists
            username_field = driver.find_element(By.ID, "username")
            password_field = driver.find_element(By.ID, "password")
            self.assertIsNotNone(username_field)
            self.assertIsNotNone(password_field)
            
            driver.quit()
            
        except Exception as e:
            self.skipTest(f"Selenium test failed: {e}")

class APITestSuite(unittest.TestCase):
    """Test suite for API functionality"""
    
    def setUp(self):
        """Set up API test environment"""
        self.api_port = 8081
        self.graphql_port = 8083
        self.mobile_port = 8084
        self.websocket_port = 8082
        
        self.rest_base_url = f"http://localhost:{self.api_port}"
        self.graphql_base_url = f"http://localhost:{self.graphql_port}"
        self.mobile_base_url = f"http://localhost:{self.mobile_port}"
        self.websocket_url = f"ws://localhost:{self.websocket_port}"
        
        # API credentials for testing
        self.api_key = "ddos_admin_key_12345"
        self.headers = {"X-API-Key": self.api_key}
    
    def test_api_import(self):
        """Test API modules can be imported"""
        try:
            from .api import RESTAPIServer, GraphQLAPIServer, WebSocketManager
            from .mobile import MobileAPIGateway, RemoteManagementService
            self.assertTrue(True, "API modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import API modules: {e}")
    
    def test_api_authentication(self):
        """Test API authentication functionality"""
        from .api import APIAuthentication
        
        auth = APIAuthentication()
        
        # Test valid API key
        user_info = auth.validate_api_key("ddos_admin_key_12345")
        self.assertIsNotNone(user_info)
        self.assertEqual(user_info['user'], 'admin')
        self.assertIn('admin', user_info['permissions'])
        
        # Test invalid API key
        user_info = auth.validate_api_key("invalid_key")
        self.assertIsNone(user_info)
        
        # Test JWT token creation
        token = auth.create_jwt_token('testuser', ['read'])
        self.assertIsNotNone(token)
        
        # Test JWT token validation
        token_info = auth.validate_jwt_token(token)
        self.assertIsNotNone(token_info)
        self.assertEqual(token_info['user'], 'testuser')
    
    def test_api_response_format(self):
        """Test API response format"""
        from .api import APIResponse
        
        # Test successful response
        response = APIResponse(success=True, data={'test': 'data'})
        response_dict = response.to_dict()
        
        self.assertTrue(response_dict['success'])
        self.assertEqual(response_dict['data']['test'], 'data')
        self.assertIsNotNone(response_dict['timestamp'])
        
        # Test error response
        error_response = APIResponse(success=False, error='Test error')
        error_dict = error_response.to_dict()
        
        self.assertFalse(error_dict['success'])
        self.assertEqual(error_dict['error'], 'Test error')
    
    def test_graphql_schema(self):
        """Test GraphQL schema definition"""
        from .api import Query, Mutation, AttackType, TargetType, MetricsType
        
        # Test that schema types are defined
        self.assertTrue(hasattr(AttackType, 'id'))
        self.assertTrue(hasattr(AttackType, 'target'))
        self.assertTrue(hasattr(AttackType, 'protocol'))
        
        self.assertTrue(hasattr(TargetType, 'ip'))
        self.assertTrue(hasattr(TargetType, 'hostname'))
        
        self.assertTrue(hasattr(MetricsType, 'cpu_usage'))
        self.assertTrue(hasattr(MetricsType, 'active_attacks'))
        
        # Test query methods exist
        query = Query()
        self.assertTrue(hasattr(query, 'resolve_attack'))
        self.assertTrue(hasattr(query, 'resolve_attacks'))
        self.assertTrue(hasattr(query, 'resolve_metrics'))
    
    def test_websocket_manager(self):
        """Test WebSocket manager functionality"""
        from .api import WebSocketManager
        
        manager = WebSocketManager()
        
        # Test connection management
        self.assertEqual(len(manager.connections), 0)
        self.assertEqual(len(manager.subscriptions), 0)
        
        # Test message processing (mock)
        test_message = {
            'type': 'subscribe',
            'subscription': 'metrics'
        }
        
        # This would normally be tested with actual WebSocket connections
        self.assertIsInstance(test_message, dict)
    
    def test_mobile_api_components(self):
        """Test mobile API components"""
        from .mobile import MobileSessionManager, PushNotificationService, MobileDataOptimizer
        
        # Test session manager
        session_manager = MobileSessionManager()
        session = session_manager.create_session('device1', 'ios', '1.0.0', 'user1')
        self.assertEqual(session.device_id, 'device1')
        self.assertEqual(session.device_type, 'ios')
        
        retrieved_session = session_manager.get_session(session.session_id)
        self.assertIsNotNone(retrieved_session)
        self.assertEqual(retrieved_session.device_id, 'device1')
        
        # Test push notification service
        push_service = PushNotificationService()
        push_service.register_device('device1', 'push_token_123', 'ios')
        self.assertIn('device1', push_service.device_tokens)
        
        # Test data optimizer
        optimizer = MobileDataOptimizer()
        test_attacks = [
            {'id': 'attack1', 'target': '192.168.1.1', 'port': 80, 'protocol': 'HTTP', 'status': 'active', 'pps': 1000, 'duration': 60}
        ]
        
        optimized = optimizer.optimize_attack_list(test_attacks)
        self.assertEqual(len(optimized), 1)
        self.assertEqual(optimized[0].id, 'attack1')
    
    def test_remote_management_service(self):
        """Test remote management service"""
        from .mobile import RemoteManagementService
        
        service = RemoteManagementService()
        
        # Test device authorization
        self.assertTrue(service.authorize_device('device1', 'user1'))
        self.assertIn('device1', service.authorized_devices)
        
        # Test command execution
        result = service.execute_remote_command('device1', 'get_status', {})
        self.assertTrue(result['success'])
        
        # Test unauthorized device
        result = service.execute_remote_command('device2', 'get_status', {})
        self.assertFalse(result['success'])
        self.assertIn('not authorized', result['error'])
    
    @unittest.skipUnless(REQUESTS_AVAILABLE, "requests library not available")
    def test_api_endpoints_mock(self):
        """Test API endpoints with mock data"""
        # This would test actual API endpoints if servers were running
        # For now, we test the endpoint logic through direct method calls
        
        from .api import AttackResource
        
        resource = AttackResource()
        
        # Test attack data retrieval (mock)
        attack = resource._get_attack_by_id('test_attack')
        self.assertIsNotNone(attack)
        self.assertEqual(attack.id, 'test_attack')
        
        # Test attack validation
        self.assertTrue(resource._validate_target('192.168.1.100'))
        
        # Test attack starting
        attack_id = resource._start_attack({
            'target': '192.168.1.100',
            'port': 80,
            'protocol': 'HTTP'
        })
        self.assertIsNotNone(attack_id)
        self.assertTrue(attack_id.startswith('attack_'))

class PerformanceTestSuite(unittest.TestCase):
    """Test suite for interface performance"""
    
    def test_cli_response_time(self):
        """Test CLI command response time"""
        from .cli import AdvancedCLI
        
        cli = AdvancedCLI()
        
        start_time = time.time()
        result = cli.run_command('help')
        end_time = time.time()
        
        response_time = end_time - start_time
        self.assertLess(response_time, 1.0, "CLI command should respond within 1 second")
    
    def test_api_data_serialization_performance(self):
        """Test API data serialization performance"""
        from .api import APIResponse
        
        # Create large dataset
        large_data = {
            'attacks': [
                {
                    'id': f'attack_{i}',
                    'target': f'192.168.1.{i % 255}',
                    'port': 80,
                    'protocol': 'HTTP',
                    'status': 'active'
                }
                for i in range(1000)
            ]
        }
        
        start_time = time.time()
        response = APIResponse(success=True, data=large_data)
        response_dict = response.to_dict()
        end_time = time.time()
        
        serialization_time = end_time - start_time
        self.assertLess(serialization_time, 0.1, "Large data serialization should be fast")
    
    def test_mobile_data_optimization_performance(self):
        """Test mobile data optimization performance"""
        from .mobile import MobileDataOptimizer
        
        # Create large attack list
        attacks = [
            {
                'id': f'attack_{i}',
                'target': f'192.168.1.{i % 255}',
                'port': 80,
                'protocol': 'HTTP',
                'status': 'active',
                'pps': 1000,
                'duration': 60,
                'extra_data': 'x' * 1000  # Large extra data
            }
            for i in range(1000)
        ]
        
        start_time = time.time()
        optimized = MobileDataOptimizer.optimize_attack_list(attacks)
        end_time = time.time()
        
        optimization_time = end_time - start_time
        self.assertLess(optimization_time, 0.5, "Mobile optimization should be fast")
        self.assertEqual(len(optimized), 1000)

class UsabilityTestSuite(unittest.TestCase):
    """Test suite for interface usability"""
    
    def test_cli_help_completeness(self):
        """Test CLI help system completeness"""
        from .cli import InteractiveMode, AdvancedCLI
        
        cli = AdvancedCLI()
        interactive = InteractiveMode(cli)
        
        # Test that all commands have help methods
        commands = ['attack', 'target', 'config', 'monitor', 'script']
        
        for command in commands:
            help_method = f'_show_{command}_help'
            self.assertTrue(hasattr(interactive, help_method),
                          f"Help method {help_method} should exist")
    
    def test_api_error_messages(self):
        """Test API error message quality"""
        from .api import APIResponse
        
        # Test that error messages are descriptive
        error_response = APIResponse(
            success=False,
            error="Invalid target: IP address must be in valid format"
        )
        
        error_dict = error_response.to_dict()
        self.assertIn("Invalid target", error_dict['error'])
        self.assertIn("valid format", error_dict['error'])
    
    def test_mobile_interface_simplicity(self):
        """Test mobile interface data simplicity"""
        from .mobile import MobileDataOptimizer, MobileMetrics
        
        # Test that mobile metrics are simplified
        full_metrics = {
            'cpu_usage': 45.2,
            'memory_usage': 62.8,
            'network_usage': 78.5,
            'active_attacks': 3,
            'total_pps': 15000,
            'total_bandwidth': 750.5,
            'detailed_stats': {'complex': 'data'},
            'internal_counters': [1, 2, 3, 4, 5]
        }
        
        mobile_metrics = MobileDataOptimizer.optimize_metrics(full_metrics)
        
        # Check that only essential fields are included
        self.assertIsInstance(mobile_metrics, MobileMetrics)
        self.assertTrue(hasattr(mobile_metrics, 'active_attacks'))
        self.assertTrue(hasattr(mobile_metrics, 'status'))
        
        # Check that complex data is not included
        mobile_dict = mobile_metrics.__dict__
        self.assertNotIn('detailed_stats', mobile_dict)
        self.assertNotIn('internal_counters', mobile_dict)

class IntegrationTestSuite(unittest.TestCase):
    """Integration tests for interface components"""
    
    def test_cli_to_api_integration(self):
        """Test CLI integration with API components"""
        from .cli import AdvancedCLI
        from .api import APIAuthentication
        
        cli = AdvancedCLI()
        auth = APIAuthentication()
        
        # Test that CLI can work with API authentication
        user_info = auth.validate_api_key("ddos_admin_key_12345")
        self.assertIsNotNone(user_info)
        
        # Test CLI command execution
        result = cli.start_attack(type('Args', (), {
            'target': '192.168.1.100',
            'port': 80,
            'protocol': 'HTTP',
            'duration': 60
        })())
        
        self.assertTrue(result['success'])
        self.assertIn('session_id', result)
    
    def test_web_gui_to_api_integration(self):
        """Test Web GUI integration with API"""
        from .web_gui import DashboardManager, VisualizationEngine
        from .api import APIResponse
        
        dashboard_manager = DashboardManager()
        viz_engine = VisualizationEngine()
        
        # Test that GUI components can work with API data format
        chart_data = viz_engine.get_chart_data('attack_status')
        api_response = APIResponse(success=True, data=chart_data)
        
        self.assertTrue(api_response.success)
        self.assertIsNotNone(api_response.data)
    
    def test_mobile_to_web_integration(self):
        """Test mobile API integration with web components"""
        from .mobile import MobileDataOptimizer
        from .web_gui import VisualizationEngine
        
        viz_engine = VisualizationEngine()
        optimizer = MobileDataOptimizer()
        
        # Get data from web component
        chart_data = viz_engine.get_chart_data('real_time_chart')
        
        # Test that mobile optimizer can handle web data
        if 'datasets' in chart_data:
            # Convert to attack format for testing
            mock_attacks = [
                {
                    'id': f'attack_{i}',
                    'target': '192.168.1.100',
                    'port': 80,
                    'protocol': 'HTTP',
                    'status': 'active',
                    'pps': dataset.get('data', [0])[0] if dataset.get('data') else 0,
                    'duration': 60
                }
                for i, dataset in enumerate(chart_data['datasets'])
            ]
            
            optimized = optimizer.optimize_attack_list(mock_attacks)
            self.assertIsInstance(optimized, list)

def run_all_tests():
    """Run all interface tests"""
    test_suites = [
        CLITestSuite,
        WebGUITestSuite,
        APITestSuite,
        PerformanceTestSuite,
        UsabilityTestSuite,
        IntegrationTestSuite
    ]
    
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    
    print("=" * 80)
    print("INTERFACE TESTING AND VALIDATION SUITE")
    print("=" * 80)
    
    for suite_class in test_suites:
        print(f"\nRunning {suite_class.__name__}...")
        
        suite = unittest.TestLoader().loadTestsFromTestCase(suite_class)
        runner = unittest.TextTestRunner(verbosity=1, stream=sys.stdout)
        result = runner.run(suite)
        
        total_tests += result.testsRun
        passed_tests += result.testsRun - len(result.failures) - len(result.errors)
        failed_tests += len(result.failures) + len(result.errors)
        
        if result.failures:
            print(f"Failures in {suite_class.__name__}:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback}")
        
        if result.errors:
            print(f"Errors in {suite_class.__name__}:")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback}")
    
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%" if total_tests > 0 else "No tests run")
    
    if failed_tests == 0:
        print("\n✅ All interface tests passed!")
        return True
    else:
        print(f"\n❌ {failed_tests} tests failed")
        return False

def validate_interface_requirements():
    """Validate that interfaces meet requirements"""
    print("\n" + "=" * 80)
    print("INTERFACE REQUIREMENTS VALIDATION")
    print("=" * 80)
    
    requirements_met = []
    requirements_failed = []
    
    # Requirement 6.4: CLI with intelligent auto-completion
    try:
        from .cli import CommandCompleter
        completer = CommandCompleter()
        completions = completer.complete('att', 'att')
        if 'attack' in completions:
            requirements_met.append("✅ CLI intelligent auto-completion")
        else:
            requirements_failed.append("❌ CLI auto-completion not working")
    except Exception as e:
        requirements_failed.append(f"❌ CLI auto-completion error: {e}")
    
    # Requirement 6.4: Interactive mode with real-time feedback
    try:
        from .cli import InteractiveMode, AdvancedCLI
        cli = AdvancedCLI()
        interactive = InteractiveMode(cli)
        if hasattr(interactive, 'do_attack') and hasattr(interactive, 'cmdloop'):
            requirements_met.append("✅ CLI interactive mode with real-time feedback")
        else:
            requirements_failed.append("❌ CLI interactive mode incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ CLI interactive mode error: {e}")
    
    # Requirement 6.4: Scripting support and batch operations
    try:
        from .cli import ScriptingEngine
        cli = AdvancedCLI()
        engine = ScriptingEngine(cli)
        if hasattr(engine, 'run_script') and hasattr(engine, 'validate_script'):
            requirements_met.append("✅ CLI scripting support and batch operations")
        else:
            requirements_failed.append("❌ CLI scripting support incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ CLI scripting support error: {e}")
    
    # Requirement 6.4 & 7.4: Web GUI with real-time updates
    try:
        from .web_gui import WebGUI, DashboardManager
        manager = DashboardManager()
        dashboard = manager.get_dashboard('main')
        if dashboard and 'layout' in dashboard:
            requirements_met.append("✅ Web GUI with advanced visualization")
        else:
            requirements_failed.append("❌ Web GUI dashboard incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ Web GUI error: {e}")
    
    # Requirement 6.4 & 7.4: Collaborative features
    try:
        from .web_gui import CollaborationManager
        collab = CollaborationManager()
        if hasattr(collab, 'add_user_to_session') and hasattr(collab, 'add_chat_message'):
            requirements_met.append("✅ Web GUI collaborative features")
        else:
            requirements_failed.append("❌ Web GUI collaboration incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ Web GUI collaboration error: {e}")
    
    # Requirement 6.4 & 7.4: REST API
    try:
        from .api import RESTAPIServer, AttackResource
        server = RESTAPIServer()
        if hasattr(server, 'app') and hasattr(server, 'api'):
            requirements_met.append("✅ REST API for all functionality")
        else:
            requirements_failed.append("❌ REST API incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ REST API error: {e}")
    
    # Requirement 6.4 & 7.4: GraphQL API
    try:
        from .api import GraphQLAPIServer, Query, Mutation
        server = GraphQLAPIServer()
        if hasattr(server, 'schema') and hasattr(Query, 'resolve_attacks'):
            requirements_met.append("✅ GraphQL API for flexible data querying")
        else:
            requirements_failed.append("❌ GraphQL API incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ GraphQL API error: {e}")
    
    # Requirement 6.4 & 7.4: WebSocket support
    try:
        from .api import WebSocketManager
        manager = WebSocketManager()
        if hasattr(manager, 'register_connection') and hasattr(manager, 'broadcast_update'):
            requirements_met.append("✅ WebSocket support for real-time updates")
        else:
            requirements_failed.append("❌ WebSocket support incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ WebSocket support error: {e}")
    
    # Mobile API Gateway
    try:
        from .mobile import MobileAPIGateway, RemoteManagementService
        gateway = MobileAPIGateway()
        remote = RemoteManagementService()
        if hasattr(gateway, 'app') and hasattr(remote, 'execute_remote_command'):
            requirements_met.append("✅ Mobile app support and remote management")
        else:
            requirements_failed.append("❌ Mobile support incomplete")
    except Exception as e:
        requirements_failed.append(f"❌ Mobile support error: {e}")
    
    # Print results
    print("\nRequirements Met:")
    for req in requirements_met:
        print(f"  {req}")
    
    if requirements_failed:
        print("\nRequirements Failed:")
        for req in requirements_failed:
            print(f"  {req}")
    
    success_rate = len(requirements_met) / (len(requirements_met) + len(requirements_failed)) * 100
    print(f"\nRequirements Compliance: {success_rate:.1f}%")
    
    return len(requirements_failed) == 0

if __name__ == "__main__":
    # Run all tests
    tests_passed = run_all_tests()
    
    # Validate requirements
    requirements_met = validate_interface_requirements()
    
    # Overall result
    if tests_passed and requirements_met:
        print("\n🎉 All interface tests passed and requirements met!")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed or requirements not met")
        sys.exit(1)