"""User interfaces module."""

try:
    from .cli import AdvancedCLI, InteractiveMode, ScriptingEngine
except ImportError:
    AdvancedCLI = None
    InteractiveMode = None
    ScriptingEngine = None

try:
    from .web_gui import DashboardManager, VisualizationEngine, WebGUI
except ImportError:
    WebGUI = None
    DashboardManager = None
    VisualizationEngine = None

try:
    from .api import GraphQLAPIServer, RESTAPIServer, WebSocketManager
except ImportError:
    RESTAPIServer = None
    GraphQLAPIServer = None
    WebSocketManager = None

try:
    from .mobile import MobileAPIGateway, RemoteManagementService
except ImportError:
    MobileAPIGateway = None
    RemoteManagementService = None

__all__ = [
    'AdvancedCLI',
    'InteractiveMode',
    'ScriptingEngine',
    'WebGUI',
    'DashboardManager',
    'VisualizationEngine',
    'RESTAPIServer',
    'GraphQLAPIServer',
    'WebSocketManager',
    'MobileAPIGateway',
    'RemoteManagementService',
]
