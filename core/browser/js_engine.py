"""
JavaScript Execution Engine

Provides JavaScript execution capabilities using QuickJS for challenge solving
and browser emulation. Supports async execution and DOM interaction.
"""

import asyncio
import json
import logging
import threading
import time
from typing import Any, Dict, Optional, Callable
from concurrent.futures import ThreadPoolExecutor

try:
    import quickjs
    QUICKJS_AVAILABLE = True
except ImportError:
    QUICKJS_AVAILABLE = False
    logging.warning("QuickJS not available, falling back to basic JS parsing")

from .dom_stubs import DOMStubs


class JavaScriptEngine:
    """JavaScript execution engine with DOM stubs and async support"""
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.dom_stubs = DOMStubs()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        if QUICKJS_AVAILABLE:
            self.context = quickjs.Context()
            self._setup_context()
        else:
            self.context = None
            self.logger.warning("QuickJS not available, limited JS support")
    
    def _setup_context(self):
        """Setup JavaScript context with DOM stubs and browser APIs"""
        if not self.context:
            return
            
        # Inject DOM stubs
        self.context.set("document", self.dom_stubs.document)
        self.context.set("window", self.dom_stubs.window)
        self.context.set("navigator", self.dom_stubs.navigator)
        self.context.set("location", self.dom_stubs.location)
        self.context.set("console", self.dom_stubs.console)
        
        # Inject common browser globals
        self.context.eval("""
            // Common browser globals
            var XMLHttpRequest = function() {
                this.open = function() {};
                this.send = function() {};
                this.setRequestHeader = function() {};
                this.readyState = 4;
                this.status = 200;
                this.responseText = '';
            };
            
            var fetch = function(url, options) {
                return Promise.resolve({
                    ok: true,
                    status: 200,
                    json: function() { return Promise.resolve({}); },
                    text: function() { return Promise.resolve(''); }
                });
            };
            
            var setTimeout = function(callback, delay) {
                // Stub implementation
                return 1;
            };
            
            var clearTimeout = function(id) {
                // Stub implementation
            };
            
            var setInterval = function(callback, delay) {
                // Stub implementation  
                return 1;
            };
            
            var clearInterval = function(id) {
                // Stub implementation
            };
            
            // Canvas and WebGL stubs for fingerprinting
            var HTMLCanvasElement = function() {
                this.getContext = function(type) {
                    if (type === '2d') {
                        return {
                            fillText: function() {},
                            getImageData: function() {
                                return { data: new Uint8ClampedArray(4) };
                            },
                            toDataURL: function() {
                                return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
                            }
                        };
                    } else if (type === 'webgl' || type === 'experimental-webgl') {
                        return {
                            getParameter: function(param) {
                                // Return consistent WebGL parameters
                                switch(param) {
                                    case 7936: return 'WebKit WebGL';
                                    case 7937: return 'WebKit GLSL ES';
                                    case 7938: return 'WebGL 1.0';
                                    default: return '';
                                }
                            },
                            getExtension: function() { return null; },
                            getSupportedExtensions: function() { return []; }
                        };
                    }
                    return null;
                };
            };
        """)
    
    def execute(self, code: str, context_vars: Optional[Dict[str, Any]] = None) -> Any:
        """Execute JavaScript code synchronously"""
        if not QUICKJS_AVAILABLE or not self.context:
            self.logger.warning("JavaScript execution not available")
            return None
            
        try:
            # Set context variables
            if context_vars:
                for key, value in context_vars.items():
                    self.context.set(key, value)
            
            # Execute code with timeout
            start_time = time.time()
            result = self.context.eval(code)
            
            if time.time() - start_time > self.timeout:
                raise TimeoutError("JavaScript execution timeout")
                
            return result
            
        except Exception as e:
            self.logger.error(f"JavaScript execution error: {e}")
            return None
    
    async def execute_async(self, code: str, context_vars: Optional[Dict[str, Any]] = None) -> Any:
        """Execute JavaScript code asynchronously"""
        loop = asyncio.get_event_loop()
        
        def _execute():
            return self.execute(code, context_vars)
        
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(self.executor, _execute),
                timeout=self.timeout
            )
            return result
        except asyncio.TimeoutError:
            self.logger.error("Async JavaScript execution timeout")
            return None
    
    def execute_function(self, func_name: str, *args) -> Any:
        """Execute a JavaScript function by name"""
        if not QUICKJS_AVAILABLE or not self.context:
            return None
            
        try:
            # Convert Python args to JS
            js_args = json.dumps(list(args))
            code = f"{func_name}.apply(null, {js_args})"
            return self.execute(code)
        except Exception as e:
            self.logger.error(f"Function execution error: {e}")
            return None
    
    def set_global(self, name: str, value: Any):
        """Set a global variable in the JavaScript context"""
        if self.context:
            self.context.set(name, value)
    
    def get_global(self, name: str) -> Any:
        """Get a global variable from the JavaScript context"""
        if not self.context:
            return None
            
        try:
            return self.context.eval(name)
        except:
            return None
    
    def evaluate_challenge(self, challenge_code: str, challenge_data: Dict[str, Any]) -> Optional[str]:
        """Evaluate a JavaScript challenge and return the solution"""
        try:
            # Set challenge data as globals
            for key, value in challenge_data.items():
                self.set_global(key, value)
            
            # Execute challenge code
            result = self.execute(challenge_code)
            
            # Try to extract common challenge result patterns
            if result is not None:
                return str(result)
            
            # Check for common result variable names
            for var_name in ['result', 'answer', 'solution', 'token', 'response']:
                value = self.get_global(var_name)
                if value is not None:
                    return str(value)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Challenge evaluation error: {e}")
            return None
    
    def inject_anti_detection(self):
        """Inject anti-detection code to avoid bot detection"""
        if not self.context:
            return
            
        anti_detection_code = """
            // Override common bot detection methods
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    {
                        name: 'Chrome PDF Plugin',
                        filename: 'internal-pdf-viewer',
                        description: 'Portable Document Format'
                    }
                ],
            });
            
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
            
            // Override automation detection
            window.chrome = {
                runtime: {},
                loadTimes: function() {},
                csi: function() {},
                app: {}
            };
            
            // Override permission API
            navigator.permissions = {
                query: function() {
                    return Promise.resolve({ state: 'granted' });
                }
            };
            
            // Override notification API
            window.Notification = {
                permission: 'default',
                requestPermission: function() {
                    return Promise.resolve('default');
                }
            };
        """
        
        self.execute(anti_detection_code)
    
    def cleanup(self):
        """Cleanup resources"""
        if self.executor:
            self.executor.shutdown(wait=True)
        
        if self.context:
            # QuickJS context cleanup is automatic
            pass


class AsyncJavaScriptEngine(JavaScriptEngine):
    """Async-focused JavaScript engine for concurrent challenge solving"""
    
    def __init__(self, timeout: float = 30.0, max_workers: int = 8):
        super().__init__(timeout)
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)
    
    async def solve_challenge_batch(self, challenges: list) -> list:
        """Solve multiple challenges concurrently"""
        async def solve_single(challenge):
            async with self.semaphore:
                return await self.execute_async(
                    challenge.get('code', ''),
                    challenge.get('context', {})
                )
        
        tasks = [solve_single(challenge) for challenge in challenges]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [
            result if not isinstance(result, Exception) else None
            for result in results
        ]