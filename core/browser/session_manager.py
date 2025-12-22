"""
Browser Session Manager

Manages browser state across multiple requests, handles redirects with state
preservation, and supports multiple concurrent sessions.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Tuple, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, asdict
from collections import defaultdict

import aiohttp
from aiohttp import ClientSession, ClientResponse

from .cookie_manager import CookieManager
from .fingerprint_spoofer import FingerprintSpoofer
from .js_engine import JavaScriptEngine
from .turnstile_bypass import TurnstileBypass
from .captcha_solver import CaptchaSolver


@dataclass
class RequestState:
    """Represents the state of a single request"""
    url: str
    method: str = 'GET'
    headers: Dict[str, str] = None
    data: Any = None
    cookies: Dict[str, str] = None
    timestamp: float = None
    response_status: int = None
    response_headers: Dict[str, str] = None
    redirect_count: int = 0
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.cookies is None:
            self.cookies = {}
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class SessionState:
    """Represents the complete state of a browser session"""
    session_id: str
    user_agent: str
    referrer: str = ''
    current_url: str = ''
    request_history: List[RequestState] = None
    local_storage: Dict[str, str] = None
    session_storage: Dict[str, str] = None
    form_data: Dict[str, Any] = None
    challenge_tokens: Dict[str, str] = None
    created_at: float = None
    last_activity: float = None
    
    def __post_init__(self):
        if self.request_history is None:
            self.request_history = []
        if self.local_storage is None:
            self.local_storage = {}
        if self.session_storage is None:
            self.session_storage = {}
        if self.form_data is None:
            self.form_data = {}
        if self.challenge_tokens is None:
            self.challenge_tokens = {}
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_activity is None:
            self.last_activity = time.time()


class BrowserSession:
    """Individual browser session with state management"""
    
    def __init__(self, session_id: str, profile_name: str = 'chrome_120_windows',
                 captcha_api_keys: Optional[Dict[str, str]] = None):
        self.session_id = session_id
        self.profile_name = profile_name
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.cookie_manager = CookieManager()
        self.fingerprint_spoofer = FingerprintSpoofer(profile_name)
        self.js_engine = JavaScriptEngine()
        self.turnstile_bypass = None  # Initialized when needed
        self.captcha_solver = None
        
        if captcha_api_keys:
            self.captcha_solver = CaptchaSolver(api_keys=captcha_api_keys)
        
        # Session state
        self.state = SessionState(
            session_id=session_id,
            user_agent=self._get_user_agent_for_profile(profile_name)
        )
        
        # HTTP session
        self.http_session: Optional[ClientSession] = None
        self.max_redirects = 10
        self.request_timeout = 30
        
        # State preservation settings
        self.preserve_cookies = True
        self.preserve_referrer = True
        self.preserve_form_data = True
        self.auto_solve_challenges = True
    
    def _get_user_agent_for_profile(self, profile_name: str) -> str:
        """Get User-Agent string for browser profile"""
        user_agents = {
            'chrome_120_windows': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            ),
            'firefox_121_windows': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) '
                'Gecko/20100101 Firefox/121.0'
            ),
            'safari_17_macos': (
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
                '(KHTML, like Gecko) Version/17.0 Safari/605.1.15'
            )
        }
        return user_agents.get(profile_name, user_agents['chrome_120_windows'])
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False  # Allow insecure connections for testing
        )
        
        timeout = aiohttp.ClientTimeout(total=self.request_timeout)
        
        self.http_session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': self.state.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1'
            }
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.http_session:
            await self.http_session.close()
        
        if self.js_engine:
            self.js_engine.cleanup()
    
    async def request(self, method: str, url: str, **kwargs) -> Tuple[ClientResponse, str]:
        """Make an HTTP request with state management"""
        if not self.http_session:
            raise RuntimeError("Session not initialized. Use async context manager.")
        
        # Update state
        self.state.last_activity = time.time()
        
        # Prepare request
        headers = kwargs.get('headers', {}).copy()
        
        # Add cookies
        if self.preserve_cookies:
            cookie_header = self.cookie_manager.get_cookie_header(url)
            if cookie_header:
                headers['Cookie'] = cookie_header
        
        # Add referrer
        if self.preserve_referrer and self.state.referrer:
            headers['Referer'] = self.state.referrer
        
        # Inject fingerprint headers
        headers.update(self._get_fingerprint_headers())
        
        kwargs['headers'] = headers
        
        # Create request state
        request_state = RequestState(
            url=url,
            method=method,
            headers=headers,
            data=kwargs.get('data'),
            cookies=self.cookie_manager.get_cookies_for_request(url)
        )
        
        try:
            # Make request with redirect handling
            response, final_url, content = await self._make_request_with_redirects(
                method, url, **kwargs
            )
            
            # Update request state
            request_state.response_status = response.status
            request_state.response_headers = dict(response.headers)
            
            # Process response
            await self._process_response(response, final_url, content)
            
            # Update session state
            self.state.current_url = final_url
            self.state.referrer = final_url
            self.state.request_history.append(request_state)
            
            # Limit history size
            if len(self.state.request_history) > 100:
                self.state.request_history = self.state.request_history[-50:]
            
            return response, content
            
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            request_state.response_status = 0
            self.state.request_history.append(request_state)
            raise
    
    async def _make_request_with_redirects(self, method: str, url: str, **kwargs) -> Tuple[ClientResponse, str, str]:
        """Make request with manual redirect handling to preserve state"""
        current_url = url
        redirect_count = 0
        
        while redirect_count < self.max_redirects:
            try:
                # Disable automatic redirects
                kwargs['allow_redirects'] = False
                
                async with self.http_session.request(method, current_url, **kwargs) as response:
                    content = await response.text()
                    
                    # Check for redirects
                    if response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get('Location')
                        if location:
                            # Handle relative URLs
                            next_url = urljoin(current_url, location)
                            
                            # Update referrer for redirect
                            if 'headers' not in kwargs:
                                kwargs['headers'] = {}
                            kwargs['headers']['Referer'] = current_url
                            
                            # Process cookies from redirect response
                            if self.preserve_cookies:
                                self.cookie_manager.extract_cookies_from_headers(
                                    dict(response.headers), current_url
                                )
                            
                            current_url = next_url
                            redirect_count += 1
                            
                            # Change method to GET for 303 redirects
                            if response.status == 303:
                                method = 'GET'
                                kwargs.pop('data', None)
                                kwargs.pop('json', None)
                            
                            continue
                    
                    # No redirect, return response
                    return response, current_url, content
                    
            except Exception as e:
                self.logger.error(f"Request error at {current_url}: {e}")
                raise
        
        raise aiohttp.ClientError(f"Too many redirects (>{self.max_redirects})")
    
    async def _process_response(self, response: ClientResponse, url: str, content: str):
        """Process response and update session state"""
        try:
            # Extract cookies
            if self.preserve_cookies:
                self.cookie_manager.extract_cookies_from_headers(
                    dict(response.headers), url
                )
                self.cookie_manager.extract_cookies_from_html(content, url)
            
            # Handle challenges if auto-solving is enabled
            if self.auto_solve_challenges:
                await self._handle_challenges(content, url)
            
            # Extract and preserve form data
            if self.preserve_form_data:
                self._extract_form_data(content, url)
            
            # Execute any JavaScript for state updates
            await self._execute_page_javascript(content, url)
            
        except Exception as e:
            self.logger.error(f"Error processing response: {e}")
    
    async def _handle_challenges(self, content: str, url: str):
        """Handle various challenges (Turnstile, CAPTCHA, etc.)"""
        try:
            # Handle Turnstile challenges
            if 'turnstile' in content.lower() or 'cf-challenge' in content.lower():
                if not self.turnstile_bypass:
                    self.turnstile_bypass = TurnstileBypass(self.js_engine)
                    await self.turnstile_bypass.__aenter__()
                
                sitekey, token = await self.turnstile_bypass.solve_page_challenge(content, url)
                if sitekey and token:
                    self.state.challenge_tokens[f'turnstile_{sitekey}'] = token
                    self.logger.info(f"Solved Turnstile challenge: {sitekey}")
            
            # Handle CAPTCHA challenges
            if self.captcha_solver:
                solutions = await self.captcha_solver.solve_page_challenges(content, url)
                self.state.challenge_tokens.update(solutions)
                if solutions:
                    self.logger.info(f"Solved {len(solutions)} CAPTCHA challenges")
            
        except Exception as e:
            self.logger.error(f"Error handling challenges: {e}")
    
    def _extract_form_data(self, content: str, url: str):
        """Extract form data for potential reuse"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                form_id = form.get('id') or form.get('name') or f'form_{len(self.state.form_data)}'
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'fields': {}
                }
                
                # Extract input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_elem in inputs:
                    name = input_elem.get('name')
                    if name:
                        value = input_elem.get('value', '')
                        input_type = input_elem.get('type', 'text')
                        form_data['fields'][name] = {
                            'value': value,
                            'type': input_type,
                            'required': input_elem.has_attr('required')
                        }
                
                self.state.form_data[form_id] = form_data
                
        except Exception as e:
            self.logger.error(f"Error extracting form data: {e}")
    
    async def _execute_page_javascript(self, content: str, url: str):
        """Execute page JavaScript for state updates"""
        try:
            # Inject fingerprint overrides
            fingerprint_code = self.fingerprint_spoofer.inject_fingerprint_overrides(self.js_engine)
            await self.js_engine.execute_async(fingerprint_code)
            
            # Update DOM stubs with current URL
            self.js_engine.dom_stubs.update_url(url)
            
            # Set localStorage and sessionStorage
            for key, value in self.state.local_storage.items():
                self.js_engine.set_global(f'localStorage__{key}', value)
            
            for key, value in self.state.session_storage.items():
                self.js_engine.set_global(f'sessionStorage__{key}', value)
            
        except Exception as e:
            self.logger.error(f"Error executing page JavaScript: {e}")
    
    def _get_fingerprint_headers(self) -> Dict[str, str]:
        """Get headers that match the browser fingerprint"""
        headers = {}
        
        # Add browser-specific headers
        if 'chrome' in self.profile_name.lower():
            headers.update({
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"'
            })
        elif 'firefox' in self.profile_name.lower():
            headers.update({
                'DNT': '1',
                'Sec-GPC': '1'
            })
        elif 'safari' in self.profile_name.lower():
            headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            })
        
        return headers
    
    async def get(self, url: str, **kwargs) -> Tuple[ClientResponse, str]:
        """Make a GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Tuple[ClientResponse, str]:
        """Make a POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def submit_form(self, form_id: str, field_values: Dict[str, str] = None) -> Tuple[ClientResponse, str]:
        """Submit a form with preserved state"""
        if form_id not in self.state.form_data:
            raise ValueError(f"Form {form_id} not found in session state")
        
        form_data = self.state.form_data[form_id]
        action_url = form_data['action']
        method = form_data['method']
        
        # Prepare form data
        data = {}
        for field_name, field_info in form_data['fields'].items():
            if field_values and field_name in field_values:
                data[field_name] = field_values[field_name]
            else:
                data[field_name] = field_info['value']
        
        # Inject challenge tokens
        for token_key, token_value in self.state.challenge_tokens.items():
            if 'turnstile' in token_key:
                data['cf-turnstile-response'] = token_value
            elif 'recaptcha' in token_key:
                data['g-recaptcha-response'] = token_value
            elif 'hcaptcha' in token_key:
                data['h-captcha-response'] = token_value
        
        # Submit form
        if method == 'GET':
            return await self.get(action_url, params=data)
        else:
            return await self.post(action_url, data=data)
    
    def get_state_snapshot(self) -> Dict[str, Any]:
        """Get a snapshot of the current session state"""
        return {
            'session_state': asdict(self.state),
            'cookies': self.cookie_manager.jar.to_dict(),
            'fingerprint_profile': self.profile_name
        }
    
    def restore_state_snapshot(self, snapshot: Dict[str, Any]):
        """Restore session state from a snapshot"""
        try:
            # Restore session state
            state_data = snapshot.get('session_state', {})
            self.state = SessionState(**state_data)
            
            # Restore cookies
            cookie_data = snapshot.get('cookies', {})
            self.cookie_manager.jar = self.cookie_manager.jar.from_dict(cookie_data)
            
            # Restore fingerprint profile
            profile = snapshot.get('fingerprint_profile', self.profile_name)
            if profile != self.profile_name:
                self.fingerprint_spoofer.switch_profile(profile)
                self.profile_name = profile
                self.state.user_agent = self._get_user_agent_for_profile(profile)
            
        except Exception as e:
            self.logger.error(f"Error restoring state snapshot: {e}")
    
    def clear_state(self):
        """Clear all session state"""
        self.state = SessionState(
            session_id=self.session_id,
            user_agent=self.state.user_agent
        )
        self.cookie_manager.jar.clear_all()


class SessionManager:
    """Manages multiple concurrent browser sessions"""
    
    def __init__(self, max_sessions: int = 100):
        self.max_sessions = max_sessions
        self.sessions: Dict[str, BrowserSession] = {}
        self.session_locks: Dict[str, asyncio.Lock] = {}
        self.logger = logging.getLogger(__name__)
        
        # Session cleanup settings
        self.session_timeout = 3600  # 1 hour
        self.cleanup_interval = 300   # 5 minutes
        self._cleanup_task = None
    
    async def create_session(self, profile_name: str = 'chrome_120_windows',
                           captcha_api_keys: Optional[Dict[str, str]] = None) -> str:
        """Create a new browser session"""
        session_id = str(uuid.uuid4())
        
        # Check session limit
        if len(self.sessions) >= self.max_sessions:
            await self._cleanup_expired_sessions()
            
            if len(self.sessions) >= self.max_sessions:
                # Remove oldest session
                oldest_id = min(self.sessions.keys(), 
                              key=lambda x: self.sessions[x].state.last_activity)
                await self.destroy_session(oldest_id)
        
        # Create session
        session = BrowserSession(session_id, profile_name, captcha_api_keys)
        self.sessions[session_id] = session
        self.session_locks[session_id] = asyncio.Lock()
        
        self.logger.info(f"Created session {session_id} with profile {profile_name}")
        
        # Start cleanup task if not running
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[BrowserSession]:
        """Get a browser session by ID"""
        return self.sessions.get(session_id)
    
    async def destroy_session(self, session_id: str):
        """Destroy a browser session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            
            # Close HTTP session if active
            if session.http_session and not session.http_session.closed:
                await session.http_session.close()
            
            # Cleanup JavaScript engine
            if session.js_engine:
                session.js_engine.cleanup()
            
            # Remove from tracking
            del self.sessions[session_id]
            del self.session_locks[session_id]
            
            self.logger.info(f"Destroyed session {session_id}")
    
    async def with_session(self, session_id: str):
        """Context manager for using a session"""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        lock = self.session_locks.get(session_id)
        if not lock:
            raise ValueError(f"Session lock {session_id} not found")
        
        class SessionContext:
            def __init__(self, session, lock):
                self.session = session
                self.lock = lock
            
            async def __aenter__(self):
                await self.lock.acquire()
                return await self.session.__aenter__()
            
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                try:
                    await self.session.__aexit__(exc_type, exc_val, exc_tb)
                finally:
                    self.lock.release()
        
        return SessionContext(session, lock)
    
    async def _cleanup_expired_sessions(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self.sessions.items():
            if current_time - session.state.last_activity > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            await self.destroy_session(session_id)
            self.logger.info(f"Cleaned up expired session {session_id}")
    
    async def _periodic_cleanup(self):
        """Periodic cleanup task"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup task error: {e}")
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics about active sessions"""
        current_time = time.time()
        active_sessions = 0
        total_requests = 0
        
        for session in self.sessions.values():
            if current_time - session.state.last_activity < 300:  # Active in last 5 minutes
                active_sessions += 1
            total_requests += len(session.state.request_history)
        
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': active_sessions,
            'total_requests': total_requests,
            'max_sessions': self.max_sessions
        }
    
    async def shutdown(self):
        """Shutdown the session manager"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Destroy all sessions
        session_ids = list(self.sessions.keys())
        for session_id in session_ids:
            await self.destroy_session(session_id)