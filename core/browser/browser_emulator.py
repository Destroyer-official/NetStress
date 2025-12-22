"""
Browser Emulator

Main browser emulation class that coordinates all browser components
including JavaScript execution, challenge solving, and state management.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse

from .js_engine import JavaScriptEngine
from .dom_stubs import DOMStubs
from .cookie_manager import CookieManager
from .fingerprint_spoofer import FingerprintSpoofer
from .turnstile_bypass import TurnstileBypass
from .captcha_solver import CaptchaSolver
from .session_manager import SessionManager, BrowserSession


class BrowserEmulator:
    """Main browser emulator coordinating all components"""
    
    def __init__(self, profile_name: str = 'chrome_120_windows',
                 captcha_api_keys: Optional[Dict[str, str]] = None,
                 max_sessions: int = 100):
        self.profile_name = profile_name
        self.captcha_api_keys = captcha_api_keys or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize session manager
        self.session_manager = SessionManager(max_sessions)
        
        # Global components (shared across sessions)
        self.available_profiles = [
            'chrome_120_windows',
            'firefox_121_windows', 
            'safari_17_macos'
        ]
    
    async def create_session(self, profile_name: Optional[str] = None) -> str:
        """Create a new browser session"""
        profile = profile_name or self.profile_name
        return await self.session_manager.create_session(profile, self.captcha_api_keys)
    
    async def destroy_session(self, session_id: str):
        """Destroy a browser session"""
        await self.session_manager.destroy_session(session_id)
    
    async def navigate(self, session_id: str, url: str, **kwargs) -> Tuple[int, str]:
        """Navigate to a URL in a session"""
        async with self.session_manager.with_session(session_id) as session:
            response, content = await session.get(url, **kwargs)
            return response.status, content
    
    async def submit_form(self, session_id: str, form_id: str, 
                         field_values: Dict[str, str] = None) -> Tuple[int, str]:
        """Submit a form in a session"""
        async with self.session_manager.with_session(session_id) as session:
            response, content = await session.submit_form(form_id, field_values)
            return response.status, content
    
    async def execute_javascript(self, session_id: str, code: str, 
                                context_vars: Optional[Dict[str, Any]] = None) -> Any:
        """Execute JavaScript in a session"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        return await session.js_engine.execute_async(code, context_vars)
    
    async def solve_challenges(self, session_id: str, html_content: str, 
                              url: str) -> Dict[str, str]:
        """Solve challenges in HTML content"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        solutions = {}
        
        # Solve Turnstile challenges
        if session.turnstile_bypass:
            sitekey, token = await session.turnstile_bypass.solve_page_challenge(html_content, url)
            if sitekey and token:
                solutions[f'turnstile_{sitekey}'] = token
        
        # Solve CAPTCHA challenges
        if session.captcha_solver:
            captcha_solutions = await session.captcha_solver.solve_page_challenges(html_content, url)
            solutions.update(captcha_solutions)
        
        return solutions
    
    async def get_session_cookies(self, session_id: str, domain: str = None) -> Dict[str, str]:
        """Get cookies for a session"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        if domain:
            cookies = session.cookie_manager.jar.cookies.get(domain.lower(), {})
            return {name: cookie.value for name, cookie in cookies.items()}
        else:
            all_cookies = {}
            for domain_cookies in session.cookie_manager.jar.cookies.values():
                for name, cookie in domain_cookies.items():
                    all_cookies[name] = cookie.value
            return all_cookies
    
    async def set_session_cookie(self, session_id: str, name: str, value: str, 
                                domain: str, **kwargs):
        """Set a cookie in a session"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.cookie_manager.set_cookie(name, value, domain, **kwargs)
    
    async def get_session_state(self, session_id: str) -> Dict[str, Any]:
        """Get complete session state"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        return session.get_state_snapshot()
    
    async def restore_session_state(self, session_id: str, state_data: Dict[str, Any]):
        """Restore session state from data"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.restore_state_snapshot(state_data)
    
    async def switch_profile(self, session_id: str, profile_name: str):
        """Switch browser profile for a session"""
        if profile_name not in self.available_profiles:
            raise ValueError(f"Profile {profile_name} not available")
        
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.fingerprint_spoofer.switch_profile(profile_name)
        session.profile_name = profile_name
        session.state.user_agent = session._get_user_agent_for_profile(profile_name)
        
        self.logger.info(f"Switched session {session_id} to profile {profile_name}")
    
    async def get_fingerprint_data(self, session_id: str) -> Dict[str, Any]:
        """Get fingerprint data for a session"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        return session.fingerprint_spoofer.generate_fingerprint_report()
    
    async def inject_challenge_solutions(self, session_id: str, html_content: str, 
                                       solutions: Dict[str, str]) -> str:
        """Inject challenge solutions into HTML"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        modified_html = html_content
        
        # Inject Turnstile solutions
        if session.turnstile_bypass:
            for key, token in solutions.items():
                if key.startswith('turnstile_'):
                    modified_html = session.turnstile_bypass.inject_token_into_form(
                        modified_html, token
                    )
        
        # Inject CAPTCHA solutions
        if session.captcha_solver:
            modified_html = session.captcha_solver.inject_solutions_into_form(
                modified_html, solutions
            )
        
        return modified_html
    
    async def evaluate_page_challenges(self, session_id: str, html_content: str, 
                                     url: str) -> Dict[str, Any]:
        """Evaluate and solve all challenges on a page"""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        results = {
            'challenges_found': [],
            'solutions': {},
            'success': False,
            'modified_html': html_content
        }
        
        try:
            # Detect Turnstile challenges
            if session.turnstile_bypass:
                challenge = session.turnstile_bypass.detect_turnstile(html_content, url)
                if challenge:
                    results['challenges_found'].append({
                        'type': 'turnstile',
                        'sitekey': challenge.sitekey
                    })
                    
                    token = await session.turnstile_bypass.solve_challenge(challenge, url)
                    if token:
                        key = f'turnstile_{challenge.sitekey}'
                        results['solutions'][key] = token
                        session.state.challenge_tokens[key] = token
            
            # Detect and solve CAPTCHA challenges
            if session.captcha_solver:
                captcha_challenges = session.captcha_solver.detect_captcha(html_content, url)
                for challenge in captcha_challenges:
                    results['challenges_found'].append({
                        'type': challenge.challenge_type,
                        'sitekey': challenge.site_key or 'image'
                    })
                
                captcha_solutions = await session.captcha_solver.solve_page_challenges(html_content, url)
                results['solutions'].update(captcha_solutions)
                session.state.challenge_tokens.update(captcha_solutions)
            
            # Inject solutions into HTML
            if results['solutions']:
                results['modified_html'] = await self.inject_challenge_solutions(
                    session_id, html_content, results['solutions']
                )
                results['success'] = True
            
        except Exception as e:
            self.logger.error(f"Error evaluating page challenges: {e}")
            results['error'] = str(e)
        
        return results
    
    async def simulate_user_interaction(self, session_id: str, interaction_type: str, 
                                      **kwargs) -> Dict[str, Any]:
        """Simulate user interactions like clicks, form fills, etc."""
        session = await self.session_manager.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        result = {'success': False, 'action': interaction_type}
        
        try:
            if interaction_type == 'click':
                # Simulate click by executing JavaScript
                element_selector = kwargs.get('selector', '')
                js_code = f"""
                    var element = document.querySelector('{element_selector}');
                    if (element) {{
                        element.click();
                        'clicked';
                    }} else {{
                        'element_not_found';
                    }}
                """
                result['result'] = await session.js_engine.execute_async(js_code)
                result['success'] = result['result'] == 'clicked'
            
            elif interaction_type == 'fill_form':
                # Fill form fields
                form_data = kwargs.get('form_data', {})
                for field_name, value in form_data.items():
                    js_code = f"""
                        var field = document.querySelector('input[name="{field_name}"], textarea[name="{field_name}"]');
                        if (field) {{
                            field.value = '{value}';
                            field.dispatchEvent(new Event('input', {{ bubbles: true }}));
                            field.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        }}
                    """
                    await session.js_engine.execute_async(js_code)
                
                result['success'] = True
                result['fields_filled'] = len(form_data)
            
            elif interaction_type == 'wait':
                # Wait for specified time
                wait_time = kwargs.get('seconds', 1)
                await asyncio.sleep(wait_time)
                result['success'] = True
                result['waited_seconds'] = wait_time
            
            elif interaction_type == 'scroll':
                # Simulate scrolling
                scroll_y = kwargs.get('y', 100)
                js_code = f"window.scrollTo(0, {scroll_y});"
                await session.js_engine.execute_async(js_code)
                result['success'] = True
                result['scroll_position'] = scroll_y
            
        except Exception as e:
            self.logger.error(f"Error simulating {interaction_type}: {e}")
            result['error'] = str(e)
        
        return result
    
    def get_available_profiles(self) -> List[str]:
        """Get list of available browser profiles"""
        return self.available_profiles.copy()
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics about all sessions"""
        return self.session_manager.get_session_stats()
    
    async def cleanup_expired_sessions(self):
        """Manually trigger cleanup of expired sessions"""
        await self.session_manager._cleanup_expired_sessions()
    
    async def shutdown(self):
        """Shutdown the browser emulator"""
        await self.session_manager.shutdown()
        self.logger.info("Browser emulator shutdown complete")


class BrowserEmulatorPool:
    """Pool of browser emulators for high-concurrency scenarios"""
    
    def __init__(self, pool_size: int = 10, **emulator_kwargs):
        self.pool_size = pool_size
        self.emulator_kwargs = emulator_kwargs
        self.emulators: List[BrowserEmulator] = []
        self.current_index = 0
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize the emulator pool"""
        for i in range(self.pool_size):
            emulator = BrowserEmulator(**self.emulator_kwargs)
            self.emulators.append(emulator)
        
        self.logger.info(f"Initialized browser emulator pool with {self.pool_size} emulators")
    
    def get_emulator(self) -> BrowserEmulator:
        """Get the next emulator in round-robin fashion"""
        emulator = self.emulators[self.current_index]
        self.current_index = (self.current_index + 1) % self.pool_size
        return emulator
    
    async def create_session(self, profile_name: Optional[str] = None) -> Tuple[BrowserEmulator, str]:
        """Create a session using an available emulator"""
        emulator = self.get_emulator()
        session_id = await emulator.create_session(profile_name)
        return emulator, session_id
    
    async def shutdown(self):
        """Shutdown all emulators in the pool"""
        for emulator in self.emulators:
            await emulator.shutdown()
        
        self.logger.info("Browser emulator pool shutdown complete")