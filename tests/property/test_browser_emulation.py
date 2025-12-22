"""
Property-Based Tests for Browser Emulation

Tests the browser emulation fidelity across different profiles and scenarios.
**Validates: Requirements 11.1, 11.3, 11.4, 11.6**
"""

import asyncio
import json
import pytest
from hypothesis import given, strategies as st, settings, assume
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
import logging

from NetStress.core.browser.browser_emulator import BrowserEmulator
from NetStress.core.browser.js_engine import JavaScriptEngine
from NetStress.core.browser.fingerprint_spoofer import FingerprintSpoofer
from NetStress.core.browser.cookie_manager import CookieManager
from NetStress.core.browser.session_manager import SessionManager


# Test data generators
@st.composite
def browser_profile(draw):
    """Generate valid browser profile names"""
    profiles = ['chrome_120_windows', 'firefox_121_windows', 'safari_17_macos']
    return draw(st.sampled_from(profiles))


@st.composite
def url_strategy(draw):
    """Generate valid URLs for testing"""
    schemes = ['http', 'https']
    domains = ['example.com', 'test.org', 'demo.net', 'localhost']
    paths = ['', '/', '/test', '/page.html', '/api/endpoint']
    
    scheme = draw(st.sampled_from(schemes))
    domain = draw(st.sampled_from(domains))
    path = draw(st.sampled_from(paths))
    
    return f"{scheme}://{domain}{path}"


@st.composite
def javascript_code(draw):
    """Generate safe JavaScript code for testing"""
    safe_js_snippets = [
        "1 + 1",
        "Math.random()",
        "new Date().getTime()",
        "navigator.userAgent",
        "window.location.href",
        "document.title",
        "JSON.stringify({test: 'value'})",
        "Array.from({length: 5}, (_, i) => i)",
        "'hello world'.toUpperCase()",
        "typeof window"
    ]
    return draw(st.sampled_from(safe_js_snippets))


@st.composite
def cookie_data(draw):
    """Generate cookie data for testing"""
    name = draw(st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))))
    value = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc'))))
    domain = draw(st.sampled_from(['example.com', 'test.org', 'localhost']))
    
    return {
        'name': name,
        'value': value,
        'domain': domain,
        'path': '/',
        'secure': draw(st.booleans()),
        'http_only': draw(st.booleans())
    }


class TestBrowserEmulationProperties:
    """Property-based tests for browser emulation fidelity"""
    
    @pytest.fixture
    def event_loop(self):
        """Create event loop for async tests"""
        loop = asyncio.new_event_loop()
        yield loop
        loop.close()
    
    @given(profile=browser_profile())
    @settings(max_examples=10, deadline=30000)
    def test_fingerprint_consistency_property(self, profile):
        """
        Property 8: Browser Emulation Fidelity - Fingerprint Consistency
        
        For any browser profile, the fingerprint data should be consistent
        across multiple generations and match the expected profile characteristics.
        **Validates: Requirements 11.4**
        """
        spoofer = FingerprintSpoofer(profile)
        
        # Generate fingerprint multiple times
        fingerprint1 = spoofer.generate_fingerprint_report()
        fingerprint2 = spoofer.generate_fingerprint_report()
        
        # Fingerprints should be consistent
        assert fingerprint1['canvas']['hash'] == fingerprint2['canvas']['hash']
        assert fingerprint1['webgl']['hash'] == fingerprint2['webgl']['hash']
        assert fingerprint1['profile'] == fingerprint2['profile'] == profile
        
        # Validate fingerprint structure
        assert 'canvas' in fingerprint1
        assert 'webgl' in fingerprint1
        assert 'audio' in fingerprint1
        assert 'screen' in fingerprint1
        
        # Canvas fingerprint should have required fields
        canvas_fp = fingerprint1['canvas']
        assert 'data_url' in canvas_fp
        assert 'hash' in canvas_fp
        assert 'text_metrics' in canvas_fp
        assert 'fonts' in canvas_fp
        
        # WebGL fingerprint should have required fields
        webgl_fp = fingerprint1['webgl']
        assert 'vendor' in webgl_fp
        assert 'renderer' in webgl_fp
        assert 'version' in webgl_fp
        assert 'extensions' in webgl_fp
        assert isinstance(webgl_fp['extensions'], list)
        assert len(webgl_fp['extensions']) > 0
        
        # Validate consistency check
        assert spoofer.validate_fingerprint_consistency()
    
    @given(js_code=javascript_code())
    @settings(max_examples=10, deadline=10000)
    def test_javascript_execution_property(self, js_code):
        """
        Property 8: Browser Emulation Fidelity - JavaScript Execution
        
        For any safe JavaScript code, the execution should complete without
        errors and return consistent results.
        **Validates: Requirements 11.1**
        """
        engine = JavaScriptEngine()
        
        try:
            # Execute code multiple times
            result1 = engine.execute(js_code)
            result2 = engine.execute(js_code)
            
            # For deterministic code, results should be the same
            if 'random' not in js_code.lower() and 'date' not in js_code.lower():
                assert result1 == result2
            
            # If QuickJS is available, results should not be None for valid code
            if hasattr(engine, 'context') and engine.context is not None:
                if js_code in ["1 + 1", "'hello world'.toUpperCase()", "typeof window"]:
                    assert result1 is not None
                    assert result2 is not None
            else:
                # If QuickJS is not available, execution returns None (expected behavior)
                assert result1 is None
                assert result2 is None
        
        finally:
            engine.cleanup()
    
    @given(cookie=cookie_data(), url=url_strategy())
    @settings(max_examples=10, deadline=5000)
    def test_cookie_management_property(self, cookie, url):
        """
        Property 8: Browser Emulation Fidelity - Cookie Management
        
        For any valid cookie and URL, cookie storage and retrieval should
        maintain data integrity and domain matching rules.
        **Validates: Requirements 11.3**
        """
        manager = CookieManager()
        
        # Set cookie
        manager.set_cookie(**cookie)
        
        # Retrieve cookie
        retrieved = manager.get_cookie(cookie['name'], cookie['domain'])
        
        # Cookie should be retrievable
        assert retrieved is not None
        assert retrieved.name == cookie['name']
        assert retrieved.value == cookie['value']
        assert retrieved.domain == cookie['domain']
        
        # Cookie should be included for matching URLs
        # Only check if the URL domain matches the cookie domain
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        url_domain = parsed_url.netloc.lower()
        cookie_domain = cookie['domain'].lower()
        is_secure_url = parsed_url.scheme == 'https'
        
        # Check if domain matches and secure flag is compatible
        domain_matches = (cookie_domain == url_domain or url_domain.endswith('.' + cookie_domain))
        secure_compatible = not cookie['secure'] or is_secure_url
        
        if domain_matches and secure_compatible:
            cookies_for_url = manager.get_cookies_for_request(url)
            assert cookie['name'] in cookies_for_url
            assert cookies_for_url[cookie['name']] == cookie['value']
            
            # Cookie header should be properly formatted
            header = manager.get_cookie_header(url)
            assert header is not None
            assert f"{cookie['name']}={cookie['value']}" in header
    
    @pytest.mark.asyncio
    @given(profile=browser_profile())
    @settings(max_examples=5, deadline=60000)
    async def test_session_state_preservation_property(self, profile):
        """
        Property 8: Browser Emulation Fidelity - Session State Preservation
        
        For any browser profile, session state should be preserved across
        operations and snapshots should be restorable.
        **Validates: Requirements 11.6**
        """
        emulator = BrowserEmulator(profile_name=profile, max_sessions=10)
        
        try:
            # Create session
            session_id = await emulator.create_session(profile)
            
            # Set some cookies and state
            await emulator.set_session_cookie(
                session_id, 'test_cookie', 'test_value', 'example.com'
            )
            
            # Get initial state snapshot
            initial_state = await emulator.get_session_state(session_id)
            
            # Verify state structure
            assert 'session_state' in initial_state
            assert 'cookies' in initial_state
            assert 'fingerprint_profile' in initial_state
            assert initial_state['fingerprint_profile'] == profile
            
            # Create new session and restore state
            session_id2 = await emulator.create_session(profile)
            await emulator.restore_session_state(session_id2, initial_state)
            
            # Verify state was restored
            restored_state = await emulator.get_session_state(session_id2)
            
            # Key state elements should match
            assert restored_state['fingerprint_profile'] == initial_state['fingerprint_profile']
            
            # Cookies should be preserved
            cookies1 = await emulator.get_session_cookies(session_id)
            cookies2 = await emulator.get_session_cookies(session_id2)
            
            # Test cookie should be present in both
            assert 'test_cookie' in cookies1
            assert 'test_cookie' in cookies2
            assert cookies1['test_cookie'] == cookies2['test_cookie']
        
        finally:
            await emulator.shutdown()


class BrowserEmulationStateMachine(RuleBasedStateMachine):
    """Stateful property testing for browser emulation"""
    
    def __init__(self):
        super().__init__()
        self.emulator = None
        self.sessions = {}
        self.profiles = ['chrome_120_windows', 'firefox_121_windows', 'safari_17_macos']
    
    @initialize()
    async def setup_emulator(self):
        """Initialize the browser emulator"""
        self.emulator = BrowserEmulator(max_sessions=5)
    
    @rule(profile=st.sampled_from(['chrome_120_windows', 'firefox_121_windows', 'safari_17_macos']))
    async def create_session(self, profile):
        """Create a new browser session"""
        if len(self.sessions) < 3:  # Limit sessions for testing
            session_id = await self.emulator.create_session(profile)
            self.sessions[session_id] = {
                'profile': profile,
                'cookies': {},
                'state_snapshots': []
            }
    
    @rule(session_id=st.sampled_from([]), cookie=cookie_data())
    async def set_cookie(self, session_id, cookie):
        """Set a cookie in a session"""
        if session_id in self.sessions:
            await self.emulator.set_session_cookie(
                session_id, cookie['name'], cookie['value'], cookie['domain']
            )
            self.sessions[session_id]['cookies'][cookie['name']] = cookie['value']
    
    @rule(session_id=st.sampled_from([]))
    async def take_state_snapshot(self, session_id):
        """Take a state snapshot"""
        if session_id in self.sessions:
            snapshot = await self.emulator.get_session_state(session_id)
            self.sessions[session_id]['state_snapshots'].append(snapshot)
    
    @rule(session_id=st.sampled_from([]), profile=st.sampled_from(['chrome_120_windows', 'firefox_121_windows', 'safari_17_macos']))
    async def switch_profile(self, session_id, profile):
        """Switch browser profile"""
        if session_id in self.sessions:
            await self.emulator.switch_profile(session_id, profile)
            self.sessions[session_id]['profile'] = profile
    
    @invariant()
    async def session_consistency_invariant(self):
        """Sessions should maintain consistent state"""
        for session_id, session_data in self.sessions.items():
            # Verify session exists in emulator
            session = await self.emulator.session_manager.get_session(session_id)
            if session:
                # Profile should match
                assert session.profile_name == session_data['profile']
                
                # Cookies should be accessible
                cookies = await self.emulator.get_session_cookies(session_id)
                for cookie_name, cookie_value in session_data['cookies'].items():
                    if cookie_name in cookies:
                        assert cookies[cookie_name] == cookie_value
    
    @invariant()
    def emulator_state_invariant(self):
        """Emulator should maintain valid state"""
        if self.emulator:
            stats = self.emulator.get_session_stats()
            assert stats['total_sessions'] >= 0
            assert stats['active_sessions'] >= 0
            assert stats['active_sessions'] <= stats['total_sessions']
    
    def teardown(self):
        """Cleanup after testing"""
        if self.emulator:
            asyncio.create_task(self.emulator.shutdown())


# Async test runner for stateful testing
@pytest.mark.asyncio
@given(st.just(None))  # Add @given decorator to make @settings valid
@settings(max_examples=5, stateful_step_count=20, deadline=120000)
async def test_browser_emulation_stateful_property(_):
    """
    Property 8: Browser Emulation Fidelity - Stateful Behavior
    
    Browser emulation should maintain consistent state across complex
    sequences of operations.
    **Validates: Requirements 11.1, 11.3, 11.4, 11.6**
    """
    # Note: This is a simplified version since hypothesis stateful testing
    # with async is complex. In practice, you'd use a custom async runner.
    
    emulator = BrowserEmulator(max_sessions=3)
    
    try:
        # Create multiple sessions with different profiles
        sessions = []
        for profile in ['chrome_120_windows', 'firefox_121_windows']:
            session_id = await emulator.create_session(profile)
            sessions.append((session_id, profile))
        
        # Perform operations on each session
        for session_id, profile in sessions:
            # Set cookies
            await emulator.set_session_cookie(
                session_id, f'test_{profile}', 'value', 'example.com'
            )
            
            # Take state snapshot
            snapshot = await emulator.get_session_state(session_id)
            
            # Verify snapshot integrity
            assert snapshot['fingerprint_profile'] == profile
            assert 'session_state' in snapshot
            assert 'cookies' in snapshot
            
            # Verify cookies are accessible
            cookies = await emulator.get_session_cookies(session_id)
            assert f'test_{profile}' in cookies
        
        # Verify session isolation
        cookies1 = await emulator.get_session_cookies(sessions[0][0])
        cookies2 = await emulator.get_session_cookies(sessions[1][0])
        
        # Each session should have its own cookies
        assert f'test_{sessions[0][1]}' in cookies1
        assert f'test_{sessions[1][1]}' in cookies2
        assert f'test_{sessions[0][1]}' not in cookies2
        assert f'test_{sessions[1][1]}' not in cookies1
    
    finally:
        await emulator.shutdown()


if __name__ == "__main__":
    # Run property tests
    pytest.main([__file__, "-v", "--tb=short"])