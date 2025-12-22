"""
Browser Emulation Module

This module provides headless browser emulation capabilities for NetStress,
including JavaScript execution, DOM manipulation, and challenge solving.
"""

from .js_engine import JavaScriptEngine
from .dom_stubs import DOMStubs
from .browser_emulator import BrowserEmulator
from .cookie_manager import CookieManager
from .fingerprint_spoofer import FingerprintSpoofer
from .captcha_solver import CaptchaSolver
from .session_manager import SessionManager

__all__ = [
    'JavaScriptEngine',
    'DOMStubs', 
    'BrowserEmulator',
    'CookieManager',
    'FingerprintSpoofer',
    'CaptchaSolver',
    'SessionManager'
]