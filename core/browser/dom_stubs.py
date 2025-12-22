"""
DOM Stubs for JavaScript Execution

Provides minimal DOM API stubs to support JavaScript challenge execution
without requiring a full browser engine.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class DOMElement:
    """Stub DOM element implementation"""
    
    def __init__(self, tag_name: str = 'div', attributes: Optional[Dict[str, str]] = None):
        self.tag_name = tag_name.lower()
        self.attributes = attributes or {}
        self.children = []
        self.parent = None
        self.text_content = ''
        self.inner_html = ''
        self.style = {}
        
    def get_attribute(self, name: str) -> Optional[str]:
        return self.attributes.get(name)
    
    def set_attribute(self, name: str, value: str):
        self.attributes[name] = value
    
    def append_child(self, child: 'DOMElement'):
        child.parent = self
        self.children.append(child)
    
    def remove_child(self, child: 'DOMElement'):
        if child in self.children:
            child.parent = None
            self.children.remove(child)
    
    def query_selector(self, selector: str) -> Optional['DOMElement']:
        """Basic CSS selector support"""
        # Simple implementation for common selectors
        if selector.startswith('#'):
            # ID selector
            element_id = selector[1:]
            return self._find_by_id(element_id)
        elif selector.startswith('.'):
            # Class selector
            class_name = selector[1:]
            return self._find_by_class(class_name)
        else:
            # Tag selector
            return self._find_by_tag(selector)
    
    def query_selector_all(self, selector: str) -> List['DOMElement']:
        """Find all matching elements"""
        results = []
        if selector.startswith('#'):
            element = self._find_by_id(selector[1:])
            if element:
                results.append(element)
        elif selector.startswith('.'):
            results = self._find_all_by_class(selector[1:])
        else:
            results = self._find_all_by_tag(selector)
        return results
    
    def _find_by_id(self, element_id: str) -> Optional['DOMElement']:
        if self.attributes.get('id') == element_id:
            return self
        for child in self.children:
            result = child._find_by_id(element_id)
            if result:
                return result
        return None
    
    def _find_by_class(self, class_name: str) -> Optional['DOMElement']:
        classes = self.attributes.get('class', '').split()
        if class_name in classes:
            return self
        for child in self.children:
            result = child._find_by_class(class_name)
            if result:
                return result
        return None
    
    def _find_by_tag(self, tag_name: str) -> Optional['DOMElement']:
        if self.tag_name == tag_name.lower():
            return self
        for child in self.children:
            result = child._find_by_tag(tag_name)
            if result:
                return result
        return None
    
    def _find_all_by_class(self, class_name: str) -> List['DOMElement']:
        results = []
        classes = self.attributes.get('class', '').split()
        if class_name in classes:
            results.append(self)
        for child in self.children:
            results.extend(child._find_all_by_class(class_name))
        return results
    
    def _find_all_by_tag(self, tag_name: str) -> List['DOMElement']:
        results = []
        if self.tag_name == tag_name.lower():
            results.append(self)
        for child in self.children:
            results.extend(child._find_all_by_tag(tag_name))
        return results


class DOMDocument:
    """Stub document object"""
    
    def __init__(self):
        self.body = DOMElement('body')
        self.head = DOMElement('head')
        self.document_element = DOMElement('html')
        self.document_element.append_child(self.head)
        self.document_element.append_child(self.body)
        self.cookie = ''
        self.title = 'NetStress Browser Emulator'
        self.url = 'about:blank'
        self.domain = 'localhost'
        self.ready_state = 'complete'
        
    def get_element_by_id(self, element_id: str) -> Optional[DOMElement]:
        return self.document_element._find_by_id(element_id)
    
    def get_elements_by_tag_name(self, tag_name: str) -> List[DOMElement]:
        return self.document_element._find_all_by_tag(tag_name)
    
    def get_elements_by_class_name(self, class_name: str) -> List[DOMElement]:
        return self.document_element._find_all_by_class(class_name)
    
    def query_selector(self, selector: str) -> Optional[DOMElement]:
        return self.document_element.query_selector(selector)
    
    def query_selector_all(self, selector: str) -> List[DOMElement]:
        return self.document_element.query_selector_all(selector)
    
    def create_element(self, tag_name: str) -> DOMElement:
        return DOMElement(tag_name)
    
    def add_event_listener(self, event_type: str, callback):
        # Stub implementation
        pass
    
    def remove_event_listener(self, event_type: str, callback):
        # Stub implementation
        pass


class DOMWindow:
    """Stub window object"""
    
    def __init__(self, document: DOMDocument):
        self.document = document
        self.location = DOMLocation()
        self.navigator = DOMNavigator()
        self.screen = DOMScreen()
        self.history = DOMHistory()
        self.local_storage = DOMStorage()
        self.session_storage = DOMStorage()
        self.inner_width = 1920
        self.inner_height = 1080
        self.outer_width = 1920
        self.outer_height = 1080
        self.device_pixel_ratio = 1.0
        
    def alert(self, message: str):
        logging.info(f"Browser alert: {message}")
    
    def confirm(self, message: str) -> bool:
        logging.info(f"Browser confirm: {message}")
        return True
    
    def prompt(self, message: str, default: str = '') -> str:
        logging.info(f"Browser prompt: {message}")
        return default
    
    def open(self, url: str, target: str = '_blank', features: str = '') -> 'DOMWindow':
        logging.info(f"Window open: {url}")
        return self
    
    def close(self):
        logging.info("Window close")
    
    def add_event_listener(self, event_type: str, callback):
        # Stub implementation
        pass
    
    def remove_event_listener(self, event_type: str, callback):
        # Stub implementation
        pass


class DOMLocation:
    """Stub location object"""
    
    def __init__(self, url: str = 'about:blank'):
        self.href = url
        parsed = urlparse(url)
        self.protocol = parsed.scheme + ':' if parsed.scheme else 'about:'
        self.host = parsed.netloc or 'blank'
        self.hostname = parsed.hostname or 'blank'
        self.port = str(parsed.port) if parsed.port else ''
        self.pathname = parsed.path or ''
        self.search = '?' + parsed.query if parsed.query else ''
        self.hash = '#' + parsed.fragment if parsed.fragment else ''
        self.origin = f"{self.protocol}//{self.host}" if self.host != 'blank' else 'null'
    
    def reload(self):
        logging.info("Location reload")
    
    def replace(self, url: str):
        logging.info(f"Location replace: {url}")
        self.__init__(url)
    
    def assign(self, url: str):
        logging.info(f"Location assign: {url}")
        self.__init__(url)


class DOMNavigator:
    """Stub navigator object"""
    
    def __init__(self):
        self.user_agent = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        self.app_name = 'Netscape'
        self.app_version = '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.platform = 'Win32'
        self.language = 'en-US'
        self.languages = ['en-US', 'en']
        self.cookie_enabled = True
        self.do_not_track = None
        self.hardware_concurrency = 8
        self.max_touch_points = 0
        self.vendor = 'Google Inc.'
        self.vendor_sub = ''
        self.product = 'Gecko'
        self.product_sub = '20030107'
        self.online = True
        
    def get_user_media(self, constraints: Dict[str, Any]):
        # Stub implementation
        return None
    
    def send_beacon(self, url: str, data: Any) -> bool:
        logging.info(f"Navigator sendBeacon: {url}")
        return True


class DOMScreen:
    """Stub screen object"""
    
    def __init__(self):
        self.width = 1920
        self.height = 1080
        self.avail_width = 1920
        self.avail_height = 1040
        self.color_depth = 24
        self.pixel_depth = 24
        self.orientation = {'type': 'landscape-primary', 'angle': 0}


class DOMHistory:
    """Stub history object"""
    
    def __init__(self):
        self.length = 1
        self.state = None
    
    def back(self):
        logging.info("History back")
    
    def forward(self):
        logging.info("History forward")
    
    def go(self, delta: int):
        logging.info(f"History go: {delta}")
    
    def push_state(self, state: Any, title: str, url: str):
        logging.info(f"History pushState: {url}")
        self.state = state
    
    def replace_state(self, state: Any, title: str, url: str):
        logging.info(f"History replaceState: {url}")
        self.state = state


class DOMStorage:
    """Stub storage object (localStorage/sessionStorage)"""
    
    def __init__(self):
        self._storage = {}
    
    def get_item(self, key: str) -> Optional[str]:
        return self._storage.get(key)
    
    def set_item(self, key: str, value: str):
        self._storage[key] = str(value)
    
    def remove_item(self, key: str):
        self._storage.pop(key, None)
    
    def clear(self):
        self._storage.clear()
    
    def key(self, index: int) -> Optional[str]:
        keys = list(self._storage.keys())
        return keys[index] if 0 <= index < len(keys) else None
    
    @property
    def length(self) -> int:
        return len(self._storage)


class DOMConsole:
    """Stub console object"""
    
    def __init__(self):
        self.logger = logging.getLogger('browser.console')
    
    def log(self, *args):
        message = ' '.join(str(arg) for arg in args)
        self.logger.info(f"Console.log: {message}")
    
    def error(self, *args):
        message = ' '.join(str(arg) for arg in args)
        self.logger.error(f"Console.error: {message}")
    
    def warn(self, *args):
        message = ' '.join(str(arg) for arg in args)
        self.logger.warning(f"Console.warn: {message}")
    
    def info(self, *args):
        message = ' '.join(str(arg) for arg in args)
        self.logger.info(f"Console.info: {message}")
    
    def debug(self, *args):
        message = ' '.join(str(arg) for arg in args)
        self.logger.debug(f"Console.debug: {message}")


class DOMStubs:
    """Container for all DOM stub objects"""
    
    def __init__(self, url: str = 'about:blank'):
        self.document = DOMDocument()
        self.window = DOMWindow(self.document)
        self.navigator = self.window.navigator
        self.location = DOMLocation(url)
        self.console = DOMConsole()
        
        # Update document URL info
        self.document.url = url
        parsed = urlparse(url)
        self.document.domain = parsed.hostname or 'localhost'
        
        # Link window and document
        self.window.location = self.location
        self.document.default_view = self.window
    
    def update_url(self, url: str):
        """Update the current URL and related objects"""
        self.location = DOMLocation(url)
        self.window.location = self.location
        self.document.url = url
        parsed = urlparse(url)
        self.document.domain = parsed.hostname or 'localhost'
    
    def inject_challenge_elements(self, challenge_data: Dict[str, Any]):
        """Inject challenge-specific DOM elements"""
        # Create common challenge elements
        if 'turnstile' in challenge_data:
            turnstile_div = self.document.create_element('div')
            turnstile_div.set_attribute('class', 'cf-turnstile')
            turnstile_div.set_attribute('data-sitekey', challenge_data.get('sitekey', ''))
            self.document.body.append_child(turnstile_div)
        
        if 'captcha' in challenge_data:
            captcha_div = self.document.create_element('div')
            captcha_div.set_attribute('id', 'captcha-container')
            self.document.body.append_child(captcha_div)
        
        # Inject any custom elements
        for element_data in challenge_data.get('elements', []):
            element = self.document.create_element(element_data.get('tag', 'div'))
            for attr, value in element_data.get('attributes', {}).items():
                element.set_attribute(attr, value)
            element.text_content = element_data.get('text', '')
            self.document.body.append_child(element)