"""
Advanced Header Randomization Module

Enhanced header randomization with:
- Browser-specific header ordering
- Random but consistent header values
- Cookie management mimicking real users
- Session persistence
"""

import random
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class BrowserProfile:
    """Browser-specific profile with header ordering"""
    name: str
    user_agent: str
    header_order: List[str]
    default_headers: Dict[str, str]
    sec_headers: Dict[str, str] = field(default_factory=dict)
    
    
# Browser-specific header ordering (critical for fingerprinting)
CHROME_HEADER_ORDER = [
    'Host',
    'Connection',
    'Cache-Control',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'Upgrade-Insecure-Requests',
    'User-Agent',
    'Accept',
    'Sec-Fetch-Site',
    'Sec-Fetch-Mode',
    'Sec-Fetch-User',
    'Sec-Fetch-Dest',
    'Referer',
    'Accept-Encoding',
    'Accept-Language',
    'Cookie',
]

FIREFOX_HEADER_ORDER = [
    'Host',
    'User-Agent',
    'Accept',
    'Accept-Language',
    'Accept-Encoding',
    'Referer',
    'Connection',
    'Cookie',
    'Upgrade-Insecure-Requests',
    'Sec-Fetch-Dest',
    'Sec-Fetch-Mode',
    'Sec-Fetch-Site',
    'Sec-Fetch-User',
    'Cache-Control',
]

SAFARI_HEADER_ORDER = [
    'Host',
    'Accept',
    'Sec-Fetch-Site',
    'Accept-Language',
    'Sec-Fetch-Mode',
    'Accept-Encoding',
    'Sec-Fetch-Dest',
    'User-Agent',
    'Referer',
    'Connection',
    'Cookie',
]

EDGE_HEADER_ORDER = CHROME_HEADER_ORDER  # Edge uses Chromium


# Browser profiles with correct ordering
BROWSER_PROFILES = {
    'chrome_120': BrowserProfile(
        name='Chrome 120',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        header_order=CHROME_HEADER_ORDER,
        default_headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        },
        sec_headers={
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
        }
    ),
    'firefox_121': BrowserProfile(
        name='Firefox 121',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        header_order=FIREFOX_HEADER_ORDER,
        default_headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        },
        sec_headers={
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
    ),
    'safari_17': BrowserProfile(
        name='Safari 17',
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        header_order=SAFARI_HEADER_ORDER,
        default_headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        },
        sec_headers={
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
        }
    ),
    'edge_120': BrowserProfile(
        name='Edge 120',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        header_order=EDGE_HEADER_ORDER,
        default_headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        },
        sec_headers={
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
        }
    ),
}


@dataclass
class Cookie:
    """HTTP Cookie"""
    name: str
    value: str
    domain: str
    path: str = '/'
    expires: Optional[datetime] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if cookie is expired"""
        if self.expires is None:
            return False
        return datetime.now() > self.expires
        
    def to_header_value(self) -> str:
        """Convert to Cookie header value"""
        return f"{self.name}={self.value}"


class CookieJar:
    """
    Cookie management mimicking real browser behavior.
    
    Handles:
    - Cookie storage and retrieval
    - Domain matching
    - Expiration
    - Secure/HttpOnly flags
    """
    
    def __init__(self):
        self._cookies: Dict[str, List[Cookie]] = {}
        
    def add_cookie(self, cookie: Cookie):
        """Add cookie to jar"""
        domain = cookie.domain
        if domain not in self._cookies:
            self._cookies[domain] = []
            
        # Remove existing cookie with same name
        self._cookies[domain] = [
            c for c in self._cookies[domain] 
            if c.name != cookie.name
        ]
        
        self._cookies[domain].append(cookie)
        
    def get_cookies(self, domain: str, path: str = '/', secure: bool = False) -> List[Cookie]:
        """Get cookies for domain and path"""
        cookies = []
        
        # Check all domains that match
        for cookie_domain, domain_cookies in self._cookies.items():
            if self._domain_matches(domain, cookie_domain):
                for cookie in domain_cookies:
                    # Check expiration
                    if cookie.is_expired():
                        continue
                        
                    # Check path
                    if not path.startswith(cookie.path):
                        continue
                        
                    # Check secure flag
                    if cookie.secure and not secure:
                        continue
                        
                    cookies.append(cookie)
                    
        return cookies
        
    def _domain_matches(self, request_domain: str, cookie_domain: str) -> bool:
        """Check if request domain matches cookie domain"""
        # Exact match
        if request_domain == cookie_domain:
            return True
            
        # Subdomain match (cookie_domain starts with .)
        if cookie_domain.startswith('.'):
            return request_domain.endswith(cookie_domain) or request_domain == cookie_domain[1:]
            
        return False
        
    def get_cookie_header(self, domain: str, path: str = '/', secure: bool = False) -> Optional[str]:
        """Get Cookie header value for request"""
        cookies = self.get_cookies(domain, path, secure)
        if not cookies:
            return None
            
        return '; '.join(c.to_header_value() for c in cookies)
        
    def parse_set_cookie(self, set_cookie_header: str, domain: str) -> Cookie:
        """Parse Set-Cookie header"""
        parts = set_cookie_header.split(';')
        
        # First part is name=value
        name_value = parts[0].strip()
        if '=' in name_value:
            name, value = name_value.split('=', 1)
        else:
            name, value = name_value, ''
            
        cookie = Cookie(name=name.strip(), value=value.strip(), domain=domain)
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                attr_name, attr_value = part.split('=', 1)
                attr_name = attr_name.strip().lower()
                attr_value = attr_value.strip()
                
                if attr_name == 'domain':
                    cookie.domain = attr_value
                elif attr_name == 'path':
                    cookie.path = attr_value
                elif attr_name == 'expires':
                    # Parse expires date
                    try:
                        cookie.expires = datetime.strptime(attr_value, '%a, %d %b %Y %H:%M:%S GMT')
                    except ValueError:
                        pass
                elif attr_name == 'max-age':
                    try:
                        max_age = int(attr_value)
                        cookie.expires = datetime.now() + timedelta(seconds=max_age)
                    except ValueError:
                        pass
                elif attr_name == 'samesite':
                    cookie.same_site = attr_value
            else:
                attr_name = part.lower()
                if attr_name == 'secure':
                    cookie.secure = True
                elif attr_name == 'httponly':
                    cookie.http_only = True
                    
        return cookie
        
    def clear_expired(self):
        """Remove expired cookies"""
        for domain in self._cookies:
            self._cookies[domain] = [
                c for c in self._cookies[domain]
                if not c.is_expired()
            ]


class SessionManager:
    """
    Manages session state like a real browser.
    
    Tracks:
    - Session ID
    - Cookies
    - Referer chain
    - Request count
    """
    
    def __init__(self, profile_name: str = 'chrome_120'):
        self.session_id = str(uuid.uuid4())
        self.profile = BROWSER_PROFILES.get(profile_name, BROWSER_PROFILES['chrome_120'])
        self.cookie_jar = CookieJar()
        self.referer_chain: List[str] = []
        self.request_count = 0
        self.session_start = time.time()
        
        # Generate consistent session cookies
        self._generate_session_cookies()
        
    def _generate_session_cookies(self):
        """Generate realistic session cookies"""
        # Common session cookie names
        session_names = ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', '_ga', '_gid']
        
        for name in random.sample(session_names, random.randint(1, 3)):
            value = hashlib.md5(f"{self.session_id}{name}{time.time()}".encode()).hexdigest()
            cookie = Cookie(
                name=name,
                value=value,
                domain='.example.com',  # Will be updated per request
                path='/',
                expires=datetime.now() + timedelta(hours=24)
            )
            self.cookie_jar.add_cookie(cookie)
            
    def get_headers(self, url: str, method: str = 'GET', is_ajax: bool = False) -> OrderedDict:
        """
        Get headers for request with proper ordering.
        
        Args:
            url: Target URL
            method: HTTP method
            is_ajax: Whether this is an AJAX request
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        headers = OrderedDict()
        
        # Start with profile defaults
        base_headers = self.profile.default_headers.copy()
        base_headers['Host'] = parsed.netloc
        base_headers['User-Agent'] = self.profile.user_agent
        
        # Add referer if we have history
        if self.referer_chain:
            base_headers['Referer'] = self.referer_chain[-1]
            
        # Add cookies
        cookie_header = self.cookie_jar.get_cookie_header(
            parsed.netloc,
            parsed.path or '/',
            parsed.scheme == 'https'
        )
        if cookie_header:
            base_headers['Cookie'] = cookie_header
            
        # Add sec headers
        base_headers.update(self.profile.sec_headers)
        
        # Modify for AJAX requests
        if is_ajax:
            base_headers['X-Requested-With'] = 'XMLHttpRequest'
            base_headers['Sec-Fetch-Mode'] = 'cors'
            base_headers['Sec-Fetch-Dest'] = 'empty'
            
        # Add cache control occasionally
        if random.random() < 0.3:
            base_headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0'])
            
        # Order headers according to browser profile
        for header_name in self.profile.header_order:
            if header_name in base_headers:
                headers[header_name] = base_headers[header_name]
                
        # Add any remaining headers not in order list
        for key, value in base_headers.items():
            if key not in headers:
                headers[key] = value
                
        return headers
        
    def update_referer(self, url: str):
        """Update referer chain"""
        self.referer_chain.append(url)
        
        # Keep only last 5 referers
        if len(self.referer_chain) > 5:
            self.referer_chain.pop(0)
            
    def process_response_cookies(self, set_cookie_headers: List[str], domain: str):
        """Process Set-Cookie headers from response"""
        for header in set_cookie_headers:
            cookie = self.cookie_jar.parse_set_cookie(header, domain)
            self.cookie_jar.add_cookie(cookie)
            
    def increment_request_count(self):
        """Increment request counter"""
        self.request_count += 1
        
    def get_session_age(self) -> float:
        """Get session age in seconds"""
        return time.time() - self.session_start


class AdvancedHeaderRandomizer:
    """
    Advanced header randomization with session management.
    
    Provides:
    - Browser-specific header ordering
    - Consistent session state
    - Cookie management
    - Referer chain tracking
    """
    
    def __init__(self, profile_name: Optional[str] = None):
        if profile_name is None:
            profile_name = random.choice(list(BROWSER_PROFILES.keys()))
            
        self.session = SessionManager(profile_name)
        
    def get_headers(self, url: str, method: str = 'GET', is_ajax: bool = False) -> Dict[str, str]:
        """Get headers for request"""
        headers = self.session.get_headers(url, method, is_ajax)
        self.session.increment_request_count()
        return dict(headers)
        
    def update_from_response(self, url: str, set_cookie_headers: List[str]):
        """Update session state from response"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        self.session.update_referer(url)
        self.session.process_response_cookies(set_cookie_headers, parsed.netloc)
        
    def get_profile_name(self) -> str:
        """Get current browser profile name"""
        return self.session.profile.name
        
    def get_session_stats(self) -> dict:
        """Get session statistics"""
        return {
            'session_id': self.session.session_id,
            'profile': self.session.profile.name,
            'request_count': self.session.request_count,
            'session_age': self.session.get_session_age(),
            'referer_chain_length': len(self.session.referer_chain),
            'cookie_count': sum(len(cookies) for cookies in self.session.cookie_jar._cookies.values()),
        }


# Convenience function for quick usage
def get_realistic_headers(url: str, profile: Optional[str] = None) -> Dict[str, str]:
    """
    Get realistic headers for a URL.
    
    Args:
        url: Target URL
        profile: Browser profile name (chrome_120, firefox_121, safari_17, edge_120)
        
    Returns:
        Dictionary of headers with proper ordering
    """
    randomizer = AdvancedHeaderRandomizer(profile)
    return randomizer.get_headers(url)
