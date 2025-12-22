"""
Cookie Manager

Handles cookie extraction, storage, and reuse across browser sessions.
Supports domain-based cookie management and automatic cookie injection.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urljoin
from http.cookies import SimpleCookie, Morsel
import re


class Cookie:
    """Represents a single HTTP cookie"""
    
    def __init__(self, name: str, value: str, domain: str = '', path: str = '/',
                 expires: Optional[float] = None, max_age: Optional[int] = None,
                 secure: bool = False, http_only: bool = False,
                 same_site: Optional[str] = None):
        self.name = name
        self.value = value
        self.domain = domain.lower() if domain else ''
        self.path = path
        self.expires = expires
        self.max_age = max_age
        self.secure = secure
        self.http_only = http_only
        self.same_site = same_site
        self.created_at = time.time()
    
    def is_expired(self) -> bool:
        """Check if the cookie is expired"""
        current_time = time.time()
        
        # Check max_age first (takes precedence over expires)
        if self.max_age is not None:
            return current_time > (self.created_at + self.max_age)
        
        # Check expires
        if self.expires is not None:
            return current_time > self.expires
        
        # Session cookie (no expiry)
        return False
    
    def matches_domain(self, domain: str) -> bool:
        """Check if cookie matches the given domain"""
        domain = domain.lower()
        cookie_domain = self.domain.lower()
        
        if not cookie_domain:
            return True
        
        # Exact match
        if cookie_domain == domain:
            return True
        
        # Domain cookie (starts with .)
        if cookie_domain.startswith('.'):
            return domain.endswith(cookie_domain[1:]) or domain == cookie_domain[1:]
        
        # Subdomain match
        return domain.endswith('.' + cookie_domain)
    
    def matches_path(self, path: str) -> bool:
        """Check if cookie matches the given path"""
        if not self.path or self.path == '/':
            return True
        
        # Path must start with cookie path
        return path.startswith(self.path)
    
    def to_header_value(self) -> str:
        """Convert cookie to header value format"""
        return f"{self.name}={self.value}"
    
    def to_set_cookie_header(self) -> str:
        """Convert cookie to Set-Cookie header format"""
        parts = [f"{self.name}={self.value}"]
        
        if self.domain:
            parts.append(f"Domain={self.domain}")
        
        if self.path and self.path != '/':
            parts.append(f"Path={self.path}")
        
        if self.expires:
            expires_str = datetime.fromtimestamp(self.expires, timezone.utc).strftime(
                '%a, %d %b %Y %H:%M:%S GMT'
            )
            parts.append(f"Expires={expires_str}")
        
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        
        if self.secure:
            parts.append("Secure")
        
        if self.http_only:
            parts.append("HttpOnly")
        
        if self.same_site:
            parts.append(f"SameSite={self.same_site}")
        
        return "; ".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cookie to dictionary for serialization"""
        return {
            'name': self.name,
            'value': self.value,
            'domain': self.domain,
            'path': self.path,
            'expires': self.expires,
            'max_age': self.max_age,
            'secure': self.secure,
            'http_only': self.http_only,
            'same_site': self.same_site,
            'created_at': self.created_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Cookie':
        """Create cookie from dictionary"""
        cookie = cls(
            name=data['name'],
            value=data['value'],
            domain=data.get('domain', ''),
            path=data.get('path', '/'),
            expires=data.get('expires'),
            max_age=data.get('max_age'),
            secure=data.get('secure', False),
            http_only=data.get('http_only', False),
            same_site=data.get('same_site')
        )
        cookie.created_at = data.get('created_at', time.time())
        return cookie


class CookieJar:
    """Container for managing multiple cookies"""
    
    def __init__(self):
        self.cookies: Dict[str, Dict[str, Cookie]] = {}  # domain -> {name: cookie}
        self.logger = logging.getLogger(__name__)
    
    def add_cookie(self, cookie: Cookie):
        """Add a cookie to the jar"""
        domain = cookie.domain or 'default'
        
        if domain not in self.cookies:
            self.cookies[domain] = {}
        
        self.cookies[domain][cookie.name] = cookie
        self.logger.debug(f"Added cookie: {cookie.name} for domain {domain}")
    
    def get_cookies_for_url(self, url: str) -> List[Cookie]:
        """Get all cookies that should be sent with a request to the given URL"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path or '/'
        is_secure = parsed.scheme == 'https'
        
        matching_cookies = []
        
        # Check all domains for matches
        for cookie_domain, domain_cookies in self.cookies.items():
            for cookie in domain_cookies.values():
                # Skip expired cookies
                if cookie.is_expired():
                    continue
                
                # Check domain match
                if not cookie.matches_domain(domain):
                    continue
                
                # Check path match
                if not cookie.matches_path(path):
                    continue
                
                # Check secure flag
                if cookie.secure and not is_secure:
                    continue
                
                matching_cookies.append(cookie)
        
        return matching_cookies
    
    def get_cookie_header(self, url: str) -> Optional[str]:
        """Get the Cookie header value for a URL"""
        cookies = self.get_cookies_for_url(url)
        if not cookies:
            return None
        
        cookie_values = [cookie.to_header_value() for cookie in cookies]
        return "; ".join(cookie_values)
    
    def remove_expired_cookies(self):
        """Remove all expired cookies from the jar"""
        for domain in list(self.cookies.keys()):
            for name in list(self.cookies[domain].keys()):
                if self.cookies[domain][name].is_expired():
                    del self.cookies[domain][name]
                    self.logger.debug(f"Removed expired cookie: {name} from domain {domain}")
            
            # Remove empty domains
            if not self.cookies[domain]:
                del self.cookies[domain]
    
    def clear_domain(self, domain: str):
        """Clear all cookies for a specific domain"""
        domain = domain.lower()
        if domain in self.cookies:
            del self.cookies[domain]
            self.logger.info(f"Cleared cookies for domain: {domain}")
    
    def clear_all(self):
        """Clear all cookies"""
        self.cookies.clear()
        self.logger.info("Cleared all cookies")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert cookie jar to dictionary for serialization"""
        return {
            domain: {name: cookie.to_dict() for name, cookie in cookies.items()}
            for domain, cookies in self.cookies.items()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CookieJar':
        """Create cookie jar from dictionary"""
        jar = cls()
        for domain, cookies in data.items():
            jar.cookies[domain] = {
                name: Cookie.from_dict(cookie_data)
                for name, cookie_data in cookies.items()
            }
        return jar


class CookieManager:
    """High-level cookie management for browser sessions"""
    
    def __init__(self):
        self.jar = CookieJar()
        self.logger = logging.getLogger(__name__)
        
        # Common cookie patterns for extraction
        self.cookie_patterns = [
            r'Set-Cookie:\s*([^;\r\n]+(?:;[^;\r\n]+)*)',
            r'document\.cookie\s*=\s*["\']([^"\']+)["\']',
            r'setCookie\(["\']([^"\']+)["\']',
        ]
    
    def extract_cookies_from_headers(self, headers: Dict[str, str], url: str):
        """Extract cookies from HTTP response headers"""
        set_cookie_headers = []
        
        # Handle different header formats
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                if isinstance(value, list):
                    set_cookie_headers.extend(value)
                else:
                    set_cookie_headers.append(value)
        
        # Parse each Set-Cookie header
        for header_value in set_cookie_headers:
            cookie = self._parse_set_cookie_header(header_value, url)
            if cookie:
                self.jar.add_cookie(cookie)
    
    def extract_cookies_from_html(self, html_content: str, url: str):
        """Extract cookies from HTML content (JavaScript cookie setting)"""
        try:
            # Look for document.cookie assignments
            js_cookie_pattern = r'document\.cookie\s*=\s*["\']([^"\']+)["\']'
            matches = re.findall(js_cookie_pattern, html_content, re.IGNORECASE)
            
            for match in matches:
                cookie = self._parse_cookie_string(match, url)
                if cookie:
                    self.jar.add_cookie(cookie)
            
            # Look for setCookie function calls
            set_cookie_pattern = r'setCookie\s*\(\s*["\']([^"\']+)["\']'
            matches = re.findall(set_cookie_pattern, html_content, re.IGNORECASE)
            
            for match in matches:
                cookie = self._parse_cookie_string(match, url)
                if cookie:
                    self.jar.add_cookie(cookie)
            
        except Exception as e:
            self.logger.error(f"Error extracting cookies from HTML: {e}")
    
    def _parse_set_cookie_header(self, header_value: str, url: str) -> Optional[Cookie]:
        """Parse a Set-Cookie header value"""
        try:
            # Use SimpleCookie for parsing
            simple_cookie = SimpleCookie()
            simple_cookie.load(header_value)
            
            if not simple_cookie:
                return None
            
            # Get the first (and usually only) cookie
            morsel = next(iter(simple_cookie.values()))
            
            # Extract domain from URL if not specified
            parsed_url = urlparse(url)
            domain = morsel.get('domain', '') or parsed_url.netloc
            
            # Parse expires
            expires = None
            if morsel.get('expires'):
                try:
                    expires_str = morsel['expires']
                    expires = datetime.strptime(expires_str, '%a, %d %b %Y %H:%M:%S %Z').timestamp()
                except:
                    pass
            
            # Parse max-age
            max_age = None
            if morsel.get('max-age'):
                try:
                    max_age = int(morsel['max-age'])
                except:
                    pass
            
            cookie = Cookie(
                name=morsel.key,
                value=morsel.value,
                domain=domain,
                path=morsel.get('path', '/'),
                expires=expires,
                max_age=max_age,
                secure=bool(morsel.get('secure')),
                http_only=bool(morsel.get('httponly')),
                same_site=morsel.get('samesite')
            )
            
            return cookie
            
        except Exception as e:
            self.logger.error(f"Error parsing Set-Cookie header: {e}")
            return None
    
    def _parse_cookie_string(self, cookie_string: str, url: str) -> Optional[Cookie]:
        """Parse a cookie string (name=value; attributes)"""
        try:
            parts = [part.strip() for part in cookie_string.split(';')]
            if not parts:
                return None
            
            # First part is name=value
            name_value = parts[0]
            if '=' not in name_value:
                return None
            
            name, value = name_value.split('=', 1)
            name = name.strip()
            value = value.strip()
            
            # Parse attributes
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = '/'
            expires = None
            max_age = None
            secure = False
            http_only = False
            same_site = None
            
            for part in parts[1:]:
                if '=' in part:
                    attr_name, attr_value = part.split('=', 1)
                    attr_name = attr_name.strip().lower()
                    attr_value = attr_value.strip()
                    
                    if attr_name == 'domain':
                        domain = attr_value
                    elif attr_name == 'path':
                        path = attr_value
                    elif attr_name == 'expires':
                        try:
                            expires = datetime.strptime(attr_value, '%a, %d %b %Y %H:%M:%S %Z').timestamp()
                        except:
                            pass
                    elif attr_name == 'max-age':
                        try:
                            max_age = int(attr_value)
                        except:
                            pass
                    elif attr_name == 'samesite':
                        same_site = attr_value
                else:
                    attr_name = part.strip().lower()
                    if attr_name == 'secure':
                        secure = True
                    elif attr_name == 'httponly':
                        http_only = True
            
            return Cookie(
                name=name,
                value=value,
                domain=domain,
                path=path,
                expires=expires,
                max_age=max_age,
                secure=secure,
                http_only=http_only,
                same_site=same_site
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing cookie string: {e}")
            return None
    
    def get_cookies_for_request(self, url: str) -> Dict[str, str]:
        """Get cookies as a dictionary for request headers"""
        cookies = self.jar.get_cookies_for_url(url)
        return {cookie.name: cookie.value for cookie in cookies}
    
    def get_cookie_header(self, url: str) -> Optional[str]:
        """Get the Cookie header value for a request"""
        return self.jar.get_cookie_header(url)
    
    def add_cookie_from_string(self, cookie_string: str, url: str):
        """Add a cookie from a string representation"""
        cookie = self._parse_cookie_string(cookie_string, url)
        if cookie:
            self.jar.add_cookie(cookie)
    
    def set_cookie(self, name: str, value: str, domain: str, **kwargs):
        """Manually set a cookie"""
        cookie = Cookie(name=name, value=value, domain=domain, **kwargs)
        self.jar.add_cookie(cookie)
    
    def get_cookie(self, name: str, domain: str = None) -> Optional[Cookie]:
        """Get a specific cookie by name and domain"""
        if domain:
            domain_cookies = self.jar.cookies.get(domain.lower(), {})
            return domain_cookies.get(name)
        else:
            # Search all domains
            for domain_cookies in self.jar.cookies.values():
                if name in domain_cookies:
                    return domain_cookies[name]
            return None
    
    def delete_cookie(self, name: str, domain: str = None):
        """Delete a specific cookie"""
        if domain:
            domain = domain.lower()
            if domain in self.jar.cookies and name in self.jar.cookies[domain]:
                del self.jar.cookies[domain][name]
                self.logger.info(f"Deleted cookie: {name} from domain {domain}")
        else:
            # Delete from all domains
            for domain in self.jar.cookies:
                if name in self.jar.cookies[domain]:
                    del self.jar.cookies[domain][name]
                    self.logger.info(f"Deleted cookie: {name} from domain {domain}")
    
    def cleanup_expired(self):
        """Remove expired cookies"""
        self.jar.remove_expired_cookies()
    
    def save_to_file(self, filepath: str):
        """Save cookies to a JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.jar.to_dict(), f, indent=2)
            self.logger.info(f"Saved cookies to {filepath}")
        except Exception as e:
            self.logger.error(f"Error saving cookies: {e}")
    
    def load_from_file(self, filepath: str):
        """Load cookies from a JSON file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            self.jar = CookieJar.from_dict(data)
            self.logger.info(f"Loaded cookies from {filepath}")
        except Exception as e:
            self.logger.error(f"Error loading cookies: {e}")
    
    def get_session_cookies(self, domain: str = None) -> List[Cookie]:
        """Get all session cookies (no expiry) for a domain"""
        cookies = []
        
        domains_to_check = [domain.lower()] if domain else self.jar.cookies.keys()
        
        for check_domain in domains_to_check:
            if check_domain in self.jar.cookies:
                for cookie in self.jar.cookies[check_domain].values():
                    if cookie.expires is None and cookie.max_age is None:
                        cookies.append(cookie)
        
        return cookies
    
    def get_persistent_cookies(self, domain: str = None) -> List[Cookie]:
        """Get all persistent cookies (with expiry) for a domain"""
        cookies = []
        
        domains_to_check = [domain.lower()] if domain else self.jar.cookies.keys()
        
        for check_domain in domains_to_check:
            if check_domain in self.jar.cookies:
                for cookie in self.jar.cookies[check_domain].values():
                    if cookie.expires is not None or cookie.max_age is not None:
                        if not cookie.is_expired():
                            cookies.append(cookie)
        
        return cookies
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cookie statistics"""
        total_cookies = sum(len(cookies) for cookies in self.jar.cookies.values())
        session_cookies = len(self.get_session_cookies())
        persistent_cookies = len(self.get_persistent_cookies())
        expired_count = 0
        
        for domain_cookies in self.jar.cookies.values():
            for cookie in domain_cookies.values():
                if cookie.is_expired():
                    expired_count += 1
        
        return {
            'total_cookies': total_cookies,
            'session_cookies': session_cookies,
            'persistent_cookies': persistent_cookies,
            'expired_cookies': expired_count,
            'domains': len(self.jar.cookies)
        }