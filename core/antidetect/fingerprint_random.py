"""
Fingerprint Randomization Module

Randomizes various fingerprints to evade detection:
- JA3/JA3S TLS fingerprints
- HTTP header fingerprints
- Browser fingerprints
- TCP/IP fingerprints
"""

import random
import hashlib
import struct
import ssl
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class FingerprintProfile:
    """Fingerprint profile"""
    name: str
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str
    headers_order: List[str]
    tls_version: int
    cipher_suites: List[int]
    extensions: List[int]


# Common browser profiles
BROWSER_PROFILES = [
    FingerprintProfile(
        name='chrome_120_win',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        accept='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        accept_language='en-US,en;q=0.9',
        accept_encoding='gzip, deflate, br',
        headers_order=['Host', 'Connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'Upgrade-Insecure-Requests', 'User-Agent', 'Accept', 'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-User', 'Sec-Fetch-Dest', 'Accept-Encoding', 'Accept-Language'],
        tls_version=0x0303,
        cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    ),
    FingerprintProfile(
        name='firefox_121_win',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        accept='text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        accept_language='en-US,en;q=0.5',
        accept_encoding='gzip, deflate, br',
        headers_order=['Host', 'User-Agent', 'Accept', 'Accept-Language', 'Accept-Encoding', 'Connection', 'Upgrade-Insecure-Requests', 'Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Sec-Fetch-User'],
        tls_version=0x0303,
        cipher_suites=[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033, 0x0039, 0x002f, 0x0035],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21],
    ),
    FingerprintProfile(
        name='safari_17_mac',
        user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        accept='text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        accept_language='en-US,en;q=0.9',
        accept_encoding='gzip, deflate, br',
        headers_order=['Host', 'Accept', 'Sec-Fetch-Site', 'Accept-Language', 'Sec-Fetch-Mode', 'Accept-Encoding', 'Sec-Fetch-Dest', 'User-Agent'],
        tls_version=0x0303,
        cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f],
        extensions=[0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
    ),
    FingerprintProfile(
        name='edge_120_win',
        user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        accept='text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        accept_language='en-US,en;q=0.9',
        accept_encoding='gzip, deflate, br',
        headers_order=['Host', 'Connection', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'Upgrade-Insecure-Requests', 'User-Agent', 'Accept', 'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-User', 'Sec-Fetch-Dest', 'Accept-Encoding', 'Accept-Language'],
        tls_version=0x0303,
        cipher_suites=[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
    ),
]


class FingerprintRandomizer:
    """
    Fingerprint Randomizer
    
    Randomizes browser fingerprints for each request.
    """
    
    def __init__(self, profiles: List[FingerprintProfile] = None):
        self.profiles = profiles or BROWSER_PROFILES
        self._current_profile: Optional[FingerprintProfile] = None
        
    def get_random_profile(self) -> FingerprintProfile:
        """Get random browser profile"""
        self._current_profile = random.choice(self.profiles)
        return self._current_profile
        
    def get_headers(self, host: str, path: str = '/') -> Dict[str, str]:
        """Get headers matching current profile"""
        if not self._current_profile:
            self.get_random_profile()
            
        profile = self._current_profile
        
        headers = {
            'Host': host,
            'User-Agent': profile.user_agent,
            'Accept': profile.accept,
            'Accept-Language': profile.accept_language,
            'Accept-Encoding': profile.accept_encoding,
            'Connection': 'keep-alive',
        }
        
        # Add Chrome-specific headers
        if 'Chrome' in profile.user_agent and 'Edg' not in profile.user_agent:
            headers.update({
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
                'Upgrade-Insecure-Requests': '1',
            })
        elif 'Edg' in profile.user_agent:
            headers.update({
                'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document',
            })
        elif 'Firefox' in profile.user_agent:
            headers.update({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            })
            
        return headers
        
    def build_request(self, method: str, host: str, path: str = '/', body: bytes = b'') -> bytes:
        """Build HTTP request with fingerprint-matched headers"""
        headers = self.get_headers(host, path)
        
        if body:
            headers['Content-Length'] = str(len(body))
            
        # Order headers according to profile
        profile = self._current_profile
        ordered_headers = []
        
        for header_name in profile.headers_order:
            if header_name in headers:
                ordered_headers.append((header_name, headers[header_name]))
                
        # Add remaining headers
        for key, value in headers.items():
            if key not in profile.headers_order:
                ordered_headers.append((key, value))
                
        request = f"{method} {path} HTTP/1.1\r\n"
        for key, value in ordered_headers:
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        
        return request.encode() + body


class JA3Randomizer:
    """
    JA3 Fingerprint Randomizer
    
    Randomizes TLS fingerprints to evade JA3-based detection.
    """
    
    # Known JA3 hashes for common browsers
    KNOWN_JA3 = {
        'chrome_120': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
        'firefox_121': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25,0',
        'safari_17': '771,4865-4866-4867-49196-49195-52393-49188-49187-49162-49161-49200-49199-52392-49192-49191-49172-49171-157-156-61-60-53-47-255,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0',
    }
    
    def __init__(self):
        self._current_ja3: Optional[str] = None
        
    def get_random_ja3(self) -> str:
        """Get random JA3 fingerprint"""
        self._current_ja3 = random.choice(list(self.KNOWN_JA3.values()))
        return self._current_ja3
        
    def get_ja3_hash(self, ja3_string: str = None) -> str:
        """Calculate JA3 hash"""
        ja3 = ja3_string or self._current_ja3 or self.get_random_ja3()
        return hashlib.md5(ja3.encode()).hexdigest()
        
    def parse_ja3(self, ja3_string: str) -> Dict[str, Any]:
        """Parse JA3 string into components"""
        parts = ja3_string.split(',')
        return {
            'tls_version': int(parts[0]),
            'cipher_suites': [int(x) for x in parts[1].split('-')] if parts[1] else [],
            'extensions': [int(x) for x in parts[2].split('-')] if parts[2] else [],
            'elliptic_curves': [int(x) for x in parts[3].split('-')] if parts[3] else [],
            'ec_point_formats': [int(x) for x in parts[4].split('-')] if parts[4] else [],
        }
        
    def generate_random_ja3(self) -> str:
        """Generate randomized JA3 string"""
        # TLS version (usually 771 = TLS 1.2)
        version = random.choice([769, 770, 771, 772])
        
        # Cipher suites
        common_ciphers = [
            4865, 4866, 4867,  # TLS 1.3
            49195, 49199, 49196, 49200,  # ECDHE
            52393, 52392,  # ChaCha20
            49171, 49172,  # ECDHE-RSA
            156, 157, 47, 53,  # AES
        ]
        num_ciphers = random.randint(8, 15)
        ciphers = random.sample(common_ciphers, min(num_ciphers, len(common_ciphers)))
        
        # Extensions
        common_extensions = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21]
        num_extensions = random.randint(10, 15)
        extensions = random.sample(common_extensions, min(num_extensions, len(common_extensions)))
        
        # Elliptic curves
        curves = [29, 23, 24, 25]
        random.shuffle(curves)
        
        # EC point formats
        formats = [0]
        
        ja3 = f"{version},{'-'.join(map(str, ciphers))},{'-'.join(map(str, extensions))},{'-'.join(map(str, curves))},{'-'.join(map(str, formats))}"
        
        self._current_ja3 = ja3
        return ja3


class HeaderRandomizer:
    """
    HTTP Header Randomizer
    
    Randomizes HTTP headers while maintaining validity.
    """
    
    # Header value variations
    ACCEPT_VARIATIONS = [
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8',
    ]
    
    ACCEPT_LANGUAGE_VARIATIONS = [
        'en-US,en;q=0.9',
        'en-US,en;q=0.5',
        'en-GB,en;q=0.9,en-US;q=0.8',
        'en;q=0.9',
        'en-US',
    ]
    
    ACCEPT_ENCODING_VARIATIONS = [
        'gzip, deflate, br',
        'gzip, deflate',
        'gzip, deflate, br, zstd',
        'br, gzip, deflate',
    ]
    
    CONNECTION_VARIATIONS = [
        'keep-alive',
        'Keep-Alive',
        'close',
    ]
    
    def __init__(self):
        self._cache: Dict[str, str] = {}
        
    def randomize_headers(self, base_headers: Dict[str, str]) -> Dict[str, str]:
        """Randomize header values"""
        headers = base_headers.copy()
        
        if 'Accept' in headers:
            headers['Accept'] = random.choice(self.ACCEPT_VARIATIONS)
            
        if 'Accept-Language' in headers:
            headers['Accept-Language'] = random.choice(self.ACCEPT_LANGUAGE_VARIATIONS)
            
        if 'Accept-Encoding' in headers:
            headers['Accept-Encoding'] = random.choice(self.ACCEPT_ENCODING_VARIATIONS)
            
        if 'Connection' in headers:
            headers['Connection'] = random.choice(self.CONNECTION_VARIATIONS)
            
        # Add random cache-control
        if random.random() < 0.3:
            headers['Cache-Control'] = random.choice(['no-cache', 'max-age=0', 'no-store'])
            
        # Add random DNT
        if random.random() < 0.5:
            headers['DNT'] = '1'
            
        return headers
        
    def randomize_header_order(self, headers: Dict[str, str]) -> List[Tuple[str, str]]:
        """Randomize header order"""
        items = list(headers.items())
        
        # Keep Host first
        host_item = None
        for i, (key, value) in enumerate(items):
            if key.lower() == 'host':
                host_item = items.pop(i)
                break
                
        # Shuffle remaining
        random.shuffle(items)
        
        if host_item:
            items.insert(0, host_item)
            
        return items
        
    def add_noise_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Add random noise headers"""
        noise_headers = [
            ('X-Requested-With', 'XMLHttpRequest'),
            ('X-Forwarded-For', f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}'),
            ('X-Real-IP', f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}'),
            ('Via', f'1.1 proxy{random.randint(1,99)}.example.com'),
        ]
        
        # Add 0-2 random noise headers
        for header, value in random.sample(noise_headers, random.randint(0, 2)):
            if header not in headers:
                headers[header] = value
                
        return headers
