"""
CAPTCHA Solver Integration

Provides integration with external CAPTCHA solving services like 2captcha
and anti-captcha for automated challenge solving.
"""

import asyncio
import base64
import json
import logging
import time
from typing import Dict, Optional, Any, List, Tuple
from urllib.parse import urljoin
import aiohttp
from bs4 import BeautifulSoup
import re


class CaptchaChallenge:
    """Represents a CAPTCHA challenge"""
    
    def __init__(self, challenge_type: str, site_key: str = '', image_data: str = '',
                 page_url: str = '', additional_data: Optional[Dict[str, Any]] = None):
        self.challenge_type = challenge_type  # recaptcha_v2, recaptcha_v3, hcaptcha, image, etc.
        self.site_key = site_key
        self.image_data = image_data
        self.page_url = page_url
        self.additional_data = additional_data or {}
        self.challenge_id = None
        self.solution = None
        self.created_at = time.time()


class TwoCaptchaSolver:
    """2captcha.com API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'http://2captcha.com'
        self.logger = logging.getLogger(__name__)
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def solve_recaptcha_v2(self, site_key: str, page_url: str, 
                                data_s: str = '', invisible: bool = False) -> Optional[str]:
        """Solve reCAPTCHA v2 challenge"""
        try:
            # Submit challenge
            submit_data = {
                'key': self.api_key,
                'method': 'userrecaptcha',
                'googlekey': site_key,
                'pageurl': page_url,
                'json': 1
            }
            
            if data_s:
                submit_data['data-s'] = data_s
            
            if invisible:
                submit_data['invisible'] = 1
            
            async with self.session.post(f"{self.base_url}/in.php", data=submit_data) as response:
                result = await response.json()
                
                if result.get('status') != 1:
                    self.logger.error(f"2captcha submit error: {result.get('error_text')}")
                    return None
                
                captcha_id = result.get('request')
                if not captcha_id:
                    return None
            
            # Wait for solution
            return await self._wait_for_solution(captcha_id)
            
        except Exception as e:
            self.logger.error(f"2captcha reCAPTCHA v2 error: {e}")
            return None
    
    async def solve_recaptcha_v3(self, site_key: str, page_url: str, 
                                action: str = 'verify', min_score: float = 0.3) -> Optional[str]:
        """Solve reCAPTCHA v3 challenge"""
        try:
            submit_data = {
                'key': self.api_key,
                'method': 'userrecaptcha',
                'version': 'v3',
                'googlekey': site_key,
                'pageurl': page_url,
                'action': action,
                'min_score': min_score,
                'json': 1
            }
            
            async with self.session.post(f"{self.base_url}/in.php", data=submit_data) as response:
                result = await response.json()
                
                if result.get('status') != 1:
                    self.logger.error(f"2captcha submit error: {result.get('error_text')}")
                    return None
                
                captcha_id = result.get('request')
                if not captcha_id:
                    return None
            
            return await self._wait_for_solution(captcha_id)
            
        except Exception as e:
            self.logger.error(f"2captcha reCAPTCHA v3 error: {e}")
            return None
    
    async def solve_hcaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        """Solve hCaptcha challenge"""
        try:
            submit_data = {
                'key': self.api_key,
                'method': 'hcaptcha',
                'sitekey': site_key,
                'pageurl': page_url,
                'json': 1
            }
            
            async with self.session.post(f"{self.base_url}/in.php", data=submit_data) as response:
                result = await response.json()
                
                if result.get('status') != 1:
                    self.logger.error(f"2captcha submit error: {result.get('error_text')}")
                    return None
                
                captcha_id = result.get('request')
                if not captcha_id:
                    return None
            
            return await self._wait_for_solution(captcha_id)
            
        except Exception as e:
            self.logger.error(f"2captcha hCaptcha error: {e}")
            return None
    
    async def solve_image_captcha(self, image_data: str, case_sensitive: bool = False,
                                 numeric_only: bool = False, min_length: int = 0,
                                 max_length: int = 0) -> Optional[str]:
        """Solve image-based CAPTCHA"""
        try:
            submit_data = {
                'key': self.api_key,
                'method': 'base64',
                'body': image_data,
                'json': 1
            }
            
            if case_sensitive:
                submit_data['regsense'] = 1
            
            if numeric_only:
                submit_data['numeric'] = 1
            
            if min_length > 0:
                submit_data['min_len'] = min_length
            
            if max_length > 0:
                submit_data['max_len'] = max_length
            
            async with self.session.post(f"{self.base_url}/in.php", data=submit_data) as response:
                result = await response.json()
                
                if result.get('status') != 1:
                    self.logger.error(f"2captcha submit error: {result.get('error_text')}")
                    return None
                
                captcha_id = result.get('request')
                if not captcha_id:
                    return None
            
            return await self._wait_for_solution(captcha_id)
            
        except Exception as e:
            self.logger.error(f"2captcha image CAPTCHA error: {e}")
            return None
    
    async def _wait_for_solution(self, captcha_id: str, timeout: int = 120) -> Optional[str]:
        """Wait for CAPTCHA solution"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                params = {
                    'key': self.api_key,
                    'action': 'get',
                    'id': captcha_id,
                    'json': 1
                }
                
                async with self.session.get(f"{self.base_url}/res.php", params=params) as response:
                    result = await response.json()
                    
                    if result.get('status') == 1:
                        return result.get('request')
                    elif result.get('error_text') == 'CAPCHA_NOT_READY':
                        await asyncio.sleep(5)
                        continue
                    else:
                        self.logger.error(f"2captcha solution error: {result.get('error_text')}")
                        return None
                        
            except Exception as e:
                self.logger.error(f"2captcha polling error: {e}")
                await asyncio.sleep(5)
        
        self.logger.error("2captcha solution timeout")
        return None
    
    async def get_balance(self) -> Optional[float]:
        """Get account balance"""
        try:
            params = {
                'key': self.api_key,
                'action': 'getbalance',
                'json': 1
            }
            
            async with self.session.get(f"{self.base_url}/res.php", params=params) as response:
                result = await response.json()
                
                if result.get('status') == 1:
                    return float(result.get('request', 0))
                
                return None
                
        except Exception as e:
            self.logger.error(f"2captcha balance error: {e}")
            return None


class AntiCaptchaSolver:
    """anti-captcha.com API integration"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = 'https://api.anti-captcha.com'
        self.logger = logging.getLogger(__name__)
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def solve_recaptcha_v2(self, site_key: str, page_url: str, 
                                data_s: str = '', invisible: bool = False) -> Optional[str]:
        """Solve reCAPTCHA v2 challenge"""
        try:
            task_data = {
                'clientKey': self.api_key,
                'task': {
                    'type': 'NoCaptchaTaskProxyless',
                    'websiteURL': page_url,
                    'websiteKey': site_key
                }
            }
            
            if data_s:
                task_data['task']['dataS'] = data_s
            
            if invisible:
                task_data['task']['isInvisible'] = True
            
            # Create task
            async with self.session.post(f"{self.base_url}/createTask", json=task_data) as response:
                result = await response.json()
                
                if result.get('errorId') != 0:
                    self.logger.error(f"Anti-captcha create task error: {result.get('errorDescription')}")
                    return None
                
                task_id = result.get('taskId')
                if not task_id:
                    return None
            
            # Wait for solution
            return await self._wait_for_solution(task_id)
            
        except Exception as e:
            self.logger.error(f"Anti-captcha reCAPTCHA v2 error: {e}")
            return None
    
    async def solve_recaptcha_v3(self, site_key: str, page_url: str, 
                                action: str = 'verify', min_score: float = 0.3) -> Optional[str]:
        """Solve reCAPTCHA v3 challenge"""
        try:
            task_data = {
                'clientKey': self.api_key,
                'task': {
                    'type': 'RecaptchaV3TaskProxyless',
                    'websiteURL': page_url,
                    'websiteKey': site_key,
                    'pageAction': action,
                    'minScore': min_score
                }
            }
            
            async with self.session.post(f"{self.base_url}/createTask", json=task_data) as response:
                result = await response.json()
                
                if result.get('errorId') != 0:
                    self.logger.error(f"Anti-captcha create task error: {result.get('errorDescription')}")
                    return None
                
                task_id = result.get('taskId')
                if not task_id:
                    return None
            
            return await self._wait_for_solution(task_id)
            
        except Exception as e:
            self.logger.error(f"Anti-captcha reCAPTCHA v3 error: {e}")
            return None
    
    async def solve_hcaptcha(self, site_key: str, page_url: str) -> Optional[str]:
        """Solve hCaptcha challenge"""
        try:
            task_data = {
                'clientKey': self.api_key,
                'task': {
                    'type': 'HCaptchaTaskProxyless',
                    'websiteURL': page_url,
                    'websiteKey': site_key
                }
            }
            
            async with self.session.post(f"{self.base_url}/createTask", json=task_data) as response:
                result = await response.json()
                
                if result.get('errorId') != 0:
                    self.logger.error(f"Anti-captcha create task error: {result.get('errorDescription')}")
                    return None
                
                task_id = result.get('taskId')
                if not task_id:
                    return None
            
            return await self._wait_for_solution(task_id)
            
        except Exception as e:
            self.logger.error(f"Anti-captcha hCaptcha error: {e}")
            return None
    
    async def solve_image_captcha(self, image_data: str, case_sensitive: bool = False,
                                 numeric_only: bool = False) -> Optional[str]:
        """Solve image-based CAPTCHA"""
        try:
            task_data = {
                'clientKey': self.api_key,
                'task': {
                    'type': 'ImageToTextTask',
                    'body': image_data,
                    'case': case_sensitive,
                    'numeric': numeric_only
                }
            }
            
            async with self.session.post(f"{self.base_url}/createTask", json=task_data) as response:
                result = await response.json()
                
                if result.get('errorId') != 0:
                    self.logger.error(f"Anti-captcha create task error: {result.get('errorDescription')}")
                    return None
                
                task_id = result.get('taskId')
                if not task_id:
                    return None
            
            return await self._wait_for_solution(task_id)
            
        except Exception as e:
            self.logger.error(f"Anti-captcha image CAPTCHA error: {e}")
            return None
    
    async def _wait_for_solution(self, task_id: int, timeout: int = 120) -> Optional[str]:
        """Wait for CAPTCHA solution"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                task_data = {
                    'clientKey': self.api_key,
                    'taskId': task_id
                }
                
                async with self.session.post(f"{self.base_url}/getTaskResult", json=task_data) as response:
                    result = await response.json()
                    
                    if result.get('errorId') != 0:
                        self.logger.error(f"Anti-captcha solution error: {result.get('errorDescription')}")
                        return None
                    
                    if result.get('status') == 'ready':
                        solution = result.get('solution', {})
                        return solution.get('gRecaptchaResponse') or solution.get('text')
                    elif result.get('status') == 'processing':
                        await asyncio.sleep(5)
                        continue
                    else:
                        self.logger.error(f"Anti-captcha unknown status: {result.get('status')}")
                        return None
                        
            except Exception as e:
                self.logger.error(f"Anti-captcha polling error: {e}")
                await asyncio.sleep(5)
        
        self.logger.error("Anti-captcha solution timeout")
        return None
    
    async def get_balance(self) -> Optional[float]:
        """Get account balance"""
        try:
            balance_data = {
                'clientKey': self.api_key
            }
            
            async with self.session.post(f"{self.base_url}/getBalance", json=balance_data) as response:
                result = await response.json()
                
                if result.get('errorId') == 0:
                    return float(result.get('balance', 0))
                
                return None
                
        except Exception as e:
            self.logger.error(f"Anti-captcha balance error: {e}")
            return None


class CaptchaSolver:
    """Main CAPTCHA solver with multiple service support"""
    
    def __init__(self, primary_service: str = '2captcha', 
                 api_keys: Optional[Dict[str, str]] = None):
        self.primary_service = primary_service
        self.api_keys = api_keys or {}
        self.logger = logging.getLogger(__name__)
        
        # Service priority order
        self.service_priority = ['2captcha', 'anticaptcha']
        
        # CAPTCHA detection patterns
        self.captcha_patterns = {
            'recaptcha_v2': [
                r'<div[^>]*class="g-recaptcha"[^>]*data-sitekey="([^"]+)"',
                r'grecaptcha\.render\([^,]*,\s*{\s*sitekey:\s*["\']([^"\']+)["\']',
                r'data-sitekey="([^"]+)"[^>]*class="g-recaptcha"'
            ],
            'recaptcha_v3': [
                r'grecaptcha\.execute\(["\']([^"\']+)["\']',
                r'data-sitekey="([^"]+)"[^>]*data-action="([^"]+)"'
            ],
            'hcaptcha': [
                r'<div[^>]*class="h-captcha"[^>]*data-sitekey="([^"]+)"',
                r'hcaptcha\.render\([^,]*,\s*{\s*sitekey:\s*["\']([^"\']+)["\']'
            ],
            'turnstile': [
                r'<div[^>]*class="cf-turnstile"[^>]*data-sitekey="([^"]+)"'
            ]
        }
    
    def detect_captcha(self, html_content: str, url: str) -> List[CaptchaChallenge]:
        """Detect CAPTCHA challenges in HTML content"""
        challenges = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Detect reCAPTCHA v2
            recaptcha_divs = soup.find_all('div', class_=re.compile(r'g-recaptcha'))
            for div in recaptcha_divs:
                site_key = div.get('data-sitekey')
                if site_key:
                    challenges.append(CaptchaChallenge(
                        challenge_type='recaptcha_v2',
                        site_key=site_key,
                        page_url=url,
                        additional_data={
                            'data_s': div.get('data-s', ''),
                            'invisible': div.get('data-size') == 'invisible'
                        }
                    ))
            
            # Detect hCaptcha
            hcaptcha_divs = soup.find_all('div', class_=re.compile(r'h-captcha'))
            for div in hcaptcha_divs:
                site_key = div.get('data-sitekey')
                if site_key:
                    challenges.append(CaptchaChallenge(
                        challenge_type='hcaptcha',
                        site_key=site_key,
                        page_url=url
                    ))
            
            # Detect Turnstile
            turnstile_divs = soup.find_all('div', class_=re.compile(r'cf-turnstile'))
            for div in turnstile_divs:
                site_key = div.get('data-sitekey')
                if site_key:
                    challenges.append(CaptchaChallenge(
                        challenge_type='turnstile',
                        site_key=site_key,
                        page_url=url,
                        additional_data={
                            'action': div.get('data-action', ''),
                            'cdata': div.get('data-cdata', '')
                        }
                    ))
            
            # Detect JavaScript-based CAPTCHAs
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string:
                    # reCAPTCHA v3
                    v3_match = re.search(r'grecaptcha\.execute\(["\']([^"\']+)["\']', script.string)
                    if v3_match:
                        challenges.append(CaptchaChallenge(
                            challenge_type='recaptcha_v3',
                            site_key=v3_match.group(1),
                            page_url=url
                        ))
            
            # Detect image CAPTCHAs
            captcha_images = soup.find_all('img', src=re.compile(r'captcha|challenge'))
            for img in captcha_images:
                src = img.get('src')
                if src:
                    challenges.append(CaptchaChallenge(
                        challenge_type='image',
                        image_data=src,
                        page_url=url
                    ))
            
        except Exception as e:
            self.logger.error(f"Error detecting CAPTCHAs: {e}")
        
        return challenges
    
    async def solve_challenge(self, challenge: CaptchaChallenge) -> Optional[str]:
        """Solve a CAPTCHA challenge using available services"""
        for service_name in self.service_priority:
            if service_name not in self.api_keys:
                continue
            
            try:
                solution = await self._solve_with_service(challenge, service_name)
                if solution:
                    self.logger.info(f"CAPTCHA solved with {service_name}")
                    return solution
            except Exception as e:
                self.logger.error(f"Error solving with {service_name}: {e}")
                continue
        
        self.logger.error("Failed to solve CAPTCHA with all services")
        return None
    
    async def _solve_with_service(self, challenge: CaptchaChallenge, service_name: str) -> Optional[str]:
        """Solve challenge with specific service"""
        api_key = self.api_keys.get(service_name)
        if not api_key:
            return None
        
        if service_name == '2captcha':
            async with TwoCaptchaSolver(api_key) as solver:
                return await self._solve_with_2captcha(solver, challenge)
        elif service_name == 'anticaptcha':
            async with AntiCaptchaSolver(api_key) as solver:
                return await self._solve_with_anticaptcha(solver, challenge)
        
        return None
    
    async def _solve_with_2captcha(self, solver: TwoCaptchaSolver, challenge: CaptchaChallenge) -> Optional[str]:
        """Solve challenge with 2captcha"""
        if challenge.challenge_type == 'recaptcha_v2':
            return await solver.solve_recaptcha_v2(
                challenge.site_key,
                challenge.page_url,
                challenge.additional_data.get('data_s', ''),
                challenge.additional_data.get('invisible', False)
            )
        elif challenge.challenge_type == 'recaptcha_v3':
            return await solver.solve_recaptcha_v3(
                challenge.site_key,
                challenge.page_url,
                challenge.additional_data.get('action', 'verify'),
                challenge.additional_data.get('min_score', 0.3)
            )
        elif challenge.challenge_type == 'hcaptcha':
            return await solver.solve_hcaptcha(challenge.site_key, challenge.page_url)
        elif challenge.challenge_type == 'image':
            # Convert image URL to base64 if needed
            image_data = challenge.image_data
            if image_data.startswith('http'):
                # Download and convert to base64
                image_data = await self._download_image_as_base64(image_data)
            
            return await solver.solve_image_captcha(image_data)
        
        return None
    
    async def _solve_with_anticaptcha(self, solver: AntiCaptchaSolver, challenge: CaptchaChallenge) -> Optional[str]:
        """Solve challenge with anti-captcha"""
        if challenge.challenge_type == 'recaptcha_v2':
            return await solver.solve_recaptcha_v2(
                challenge.site_key,
                challenge.page_url,
                challenge.additional_data.get('data_s', ''),
                challenge.additional_data.get('invisible', False)
            )
        elif challenge.challenge_type == 'recaptcha_v3':
            return await solver.solve_recaptcha_v3(
                challenge.site_key,
                challenge.page_url,
                challenge.additional_data.get('action', 'verify'),
                challenge.additional_data.get('min_score', 0.3)
            )
        elif challenge.challenge_type == 'hcaptcha':
            return await solver.solve_hcaptcha(challenge.site_key, challenge.page_url)
        elif challenge.challenge_type == 'image':
            image_data = challenge.image_data
            if image_data.startswith('http'):
                image_data = await self._download_image_as_base64(image_data)
            
            return await solver.solve_image_captcha(image_data)
        
        return None
    
    async def _download_image_as_base64(self, image_url: str) -> str:
        """Download image and convert to base64"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(image_url) as response:
                    if response.status == 200:
                        image_data = await response.read()
                        return base64.b64encode(image_data).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Error downloading image: {e}")
        
        return ''
    
    async def solve_page_challenges(self, html_content: str, url: str) -> Dict[str, str]:
        """Detect and solve all CAPTCHA challenges on a page"""
        challenges = self.detect_captcha(html_content, url)
        solutions = {}
        
        for challenge in challenges:
            solution = await self.solve_challenge(challenge)
            if solution:
                key = f"{challenge.challenge_type}_{challenge.site_key or 'image'}"
                solutions[key] = solution
        
        return solutions
    
    def inject_solutions_into_form(self, html_content: str, solutions: Dict[str, str]) -> str:
        """Inject CAPTCHA solutions into form fields"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Inject reCAPTCHA solutions
            for key, solution in solutions.items():
                if key.startswith('recaptcha_v2_'):
                    # Find g-recaptcha-response fields
                    response_fields = soup.find_all('textarea', {'name': 'g-recaptcha-response'})
                    for field in response_fields:
                        field.string = solution
                
                elif key.startswith('recaptcha_v3_'):
                    # Inject into hidden fields or JavaScript
                    hidden_fields = soup.find_all('input', {'type': 'hidden'})
                    for field in hidden_fields:
                        if 'recaptcha' in field.get('name', '').lower():
                            field['value'] = solution
                
                elif key.startswith('hcaptcha_'):
                    # Find h-captcha-response fields
                    response_fields = soup.find_all('textarea', {'name': 'h-captcha-response'})
                    for field in response_fields:
                        field.string = solution
                
                elif key.startswith('turnstile_'):
                    # Find cf-turnstile-response fields
                    response_fields = soup.find_all('input', {'name': 'cf-turnstile-response'})
                    for field in response_fields:
                        field['value'] = solution
            
            return str(soup)
            
        except Exception as e:
            self.logger.error(f"Error injecting solutions: {e}")
            return html_content
    
    async def get_service_balances(self) -> Dict[str, Optional[float]]:
        """Get balances for all configured services"""
        balances = {}
        
        for service_name, api_key in self.api_keys.items():
            try:
                if service_name == '2captcha':
                    async with TwoCaptchaSolver(api_key) as solver:
                        balances[service_name] = await solver.get_balance()
                elif service_name == 'anticaptcha':
                    async with AntiCaptchaSolver(api_key) as solver:
                        balances[service_name] = await solver.get_balance()
            except Exception as e:
                self.logger.error(f"Error getting {service_name} balance: {e}")
                balances[service_name] = None
        
        return balances