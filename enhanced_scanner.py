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
    
    def __init__(self, target: str, max_workers: int = 10, timeout: int = 30):
        self.original_target = target
        self.target = self._normalize_target(target)
        self.domain = self._extract_domain(self.target)
        self.max_workers = max_workers
        self.timeout = timeout
        self.session = self._create_session()
        self.scan_id = self._generate_scan_id()
        self.start_time = datetime.now()
        self.progress_callback = None
        self.cache = {}
        self.scan_results = {}
        
        logger.info(f"Initialized scanner for target: {self.target} (domain: {self.domain})")
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL to ensure proper format"""
        if not target:
            raise ValueError("Target URL cannot be empty")
        
        # Remove any whitespace
        target = target.strip()
        
        # Add protocol if missing
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Validate URL format
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL format: {target}")
        
        return target
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper configuration"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'VulnScanner/2.0 (Professional Security Scanner)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        session.verify = False
        return session
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_hash = hashlib.md5(self.target.encode()).hexdigest()[:8]
        return f"scan_{timestamp}_{target_hash}"
    
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, percentage: float, message: str):
        """Update scan progress"""
        if self.progress_callback:
            self.progress_callback(percentage, message)
        logger.info(f"Progress: {percentage:.1f}% - {message}")
    
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
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        
        try:
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((self.domain, port))
                    if result == 0:
                        test_result['details']['open_ports'].append({
                            'port': port,
                            'state': 'open',
                            'service': self._get_service_name(port)
                        })
                    sock.close()
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
        """Scan for common vulnerabilities"""
        test_result = {
            'test_name': 'Vulnerability Scanning',
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'details': {'vulnerabilities': []}
        }
        
        try:
            # XSS Detection
            xss_result = self._test_xss()
            if xss_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'description': 'Potential XSS vulnerability detected',
                    'details': xss_result
                })
            
            # SQL Injection Detection
            sqli_result = self._test_sql_injection()
            if sqli_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'description': 'Potential SQL injection vulnerability detected',
                    'details': sqli_result
                })
            
            # Directory Traversal
            dir_traversal_result = self._test_directory_traversal()
            if dir_traversal_result['vulnerable']:
                test_result['details']['vulnerabilities'].append({
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'description': 'Potential directory traversal vulnerability detected',
                    'details': dir_traversal_result
                })
            
            test_result['status'] = 'success'
            
        except Exception as e:
            test_result['status'] = 'error'
            test_result['error'] = str(e)
            logger.error(f"Vulnerability scanning failed: {e}")
        
        return test_result
    
    def _test_xss(self) -> Dict[str, Any]:
        """Test for XSS vulnerabilities"""
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "javascript:alert('XSS')"
        ]
        
        result = {'vulnerable': False, 'payloads_tested': len(payloads), 'responses': []}
        
        try:
            for payload in payloads:
                # Test in URL parameters
                test_url = f"{self.target}?q={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                
                if payload in response.text:
                    result['vulnerable'] = True
                    result['responses'].append({
                        'payload': payload,
                        'reflected': True,
                        'url': test_url
                    })
                    break
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
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
            ('information_disclosure', self._information_disclosure)
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