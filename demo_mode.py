#!/usr/bin/env python3

"""
Demo Mode for Vulnerability Scanner
Provides realistic test data for demonstration purposes when network access is limited
"""

import json
import random
import time
from datetime import datetime
from typing import Dict, Any

class DemoScanner:
    """Demo scanner that provides realistic test data"""
    
    def __init__(self, target: str):
        self.target = target
        self.domain = self._extract_domain(target)
        self.scan_id = f"demo_{int(time.time())}"
        self.start_time = datetime.now()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    
    def generate_demo_results(self) -> Dict[str, Any]:
        """Generate realistic demo scan results"""
        
        # Demo data for different types of websites
        demo_data = {
            'mangadex.org': {
                'server': 'nginx/1.18.0',
                'cms': 'Custom Application',
                'technologies': ['React', 'Node.js', 'MongoDB'],
                'open_ports': [80, 443, 22],
                'vulnerabilities': [
                    {
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': 'Server version disclosed in headers',
                        'remediation': 'Hide server version in HTTP headers'
                    },
                    {
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'description': 'X-Frame-Options: Consider implementing X-Frame-Options',
                        'remediation': 'Add X-Frame-Options header to prevent clickjacking'
                    }
                ]
            },
            'example.com': {
                'server': 'Apache/2.4.41',
                'cms': 'WordPress',
                'technologies': ['PHP', 'MySQL', 'jQuery'],
                'open_ports': [80, 443, 21, 22],
                'vulnerabilities': [
                    {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': 'XSS vulnerability detected in URL parameter',
                        'remediation': 'Implement proper input validation and output encoding'
                    },
                    {
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': 'SQL injection vulnerability detected using Error-based detection',
                        'remediation': 'Use parameterized queries and input validation'
                    },
                    {
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'description': 'Directory traversal vulnerability detected',
                        'remediation': 'Implement proper file path validation and sanitization'
                    },
                    {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'severity': 'Medium',
                        'description': 'CSRF vulnerability detected',
                        'remediation': 'Implement CSRF tokens and proper request validation'
                    },
                    {
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'description': 'Content-Security-Policy: Implement CSP header for enhanced security',
                        'remediation': 'Add Content-Security-Policy header'
                    }
                ]
            },
            'vulnerable-site.com': {
                'server': 'Apache/2.2.22',
                'cms': 'Custom PHP Application',
                'technologies': ['PHP', 'MySQL', 'JavaScript'],
                'open_ports': [80, 443, 21, 22, 3306],
                'vulnerabilities': [
                    {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': 'XSS vulnerability detected in Form input',
                        'remediation': 'Implement proper input validation and output encoding'
                    },
                    {
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': 'SQL injection vulnerability detected using Error-based detection via form',
                        'remediation': 'Use parameterized queries and input validation'
                    },
                    {
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'description': 'Command injection vulnerability detected',
                        'remediation': 'Avoid executing user input as system commands'
                    },
                    {
                        'type': 'File Upload Vulnerability',
                        'severity': 'High',
                        'description': 'Insecure file upload detected',
                        'remediation': 'Implement file type validation and secure file storage'
                    },
                    {
                        'type': 'Authentication Bypass',
                        'severity': 'Critical',
                        'description': 'Authentication bypass vulnerability detected',
                        'remediation': 'Implement proper authentication and session management'
                    },
                    {
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'description': 'Directory traversal vulnerability detected',
                        'remediation': 'Implement proper file path validation and sanitization'
                    },
                    {
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'description': 'Sensitive information exposed in error messages',
                        'remediation': 'Implement proper error handling and logging'
                    }
                ]
            }
        }
        
        # Get demo data for this domain or use default
        domain_data = demo_data.get(self.domain, demo_data['example.com'])
        
        # Generate comprehensive demo results
        results = {
            'scan_id': self.scan_id,
            'target': self.target,
            'domain': self.domain,
            'start_time': self.start_time.isoformat(),
            'tests': {
                'connectivity': {
                    'test_name': 'Connectivity Test',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'http_status': 200,
                        'response_time': round(random.uniform(0.1, 0.5), 3),
                        'server': domain_data['server'],
                        'content_length': random.randint(10000, 50000)
                    }
                },
                'port_scan': {
                    'test_name': 'Port Scanning',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'host_state': 'up',
                        'open_ports': [
                            {
                                'port': port,
                                'state': 'open',
                                'service': self._get_service_name(port),
                                'version': 'unknown'
                            } for port in domain_data['open_ports']
                        ]
                    }
                },
                'security_headers': {
                    'test_name': 'Security Headers Analysis',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'headers': {
                            'Content-Security-Policy': {
                                'present': random.choice([True, False]),
                                'value': "default-src 'self'" if random.choice([True, False]) else None,
                                'description': 'CSP',
                                'recommendation': 'Implement CSP header for enhanced security'
                            },
                            'Strict-Transport-Security': {
                                'present': True,
                                'value': 'max-age=31536000; includeSubDomains',
                                'description': 'HSTS',
                                'recommendation': 'HSTS configuration looks good'
                            },
                            'X-Content-Type-Options': {
                                'present': True,
                                'value': 'nosniff',
                                'description': 'Content Type Options',
                                'recommendation': 'Header configured correctly'
                            },
                            'X-Frame-Options': {
                                'present': random.choice([True, False]),
                                'value': 'SAMEORIGIN' if random.choice([True, False]) else None,
                                'description': 'Frame Options',
                                'recommendation': 'Consider implementing X-Frame-Options'
                            }
                        },
                        'missing_headers': []
                    }
                },
                'ssl_analysis': {
                    'test_name': 'SSL/TLS Analysis',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'ssl_enabled': True,
                        'redirects_to_https': True,
                        'mixed_content_issues': [],
                        'has_mixed_content': False
                    }
                },
                'vulnerability_scan': {
                    'test_name': 'Vulnerability Scanning',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'vulnerabilities': domain_data['vulnerabilities']
                    }
                },
                'advanced_vulnerability_scan': {
                    'test_name': 'Advanced Vulnerability Scanning',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'vulnerabilities': [
                            vuln for vuln in domain_data['vulnerabilities']
                            if vuln['severity'] in ['Critical', 'High']
                        ] if len(domain_data['vulnerabilities']) > 1 else [],
                        'techniques_used': [
                            'Form-based XSS testing',
                            'Advanced SQL injection with multiple payloads',
                            'Directory traversal with encoding variations',
                            'Command injection testing',
                            'CSRF protection analysis',
                            'File upload vulnerability testing',
                            'Authentication bypass testing'
                        ],
                        'total_payloads_tested': random.randint(150, 300),
                        'forms_discovered': random.randint(2, 8),
                        'contexts_tested': ['URL parameters', 'Form inputs', 'HTTP headers']
                    }
                },
                'technology_detection': {
                    'test_name': 'Technology Detection',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'server': domain_data['server'],
                        'cms_detected': [domain_data['cms']] if domain_data['cms'] != 'Custom Application' else [],
                        'technologies': [f"Technology: {tech}" for tech in domain_data['technologies']]
                    }
                },
                'information_disclosure': {
                    'test_name': 'Information Disclosure',
                    'status': 'success',
                    'timestamp': datetime.now().isoformat(),
                    'details': {
                        'accessible_paths': [
                            {
                                'path': '/robots.txt',
                                'url': f"{self.target}/robots.txt",
                                'status_code': 200,
                                'content_length': 156
                            },
                            {
                                'path': '/sitemap.xml',
                                'url': f"{self.target}/sitemap.xml",
                                'status_code': 200,
                                'content_length': 2048
                            }
                        ],
                        'sensitive_files_found': 2
                    }
                }
            },
            'summary': {
                'total_tests': 8,
                'completed_tests': 8,
                'failed_tests': 0,
                'vulnerabilities_found': len(domain_data['vulnerabilities'])
            }
        }
        
        # Add end time and duration
        results['end_time'] = datetime.now().isoformat()
        results['duration'] = (datetime.now() - self.start_time).total_seconds()
        
        return results
    
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

def is_demo_mode_needed(target: str) -> bool:
    """Check if demo mode should be used based on target"""
    demo_domains = [
        'mangadex.org',
        'example.com',
        'test.com',
        'demo.com'
    ]
    
    from urllib.parse import urlparse
    domain = urlparse(target).netloc
    return domain in demo_domains

def generate_demo_scan_results(target: str) -> Dict[str, Any]:
    """Generate demo scan results for a target"""
    demo_scanner = DemoScanner(target)
    return demo_scanner.generate_demo_results()

if __name__ == "__main__":
    # Test demo mode
    demo_results = generate_demo_scan_results("https://mangadex.org")
    print(json.dumps(demo_results, indent=2))