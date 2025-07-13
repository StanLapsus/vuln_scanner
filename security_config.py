#!/usr/bin/env python3

"""
Security Configuration Module for Vulnerability Scanner
Centralized security settings and limits
"""

import os
from typing import Dict, Any

class SecurityConfig:
    """Centralized security configuration"""
    
    def __init__(self):
        self.config = {
            # Request limits
            'MAX_REQUEST_SIZE': int(os.getenv('VULN_SCANNER_MAX_REQUEST_SIZE', '1048576')),  # 1MB
            'MAX_FILE_SIZE': int(os.getenv('VULN_SCANNER_MAX_FILE_SIZE', '10485760')),  # 10MB
            'MAX_URL_LENGTH': int(os.getenv('VULN_SCANNER_MAX_URL_LENGTH', '2048')),
            
            # Rate limiting
            'RATE_LIMIT_REQUESTS_PER_MINUTE': int(os.getenv('VULN_SCANNER_RATE_LIMIT', '30')),
            'RATE_LIMIT_WINDOW_SECONDS': int(os.getenv('VULN_SCANNER_RATE_WINDOW', '60')),
            
            # Authentication
            'MAX_FAILED_LOGIN_ATTEMPTS': int(os.getenv('VULN_SCANNER_MAX_FAILED_ATTEMPTS', '5')),
            'LOCKOUT_DURATION_SECONDS': int(os.getenv('VULN_SCANNER_LOCKOUT_DURATION', '900')),  # 15 minutes
            'SESSION_TIMEOUT_SECONDS': int(os.getenv('VULN_SCANNER_SESSION_TIMEOUT', '3600')),  # 1 hour
            
            # Timeouts
            'HTTP_CONNECT_TIMEOUT': int(os.getenv('VULN_SCANNER_CONNECT_TIMEOUT', '5')),
            'HTTP_READ_TIMEOUT': int(os.getenv('VULN_SCANNER_READ_TIMEOUT', '30')),
            'SCAN_TIMEOUT': int(os.getenv('VULN_SCANNER_SCAN_TIMEOUT', '1800')),  # 30 minutes
            
            # Resource limits
            'MAX_CONCURRENT_SCANS': int(os.getenv('VULN_SCANNER_MAX_CONCURRENT_SCANS', '3')),
            'MAX_SCAN_WORKERS': int(os.getenv('VULN_SCANNER_MAX_WORKERS', '10')),
            'MAX_MEMORY_USAGE_MB': int(os.getenv('VULN_SCANNER_MAX_MEMORY_MB', '512')),
            'MAX_CPU_USAGE_PERCENT': int(os.getenv('VULN_SCANNER_MAX_CPU_PERCENT', '80')),
            
            # Security headers
            'SECURITY_HEADERS': {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            },
            
            # File type restrictions
            'ALLOWED_STATIC_EXTENSIONS': {'.css', '.js', '.png', '.jpg', '.jpeg', '.ico', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot'},
            'BLOCKED_FILE_PATTERNS': [
                '.env', '.git', '.svn', '.hg', '.config', '.backup', '.bak', '.tmp', '.log',
                'passwd', 'shadow', 'hosts', 'config', 'settings', 'database', 'db'
            ],
            
            # IP restrictions
            'BLOCK_PRIVATE_IPS': os.getenv('VULN_SCANNER_BLOCK_PRIVATE_IPS', 'true').lower() == 'true',
            'BLOCK_LOCAL_IPS': os.getenv('VULN_SCANNER_BLOCK_LOCAL_IPS', 'true').lower() == 'true',
            'ALLOWED_SCHEMES': ['http', 'https'],
            'BLOCKED_SCHEMES': ['file', 'ftp', 'javascript', 'data', 'vbscript', 'about'],
            
            # Logging
            'LOG_SECURITY_EVENTS': os.getenv('VULN_SCANNER_LOG_SECURITY', 'true').lower() == 'true',
            'LOG_ACCESS_ATTEMPTS': os.getenv('VULN_SCANNER_LOG_ACCESS', 'true').lower() == 'true',
            'LOG_FAILED_REQUESTS': os.getenv('VULN_SCANNER_LOG_FAILED', 'true').lower() == 'true',
            
            # SSL/TLS
            'SSL_VERIFY_ENABLED': os.getenv('VULN_SCANNER_SSL_VERIFY', 'true').lower() == 'true',
            'SSL_CIPHER_SUITES': 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS',
            'SSL_PROTOCOLS': ['TLSv1.2', 'TLSv1.3'],
            
            # Content validation
            'VALIDATE_JSON_STRUCTURE': True,
            'VALIDATE_CONTENT_TYPE': True,
            'VALIDATE_CSRF_TOKENS': True,
            'VALIDATE_REFERRER': False,  # Can be enabled for stricter security
            
            # Dangerous patterns
            'DANGEROUS_URL_PATTERNS': [
                'javascript:', 'data:', 'vbscript:', 'file:', 'ftp:',
                '<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=',
                'eval(', 'exec(', 'system(', 'shell_exec(', 'passthru(',
                '../', '..\\', '%2e%2e%2f', '%2e%2e%5c', '....//','....\\\\',
                'union select', 'drop table', 'insert into', 'delete from',
                '<?php', '<%', '<script>', '</script>', '<iframe', '<object'
            ],
            
            'DANGEROUS_HEADERS': [
                'X-Forwarded-For', 'X-Real-IP', 'X-Remote-IP', 'X-Client-IP',
                'X-Originating-IP', 'X-Remote-Addr', 'X-Forwarded-Host'
            ]
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def get_timeout_config(self) -> Dict[str, int]:
        """Get timeout configuration"""
        return {
            'connect': self.get('HTTP_CONNECT_TIMEOUT'),
            'read': self.get('HTTP_READ_TIMEOUT'),
            'scan': self.get('SCAN_TIMEOUT')
        }
    
    def get_resource_limits(self) -> Dict[str, int]:
        """Get resource limits"""
        return {
            'max_concurrent_scans': self.get('MAX_CONCURRENT_SCANS'),
            'max_workers': self.get('MAX_SCAN_WORKERS'),
            'max_memory_mb': self.get('MAX_MEMORY_USAGE_MB'),
            'max_cpu_percent': self.get('MAX_CPU_USAGE_PERCENT')
        }
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers"""
        return self.get('SECURITY_HEADERS', {})
    
    def is_allowed_file_extension(self, filename: str) -> bool:
        """Check if file extension is allowed"""
        import os
        ext = os.path.splitext(filename)[1].lower()
        return ext in self.get('ALLOWED_STATIC_EXTENSIONS', set())
    
    def is_dangerous_pattern(self, text: str) -> bool:
        """Check if text contains dangerous patterns"""
        text_lower = text.lower()
        for pattern in self.get('DANGEROUS_URL_PATTERNS', []):
            if pattern in text_lower:
                return True
        return False
    
    def is_safe_url_scheme(self, url: str) -> bool:
        """Check if URL scheme is safe"""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            return scheme in self.get('ALLOWED_SCHEMES', ['http', 'https'])
        except Exception:
            return False

# Global security configuration instance
security_config = SecurityConfig()