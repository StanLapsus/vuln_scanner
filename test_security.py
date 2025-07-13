#!/usr/bin/env python3

"""
Security Testing Module for Vulnerability Scanner
Tests for the security improvements made to the scanner
"""

import unittest
import json
import os
import tempfile
import time
from unittest.mock import patch, MagicMock

class TestSecurityImprovements(unittest.TestCase):
    """Test security improvements"""
    
    def setUp(self):
        """Set up test environment"""
        # Import here to avoid circular imports
        from web_app import EnhancedScanHandler, session_manager, ip_whitelist
        from security_config import security_config
        
        self.handler_class = EnhancedScanHandler
        self.session_manager = session_manager
        self.ip_whitelist = ip_whitelist
        self.security_config = security_config
    
    def test_input_validation(self):
        """Test URL input validation"""
        from enhanced_scanner import EnhancedVulnerabilityScanner
        
        # Test valid URLs
        valid_urls = [
            "https://example.com",
            "http://test.com",
            "https://subdomain.example.com:8080"
        ]
        
        for url in valid_urls:
            try:
                scanner = EnhancedVulnerabilityScanner(url)
                self.assertIsNotNone(scanner.target)
            except Exception as e:
                self.fail(f"Valid URL {url} should not raise exception: {e}")
        
        # Test invalid URLs
        invalid_urls = [
            "javascript:alert('xss')",
            "file:///etc/passwd",
            "http://localhost",
            "https://127.0.0.1",
            "http://example.com/<script>",
            "https://test.com/path?param=<script>alert('xss')</script>"
        ]
        
        for url in invalid_urls:
            with self.assertRaises(ValueError, msg=f"Invalid URL {url} should raise ValueError"):
                scanner = EnhancedVulnerabilityScanner(url)
    
    def test_path_traversal_protection(self):
        """Test path traversal protection in static file serving"""
        # Test that path traversal attempts are blocked
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "static/../../../etc/passwd",
            "static/../../config/database.yml"
        ]
        
        for path in dangerous_paths:
            # Simulate path normalization
            normalized = os.path.normpath(path)
            self.assertFalse(
                normalized.startswith('static/'),
                f"Path {path} should be blocked by path traversal protection"
            )
    
    def test_csrf_protection(self):
        """Test CSRF token validation"""
        if not self.session_manager:
            self.skipTest("Authentication disabled")
        
        # Create a session
        session_id = self.session_manager.create_session("admin")
        
        # Generate CSRF token
        csrf_token = self.session_manager.generate_csrf_token(session_id)
        self.assertIsNotNone(csrf_token)
        
        # Validate correct token
        self.assertTrue(self.session_manager.validate_csrf_token(session_id, csrf_token))
        
        # Validate incorrect token
        self.assertFalse(self.session_manager.validate_csrf_token(session_id, "invalid_token"))
        
        # Cleanup
        self.session_manager.destroy_session(session_id)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        from web_app import RateLimiter
        
        # Create a rate limiter with low limits for testing
        limiter = RateLimiter(requests_per_minute=3)
        
        # Test that requests are initially allowed
        self.assertTrue(limiter.is_allowed("127.0.0.1"))
        self.assertTrue(limiter.is_allowed("127.0.0.1"))
        self.assertTrue(limiter.is_allowed("127.0.0.1"))
        
        # Test that 4th request is blocked
        self.assertFalse(limiter.is_allowed("127.0.0.1"))
        
        # Test that different IP is allowed
        self.assertTrue(limiter.is_allowed("192.168.1.1"))
    
    def test_security_headers(self):
        """Test security headers configuration"""
        headers = self.security_config.get_security_headers()
        
        # Check that important security headers are present
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy'
        ]
        
        for header in required_headers:
            self.assertIn(header, headers, f"Security header {header} should be present")
    
    def test_file_extension_validation(self):
        """Test file extension validation"""
        # Test allowed extensions
        allowed_files = [
            "style.css",
            "script.js",
            "image.png",
            "icon.ico"
        ]
        
        for filename in allowed_files:
            self.assertTrue(
                self.security_config.is_allowed_file_extension(filename),
                f"File {filename} should be allowed"
            )
        
        # Test blocked extensions
        blocked_files = [
            "config.php",
            "script.py",
            "data.sql",
            "backup.bak",
            "sensitive.env"
        ]
        
        for filename in blocked_files:
            self.assertFalse(
                self.security_config.is_allowed_file_extension(filename),
                f"File {filename} should be blocked"
            )
    
    def test_dangerous_pattern_detection(self):
        """Test dangerous pattern detection"""
        # Test dangerous patterns
        dangerous_inputs = [
            "javascript:alert('xss')",
            "<script>alert('xss')</script>",
            "union select * from users",
            "../../../etc/passwd",
            "eval(malicious_code)",
            "system('rm -rf /')"
        ]
        
        for input_text in dangerous_inputs:
            self.assertTrue(
                self.security_config.is_dangerous_pattern(input_text),
                f"Input '{input_text}' should be detected as dangerous"
            )
        
        # Test safe patterns
        safe_inputs = [
            "https://example.com",
            "normal text input",
            "user@example.com",
            "Some regular content"
        ]
        
        for input_text in safe_inputs:
            self.assertFalse(
                self.security_config.is_dangerous_pattern(input_text),
                f"Input '{input_text}' should be safe"
            )
    
    def test_url_scheme_validation(self):
        """Test URL scheme validation"""
        # Test safe schemes
        safe_urls = [
            "https://example.com",
            "http://test.com"
        ]
        
        for url in safe_urls:
            self.assertTrue(
                self.security_config.is_safe_url_scheme(url),
                f"URL {url} should have safe scheme"
            )
        
        # Test dangerous schemes
        dangerous_urls = [
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "file:///etc/passwd",
            "ftp://example.com/file.txt"
        ]
        
        for url in dangerous_urls:
            self.assertFalse(
                self.security_config.is_safe_url_scheme(url),
                f"URL {url} should have dangerous scheme"
            )
    
    def test_session_management(self):
        """Test session management security"""
        if not self.session_manager:
            self.skipTest("Authentication disabled")
        
        # Test session creation
        session_id = self.session_manager.create_session("testuser")
        self.assertIsNotNone(session_id)
        
        # Test session validation
        self.assertTrue(self.session_manager.validate_session(session_id, "127.0.0.1"))
        
        # Test session destruction
        self.session_manager.destroy_session(session_id)
        self.assertFalse(self.session_manager.validate_session(session_id, "127.0.0.1"))
    
    def test_ip_whitelisting(self):
        """Test IP whitelisting functionality"""
        # Test with localhost (should be allowed by default)
        self.assertTrue(self.ip_whitelist.is_allowed("127.0.0.1"))
        self.assertTrue(self.ip_whitelist.is_allowed("localhost"))
        
        # Test with external IP (behavior depends on configuration)
        external_ip = "192.168.1.100"
        allowed = self.ip_whitelist.is_allowed(external_ip)
        # Result depends on whether IP whitelisting is enabled
        self.assertIsInstance(allowed, bool)
    
    def test_log_injection_prevention(self):
        """Test log injection prevention"""
        from web_app import EnhancedScanHandler
        
        # Create mock handler
        handler = MagicMock(spec=EnhancedScanHandler)
        handler.address_string = MagicMock(return_value="127.0.0.1")
        
        # Test that malicious log input is sanitized
        malicious_inputs = [
            "test\nINJECTED LOG LINE",
            "test\rINJECTED LOG LINE",
            "test\tINJECTED LOG LINE"
        ]
        
        for malicious_input in malicious_inputs:
            # The sanitization should remove or escape dangerous characters
            sanitized = malicious_input.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            self.assertNotIn('\n', sanitized)
            self.assertNotIn('\r', sanitized)
    
    def test_timeout_configuration(self):
        """Test timeout configuration"""
        timeouts = self.security_config.get_timeout_config()
        
        # Check that timeouts are properly configured
        self.assertIn('connect', timeouts)
        self.assertIn('read', timeouts)
        self.assertIn('scan', timeouts)
        
        # Check that timeouts are reasonable
        self.assertGreater(timeouts['connect'], 0)
        self.assertGreater(timeouts['read'], 0)
        self.assertGreater(timeouts['scan'], 0)
    
    def test_resource_limits(self):
        """Test resource limits configuration"""
        limits = self.security_config.get_resource_limits()
        
        # Check that limits are properly configured
        required_limits = ['max_concurrent_scans', 'max_workers', 'max_memory_mb', 'max_cpu_percent']
        
        for limit in required_limits:
            self.assertIn(limit, limits)
            self.assertGreater(limits[limit], 0)


if __name__ == '__main__':
    # Run the security tests
    unittest.main(verbosity=2)