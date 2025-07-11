#!/usr/bin/env python3
"""
Comprehensive Test Suite for Vuln Scanner
Tests for enhanced security analysis and production-ready features
"""

import unittest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock
import requests
from scan import ProductionVulnerabilityScanner, save_results_to_file
from enhanced_scanner import EnhancedVulnerabilityScanner


class TestVulnerabilityScanner(unittest.TestCase):
    """Test suite for the vulnerability scanner"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_target = "https://example.com"
        self.scanner = ProductionVulnerabilityScanner(self.test_target)
        
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.target, self.test_target)
        self.assertIsNotNone(self.scanner.demo_mode)
        self.assertEqual(self.scanner.threads, 10)
        
    def test_demo_mode_detection(self):
        """Test demo mode detection for different targets"""
        # Test with example.com (should be demo mode)
        scanner_demo = ProductionVulnerabilityScanner("https://example.com")
        self.assertTrue(scanner_demo.demo_mode)
        
        # Test with httpbin.org (should be demo mode)
        scanner_httpbin = ProductionVulnerabilityScanner("https://httpbin.org")
        self.assertTrue(scanner_httpbin.demo_mode)
        
    def test_progress_tracking(self):
        """Test progress tracking functionality"""
        progress_data = []
        
        def track_progress(progress, message):
            progress_data.append({"progress": progress, "message": message})
        
        self.scanner.set_progress_callback(track_progress)
        self.scanner.update_progress(50, "Testing progress")
        
        self.assertEqual(len(progress_data), 1)
        self.assertEqual(progress_data[0]["progress"], 50)
        self.assertEqual(progress_data[0]["message"], "Testing progress")
        
    def test_demo_scan_results(self):
        """Test that demo scan produces expected results"""
        results = self.scanner.run_legacy_scans()
        
        # Verify basic result structure
        self.assertIsInstance(results, dict)
        self.assertIn('target', results)
        self.assertEqual(results['target'], self.test_target)
        
        # Verify scan metadata
        self.assertIn('scan_id', results)
        self.assertIn('start_time', results)
        self.assertIn('end_time', results)
        
        # Verify test results
        self.assertIn('tests', results)
        self.assertIn('summary', results)
        
    def test_vulnerability_detection(self):
        """Test vulnerability detection capabilities"""
        results = self.scanner.run_legacy_scans()
        
        # Parse tests data
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for vulnerability scan results
        self.assertIn('vulnerability_scan', tests_data)
        vuln_scan = tests_data['vulnerability_scan']
        self.assertIn('details', vuln_scan)
        self.assertIn('vulnerabilities', vuln_scan['details'])
        
    def test_security_headers_analysis(self):
        """Test security headers analysis"""
        results = self.scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for security headers analysis
        self.assertIn('security_headers', tests_data)
        headers_scan = tests_data['security_headers']
        self.assertIn('details', headers_scan)
        self.assertIn('headers', headers_scan['details'])
        
        # Verify specific headers are checked
        headers = headers_scan['details']['headers']
        expected_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 
                          'X-Content-Type-Options', 'X-Frame-Options']
        
        for header in expected_headers:
            self.assertIn(header, headers)
            
    def test_port_scanning(self):
        """Test port scanning functionality"""
        results = self.scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for port scan results
        self.assertIn('port_scan', tests_data)
        port_scan = tests_data['port_scan']
        self.assertIn('details', port_scan)
        self.assertIn('open_ports', port_scan['details'])
        
        # Verify port information structure
        open_ports = port_scan['details']['open_ports']
        self.assertIsInstance(open_ports, list)
        
        if open_ports:
            port = open_ports[0]
            self.assertIn('port', port)
            self.assertIn('state', port)
            self.assertIn('service', port)
            
    def test_information_disclosure(self):
        """Test information disclosure detection"""
        results = self.scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for information disclosure results
        self.assertIn('information_disclosure', tests_data)
        info_scan = tests_data['information_disclosure']
        self.assertIn('details', info_scan)
        self.assertIn('accessible_paths', info_scan['details'])
        
    def test_technology_detection(self):
        """Test technology stack detection"""
        results = self.scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for technology detection results
        self.assertIn('technology_detection', tests_data)
        tech_scan = tests_data['technology_detection']
        self.assertIn('details', tech_scan)
        
        details = tech_scan['details']
        self.assertIn('server', details)
        self.assertIn('cms_detected', details)
        self.assertIn('technologies', details)
        
    def test_ssl_analysis(self):
        """Test SSL/TLS analysis"""
        results = self.scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for SSL analysis results
        self.assertIn('ssl_analysis', tests_data)
        ssl_scan = tests_data['ssl_analysis']
        self.assertIn('details', ssl_scan)
        
        ssl_details = ssl_scan['details']
        self.assertIn('ssl_enabled', ssl_details)
        self.assertIn('redirects_to_https', ssl_details)
        self.assertIn('mixed_content_issues', ssl_details)
        
    def test_connectivity_check(self):
        """Test basic connectivity check"""
        results = self.scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for connectivity results
        self.assertIn('connectivity', tests_data)
        conn_scan = tests_data['connectivity']
        self.assertIn('details', conn_scan)
        
        conn_details = conn_scan['details']
        self.assertIn('http_status', conn_details)
        self.assertIn('response_time', conn_details)
        self.assertIn('server', conn_details)
        
    def test_results_file_generation(self):
        """Test report file generation"""
        results = self.scanner.run_legacy_scans()
        
        # Test JSON report generation
        filename = save_results_to_file(results)
        self.assertTrue(os.path.exists(filename))
        
        # Verify file contents
        with open(filename, 'r') as f:
            saved_data = json.load(f)
            
        self.assertEqual(saved_data['target'], results['target'])
        self.assertEqual(saved_data['scan_id'], results['scan_id'])
        
        # Clean up
        os.remove(filename)
        
    def test_error_handling(self):
        """Test error handling for invalid targets"""
        # Test with invalid URL
        invalid_scanner = ProductionVulnerabilityScanner("invalid-url")
        results = invalid_scanner.run_legacy_scans()
        
        # Should still return results structure even with errors
        self.assertIsInstance(results, dict)
        
    def test_scan_duration_tracking(self):
        """Test that scan duration is properly tracked"""
        results = self.scanner.run_legacy_scans()
        
        self.assertIn('duration', results)
        self.assertIsInstance(results['duration'], (int, float))
        self.assertGreaterEqual(results['duration'], 0)
        
    def test_summary_generation(self):
        """Test that summary data is generated correctly"""
        results = self.scanner.run_legacy_scans()
        
        self.assertIn('summary', results)
        summary = results['summary']
        
        # Check summary structure
        self.assertIn('total_tests', summary)
        self.assertIn('completed_tests', summary)
        self.assertIn('failed_tests', summary)
        self.assertIn('vulnerabilities_found', summary)
        
        # Verify summary data types
        self.assertIsInstance(summary['total_tests'], int)
        self.assertIsInstance(summary['completed_tests'], int)
        self.assertIsInstance(summary['failed_tests'], int)
        self.assertIsInstance(summary['vulnerabilities_found'], int)


class TestEnhancedScanner(unittest.TestCase):
    """Test suite for the enhanced vulnerability scanner"""
    
    def test_enhanced_scanner_initialization(self):
        """Test enhanced scanner initialization"""
        scanner = EnhancedVulnerabilityScanner("https://example.com")
        self.assertEqual(scanner.original_target, "https://example.com")
        self.assertEqual(scanner.max_workers, 10)
        self.assertEqual(scanner.timeout, 30)
        
    def test_target_normalization(self):
        """Test URL normalization"""
        # Test with various URL formats
        test_cases = [
            ("https://example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("example.com", "https://example.com"),
            ("www.example.com", "https://www.example.com"),
        ]
        
        for input_url, expected in test_cases:
            scanner = EnhancedVulnerabilityScanner(input_url)
            # Basic validation that target is normalized
            self.assertTrue(scanner.target.startswith(('http://', 'https://')))
            
    def test_scan_id_generation(self):
        """Test scan ID generation"""
        scanner = EnhancedVulnerabilityScanner("https://example.com")
        self.assertIsNotNone(scanner.scan_id)
        self.assertIsInstance(scanner.scan_id, str)
        
        # Test uniqueness
        scanner2 = EnhancedVulnerabilityScanner("https://example.com")
        self.assertNotEqual(scanner.scan_id, scanner2.scan_id)


class TestSecurityAnalysis(unittest.TestCase):
    """Test suite for security analysis capabilities"""
    
    def test_vulnerability_severity_classification(self):
        """Test vulnerability severity classification"""
        scanner = ProductionVulnerabilityScanner("https://example.com")
        results = scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check that vulnerabilities have severity levels
        if 'vulnerability_scan' in tests_data:
            vuln_scan = tests_data['vulnerability_scan']
            if 'details' in vuln_scan and 'vulnerabilities' in vuln_scan['details']:
                vulnerabilities = vuln_scan['details']['vulnerabilities']
                
                for vuln in vulnerabilities:
                    self.assertIn('severity', vuln)
                    self.assertIn(vuln['severity'], ['Critical', 'High', 'Medium', 'Low'])
                    
    def test_security_recommendations(self):
        """Test that security recommendations are provided"""
        scanner = ProductionVulnerabilityScanner("https://example.com")
        results = scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check security headers recommendations
        if 'security_headers' in tests_data:
            headers_scan = tests_data['security_headers']
            if 'details' in headers_scan and 'headers' in headers_scan['details']:
                headers = headers_scan['details']['headers']
                
                for header_name, header_info in headers.items():
                    self.assertIn('recommendation', header_info)
                    self.assertIsInstance(header_info['recommendation'], str)
                    
    def test_comprehensive_analysis(self):
        """Test that comprehensive analysis covers all major areas"""
        scanner = ProductionVulnerabilityScanner("https://example.com")
        results = scanner.run_legacy_scans()
        
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check that all major security areas are covered
        required_tests = [
            'connectivity',
            'port_scan',
            'security_headers',
            'ssl_analysis',
            'vulnerability_scan',
            'technology_detection',
            'information_disclosure'
        ]
        
        for test_name in required_tests:
            self.assertIn(test_name, tests_data, f"Missing test: {test_name}")
            
    def test_owasp_compliance_mapping(self):
        """Test OWASP Top 10 compliance mapping"""
        scanner = ProductionVulnerabilityScanner("https://example.com")
        results = scanner.run_legacy_scans()
        
        # Verify that security analysis covers OWASP categories
        tests_data = results.get('tests', {})
        if isinstance(tests_data, str):
            tests_data = json.loads(tests_data)
        
        # Check for OWASP-related security checks
        owasp_areas = [
            'security_headers',  # A06: Vulnerable and Outdated Components
            'ssl_analysis',      # A02: Cryptographic Failures
            'information_disclosure',  # A01: Broken Access Control
            'vulnerability_scan'  # Various OWASP categories
        ]
        
        for area in owasp_areas:
            self.assertIn(area, tests_data, f"Missing OWASP area: {area}")


if __name__ == '__main__':
    # Run tests with detailed output
    unittest.main(verbosity=2)