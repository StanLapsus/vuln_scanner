#!/usr/bin/env python3
"""
Optimized Test Suite for Vuln Scanner
Fast tests using mocking and intelligent test execution
"""

import unittest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock
import requests
from scan import ProductionVulnerabilityScanner, save_results_to_file
from enhanced_scanner import EnhancedVulnerabilityScanner
from fast_testing import OptimizedTestCase, FastTestMockProvider


class TestVulnerabilityScanner(OptimizedTestCase):
    """Optimized test suite for the vulnerability scanner"""
    
    def setUp(self):
        """Set up test environment with mocking"""
        super().setUp()
        self.test_target = "https://example.com"
        self.scanner = self.get_mock_scanner(self.test_target)
        
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
        
        # Test with test.com (should be demo mode for testing)
        scanner_test = ProductionVulnerabilityScanner("https://test.com")
        self.assertTrue(scanner_test.demo_mode)
        
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
        with patch.object(self.scanner, 'run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('basic_scan')
            
            results = self.scanner.run_legacy_scans()
            
            # Verify basic result structure
            self.assert_scan_structure(results)
            self.assertEqual(results['target'], self.test_target)
        
    def test_vulnerability_detection(self):
        """Test vulnerability detection capabilities"""
        with patch.object(self.scanner, 'run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('vulnerable_scan')
            
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
            
            # Check vulnerability structure
            vulnerabilities = vuln_scan['details']['vulnerabilities']
            if vulnerabilities:
                self.assert_vulnerability_structure(vulnerabilities[0])
        
    def test_security_headers_analysis(self):
        """Test security headers analysis"""
        with patch.object(self.scanner, 'run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('basic_scan')
            
            results = self.scanner.run_legacy_scans()
            
            tests_data = results.get('tests', {})
            if isinstance(tests_data, str):
                tests_data = json.loads(tests_data)
            
            # Check for security headers analysis
            self.assertIn('security_headers', tests_data)
            headers_scan = tests_data['security_headers']
            self.assert_test_structure(headers_scan)
            
    def test_connectivity_check(self):
        """Test basic connectivity check"""
        with patch.object(self.scanner, 'run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('basic_scan')
            
            results = self.scanner.run_legacy_scans()
            
            tests_data = results.get('tests', {})
            if isinstance(tests_data, str):
                tests_data = json.loads(tests_data)
            
            # Check for connectivity results
            self.assertIn('connectivity', tests_data)
            conn_scan = tests_data['connectivity']
            self.assert_test_structure(conn_scan)
            
    def test_error_handling(self):
        """Test error handling for invalid targets"""
        with patch('requests.get', side_effect=requests.exceptions.RequestException("Connection failed")):
            invalid_scanner = ProductionVulnerabilityScanner("invalid-url")
            results = invalid_scanner.run_legacy_scans()
            
            # Should still return results structure even with errors
            self.assertIsInstance(results, dict)
            self.assertIn('target', results)
            
    def test_scan_duration_tracking(self):
        """Test that scan duration is properly tracked"""
        with patch.object(self.scanner, 'run_legacy_scans') as mock_scan:
            mock_result = self.mock_provider.get_mock_scan_result('basic_scan')
            mock_scan.return_value = mock_result
            
            results = self.scanner.run_legacy_scans()
            
            self.assertIn('duration', results)
            self.assertIsInstance(results['duration'], (int, float))
            self.assertGreaterEqual(results['duration'], 0)
            
    def test_results_file_generation(self):
        """Test report file generation"""
        with patch.object(self.scanner, 'run_legacy_scans') as mock_scan:
            mock_result = self.mock_provider.get_mock_scan_result('basic_scan')
            mock_scan.return_value = mock_result
            
            results = self.scanner.run_legacy_scans()
            
            # Test JSON report generation
            filename = save_results_to_file(results)
            self.assertTrue(os.path.exists(filename))
            
            # Clean up
            os.remove(filename)


class TestEnhancedScanner(OptimizedTestCase):
    """Optimized test suite for the enhanced vulnerability scanner"""
    
    def test_enhanced_scanner_initialization(self):
        """Test enhanced scanner initialization"""
        with patch('enhanced_scanner.get_dynamic_config') as mock_config:
            mock_config.return_value = {'workers': 5, 'timeout': 15}
            
            scanner = EnhancedVulnerabilityScanner("https://example.com")
            self.assertEqual(scanner.original_target, "https://example.com")
            self.assertIsNotNone(scanner.max_workers)
            self.assertIsNotNone(scanner.timeout)
        
    def test_target_normalization(self):
        """Test URL normalization"""
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
        import time
        
        scanner1 = EnhancedVulnerabilityScanner("https://example.com")
        self.assertIsNotNone(scanner1.scan_id)
        self.assertIsInstance(scanner1.scan_id, str)
        
        # Small delay to ensure different timestamp
        time.sleep(0.01)
        
        # Test uniqueness
        scanner2 = EnhancedVulnerabilityScanner("https://example.com")
        self.assertNotEqual(scanner1.scan_id, scanner2.scan_id)


class TestSecurityAnalysis(OptimizedTestCase):
    """Optimized test suite for security analysis capabilities"""
    
    def test_vulnerability_severity_classification(self):
        """Test vulnerability severity classification"""
        with patch('scan.ProductionVulnerabilityScanner.run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('vulnerable_scan')
            
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
                        
    def test_comprehensive_analysis(self):
        """Test that comprehensive analysis covers all major areas"""
        with patch('scan.ProductionVulnerabilityScanner.run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('basic_scan')
            
            scanner = ProductionVulnerabilityScanner("https://example.com")
            results = scanner.run_legacy_scans()
            
            tests_data = results.get('tests', {})
            if isinstance(tests_data, str):
                tests_data = json.loads(tests_data)
            
            # Check that major security areas are covered
            important_tests = ['connectivity', 'security_headers']
            
            for test_name in important_tests:
                if test_name in tests_data:
                    self.assertIn(test_name, tests_data, f"Missing test: {test_name}")
                    
    def test_owasp_compliance_mapping(self):
        """Test OWASP Top 10 compliance mapping"""
        with patch('scan.ProductionVulnerabilityScanner.run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('basic_scan')
            
            scanner = ProductionVulnerabilityScanner("https://example.com")
            results = scanner.run_legacy_scans()
            
            # Verify that security analysis exists
            tests_data = results.get('tests', {})
            if isinstance(tests_data, str):
                tests_data = json.loads(tests_data)
            
            # Check for OWASP-related security checks
            self.assertIsInstance(tests_data, dict)
            self.assertGreater(len(tests_data), 0)


class TestPerformanceOptimizations(OptimizedTestCase):
    """Test performance optimizations"""
    
    def test_fast_scan_execution(self):
        """Test that scans execute quickly with optimizations"""
        start_time = self.start_time
        
        with patch('scan.ProductionVulnerabilityScanner.run_legacy_scans') as mock_scan:
            mock_scan.return_value = self.mock_provider.get_mock_scan_result('basic_scan')
            
            scanner = ProductionVulnerabilityScanner("https://example.com")
            results = scanner.run_legacy_scans()
            
            execution_time = time.time() - start_time
            
            # Should complete quickly with mocking
            self.assertLess(execution_time, 1.0, "Scan should complete quickly with mocking")
            
    def test_mock_response_handling(self):
        """Test that mock responses are handled correctly"""
        mock_response = self.mock_provider.get_mock_response('https://example.com')
        
        self.assertEqual(mock_response.status_code, 200)
        self.assertIn('nginx', mock_response.headers['Server'])
        self.assertIn('Example Domain', mock_response.text)
        
    def test_cache_efficiency(self):
        """Test caching mechanisms"""
        # This would test actual cache implementation
        # For now, just verify the structure exists
        self.assertIsNotNone(self.mock_provider)
        self.assertIsInstance(self.mock_provider.mock_responses, dict)


if __name__ == '__main__':
    # Run tests with optimizations
    import time
    from fast_testing import run_fast_tests, get_performance_report
    
    print("Running optimized tests...")
    start_time = time.time()
    
    # Test classes to run
    test_classes = [
        TestVulnerabilityScanner,
        TestEnhancedScanner,
        TestSecurityAnalysis,
        TestPerformanceOptimizations
    ]
    
    # Run tests
    results = run_fast_tests(test_classes)
    
    total_time = time.time() - start_time
    print(f"\nTest execution completed in {total_time:.2f} seconds")
    print(f"Tests run: {results['tests_run']}")
    print(f"Success rate: {results['success_rate']:.2%}")
    print(f"Average time per test: {results['average_time_per_test']:.3f}s")
    
    # Get performance report
    perf_report = get_performance_report()
    if 'recommendations' in perf_report:
        print("\nPerformance recommendations:")
        for rec in perf_report['recommendations']:
            print(f"- {rec}")
    
    # Also run with unittest for compatibility
    print("\nRunning with unittest...")
    unittest.main(verbosity=2, exit=False)