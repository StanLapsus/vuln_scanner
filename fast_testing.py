#!/usr/bin/env python3
"""
Fast Testing Infrastructure with Mocking
Reduces test execution time through intelligent mocking and test optimization
"""

import json
import time
import unittest
from unittest.mock import Mock, patch, MagicMock
import requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from io import StringIO
import sys

@dataclass
class MockResponse:
    """Mock HTTP response for testing"""
    status_code: int
    headers: Dict[str, str]
    text: str
    content: bytes
    url: str
    elapsed: float = 0.1
    
    def json(self):
        return json.loads(self.text)

class FastTestMockProvider:
    """Provides mock responses for fast testing"""
    
    def __init__(self):
        self.mock_responses = self._create_mock_responses()
        self.mock_scan_results = self._create_mock_scan_results()
    
    def _create_mock_responses(self) -> Dict[str, MockResponse]:
        """Create mock HTTP responses for common test scenarios"""
        return {
            'example.com': MockResponse(
                status_code=200,
                headers={
                    'Server': 'nginx/1.18.0',
                    'Content-Type': 'text/html',
                    'X-Frame-Options': 'SAMEORIGIN',
                    'Content-Security-Policy': 'default-src \'self\'',
                    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
                },
                text="""
                <!DOCTYPE html>
                <html>
                <head><title>Example Domain</title></head>
                <body>
                    <h1>Example Domain</h1>
                    <p>This domain is for use in illustrative examples in documents.</p>
                </body>
                </html>
                """,
                content=b'<!DOCTYPE html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples in documents.</p></body></html>',
                url='https://example.com',
                elapsed=0.1
            ),
            'vulnerable.com': MockResponse(
                status_code=200,
                headers={
                    'Server': 'Apache/2.4.41',
                    'Content-Type': 'text/html',
                    'X-Powered-By': 'PHP/7.4.3'
                },
                text="""
                <!DOCTYPE html>
                <html>
                <head><title>Vulnerable Site</title></head>
                <body>
                    <h1>Welcome</h1>
                    <script>alert('XSS')</script>
                    <p>mysql_fetch_array(): supplied argument is not a valid MySQL result resource</p>
                    <p>Fatal error: Uncaught Error: Call to undefined function mysql_connect() in /var/www/html/index.php:15</p>
                </body>
                </html>
                """,
                content=b'Mock vulnerable content',
                url='https://vulnerable.com',
                elapsed=0.2
            ),
            'slow.com': MockResponse(
                status_code=200,
                headers={'Server': 'SlowServer/1.0'},
                text='<html><body>Slow response</body></html>',
                content=b'Slow response',
                url='https://slow.com',
                elapsed=5.0
            ),
            'error.com': MockResponse(
                status_code=500,
                headers={'Server': 'ErrorServer/1.0'},
                text='Internal Server Error',
                content=b'Internal Server Error',
                url='https://error.com',
                elapsed=0.1
            ),
            'timeout.com': None  # Will trigger timeout
        }
    
    def _create_mock_scan_results(self) -> Dict[str, Dict[str, Any]]:
        """Create mock scan results for different scenarios"""
        return {
            'basic_scan': {
                'target': 'https://example.com',
                'scan_id': 'test_scan_123',
                'start_time': '2023-01-01T00:00:00',
                'end_time': '2023-01-01T00:00:30',
                'duration': 30.0,
                'tests': {
                    'connectivity': {
                        'test_name': 'Connectivity Check',
                        'status': 'success',
                        'details': {
                            'http_status': 200,
                            'response_time': 0.1,
                            'server': 'nginx/1.18.0'
                        }
                    },
                    'security_headers': {
                        'test_name': 'Security Headers Analysis',
                        'status': 'success',
                        'details': {
                            'headers': {
                                'Content-Security-Policy': {
                                    'value': 'default-src \'self\'',
                                    'present': True,
                                    'recommendation': 'Good security policy'
                                },
                                'Strict-Transport-Security': {
                                    'value': 'max-age=31536000; includeSubDomains',
                                    'present': True,
                                    'recommendation': 'HSTS properly configured'
                                }
                            }
                        }
                    }
                },
                'summary': {
                    'total_tests': 2,
                    'completed_tests': 2,
                    'failed_tests': 0,
                    'vulnerabilities_found': 0
                }
            },
            'vulnerable_scan': {
                'target': 'https://vulnerable.com',
                'scan_id': 'test_scan_456',
                'start_time': '2023-01-01T00:00:00',
                'end_time': '2023-01-01T00:01:00',
                'duration': 60.0,
                'tests': {
                    'vulnerability_scan': {
                        'test_name': 'Vulnerability Scan',
                        'status': 'success',
                        'details': {
                            'vulnerabilities': [
                                {
                                    'name': 'Cross-Site Scripting (XSS)',
                                    'severity': 'High',
                                    'category': 'XSS',
                                    'description': 'Reflected XSS vulnerability detected',
                                    'recommendation': 'Implement proper output encoding'
                                },
                                {
                                    'name': 'SQL Injection',
                                    'severity': 'High',
                                    'category': 'SQLi',
                                    'description': 'Database error messages indicate SQL injection',
                                    'recommendation': 'Use parameterized queries'
                                }
                            ]
                        }
                    }
                },
                'summary': {
                    'total_tests': 1,
                    'completed_tests': 1,
                    'failed_tests': 0,
                    'vulnerabilities_found': 2
                }
            }
        }
    
    def get_mock_response(self, url: str, method: str = 'GET', **kwargs) -> MockResponse:
        """Get mock response for a URL"""
        domain = url.split('://')[1].split('/')[0] if '://' in url else url.split('/')[0]
        
        if domain in self.mock_responses:
            response = self.mock_responses[domain]
            if response is None:
                raise requests.exceptions.Timeout("Mock timeout")
            return response
        
        # Default mock response
        return MockResponse(
            status_code=200,
            headers={'Server': 'MockServer/1.0'},
            text='<html><body>Mock response</body></html>',
            content=b'Mock response',
            url=url,
            elapsed=0.1
        )
    
    def get_mock_scan_result(self, scan_type: str = 'basic_scan') -> Dict[str, Any]:
        """Get mock scan result"""
        return self.mock_scan_results.get(scan_type, self.mock_scan_results['basic_scan'])

class FastTestRunner:
    """Fast test runner with optimizations"""
    
    def __init__(self):
        self.mock_provider = FastTestMockProvider()
        self.test_results = []
        self.start_time = None
        self.total_time = 0
    
    def run_tests(self, test_classes: List[unittest.TestCase]) -> Dict[str, Any]:
        """Run tests with optimizations"""
        self.start_time = time.time()
        
        # Create test suite
        suite = unittest.TestSuite()
        for test_class in test_classes:
            suite.addTest(unittest.makeSuite(test_class))
        
        # Run tests with mocking
        with patch('requests.get', side_effect=self._mock_requests_get):
            with patch('requests.post', side_effect=self._mock_requests_post):
                with patch('socket.socket') as mock_socket:
                    mock_socket.return_value.connect_ex.return_value = 0
                    
                    # Capture test output
                    test_output = StringIO()
                    runner = unittest.TextTestRunner(stream=test_output, verbosity=2)
                    result = runner.run(suite)
        
        self.total_time = time.time() - self.start_time
        
        return {
            'tests_run': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'success_rate': (result.testsRun - len(result.failures) - len(result.errors)) / max(1, result.testsRun),
            'total_time': self.total_time,
            'average_time_per_test': self.total_time / max(1, result.testsRun),
            'output': test_output.getvalue()
        }
    
    def _mock_requests_get(self, url: str, **kwargs) -> MockResponse:
        """Mock requests.get"""
        return self.mock_provider.get_mock_response(url, 'GET', **kwargs)
    
    def _mock_requests_post(self, url: str, **kwargs) -> MockResponse:
        """Mock requests.post"""
        return self.mock_provider.get_mock_response(url, 'POST', **kwargs)

class OptimizedTestCase(unittest.TestCase):
    """Base test case with optimizations"""
    
    def setUp(self):
        """Set up test with mocking"""
        self.mock_provider = FastTestMockProvider()
        self.start_time = time.time()
    
    def tearDown(self):
        """Clean up after test"""
        duration = time.time() - self.start_time
        if duration > 2.0:  # Warn if test takes too long
            print(f"Warning: Test {self._testMethodName} took {duration:.2f}s")
    
    def get_mock_scanner(self, target: str = 'https://example.com'):
        """Get mock scanner for testing"""
        from scan import ProductionVulnerabilityScanner
        
        scanner = ProductionVulnerabilityScanner(target)
        
        # Mock the session
        scanner.session = Mock()
        scanner.session.get.return_value = self.mock_provider.get_mock_response(target)
        scanner.session.post.return_value = self.mock_provider.get_mock_response(target)
        
        return scanner
    
    def assert_scan_structure(self, results: Dict[str, Any]):
        """Assert that scan results have the expected structure"""
        self.assertIn('target', results)
        self.assertIn('scan_id', results)
        self.assertIn('start_time', results)
        self.assertIn('end_time', results)
        self.assertIn('duration', results)
        self.assertIn('tests', results)
        self.assertIn('summary', results)
    
    def assert_test_structure(self, test_result: Dict[str, Any]):
        """Assert that test result has the expected structure"""
        self.assertIn('test_name', test_result)
        self.assertIn('status', test_result)
        self.assertIn('details', test_result)
    
    def assert_vulnerability_structure(self, vulnerability: Dict[str, Any]):
        """Assert that vulnerability has the expected structure"""
        self.assertIn('name', vulnerability)
        self.assertIn('severity', vulnerability)
        self.assertIn('category', vulnerability)
        self.assertIn('description', vulnerability)

class ParallelTestRunner:
    """Run tests in parallel for faster execution"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.mock_provider = FastTestMockProvider()
    
    def run_tests_parallel(self, test_classes: List[unittest.TestCase]) -> Dict[str, Any]:
        """Run tests in parallel using threading"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        start_time = time.time()
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for test_class in test_classes:
                future = executor.submit(self._run_single_test_class, test_class)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"Test execution error: {e}")
        
        total_time = time.time() - start_time
        
        # Aggregate results
        total_tests = sum(r.get('tests_run', 0) for r in results)
        total_failures = sum(r.get('failures', 0) for r in results)
        total_errors = sum(r.get('errors', 0) for r in results)
        
        return {
            'tests_run': total_tests,
            'failures': total_failures,
            'errors': total_errors,
            'success_rate': (total_tests - total_failures - total_errors) / max(1, total_tests),
            'total_time': total_time,
            'average_time_per_test': total_time / max(1, total_tests),
            'parallel_efficiency': len(test_classes) / max(1, total_time)
        }
    
    def _run_single_test_class(self, test_class: unittest.TestCase) -> Dict[str, Any]:
        """Run a single test class"""
        suite = unittest.makeSuite(test_class)
        
        with patch('requests.get', side_effect=self._mock_requests_get):
            with patch('requests.post', side_effect=self._mock_requests_post):
                test_output = StringIO()
                runner = unittest.TextTestRunner(stream=test_output, verbosity=0)
                result = runner.run(suite)
        
        return {
            'test_class': test_class.__name__,
            'tests_run': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'output': test_output.getvalue()
        }
    
    def _mock_requests_get(self, url: str, **kwargs) -> MockResponse:
        """Mock requests.get"""
        return self.mock_provider.get_mock_response(url, 'GET', **kwargs)
    
    def _mock_requests_post(self, url: str, **kwargs) -> MockResponse:
        """Mock requests.post"""
        return self.mock_provider.get_mock_response(url, 'POST', **kwargs)

class TestPerformanceBenchmark:
    """Performance benchmark for tests"""
    
    def __init__(self):
        self.benchmarks = {}
        self.thresholds = {
            'unit_test': 1.0,      # Unit tests should complete in < 1s
            'integration_test': 5.0, # Integration tests should complete in < 5s
            'full_scan_test': 30.0   # Full scan tests should complete in < 30s
        }
    
    def benchmark_test(self, test_name: str, test_function: callable, test_type: str = 'unit_test'):
        """Benchmark a test function"""
        start_time = time.time()
        
        try:
            result = test_function()
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
        
        duration = time.time() - start_time
        
        self.benchmarks[test_name] = {
            'duration': duration,
            'success': success,
            'error': error,
            'result': result,
            'type': test_type,
            'threshold': self.thresholds.get(test_type, 1.0),
            'within_threshold': duration <= self.thresholds.get(test_type, 1.0)
        }
        
        return self.benchmarks[test_name]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance report"""
        if not self.benchmarks:
            return {'message': 'No benchmarks available'}
        
        total_tests = len(self.benchmarks)
        successful_tests = sum(1 for b in self.benchmarks.values() if b['success'])
        within_threshold = sum(1 for b in self.benchmarks.values() if b['within_threshold'])
        
        avg_duration = sum(b['duration'] for b in self.benchmarks.values()) / total_tests
        max_duration = max(b['duration'] for b in self.benchmarks.values())
        min_duration = min(b['duration'] for b in self.benchmarks.values())
        
        slow_tests = [
            name for name, benchmark in self.benchmarks.items()
            if not benchmark['within_threshold']
        ]
        
        return {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'within_threshold': within_threshold,
            'success_rate': successful_tests / total_tests,
            'threshold_compliance': within_threshold / total_tests,
            'average_duration': avg_duration,
            'max_duration': max_duration,
            'min_duration': min_duration,
            'slow_tests': slow_tests,
            'recommendations': self._get_recommendations()
        }
    
    def _get_recommendations(self) -> List[str]:
        """Get performance recommendations"""
        recommendations = []
        
        slow_tests = [
            name for name, benchmark in self.benchmarks.items()
            if not benchmark['within_threshold']
        ]
        
        if slow_tests:
            recommendations.append(f"Optimize {len(slow_tests)} slow tests: {', '.join(slow_tests[:3])}")
        
        avg_duration = sum(b['duration'] for b in self.benchmarks.values()) / len(self.benchmarks)
        if avg_duration > 2.0:
            recommendations.append("Consider adding more mocking to reduce average test duration")
        
        failed_tests = [
            name for name, benchmark in self.benchmarks.items()
            if not benchmark['success']
        ]
        
        if failed_tests:
            recommendations.append(f"Fix {len(failed_tests)} failing tests")
        
        return recommendations

# Global instances
fast_test_runner = FastTestRunner()
performance_benchmark = TestPerformanceBenchmark()

def run_fast_tests(test_classes: List[unittest.TestCase]) -> Dict[str, Any]:
    """Run tests with fast execution optimizations"""
    return fast_test_runner.run_tests(test_classes)

def run_parallel_tests(test_classes: List[unittest.TestCase], max_workers: int = 4) -> Dict[str, Any]:
    """Run tests in parallel"""
    parallel_runner = ParallelTestRunner(max_workers)
    return parallel_runner.run_tests_parallel(test_classes)

def benchmark_test(test_name: str, test_function: callable, test_type: str = 'unit_test'):
    """Benchmark a test function"""
    return performance_benchmark.benchmark_test(test_name, test_function, test_type)

def get_performance_report() -> Dict[str, Any]:
    """Get performance report"""
    return performance_benchmark.get_performance_report()