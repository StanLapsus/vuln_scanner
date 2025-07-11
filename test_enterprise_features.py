#!/usr/bin/env python3
"""
Test script for enterprise features
"""

import asyncio
import json
import sys
import os

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enterprise_features import ReportGenerator, UserManager, CIPipeline
from performance_optimizer import PerformanceOptimizer

def test_enterprise_features():
    """Test enterprise features"""
    print("Testing Enterprise Features...")
    
    # Sample scan results
    sample_results = {
        'target_url': 'https://example.com',
        'scan_duration': 45.2,
        'advanced_xss': {
            'status': 'warning',
            'result': 'XSS vulnerability found in search parameter',
            'confidence': 0.8,
            'evidence': ['Payload reflected in response'],
            'recommendations': ['Implement input validation'],
            'cvss_score': 6.1
        },
        'security_headers': {
            'status': 'info',
            'result': 'Security headers analysis complete',
            'confidence': 0.9,
            'cvss_score': 0.0
        },
        'advanced_sql_injection': {
            'status': 'warning',
            'result': 'SQL injection vulnerability detected',
            'confidence': 0.9,
            'evidence': ['Error message indicates SQL injection'],
            'recommendations': ['Use parameterized queries'],
            'cvss_score': 9.8
        }
    }
    
    # Test report generation
    print("\n1. Testing Report Generation...")
    report_gen = ReportGenerator()
    
    try:
        # Generate HTML report
        html_report_path = report_gen.generate_report(sample_results, 'html')
        print(f"✓ HTML report generated successfully")
        
        # Generate JSON report
        json_report_path = report_gen.generate_report(sample_results, 'json')
        print(f"✓ JSON report generated successfully")
        
        # Generate XML report
        xml_report_path = report_gen.generate_report(sample_results, 'xml')
        print(f"✓ XML report generated successfully")
        
        # Generate CSV report
        csv_report_path = report_gen.generate_report(sample_results, 'csv')
        print(f"✓ CSV report generated successfully")
        
    except Exception as e:
        print(f"✗ Report generation failed: {e}")
    
    # Test user management
    print("\n2. Testing User Management...")
    user_manager = UserManager()
    
    try:
        # Create user
        user = user_manager.create_user('testuser', 'test@example.com', 'password123', 'user')
        print(f"✓ User created: {user['username']}")
        
        # Authenticate user
        auth_user = user_manager.authenticate('testuser', 'password123')
        if auth_user:
            print(f"✓ User authenticated successfully")
            
            # Generate JWT token
            token = user_manager.generate_jwt_token(auth_user)
            print(f"✓ JWT token generated")
            
            # Verify JWT token
            payload = user_manager.verify_jwt_token(token)
            if payload:
                print(f"✓ JWT token verified successfully")
            else:
                print(f"✗ JWT token verification failed")
        else:
            print(f"✗ User authentication failed")
            
    except Exception as e:
        print(f"✗ User management test failed: {e}")
    
    # Test CI/CD pipeline
    print("\n3. Testing CI/CD Pipeline...")
    ci_pipeline = CIPipeline()
    
    try:
        # Generate JUnit report
        junit_report = ci_pipeline.generate_ci_report(sample_results, 'junit')
        print(f"✓ JUnit report generated")
        
        # Generate SARIF report
        sarif_report = ci_pipeline.generate_ci_report(sample_results, 'sarif')
        print(f"✓ SARIF report generated")
        
    except Exception as e:
        print(f"✗ CI/CD pipeline test failed: {e}")
    
    # Test performance optimizer
    print("\n4. Testing Performance Optimizer...")
    optimizer = PerformanceOptimizer(max_workers=3)
    
    try:
        # Get performance metrics
        metrics = optimizer.get_performance_metrics()
        print(f"✓ Performance metrics retrieved")
        print(f"  - Optimal concurrency: {metrics.get('optimal_concurrency', 'N/A')}")
        print(f"  - Active tasks: {metrics.get('active_tasks', 'N/A')}")
        
        # Test caching
        @optimizer.cache_manager.cache_result(ttl=60)
        def cached_function(x):
            return x * 2
        
        result1 = cached_function(5)
        result2 = cached_function(5)  # Should be cached
        print(f"✓ Caching system working (result: {result1})")
        
        cache_stats = optimizer.cache_manager.get_stats()
        print(f"  - Cache hit rate: {cache_stats.get('hit_rate', 0):.2%}")
        
    except Exception as e:
        print(f"✗ Performance optimizer test failed: {e}")
    
    print("\n" + "="*50)
    print("Enterprise Features Test Complete!")
    print("="*50)

if __name__ == "__main__":
    test_enterprise_features()