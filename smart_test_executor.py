#!/usr/bin/env python3
"""
Smart Test Execution System for Vulnerability Scanner
Implements intelligent test ordering, early termination, and caching
"""

import time
import logging
import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class TestPriority(Enum):
    """Test priority levels for smart execution"""
    CRITICAL = 1    # Must run first (connectivity, basic checks)
    HIGH = 2        # Important security tests
    MEDIUM = 3      # Standard vulnerability tests
    LOW = 4         # Nice-to-have tests
    OPTIONAL = 5    # Only run if time permits

@dataclass
class TestDefinition:
    """Definition of a test with execution metadata"""
    name: str
    function: Callable
    priority: TestPriority
    estimated_duration: int  # seconds
    dependencies: List[str] = field(default_factory=list)
    max_retries: int = 3
    timeout: int = 30
    cache_duration: int = 300  # seconds
    early_termination: bool = True
    
class TestResult:
    """Enhanced test result with execution metadata"""
    def __init__(self, test_name: str):
        self.test_name = test_name
        self.start_time = time.time()
        self.end_time = None
        self.duration = None
        self.result = None
        self.error = None
        self.cached = False
        self.retries = 0
        self.priority = None
        self.terminated_early = False
        
    def complete(self, result: Any = None, error: Exception = None):
        """Mark test as complete"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.result = result
        self.error = error
        
    def is_successful(self) -> bool:
        """Check if test completed successfully"""
        return self.error is None and self.result is not None

class SmartTestExecutor:
    """Smart test execution system with optimization features"""
    
    def __init__(self, max_workers: int = 10, time_budget: int = 300):
        self.max_workers = max_workers
        self.time_budget = time_budget  # Total time budget in seconds
        self.cache = {}
        self.test_definitions = {}
        self.test_results = {}
        self.execution_stats = {
            'total_tests': 0,
            'completed_tests': 0,
            'cached_tests': 0,
            'failed_tests': 0,
            'terminated_early': 0,
            'total_time': 0
        }
        
    def register_test(self, test_def: TestDefinition):
        """Register a test definition"""
        self.test_definitions[test_def.name] = test_def
        logger.debug(f"Registered test: {test_def.name} (priority: {test_def.priority.name})")
        
    def _get_cache_key(self, test_name: str, target: str, params: Dict[str, Any] = None) -> str:
        """Generate cache key for test result"""
        cache_data = {
            'test': test_name,
            'target': target,
            'params': params or {}
        }
        return hashlib.md5(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()
    
    def _is_cached(self, test_name: str, target: str, params: Dict[str, Any] = None) -> Optional[Any]:
        """Check if test result is cached and still valid"""
        cache_key = self._get_cache_key(test_name, target, params)
        
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            test_def = self.test_definitions.get(test_name)
            
            if test_def and time.time() - timestamp < test_def.cache_duration:
                logger.debug(f"Cache hit for {test_name}")
                return cached_result
                
        return None
    
    def _cache_result(self, test_name: str, target: str, result: Any, params: Dict[str, Any] = None):
        """Cache test result"""
        cache_key = self._get_cache_key(test_name, target, params)
        self.cache[cache_key] = (result, time.time())
        logger.debug(f"Cached result for {test_name}")
    
    def _should_terminate_early(self, test_name: str, elapsed_time: float) -> bool:
        """Determine if a test should be terminated early"""
        test_def = self.test_definitions.get(test_name)
        if not test_def or not test_def.early_termination:
            return False
        
        # Terminate if taking much longer than estimated
        if elapsed_time > test_def.estimated_duration * 2:
            logger.warning(f"Terminating {test_name} early - exceeded estimated duration")
            return True
        
        # Terminate if we're running out of time budget
        remaining_time = self.time_budget - sum(
            result.duration for result in self.test_results.values() 
            if result.duration is not None
        )
        
        if remaining_time < test_def.estimated_duration * 0.5:
            logger.warning(f"Terminating {test_name} early - insufficient time budget")
            return True
            
        return False
    
    def _execute_single_test(self, test_name: str, target: str, params: Dict[str, Any] = None) -> TestResult:
        """Execute a single test with error handling and caching"""
        test_result = TestResult(test_name)
        test_def = self.test_definitions.get(test_name)
        
        if not test_def:
            test_result.complete(error=Exception(f"Test definition not found: {test_name}"))
            return test_result
        
        test_result.priority = test_def.priority
        
        # Check cache first
        cached_result = self._is_cached(test_name, target, params)
        if cached_result is not None:
            test_result.result = cached_result
            test_result.cached = True
            test_result.complete(cached_result)
            self.execution_stats['cached_tests'] += 1
            return test_result
        
        # Execute test with retries
        last_error = None
        for attempt in range(test_def.max_retries):
            try:
                test_result.retries = attempt
                
                # Execute the test function
                if params:
                    result = test_def.function(target, **params)
                else:
                    result = test_def.function(target)
                
                # Check for early termination
                if self._should_terminate_early(test_name, time.time() - test_result.start_time):
                    test_result.terminated_early = True
                    break
                
                # Success
                test_result.complete(result)
                self._cache_result(test_name, target, result, params)
                return test_result
                
            except Exception as e:
                last_error = e
                logger.warning(f"Test {test_name} failed (attempt {attempt + 1}): {e}")
                
                if attempt < test_def.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        # All retries failed
        test_result.complete(error=last_error)
        self.execution_stats['failed_tests'] += 1
        return test_result
    
    def _get_test_execution_order(self, test_names: List[str]) -> List[str]:
        """Get optimal test execution order based on priorities and dependencies"""
        # Group tests by priority
        priority_groups = {}
        for test_name in test_names:
            test_def = self.test_definitions.get(test_name)
            if test_def:
                priority = test_def.priority
                if priority not in priority_groups:
                    priority_groups[priority] = []
                priority_groups[priority].append(test_name)
        
        # Sort by priority and handle dependencies
        ordered_tests = []
        for priority in sorted(priority_groups.keys(), key=lambda x: x.value):
            tests_in_priority = priority_groups[priority]
            
            # Sort by estimated duration (faster tests first)
            tests_in_priority.sort(key=lambda x: self.test_definitions[x].estimated_duration)
            
            # Add to execution order
            ordered_tests.extend(tests_in_priority)
        
        return ordered_tests
    
    def _estimate_remaining_time(self, completed_tests: List[str], pending_tests: List[str]) -> int:
        """Estimate time needed for remaining tests"""
        total_estimated = sum(
            self.test_definitions[test_name].estimated_duration 
            for test_name in pending_tests
            if test_name in self.test_definitions
        )
        
        # Apply efficiency factor based on completed tests
        if completed_tests:
            actual_time = sum(
                self.test_results[test_name].duration 
                for test_name in completed_tests
                if test_name in self.test_results and self.test_results[test_name].duration
            )
            estimated_time = sum(
                self.test_definitions[test_name].estimated_duration 
                for test_name in completed_tests
                if test_name in self.test_definitions
            )
            
            if estimated_time > 0:
                efficiency_factor = actual_time / estimated_time
                total_estimated *= efficiency_factor
        
        return int(total_estimated)
    
    def execute_tests(self, test_names: List[str], target: str, 
                     progress_callback: Optional[Callable] = None) -> Dict[str, TestResult]:
        """Execute tests with smart optimization"""
        start_time = time.time()
        self.execution_stats['total_tests'] = len(test_names)
        
        # Get optimal execution order
        ordered_tests = self._get_test_execution_order(test_names)
        
        # Execute tests
        completed_tests = []
        pending_tests = ordered_tests.copy()
        
        # Use ThreadPoolExecutor for parallel execution of compatible tests
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            # Submit initial batch of tests
            for test_name in ordered_tests:
                test_def = self.test_definitions.get(test_name)
                if test_def and test_def.priority in [TestPriority.CRITICAL, TestPriority.HIGH]:
                    future = executor.submit(self._execute_single_test, test_name, target)
                    futures[future] = test_name
            
            # Process results as they complete
            for future in as_completed(futures, timeout=self.time_budget):
                test_name = futures[future]
                test_result = future.result()
                
                self.test_results[test_name] = test_result
                completed_tests.append(test_name)
                pending_tests.remove(test_name)
                
                self.execution_stats['completed_tests'] += 1
                if test_result.terminated_early:
                    self.execution_stats['terminated_early'] += 1
                
                # Update progress
                if progress_callback:
                    progress = (len(completed_tests) / len(test_names)) * 100
                    progress_callback(progress, f"Completed {test_name}")
                
                # Check time budget
                elapsed_time = time.time() - start_time
                if elapsed_time > self.time_budget:
                    logger.warning(f"Time budget exceeded, stopping execution")
                    break
                
                # Estimate remaining time
                remaining_time = self.time_budget - elapsed_time
                estimated_remaining = self._estimate_remaining_time(completed_tests, pending_tests)
                
                # Submit more tests if we have time
                if remaining_time > estimated_remaining * 0.5 and pending_tests:
                    # Submit next batch
                    batch_size = min(self.max_workers - len(futures), len(pending_tests))
                    for i in range(batch_size):
                        if pending_tests:
                            next_test = pending_tests[0]
                            future = executor.submit(self._execute_single_test, next_test, target)
                            futures[future] = next_test
        
        # Update final statistics
        self.execution_stats['total_time'] = time.time() - start_time
        
        logger.info(f"Test execution completed: {self.execution_stats}")
        return self.test_results
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of test execution"""
        successful_tests = sum(1 for result in self.test_results.values() if result.is_successful())
        
        return {
            'total_tests': self.execution_stats['total_tests'],
            'completed_tests': self.execution_stats['completed_tests'],
            'successful_tests': successful_tests,
            'failed_tests': self.execution_stats['failed_tests'],
            'cached_tests': self.execution_stats['cached_tests'],
            'terminated_early': self.execution_stats['terminated_early'],
            'total_time': self.execution_stats['total_time'],
            'efficiency': successful_tests / max(1, self.execution_stats['total_tests']),
            'average_test_time': self.execution_stats['total_time'] / max(1, self.execution_stats['completed_tests'])
        }
    
    def clear_cache(self):
        """Clear cached test results"""
        self.cache.clear()
        logger.info("Test cache cleared")
    
    def get_test_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for completed tests"""
        metrics = {}
        
        for test_name, result in self.test_results.items():
            if result.duration is not None:
                test_def = self.test_definitions.get(test_name)
                estimated_duration = test_def.estimated_duration if test_def else 0
                
                metrics[test_name] = {
                    'duration': result.duration,
                    'estimated_duration': estimated_duration,
                    'efficiency': estimated_duration / max(result.duration, 0.001),
                    'success': result.is_successful(),
                    'cached': result.cached,
                    'retries': result.retries,
                    'terminated_early': result.terminated_early
                }
        
        return metrics

# Global smart executor instance
smart_executor = SmartTestExecutor()

def register_test(name: str, function: Callable, priority: TestPriority, 
                 estimated_duration: int = 30, **kwargs):
    """Register a test with the smart executor"""
    test_def = TestDefinition(
        name=name,
        function=function,
        priority=priority,
        estimated_duration=estimated_duration,
        **kwargs
    )
    smart_executor.register_test(test_def)

def execute_smart_tests(test_names: List[str], target: str, 
                       progress_callback: Optional[Callable] = None,
                       time_budget: int = 300) -> Dict[str, Any]:
    """Execute tests using the smart test execution system"""
    smart_executor.time_budget = time_budget
    results = smart_executor.execute_tests(test_names, target, progress_callback)
    
    # Convert TestResult objects to dictionaries
    formatted_results = {}
    for test_name, result in results.items():
        formatted_results[test_name] = {
            'result': result.result,
            'duration': result.duration,
            'success': result.is_successful(),
            'error': str(result.error) if result.error else None,
            'cached': result.cached,
            'retries': result.retries,
            'terminated_early': result.terminated_early
        }
    
    return {
        'test_results': formatted_results,
        'execution_summary': smart_executor.get_execution_summary(),
        'performance_metrics': smart_executor.get_test_performance_metrics()
    }