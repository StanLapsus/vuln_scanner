#!/usr/bin/env python3
"""
Performance and Architecture Optimization Module
Smart queuing, concurrency controls, caching, and resource management
"""

import asyncio
import threading
import time
import json
import hashlib
import pickle
import gzip
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, PriorityQueue, Empty
import psutil
import logging
from functools import wraps
from contextlib import contextmanager
import weakref
import gc

logger = logging.getLogger(__name__)

@dataclass
class ScanTask:
    """Enhanced scan task with priority and metadata"""
    task_id: str
    target_url: str
    scan_type: str
    priority: int = 5  # 1-10, higher = more priority
    created_at: float = field(default_factory=time.time)
    timeout: int = 300  # 5 minutes default
    retries: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __lt__(self, other):
        # Higher priority first, then older tasks first
        if self.priority != other.priority:
            return self.priority > other.priority
        return self.created_at < other.created_at

class ResourceMonitor:
    """Monitor system resources and adjust performance accordingly"""
    
    def __init__(self):
        self.cpu_threshold = 80.0  # Percentage
        self.memory_threshold = 80.0  # Percentage
        self.disk_threshold = 90.0  # Percentage
        self.network_threshold = 100 * 1024 * 1024  # 100MB/s
        self.monitoring = False
        self.stats = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0,
            'network_io': 0.0,
            'concurrent_tasks': 0
        }
    
    def start_monitoring(self):
        """Start resource monitoring in background"""
        self.monitoring = True
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring = False
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                self.stats['cpu_usage'] = psutil.cpu_percent(interval=1)
                self.stats['memory_usage'] = psutil.virtual_memory().percent
                self.stats['disk_usage'] = psutil.disk_usage('/').percent
                
                # Network I/O (bytes per second)
                net_io = psutil.net_io_counters()
                time.sleep(1)
                net_io_new = psutil.net_io_counters()
                self.stats['network_io'] = (net_io_new.bytes_sent + net_io_new.bytes_recv) - \
                                          (net_io.bytes_sent + net_io.bytes_recv)
                
            except Exception as e:
                logger.error(f"Error monitoring resources: {e}")
                time.sleep(5)
    
    def get_optimal_concurrency(self, base_concurrency: int = 10) -> int:
        """Calculate optimal concurrency based on system resources"""
        if not self.monitoring:
            return base_concurrency
        
        cpu_factor = max(0.1, 1.0 - (self.stats['cpu_usage'] / 100.0))
        memory_factor = max(0.1, 1.0 - (self.stats['memory_usage'] / 100.0))
        
        # Adjust based on resource usage
        optimal = int(base_concurrency * cpu_factor * memory_factor)
        
        # Ensure minimum and maximum bounds
        return max(2, min(optimal, base_concurrency * 2))
    
    def should_throttle(self) -> bool:
        """Check if we should throttle operations"""
        return (self.stats['cpu_usage'] > self.cpu_threshold or
                self.stats['memory_usage'] > self.memory_threshold or
                self.stats['disk_usage'] > self.disk_threshold)

class CacheManager:
    """Intelligent caching system with TTL and compression"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.expire_times = {}
        self._lock = threading.RLock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'memory_usage': 0
        }
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = json.dumps({'args': args, 'kwargs': kwargs}, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _cleanup_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [key for key, expire_time in self.expire_times.items() 
                       if expire_time < current_time]
        
        for key in expired_keys:
            self._remove_entry(key)
    
    def _remove_entry(self, key: str):
        """Remove entry from cache"""
        if key in self.cache:
            del self.cache[key]
            del self.access_times[key]
            del self.expire_times[key]
            self.stats['evictions'] += 1
    
    def _evict_lru(self):
        """Evict least recently used entries"""
        if not self.cache:
            return
        
        # Find LRU key
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self._remove_entry(lru_key)
    
    def _compress_data(self, data: Any) -> bytes:
        """Compress data for storage"""
        pickled = pickle.dumps(data)
        return gzip.compress(pickled)
    
    def _decompress_data(self, compressed_data: bytes) -> Any:
        """Decompress stored data"""
        pickled = gzip.decompress(compressed_data)
        return pickle.loads(pickled)
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self._lock:
            self._cleanup_expired()
            
            if key in self.cache:
                self.access_times[key] = time.time()
                self.stats['hits'] += 1
                return self._decompress_data(self.cache[key])
            
            self.stats['misses'] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set item in cache"""
        with self._lock:
            self._cleanup_expired()
            
            # Evict if at capacity
            while len(self.cache) >= self.max_size:
                self._evict_lru()
            
            # Store compressed data
            compressed_value = self._compress_data(value)
            self.cache[key] = compressed_value
            self.access_times[key] = time.time()
            self.expire_times[key] = time.time() + (ttl or self.default_ttl)
    
    def cache_result(self, ttl: Optional[int] = None):
        """Decorator for caching function results"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                cache_key = self._generate_key(func.__name__, *args, **kwargs)
                
                # Try to get from cache
                result = self.get(cache_key)
                if result is not None:
                    return result
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                return result
            
            return wrapper
        return decorator
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = self.stats['hits'] / total_requests if total_requests > 0 else 0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': hit_rate,
                'hits': self.stats['hits'],
                'misses': self.stats['misses'],
                'evictions': self.stats['evictions']
            }

class SmartQueue:
    """Smart priority queue with load balancing and throttling"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.queue = PriorityQueue(maxsize=max_size)
        self.processing = {}  # task_id -> (thread_id, start_time)
        self.completed = {}  # task_id -> (result, completion_time)
        self.failed = {}     # task_id -> (error, failure_time)
        self._lock = threading.Lock()
        self.stats = {
            'queued': 0,
            'processing': 0,
            'completed': 0,
            'failed': 0,
            'avg_processing_time': 0.0
        }
    
    def enqueue(self, task: ScanTask) -> bool:
        """Add task to queue"""
        try:
            self.queue.put(task, block=False)
            with self._lock:
                self.stats['queued'] += 1
            return True
        except:
            return False
    
    def dequeue(self, timeout: float = 1.0) -> Optional[ScanTask]:
        """Get next task from queue"""
        try:
            task = self.queue.get(timeout=timeout)
            with self._lock:
                self.stats['queued'] -= 1
                self.stats['processing'] += 1
                self.processing[task.task_id] = (threading.current_thread().ident, time.time())
            return task
        except Empty:
            return None
    
    def mark_completed(self, task_id: str, result: Any):
        """Mark task as completed"""
        with self._lock:
            if task_id in self.processing:
                thread_id, start_time = self.processing[task_id]
                processing_time = time.time() - start_time
                
                # Update average processing time
                total_completed = self.stats['completed']
                self.stats['avg_processing_time'] = (
                    (self.stats['avg_processing_time'] * total_completed + processing_time) /
                    (total_completed + 1)
                )
                
                del self.processing[task_id]
                self.completed[task_id] = (result, time.time())
                self.stats['processing'] -= 1
                self.stats['completed'] += 1
    
    def mark_failed(self, task_id: str, error: Exception):
        """Mark task as failed"""
        with self._lock:
            if task_id in self.processing:
                del self.processing[task_id]
                self.failed[task_id] = (error, time.time())
                self.stats['processing'] -= 1
                self.stats['failed'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        with self._lock:
            return {
                'queue_size': self.queue.qsize(),
                'max_size': self.max_size,
                'processing_tasks': len(self.processing),
                'completed_tasks': len(self.completed),
                'failed_tasks': len(self.failed),
                'avg_processing_time': self.stats['avg_processing_time'],
                'queue_utilization': self.queue.qsize() / self.max_size
            }

class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, rate: float, capacity: int = None):
        self.rate = rate  # tokens per second
        self.capacity = capacity or int(rate * 2)  # bucket capacity
        self.tokens = self.capacity
        self.last_update = time.time()
        self._lock = threading.Lock()
    
    def acquire(self, tokens: int = 1, timeout: float = None) -> bool:
        """Acquire tokens from bucket"""
        end_time = time.time() + timeout if timeout else None
        
        while True:
            with self._lock:
                now = time.time()
                # Add tokens based on elapsed time
                elapsed = now - self.last_update
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            
            if end_time and time.time() >= end_time:
                return False
            
            time.sleep(0.01)  # Small delay before retry
    
    @contextmanager
    def limit(self, tokens: int = 1, timeout: float = None):
        """Context manager for rate limiting"""
        if self.acquire(tokens, timeout):
            try:
                yield
            finally:
                pass
        else:
            raise Exception("Rate limit exceeded")

class PerformanceOptimizer:
    """Main performance optimization coordinator"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.resource_monitor = ResourceMonitor()
        self.cache_manager = CacheManager()
        self.smart_queue = SmartQueue()
        self.rate_limiter = RateLimiter(rate=10.0)  # 10 requests per second
        self.executor = None
        self.active_tasks = weakref.WeakSet()
        
        # Start monitoring
        self.resource_monitor.start_monitoring()
    
    def optimize_concurrency(self):
        """Dynamically adjust concurrency based on system resources"""
        optimal_workers = self.resource_monitor.get_optimal_concurrency(self.max_workers)
        
        if self.executor and self.executor._max_workers != optimal_workers:
            # Recreate executor with new worker count
            old_executor = self.executor
            self.executor = ThreadPoolExecutor(max_workers=optimal_workers)
            
            # Schedule shutdown of old executor
            threading.Thread(target=old_executor.shutdown, args=(True,), daemon=True).start()
            
            logger.info(f"Adjusted concurrency from {old_executor._max_workers} to {optimal_workers}")
    
    def execute_with_optimization(self, func: Callable, *args, **kwargs):
        """Execute function with performance optimizations"""
        # Check if we should throttle
        if self.resource_monitor.should_throttle():
            time.sleep(0.1)  # Brief throttle delay
        
        # Apply rate limiting
        with self.rate_limiter.limit():
            # Try to get cached result first
            cache_key = self.cache_manager._generate_key(func.__name__, *args, **kwargs)
            cached_result = self.cache_manager.get(cache_key)
            
            if cached_result is not None:
                return cached_result
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Cache result
            self.cache_manager.set(cache_key, result)
            
            return result
    
    def process_task_queue(self, task_handler: Callable):
        """Process tasks from the smart queue"""
        if not self.executor:
            optimal_workers = self.resource_monitor.get_optimal_concurrency(self.max_workers)
            self.executor = ThreadPoolExecutor(max_workers=optimal_workers)
        
        def worker():
            while True:
                task = self.smart_queue.dequeue()
                if task is None:
                    break
                
                try:
                    # Execute task with optimization
                    result = self.execute_with_optimization(task_handler, task)
                    self.smart_queue.mark_completed(task.task_id, result)
                except Exception as e:
                    self.smart_queue.mark_failed(task.task_id, e)
                    logger.error(f"Task {task.task_id} failed: {e}")
                finally:
                    # Periodic garbage collection
                    if len(self.active_tasks) % 100 == 0:
                        gc.collect()
        
        # Start worker threads
        futures = []
        for _ in range(self.executor._max_workers):
            future = self.executor.submit(worker)
            futures.append(future)
        
        return futures
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        return {
            'resource_usage': self.resource_monitor.stats,
            'cache_stats': self.cache_manager.get_stats(),
            'queue_stats': self.smart_queue.get_stats(),
            'optimal_concurrency': self.resource_monitor.get_optimal_concurrency(self.max_workers),
            'active_tasks': len(self.active_tasks)
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.resource_monitor.stop_monitoring()
        if self.executor:
            self.executor.shutdown(wait=True)
        
        # Force garbage collection
        gc.collect()

# Performance decorators
def performance_monitor(func):
    """Decorator to monitor function performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"{func.__name__} executed in {execution_time:.3f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"{func.__name__} failed after {execution_time:.3f}s: {e}")
            raise
    return wrapper

def memory_limit(max_memory_mb: int):
    """Decorator to enforce memory limits"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            process = psutil.Process()
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            result = func(*args, **kwargs)
            
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_used = final_memory - initial_memory
            
            if memory_used > max_memory_mb:
                logger.warning(f"{func.__name__} used {memory_used:.2f}MB (limit: {max_memory_mb}MB)")
                # Force garbage collection
                gc.collect()
            
            return result
        return wrapper
    return decorator

# Usage example
if __name__ == "__main__":
    # Initialize performance optimizer
    optimizer = PerformanceOptimizer(max_workers=5)
    
    # Example function to optimize
    @performance_monitor
    @memory_limit(100)
    def example_scan_function(url: str):
        # Simulate scan work
        time.sleep(1)
        return f"Scanned {url}"
    
    # Add tasks to queue
    for i in range(10):
        task = ScanTask(
            task_id=f"task_{i}",
            target_url=f"https://example{i}.com",
            scan_type="full_scan",
            priority=i % 3 + 1
        )
        optimizer.smart_queue.enqueue(task)
    
    # Process tasks
    futures = optimizer.process_task_queue(example_scan_function)
    
    # Wait for completion
    for future in futures:
        try:
            future.result(timeout=5)
        except:
            pass
    
    # Get performance metrics
    metrics = optimizer.get_performance_metrics()
    print(json.dumps(metrics, indent=2))
    
    # Cleanup
    optimizer.cleanup()