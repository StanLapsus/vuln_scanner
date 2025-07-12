#!/usr/bin/env python3
"""
Dynamic Configuration System for Vulnerability Scanner
Replaces hardcoded values with intelligent, adaptive configurations
"""

import time
import math
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
import requests

logger = logging.getLogger(__name__)

@dataclass
class TargetProfile:
    """Profile for a target based on initial reconnaissance"""
    domain: str
    response_time: float
    server_type: str
    content_length: int
    is_responsive: bool
    complexity_score: float
    recommended_timeout: int
    recommended_delay: float
    recommended_workers: int

class DynamicConfigManager:
    """Manages dynamic configuration based on target characteristics"""
    
    def __init__(self):
        self.target_profiles: Dict[str, TargetProfile] = {}
        self.base_config = {
            'min_timeout': 5,
            'max_timeout': 120,
            'base_timeout': 30,
            'min_delay': 0.05,
            'max_delay': 2.0,
            'base_delay': 0.1,
            'min_workers': 1,
            'max_workers': 20,
            'base_workers': 10,
            'probe_timeout': 10,
            'complexity_factors': {
                'high_response_time': 1.5,
                'large_content': 1.3,
                'slow_server': 1.4,
                'fast_server': 0.8,
                'small_content': 0.9,
                'cdn_detected': 0.7
            }
        }
    
    def profile_target(self, target: str) -> TargetProfile:
        """Profile a target to determine optimal configuration"""
        domain = urlparse(target).netloc
        
        # Check if we already have a profile for this domain
        if domain in self.target_profiles:
            return self.target_profiles[domain]
        
        logger.info(f"Profiling target: {target}")
        
        # Perform initial reconnaissance
        try:
            start_time = time.time()
            response = requests.get(target, timeout=self.base_config['probe_timeout'])
            response_time = time.time() - start_time
            
            server_type = response.headers.get('Server', 'Unknown')
            content_length = len(response.content)
            status_code = response.status_code
            
            # Calculate complexity score
            complexity_score = self._calculate_complexity_score(
                response_time, content_length, server_type, status_code
            )
            
            # Generate recommendations
            recommended_timeout = self._calculate_timeout(complexity_score, response_time)
            recommended_delay = self._calculate_delay(complexity_score, response_time)
            recommended_workers = self._calculate_workers(complexity_score, response_time)
            
            profile = TargetProfile(
                domain=domain,
                response_time=response_time,
                server_type=server_type,
                content_length=content_length,
                is_responsive=True,
                complexity_score=complexity_score,
                recommended_timeout=recommended_timeout,
                recommended_delay=recommended_delay,
                recommended_workers=recommended_workers
            )
            
            self.target_profiles[domain] = profile
            logger.info(f"Target profile created: {domain} (complexity: {complexity_score:.2f})")
            
            return profile
            
        except Exception as e:
            logger.warning(f"Failed to profile target {target}: {e}")
            
            # Create default profile for unresponsive targets
            profile = TargetProfile(
                domain=domain,
                response_time=float('inf'),
                server_type='Unknown',
                content_length=0,
                is_responsive=False,
                complexity_score=2.0,  # High complexity for safety
                recommended_timeout=self.base_config['max_timeout'],
                recommended_delay=self.base_config['max_delay'],
                recommended_workers=self.base_config['min_workers']
            )
            
            self.target_profiles[domain] = profile
            return profile
    
    def _calculate_complexity_score(self, response_time: float, content_length: int, 
                                  server_type: str, status_code: int) -> float:
        """Calculate complexity score based on target characteristics"""
        score = 1.0
        factors = self.base_config['complexity_factors']
        
        # Response time factor
        if response_time > 2.0:
            score *= factors['high_response_time']
        elif response_time < 0.5:
            score *= factors['fast_server']
        
        # Content size factor
        if content_length > 1000000:  # 1MB+
            score *= factors['large_content']
        elif content_length < 10000:  # 10KB-
            score *= factors['small_content']
        
        # Server type factor
        server_lower = server_type.lower()
        if any(cdn in server_lower for cdn in ['cloudflare', 'cloudfront', 'akamai']):
            score *= factors['cdn_detected']
        elif any(slow in server_lower for slow in ['iis', 'apache']):
            score *= factors['slow_server']
        
        # Status code factor
        if status_code in [429, 503, 504]:
            score *= 1.5  # Rate limited or overloaded
        elif status_code in [403, 401]:
            score *= 1.2  # Protected
        
        return max(0.5, min(3.0, score))  # Clamp between 0.5 and 3.0
    
    def _calculate_timeout(self, complexity_score: float, response_time: float) -> int:
        """Calculate optimal timeout based on complexity and response time"""
        base_timeout = self.base_config['base_timeout']
        
        # Factor in complexity
        timeout = base_timeout * complexity_score
        
        # Factor in response time (at least 5x the response time)
        if response_time != float('inf'):
            timeout = max(timeout, response_time * 5)
        
        # Apply bounds
        return int(max(self.base_config['min_timeout'], 
                      min(self.base_config['max_timeout'], timeout)))
    
    def _calculate_delay(self, complexity_score: float, response_time: float) -> float:
        """Calculate optimal delay between requests"""
        base_delay = self.base_config['base_delay']
        
        # Scale with complexity
        delay = base_delay * complexity_score
        
        # Factor in response time
        if response_time != float('inf'):
            delay = max(delay, response_time * 0.1)
        
        # Apply bounds
        return max(self.base_config['min_delay'], 
                  min(self.base_config['max_delay'], delay))
    
    def _calculate_workers(self, complexity_score: float, response_time: float) -> int:
        """Calculate optimal number of workers"""
        base_workers = self.base_config['base_workers']
        
        # Fewer workers for more complex targets
        workers = int(base_workers / complexity_score)
        
        # Factor in response time
        if response_time != float('inf'):
            if response_time > 2.0:
                workers = max(1, workers // 2)  # Reduce workers for slow targets
            elif response_time < 0.5:
                workers = min(self.base_config['max_workers'], workers * 2)  # More workers for fast targets
        
        # Apply bounds
        return max(self.base_config['min_workers'], 
                  min(self.base_config['max_workers'], workers))
    
    def get_scan_config(self, target: str) -> Dict[str, Any]:
        """Get optimized configuration for scanning a target"""
        profile = self.profile_target(target)
        
        return {
            'timeout': profile.recommended_timeout,
            'delay': profile.recommended_delay,
            'workers': profile.recommended_workers,
            'complexity_score': profile.complexity_score,
            'target_responsive': profile.is_responsive,
            'estimated_scan_time': self._estimate_scan_time(profile),
            'retry_config': self._get_retry_config(profile)
        }
    
    def _estimate_scan_time(self, profile: TargetProfile) -> int:
        """Estimate total scan time based on target profile"""
        base_time = 60  # Base scan time in seconds
        
        # Factor in complexity
        estimated_time = base_time * profile.complexity_score
        
        # Factor in response time
        if profile.response_time != float('inf'):
            estimated_time += profile.response_time * 20  # Rough estimate
        
        # Factor in workers (more workers = faster scan)
        estimated_time = estimated_time / math.sqrt(profile.recommended_workers)
        
        return int(max(30, min(600, estimated_time)))  # Between 30 seconds and 10 minutes
    
    def _get_retry_config(self, profile: TargetProfile) -> Dict[str, Any]:
        """Get retry configuration based on target profile"""
        if not profile.is_responsive:
            return {
                'max_retries': 1,
                'backoff_factor': 2.0,
                'retry_delay': 5.0
            }
        
        complexity_factor = profile.complexity_score
        
        return {
            'max_retries': max(1, int(3 / complexity_factor)),
            'backoff_factor': 1.5 + (complexity_factor - 1) * 0.5,
            'retry_delay': profile.recommended_delay * 2
        }
    
    def update_profile_from_scan(self, target: str, scan_results: Dict[str, Any]) -> None:
        """Update target profile based on scan results"""
        domain = urlparse(target).netloc
        
        if domain not in self.target_profiles:
            return
        
        profile = self.target_profiles[domain]
        
        # Update based on scan performance
        if 'scan_duration' in scan_results:
            actual_duration = scan_results['scan_duration']
            estimated_duration = self._estimate_scan_time(profile)
            
            # Adjust complexity score based on actual vs estimated duration
            if actual_duration > estimated_duration * 1.5:
                profile.complexity_score = min(3.0, profile.complexity_score * 1.1)
            elif actual_duration < estimated_duration * 0.7:
                profile.complexity_score = max(0.5, profile.complexity_score * 0.9)
        
        # Update recommendations
        profile.recommended_timeout = self._calculate_timeout(
            profile.complexity_score, profile.response_time
        )
        profile.recommended_delay = self._calculate_delay(
            profile.complexity_score, profile.response_time
        )
        profile.recommended_workers = self._calculate_workers(
            profile.complexity_score, profile.response_time
        )
        
        logger.info(f"Updated profile for {domain}: complexity={profile.complexity_score:.2f}")
    
    def get_adaptive_delays(self, target: str, test_type: str) -> Dict[str, float]:
        """Get adaptive delays for different test types"""
        profile = self.profile_target(target)
        base_delay = profile.recommended_delay
        
        # Different delays for different test types
        delays = {
            'vulnerability_scan': base_delay * 1.5,  # More aggressive, need more delay
            'port_scan': base_delay * 0.5,          # Less intrusive
            'directory_scan': base_delay * 1.2,     # Moderate
            'header_scan': base_delay * 0.3,        # Very light
            'ssl_scan': base_delay * 0.8,           # Light
            'technology_scan': base_delay * 0.6,    # Light
            'information_disclosure': base_delay * 1.0  # Standard
        }
        
        return delays.get(test_type, base_delay)
    
    def should_skip_test(self, target: str, test_type: str) -> Tuple[bool, str]:
        """Determine if a test should be skipped based on target profile"""
        profile = self.profile_target(target)
        
        # Skip intensive tests for unresponsive targets
        if not profile.is_responsive:
            intensive_tests = ['vulnerability_scan', 'directory_scan', 'port_scan']
            if test_type in intensive_tests:
                return True, f"Skipping {test_type} - target unresponsive"
        
        # Skip port scan for CDN targets (usually not useful)
        if test_type == 'port_scan' and 'cdn' in profile.server_type.lower():
            return True, "Skipping port scan - CDN detected"
        
        return False, ""

# Global instance
dynamic_config = DynamicConfigManager()

def get_dynamic_config(target: str) -> Dict[str, Any]:
    """Get dynamic configuration for a target"""
    return dynamic_config.get_scan_config(target)

def get_adaptive_delay(target: str, test_type: str) -> float:
    """Get adaptive delay for a specific test type"""
    return dynamic_config.get_adaptive_delays(target, test_type)

def should_skip_test(target: str, test_type: str) -> Tuple[bool, str]:
    """Check if a test should be skipped"""
    return dynamic_config.should_skip_test(target, test_type)

def update_target_profile(target: str, scan_results: Dict[str, Any]) -> None:
    """Update target profile after scan"""
    dynamic_config.update_profile_from_scan(target, scan_results)