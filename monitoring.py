#!/usr/bin/env python3
"""
Enhanced Logging and Monitoring for Vulnerability Scanner
Production-ready logging, metrics, and monitoring capabilities
"""

import logging
import json
import time
import threading
import psutil
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ScanMetrics:
    """Metrics for a single scan"""
    scan_id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    status: str = 'running'
    tests_run: int = 0
    vulnerabilities_found: int = 0
    errors_encountered: int = 0
    memory_usage: Dict[str, float] = field(default_factory=dict)
    cpu_usage: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'status': self.status,
            'tests_run': self.tests_run,
            'vulnerabilities_found': self.vulnerabilities_found,
            'errors_encountered': self.errors_encountered,
            'memory_usage': self.memory_usage,
            'cpu_usage': self.cpu_usage
        }


class MetricsCollector:
    """Collects and stores metrics for monitoring"""
    
    def __init__(self, db_path: str = 'metrics.db'):
        self.db_path = db_path
        self.current_scans: Dict[str, ScanMetrics] = {}
        self.lock = threading.Lock()
        self.init_database()
        
    def init_database(self) -> None:
        """Initialize the metrics database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS scan_metrics (
                        scan_id TEXT PRIMARY KEY,
                        target TEXT,
                        start_time TEXT,
                        end_time TEXT,
                        duration REAL,
                        status TEXT,
                        tests_run INTEGER,
                        vulnerabilities_found INTEGER,
                        errors_encountered INTEGER,
                        memory_usage TEXT,
                        cpu_usage REAL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        cpu_percent REAL,
                        memory_percent REAL,
                        memory_used INTEGER,
                        disk_usage REAL,
                        active_scans INTEGER,
                        total_scans INTEGER
                    )
                ''')
                
                conn.commit()
                logger.info("Metrics database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize metrics database: {e}")
    
    def start_scan_metrics(self, scan_id: str, target: str) -> None:
        """Start collecting metrics for a scan"""
        with self.lock:
            metrics = ScanMetrics(
                scan_id=scan_id,
                target=target,
                start_time=datetime.now()
            )
            self.current_scans[scan_id] = metrics
            logger.info(f"Started metrics collection for scan {scan_id}")
    
    def update_scan_metrics(self, scan_id: str, **kwargs) -> None:
        """Update metrics for a scan"""
        with self.lock:
            if scan_id in self.current_scans:
                metrics = self.current_scans[scan_id]
                for key, value in kwargs.items():
                    if hasattr(metrics, key):
                        setattr(metrics, key, value)
                
                # Update system metrics
                try:
                    process = psutil.Process()
                    metrics.memory_usage = {
                        'rss': process.memory_info().rss,
                        'vms': process.memory_info().vms,
                        'percent': process.memory_percent()
                    }
                    metrics.cpu_usage = process.cpu_percent()
                except Exception as e:
                    logger.warning(f"Failed to update system metrics: {e}")
    
    def finish_scan_metrics(self, scan_id: str, status: str = 'completed') -> None:
        """Finish collecting metrics for a scan"""
        with self.lock:
            if scan_id in self.current_scans:
                metrics = self.current_scans[scan_id]
                metrics.end_time = datetime.now()
                metrics.duration = (metrics.end_time - metrics.start_time).total_seconds()
                metrics.status = status
                
                # Save to database
                self.save_scan_metrics(metrics)
                
                # Remove from current scans
                del self.current_scans[scan_id]
                logger.info(f"Finished metrics collection for scan {scan_id}")
    
    def save_scan_metrics(self, metrics: ScanMetrics) -> None:
        """Save scan metrics to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO scan_metrics 
                    (scan_id, target, start_time, end_time, duration, status, 
                     tests_run, vulnerabilities_found, errors_encountered, 
                     memory_usage, cpu_usage)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.scan_id,
                    metrics.target,
                    metrics.start_time.isoformat(),
                    metrics.end_time.isoformat() if metrics.end_time else None,
                    metrics.duration,
                    metrics.status,
                    metrics.tests_run,
                    metrics.vulnerabilities_found,
                    metrics.errors_encountered,
                    json.dumps(metrics.memory_usage),
                    metrics.cpu_usage
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save scan metrics: {e}")
    
    def save_system_metrics(self) -> None:
        """Save current system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO system_metrics 
                    (timestamp, cpu_percent, memory_percent, memory_used, 
                     disk_usage, active_scans, total_scans)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now().isoformat(),
                    cpu_percent,
                    memory.percent,
                    memory.used,
                    disk.percent,
                    len(self.current_scans),
                    self.get_total_scans()
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save system metrics: {e}")
    
    def get_scan_metrics(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get metrics for a specific scan"""
        with self.lock:
            if scan_id in self.current_scans:
                return self.current_scans[scan_id].to_dict()
        
        # Check database
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT * FROM scan_metrics WHERE scan_id = ?',
                    (scan_id,)
                )
                row = cursor.fetchone()
                if row:
                    return {
                        'scan_id': row[0],
                        'target': row[1],
                        'start_time': row[2],
                        'end_time': row[3],
                        'duration': row[4],
                        'status': row[5],
                        'tests_run': row[6],
                        'vulnerabilities_found': row[7],
                        'errors_encountered': row[8],
                        'memory_usage': json.loads(row[9]) if row[9] else {},
                        'cpu_usage': row[10]
                    }
        except Exception as e:
            logger.error(f"Failed to get scan metrics: {e}")
        
        return None
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_total': memory.total,
                'disk_percent': disk.percent,
                'disk_used': disk.used,
                'disk_total': disk.total,
                'active_scans': len(self.current_scans),
                'total_scans': self.get_total_scans(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    def get_total_scans(self) -> int:
        """Get total number of scans"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM scan_metrics')
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to get total scans: {e}")
            return 0
    
    def get_scan_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get scan history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT * FROM scan_metrics ORDER BY start_time DESC LIMIT ?',
                    (limit,)
                )
                rows = cursor.fetchall()
                
                return [
                    {
                        'scan_id': row[0],
                        'target': row[1],
                        'start_time': row[2],
                        'end_time': row[3],
                        'duration': row[4],
                        'status': row[5],
                        'tests_run': row[6],
                        'vulnerabilities_found': row[7],
                        'errors_encountered': row[8],
                        'memory_usage': json.loads(row[9]) if row[9] else {},
                        'cpu_usage': row[10]
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get scan statistics
                cursor = conn.execute('''
                    SELECT 
                        COUNT(*) as total_scans,
                        AVG(duration) as avg_duration,
                        SUM(vulnerabilities_found) as total_vulns,
                        SUM(errors_encountered) as total_errors
                    FROM scan_metrics
                    WHERE status = 'completed'
                ''')
                scan_stats = cursor.fetchone()
                
                # Get recent system metrics
                cursor = conn.execute('''
                    SELECT AVG(cpu_percent), AVG(memory_percent), AVG(disk_usage)
                    FROM system_metrics
                    WHERE timestamp > datetime('now', '-1 hour')
                ''')
                system_stats = cursor.fetchone()
                
                return {
                    'total_scans': scan_stats[0] or 0,
                    'avg_duration': scan_stats[1] or 0,
                    'total_vulnerabilities': scan_stats[2] or 0,
                    'total_errors': scan_stats[3] or 0,
                    'avg_cpu_usage': system_stats[0] or 0,
                    'avg_memory_usage': system_stats[1] or 0,
                    'avg_disk_usage': system_stats[2] or 0,
                    'active_scans': len(self.current_scans),
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            logger.error(f"Failed to get metrics summary: {e}")
            return {}


class EnhancedLogger:
    """Enhanced logging with structured logging and monitoring"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.metrics_collector = MetricsCollector()
        self.alerts_queue = deque(maxlen=100)
        self.error_patterns = defaultdict(int)
        
    def info(self, message: str, **kwargs) -> None:
        """Log info message with context"""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message with context"""
        self.logger.warning(message, extra=kwargs)
        self.check_alert_conditions(message, 'warning')
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message with context"""
        self.logger.error(message, extra=kwargs)
        self.track_error_pattern(message)
        self.check_alert_conditions(message, 'error')
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message with context"""
        self.logger.critical(message, extra=kwargs)
        self.track_error_pattern(message)
        self.check_alert_conditions(message, 'critical')
    
    def track_error_pattern(self, message: str) -> None:
        """Track error patterns for monitoring"""
        # Extract error pattern (simplified)
        pattern = message.split(':')[0] if ':' in message else message
        self.error_patterns[pattern] += 1
        
        # Alert if error pattern is frequent
        if self.error_patterns[pattern] > 5:
            self.add_alert(f"Frequent error pattern: {pattern}", 'high')
    
    def check_alert_conditions(self, message: str, level: str) -> None:
        """Check if alert conditions are met"""
        alert_keywords = [
            'timeout', 'failed', 'critical', 'exception', 'error',
            'unauthorized', 'forbidden', 'connection', 'memory'
        ]
        
        if any(keyword in message.lower() for keyword in alert_keywords):
            severity = 'high' if level in ['error', 'critical'] else 'medium'
            self.add_alert(message, severity)
    
    def add_alert(self, message: str, severity: str = 'medium') -> None:
        """Add alert to queue"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'severity': severity,
            'id': f"alert_{int(time.time())}_{hash(message) % 1000}"
        }
        self.alerts_queue.append(alert)
        self.logger.warning(f"Alert generated: {alert}")
    
    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return list(self.alerts_queue)[-limit:]
    
    def get_error_patterns(self) -> Dict[str, int]:
        """Get error patterns"""
        return dict(self.error_patterns)
    
    def clear_alerts(self) -> None:
        """Clear all alerts"""
        self.alerts_queue.clear()
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        return {
            'total_alerts': len(self.alerts_queue),
            'error_patterns': len(self.error_patterns),
            'most_common_errors': dict(
                sorted(self.error_patterns.items(), key=lambda x: x[1], reverse=True)[:5]
            ),
            'recent_alerts': len([
                alert for alert in self.alerts_queue
                if datetime.fromisoformat(alert['timestamp']) > datetime.now() - timedelta(hours=1)
            ])
        }


class MonitoringDashboard:
    """Simple monitoring dashboard"""
    
    def __init__(self, metrics_collector: MetricsCollector, enhanced_logger: EnhancedLogger):
        self.metrics_collector = metrics_collector
        self.enhanced_logger = enhanced_logger
    
    def generate_status_report(self) -> Dict[str, Any]:
        """Generate comprehensive status report"""
        return {
            'system_metrics': self.metrics_collector.get_system_metrics(),
            'metrics_summary': self.metrics_collector.get_metrics_summary(),
            'scan_history': self.metrics_collector.get_scan_history(limit=10),
            'recent_alerts': self.enhanced_logger.get_alerts(limit=10),
            'error_patterns': self.enhanced_logger.get_error_patterns(),
            'log_stats': self.enhanced_logger.get_log_stats(),
            'generated_at': datetime.now().isoformat()
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        system_metrics = self.metrics_collector.get_system_metrics()
        alerts = self.enhanced_logger.get_alerts(limit=5)
        
        # Determine health status
        health_status = 'healthy'
        health_issues = []
        
        # Check system resources
        if system_metrics.get('cpu_percent', 0) > 80:
            health_status = 'warning'
            health_issues.append('High CPU usage')
        
        if system_metrics.get('memory_percent', 0) > 90:
            health_status = 'warning'
            health_issues.append('High memory usage')
        
        if system_metrics.get('disk_percent', 0) > 95:
            health_status = 'critical'
            health_issues.append('Low disk space')
        
        # Check for critical alerts
        critical_alerts = [alert for alert in alerts if alert['severity'] == 'high']
        if critical_alerts:
            health_status = 'warning'
            health_issues.append(f'{len(critical_alerts)} critical alerts')
        
        return {
            'status': health_status,
            'issues': health_issues,
            'system_metrics': system_metrics,
            'active_scans': system_metrics.get('active_scans', 0),
            'total_scans': system_metrics.get('total_scans', 0),
            'timestamp': datetime.now().isoformat()
        }
    
    def export_metrics(self, format: str = 'json') -> str:
        """Export metrics in specified format"""
        data = self.generate_status_report()
        
        if format == 'json':
            return json.dumps(data, indent=2)
        elif format == 'csv':
            # Simple CSV export for system metrics
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write system metrics
            writer.writerow(['Metric', 'Value'])
            for key, value in data['system_metrics'].items():
                writer.writerow([key, value])
            
            return output.getvalue()
        else:
            return str(data)


# Global instances
metrics_collector = MetricsCollector()
enhanced_logger = EnhancedLogger('vuln_scanner')
monitoring_dashboard = MonitoringDashboard(metrics_collector, enhanced_logger)

# Convenience functions
def start_scan_tracking(scan_id: str, target: str) -> None:
    """Start tracking a scan"""
    metrics_collector.start_scan_metrics(scan_id, target)

def update_scan_progress(scan_id: str, **kwargs) -> None:
    """Update scan progress"""
    metrics_collector.update_scan_metrics(scan_id, **kwargs)

def finish_scan_tracking(scan_id: str, status: str = 'completed') -> None:
    """Finish tracking a scan"""
    metrics_collector.finish_scan_metrics(scan_id, status)

def get_health_status() -> Dict[str, Any]:
    """Get system health status"""
    return monitoring_dashboard.health_check()

def get_monitoring_report() -> Dict[str, Any]:
    """Get comprehensive monitoring report"""
    return monitoring_dashboard.generate_status_report()


if __name__ == '__main__':
    # Test the monitoring system
    print("Testing monitoring system...")
    
    # Test metrics collection
    scan_id = "test_scan_123"
    start_scan_tracking(scan_id, "https://example.com")
    
    # Simulate scan progress
    update_scan_progress(scan_id, tests_run=5, vulnerabilities_found=2)
    
    # Test logging
    enhanced_logger.info("Test info message")
    enhanced_logger.warning("Test warning message")
    enhanced_logger.error("Test error message")
    
    # Finish scan
    finish_scan_tracking(scan_id, "completed")
    
    # Get status report
    report = get_monitoring_report()
    print(json.dumps(report, indent=2))
    
    # Get health status
    health = get_health_status()
    print(f"\nHealth Status: {health['status']}")
    print(f"Issues: {health['issues']}")
    print(f"Active Scans: {health['active_scans']}")
    print(f"Total Scans: {health['total_scans']}")