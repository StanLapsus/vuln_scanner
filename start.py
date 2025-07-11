#!/usr/bin/env python3
"""
Production-Ready Vulnerability Scanner Launcher
Enhanced with configuration management, monitoring, and production features
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import ConfigManager, setup_logging
from monitoring import enhanced_logger, get_health_status, get_monitoring_report
from web_app import start_server
from scan import ProductionVulnerabilityScanner

def setup_argument_parser():
    """Set up command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Production-Ready Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --web                          # Start web server
  %(prog)s --web --port 9000              # Start web server on port 9000
  %(prog)s --cli --target https://example.com  # CLI scan
  %(prog)s --config config.json          # Use custom config file
  %(prog)s --health                      # Check system health
  %(prog)s --monitor                     # Show monitoring dashboard
        """
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--web', action='store_true', 
                           help='Start web server (default)')
    mode_group.add_argument('--cli', action='store_true',
                           help='Run in CLI mode')
    mode_group.add_argument('--health', action='store_true',
                           help='Check system health')
    mode_group.add_argument('--monitor', action='store_true',
                           help='Show monitoring dashboard')
    
    # Web server options
    parser.add_argument('--port', type=int, default=8080,
                       help='Web server port (default: 8080)')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Web server host (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    
    # CLI options
    parser.add_argument('--target', type=str,
                       help='Target URL for CLI scan')
    parser.add_argument('--output', type=str,
                       help='Output file for CLI scan results')
    parser.add_argument('--format', choices=['json', 'html', 'csv'],
                       default='json', help='Output format (default: json)')
    
    # Configuration options
    parser.add_argument('--config', type=str,
                       help='Configuration file path')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Log level (default: INFO)')
    parser.add_argument('--log-file', type=str,
                       help='Log file path')
    
    # Advanced options
    parser.add_argument('--workers', type=int,
                       help='Number of worker threads')
    parser.add_argument('--timeout', type=int,
                       help='Request timeout in seconds')
    parser.add_argument('--rate-limit', type=int,
                       help='Rate limit for requests')
    parser.add_argument('--deep-scan', action='store_true',
                       help='Enable deep scanning')
    
    # Utility options
    parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')
    parser.add_argument('--create-config', action='store_true',
                       help='Create sample configuration file')
    
    return parser

def main():
    """Main application entry point"""
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Handle utility commands first
    if args.create_config:
        from config import create_sample_config
        create_sample_config()
        print("Sample configuration created: scanner_config.sample.json")
        return
    
    try:
        # Initialize configuration
        config_manager = ConfigManager(args.config)
        config = config_manager.get_config()
        
        # Override config with command line arguments
        if args.port:
            config.web_port = args.port
        if args.host:
            config.web_host = args.host
        if args.debug:
            config.debug_mode = True
        if args.workers:
            config.max_workers = args.workers
        if args.timeout:
            config.timeout = args.timeout
        if args.rate_limit:
            config.rate_limit = args.rate_limit
        if args.deep_scan:
            config.enable_deep_scan = True
        if args.log_level:
            config.log_level = args.log_level
        if args.log_file:
            config.log_file = args.log_file
        
        # Setup logging
        setup_logging(config)
        
        # Log startup
        enhanced_logger.info(f"Starting Vulnerability Scanner v2.0.0", 
                            mode=args.web and 'web' or 'cli',
                            config=config.__dict__)
        
        # Handle different modes
        if args.health:
            handle_health_check()
        elif args.monitor:
            handle_monitoring_dashboard()
        elif args.cli:
            handle_cli_mode(args, config)
        else:
            # Default to web mode
            handle_web_mode(args, config)
            
    except KeyboardInterrupt:
        enhanced_logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        enhanced_logger.error(f"Application error: {e}")
        sys.exit(1)

def handle_health_check():
    """Handle health check mode"""
    print("Checking system health...")
    health = get_health_status()
    
    print(f"Status: {health['status'].upper()}")
    print(f"Active Scans: {health['active_scans']}")
    print(f"Total Scans: {health['total_scans']}")
    
    if health['issues']:
        print("\nIssues:")
        for issue in health['issues']:
            print(f"  - {issue}")
    
    system_metrics = health['system_metrics']
    print(f"\nSystem Metrics:")
    print(f"  CPU Usage: {system_metrics.get('cpu_percent', 0):.1f}%")
    print(f"  Memory Usage: {system_metrics.get('memory_percent', 0):.1f}%")
    print(f"  Disk Usage: {system_metrics.get('disk_percent', 0):.1f}%")
    
    # Exit with appropriate code
    sys.exit(0 if health['status'] == 'healthy' else 1)

def handle_monitoring_dashboard():
    """Handle monitoring dashboard mode"""
    print("Generating monitoring report...")
    report = get_monitoring_report()
    
    print(f"Generated at: {report['generated_at']}")
    print(f"Total Scans: {report['metrics_summary']['total_scans']}")
    print(f"Total Vulnerabilities: {report['metrics_summary']['total_vulnerabilities']}")
    print(f"Active Scans: {report['system_metrics']['active_scans']}")
    
    if report['recent_alerts']:
        print(f"\nRecent Alerts ({len(report['recent_alerts'])}):")
        for alert in report['recent_alerts'][:5]:
            print(f"  [{alert['severity'].upper()}] {alert['message']}")
    
    if report['error_patterns']:
        print(f"\nError Patterns:")
        for pattern, count in report['error_patterns'].items():
            print(f"  {pattern}: {count}")
    
    print(f"\nSystem Health:")
    print(f"  CPU: {report['system_metrics']['cpu_percent']:.1f}%")
    print(f"  Memory: {report['system_metrics']['memory_percent']:.1f}%")
    print(f"  Disk: {report['system_metrics']['disk_percent']:.1f}%")

def handle_cli_mode(args, config):
    """Handle CLI mode"""
    if not args.target:
        print("Error: --target is required for CLI mode")
        sys.exit(1)
    
    print(f"Starting CLI scan for: {args.target}")
    enhanced_logger.info(f"CLI scan started", target=args.target)
    
    try:
        # Initialize scanner
        scanner = ProductionVulnerabilityScanner(args.target, config.max_workers)
        
        # Run scan
        results = scanner.run_legacy_scans()
        
        # Save results
        import time
        output_file = args.output or f"scan_results_{int(time.time())}.{args.format}"
        
        if args.format == 'json':
            import json
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        elif args.format == 'html':
            # Use the scanner's HTML generation
            html_file = scanner.generate_report('html')
            if args.output:
                os.rename(html_file, output_file)
            else:
                output_file = html_file
        elif args.format == 'csv':
            # Basic CSV export
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Target', 'Scan ID', 'Duration', 'Tests Run', 'Vulnerabilities'])
                writer.writerow([
                    results.get('target', ''),
                    results.get('scan_id', ''),
                    results.get('duration', 0),
                    results.get('summary', {}).get('total_tests', 0),
                    results.get('summary', {}).get('vulnerabilities_found', 0)
                ])
        
        print(f"Scan completed. Results saved to: {output_file}")
        
        # Print summary
        summary = results.get('summary', {})
        print(f"Tests Run: {summary.get('total_tests', 0)}")
        print(f"Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
        print(f"Duration: {results.get('duration', 0):.2f} seconds")
        
        enhanced_logger.info(f"CLI scan completed", 
                            target=args.target,
                            output_file=output_file,
                            summary=summary)
        
    except Exception as e:
        enhanced_logger.error(f"CLI scan failed", target=args.target, error=str(e))
        print(f"Error: {e}")
        sys.exit(1)

def handle_web_mode(args, config):
    """Handle web mode"""
    print(f"Starting web server on {config.web_host}:{config.web_port}")
    enhanced_logger.info(f"Web server starting", 
                        host=config.web_host, 
                        port=config.web_port,
                        debug=config.debug_mode)
    
    # Create necessary directories
    from pathlib import Path
    Path(config.output_directory).mkdir(parents=True, exist_ok=True)
    Path('logs').mkdir(parents=True, exist_ok=True)
    Path('reports').mkdir(parents=True, exist_ok=True)
    
    try:
        # Start the web server
        start_server(config.web_port)
    except Exception as e:
        enhanced_logger.error(f"Web server failed to start", error=str(e))
        print(f"Error starting web server: {e}")
        sys.exit(1)

def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║               🔍 Vulnerability Scanner v2.0.0                 ║
    ║                                                               ║
    ║              Production-Ready Security Testing                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

if __name__ == '__main__':
    # Print banner
    print_banner()
    
    # Run main application
    main()