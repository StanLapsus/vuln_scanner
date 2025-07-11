#!/usr/bin/env python3

"""
Production-Ready Vulnerability Scanner
Enhanced with sophisticated methods and real-time capabilities
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from enhanced_scanner import EnhancedVulnerabilityScanner
from demo_mode import is_demo_mode_needed, generate_demo_scan_results
from advanced_analyzer import AdvancedSecurityAnalyzer
import urllib3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProductionVulnerabilityScanner:
    """Production-ready vulnerability scanner with enhanced capabilities"""
    
    def __init__(self, target, threads=10):
        self.target = target
        self.threads = threads
        self.scanner = None
        self.scan_results = {}
        self.progress_data = {'progress': 0, 'message': 'Initializing...'}
        self.demo_mode = is_demo_mode_needed(target)
        
        logger.info(f"Scanner initialized for {target} (Demo mode: {self.demo_mode})")
        
    def set_progress_callback(self, callback):
        """Set progress callback for real-time updates"""
        self.progress_callback = callback
        
    def update_progress(self, progress, message):
        """Update scan progress"""
        self.progress_data = {'progress': progress, 'message': message}
        if hasattr(self, 'progress_callback'):
            self.progress_callback(progress, message)
    
    async def scan_website(self):
        """Run comprehensive security scan"""
        try:
            if self.demo_mode:
                logger.info(f"Using demo mode for {self.target}")
                return await self._run_demo_scan()
            else:
                logger.info(f"Using live scanner for {self.target}")
                return await self._run_live_scan()
                
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            error_result = {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'target': self.target
            }
            return error_result
    
    async def _run_demo_scan(self):
        """Run demo scan with simulated progress"""
        self.update_progress(10, "Initializing demo scan...")
        await asyncio.sleep(1)
        
        self.update_progress(30, "Simulating network tests...")
        await asyncio.sleep(1)
        
        self.update_progress(60, "Generating realistic test data...")
        await asyncio.sleep(1)
        
        self.update_progress(90, "Finalizing demo results...")
        await asyncio.sleep(0.5)
        
        # Generate demo results
        results = generate_demo_scan_results(self.target)
        
        self.update_progress(100, "Demo scan completed")
        self.scan_results = results
        return results
    
    async def _run_live_scan(self):
        """Run live scan with enhanced scanner"""
        # Initialize enhanced scanner
        self.scanner = EnhancedVulnerabilityScanner(
            self.target, 
            max_workers=self.threads,
            timeout=30
        )
        
        # Set progress callback
        self.scanner.set_progress_callback(self.update_progress)
        
        # Run comprehensive scan
        logger.info(f"Starting live scan for {self.target}")
        results = await self.scanner.run_comprehensive_scan()
        
        # Store results
        self.scan_results = results
        return results
    
    def run_legacy_scans(self):
        """Run legacy scanning methods with enhanced error handling"""
        try:
            # Run the enhanced scanner synchronously
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(self.scan_website())
                return results
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Legacy scan failed: {e}")
            return {
                'error': f"Scan failed: {str(e)}",
                'timestamp': datetime.now().isoformat(),
                'target': self.target
            }
    
    def get_progress(self):
        """Get current scan progress"""
        return self.progress_data
    
    def generate_report(self, format_type='json'):
        """Generate scan report"""
        if self.scan_results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.{format_type}"
            
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=2, default=str)
            elif format_type == 'html':
                self._generate_html_report(filename)
            
            logger.info(f"Report generated: {filename}")
            return filename
        else:
            raise ValueError("No scan results available")
    
    def _generate_html_report(self, filename):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {self.target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header p {{ margin: 5px 0; opacity: 0.9; }}
                .summary {{ background: #f8f9fa; padding: 20px; border-bottom: 1px solid #e9ecef; }}
                .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                .summary-item {{ text-align: center; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .summary-item h3 {{ margin: 0; font-size: 2em; color: #333; }}
                .summary-item p {{ margin: 5px 0; color: #666; }}
                .results {{ padding: 20px; }}
                .test-result {{ margin: 20px 0; border: 1px solid #e9ecef; border-radius: 8px; overflow: hidden; }}
                .test-header {{ background: #f8f9fa; padding: 15px; border-bottom: 1px solid #e9ecef; }}
                .test-header h3 {{ margin: 0; color: #333; }}
                .test-status {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.9em; font-weight: bold; }}
                .status-success {{ background: #d4edda; color: #155724; }}
                .status-error {{ background: #f8d7da; color: #721c24; }}
                .status-warning {{ background: #fff3cd; color: #856404; }}
                .test-content {{ padding: 15px; }}
                .vulnerability {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 10px 0; }}
                .vulnerability-high {{ background: #f8d7da; border-color: #f5c6cb; }}
                .vulnerability-medium {{ background: #fff3cd; border-color: #ffeaa7; }}
                .vulnerability-low {{ background: #d1ecf1; border-color: #bee5eb; }}
                pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
                .footer {{ text-align: center; padding: 20px; color: #666; border-top: 1px solid #e9ecef; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Security Scan Report</h1>
                    <p><strong>Target:</strong> {self.target}</p>
                    <p><strong>Scan ID:</strong> {self.scan_results.get('scan_id', 'Unknown')}</p>
                    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="summary">
                    <div class="summary-grid">
                        <div class="summary-item">
                            <h3>{self.scan_results.get('summary', {}).get('total_tests', 0)}</h3>
                            <p>Total Tests</p>
                        </div>
                        <div class="summary-item">
                            <h3>{self.scan_results.get('summary', {}).get('completed_tests', 0)}</h3>
                            <p>Completed Tests</p>
                        </div>
                        <div class="summary-item">
                            <h3>{self.scan_results.get('summary', {}).get('vulnerabilities_found', 0)}</h3>
                            <p>Vulnerabilities Found</p>
                        </div>
                        <div class="summary-item">
                            <h3>{self.scan_results.get('duration', 0):.2f}s</h3>
                            <p>Scan Duration</p>
                        </div>
                    </div>
                </div>
                
                <div class="results">
                    <h2>Test Results</h2>
                    {self._format_test_results_html()}
                </div>
                
                <div class="footer">
                    <p>Generated by Production Vulnerability Scanner v2.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _format_test_results_html(self):
        """Format test results for HTML"""
        html = ""
        tests = self.scan_results.get('tests', {})
        
        for test_name, test_data in tests.items():
            status = test_data.get('status', 'unknown')
            status_class = f"status-{status}"
            
            html += f"""
            <div class="test-result">
                <div class="test-header">
                    <h3>{test_data.get('test_name', test_name).title()}</h3>
                    <span class="test-status {status_class}">{status.upper()}</span>
                </div>
                <div class="test-content">
                    <p><strong>Timestamp:</strong> {test_data.get('timestamp', 'N/A')}</p>
                    {f'<p><strong>Error:</strong> {test_data.get("error", "")}</p>' if test_data.get('error') else ''}
                    {self._format_test_details_html(test_data.get('details', {}))}
                </div>
            </div>
            """
        
        return html
    
    def _format_test_details_html(self, details):
        """Format test details for HTML"""
        if not details:
            return ""
        
        html = "<h4>Details:</h4>"
        
        # Handle vulnerabilities specially
        if 'vulnerabilities' in details:
            vulnerabilities = details['vulnerabilities']
            if vulnerabilities:
                html += "<h5>Vulnerabilities Found:</h5>"
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Unknown').lower()
                    html += f"""
                    <div class="vulnerability vulnerability-{severity}">
                        <strong>{vuln.get('type', 'Unknown Vulnerability')}</strong>
                        <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                        <p>{vuln.get('description', 'No description available')}</p>
                    </div>
                    """
            else:
                html += "<p>No vulnerabilities found.</p>"
        
        # Handle other details
        html += f"<pre>{json.dumps(details, indent=2)}</pre>"
        
        return html

# Maintain backward compatibility
class UltimateAdvancedWebScanner(ProductionVulnerabilityScanner):
    """Legacy class name for backward compatibility"""
    pass

# Legacy methods removed - now using enhanced scanner

def save_results_to_file(results):
    """Save scan results to JSON file"""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    file_name = f"scan_results_{timestamp}.json"
    
    # Ensure results is serializable
    if hasattr(results, 'to_dict'):
        results = results.to_dict()
    
    with open(file_name, "w") as f:
        json.dump(results, f, indent=4, default=str)
    
    logger.info(f"Results saved to {file_name}")
    return file_name

def print_colored_results(results):
    """Print results with colors (legacy function)"""
    print(f"\n=== SCAN RESULTS ===")
    print(f"Target: {results.get('target', 'Unknown')}")
    print(f"Scan ID: {results.get('scan_id', 'Unknown')}")
    print(f"Duration: {results.get('duration', 0):.2f}s")
    print(f"Tests: {results.get('summary', {}).get('total_tests', 0)}")
    print(f"Vulnerabilities: {results.get('summary', {}).get('vulnerabilities_found', 0)}")
    print("=" * 50)

def main():
    """Main function for CLI usage"""
    print("🔍 Production-Ready Vulnerability Scanner")
    print("For CLI usage, run: python3 enhanced_scanner.py <target>")
    print("For web interface, run: python3 start.py")

if __name__ == "__main__":
    main()

def save_results_to_file(results):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    file_name = f"scan_results_{timestamp}.json"
    with open(file_name, "w") as f:
        json.dump(results, f, indent=4)
    return file_name

def print_colored_results(results):
    def colored_text(text, color):
        return f"{color}{text}{Style.RESET_ALL}"

    for technique, result in results.items():
        if isinstance(result, dict):
            print(colored_text(f"\n{technique} Results:", Fore.CYAN))
            for key, value in result.items():
                print(colored_text(f"{key}: {value}", Fore.YELLOW))
        else:
            print(colored_text(f"\n{technique}:", Fore.CYAN))
            print(colored_text(result, Fore.YELLOW))

def main():
    """This function is kept for backward compatibility but CLI mode is deprecated"""
    print("CLI mode is deprecated. Please use the web interface.")
    print("Run: python3 start.py")

if __name__ == "__main__":
    main()
