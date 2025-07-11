#!/usr/bin/env python3

"""
Production-Ready Web Application for Vulnerability Scanner
Enhanced with real-time capabilities, proper error handling, and professional features
"""

import json
import logging
import os
import socketserver
import threading
import time
from datetime import datetime
from http.server import SimpleHTTPRequestHandler
from urllib.parse import urlparse

from scan import ProductionVulnerabilityScanner, save_results_to_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webapp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedScanHandler(SimpleHTTPRequestHandler):
    """Enhanced HTTP request handler with production features"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests with enhanced routing"""
        try:
            if self.path == '/':
                self.serve_template('index.html')
            elif self.path == '/api/scan_status':
                self.handle_scan_status()
            elif self.path == '/api/health':
                self.handle_health_check()
            elif self.path == '/api/metrics':
                self.handle_metrics()
            elif self.path.startswith('/static/'):
                self.serve_static_file()
            elif self.path.startswith('/api/download/'):
                self.handle_download()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_POST(self):
        """Handle POST requests with enhanced routing"""
        try:
            if self.path == '/api/scan':
                self.handle_scan_request()
            elif self.path == '/api/generate_report':
                self.handle_generate_report()
            elif self.path == '/api/cancel_scan':
                self.handle_cancel_scan()
            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def serve_template(self, template_name):
        """Serve HTML template with error handling"""
        try:
            template_path = os.path.join('templates', template_name)
            if os.path.exists(template_path):
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                with open(template_path, 'r', encoding='utf-8') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            else:
                self.send_error(404, f"Template {template_name} not found")
        except Exception as e:
            logger.error(f"Error serving template {template_name}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def serve_static_file(self):
        """Serve static files with proper MIME types"""
        try:
            file_path = self.path[1:]  # Remove leading slash
            if os.path.exists(file_path) and os.path.isfile(file_path):
                # Determine MIME type
                if file_path.endswith('.css'):
                    content_type = 'text/css'
                elif file_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif file_path.endswith('.png'):
                    content_type = 'image/png'
                elif file_path.endswith('.jpg') or file_path.endswith('.jpeg'):
                    content_type = 'image/jpeg'
                elif file_path.endswith('.ico'):
                    content_type = 'image/x-icon'
                else:
                    content_type = 'text/plain'
                
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.send_header('Cache-Control', 'public, max-age=3600')
                self.end_headers()
                
                mode = 'rb' if content_type.startswith('image/') else 'r'
                encoding = None if mode == 'rb' else 'utf-8'
                
                with open(file_path, mode, encoding=encoding) as f:
                    content = f.read()
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    self.wfile.write(content)
            else:
                self.send_error(404, "Static file not found")
        except Exception as e:
            logger.error(f"Error serving static file {self.path}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_scan_status(self):
        """Handle scan status requests"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            
            status = getattr(self.server, 'scan_status', {'status': 'idle'})
            self.wfile.write(json.dumps(status).encode())
        except Exception as e:
            logger.error(f"Error handling scan status: {e}")
            self.send_json_error(500, "Failed to get scan status")
    
    def handle_health_check(self):
        """Handle health check requests"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            health_data = {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'uptime': time.time() - getattr(self.server, 'start_time', time.time()),
                'version': '2.0.0'
            }
            self.wfile.write(json.dumps(health_data).encode())
        except Exception as e:
            logger.error(f"Error handling health check: {e}")
            self.send_json_error(500, "Health check failed")
    
    def handle_metrics(self):
        """Handle metrics requests"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            metrics = {
                'total_scans': getattr(self.server, 'total_scans', 0),
                'active_scans': 1 if getattr(self.server, 'scan_status', {}).get('status') == 'running' else 0,
                'uptime': time.time() - getattr(self.server, 'start_time', time.time()),
                'memory_usage': self.get_memory_usage(),
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(metrics).encode())
        except Exception as e:
            logger.error(f"Error handling metrics: {e}")
            self.send_json_error(500, "Failed to get metrics")
    
    def get_memory_usage(self):
        """Get current memory usage"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return {
                'rss': process.memory_info().rss,
                'vms': process.memory_info().vms,
                'percent': process.memory_percent()
            }
        except ImportError:
            return {'error': 'psutil not available'}
        except Exception as e:
            return {'error': str(e)}
    
    def handle_scan_request(self):
        """Handle scan requests with enhanced validation"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 1024 * 1024:  # 1MB limit
                self.send_json_error(413, "Request too large")
                return
            
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            # Validate request data
            target = data.get('target', '').strip()
            if not target:
                self.send_json_error(400, "Target URL is required")
                return
            
            # Validate URL format
            if not self.is_valid_url(target):
                self.send_json_error(400, "Invalid URL format")
                return
            
            # Check if scan is already running
            current_status = getattr(self.server, 'scan_status', {}).get('status')
            if current_status == 'running':
                self.send_json_error(409, "Scan already in progress")
                return
            
            # Start scan in background
            self.start_background_scan(target)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                'message': 'Scan started successfully',
                'target': target,
                'scan_id': getattr(self.server, 'current_scan_id', 'unknown'),
                'timestamp': datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response).encode())
            
        except json.JSONDecodeError:
            self.send_json_error(400, "Invalid JSON format")
        except Exception as e:
            logger.error(f"Error handling scan request: {e}")
            self.send_json_error(500, "Failed to start scan")
    
    def is_valid_url(self, url):
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def start_background_scan(self, target):
        """Start scan in background thread"""
        def run_scan():
            try:
                # Initialize scanner
                scanner = ProductionVulnerabilityScanner(target)
                
                # Set up progress tracking
                def progress_callback(progress, message):
                    self.server.scan_status = {
                        'status': 'running',
                        'progress': progress,
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    }
                
                scanner.set_progress_callback(progress_callback)
                
                # Update server state
                self.server.scan_status = {
                    'status': 'running',
                    'progress': 0,
                    'message': 'Initializing scan...',
                    'timestamp': datetime.now().isoformat()
                }
                self.server.current_scan_id = f"scan_{int(time.time())}"
                
                # Run scan
                results = scanner.run_legacy_scans()
                
                # Save results
                filename = save_results_to_file(results)
                
                # Update status
                self.server.scan_status = {
                    'status': 'complete',
                    'progress': 100,
                    'message': 'Scan completed successfully',
                    'results': results,
                    'filename': filename,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Update metrics
                self.server.total_scans = getattr(self.server, 'total_scans', 0) + 1
                self.server.last_scan_results = results
                
                logger.info(f"Scan completed for {target}")
                
            except Exception as e:
                logger.error(f"Scan failed for {target}: {e}")
                self.server.scan_status = {
                    'status': 'error',
                    'progress': 0,
                    'message': f'Scan failed: {str(e)}',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
        
        # Start background thread
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
    
    def handle_generate_report(self):
        """Handle report generation requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            format_type = data.get('format', 'html')
            
            # Check if we have results
            results = getattr(self.server, 'last_scan_results', None)
            if not results:
                self.send_json_error(400, "No scan results available")
                return
            
            # Generate report filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.{format_type}"
            
            if format_type == 'html':
                self.generate_html_report(results, filename)
            elif format_type == 'json':
                self.generate_json_report(results, filename)
            else:
                self.send_json_error(400, "Unsupported format")
                return
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {
                'success': True,
                'message': 'Report generated successfully',
                'filename': filename,
                'download_url': f'/api/download/{filename}'
            }
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            self.send_json_error(500, "Failed to generate report")
    
    def generate_html_report(self, results, filename):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #333; color: white; padding: 20px; text-align: center; }}
                .summary {{ background: #f4f4f4; padding: 15px; margin: 20px 0; }}
                .result {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
                .error {{ border-left: 5px solid #f44336; }}
                .success {{ border-left: 5px solid #4CAF50; }}
                pre {{ background: #f5f5f5; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target:</strong> {results.get('target', 'Unknown')}</p>
                <p><strong>Scan ID:</strong> {results.get('scan_id', 'Unknown')}</p>
                <p><strong>Duration:</strong> {results.get('duration', 0):.2f} seconds</p>
            </div>
            
            <div class="results">
                <h2>Test Results</h2>
                {self.format_results_html(results)}
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def format_results_html(self, results):
        """Format results for HTML display"""
        html = ""
        tests = results.get('tests', {})
        
        if not tests:
            return "<p>No test results available</p>"
        
        for test_name, test_data in tests.items():
            status = test_data.get('status', 'unknown')
            status_class = 'success' if status == 'success' else 'error'
            
            html += f"""
            <div class="result {status_class}">
                <h3>{test_name.replace('_', ' ').title()}</h3>
                <p><strong>Status:</strong> {status}</p>
                <p><strong>Timestamp:</strong> {test_data.get('timestamp', 'N/A')}</p>
                {f'<p><strong>Error:</strong> {test_data.get("error", "")}</p>' if test_data.get('error') else ''}
                {f'<pre>{json.dumps(test_data.get("details", {}), indent=2)}</pre>' if test_data.get('details') else ''}
            </div>
            """
        
        return html
    
    def generate_json_report(self, results, filename):
        """Generate JSON report"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
    
    def handle_download(self):
        """Handle file download requests"""
        try:
            filename = self.path.split('/')[-1]
            
            if not os.path.exists(filename):
                self.send_error(404, "File not found")
                return
            
            # Determine content type
            if filename.endswith('.html'):
                content_type = 'text/html'
            elif filename.endswith('.json'):
                content_type = 'application/json'
            else:
                content_type = 'application/octet-stream'
            
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.end_headers()
            
            with open(filename, 'rb') as f:
                self.wfile.write(f.read())
                
        except Exception as e:
            logger.error(f"Error handling download: {e}")
            self.send_error(500, "Download failed")
    
    def handle_cancel_scan(self):
        """Handle scan cancellation requests"""
        try:
            current_status = getattr(self.server, 'scan_status', {}).get('status')
            
            if current_status == 'running':
                self.server.scan_status = {
                    'status': 'cancelled',
                    'progress': 0,
                    'message': 'Scan cancelled by user',
                    'timestamp': datetime.now().isoformat()
                }
                message = 'Scan cancelled successfully'
            else:
                message = 'No active scan to cancel'
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            response = {'message': message}
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logger.error(f"Error handling scan cancellation: {e}")
            self.send_json_error(500, "Failed to cancel scan")
    
    def send_json_error(self, status_code, message):
        """Send JSON error response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        error_response = {
            'error': message,
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(error_response).encode())

def create_directories():
    """Create necessary directories"""
    directories = ['templates', 'static', 'reports', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Created directory: {directory}")

def start_server(port=8080):
    """Start the enhanced web server"""
    logger.info(f"Starting enhanced vulnerability scanner web server on port {port}")
    
    # Create directories
    create_directories()
    
    # Create server
    with socketserver.TCPServer(("", port), EnhancedScanHandler) as httpd:
        # Initialize server attributes
        httpd.scan_status = {'status': 'idle'}
        httpd.start_time = time.time()
        httpd.total_scans = 0
        httpd.last_scan_results = None
        httpd.current_scan_id = None
        
        logger.info(f"Server running at http://localhost:{port}")
        logger.info("Enhanced features: Health checks, metrics, real-time progress, report generation")
        logger.info("Press Ctrl+C to stop the server")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            logger.info("Server shutdown complete")

if __name__ == "__main__":
    start_server()