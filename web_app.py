#!/usr/bin/env python3

import json
import urllib.parse
import socketserver
import http.server
import threading
import os
import time
from scan import UltimateAdvancedWebScanner, save_results_to_file
from performance_optimizer import PerformanceOptimizer, ScanTask
from enterprise_features import ReportGenerator, UserManager, CIPipeline, RateLimiter

# Global instances
performance_optimizer = PerformanceOptimizer(max_workers=5)
report_generator = ReportGenerator()
user_manager = UserManager()
ci_pipeline = CIPipeline()
rate_limiter = RateLimiter(max_requests=50, window_seconds=3600)  # 50 requests per hour

class ScanHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('templates/index.html', 'r') as f:
                content = f.read()
            self.wfile.write(content.encode())
        elif self.path == '/api/scan_status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Check if scan is running
            status = getattr(self.server, 'scan_status', {'status': 'idle'})
            self.wfile.write(json.dumps(status).encode())
        elif self.path == '/api/performance_metrics':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Get performance metrics
            metrics = performance_optimizer.get_performance_metrics()
            self.wfile.write(json.dumps(metrics).encode())
        elif self.path == '/api/generate_report':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            # Generate report endpoint
            scan_results = getattr(self.server, 'last_scan_results', {})
            if scan_results:
                try:
                    report_path = report_generator.generate_report(scan_results, 'html')
                    self.wfile.write(json.dumps({
                        'success': True,
                        'report_path': report_path,
                        'message': 'Report generated successfully'
                    }).encode())
                except Exception as e:
                    self.wfile.write(json.dumps({
                        'success': False,
                        'error': str(e)
                    }).encode())
            else:
                self.wfile.write(json.dumps({
                    'success': False,
                    'error': 'No scan results available'
                }).encode())
        elif self.path.startswith('/api/download_report/'):
            # Download report endpoint
            report_filename = self.path.split('/')[-1]
            report_path = f"/tmp/{report_filename}"
            
            if os.path.exists(report_path):
                self.send_response(200)
                
                # Determine content type based on file extension
                if report_path.endswith('.html'):
                    self.send_header('Content-type', 'text/html')
                    self.send_header('Content-Disposition', f'attachment; filename="{report_filename}"')
                elif report_path.endswith('.pdf'):
                    self.send_header('Content-type', 'application/pdf')
                    self.send_header('Content-Disposition', f'attachment; filename="{report_filename}"')
                elif report_path.endswith('.json'):
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Content-Disposition', f'attachment; filename="{report_filename}"')
                else:
                    self.send_header('Content-type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename="{report_filename}"')
                
                self.end_headers()
                
                with open(report_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Report not found")
        elif self.path.startswith('/static/'):
            # Serve static files
            filepath = self.path[1:]  # Remove leading slash
            if os.path.exists(filepath):
                if filepath.endswith('.css'):
                    self.send_response(200)
                    self.send_header('Content-type', 'text/css')
                    self.end_headers()
                elif filepath.endswith('.js'):
                    self.send_response(200)
                    self.send_header('Content-type', 'application/javascript')
                    self.end_headers()
                else:
                    super().do_GET()
                    return
                with open(filepath, 'r') as f:
                    self.wfile.write(f.read().encode())
            else:
                self.send_error(404)
        else:
            self.send_error(404)
    
    def do_POST(self):
        # Rate limiting
        client_ip = self.client_address[0]
        if not rate_limiter.is_allowed(client_ip):
            self.send_response(429)  # Too Many Requests
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'error': 'Rate limit exceeded. Please try again later.'
            }).encode())
            return
        
        if self.path == '/api/scan':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            target = data.get('target', '')
            if not target:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Target URL required'}).encode())
                return
            
            # Start scan using performance optimizer
            def run_scan():
                try:
                    self.server.scan_status = {'status': 'running', 'progress': 0}
                    
                    # Create optimized scan task
                    task = ScanTask(
                        task_id=f"scan_{int(time.time())}",
                        target_url=target,
                        scan_type="comprehensive",
                        priority=8,  # High priority
                        timeout=600  # 10 minutes
                    )
                    
                    # Add to queue
                    performance_optimizer.smart_queue.enqueue(task)
                    
                    # Process with optimization
                    self.server.scan_status = {'status': 'running', 'progress': 25}
                    
                    def optimized_scan_handler(scan_task):
                        scanner = UltimateAdvancedWebScanner(scan_task.target_url)
                        
                        # Run async scan with optimization
                        import asyncio
                        
                        # Create new event loop for thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        
                        try:
                            # Update progress
                            self.server.scan_status = {'status': 'running', 'progress': 50}
                            
                            # Execute scan with performance optimization
                            results = performance_optimizer.execute_with_optimization(
                                loop.run_until_complete,
                                scanner.scan_website()
                            )
                            
                            return results
                        finally:
                            loop.close()
                    
                    # Execute optimized scan
                    results = optimized_scan_handler(task)
                    
                    self.server.scan_status = {'status': 'running', 'progress': 90}
                    
                    filename = save_results_to_file(results)
                    
                    # Mark task as completed
                    performance_optimizer.smart_queue.mark_completed(task.task_id, results)
                    
                    # Store results for report generation
                    self.server.last_scan_results = results
                    
                    self.server.scan_status = {
                        'status': 'complete', 
                        'progress': 100,
                        'results': results,
                        'filename': filename,
                        'performance_metrics': performance_optimizer.get_performance_metrics()
                    }
                    
                except Exception as e:
                    # Mark task as failed
                    if 'task' in locals():
                        performance_optimizer.smart_queue.mark_failed(task.task_id, e)
                    
                    self.server.scan_status = {
                        'status': 'error',
                        'error': str(e)
                    }
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': 'Scan started'}).encode())
        else:
            self.send_error(404)

def create_directories():
    """Create necessary directories if they don't exist"""
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

def start_server(port=8080):
    create_directories()
    
    with socketserver.TCPServer(("", port), ScanHandler) as httpd:
        httpd.scan_status = {'status': 'idle'}
        print(f"Server running at http://localhost:{port}")
        print("Press Ctrl+C to stop the server")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")

if __name__ == "__main__":
    start_server()