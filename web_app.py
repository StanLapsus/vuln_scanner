#!/usr/bin/env python3

import json
import urllib.parse
import socketserver
import http.server
import threading
import os
import time
from scan import UltimateAdvancedWebScanner, save_results_to_file

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
            
            # Start scan in background thread
            def run_scan():
                try:
                    self.server.scan_status = {'status': 'running', 'progress': 0}
                    scanner = UltimateAdvancedWebScanner(target)
                    
                    # Update progress
                    self.server.scan_status = {'status': 'running', 'progress': 50}
                    
                    results = scanner.scan_website()
                    filename = save_results_to_file(results)
                    
                    self.server.scan_status = {
                        'status': 'complete', 
                        'progress': 100,
                        'results': results,
                        'filename': filename
                    }
                except Exception as e:
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