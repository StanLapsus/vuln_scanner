#!/usr/bin/env python3

"""
Production-Ready Web Application for Vulnerability Scanner
Enhanced with real-time capabilities, proper error handling, and professional features
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socketserver
import threading
import time
from datetime import datetime, timedelta
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

# Security logging configuration
security_logger = logging.getLogger('security')
security_handler = logging.FileHandler('security.log')
security_handler.setFormatter(logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s'))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

def log_security_event(event_type, message, client_ip=None, username=None):
    """Log security-related events"""
    context = []
    if client_ip:
        context.append(f"IP={client_ip}")
    if username:
        context.append(f"User={username}")
    
    context_str = f"[{', '.join(context)}]" if context else ""
    security_logger.warning(f"{event_type}: {message} {context_str}")

# Authentication configuration
AUTH_CONFIG = {
    'enabled': os.getenv('VULN_SCANNER_AUTH_ENABLED', 'true').lower() == 'true',
    'username': os.getenv('VULN_SCANNER_USERNAME', 'admin'),
    'password_hash': None,  # Will be set below
    'session_timeout': 3600,  # 1 hour in seconds
    'max_failed_attempts': 5,
    'lockout_duration': 900,  # 15 minutes in seconds
}

# Set password hash (SHA-256 of password)
default_password = os.getenv('VULN_SCANNER_PASSWORD', 'securepassword123')
AUTH_CONFIG['password_hash'] = hashlib.sha256(default_password.encode()).hexdigest()

# IP Whitelisting configuration
class IPWhitelisting:
    def __init__(self):
        self.enabled = os.getenv('VULN_SCANNER_IP_WHITELIST_ENABLED', 'false').lower() == 'true'
        self.whitelist = []
        
        if self.enabled:
            # Load whitelist from environment variable
            whitelist_env = os.getenv('VULN_SCANNER_IP_WHITELIST', '')
            if whitelist_env:
                self.whitelist = [ip.strip() for ip in whitelist_env.split(',') if ip.strip()]
            
            # Add localhost by default
            if not self.whitelist:
                self.whitelist = ['127.0.0.1', '::1', 'localhost']
            
            logger.info(f"IP whitelisting enabled with {len(self.whitelist)} allowed IPs")
    
    def is_allowed(self, client_ip):
        """Check if IP is whitelisted"""
        if not self.enabled:
            return True
        
        # Check exact match
        if client_ip in self.whitelist:
            return True
        
        # Check for localhost variations
        if client_ip in ['127.0.0.1', '::1', 'localhost']:
            return True
        
        # Check for private IP ranges if localhost is whitelisted
        if 'localhost' in self.whitelist or '127.0.0.1' in self.whitelist:
            import ipaddress
            try:
                ip = ipaddress.ip_address(client_ip)
                if ip.is_private or ip.is_loopback:
                    return True
            except ValueError:
                pass
        
        return False

# Global IP whitelist manager
ip_whitelist = IPWhitelisting()

# Session management
class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.failed_attempts = {}
        self.secret_key = secrets.token_hex(32)
    
    def create_session(self, username):
        """Create a new session for user"""
        session_id = secrets.token_hex(32)
        self.sessions[session_id] = {
            'username': username,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'ip_address': None  # Will be set by handler
        }
        return session_id
    
    def validate_session(self, session_id, client_ip):
        """Validate session and update activity"""
        if not session_id or session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        now = datetime.now()
        
        # Check if session expired
        if (now - session['last_activity']).seconds > AUTH_CONFIG['session_timeout']:
            del self.sessions[session_id]
            return False
        
        # Update last activity
        session['last_activity'] = now
        session['ip_address'] = client_ip
        return True
    
    def destroy_session(self, session_id):
        """Destroy session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def is_ip_locked(self, ip_address):
        """Check if IP is locked due to failed attempts"""
        if ip_address not in self.failed_attempts:
            return False
        
        attempt_info = self.failed_attempts[ip_address]
        if attempt_info['count'] >= AUTH_CONFIG['max_failed_attempts']:
            lockout_time = attempt_info['last_attempt'] + timedelta(seconds=AUTH_CONFIG['lockout_duration'])
            if datetime.now() < lockout_time:
                return True
            else:
                # Lockout expired, reset attempts
                del self.failed_attempts[ip_address]
        
        return False
    
    def record_failed_attempt(self, ip_address):
        """Record failed login attempt"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {'count': 0, 'last_attempt': datetime.now()}
        
        self.failed_attempts[ip_address]['count'] += 1
        self.failed_attempts[ip_address]['last_attempt'] = datetime.now()
    
    def reset_failed_attempts(self, ip_address):
        """Reset failed attempts after successful login"""
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def generate_csrf_token(self, session_id):
        """Generate CSRF token for session"""
        if session_id not in self.sessions:
            return None
        
        # Generate CSRF token tied to session
        token_data = f"{session_id}:{self.secret_key}:{datetime.now().timestamp()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Store token in session
        self.sessions[session_id]['csrf_token'] = token
        return token
    
    def validate_csrf_token(self, session_id, provided_token):
        """Validate CSRF token"""
        if not session_id or session_id not in self.sessions:
            return False
            
        session_token = self.sessions[session_id].get('csrf_token')
        if not session_token:
            return False
            
        return hmac.compare_digest(session_token, provided_token)

# Global session manager
session_manager = SessionManager() if AUTH_CONFIG['enabled'] else None

# Rate limiting implementation
class RateLimiter:
    def __init__(self, requests_per_minute=60):
        self.requests_per_minute = requests_per_minute
        self.requests = {}
        self.cleanup_interval = 60  # seconds
        self.last_cleanup = time.time()
    
    def is_allowed(self, client_ip):
        """Check if request is allowed based on rate limiting"""
        current_time = time.time()
        
        # Cleanup old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Get or create request list for this IP
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Remove requests older than 1 minute
        minute_ago = current_time - 60
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip] 
            if req_time > minute_ago
        ]
        
        # Check if under limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return False
        
        # Add current request
        self.requests[client_ip].append(current_time)
        return True
    
    def _cleanup_old_entries(self, current_time):
        """Remove old entries to prevent memory growth"""
        minute_ago = current_time - 60
        for ip in list(self.requests.keys()):
            self.requests[ip] = [
                req_time for req_time in self.requests[ip]
                if req_time > minute_ago
            ]
            if not self.requests[ip]:
                del self.requests[ip]

# Global rate limiter instance
rate_limiter = RateLimiter(requests_per_minute=30)  # 30 requests per minute per IP

class EnhancedScanHandler(SimpleHTTPRequestHandler):
    """Enhanced HTTP request handler with production features"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
    def log_message(self, format, *args):
        """Override to use our logger with security context and prevent log injection"""
        client_ip = self.address_string()
        # Security: Sanitize log message to prevent log injection
        sanitized_args = []
        for arg in args:
            if isinstance(arg, str):
                # Remove potentially dangerous characters
                sanitized = arg.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                sanitized = ''.join(c for c in sanitized if ord(c) >= 32 or c in '\n\r\t')
                sanitized_args.append(sanitized)
            else:
                sanitized_args.append(arg)
        
        try:
            message = format % tuple(sanitized_args)
            logger.info(f"{client_ip} - {message}")
        except Exception as e:
            logger.error(f"Log formatting error: {e}")
    
    def _safe_log_error(self, message, *args):
        """Safe logging method that prevents injection"""
        sanitized_message = str(message).replace('\n', '\\n').replace('\r', '\\r')
        sanitized_args = [str(arg).replace('\n', '\\n').replace('\r', '\\r') for arg in args]
        try:
            logger.error(sanitized_message % tuple(sanitized_args))
        except Exception:
            logger.error(f"Error logging message: {sanitized_message}")
    
    def _check_ip_whitelist(self):
        """Check if client IP is whitelisted"""
        client_ip = self.address_string()
        if not ip_whitelist.is_allowed(client_ip):
            log_security_event("ACCESS_DENIED", f"Non-whitelisted IP access attempt", client_ip)
            self.send_error(403, "Access denied")
            return False
        return True
    
    def _validate_user_agent(self):
        """Validate user agent for suspicious patterns"""
        user_agent = self.headers.get('User-Agent', '')
        client_ip = self.address_string()
        
        # Check for empty user agent
        if not user_agent:
            log_security_event("SUSPICIOUS_REQUEST", "Empty User-Agent header", client_ip)
            return True  # Allow but log
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'sqlmap', 'nikto', 'dirb', 'gobuster', 'wpscan', 'nmap',
            'burp', 'zap', 'w3af', 'masscan', 'nuclei', 'httpx',
            'bot', 'crawler', 'spider', 'scraper'
        ]
        
        user_agent_lower = user_agent.lower()
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                log_security_event("SUSPICIOUS_USER_AGENT", f"Detected pattern '{pattern}' in User-Agent: {user_agent}", client_ip)
                # Don't block, just log for now
                break
        
        return True
    
    def _check_authentication(self):
        """Check if request is authenticated"""
        if not AUTH_CONFIG['enabled']:
            return True
        
        # Check if IP is locked
        client_ip = self.address_string()
        if session_manager.is_ip_locked(client_ip):
            self.send_error(423, "Account locked due to too many failed attempts")
            return False
        
        # Check for session cookie
        cookie_header = self.headers.get('Cookie', '')
        session_id = None
        
        if cookie_header:
            cookies = {}
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies[key] = value
            session_id = cookies.get('session_id')
        
        if session_id and session_manager.validate_session(session_id, client_ip):
            return True
        
        # Not authenticated, send login page or error
        if self.path == '/login' or self.path.startswith('/static/'):
            return True  # Allow access to login page and static files
        
        self.send_error(401, "Authentication required")
        return False
    
    def _authenticate_user(self, username, password):
        """Authenticate user credentials"""
        if not AUTH_CONFIG['enabled']:
            return True
        
        # Check credentials
        if username != AUTH_CONFIG['username']:
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == AUTH_CONFIG['password_hash']
    
    def _get_session_id(self):
        """Extract session ID from cookies"""
        cookie_header = self.headers.get('Cookie', '')
        if not cookie_header:
            return None
            
        cookies = {}
        for cookie in cookie_header.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
        
        return cookies.get('session_id')
    
    def _validate_csrf_token(self, provided_token):
        """Validate CSRF token for state-changing requests"""
        if not AUTH_CONFIG['enabled'] or not session_manager:
            return True
            
        session_id = self._get_session_id()
        if not session_id:
            return False
            
        return session_manager.validate_csrf_token(session_id, provided_token)
        
    def _check_rate_limit(self):
        """Check if request should be rate limited"""
        client_ip = self.address_string()
        if not rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            self.send_error(429, "Too Many Requests")
            return False
        return True
    
    def _validate_request_size(self):
        """Validate request size to prevent DoS attacks"""
        content_length = self.headers.get('Content-Length')
        if content_length:
            try:
                length = int(content_length)
                if length > 1024 * 1024:  # 1MB limit
                    self.send_error(413, "Request Entity Too Large")
                    return False
            except ValueError:
                self.send_error(400, "Invalid Content-Length")
                return False
        return True
    
    def do_GET(self):
        """Handle GET requests with enhanced routing and security"""
        try:
            if not self._check_ip_whitelist():
                return
            
            if not self._validate_user_agent():
                return
                
            if not self._check_rate_limit():
                return
            
            if not self._check_authentication():
                return
                
            if self.path == '/':
                self.serve_template('index.html')
            elif self.path == '/login':
                self.serve_login_page()
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
        """Handle POST requests with enhanced routing and security"""
        try:
            if not self._check_ip_whitelist():
                return
            
            if not self._validate_user_agent():
                return
                
            if not self._check_rate_limit():
                return
                
            if not self._validate_request_size():
                return
            
            # Handle login separately (doesn't need authentication)
            if self.path == '/api/login':
                self.handle_login()
                return
            
            # Check authentication for other endpoints
            if not self._check_authentication():
                return
                
            # Security: Validate Content-Type for POST requests
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('application/json'):
                self.send_error(415, "Unsupported Media Type")
                return
                
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
    
    def send_security_headers(self):
        """Add security headers to all responses"""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    
    def serve_template(self, template_name):
        """Serve HTML template with error handling and security headers"""
        try:
            template_path = os.path.join('templates', template_name)
            # Security: Prevent path traversal in template names
            if '..' in template_name or '/' in template_name:
                self.send_error(403, "Access denied")
                return
                
            if os.path.exists(template_path):
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.send_security_headers()
                self.end_headers()
                with open(template_path, 'r', encoding='utf-8') as f:
                    self.wfile.write(f.read().encode('utf-8'))
            else:
                # Security: Don't reveal specific file paths
                self.send_error(404, "Page not found")
        except Exception as e:
            # Security: Don't reveal internal error details
            self._safe_log_error(f"Error serving template {template_name}: {e}")
            self.send_error(500, "Internal Server Error")
    
    def serve_static_file(self):
        """Serve static files with proper MIME types and security"""
        try:
            # Extract requested file path and normalize it
            requested_path = self.path[1:]  # Remove leading slash
            
            # Security: Prevent directory traversal attacks
            # Only allow files from static directory and prevent path traversal
            if not requested_path.startswith('static/'):
                self.send_error(403, "Access denied")
                return
                
            # Normalize path to prevent directory traversal
            normalized_path = os.path.normpath(requested_path)
            
            # Additional security check: ensure the normalized path still starts with static/
            if not normalized_path.startswith('static/'):
                self.send_error(403, "Access denied")
                return
                
            # Check if file exists and is actually a file (not directory)
            if os.path.exists(normalized_path) and os.path.isfile(normalized_path):
                # Security: Restrict file extensions to prevent serving sensitive files
                allowed_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.ico', '.gif', '.svg'}
                file_ext = os.path.splitext(normalized_path)[1].lower()
                
                if file_ext not in allowed_extensions:
                    self.send_error(403, "File type not allowed")
                    return
                
                # Determine MIME type
                if file_ext == '.css':
                    content_type = 'text/css'
                elif file_ext == '.js':
                    content_type = 'application/javascript'
                elif file_ext == '.png':
                    content_type = 'image/png'
                elif file_ext in ['.jpg', '.jpeg']:
                    content_type = 'image/jpeg'
                elif file_ext == '.ico':
                    content_type = 'image/x-icon'
                elif file_ext == '.gif':
                    content_type = 'image/gif'
                elif file_ext == '.svg':
                    content_type = 'image/svg+xml'
                else:
                    content_type = 'text/plain'
                
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.send_header('Cache-Control', 'public, max-age=3600')
                # Security headers
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                
                mode = 'rb' if content_type.startswith('image/') else 'r'
                encoding = None if mode == 'rb' else 'utf-8'
                
                # Security: Limit file size to prevent DoS
                max_file_size = 10 * 1024 * 1024  # 10MB limit
                try:
                    file_size = os.path.getsize(normalized_path)
                    if file_size > max_file_size:
                        self.send_error(413, "File too large")
                        return
                except OSError:
                    self.send_error(404, "File not found")
                    return
                
                with open(normalized_path, mode, encoding=encoding) as f:
                    content = f.read()
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    self.wfile.write(content)
            else:
                self.send_error(404, "File not found")
        except Exception as e:
            # Security: Don't reveal internal paths or errors
            self._safe_log_error(f"Error serving static file {self.path}: {e}")
            self.send_error(500, "Internal Server Error")
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
        """Handle scan requests with enhanced validation and security"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 1024 * 1024:  # 1MB limit
                self.send_json_error(413, "Request too large")
                return
            
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # Security: Validate JSON structure
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError as e:
                self.send_json_error(400, "Invalid JSON format")
                return
            
            # Security: Validate required fields and types
            if not isinstance(data, dict):
                self.send_json_error(400, "Request must be a JSON object")
                return
            
            # Security: Validate CSRF token for state-changing requests
            csrf_token = data.get('csrf_token')
            if not self._validate_csrf_token(csrf_token):
                self.send_json_error(403, "Invalid CSRF token")
                return
            
            target = data.get('target', '').strip()
            if not target:
                self.send_json_error(400, "Target URL is required")
                return
            
            # Security: Additional input validation
            if not isinstance(target, str):
                self.send_json_error(400, "Target must be a string")
                return
                
            if len(target) > 2048:
                self.send_json_error(400, "Target URL too long")
                return
            
            # Validate URL format with enhanced security
            if not self.is_valid_url(target):
                self.send_json_error(400, "Invalid URL format")
                return
            
            # Security: Check for suspicious patterns in target
            suspicious_patterns = ['file://', 'ftp://', 'javascript:', 'data:', 'vbscript:']
            target_lower = target.lower()
            if any(pattern in target_lower for pattern in suspicious_patterns):
                self.send_json_error(400, "Unsupported URL scheme")
                return
            
            # Check if scan is already running
            current_status = getattr(self.server, 'scan_status', {}).get('status')
            if current_status == 'running':
                self.send_json_error(409, "Scan already in progress")
                return
            
            # Security: Log scan request for audit
            client_ip = self.address_string()
            logger.info(f"Scan requested by {client_ip} for target: {target}")
            
            # Start scan in background
            self.start_background_scan(target)
            
            # Send response with security headers
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_security_headers()
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
        self.send_security_headers()
        self.end_headers()
        
        error_response = {
            'error': message,
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(error_response).encode())
    
    def serve_login_page(self):
        """Serve login page"""
        try:
            login_html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>VulnScanner Login</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 50px; background: #f5f5f5; }
                    .login-container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .form-group { margin-bottom: 20px; }
                    label { display: block; margin-bottom: 5px; font-weight: bold; }
                    input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 3px; }
                    button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; width: 100%; }
                    button:hover { background: #0056b3; }
                    .error { color: red; margin-top: 10px; }
                </style>
            </head>
            <body>
                <div class="login-container">
                    <h2>VulnScanner Login</h2>
                    <form id="loginForm">
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit">Login</button>
                        <div id="error" class="error"></div>
                    </form>
                </div>
                <script>
                    document.getElementById('loginForm').addEventListener('submit', function(e) {
                        e.preventDefault();
                        const username = document.getElementById('username').value;
                        const password = document.getElementById('password').value;
                        
                        fetch('/api/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username, password })
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                window.location.href = '/';
                            } else {
                                document.getElementById('error').textContent = data.error || 'Login failed';
                            }
                        })
                        .catch(error => {
                            document.getElementById('error').textContent = 'Login failed';
                        });
                    });
                </script>
            </body>
            </html>
            """
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(login_html.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error serving login page: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_login(self):
        """Handle login requests"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_json_error(400, "Invalid JSON format")
                return
            
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            if not username or not password:
                self.send_json_error(400, "Username and password required")
                return
            
            client_ip = self.address_string()
            
            # Check if IP is locked
            if session_manager and session_manager.is_ip_locked(client_ip):
                self.send_json_error(423, "Account locked due to too many failed attempts")
                return
            
            # Authenticate user
            if self._authenticate_user(username, password):
                # Success - create session
                session_id = session_manager.create_session(username) if session_manager else None
                if session_manager:
                    session_manager.reset_failed_attempts(client_ip)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                if session_id:
                    self.send_header('Set-Cookie', f'session_id={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/')
                self.send_security_headers()
                self.end_headers()
                
                response = {'success': True, 'message': 'Login successful'}
                self.wfile.write(json.dumps(response).encode())
                
                logger.info(f"Successful login for user {username} from {client_ip}")
                
            else:
                # Failed authentication
                if session_manager:
                    session_manager.record_failed_attempt(client_ip)
                self.send_json_error(401, "Invalid credentials")
                logger.warning(f"Failed login attempt for user {username} from {client_ip}")
                
        except Exception as e:
            logger.error(f"Error handling login: {e}")
            self.send_json_error(500, "Login failed")

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