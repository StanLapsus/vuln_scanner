# Vuln Scanner - Production-Grade Web Security Scanner

An advanced and powerful website vulnerability scanner with a modern monochrome web interface, enterprise-grade features, and production-ready architecture.

![Vuln Scanner UI](https://github.com/user-attachments/assets/290bf796-8873-403c-83ce-1ca3694f374a)

## 🚀 Key Features

### 🔍 **Advanced Scanning Capabilities**
1. **JavaScript Rendering**: Full SPA and dynamic content analysis using Playwright/Selenium
2. **DOM-based XSS Detection**: Client-side vulnerability assessment with context-aware payloads
3. **Advanced Port Scanning**: Comprehensive network scanning using nmap with service detection
4. **Subdomain Enumeration**: Multi-source subdomain discovery with intelligent filtering
5. **Content Discovery**: Hidden directory and file discovery with custom wordlists
6. **Security Headers Analysis**: Complete HTTP security headers evaluation
7. **CMS Detection**: Automated content management system identification
8. **Context-Aware Payloads**: Intelligent payload generation based on target analysis
9. **Multi-Protocol Testing**: Support for HTTP/HTTPS/FTP/file:// protocols
10. **Machine Learning Detection**: AI-powered anomaly detection and pattern recognition

### 🎨 **Modern User Interface**
- **Monochrome Design**: Clean black and white aesthetic with sophisticated styling
- **Fully Responsive**: Optimized for both desktop and mobile devices
- **WCAG Compliant**: Full accessibility support with ARIA labels and keyboard navigation
- **Real-time Progress**: Live scanning progress with visual feedback and notifications
- **Interactive Elements**: Hover effects, animations, and ripple effects
- **Keyboard Shortcuts**: Ctrl+Enter to scan, Escape to cancel
- **Toast Notifications**: Real-time user feedback system

### ⚡ **Performance & Architecture**
- **Smart Queuing**: Priority-based task scheduling with intelligent load balancing
- **Resource Monitoring**: Real-time system resource monitoring with auto-scaling
- **Intelligent Caching**: Compressed caching with TTL and LRU eviction
- **Concurrency Control**: Dynamic worker adjustment based on system resources
- **Rate Limiting**: Token bucket rate limiting for API protection
- **Memory Management**: Optimized memory usage with garbage collection

### 🏢 **Enterprise Features**
- **Multi-Format Reports**: HTML, PDF, JSON, XML, CSV report generation
- **CI/CD Integration**: JUnit and SARIF report formats for pipeline integration
- **User Management**: JWT-based authentication with role-based access control
- **API Rate Limiting**: Configurable rate limiting with client-based throttling
- **Audit Logging**: Comprehensive logging and monitoring capabilities
- **Multi-Tenant Ready**: Designed for public deployment with security measures

## 📋 **Vulnerability Detection**

### Web Application Vulnerabilities
- **Cross-Site Scripting (XSS)**: Reflected, Stored, and DOM-based XSS detection
- **SQL Injection**: Context-aware SQL injection testing with database-specific payloads
- **Command Injection**: Operating system command injection detection
- **Server-Side Request Forgery (SSRF)**: Internal service and metadata endpoint testing
- **XML External Entity (XXE)**: XML parsing vulnerability detection
- **Insecure Deserialization**: Multiple serialization format testing
- **Security Misconfigurations**: Comprehensive configuration analysis

### Network & Infrastructure
- **Port Scanning**: Advanced nmap-based scanning with service fingerprinting
- **SSL/TLS Analysis**: Certificate and protocol security assessment
- **HTTP Security Headers**: Complete security header evaluation
- **Directory Traversal**: Path traversal and file inclusion testing
- **Information Disclosure**: Sensitive data exposure detection

## 🛠 Installation

### Prerequisites
- Python 3.8 or higher
- Internet connection for external API calls
- Optional: Chrome/Chromium for JavaScript rendering

### Quick Start
```bash
git clone https://github.com/StanLapsus/vuln_scanner.git
cd vuln_scanner
pip install -r requirements.txt
python3 start.py --web
```

### Advanced Installation
```bash
# Install all dependencies including optional ones
pip install -r requirements.txt

# Install Playwright browsers (optional, for JavaScript rendering)
playwright install chromium

# Install additional tools for enhanced functionality
pip install reportlab weasyprint  # For PDF report generation
```

## 🚀 Usage

### Web Interface (Recommended)
```bash
# Start with default settings
python3 start.py --web

# Start on custom port
python3 start.py --web 9000

# Start with performance optimization
python3 start.py --web --optimize
```

### Command Line Interface
```bash
# Interactive CLI mode
python3 start.py --cli

# Direct scan
python3 scan.py --target https://example.com
```

### API Usage
```bash
# Start scan via API
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Check scan status
curl http://localhost:8080/api/scan_status

# Generate report
curl -X POST http://localhost:8080/api/generate_report \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'
```

## 📊 **Report Generation**

### Supported Formats
- **HTML**: Comprehensive visual reports with charts and graphs
- **PDF**: Professional reports for executives and compliance
- **JSON**: Machine-readable format for automation
- **XML**: Structured data for integration
- **CSV**: Tabular data for analysis
- **JUnit**: CI/CD pipeline integration
- **SARIF**: GitHub Security Tab integration

### Report Features
- **Executive Summary**: High-level overview with risk metrics
- **Technical Details**: Detailed vulnerability information with evidence
- **Remediation Guidance**: Specific recommendations for each finding
- **Compliance Mapping**: OWASP Top 10 and other framework alignment
- **Trend Analysis**: Historical comparison and progress tracking

## 🔧 **Configuration**

### Environment Variables
```bash
# Scanner Configuration
export VULN_SCANNER_WORKERS=10
export VULN_SCANNER_TIMEOUT=300
export VULN_SCANNER_RATE_LIMIT=100

# Security Configuration
export VULN_SCANNER_JWT_SECRET="your-secret-key"
export VULN_SCANNER_ADMIN_PASSWORD="secure-password"

# API Keys
export SHODAN_API_KEY="your-shodan-api-key"
export VIRUSTOTAL_API_KEY="your-virustotal-api-key"
```

### Advanced Configuration
```python
# config.py
SCANNER_CONFIG = {
    'max_workers': 20,
    'timeout': 300,
    'rate_limit': 100,
    'enable_javascript': True,
    'enable_ai_detection': True,
    'report_formats': ['html', 'json', 'pdf'],
    'user_management': True,
    'api_authentication': True
}
```

## 🏗 **Architecture**

### Core Components
```
vuln_scanner/
├── scan.py                 # Core scanning engine
├── advanced_scanner.py     # Advanced detection modules
├── performance_optimizer.py # Performance and resource management
├── enterprise_features.py  # Enterprise functionality
├── web_app.py             # Web server implementation
├── start.py               # Application launcher
├── requirements.txt       # Dependencies
├── templates/             # UI templates
│   └── index.html
├── static/               # Static assets
│   ├── style.css
│   └── app.js
└── tests/               # Test suites
    ├── test_advanced_scanner.py
    ├── test_enterprise_features.py
    └── test_performance.py
```

### Technology Stack
- **Backend**: Python 3.8+, Flask, asyncio
- **Frontend**: HTML5, CSS3, JavaScript ES6+
- **Rendering**: Playwright, Selenium WebDriver
- **Performance**: psutil, concurrent.futures
- **Security**: JWT, bcrypt, rate limiting
- **Reports**: Jinja2, ReportLab, WeasyPrint
- **Testing**: pytest, unittest, integration tests

## 🔒 **Security Considerations**

### Ethical Usage
⚠️ **Important**: Only scan websites you own or have explicit permission to test
- The scanner may trigger security alerts on target systems
- Some tests may be considered invasive by target systems
- Always comply with applicable laws and regulations
- Consider rate limiting for production use

### Production Deployment
```bash
# Enable security features
export VULN_SCANNER_SECURE_MODE=true
export VULN_SCANNER_HTTPS_ONLY=true
export VULN_SCANNER_CSRF_PROTECTION=true

# Configure rate limiting
export VULN_SCANNER_RATE_LIMIT=50
export VULN_SCANNER_RATE_WINDOW=3600

# Set up monitoring
export VULN_SCANNER_LOGGING_LEVEL=INFO
export VULN_SCANNER_METRICS_ENABLED=true
```

## 📈 **Performance Optimization**

### Resource Management
- **Dynamic Concurrency**: Automatically adjusts worker count based on system resources
- **Memory Optimization**: Intelligent garbage collection and memory monitoring
- **CPU Throttling**: Automatic throttling when CPU usage exceeds thresholds
- **Disk Space Management**: Automatic cleanup of temporary files and logs

### Caching Strategy
- **Intelligent Caching**: Compressed caching with TTL and LRU eviction
- **Cache Optimization**: Automatic cache size adjustment based on available memory
- **Cache Statistics**: Real-time cache hit rate and performance metrics

## 🔌 **CI/CD Integration**

### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Run Vuln Scanner
      run: |
        python3 start.py --cli --target ${{ github.event.repository.html_url }}
        # Upload SARIF results to GitHub Security tab
        python3 scripts/upload_sarif.py
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    sh 'python3 start.py --cli --target ${env.TARGET_URL}'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: 'security_report.html',
                        reportName: 'Security Report'
                    ])
                }
            }
        }
    }
}
```

## 🐛 **Troubleshooting**

### Common Issues

**"Module not found" errors**:
```bash
pip install -r requirements.txt
pip install --upgrade pip
```

**JavaScript rendering issues**:
```bash
# Install Playwright browsers
playwright install chromium

# Or use Selenium fallback
pip install selenium
```

**Permission denied for port scanning**:
```bash
# Run with appropriate permissions
sudo python3 start.py --web
# Or use alternative scanning methods
export VULN_SCANNER_SKIP_NMAP=true
```

**Memory issues with large scans**:
```bash
# Reduce worker count
export VULN_SCANNER_WORKERS=5
# Enable memory optimization
export VULN_SCANNER_MEMORY_LIMIT=1024
```

## 📝 **API Documentation**

### Scan Management
- `POST /api/scan` - Start new scan
- `GET /api/scan_status` - Check scan progress
- `GET /api/scan_results/{scan_id}` - Get scan results

### Report Generation
- `POST /api/generate_report` - Generate report in specified format
- `GET /api/download_report/{report_id}` - Download generated report

### Performance Monitoring
- `GET /api/performance_metrics` - Get system performance metrics
- `GET /api/cache_stats` - Get cache performance statistics

### User Management
- `POST /api/auth/login` - User authentication
- `POST /api/auth/register` - User registration
- `GET /api/auth/profile` - Get user profile

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/StanLapsus/vuln_scanner.git
cd vuln_scanner

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 .
black .
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Write comprehensive docstrings
- Include unit tests for new features

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- OWASP for security testing guidelines
- The Python security community
- Open source contributors and maintainers
- Security researchers and ethical hackers

## 📞 **Support**

- **Documentation**: [Wiki](https://github.com/StanLapsus/vuln_scanner/wiki)
- **Issues**: [GitHub Issues](https://github.com/StanLapsus/vuln_scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/StanLapsus/vuln_scanner/discussions)
- **Security**: [Security Policy](SECURITY.md)

---

**Vuln Scanner** - Production-Grade Web Security Testing Made Simple
