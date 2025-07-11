# Vuln Scanner

An advanced and powerful website vulnerability scanner with a modern dark mode web interface.

![Vuln Scanner UI](https://github.com/user-attachments/assets/d91226bf-a7ff-49be-b70a-6ba36a93533f)

## Features

### 🔍 **Advanced Scanning Capabilities**
1. **Advanced Port Scan**: Comprehensive network scanning using nmap
2. **Subdomain Enumeration**: Discovers subdomains using multiple sources  
3. **Advanced Content Discovery**: Discovers hidden paths and directories
4. **Security Headers Analysis**: Analyzes HTTP headers for security configurations
5. **CMS Detection**: Detects common CMS platforms
6. **Advanced XSS Testing**: Tests for XSS vulnerabilities with multiple payloads
7. **Command Injection Testing**: Tests for command injection vulnerabilities
8. **Misconfiguration Detection**: Checks for common misconfigurations
9. **Exploit Check**: Uses searchsploit to check for known vulnerabilities
10. **Shodan Integration**: Retrieves additional information from Shodan
11. **Anomaly Detection**: Detects unusual patterns or headers
12. **Machine Learning-Based Detection**: Uses text analysis and clustering to detect anomalies
13. **DNS Lookup**: Retrieves DNS information
14. **WHOIS Lookup**: Provides WHOIS information
15. **SSRF Testing**: Checks for server-side request forgery vulnerabilities
16. **Protocol-Level Vulnerability Testing**: Tests for vulnerabilities at the network protocol level

### 🌐 **Modern Web Interface**
- **Dark Mode Design**: Minimalistic yet advanced dark theme
- **Real-time Progress**: Live scanning progress with visual feedback
- **Interactive Results**: Organized results display with status indicators
- **Export Functionality**: Download scan results as JSON
- **Responsive Design**: Works on desktop and mobile devices
- **Smooth Animations**: Modern CSS animations and transitions

## Installation

### Prerequisites
- Python 3.7 or higher
- Internet connection for external API calls

### Dependencies
Install required dependencies:
```bash
pip install -r requirements.txt
```

### Optional Dependencies
For full functionality, install optional dependencies:
```bash
# For advanced port scanning
pip install python-nmap

# For protocol-level testing  
pip install scapy

# For machine learning detection
pip install scikit-learn

# For Shodan integration
pip install shodan
```

## Usage

The scanner offers two modes of operation:

### 🌐 Web Interface (Recommended)
Start the web interface:
```bash
python3 start.py --web
```

Or specify a custom port:
```bash
python3 start.py --web 9000
```

Then open your browser and navigate to:
- `http://localhost:8080` (default)
- `http://localhost:9000` (custom port)

### 💻 Command Line Interface
Run in CLI mode:
```bash
python3 start.py --cli
```

### 📋 Help
View available options:
```bash
python3 start.py --help
```

## Web Interface Features

### 🎨 Dark Mode Design
- Modern dark theme with green accent colors
- Minimalistic layout focusing on functionality
- Smooth hover effects and animations
- Professional typography using JetBrains Mono font

### 📊 Real-time Scanning
- Live progress bar showing scan completion
- Status updates during scanning process
- Automatic result refresh when scan completes

### 📄 Results Display
- Color-coded status indicators:
  - 🟢 **Complete**: Scan finished successfully
  - 🟡 **Found**: Potential vulnerabilities detected
  - 🔴 **Error**: Issues during scanning
- Organized grid layout for easy result review
- Expandable result details

### 💾 Export Functionality
- Download complete scan results as JSON
- Timestamped filenames for organization
- Structured data format for further analysis

## File Structure

```
vuln_scanner/
├── scan.py              # Core scanning engine
├── web_app.py           # Web server implementation
├── start.py             # Main application launcher
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html      # Web interface template
├── static/
│   ├── style.css       # Dark mode CSS styling
│   └── app.js          # Frontend JavaScript
└── README.md           # This file
```

## Configuration

### Shodan API Key
To use Shodan integration, update the API key in `scan.py`:
```python
api_key = "your_shodan_api_key"
```

### Scan Timeouts
Adjust timeouts in the scanner configuration:
```python
# In scan.py, modify timeout values
response = requests.get(url, verify=False, timeout=5)
```

## Security Considerations

⚠️ **Important Security Notes**:
- Only scan websites you own or have explicit permission to test
- The scanner may trigger security alerts on target systems
- Some tests may be considered invasive by target systems
- Always comply with applicable laws and regulations
- Consider rate limiting for production use

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the terms specified in the LICENSE file.

## Troubleshooting

### Common Issues

**"Module not found" errors**:
```bash
pip install -r requirements.txt
```

**Permission denied for port scanning**:
- Run with appropriate permissions or use alternative ports
- Some features require root/administrator privileges

**Network connectivity issues**:
- Ensure internet connectivity for external API calls
- Check firewall settings for outbound connections

**Browser compatibility**:
- Use modern browsers (Chrome, Firefox, Safari, Edge)
- Enable JavaScript for full functionality

## Changelog

### Latest Version
- ✨ Added modern dark mode web interface
- 🚀 Implemented real-time scanning progress
- 📊 Enhanced results display with status indicators
- 💾 Added JSON export functionality
- 🎨 Improved responsive design
- 🔧 Fixed missing imports and dependencies
- 📝 Added comprehensive documentation

---

**Vuln Scanner** - Advanced Web Security Testing Made Simple
