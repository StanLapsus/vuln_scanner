#!/usr/bin/env python3
"""
Enterprise Features Module
Report generation, user management, CI/CD integration, and deployment readiness
"""

import json
import html
import time
import os
import tempfile
import subprocess
import hashlib
import jwt
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from jinja2 import Template
import secrets
import logging

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import reportlab
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

@dataclass
class VulnerabilityReport:
    """Structured vulnerability report"""
    scan_id: str
    target_url: str
    scan_date: datetime
    scan_duration: float
    vulnerabilities: List[Dict[str, Any]]
    summary: Dict[str, Any]
    recommendations: List[str]
    scan_metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'scan_date': self.scan_date.isoformat(),
            'scan_duration': self.scan_duration,
            'vulnerabilities': self.vulnerabilities,
            'summary': self.summary,
            'recommendations': self.recommendations,
            'scan_metadata': self.scan_metadata
        }

class ReportGenerator:
    """Advanced report generation with multiple formats"""
    
    def __init__(self):
        self.templates = {
            'html': self._get_html_template(),
            'executive': self._get_executive_template(),
            'technical': self._get_technical_template()
        }
    
    def generate_report(self, results: Dict[str, Any], format_type: str = 'html', 
                       report_type: str = 'comprehensive') -> str:
        """Generate report in specified format"""
        
        # Process results into structured format
        report_data = self._process_results(results)
        
        if format_type.lower() == 'html':
            return self._generate_html_report(report_data, report_type)
        elif format_type.lower() == 'pdf':
            return self._generate_pdf_report(report_data, report_type)
        elif format_type.lower() == 'json':
            return self._generate_json_report(report_data)
        elif format_type.lower() == 'xml':
            return self._generate_xml_report(report_data)
        elif format_type.lower() == 'csv':
            return self._generate_csv_report(report_data)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _process_results(self, results: Dict[str, Any]) -> VulnerabilityReport:
        """Process raw scan results into structured report"""
        vulnerabilities = []
        summary = {
            'total_tests': 0,
            'vulnerabilities_found': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'info_findings': 0
        }
        
        for test_name, result in results.items():
            summary['total_tests'] += 1
            
            if isinstance(result, dict):
                # Handle structured results
                vuln_data = {
                    'test_name': test_name,
                    'status': result.get('status', 'unknown'),
                    'result': result.get('result', ''),
                    'confidence': result.get('confidence', 0.0),
                    'evidence': result.get('evidence', []),
                    'recommendations': result.get('recommendations', []),
                    'cvss_score': result.get('cvss_score', 0.0),
                    'severity': self._calculate_severity(result.get('cvss_score', 0.0))
                }
                
                if result.get('status') == 'warning':
                    summary['vulnerabilities_found'] += 1
                    if vuln_data['severity'] == 'high':
                        summary['high_severity'] += 1
                    elif vuln_data['severity'] == 'medium':
                        summary['medium_severity'] += 1
                    else:
                        summary['low_severity'] += 1
                else:
                    summary['info_findings'] += 1
                
                vulnerabilities.append(vuln_data)
            else:
                # Handle simple string results
                vuln_data = {
                    'test_name': test_name,
                    'status': 'info',
                    'result': str(result),
                    'confidence': 0.5,
                    'evidence': [],
                    'recommendations': [],
                    'cvss_score': 0.0,
                    'severity': 'info'
                }
                summary['info_findings'] += 1
                vulnerabilities.append(vuln_data)
        
        return VulnerabilityReport(
            scan_id=str(uuid.uuid4()),
            target_url=results.get('target_url', 'Unknown'),
            scan_date=datetime.now(),
            scan_duration=results.get('scan_duration', 0.0),
            vulnerabilities=vulnerabilities,
            summary=summary,
            recommendations=self._generate_recommendations(vulnerabilities),
            scan_metadata=results.get('metadata', {})
        )
    
    def _calculate_severity(self, cvss_score: float) -> str:
        """Calculate severity based on CVSS score"""
        if cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0.0:
            return 'low'
        else:
            return 'info'
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate general recommendations based on findings"""
        recommendations = []
        
        # Security headers recommendations
        if any('security_headers' in vuln['test_name'].lower() for vuln in vulnerabilities):
            recommendations.append("Implement comprehensive security headers (CSP, HSTS, X-Frame-Options)")
        
        # XSS recommendations
        if any('xss' in vuln['test_name'].lower() for vuln in vulnerabilities):
            recommendations.append("Implement input validation and output encoding to prevent XSS")
        
        # SQL injection recommendations
        if any('sql' in vuln['test_name'].lower() for vuln in vulnerabilities):
            recommendations.append("Use parameterized queries and input validation to prevent SQL injection")
        
        # General recommendations
        recommendations.extend([
            "Regularly update all software components and dependencies",
            "Implement a Web Application Firewall (WAF)",
            "Conduct regular security assessments and penetration testing",
            "Train developers on secure coding practices",
            "Implement proper logging and monitoring"
        ])
        
        return recommendations
    
    def _generate_html_report(self, report_data: VulnerabilityReport, report_type: str) -> str:
        """Generate HTML report"""
        template = Template(self.templates['html'])
        
        return template.render(
            report=report_data,
            report_type=report_type,
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    def _generate_pdf_report(self, report_data: VulnerabilityReport, report_type: str) -> str:
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE and not WEASYPRINT_AVAILABLE:
            raise ImportError("PDF generation requires reportlab or weasyprint")
        
        # First generate HTML
        html_content = self._generate_html_report(report_data, report_type)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as temp_html:
            temp_html.write(html_content)
            temp_html_path = temp_html.name
        
        try:
            # Generate PDF using weasyprint if available
            if WEASYPRINT_AVAILABLE:
                pdf_path = temp_html_path.replace('.html', '.pdf')
                weasyprint.HTML(temp_html_path).write_pdf(pdf_path)
                return pdf_path
            else:
                # Fallback to reportlab
                return self._generate_pdf_with_reportlab(report_data)
        finally:
            os.unlink(temp_html_path)
    
    def _generate_pdf_with_reportlab(self, report_data: VulnerabilityReport) -> str:
        """Generate PDF using reportlab"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_pdf:
            pdf_path = temp_pdf.name
        
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1  # Center
        )
        story.append(Paragraph("Vulnerability Assessment Report", title_style))
        story.append(Spacer(1, 12))
        
        # Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_data = [
            ['Target URL', report_data.target_url],
            ['Scan Date', report_data.scan_date.strftime("%Y-%m-%d %H:%M:%S")],
            ['Total Tests', str(report_data.summary['total_tests'])],
            ['Vulnerabilities Found', str(report_data.summary['vulnerabilities_found'])],
            ['High Severity', str(report_data.summary['high_severity'])],
            ['Medium Severity', str(report_data.summary['medium_severity'])],
            ['Low Severity', str(report_data.summary['low_severity'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 12))
        
        # Vulnerabilities
        story.append(Paragraph("Vulnerability Details", styles['Heading2']))
        
        for vuln in report_data.vulnerabilities:
            if vuln['status'] == 'warning':
                story.append(Paragraph(f"<b>{vuln['test_name']}</b>", styles['Heading3']))
                story.append(Paragraph(f"Severity: {vuln['severity'].upper()}", styles['Normal']))
                story.append(Paragraph(f"Confidence: {vuln['confidence']:.1%}", styles['Normal']))
                story.append(Paragraph(f"Result: {vuln['result']}", styles['Normal']))
                story.append(Spacer(1, 6))
        
        doc.build(story)
        return pdf_path
    
    def _generate_json_report(self, report_data: VulnerabilityReport) -> str:
        """Generate JSON report"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_json:
            json.dump(report_data.to_dict(), temp_json, indent=2)
            return temp_json.name
    
    def _generate_xml_report(self, report_data: VulnerabilityReport) -> str:
        """Generate XML report"""
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<vulnerability_report>
    <scan_id>{report_data.scan_id}</scan_id>
    <target_url>{html.escape(report_data.target_url)}</target_url>
    <scan_date>{report_data.scan_date.isoformat()}</scan_date>
    <scan_duration>{report_data.scan_duration}</scan_duration>
    
    <summary>
        <total_tests>{report_data.summary['total_tests']}</total_tests>
        <vulnerabilities_found>{report_data.summary['vulnerabilities_found']}</vulnerabilities_found>
        <high_severity>{report_data.summary['high_severity']}</high_severity>
        <medium_severity>{report_data.summary['medium_severity']}</medium_severity>
        <low_severity>{report_data.summary['low_severity']}</low_severity>
    </summary>
    
    <vulnerabilities>
"""
        
        for vuln in report_data.vulnerabilities:
            xml_content += f"""        <vulnerability>
            <test_name>{html.escape(vuln['test_name'])}</test_name>
            <status>{vuln['status']}</status>
            <severity>{vuln['severity']}</severity>
            <confidence>{vuln['confidence']}</confidence>
            <cvss_score>{vuln['cvss_score']}</cvss_score>
            <result>{html.escape(str(vuln['result']))}</result>
        </vulnerability>
"""
        
        xml_content += """    </vulnerabilities>
</vulnerability_report>"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_xml:
            temp_xml.write(xml_content)
            return temp_xml.name
    
    def _generate_csv_report(self, report_data: VulnerabilityReport) -> str:
        """Generate CSV report"""
        import csv
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as temp_csv:
            writer = csv.writer(temp_csv)
            
            # Header
            writer.writerow(['Test Name', 'Status', 'Severity', 'Confidence', 'CVSS Score', 'Result'])
            
            # Data
            for vuln in report_data.vulnerabilities:
                writer.writerow([
                    vuln['test_name'],
                    vuln['status'],
                    vuln['severity'],
                    f"{vuln['confidence']:.2f}",
                    vuln['cvss_score'],
                    str(vuln['result'])[:100]  # Truncate long results
                ])
            
            return temp_csv.name
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .meta-card {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .meta-card h3 {
            margin: 0;
            color: #2c3e50;
        }
        .meta-card p {
            margin: 5px 0 0 0;
            font-size: 1.2em;
            font-weight: bold;
        }
        .summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .vulnerability {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .vulnerability.high {
            border-left: 5px solid #e74c3c;
        }
        .vulnerability.medium {
            border-left: 5px solid #f39c12;
        }
        .vulnerability.low {
            border-left: 5px solid #f1c40f;
        }
        .vulnerability.info {
            border-left: 5px solid #3498db;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-high { background-color: #e74c3c; color: white; }
        .severity-medium { background-color: #f39c12; color: white; }
        .severity-low { background-color: #f1c40f; color: #333; }
        .severity-info { background-color: #3498db; color: white; }
        .confidence-bar {
            width: 100%;
            height: 20px;
            background-color: #ecf0f1;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }
        .confidence-fill {
            height: 100%;
            background-color: #27ae60;
            transition: width 0.3s ease;
        }
        .recommendations {
            background: #e8f5e8;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }
        .recommendations h2 {
            color: #27ae60;
            margin-top: 0;
        }
        .recommendations ul {
            padding-left: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Assessment Report</h1>
            <p>Generated on {{ generation_date }}</p>
        </div>
        
        <div class="meta-info">
            <div class="meta-card">
                <h3>Target URL</h3>
                <p>{{ report.target_url }}</p>
            </div>
            <div class="meta-card">
                <h3>Scan Date</h3>
                <p>{{ report.scan_date.strftime("%Y-%m-%d %H:%M") }}</p>
            </div>
            <div class="meta-card">
                <h3>Duration</h3>
                <p>{{ "%.1f"|format(report.scan_duration) }}s</p>
            </div>
            <div class="meta-card">
                <h3>Total Tests</h3>
                <p>{{ report.summary.total_tests }}</p>
            </div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="meta-info">
                <div class="meta-card">
                    <h3>Vulnerabilities Found</h3>
                    <p>{{ report.summary.vulnerabilities_found }}</p>
                </div>
                <div class="meta-card">
                    <h3>High Severity</h3>
                    <p style="color: #e74c3c;">{{ report.summary.high_severity }}</p>
                </div>
                <div class="meta-card">
                    <h3>Medium Severity</h3>
                    <p style="color: #f39c12;">{{ report.summary.medium_severity }}</p>
                </div>
                <div class="meta-card">
                    <h3>Low Severity</h3>
                    <p style="color: #f1c40f;">{{ report.summary.low_severity }}</p>
                </div>
            </div>
        </div>
        
        <h2>Vulnerability Details</h2>
        {% for vuln in report.vulnerabilities %}
        <div class="vulnerability {{ vuln.severity }}">
            <h3>{{ vuln.test_name }}</h3>
            <p>
                <span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity }}</span>
                <span style="margin-left: 10px;">Confidence: {{ "%.1f"|format(vuln.confidence * 100) }}%</span>
                {% if vuln.cvss_score > 0 %}
                <span style="margin-left: 10px;">CVSS Score: {{ vuln.cvss_score }}</span>
                {% endif %}
            </p>
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: {{ vuln.confidence * 100 }}%"></div>
            </div>
            <p><strong>Result:</strong> {{ vuln.result }}</p>
            {% if vuln.evidence %}
            <p><strong>Evidence:</strong></p>
            <ul>
                {% for evidence in vuln.evidence %}
                <li>{{ evidence }}</li>
                {% endfor %}
            </ul>
            {% endif %}
            {% if vuln.recommendations %}
            <p><strong>Recommendations:</strong></p>
            <ul>
                {% for rec in vuln.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
        
        <div class="recommendations">
            <h2>General Recommendations</h2>
            <ul>
                {% for rec in report.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="footer">
            <p>Report generated by Advanced Web Security Scanner</p>
            <p>Scan ID: {{ report.scan_id }}</p>
        </div>
    </div>
</body>
</html>
        """
    
    def _get_executive_template(self) -> str:
        """Get executive summary template"""
        return "Executive template placeholder"
    
    def _get_technical_template(self) -> str:
        """Get technical details template"""
        return "Technical template placeholder"

class UserManager:
    """User management system for multi-tenant deployment"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.users = {}  # In production, use database
        self.sessions = {}  # In production, use Redis
    
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Dict[str, Any]:
        """Create new user account"""
        if username in self.users:
            raise ValueError("Username already exists")
        
        user_id = str(uuid.uuid4())
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user = {
            'user_id': user_id,
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'role': role,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'active': True,
            'api_key': secrets.token_urlsafe(32)
        }
        
        self.users[username] = user
        return user
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user credentials"""
        if username not in self.users:
            return None
        
        user = self.users[username]
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if user['password_hash'] == password_hash and user['active']:
            user['last_login'] = datetime.now().isoformat()
            return user
        
        return None
    
    def generate_jwt_token(self, user: Dict[str, Any]) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user['user_id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

class CIPipeline:
    """CI/CD pipeline integration"""
    
    def __init__(self):
        self.supported_formats = ['json', 'xml', 'junit', 'sarif']
    
    def generate_ci_report(self, scan_results: Dict[str, Any], format_type: str = 'json') -> str:
        """Generate CI/CD compatible report"""
        if format_type == 'junit':
            return self._generate_junit_report(scan_results)
        elif format_type == 'sarif':
            return self._generate_sarif_report(scan_results)
        else:
            # Default to JSON
            return json.dumps(scan_results, indent=2)
    
    def _generate_junit_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate JUnit XML report"""
        from xml.etree.ElementTree import Element, SubElement, tostring
        
        testsuites = Element('testsuites')
        testsuite = SubElement(testsuites, 'testsuite')
        testsuite.set('name', 'Security Tests')
        testsuite.set('tests', str(len(scan_results)))
        
        failures = 0
        for test_name, result in scan_results.items():
            testcase = SubElement(testsuite, 'testcase')
            testcase.set('name', test_name)
            testcase.set('classname', 'SecurityTest')
            
            if isinstance(result, dict) and result.get('status') == 'warning':
                failure = SubElement(testcase, 'failure')
                failure.text = str(result.get('result', ''))
                failures += 1
        
        testsuite.set('failures', str(failures))
        
        return tostring(testsuites, encoding='unicode')
    
    def _generate_sarif_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate SARIF report for GitHub security tab"""
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Advanced Web Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/user/vuln-scanner"
                    }
                },
                "results": []
            }]
        }
        
        for test_name, result in scan_results.items():
            if isinstance(result, dict) and result.get('status') == 'warning':
                sarif_result = {
                    "ruleId": test_name,
                    "message": {
                        "text": str(result.get('result', ''))
                    },
                    "level": self._get_sarif_level(result.get('cvss_score', 0.0)),
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": result.get('url', 'unknown')
                            }
                        }
                    }]
                }
                
                sarif_report["runs"][0]["results"].append(sarif_result)
        
        return json.dumps(sarif_report, indent=2)
    
    def _get_sarif_level(self, cvss_score: float) -> str:
        """Convert CVSS score to SARIF level"""
        if cvss_score >= 7.0:
            return "error"
        elif cvss_score >= 4.0:
            return "warning"
        else:
            return "note"

class RateLimiter:
    """Rate limiting for API endpoints"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # client_id -> [(timestamp, count)]
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed"""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        if client_id in self.requests:
            self.requests[client_id] = [
                (timestamp, count) for timestamp, count in self.requests[client_id]
                if timestamp > window_start
            ]
        else:
            self.requests[client_id] = []
        
        # Count requests in current window
        total_requests = sum(count for _, count in self.requests[client_id])
        
        if total_requests >= self.max_requests:
            return False
        
        # Add current request
        self.requests[client_id].append((now, 1))
        return True

# Example usage
if __name__ == "__main__":
    # Test report generation
    sample_results = {
        'target_url': 'https://example.com',
        'scan_duration': 45.2,
        'advanced_xss': {
            'status': 'warning',
            'result': 'XSS vulnerability found in search parameter',
            'confidence': 0.8,
            'evidence': ['Payload reflected in response'],
            'recommendations': ['Implement input validation'],
            'cvss_score': 6.1
        },
        'security_headers': {
            'status': 'info',
            'result': 'Security headers analysis complete',
            'confidence': 0.9,
            'cvss_score': 0.0
        }
    }
    
    # Generate reports
    report_gen = ReportGenerator()
    
    # HTML report
    html_report = report_gen.generate_report(sample_results, 'html')
    print("HTML report generated")
    
    # JSON report
    json_report = report_gen.generate_report(sample_results, 'json')
    print("JSON report generated")
    
    # CI/CD integration
    ci_pipeline = CIPipeline()
    junit_report = ci_pipeline.generate_ci_report(sample_results, 'junit')
    print("JUnit report generated")
    
    sarif_report = ci_pipeline.generate_ci_report(sample_results, 'sarif')
    print("SARIF report generated")