#!/usr/bin/env python3
"""
Sophisticated Analysis Engine for Vulnerability Scanner
Advanced detection techniques using machine learning and heuristics
"""

import re
import json
import hashlib
import statistics
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityPattern:
    """Pattern for vulnerability detection"""
    name: str
    category: str
    severity: str
    pattern: str
    confidence: float
    description: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

class SophisticatedAnalyzer:
    """Advanced vulnerability analysis engine"""
    
    def __init__(self):
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.fingerprints = self._load_technology_fingerprints()
        self.ml_models = self._initialize_ml_models()
        self.analysis_cache = {}
        
    def _load_vulnerability_patterns(self) -> List[VulnerabilityPattern]:
        """Load vulnerability detection patterns"""
        patterns = [
            VulnerabilityPattern(
                name="SQL Injection - Error Based",
                category="SQL Injection",
                severity="High",
                pattern=r"(mysql_fetch_array|Warning.*mysql_|ORA-\d+|Microsoft.*ODBC.*SQL|PostgreSQL.*ERROR)",
                confidence=0.9,
                description="Database error messages indicating potential SQL injection",
                remediation="Use parameterized queries and input validation",
                cwe_id="CWE-89",
                owasp_category="A03:2021"
            ),
            VulnerabilityPattern(
                name="XSS - Reflected",
                category="Cross-Site Scripting",
                severity="High",
                pattern=r"<script[^>]*>.*?</script>|javascript:|on\w+\s*=",
                confidence=0.8,
                description="Reflected XSS vulnerability detected",
                remediation="Implement proper output encoding and CSP headers",
                cwe_id="CWE-79",
                owasp_category="A03:2021"
            ),
            VulnerabilityPattern(
                name="Directory Traversal",
                category="Path Traversal",
                severity="Medium",
                pattern=r"(\.\.[\\/]){2,}|(\.\.%2f){2,}|(\.\.%5c){2,}",
                confidence=0.7,
                description="Directory traversal attack pattern detected",
                remediation="Validate and sanitize file paths",
                cwe_id="CWE-22",
                owasp_category="A01:2021"
            ),
            VulnerabilityPattern(
                name="Command Injection",
                category="Command Injection",
                severity="Critical",
                pattern=r"(;\s*cat\s+/etc/passwd|;\s*ls\s+-la|cmd\.exe|powershell|bash|sh\s+-c)",
                confidence=0.9,
                description="Command injection vulnerability detected",
                remediation="Use safe APIs and input validation",
                cwe_id="CWE-78",
                owasp_category="A03:2021"
            ),
            VulnerabilityPattern(
                name="XXE - XML External Entity",
                category="XML External Entity",
                severity="High",
                pattern=r"<!ENTITY.*SYSTEM|<!ENTITY.*file:|<!ENTITY.*http:",
                confidence=0.8,
                description="XML External Entity vulnerability detected",
                remediation="Disable external entity processing",
                cwe_id="CWE-611",
                owasp_category="A05:2021"
            ),
            VulnerabilityPattern(
                name="SSRF - Server-Side Request Forgery",
                category="Server-Side Request Forgery",
                severity="High",
                pattern=r"(127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google\.internal)",
                confidence=0.7,
                description="Server-Side Request Forgery vulnerability detected",
                remediation="Implement URL validation and whitelist",
                cwe_id="CWE-918",
                owasp_category="A10:2021"
            ),
            VulnerabilityPattern(
                name="Information Disclosure - Stack Trace",
                category="Information Disclosure",
                severity="Medium",
                pattern=r"(at\s+\w+\.\w+\(.*:\d+\)|Traceback.*File.*line\s+\d+|Fatal error:.*in\s+.*on\s+line\s+\d+)",
                confidence=0.8,
                description="Stack trace or error information disclosed",
                remediation="Implement proper error handling",
                cwe_id="CWE-209",
                owasp_category="A09:2021"
            ),
            VulnerabilityPattern(
                name="Sensitive Data Exposure",
                category="Sensitive Data Exposure",
                severity="High",
                pattern=r"(password\s*[:=]\s*['\"]?\w+|api_key\s*[:=]\s*['\"]?\w+|secret_key\s*[:=]\s*['\"]?\w+)",
                confidence=0.9,
                description="Sensitive data exposed in response",
                remediation="Remove sensitive data from public responses",
                cwe_id="CWE-200",
                owasp_category="A02:2021"
            )
        ]
        
        logger.info(f"Loaded {len(patterns)} vulnerability patterns")
        return patterns
    
    def _load_technology_fingerprints(self) -> Dict[str, Dict[str, Any]]:
        """Load technology fingerprinting patterns"""
        fingerprints = {
            'web_servers': {
                'nginx': {
                    'headers': ['Server: nginx', 'X-Nginx-Cache'],
                    'patterns': [r'nginx/[\d\.]+'],
                    'confidence': 0.9
                },
                'apache': {
                    'headers': ['Server: Apache'],
                    'patterns': [r'Apache/[\d\.]+'],
                    'confidence': 0.9
                },
                'iis': {
                    'headers': ['Server: Microsoft-IIS'],
                    'patterns': [r'Microsoft-IIS/[\d\.]+'],
                    'confidence': 0.9
                }
            },
            'frameworks': {
                'django': {
                    'headers': ['X-Frame-Options: SAMEORIGIN'],
                    'patterns': [r'django', r'csrfmiddlewaretoken'],
                    'confidence': 0.8
                },
                'flask': {
                    'patterns': [r'Werkzeug', r'Flask'],
                    'confidence': 0.8
                },
                'express': {
                    'headers': ['X-Powered-By: Express'],
                    'patterns': [r'Express'],
                    'confidence': 0.9
                }
            },
            'databases': {
                'mysql': {
                    'patterns': [r'mysql', r'MariaDB'],
                    'confidence': 0.7
                },
                'postgresql': {
                    'patterns': [r'PostgreSQL', r'psql'],
                    'confidence': 0.7
                },
                'mongodb': {
                    'patterns': [r'MongoDB', r'mongo'],
                    'confidence': 0.7
                }
            }
        }
        
        return fingerprints
    
    def _initialize_ml_models(self) -> Dict[str, Any]:
        """Initialize machine learning models for advanced detection"""
        # This would normally load pre-trained models
        # For now, we'll use heuristic-based models
        return {
            'anomaly_detector': self._create_anomaly_detector(),
            'payload_classifier': self._create_payload_classifier(),
            'response_analyzer': self._create_response_analyzer()
        }
    
    def _create_anomaly_detector(self) -> Dict[str, Any]:
        """Create anomaly detection model"""
        return {
            'type': 'heuristic',
            'thresholds': {
                'response_time_outlier': 3.0,  # Standard deviations
                'response_size_outlier': 2.5,
                'status_code_anomaly': 0.1     # Frequency threshold
            }
        }
    
    def _create_payload_classifier(self) -> Dict[str, Any]:
        """Create payload classification model"""
        return {
            'type': 'pattern_based',
            'categories': {
                'sql_injection': [
                    r"'\s*OR\s*'1'\s*=\s*'1",
                    r"'\s*UNION\s*SELECT",
                    r"'\s*;.*DROP\s*TABLE",
                    r"'\s*;.*INSERT\s*INTO"
                ],
                'xss': [
                    r"<script>",
                    r"javascript:",
                    r"onerror\s*=",
                    r"onload\s*="
                ],
                'command_injection': [
                    r";\s*cat\s*/etc/passwd",
                    r";\s*ls\s*-la",
                    r"&\s*dir",
                    r"|\s*whoami"
                ]
            }
        }
    
    def _create_response_analyzer(self) -> Dict[str, Any]:
        """Create response analysis model"""
        return {
            'type': 'pattern_based',
            'indicators': {
                'error_patterns': [
                    r"Fatal error:",
                    r"Warning:",
                    r"Parse error:",
                    r"Notice:",
                    r"Exception:",
                    r"Traceback"
                ],
                'debug_patterns': [
                    r"DEBUG:",
                    r"TRACE:",
                    r"var_dump",
                    r"print_r",
                    r"console\.log"
                ],
                'database_patterns': [
                    r"mysql_",
                    r"ORA-\d+",
                    r"PostgreSQL.*ERROR",
                    r"SQLite.*error"
                ]
            }
        }
    
    def analyze_response(self, response: requests.Response, payload: str = None) -> Dict[str, Any]:
        """Perform sophisticated analysis of HTTP response"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'url': response.url,
            'status_code': response.status_code,
            'vulnerabilities': [],
            'technologies': [],
            'anomalies': [],
            'security_score': 0,
            'confidence': 0
        }
        
        # Analyze response content
        content = response.text
        headers = dict(response.headers)
        
        # Pattern-based vulnerability detection
        vulnerabilities = self._detect_vulnerabilities(content, headers, payload)
        analysis['vulnerabilities'] = vulnerabilities
        
        # Technology fingerprinting
        technologies = self._fingerprint_technologies(content, headers)
        analysis['technologies'] = technologies
        
        # Anomaly detection
        anomalies = self._detect_anomalies(response, payload)
        analysis['anomalies'] = anomalies
        
        # Calculate security score
        analysis['security_score'] = self._calculate_security_score(vulnerabilities, anomalies)
        
        # Calculate overall confidence
        analysis['confidence'] = self._calculate_confidence(vulnerabilities, technologies, anomalies)
        
        return analysis
    
    def _detect_vulnerabilities(self, content: str, headers: Dict[str, str], payload: str = None) -> List[Dict[str, Any]]:
        """Detect vulnerabilities using pattern matching"""
        vulnerabilities = []
        
        for pattern in self.vulnerability_patterns:
            matches = re.finditer(pattern.pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                vuln = {
                    'name': pattern.name,
                    'category': pattern.category,
                    'severity': pattern.severity,
                    'confidence': pattern.confidence,
                    'description': pattern.description,
                    'remediation': pattern.remediation,
                    'cwe_id': pattern.cwe_id,
                    'owasp_category': pattern.owasp_category,
                    'evidence': match.group(0)[:200],  # Limit evidence length
                    'location': match.start()
                }
                
                # Context-aware confidence adjustment
                if payload:
                    vuln['confidence'] = self._adjust_confidence_with_payload(
                        vuln['confidence'], payload, match.group(0)
                    )
                
                vulnerabilities.append(vuln)
        
        # Remove duplicates and sort by severity
        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        vulnerabilities.sort(key=lambda x: self._get_severity_score(x['severity']), reverse=True)
        
        return vulnerabilities
    
    def _fingerprint_technologies(self, content: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Fingerprint technologies used by the target"""
        technologies = []
        
        for category, tech_patterns in self.fingerprints.items():
            for tech_name, patterns in tech_patterns.items():
                confidence = 0
                evidence = []
                
                # Check headers
                if 'headers' in patterns:
                    for header_pattern in patterns['headers']:
                        for header_name, header_value in headers.items():
                            if header_pattern.lower() in f"{header_name}: {header_value}".lower():
                                confidence += 0.3
                                evidence.append(f"Header: {header_name}: {header_value}")
                
                # Check content patterns
                if 'patterns' in patterns:
                    for pattern in patterns['patterns']:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            confidence += 0.2
                            evidence.append(f"Content: {match.group(0)}")
                
                # Add technology if confidence is high enough
                if confidence >= 0.3:
                    technologies.append({
                        'name': tech_name,
                        'category': category,
                        'confidence': min(confidence, 1.0),
                        'evidence': evidence[:3]  # Limit evidence
                    })
        
        return technologies
    
    def _detect_anomalies(self, response: requests.Response, payload: str = None) -> List[Dict[str, Any]]:
        """Detect anomalies in response"""
        anomalies = []
        
        # Response time anomaly
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 10:
            anomalies.append({
                'type': 'response_time',
                'description': 'Unusually long response time',
                'value': response.elapsed.total_seconds(),
                'severity': 'Medium'
            })
        
        # Response size anomaly
        content_length = len(response.content)
        if content_length > 1000000:  # 1MB
            anomalies.append({
                'type': 'response_size',
                'description': 'Unusually large response size',
                'value': content_length,
                'severity': 'Low'
            })
        
        # Status code anomaly
        if response.status_code >= 500:
            anomalies.append({
                'type': 'server_error',
                'description': 'Server error response',
                'value': response.status_code,
                'severity': 'High'
            })
        
        # Payload reflection detection
        if payload and payload.lower() in response.text.lower():
            anomalies.append({
                'type': 'payload_reflection',
                'description': 'Payload reflected in response',
                'value': payload,
                'severity': 'Medium'
            })
        
        return anomalies
    
    def _adjust_confidence_with_payload(self, base_confidence: float, payload: str, evidence: str) -> float:
        """Adjust confidence based on payload-response correlation"""
        # If payload is reflected exactly, increase confidence
        if payload.lower() in evidence.lower():
            return min(base_confidence * 1.2, 1.0)
        
        # If payload shows signs of processing, increase confidence
        payload_chars = set(payload.lower())
        evidence_chars = set(evidence.lower())
        
        if len(payload_chars.intersection(evidence_chars)) > len(payload_chars) * 0.7:
            return min(base_confidence * 1.1, 1.0)
        
        return base_confidence
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create a hash based on name, category, and evidence
            vuln_hash = hashlib.md5(
                f"{vuln['name']}:{vuln['category']}:{vuln['evidence']}".encode()
            ).hexdigest()
            
            if vuln_hash not in seen:
                seen.add(vuln_hash)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _get_severity_score(self, severity: str) -> int:
        """Get numeric score for severity level"""
        scores = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        return scores.get(severity, 0)
    
    def _calculate_security_score(self, vulnerabilities: List[Dict[str, Any]], 
                                 anomalies: List[Dict[str, Any]]) -> int:
        """Calculate overall security score (0-100, where 100 is most secure)"""
        base_score = 100
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity_score = self._get_severity_score(vuln['severity'])
            confidence = vuln['confidence']
            deduction = severity_score * 10 * confidence
            base_score -= deduction
        
        # Deduct points for anomalies
        for anomaly in anomalies:
            severity_score = self._get_severity_score(anomaly.get('severity', 'Low'))
            deduction = severity_score * 5
            base_score -= deduction
        
        return max(0, int(base_score))
    
    def _calculate_confidence(self, vulnerabilities: List[Dict[str, Any]], 
                             technologies: List[Dict[str, Any]], 
                             anomalies: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence in analysis"""
        if not vulnerabilities and not technologies and not anomalies:
            return 0.0
        
        # Average confidence of all findings
        all_confidences = []
        
        for vuln in vulnerabilities:
            all_confidences.append(vuln['confidence'])
        
        for tech in technologies:
            all_confidences.append(tech['confidence'])
        
        # Anomalies have implicit confidence of 0.8
        for anomaly in anomalies:
            all_confidences.append(0.8)
        
        if all_confidences:
            return statistics.mean(all_confidences)
        
        return 0.0
    
    def analyze_multiple_responses(self, responses: List[Tuple[requests.Response, str]]) -> Dict[str, Any]:
        """Analyze multiple responses for patterns and correlations"""
        all_analyses = []
        
        for response, payload in responses:
            analysis = self.analyze_response(response, payload)
            all_analyses.append(analysis)
        
        # Aggregate results
        aggregated = {
            'total_requests': len(responses),
            'vulnerabilities': [],
            'technologies': [],
            'anomalies': [],
            'patterns': self._find_patterns(all_analyses),
            'overall_security_score': 0,
            'confidence': 0
        }
        
        # Collect all unique vulnerabilities
        all_vulns = []
        for analysis in all_analyses:
            all_vulns.extend(analysis['vulnerabilities'])
        
        aggregated['vulnerabilities'] = self._deduplicate_vulnerabilities(all_vulns)
        
        # Collect all unique technologies
        all_techs = []
        for analysis in all_analyses:
            all_techs.extend(analysis['technologies'])
        
        aggregated['technologies'] = self._deduplicate_technologies(all_techs)
        
        # Collect all anomalies
        for analysis in all_analyses:
            aggregated['anomalies'].extend(analysis['anomalies'])
        
        # Calculate overall metrics
        scores = [a['security_score'] for a in all_analyses]
        aggregated['overall_security_score'] = int(statistics.mean(scores)) if scores else 0
        
        confidences = [a['confidence'] for a in all_analyses]
        aggregated['confidence'] = statistics.mean(confidences) if confidences else 0
        
        return aggregated
    
    def _find_patterns(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find patterns across multiple analyses"""
        patterns = {
            'consistent_vulnerabilities': [],
            'technology_correlations': [],
            'anomaly_patterns': []
        }
        
        # Find consistently appearing vulnerabilities
        vuln_counts = Counter()
        for analysis in analyses:
            for vuln in analysis['vulnerabilities']:
                vuln_counts[vuln['name']] += 1
        
        total_analyses = len(analyses)
        for vuln_name, count in vuln_counts.items():
            if count > total_analyses * 0.3:  # Appears in >30% of responses
                patterns['consistent_vulnerabilities'].append({
                    'name': vuln_name,
                    'frequency': count / total_analyses,
                    'count': count
                })
        
        return patterns
    
    def _deduplicate_technologies(self, technologies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate technologies"""
        seen = set()
        unique_techs = []
        
        for tech in technologies:
            tech_key = f"{tech['name']}:{tech['category']}"
            if tech_key not in seen:
                seen.add(tech_key)
                unique_techs.append(tech)
        
        return unique_techs
    
    def generate_security_report(self, analysis: Dict[str, Any]) -> str:
        """Generate a comprehensive security report"""
        report = []
        
        report.append("# Security Analysis Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Executive Summary
        report.append("## Executive Summary")
        report.append(f"Security Score: {analysis['overall_security_score']}/100")
        report.append(f"Confidence Level: {analysis['confidence']:.2f}")
        report.append(f"Vulnerabilities Found: {len(analysis['vulnerabilities'])}")
        report.append("")
        
        # Vulnerabilities
        if analysis['vulnerabilities']:
            report.append("## Vulnerabilities")
            for vuln in analysis['vulnerabilities']:
                report.append(f"### {vuln['name']}")
                report.append(f"**Severity:** {vuln['severity']}")
                report.append(f"**Category:** {vuln['category']}")
                report.append(f"**Confidence:** {vuln['confidence']:.2f}")
                report.append(f"**Description:** {vuln['description']}")
                report.append(f"**Remediation:** {vuln['remediation']}")
                if vuln.get('cwe_id'):
                    report.append(f"**CWE ID:** {vuln['cwe_id']}")
                report.append("")
        
        # Technologies
        if analysis['technologies']:
            report.append("## Detected Technologies")
            for tech in analysis['technologies']:
                report.append(f"- {tech['name']} ({tech['category']}) - Confidence: {tech['confidence']:.2f}")
            report.append("")
        
        # Anomalies
        if analysis['anomalies']:
            report.append("## Anomalies")
            for anomaly in analysis['anomalies']:
                report.append(f"- {anomaly['type']}: {anomaly['description']}")
            report.append("")
        
        return "\n".join(report)

# Global analyzer instance
sophisticated_analyzer = SophisticatedAnalyzer()

def analyze_response(response: requests.Response, payload: str = None) -> Dict[str, Any]:
    """Analyze a single response using sophisticated techniques"""
    return sophisticated_analyzer.analyze_response(response, payload)

def analyze_multiple_responses(responses: List[Tuple[requests.Response, str]]) -> Dict[str, Any]:
    """Analyze multiple responses for patterns"""
    return sophisticated_analyzer.analyze_multiple_responses(responses)

def generate_security_report(analysis: Dict[str, Any]) -> str:
    """Generate a comprehensive security report"""
    return sophisticated_analyzer.generate_security_report(analysis)