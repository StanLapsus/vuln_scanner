class VulnScannerApp {
    constructor() {
        this.scanForm = document.getElementById('scanForm');
        this.scanBtn = document.getElementById('scanBtn');
        this.progressSection = document.getElementById('progressSection');
        this.progressFill = document.getElementById('progressFill');
        this.progressText = document.getElementById('progressText');
        this.resultsSection = document.getElementById('resultsSection');
        this.resultsGrid = document.getElementById('resultsGrid');
        this.exportBtn = document.getElementById('exportBtn');
        this.generateReportBtn = document.getElementById('generateReportBtn');
        this.targetInput = document.getElementById('target');
        
        this.currentResults = null;
        this.pollInterval = null;
        this.isScanning = false;
        
        this.init();
    }
    
    init() {
        this.scanForm.addEventListener('submit', this.handleScanSubmit.bind(this));
        this.exportBtn.addEventListener('click', this.handleExport.bind(this));
        this.generateReportBtn.addEventListener('click', this.handleGenerateReport.bind(this));
        this.targetInput.addEventListener('input', this.handleInputChange.bind(this));
        
        // Add keyboard shortcuts
        document.addEventListener('keydown', this.handleKeyboardShortcuts.bind(this));
        
        // Initialize tooltips and enhance UI
        this.enhanceUI();
    }
    
    enhanceUI() {
        // Add input validation styling
        this.targetInput.addEventListener('blur', this.validateUrl.bind(this));
        
        // Add loading states
        this.addLoadingStates();
        
        // Enhance button interactions
        this.enhanceButtons();
    }
    
    addLoadingStates() {
        const buttons = document.querySelectorAll('button');
        buttons.forEach(button => {
            button.addEventListener('click', () => {
                if (!button.disabled) {
                    button.classList.add('loading');
                    setTimeout(() => button.classList.remove('loading'), 200);
                }
            });
        });
    }
    
    enhanceButtons() {
        // Add ripple effect to buttons
        const buttons = document.querySelectorAll('button');
        buttons.forEach(button => {
            button.addEventListener('click', this.createRipple.bind(this));
        });
    }
    
    createRipple(e) {
        const button = e.currentTarget;
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;
        
        const ripple = document.createElement('span');
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            pointer-events: none;
            transform: scale(0);
            animation: ripple 0.6s ease-out;
        `;
        
        // Add CSS animation if not already present
        if (!document.querySelector('#ripple-style')) {
            const style = document.createElement('style');
            style.id = 'ripple-style';
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(4);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }
        
        button.style.position = 'relative';
        button.style.overflow = 'hidden';
        button.appendChild(ripple);
        
        setTimeout(() => {
            ripple.remove();
        }, 600);
    }
    
    handleKeyboardShortcuts(e) {
        // Ctrl+Enter to start scan
        if (e.ctrlKey && e.key === 'Enter' && !this.isScanning) {
            e.preventDefault();
            this.scanForm.dispatchEvent(new Event('submit'));
        }
        
        // Escape to cancel/reset
        if (e.key === 'Escape' && this.isScanning) {
            this.cancelScan();
        }
    }
    
    handleInputChange(e) {
        const input = e.target;
        this.clearInputError(input);
        
        // Real-time URL validation
        if (input.value && !this.isValidUrl(input.value)) {
            this.showInputError(input, 'Please enter a valid URL');
        }
    }
    
    validateUrl(e) {
        const input = e.target;
        const url = input.value.trim();
        
        if (url && !this.isValidUrl(url)) {
            this.showInputError(input, 'Please enter a valid URL (e.g., https://example.com)');
            return false;
        }
        
        this.clearInputError(input);
        return true;
    }
    
    isValidUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === 'http:' || url.protocol === 'https:';
        } catch (_) {
            return false;
        }
    }
    
    showInputError(input, message) {
        this.clearInputError(input);
        
        input.classList.add('error');
        const errorElement = document.createElement('div');
        errorElement.className = 'input-error';
        errorElement.textContent = message;
        errorElement.setAttribute('role', 'alert');
        
        input.parentNode.appendChild(errorElement);
    }
    
    clearInputError(input) {
        input.classList.remove('error');
        const errorElement = input.parentNode.querySelector('.input-error');
        if (errorElement) {
            errorElement.remove();
        }
    }
    
    async handleScanSubmit(e) {
        e.preventDefault();
        
        if (this.isScanning) {
            return;
        }
        
        const formData = new FormData(this.scanForm);
        const target = formData.get('target').trim();
        
        if (!target) {
            this.showNotification('Please enter a target URL', 'error');
            this.targetInput.focus();
            return;
        }
        
        if (!this.isValidUrl(target)) {
            this.showNotification('Please enter a valid URL', 'error');
            this.targetInput.focus();
            return;
        }
        
        try {
            await this.startScan(target);
        } catch (error) {
            this.showNotification('Error starting scan: ' + error.message, 'error');
        }
    }
    
    async startScan(target) {
        this.isScanning = true;
        
        // Update UI
        this.scanBtn.disabled = true;
        this.scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Starting...</span>';
        this.progressSection.style.display = 'block';
        this.resultsSection.style.display = 'none';
        
        // Update progress bar attributes
        this.updateProgressBar(0);
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target: target })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            this.showNotification('Scan started successfully', 'success');
            
            // Start polling for status
            this.pollScanStatus();
            
        } catch (error) {
            this.showNotification('Error starting scan: ' + error.message, 'error');
            this.resetUI();
        }
    }
    
    async pollScanStatus() {
        this.pollInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/scan_status');
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const status = await response.json();
                this.updateProgress(status);
                
                if (status.status === 'complete') {
                    clearInterval(this.pollInterval);
                    this.handleScanComplete(status);
                } else if (status.status === 'error') {
                    clearInterval(this.pollInterval);
                    this.showNotification('Scan error: ' + status.error, 'error');
                    this.resetUI();
                }
                
            } catch (error) {
                console.error('Error polling scan status:', error);
                this.showNotification('Connection error during scan', 'error');
            }
        }, 1000);
    }
    
    updateProgress(status) {
        const progress = Math.max(0, Math.min(100, status.progress || 0));
        this.updateProgressBar(progress);
        
        if (status.status === 'running') {
            if (progress < 25) {
                this.progressText.textContent = 'Initializing security tests...';
            } else if (progress < 50) {
                this.progressText.textContent = 'Scanning network services...';
            } else if (progress < 75) {
                this.progressText.textContent = 'Testing for vulnerabilities...';
            } else {
                this.progressText.textContent = 'Analyzing results...';
            }
        } else if (status.status === 'complete') {
            this.progressText.textContent = 'Scan completed successfully!';
        }
    }
    
    updateProgressBar(progress) {
        this.progressFill.style.width = progress + '%';
        this.progressSection.querySelector('.progress-bar').setAttribute('aria-valuenow', progress);
    }
    
    handleScanComplete(status) {
        this.currentResults = status.results;
        this.displayResults(status.results);
        this.resetUI();
        
        // Show success notification
        this.showNotification(`Scan completed! Results saved to ${status.filename}`, 'success');
        
        // Auto-hide progress section after delay
        setTimeout(() => {
            this.progressSection.style.display = 'none';
        }, 3000);
    }
    
    displayResults(results) {
        this.resultsGrid.innerHTML = '';
        
        if (!results || Object.keys(results).length === 0) {
            this.showEmptyResults();
            return;
        }
        
        // Create summary dashboard first
        const summaryElement = this.createSummaryDashboard(results);
        this.resultsGrid.appendChild(summaryElement);
        
        // Parse and display vulnerabilities
        const vulnerabilities = this.parseVulnerabilities(results);
        if (vulnerabilities.length > 0) {
            const vulnSection = this.createVulnerabilitySection(vulnerabilities);
            this.resultsGrid.appendChild(vulnSection);
        }
        
        // Display security findings
        const securityFindings = this.parseSecurityFindings(results);
        if (securityFindings.length > 0) {
            const securitySection = this.createSecurityFindingsSection(securityFindings);
            this.resultsGrid.appendChild(securitySection);
        }
        
        // Display technical details in collapsible sections
        const technicalDetails = this.parseTechnicalDetails(results);
        if (technicalDetails.length > 0) {
            const techSection = this.createTechnicalDetailsSection(technicalDetails);
            this.resultsGrid.appendChild(techSection);
        }
        
        this.resultsSection.style.display = 'block';
        this.resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    showEmptyResults() {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'empty-results';
        emptyDiv.innerHTML = `
            <i class="fas fa-search" style="font-size: 3rem; color: var(--text-muted); margin-bottom: 1rem;"></i>
            <p>No scan results available</p>
        `;
        this.resultsGrid.appendChild(emptyDiv);
        this.resultsSection.style.display = 'block';
    }
    
    
    createSummaryDashboard(results) {
        const summary = results.summary || {};
        const scanInfo = {
            target: results.target || 'Unknown',
            duration: results.duration || 0,
            totalTests: summary.total_tests || 0,
            vulnerabilities: summary.vulnerabilities_found || 0
        };
        
        const summaryDiv = document.createElement('div');
        summaryDiv.className = 'summary-dashboard';
        summaryDiv.innerHTML = `
            <h3><i class="fas fa-chart-bar"></i> Scan Summary</h3>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-value">${scanInfo.target}</div>
                    <div class="summary-label">Target</div>
                </div>
                <div class="summary-card">
                    <div class="summary-value">${scanInfo.totalTests}</div>
                    <div class="summary-label">Tests Run</div>
                </div>
                <div class="summary-card ${scanInfo.vulnerabilities > 0 ? 'has-vulns' : ''}">
                    <div class="summary-value">${scanInfo.vulnerabilities}</div>
                    <div class="summary-label">Vulnerabilities</div>
                </div>
                <div class="summary-card">
                    <div class="summary-value">${(scanInfo.duration * 1000).toFixed(0)}ms</div>
                    <div class="summary-label">Duration</div>
                </div>
            </div>
            <div class="analytics-section">
                <h4><i class="fas fa-chart-line"></i> Analytics & Visualization</h4>
                <div class="analytics-buttons">
                    <button id="generateAnalyticsBtn" class="analytics-btn">
                        <i class="fas fa-chart-pie"></i> Generate Analytics Dashboard
                    </button>
                    <button id="generateHeatmapBtn" class="analytics-btn">
                        <i class="fas fa-th"></i> Generate Risk Heatmap
                    </button>
                    <button id="generateTimelineBtn" class="analytics-btn">
                        <i class="fas fa-clock"></i> Generate Timeline Analysis
                    </button>
                </div>
                <div id="analyticsContainer" class="analytics-container" style="display: none;">
                    <!-- Analytics content will be populated here -->
                </div>
            </div>
        `;
        
        // Add event listeners for analytics buttons
        summaryDiv.addEventListener('click', (e) => {
            if (e.target.id === 'generateAnalyticsBtn') {
                this.generateAnalyticsDashboard(results);
            } else if (e.target.id === 'generateHeatmapBtn') {
                this.generateRiskHeatmap(results);
            } else if (e.target.id === 'generateTimelineBtn') {
                this.generateTimelineAnalysis(results);
            }
        });
        
        return summaryDiv;
    }
    
    parseVulnerabilities(results) {
        const vulnerabilities = [];
        
        // Parse vulnerabilities from tests
        if (results.tests && typeof results.tests === 'object') {
            const testsData = typeof results.tests === 'string' 
                ? JSON.parse(results.tests) 
                : results.tests;
            
            // Check vulnerability_scan results
            if (testsData.vulnerability_scan && testsData.vulnerability_scan.details) {
                const vulnData = testsData.vulnerability_scan.details;
                if (vulnData.vulnerabilities && Array.isArray(vulnData.vulnerabilities)) {
                    vulnData.vulnerabilities.forEach(vuln => {
                        vulnerabilities.push({
                            type: vuln.type || 'Unknown',
                            severity: vuln.severity || 'Low',
                            description: vuln.description || 'No description available',
                            category: 'Vulnerability',
                            timestamp: testsData.vulnerability_scan.timestamp
                        });
                    });
                }
            }
            
            // Check security headers for missing/weak configurations
            if (testsData.security_headers && testsData.security_headers.details) {
                const headers = testsData.security_headers.details.headers || {};
                Object.keys(headers).forEach(headerName => {
                    const header = headers[headerName];
                    if (!header.present || header.recommendation.includes('Consider implementing')) {
                        vulnerabilities.push({
                            type: 'Missing Security Header',
                            severity: 'Medium',
                            description: `${headerName}: ${header.recommendation}`,
                            category: 'Security Configuration',
                            timestamp: testsData.security_headers.timestamp
                        });
                    }
                });
            }
        }
        
        return vulnerabilities;
    }
    
    parseSecurityFindings(results) {
        const findings = [];
        
        if (results.tests && typeof results.tests === 'object') {
            const testsData = typeof results.tests === 'string' 
                ? JSON.parse(results.tests) 
                : results.tests;
            
            // Port scan findings
            if (testsData.port_scan && testsData.port_scan.details) {
                const portData = testsData.port_scan.details;
                if (portData.open_ports && Array.isArray(portData.open_ports)) {
                    findings.push({
                        type: 'Open Ports',
                        category: 'Network Security',
                        severity: 'Info',
                        details: portData.open_ports,
                        count: portData.open_ports.length,
                        timestamp: testsData.port_scan.timestamp
                    });
                }
            }
            
            // Information disclosure findings
            if (testsData.information_disclosure && testsData.information_disclosure.details) {
                const infoData = testsData.information_disclosure.details;
                if (infoData.accessible_paths && Array.isArray(infoData.accessible_paths)) {
                    findings.push({
                        type: 'Information Disclosure',
                        category: 'Information Leakage',
                        severity: 'Low',
                        details: infoData.accessible_paths,
                        count: infoData.sensitive_files_found || 0,
                        timestamp: testsData.information_disclosure.timestamp
                    });
                }
            }
            
            // Technology detection findings
            if (testsData.technology_detection && testsData.technology_detection.details) {
                const techData = testsData.technology_detection.details;
                findings.push({
                    type: 'Technology Stack',
                    category: 'Reconnaissance',
                    severity: 'Info',
                    details: {
                        server: techData.server,
                        cms: techData.cms_detected,
                        technologies: techData.technologies
                    },
                    timestamp: testsData.technology_detection.timestamp
                });
            }
        }
        
        return findings;
    }
    
    parseTechnicalDetails(results) {
        const details = [];
        
        if (results.tests && typeof results.tests === 'object') {
            const testsData = typeof results.tests === 'string' 
                ? JSON.parse(results.tests) 
                : results.tests;
            
            // Connectivity details
            if (testsData.connectivity && testsData.connectivity.details) {
                details.push({
                    name: 'Connectivity Test',
                    status: testsData.connectivity.status,
                    data: testsData.connectivity.details,
                    timestamp: testsData.connectivity.timestamp
                });
            }
            
            // SSL Analysis details
            if (testsData.ssl_analysis && testsData.ssl_analysis.details) {
                details.push({
                    name: 'SSL/TLS Analysis',
                    status: testsData.ssl_analysis.status,
                    data: testsData.ssl_analysis.details,
                    timestamp: testsData.ssl_analysis.timestamp
                });
            }
        }
        
        return details;
    }
    
    createVulnerabilitySection(vulnerabilities) {
        const section = document.createElement('div');
        section.className = 'vulnerability-section';
        
        let vulnCards = '';
        vulnerabilities.forEach(vuln => {
            const severityClass = vuln.severity.toLowerCase();
            vulnCards += `
                <div class="vulnerability-card ${severityClass}">
                    <div class="vuln-header">
                        <div class="vuln-type">${vuln.type}</div>
                        <div class="vuln-severity ${severityClass}">${vuln.severity}</div>
                    </div>
                    <div class="vuln-description">${vuln.description}</div>
                    <div class="vuln-meta">
                        <span class="vuln-category">${vuln.category}</span>
                        <span class="vuln-timestamp">${new Date(vuln.timestamp).toLocaleString()}</span>
                    </div>
                </div>
            `;
        });
        
        section.innerHTML = `
            <h3><i class="fas fa-exclamation-triangle"></i> Vulnerabilities Found (${vulnerabilities.length})</h3>
            <div class="vulnerability-grid">
                ${vulnCards}
            </div>
        `;
        
        return section;
    }
    
    createSecurityFindingsSection(findings) {
        const section = document.createElement('div');
        section.className = 'security-findings-section';
        
        let findingCards = '';
        findings.forEach(finding => {
            const severityClass = finding.severity.toLowerCase();
            findingCards += `
                <div class="finding-card ${severityClass}">
                    <div class="finding-header">
                        <div class="finding-type">${finding.type}</div>
                        <div class="finding-count">${finding.count || 'N/A'}</div>
                    </div>
                    <div class="finding-category">${finding.category}</div>
                    <div class="finding-details">
                        ${this.formatFindingDetails(finding.details)}
                    </div>
                </div>
            `;
        });
        
        section.innerHTML = `
            <h3><i class="fas fa-shield-alt"></i> Security Findings (${findings.length})</h3>
            <div class="findings-grid">
                ${findingCards}
            </div>
        `;
        
        return section;
    }
    
    createTechnicalDetailsSection(details) {
        const section = document.createElement('div');
        section.className = 'technical-details-section';
        
        let detailCards = '';
        details.forEach(detail => {
            const statusClass = detail.status === 'success' ? 'success' : 'error';
            detailCards += `
                <div class="detail-card collapsible">
                    <div class="detail-header" onclick="this.parentElement.classList.toggle('expanded')">
                        <div class="detail-name">${detail.name}</div>
                        <div class="detail-status ${statusClass}">${detail.status}</div>
                        <i class="fas fa-chevron-down expand-icon"></i>
                    </div>
                    <div class="detail-content">
                        <pre>${JSON.stringify(detail.data, null, 2)}</pre>
                    </div>
                </div>
            `;
        });
        
        section.innerHTML = `
            <h3><i class="fas fa-cog"></i> Technical Details</h3>
            <div class="details-grid">
                ${detailCards}
            </div>
        `;
        
        return section;
    }
    
    formatFindingDetails(details) {
        if (Array.isArray(details)) {
            return details.map(item => {
                if (typeof item === 'object') {
                    return `<div class="detail-item">${JSON.stringify(item, null, 2)}</div>`;
                } else {
                    return `<div class="detail-item">${item}</div>`;
                }
            }).join('');
        } else if (typeof details === 'object') {
            return `<pre>${JSON.stringify(details, null, 2)}</pre>`;
        } else {
            return `<div class="detail-item">${details}</div>`;
        }
    }
    
    formatTestName(testName) {
        return testName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
    
    getResultStatus(result) {
        const resultStr = String(result).toLowerCase();
        
        if (resultStr.includes('error') || resultStr.includes('failed') || resultStr.includes('not available')) {
            return { class: 'status-error', text: 'Error' };
        } else if (resultStr.includes('vulnerability') || resultStr.includes('found') || resultStr.includes('detected') || resultStr.includes('potential')) {
            return { class: 'status-warning', text: 'Found' };
        } else {
            return { class: 'status-success', text: 'Complete' };
        }
    }
    
    formatResult(result) {
        if (typeof result === 'object' && result !== null) {
            if (Array.isArray(result)) {
                return result.length > 0 ? result.join('\n') : 'No items found';
            } else {
                return JSON.stringify(result, null, 2);
            }
        } else {
            return String(result || 'No data available');
        }
    }
    
    handleExport() {
        if (!this.currentResults) {
            this.showNotification('No scan results to export', 'warning');
            return;
        }
        
        try {
            const dataStr = JSON.stringify(this.currentResults, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            
            const link = document.createElement('a');
            link.href = url;
            link.download = `scan_results_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
            link.style.display = 'none';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            URL.revokeObjectURL(url);
            this.showNotification('Results exported successfully', 'success');
        } catch (error) {
            this.showNotification('Error exporting results: ' + error.message, 'error');
        }
    }
    
    async handleGenerateReport() {
        if (!this.currentResults) {
            this.showNotification('No scan results available for report generation', 'warning');
            return;
        }
        
        try {
            this.generateReportBtn.disabled = true;
            this.generateReportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Generating...</span>';
            
            const response = await fetch('/api/generate_report', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    results: this.currentResults,
                    format: 'html'
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Report generated successfully!', 'success');
                
                // Create download link
                const reportFilename = result.report_path.split('/').pop();
                const downloadUrl = `/api/download_report/${reportFilename}`;
                
                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = reportFilename;
                link.style.display = 'none';
                
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                this.showNotification('Report download started', 'info');
            } else {
                throw new Error(result.error || 'Failed to generate report');
            }
            
        } catch (error) {
            this.showNotification('Error generating report: ' + error.message, 'error');
        } finally {
            this.generateReportBtn.disabled = false;
            this.generateReportBtn.innerHTML = '<i class="fas fa-file-alt"></i> <span>Generate Report</span>';
        }
    }
    
    cancelScan() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        
        this.isScanning = false;
        this.resetUI();
        this.showNotification('Scan cancelled', 'info');
    }
    
    resetUI() {
        this.isScanning = false;
        this.scanBtn.disabled = false;
        this.scanBtn.innerHTML = '<i class="fas fa-play"></i> <span>Start Scan</span>';
    }
    
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.setAttribute('role', 'alert');
        notification.setAttribute('aria-live', 'polite');
        
        const icon = this.getNotificationIcon(type);
        notification.innerHTML = `
            <i class="${icon}"></i>
            <span>${message}</span>
            <button class="notification-close" aria-label="Close notification">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add to container
        let container = document.querySelector('.notification-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
        
        container.appendChild(notification);
        
        // Auto-remove after delay
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
        
        // Add close button handler
        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.remove();
        });
    }
    
    getNotificationIcon(type) {
        switch (type) {
            case 'success': return 'fas fa-check-circle';
            case 'error': return 'fas fa-exclamation-circle';
            case 'warning': return 'fas fa-exclamation-triangle';
            case 'info': return 'fas fa-info-circle';
            default: return 'fas fa-info-circle';
        }
    }
    
    async generateAnalyticsDashboard(results) {
        const container = document.getElementById('analyticsContainer');
        const btn = document.getElementById('generateAnalyticsBtn');
        
        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Analytics...';
            
            // Generate analytics dashboard
            const analyticsData = this.processAnalyticsData(results);
            
            container.innerHTML = `
                <h4><i class="fas fa-chart-pie"></i> Analytics Dashboard</h4>
                <div class="analytics-grid">
                    <div class="analytics-card">
                        <h5>Vulnerability Distribution</h5>
                        <canvas id="vulnerabilityChart"></canvas>
                    </div>
                    <div class="analytics-card">
                        <h5>Risk Assessment</h5>
                        <div class="risk-assessment">
                            <div class="risk-meter">
                                <div class="risk-level risk-${analyticsData.riskLevel.toLowerCase()}">
                                    ${analyticsData.riskLevel}
                                </div>
                                <div class="risk-score">${analyticsData.securityScore}%</div>
                            </div>
                            <div class="risk-factors">
                                <h6>Key Risk Factors:</h6>
                                <ul>
                                    ${analyticsData.riskFactors.map(factor => `<li>${factor}</li>`).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="analytics-card">
                        <h5>Test Results Overview</h5>
                        <canvas id="testResultsChart"></canvas>
                    </div>
                    <div class="analytics-card">
                        <h5>Security Score Breakdown</h5>
                        <div class="score-breakdown">
                            <div class="score-item">
                                <span class="score-label">Critical Issues</span>
                                <span class="score-value">${analyticsData.criticalCount}</span>
                            </div>
                            <div class="score-item">
                                <span class="score-label">High Issues</span>
                                <span class="score-value">${analyticsData.highCount}</span>
                            </div>
                            <div class="score-item">
                                <span class="score-label">Medium Issues</span>
                                <span class="score-value">${analyticsData.mediumCount}</span>
                            </div>
                            <div class="score-item">
                                <span class="score-label">Low Issues</span>
                                <span class="score-value">${analyticsData.lowCount}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="recommendations-section">
                    <h5><i class="fas fa-lightbulb"></i> Recommendations</h5>
                    <div class="recommendations-grid">
                        ${analyticsData.recommendations.map(rec => `
                            <div class="recommendation-card">
                                <i class="fas fa-shield-alt"></i>
                                <p>${rec}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            
            container.style.display = 'block';
            
            // Initialize charts
            this.initializeCharts(analyticsData);
            
            this.showNotification('Analytics dashboard generated successfully!', 'success');
            
        } catch (error) {
            this.showNotification('Error generating analytics: ' + error.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-chart-pie"></i> Generate Analytics Dashboard';
        }
    }
    
    async generateRiskHeatmap(results) {
        const container = document.getElementById('analyticsContainer');
        const btn = document.getElementById('generateHeatmapBtn');
        
        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Heatmap...';
            
            const heatmapData = this.processHeatmapData(results);
            
            container.innerHTML = `
                <h4><i class="fas fa-th"></i> Risk Heatmap</h4>
                <div class="heatmap-container">
                    <div class="heatmap-legend">
                        <span class="legend-item">
                            <span class="legend-color low"></span>
                            <span class="legend-label">Low Risk</span>
                        </span>
                        <span class="legend-item">
                            <span class="legend-color medium"></span>
                            <span class="legend-label">Medium Risk</span>
                        </span>
                        <span class="legend-item">
                            <span class="legend-color high"></span>
                            <span class="legend-label">High Risk</span>
                        </span>
                        <span class="legend-item">
                            <span class="legend-color critical"></span>
                            <span class="legend-label">Critical Risk</span>
                        </span>
                    </div>
                    <div class="heatmap-grid">
                        ${heatmapData.map(item => `
                            <div class="heatmap-cell ${item.riskLevel}" title="${item.category}: ${item.riskScore}% risk">
                                <div class="cell-label">${item.category}</div>
                                <div class="cell-value">${item.riskScore}%</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
            
            container.style.display = 'block';
            
            this.showNotification('Risk heatmap generated successfully!', 'success');
            
        } catch (error) {
            this.showNotification('Error generating heatmap: ' + error.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-th"></i> Generate Risk Heatmap';
        }
    }
    
    async generateTimelineAnalysis(results) {
        const container = document.getElementById('analyticsContainer');
        const btn = document.getElementById('generateTimelineBtn');
        
        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Timeline...';
            
            const timelineData = this.processTimelineData(results);
            
            container.innerHTML = `
                <h4><i class="fas fa-clock"></i> Timeline Analysis</h4>
                <div class="timeline-container">
                    <div class="timeline-stats">
                        <div class="timeline-stat">
                            <span class="stat-value">${timelineData.totalDuration.toFixed(2)}s</span>
                            <span class="stat-label">Total Duration</span>
                        </div>
                        <div class="timeline-stat">
                            <span class="stat-value">${timelineData.testsCount}</span>
                            <span class="stat-label">Tests Executed</span>
                        </div>
                        <div class="timeline-stat">
                            <span class="stat-value">${timelineData.avgTestDuration.toFixed(2)}s</span>
                            <span class="stat-label">Avg Test Duration</span>
                        </div>
                    </div>
                    <div class="timeline-chart">
                        <canvas id="timelineChart"></canvas>
                    </div>
                    <div class="timeline-tests">
                        <h5>Test Execution Timeline</h5>
                        <div class="test-timeline">
                            ${timelineData.tests.map(test => `
                                <div class="timeline-item ${test.status}">
                                    <div class="timeline-marker"></div>
                                    <div class="timeline-content">
                                        <div class="test-name">${test.name}</div>
                                        <div class="test-duration">${test.duration}s</div>
                                        <div class="test-status">${test.status}</div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
            
            container.style.display = 'block';
            
            // Initialize timeline chart
            this.initializeTimelineChart(timelineData);
            
            this.showNotification('Timeline analysis generated successfully!', 'success');
            
        } catch (error) {
            this.showNotification('Error generating timeline: ' + error.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-clock"></i> Generate Timeline Analysis';
        }
    }
    
    processAnalyticsData(results) {
        const vulnerabilities = this.extractAllVulnerabilities(results);
        
        // Count by severity
        const severityCounts = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            Info: 0
        };
        
        vulnerabilities.forEach(vuln => {
            const severity = vuln.severity || 'Info';
            if (severityCounts.hasOwnProperty(severity)) {
                severityCounts[severity]++;
            }
        });
        
        // Calculate security score
        const totalVulns = vulnerabilities.length;
        const criticalWeight = severityCounts.Critical * 10;
        const highWeight = severityCounts.High * 7;
        const mediumWeight = severityCounts.Medium * 4;
        const lowWeight = severityCounts.Low * 1;
        
        const totalWeight = criticalWeight + highWeight + mediumWeight + lowWeight;
        const securityScore = Math.max(0, 100 - (totalWeight * 2));
        
        // Determine risk level
        let riskLevel = 'Low';
        if (severityCounts.Critical > 0) {
            riskLevel = 'Critical';
        } else if (severityCounts.High > 2) {
            riskLevel = 'High';
        } else if (severityCounts.High > 0) {
            riskLevel = 'Medium';
        }
        
        // Generate risk factors
        const riskFactors = [];
        if (severityCounts.Critical > 0) {
            riskFactors.push(`${severityCounts.Critical} Critical vulnerabilities detected`);
        }
        if (severityCounts.High > 0) {
            riskFactors.push(`${severityCounts.High} High severity vulnerabilities found`);
        }
        if (totalVulns > 10) {
            riskFactors.push(`High vulnerability count: ${totalVulns} total issues`);
        }
        if (riskFactors.length === 0) {
            riskFactors.push('No significant security issues detected');
        }
        
        // Generate recommendations
        const recommendations = [];
        if (severityCounts.Critical > 0) {
            recommendations.push('Immediately address all Critical vulnerabilities');
        }
        if (severityCounts.High > 0) {
            recommendations.push('Prioritize fixing High severity vulnerabilities');
        }
        recommendations.push('Implement Web Application Firewall (WAF)');
        recommendations.push('Regular security testing and monitoring');
        recommendations.push('Security awareness training for development team');
        
        return {
            severityCounts,
            securityScore,
            riskLevel,
            riskFactors,
            recommendations,
            criticalCount: severityCounts.Critical,
            highCount: severityCounts.High,
            mediumCount: severityCounts.Medium,
            lowCount: severityCounts.Low,
            totalVulnerabilities: totalVulns
        };
    }
    
    processHeatmapData(results) {
        const tests = results.tests || {};
        const heatmapData = [];
        
        const categories = {
            'Network Security': ['port_scan', 'ssl_analysis'],
            'Web Application': ['vulnerability_scan', 'advanced_vulnerability_scan'],
            'Infrastructure': ['security_headers', 'technology_detection'],
            'Information Disclosure': ['information_disclosure']
        };
        
        for (const [category, testNames] of Object.entries(categories)) {
            let vulnerabilityCount = 0;
            let criticalCount = 0;
            
            testNames.forEach(testName => {
                if (tests[testName] && tests[testName].details) {
                    const testVulns = tests[testName].details.vulnerabilities || [];
                    vulnerabilityCount += testVulns.length;
                    criticalCount += testVulns.filter(v => v.severity === 'Critical').length;
                }
            });
            
            let riskScore = 0;
            let riskLevel = 'low';
            
            if (criticalCount > 0) {
                riskScore = Math.min(100, criticalCount * 25);
                riskLevel = 'critical';
            } else if (vulnerabilityCount > 3) {
                riskScore = Math.min(100, vulnerabilityCount * 10);
                riskLevel = 'high';
            } else if (vulnerabilityCount > 0) {
                riskScore = vulnerabilityCount * 5;
                riskLevel = 'medium';
            }
            
            heatmapData.push({
                category,
                riskScore,
                riskLevel,
                vulnerabilityCount
            });
        }
        
        return heatmapData;
    }
    
    processTimelineData(results) {
        const tests = results.tests || {};
        const testData = [];
        
        let totalDuration = 0;
        
        for (const [testName, testResult] of Object.entries(tests)) {
            const duration = testResult.duration || 0.1; // Default duration
            totalDuration += duration;
            
            testData.push({
                name: testName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                duration: duration.toFixed(2),
                status: testResult.status || 'unknown',
                timestamp: testResult.timestamp || new Date().toISOString()
            });
        }
        
        return {
            tests: testData,
            totalDuration,
            testsCount: testData.length,
            avgTestDuration: totalDuration / testData.length
        };
    }
    
    extractAllVulnerabilities(results) {
        const vulnerabilities = [];
        const tests = results.tests || {};
        
        for (const [testName, testResult] of Object.entries(tests)) {
            if (testResult.details && testResult.details.vulnerabilities) {
                vulnerabilities.push(...testResult.details.vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    initializeCharts(analyticsData) {
        // Vulnerability distribution pie chart
        const vulnCtx = document.getElementById('vulnerabilityChart');
        if (vulnCtx) {
            new Chart(vulnCtx, {
                type: 'pie',
                data: {
                    labels: Object.keys(analyticsData.severityCounts),
                    datasets: [{
                        data: Object.values(analyticsData.severityCounts),
                        backgroundColor: [
                            '#dc3545', // Critical
                            '#fd7e14', // High
                            '#ffc107', // Medium
                            '#28a745', // Low
                            '#6c757d'  // Info
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
        
        // Test results bar chart
        const testCtx = document.getElementById('testResultsChart');
        if (testCtx) {
            new Chart(testCtx, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: [
                            analyticsData.criticalCount,
                            analyticsData.highCount,
                            analyticsData.mediumCount,
                            analyticsData.lowCount
                        ],
                        backgroundColor: [
                            '#dc3545',
                            '#fd7e14',
                            '#ffc107',
                            '#28a745'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }
    
    initializeTimelineChart(timelineData) {
        const ctx = document.getElementById('timelineChart');
        if (ctx) {
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timelineData.tests.map(t => t.name),
                    datasets: [{
                        label: 'Test Duration (seconds)',
                        data: timelineData.tests.map(t => parseFloat(t.duration)),
                        borderColor: '#007bff',
                        backgroundColor: 'rgba(0, 123, 255, 0.1)',
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new VulnScannerApp();
});

// Add some nice visual effects
document.addEventListener('DOMContentLoaded', () => {
    // Animate feature cards on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animationDelay = '0s';
                entry.target.style.animation = 'fadeInUp 0.6s ease-out forwards';
            }
        });
    }, observerOptions);
    
    const featureCards = document.querySelectorAll('.feature-card');
    featureCards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        card.style.animationDelay = `${index * 0.1}s`;
        observer.observe(card);
    });
});