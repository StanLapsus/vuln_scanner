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
        
        for (const [testName, result] of Object.entries(results)) {
            const resultElement = this.createResultElement(testName, result);
            this.resultsGrid.appendChild(resultElement);
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
    
    createResultElement(testName, result) {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.setAttribute('tabindex', '0');
        div.setAttribute('role', 'article');
        
        const status = this.getResultStatus(result);
        const formattedResult = this.formatResult(result);
        
        div.innerHTML = `
            <div class="result-header">
                <div class="result-title">${this.formatTestName(testName)}</div>
                <div class="result-status ${status.class}" role="status">${status.text}</div>
            </div>
            <div class="result-content">${formattedResult}</div>
        `;
        
        // Add click handler for expansion
        div.addEventListener('click', () => {
            div.classList.toggle('expanded');
        });
        
        return div;
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