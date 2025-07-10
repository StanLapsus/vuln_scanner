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
        
        this.currentResults = null;
        this.pollInterval = null;
        
        this.init();
    }
    
    init() {
        this.scanForm.addEventListener('submit', this.handleScanSubmit.bind(this));
        this.exportBtn.addEventListener('click', this.handleExport.bind(this));
    }
    
    async handleScanSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(this.scanForm);
        const target = formData.get('target');
        
        if (!target) {
            this.showError('Please enter a target URL');
            return;
        }
        
        try {
            this.startScan(target);
        } catch (error) {
            this.showError('Error starting scan: ' + error.message);
        }
    }
    
    async startScan(target) {
        // Update UI
        this.scanBtn.disabled = true;
        this.scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
        this.progressSection.style.display = 'block';
        this.resultsSection.style.display = 'none';
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target: target })
            });
            
            if (!response.ok) {
                throw new Error('Failed to start scan');
            }
            
            // Start polling for status
            this.pollScanStatus();
            
        } catch (error) {
            this.showError('Error starting scan: ' + error.message);
            this.resetUI();
        }
    }
    
    async pollScanStatus() {
        this.pollInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/scan_status');
                const status = await response.json();
                
                this.updateProgress(status);
                
                if (status.status === 'complete') {
                    clearInterval(this.pollInterval);
                    this.handleScanComplete(status);
                } else if (status.status === 'error') {
                    clearInterval(this.pollInterval);
                    this.showError('Scan error: ' + status.error);
                    this.resetUI();
                }
                
            } catch (error) {
                console.error('Error polling scan status:', error);
            }
        }, 1000);
    }
    
    updateProgress(status) {
        const progress = status.progress || 0;
        this.progressFill.style.width = progress + '%';
        
        if (status.status === 'running') {
            if (progress < 50) {
                this.progressText.textContent = 'Initializing security tests...';
            } else {
                this.progressText.textContent = 'Running vulnerability scans...';
            }
        } else if (status.status === 'complete') {
            this.progressText.textContent = 'Scan completed successfully!';
        }
    }
    
    handleScanComplete(status) {
        this.currentResults = status.results;
        this.displayResults(status.results);
        this.resetUI();
        
        // Show success message
        this.progressText.textContent = `Scan completed! Results saved to ${status.filename}`;
        setTimeout(() => {
            this.progressSection.style.display = 'none';
        }, 3000);
    }
    
    displayResults(results) {
        this.resultsGrid.innerHTML = '';
        
        for (const [testName, result] of Object.entries(results)) {
            const resultElement = this.createResultElement(testName, result);
            this.resultsGrid.appendChild(resultElement);
        }
        
        this.resultsSection.style.display = 'block';
        this.resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    createResultElement(testName, result) {
        const div = document.createElement('div');
        div.className = 'result-item';
        
        const status = this.getResultStatus(result);
        const formattedResult = this.formatResult(result);
        
        div.innerHTML = `
            <div class="result-header">
                <div class="result-title">${this.formatTestName(testName)}</div>
                <div class="result-status ${status.class}">${status.text}</div>
            </div>
            <div class="result-content">${formattedResult}</div>
        `;
        
        return div;
    }
    
    formatTestName(testName) {
        return testName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
    
    getResultStatus(result) {
        const resultStr = String(result).toLowerCase();
        
        if (resultStr.includes('error') || resultStr.includes('failed')) {
            return { class: 'status-error', text: 'Error' };
        } else if (resultStr.includes('vulnerability') || resultStr.includes('found') || resultStr.includes('detected')) {
            return { class: 'status-warning', text: 'Found' };
        } else {
            return { class: 'status-success', text: 'Complete' };
        }
    }
    
    formatResult(result) {
        if (typeof result === 'object') {
            return JSON.stringify(result, null, 2);
        } else if (Array.isArray(result)) {
            return result.length > 0 ? result.join('\n') : 'No items found';
        } else {
            return String(result);
        }
    }
    
    handleExport() {
        if (!this.currentResults) {
            this.showError('No scan results to export');
            return;
        }
        
        const dataStr = JSON.stringify(this.currentResults, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `scan_results_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        URL.revokeObjectURL(url);
    }
    
    resetUI() {
        this.scanBtn.disabled = false;
        this.scanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
    }
    
    showError(message) {
        // Simple error display - you could enhance this with a proper notification system
        alert(message);
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