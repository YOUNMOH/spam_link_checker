// DOM Elements
const urlCheckForm = document.getElementById('urlCheckForm');
const urlInput = document.getElementById('urlInput');
const clearBtn = document.getElementById('clearBtn');
const checkBtn = document.getElementById('checkBtn');
const quickCheckBtn = document.getElementById('quickCheckBtn');
const batchCheckBtn = document.getElementById('batchCheckBtn');
const processBatchBtn = document.getElementById('processBatchBtn');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const loadingSpinner = document.getElementById('loadingSpinner');
const resultsSection = document.getElementById('resultsSection');
const errorMessage = document.getElementById('errorMessage');
const batchSection = document.getElementById('batchSection');
const recentChecks = document.getElementById('recentChecks');
const totalChecks = document.getElementById('totalChecks');
const todayChecks = document.getElementById('todayChecks');

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    loadStatistics();
    loadRecentChecks();
});

// Event Listeners
urlCheckForm.addEventListener('submit', function(e) {
    e.preventDefault();
    checkUrl();
});

clearBtn.addEventListener('click', function() {
    urlInput.value = '';
    urlInput.focus();
});

quickCheckBtn.addEventListener('click', function() {
    checkUrl();
});

batchCheckBtn.addEventListener('click', function() {
    batchSection.style.display = batchSection.style.display === 'none' ? 'block' : 'none';
});

processBatchBtn.addEventListener('click', processBatchUrls);

clearHistoryBtn.addEventListener('click', clearHistory);

// Main URL Check Function
async function checkUrl() {
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL to check');
        return;
    }

    showLoading();
    hideError();
    hideResults();

    try {
        const response = await fetch('/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'An error occurred');
        }

        displayResults(data);
        loadRecentChecks();
        loadStatistics();
        
    } catch (error) {
        showError(error.message);
    } finally {
        hideLoading();
    }
}

// Display Results
function displayResults(result) {
    document.getElementById('checkedUrl').textContent = result.url;
    
    // Display risk metrics
    const riskMetrics = document.getElementById('riskMetrics');
    const statusClass = getStatusClass(result.status);
    
    riskMetrics.innerHTML = `
        <div class="col-md-4">
            <div class="metric-card ${statusClass}">
                <div class="stat-number">${result.status}</div>
                <div class="stat-label">Status</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="metric-card">
                <div class="stat-number">${result.risk_score}/100</div>
                <div class="stat-label">Risk Score</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="metric-card">
                <div class="stat-number">${result.details.length}</div>
                <div class="stat-label">Issues Found</div>
            </div>
        </div>
    `;

    // Display analysis details
    const analysisDetails = document.getElementById('analysisDetails');
    analysisDetails.innerHTML = result.details.map(detail => {
        const detailClass = getDetailClass(detail);
        return `<div class="risk-item ${detailClass}">${detail}</div>`;
    }).join('');

    // Display recommendations
    const recommendations = document.getElementById('recommendations');
    recommendations.innerHTML = getRecommendations(result.status);

    resultsSection.style.display = 'block';
}

// Get status class for styling
function getStatusClass(status) {
    switch(status) {
        case 'High Risk': return 'danger';
        case 'Suspicious': return 'warning';
        case 'Low Risk': return 'warning';
        case 'Likely Safe': return 'safe';
        default: return '';
    }
}

// Get detail class for styling
function getDetailClass(detail) {
    if (detail.includes('❌') || detail.toLowerCase().includes('blacklisted')) {
        return 'danger';
    } else if (detail.toLowerCase().includes('suspicious') || detail.toLowerCase().includes('risk')) {
        return 'warning';
    } else {
        return 'info';
    }
}

// Get recommendations based on status
function getRecommendations(status) {
    const recommendations = {
        'High Risk': `
            <div class="alert alert-danger">
                <h6>🚨 CRITICAL WARNING</h6>
                <p class="mb-2">This URL appears to be highly risky!</p>
                <ul class="mb-0">
                    <li>Avoid clicking on this link</li>
                    <li>Do not enter any personal information</li>
                    <li>Report to your IT security team</li>
                    <li>Delete the message containing this link</li>
                </ul>
            </div>
        `,
        'Suspicious': `
            <div class="alert alert-warning">
                <h6>⚠️ CAUTION</h6>
                <p class="mb-2">This URL shows suspicious characteristics</p>
                <ul class="mb-0">
                    <li>Verify the source before clicking</li>
                    <li>Use a VPN if you must visit</li>
                    <li>Access from a secure device</li>
                    <li>Don't enter sensitive information</li>
                </ul>
            </div>
        `,
        'Low Risk': `
            <div class="alert alert-info">
                <h6>ℹ️ LOW RISK</h6>
                <p class="mb-2">Some minor concerns detected</p>
                <ul class="mb-0">
                    <li>Generally safe but be cautious</li>
                    <li>Check for HTTPS encryption</li>
                    <li>Verify website reputation</li>
                    <li>Look for trust indicators</li>
                </ul>
            </div>
        `,
        'Likely Safe': `
            <div class="alert alert-success">
                <h6>✅ SAFE</h6>
                <p class="mb-2">This URL appears to be legitimate</p>
                <ul class="mb-0">
                    <li>No major security concerns detected</li>
                    <li>Standard precautions still recommended</li>
                    <li>Always be vigilant online</li>
                    <li>Keep security software updated</li>
                </ul>
            </div>
        `
    };

    return recommendations[status] || recommendations['Likely Safe'];
}

// Batch URL Processing
async function processBatchUrls() {
    const urlsText = document.getElementById('batchUrls').value.trim();
    
    if (!urlsText) {
        alert('Please enter URLs to process');
        return;
    }

    const urls = urlsText.split('\n')
        .map(url => url.trim())
        .filter(url => url.length > 0)
        .slice(0, 10);

    if (urls.length === 0) {
        alert('Please enter valid URLs');
        return;
    }

    processBatchBtn.disabled = true;
    processBatchBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';

    const batchResults = document.getElementById('batchResults');
    batchResults.innerHTML = '<div class="text-center"><div class="spinner-border text-primary"></div><p>Processing batch URLs...</p></div>';

    try {
        const results = [];
        
        for (let i = 0; i < urls.length; i++) {
            const url = urls[i];
            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ url: url })
                });

                if (response.ok) {
                    const result = await response.json();
                    results.push(result);
                } else {
                    results.push({
                        url: url,
                        status: 'Error',
                        risk_score: 0,
                        error: 'Failed to check URL'
                    });
                }
            } catch (error) {
                results.push({
                    url: url,
                    status: 'Error',
                    risk_score: 0,
                    error: error.message
                });
            }
        }

        displayBatchResults(results);
        loadRecentChecks();
        loadStatistics();
        
    } catch (error) {
        batchResults.innerHTML = `<div class="alert alert-danger">Error processing batch: ${error.message}</div>`;
    } finally {
        processBatchBtn.disabled = false;
        processBatchBtn.innerHTML = '<i class="fas fa-play"></i> Process Batch URLs';
    }
}

// Display Batch Results
function displayBatchResults(results) {
    const batchResults = document.getElementById('batchResults');
    
    const tableHTML = `
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(result => `
                        <tr>
                            <td class="text-truncate" style="max-width: 200px;" title="${result.url}">
                                ${result.url}
                            </td>
                            <td>
                                <span class="badge ${getStatusBadgeClass(result.status)}">
                                    ${result.status}
                                </span>
                            </td>
                            <td>${result.risk_score}/100</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
    
    batchResults.innerHTML = tableHTML;
}

// Get badge class for status
function getStatusBadgeClass(status) {
    switch(status) {
        case 'High Risk': return 'bg-danger';
        case 'Suspicious': return 'bg-warning text-dark';
        case 'Low Risk': return 'bg-info';
        case 'Likely Safe': return 'bg-success';
        default: return 'bg-secondary';
    }
}

// Load Recent Checks
async function loadRecentChecks() {
    try {
        const response = await fetch('/history');
        const checks = await response.json();

        if (checks.length === 0) {
            recentChecks.innerHTML = '<p class="text-muted text-center">No recent checks</p>';
            return;
        }

        recentChecks.innerHTML = checks.map(check => `
            <div class="recent-check-item ${getStatusClass(check.status)}">
                <div class="recent-check-time">${formatTime(check.created_at)}</div>
                <div class="fw-bold text-truncate" title="${check.url}">${check.url}</div>
                <div class="small">
                    Score: <strong>${check.risk_score}/100</strong> • 
                    Status: <strong>${check.status}</strong>
                </div>
            </div>
        `).join('');
        
    } catch (error) {
        console.error('Error loading recent checks:', error);
    }
}

// Load Statistics
async function loadStatistics() {
    // For now, we'll just show placeholder values
    // In a real app, you'd fetch these from an API endpoint
    totalChecks.textContent = '...';
    todayChecks.textContent = '...';
}

// Clear History
async function clearHistory() {
    if (!confirm('Are you sure you want to clear your check history?')) {
        return;
    }

    try {
        const response = await fetch('/clear-history', {
            method: 'POST'
        });

        if (response.ok) {
            loadRecentChecks();
            showTemporaryMessage('History cleared successfully', 'success');
        } else {
            throw new Error('Failed to clear history');
        }
    } catch (error) {
        showTemporaryMessage('Error clearing history: ' + error.message, 'danger');
    }
}

// Utility Functions
function showLoading() {
    loadingSpinner.style.display = 'block';
    checkBtn.disabled = true;
    quickCheckBtn.disabled = true;
}

function hideLoading() {
    loadingSpinner.style.display = 'none';
    checkBtn.disabled = false;
    quickCheckBtn.disabled = false;
}

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.style.display = 'block';
}

function hideError() {
    errorMessage.style.display = 'none';
}

function hideResults() {
    resultsSection.style.display = 'none';
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString() + ' ' + date.toLocaleDateString();
}

function showTemporaryMessage(message, type) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.querySelector('.container').insertBefore(alert, document.querySelector('.container').firstChild);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

// Auto-focus URL input
urlInput.focus();