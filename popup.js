// Popup Script

class PopupManager {
  constructor() {
    this.stats = {
      totalChecks: 0,
      threatsBlocked: 0
    };
    this.history = [];
    this.loadStats();
    this.loadHistory();
    this.init();
  }

  init() {
    // Analyze current tab on popup open
    this.analyzeCurrentTab();
    
    // Set up event listeners
    document.getElementById('check-btn').addEventListener('click', () => this.checkManualURL());
    document.getElementById('manual-url').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.checkManualURL();
    });
    document.getElementById('clear-history').addEventListener('click', () => this.clearHistory());
    
    // Update stats display
    this.updateStatsDisplay();
  }

  async analyzeCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (!tab || !tab.url) {
        this.showError('current-result', 'Cannot analyze this page');
        return;
      }

      // Display current URL
      document.getElementById('current-url').textContent = tab.url;

      // Send analysis request to background script
      chrome.runtime.sendMessage(
        { action: 'analyzeURL', url: tab.url },
        (response) => {
          if (response) {
            this.displayResult('current-result', response);
            this.addToHistory(response);
          }
        }
      );
    } catch (error) {
      console.error('Error analyzing current tab:', error);
      this.showError('current-result', 'Analysis failed');
    }
  }

  async checkManualURL() {
    const input = document.getElementById('manual-url');
    const url = input.value.trim();

    if (!url) {
      alert('Please enter a URL');
      return;
    }

    // Add protocol if missing
    const fullURL = url.startsWith('http') ? url : 'https://' + url;

    // Show loading
    const resultDiv = document.getElementById('manual-result');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = '<div class="loading">Analyzing</div>';

    // Analyze URL
    chrome.runtime.sendMessage(
      { action: 'analyzeURL', url: fullURL },
      (response) => {
        if (response) {
          this.displayResult('manual-result', response);
          this.addToHistory(response);
          input.value = ''; // Clear input
        }
      }
    );
  }

  displayResult(elementId, results) {
    const resultDiv = document.getElementById(elementId);
    resultDiv.classList.remove('hidden');

    // Risk badge
    const riskClass = `risk-${results.risk_level}`;
    const scoreClass = `score-${results.risk_level}`;

    // Build flags list
    let flagsHTML = '';
    if (results.flags && results.flags.length > 0) {
      flagsHTML = '<ul class="flags-list">';
      results.flags.forEach(flag => {
        flagsHTML += `<li>⚠️ ${flag}</li>`;
      });
      flagsHTML += '</ul>';
    } else {
      flagsHTML = '<p style="color: #28a745; text-align: center;">✅ No issues detected</p>';
    }

    // Risk description
    const riskDescriptions = {
      safe: 'This URL appears to be safe.',
      low: 'Minor concerns detected. Proceed with caution.',
      medium: 'Multiple suspicious patterns detected. Be careful!',
      high: 'High risk of phishing! Avoid this site.'
    };

    resultDiv.innerHTML = `
      <div class="risk-badge ${riskClass}">${results.risk_level} Risk</div>
      <div class="risk-score ${scoreClass}">${results.risk_score}</div>
      <p style="text-align: center; color: #666; font-size: 13px; margin-bottom: 15px;">
        ${riskDescriptions[results.risk_level]}
      </p>
      ${flagsHTML}
    `;

    // Update stats if it's a threat
    if (results.risk_level === 'medium' || results.risk_level === 'high') {
      this.stats.threatsBlocked++;
      this.saveStats();
      this.updateStatsDisplay();
    }
  }

  showError(elementId, message) {
    const resultDiv = document.getElementById(elementId);
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = `<p style="color: #dc3545; text-align: center;">${message}</p>`;
  }

  addToHistory(results) {
    // Increment total checks
    this.stats.totalChecks++;
    this.saveStats();
    this.updateStatsDisplay();

    // Add to history
    const historyItem = {
      url: results.url,
      risk_level: results.risk_level,
      risk_score: results.risk_score,
      timestamp: new Date().toISOString(),
      flags: results.flags.slice(0, 2) // Keep only first 2 flags
    };

    this.history.unshift(historyItem); // Add to beginning
    if (this.history.length > 10) {
      this.history = this.history.slice(0, 10); // Keep only last 10
    }

    this.saveHistory();
    this.updateHistoryDisplay();
  }

  updateHistoryDisplay() {
    const historyList = document.getElementById('history-list');

    if (this.history.length === 0) {
      historyList.innerHTML = '<div class="empty-state">No recent checks</div>';
      return;
    }

    historyList.innerHTML = '';
    this.history.forEach(item => {
      const historyItem = document.createElement('div');
      historyItem.className = `history-item ${item.risk_level}`;

      const domain = this.extractDomain(item.url);
      const timeAgo = this.getTimeAgo(item.timestamp);

      historyItem.innerHTML = `
        <div class="history-url">${domain}</div>
        <div class="history-meta">
          <span>Risk: ${item.risk_level.toUpperCase()}</span>
          <span>${timeAgo}</span>
        </div>
      `;

      historyList.appendChild(historyItem);
    });
  }

  extractDomain(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url.substring(0, 40) + '...';
    }
  }

  getTimeAgo(timestamp) {
    const now = new Date();
    const then = new Date(timestamp);
    const diff = Math.floor((now - then) / 1000); // seconds

    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  updateStatsDisplay() {
    document.getElementById('total-checks').textContent = this.stats.totalChecks;
    document.getElementById('threats-blocked').textContent = this.stats.threatsBlocked;
  }

  clearHistory() {
    if (confirm('Clear all history?')) {
      this.history = [];
      this.saveHistory();
      this.updateHistoryDisplay();
    }
  }

  // Storage methods
  saveStats() {
    chrome.storage.local.set({ stats: this.stats });
  }

  loadStats() {
    chrome.storage.local.get('stats', (data) => {
      if (data.stats) {
        this.stats = data.stats;
        this.updateStatsDisplay();
      }
    });
  }

  saveHistory() {
    chrome.storage.local.set({ history: this.history });
  }

  loadHistory() {
    chrome.storage.local.get('history', (data) => {
      if (data.history) {
        this.history = data.history;
        this.updateHistoryDisplay();
      }
    });
  }
}

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  new PopupManager();
});