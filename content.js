// Content Script - Runs on every webpage

// Analyze the current page URL on load
function analyzeCurrentPage() {
  const currentURL = window.location.href;
  
  chrome.runtime.sendMessage(
    { action: 'analyzeURL', url: currentURL },
    (response) => {
      if (response && response.risk_level !== 'safe') {
        // Show warning banner for suspicious sites
        showWarningBanner(response);
      }
    }
  );
}

// Create and show warning banner
function showWarningBanner(results) {
  // Don't show duplicate banners
  if (document.getElementById('phishing-detector-banner')) {
    return;
  }

  const banner = document.createElement('div');
  banner.id = 'phishing-detector-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: ${getRiskColor(results.risk_level)};
    color: white;
    padding: 15px;
    text-align: center;
    z-index: 999999;
    font-family: Arial, sans-serif;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
  `;

  banner.innerHTML = `
    <strong>⚠️ Phishing Detector Warning</strong><br>
    This website has been flagged as <strong>${results.risk_level.toUpperCase()} RISK</strong>
    (Score: ${results.risk_score})<br>
    <small>${results.flags.slice(0, 3).join(' • ')}</small>
    <button id="close-banner" style="margin-left: 15px; padding: 5px 10px; cursor: pointer;">
      Dismiss
    </button>
  `;

  document.body.insertBefore(banner, document.body.firstChild);

  // Add close functionality
  document.getElementById('close-banner').addEventListener('click', () => {
    banner.remove();
  });
}

// Get color based on risk level
function getRiskColor(level) {
  switch(level) {
    case 'high': return '#dc3545';
    case 'medium': return '#fd7e14';
    case 'low': return '#ffc107';
    default: return '#28a745';
  }
}

// Add hover tooltips to all links on the page
function addLinkAnalysis() {
  const links = document.getElementsByTagName('a');
  
  for (let link of links) {
    link.addEventListener('mouseenter', function(e) {
      const href = this.getAttribute('href');
      if (href && href.startsWith('http')) {
        analyzeLinkOnHover(this, href);
      }
    });
  }
}

// Analyze link when user hovers over it
function analyzeLinkOnHover(element, url) {
  // Don't analyze if already has tooltip
  if (element.hasAttribute('data-phishing-analyzed')) {
    return;
  }

  chrome.runtime.sendMessage(
    { action: 'analyzeURL', url: url },
    (response) => {
      if (response && response.risk_score > 20) {
        element.setAttribute('data-phishing-analyzed', 'true');
        element.style.border = `2px solid ${getRiskColor(response.risk_level)}`;
        element.title = `⚠️ Risk: ${response.risk_level} (${response.risk_score}) - ${response.flags[0]}`;
      }
    }
  );
}

// Monitor for dynamically added links
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeName === 'A') {
        const href = node.getAttribute('href');
        if (href && href.startsWith('http')) {
          node.addEventListener('mouseenter', function() {
            analyzeLinkOnHover(this, href);
          });
        }
      }
    });
  });
});

// Initialize
analyzeCurrentPage();
addLinkAnalysis();

// Start observing for dynamic content
observer.observe(document.body, {
  childList: true,
  subtree: true
});

console.log('Phishing Detector content script active');