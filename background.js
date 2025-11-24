// Phishing Detection Engine - Person A's Work + API Integration

class PhishingDetector {
  constructor() {
    // Suspicious TLDs commonly used in phishing
    this.suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
    
    // Common phishing keywords
    this.phishingKeywords = [
      'verify', 'account', 'suspended', 'confirm', 'urgent', 'security',
      'banking', 'paypal', 'signin', 'login', 'update', 'secure',
      'ebay', 'alert', 'locked', 'unusual', 'click', 'immediately'
    ];
    
    // Legitimate domains for comparison
    this.legitimateDomains = [
      'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
      'microsoft.com', 'apple.com', 'netflix.com', 'instagram.com'
    ];

    // Google Safe Browsing API Key (FREE - 10,000 requests/day)
    // Get your key at: https://developers.google.com/safe-browsing/v4/get-started
    this.SAFE_BROWSING_API_KEY = 'YOUR_API_KEY_HERE'; // Replace with your key
    this.apiEnabled = false; // Set to true when you add your API key
  }

  // Main analysis function
  analyzeURL(url) {
    const results = {
      url: url,
      risk_score: 0,
      risk_level: 'safe',
      flags: [],
      details: {}
    };

    try {
      const urlObj = new URL(url);
      
      // Run all detection checks
      this.checkIPAddress(urlObj, results);
      this.checkURLLength(urlObj, results);
      this.checkSubdomains(urlObj, results);
      this.checkSuspiciousTLD(urlObj, results);
      this.checkHTTPS(urlObj, results);
      this.checkPhishingKeywords(urlObj, results); // Check keywords before typosquatting
      this.checkTyposquatting(urlObj, results);
      this.checkSuspiciousCharacters(urlObj, results);
      this.checkPortNumber(urlObj, results);
      
      // Calculate final risk level
      this.calculateRiskLevel(results);
      
    } catch (e) {
      results.flags.push('Invalid URL format');
      results.risk_score += 50;
      results.risk_level = 'high';
    }

    return results;
  }

  // Check if URL uses IP address instead of domain
  checkIPAddress(urlObj, results) {
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(urlObj.hostname)) {
      results.risk_score += 30;
      results.flags.push('Uses IP address instead of domain name');
      results.details.usesIP = true;
    }
  }

  // Check for suspicious URL length
  checkURLLength(urlObj, results) {
    if (urlObj.href.length > 75) {
      results.risk_score += 15;
      results.flags.push('Unusually long URL');
      results.details.urlLength = urlObj.href.length;
    }
  }

  // Check for excessive subdomains
  checkSubdomains(urlObj, results) {
    const parts = urlObj.hostname.split('.');
    const subdomainCount = parts.length - 2; // Subtract domain and TLD
    
    if (subdomainCount > 2) {
      results.risk_score += 20;
      results.flags.push(`Excessive subdomains (${subdomainCount})`);
      results.details.subdomains = subdomainCount;
    }
  }

  // Check for suspicious TLDs
  checkSuspiciousTLD(urlObj, results) {
    const hostname = urlObj.hostname.toLowerCase();
    for (let tld of this.suspiciousTLDs) {
      if (hostname.endsWith(tld)) {
        results.risk_score += 25;
        results.flags.push(`Suspicious TLD: ${tld}`);
        results.details.suspiciousTLD = tld;
        break;
      }
    }
  }

  // Check if site uses HTTPS
  checkHTTPS(urlObj, results) {
    if (urlObj.protocol !== 'https:') {
      results.risk_score += 20;
      results.flags.push('Does not use HTTPS');
      results.details.hasHTTPS = false;
    } else {
      results.details.hasHTTPS = true;
    }
  }

  // Check for typosquatting attempts
  checkTyposquatting(urlObj, results) {
    const hostname = urlObj.hostname.toLowerCase();
    
    for (let legitimate of this.legitimateDomains) {
      // Only flag if hostname contains the brand name BUT is not the exact legitimate domain
      const brandName = legitimate.replace('.com', '').replace('.org', '');
      
      // Check if it contains the brand name but isn't the legitimate domain itself
      if (hostname.includes(brandName) && hostname !== legitimate && !hostname.endsWith('.' + legitimate)) {
        results.risk_score += 35;
        results.flags.push(`Possible typosquatting of ${legitimate}`);
        results.details.typosquatting = legitimate;
        break;
      }
    }
    
    // Check for common character substitutions (but be more strict)
    // Only flag if there are actual substitution patterns like g00gle, paypa1
    const substitutionPattern = /([a-z])[0o]([a-z])|([a-z])[1il]([a-z])/i;
    if (substitutionPattern.test(hostname)) {
      results.risk_score += 15;
      results.flags.push('Contains confusing character substitutions (0/O, 1/l/I)');
    }
  }

  // Check for phishing keywords in URL
  checkPhishingKeywords(urlObj, results) {
    const fullURL = urlObj.href.toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname.toLowerCase();
    const searchParams = urlObj.search.toLowerCase();
    
    const foundKeywords = [];
    
    for (let keyword of this.phishingKeywords) {
      // Check in hostname, path, and query parameters
      if (hostname.includes(keyword) || path.includes(keyword) || searchParams.includes(keyword)) {
        foundKeywords.push(keyword);
      }
    }
    
    if (foundKeywords.length > 0) {
      const score = foundKeywords.length * 10; // Increased from 5 to 10 per keyword
      results.risk_score += score;
      results.flags.push(`Contains phishing keywords: ${foundKeywords.join(', ')}`);
      results.details.phishingKeywords = foundKeywords;
    }
  }

  // Check for suspicious characters
  checkSuspiciousCharacters(urlObj, results) {
    const hostname = urlObj.hostname;
    
    // Check for @ symbol (can hide real domain)
    if (urlObj.href.includes('@')) {
      results.risk_score += 30;
      results.flags.push('Contains @ symbol (may hide real domain)');
    }
    
    // Check for excessive hyphens
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount > 3) {
      results.risk_score += 15;
      results.flags.push('Excessive hyphens in domain');
    }
    
    // Check for double slashes in path (can indicate redirection)
    if (urlObj.pathname.includes('//')) {
      results.risk_score += 20;
      results.flags.push('Double slashes in path (possible redirection)');
    }
  }

  // Check for non-standard ports
  checkPortNumber(urlObj, results) {
    const port = urlObj.port;
    if (port && port !== '80' && port !== '443') {
      results.risk_score += 15;
      results.flags.push(`Non-standard port: ${port}`);
      results.details.port = port;
    }
  }

  // Calculate final risk level based on score
  calculateRiskLevel(results) {
    if (results.risk_score >= 70) {
      results.risk_level = 'high';
    } else if (results.risk_score >= 40) {
      results.risk_level = 'medium';
    } else if (results.risk_score >= 20) {
      results.risk_level = 'low';
    } else {
      results.risk_level = 'safe';
    }
  }
}

// Initialize detector
const detector = new PhishingDetector();

// Listen for messages from popup or content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeURL') {
    const results = detector.analyzeURL(request.url);
    sendResponse(results);
  }
  return true; // Keep channel open for async response
});

// Analyze current tab when extension icon is clicked
chrome.action.onClicked.addListener((tab) => {
  if (tab.url) {
    const results = detector.analyzeURL(tab.url);
    // Store results for popup to retrieve
    chrome.storage.local.set({ lastAnalysis: results });
  }
});

console.log('Phishing Detector background script loaded');