# Phishing Detector – Chrome Extension

### A lightweight, real-time phishing detection Chrome extension that analyzes URLs and page content to help users stay safe from malicious websites.

## 📌 Overview
### Phishing attacks are one of the most common online threats. This Chrome extension provides an instant safety check for any website you visit by analyzing the structure of the URL and performing rule-based checks to detect suspicious patterns.
### It is designed to be simple, transparent, and fast — perfect for learning, experimenting, or extending into a more advanced security tool.

## 🚀 Features
### Real-time URL Scanning: Automatically evaluates the currently active tab.
### Rule-Based Detection: Flags common phishing indicators (strange domain patterns, excessive hyphens, suspicious TLDs, and more).
### Browser Action Popup: Click the extension icon to instantly check any page.
### Background Service Worker: Handles URL processing and communication with tabs.
### Clean UI: Simple popup interface for quick results.
### Works Everywhere: Supports both HTTP and HTTPS sites.

## 🧠 How It Works
### 1. The background script retrieves the active tab’s URL.
### 2. A set of predefined phishing-risk rules evaluate the URL:
#### a. Unusually long URLs
#### b. Suspicious domain patterns
#### c. Known malicious or uncommon TLDs
### 3. Excessive numbers, symbols, or deceptive formatting

### The result is displayed immediately in the popup window.

## 🛠️ Tech Stack

### JavaScript (Vanilla) – core logic
### HTML/CSS – popup interface
### Chrome Extensions API (Manifest V3)
### Service Workers

## 🔧 Installation (Local Development)
### 1. Download or clone the repository
### 2. In Google Chrome, go to Chrome Extensions
### 3. Enable Developer Mode (top-right corner).
### 4. Click Load Unpacked.
### 5. Select the project folder.
### 6. The extension will appear in your toolbar.

## 🧪 Testing
### The project includes a test_detector.html file for testing phishing detection rules.
### Open the file in your browser and run test cases against the detection logic.

## 🗺️ Roadmap
### Add machine learning–based phishing prediction
### Integrate external threat-intelligence APIs
### Show detailed breakdowns of phishing indicators
### Add history logging for past scans
### Improve UI/UX with detailed risk scoring

## 👥 Authors
### Hammad Siddique
### Abdul Moiz Ghazanfar

## 🙌 Contributions
### Contributions, ideas, and improvements are welcome!
### Feel free to open issues or submit pull requests.

## ⭐ Support
### If you find this useful, consider giving the repository a star, it really helps!

