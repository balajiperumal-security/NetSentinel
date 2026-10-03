# NetSentinel

## Lightweight Network Behavior & Threat Detection System

NetSentinel is a lightweight defensive cybersecurity system designed to monitor network traffic, identify suspicious behavior, assign risk levels, and present security information through a web dashboard.

## Objectives

- Capture network traffic
- Extract useful network features
- Log observed traffic
- Detect potentially suspicious activity
- Assign risk levels
- Explain detected activity
- Provide recommended defensive actions
- Generate a security report
- Display results through a dashboard

## Technologies Used

- Python
- Scapy
- Flask
- Regular Expressions
- Linux
- HTML
- CSS

## System Modules

### 1. Packet Capture
`capture.py`

Captures network packets and extracts:
- Source IP
- Destination IP
- Protocol
- Source port
- Destination port
- Packet size

### 2. Traffic Detection
`detector.py`

Monitors network activity and records observed traffic.

### 3. Risk Engine
`risk_engine.py`

Analyzes logged traffic and assigns risk levels based on configured thresholds.

### 4. Response Engine
`response_engine.py`

Provides:
- Risk explanation
- Recommended defensive action
- Verification guidance

### 5. Dashboard
`app.py`

Provides a web-based interface showing:
- Total events
- High-risk events
- Medium-risk events
- Low-risk events
- Recent traffic
- Security analysis

### 6. Report Generator
`report.py`

Generates:

`netsentinel_report.txt`

containing the security analysis and traffic summary.

## Project Workflow

Network Traffic
        ↓
Packet Capture
        ↓
Feature Extraction
        ↓
Traffic Logging
        ↓
Risk Analysis
        ↓
Security Explanation
        ↓
Dashboard + Report

## Current Status

NetSentinel successfully captures network traffic, logs observed events, performs basic risk analysis, displays results through a Flask dashboard, and generates a security report.

## Future Improvements

- More behavioral detection rules
- SQLite database
- Authentication for dashboard
- Better visualization
- Configurable risk thresholds
- Controlled defensive response mechanisms
- Optional AI-assisted security explanations

## Disclaimer

NetSentinel is intended for authorized defensive monitoring and cybersecurity learning environments only.
