# Apache Security Scanner

This project is designed to monitor an Apache server for security issues, generate alerts, and send them via email and to Elasticsearch. It also blocks suspicious IPs and quarantines malicious processes.

---

## Features

- **Apache Server Monitoring**:
  - Checks Apache service status.
  - Verifies if security modules (e.g., ModSecurity, ModEvasive) are enabled.
- **Bad Traffic Detection**:
  - Analyzes Apache access logs for suspicious activity (e.g., `404`, `500`, `403` errors, SQL injection, XSS, brute force attempts).
- **Alerting**:
  - Sends email alerts when bad traffic is detected.
  - Sends logs to Elasticsearch for centralized monitoring.
- **Automated Response**:
  - Blocks suspicious IPs using `iptables`.
  - Quarantines malicious processes by killing them.

---

## Prerequisites

- **Python 3.x**
- **Apache Server** (for testing and monitoring)
- **Elasticsearch** (optional, for storing logs)
- **SMTP Server** (for sending email alerts)

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/moonshot7/apache-security-scanner.git
   cd apache-security-scanner
