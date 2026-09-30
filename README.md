# 🛡️️ Cybersecurity Awareness & Threat Intelligence Dashboard
An industry-oriented defensive cybersecurity analytics platform that ingests synthetic threat telemetry, normalizes and enriches Indicators of Compromise (IOCs), calculates decoupled risk and confidence scores, maps adversary behaviors to the MITRE ATT&CK® framework, and provides interactive human-layer awareness training.

## 📌 Executive Summary
Modern Security Operations Centers (SOCs) require a continuous balance between automated indicator triage and human cyber hygiene. This defensive dashboard bridges this gap by unifying technical threat intelligence processing with employee-facing awareness learning and assessment workflows.

> **Defensive Safety Guarantee:** This project is designed exclusively for educational, research, and defensive security evaluation. It operates entirely on RFC-compliant synthetic indicators and local telemetry without executing malware, conducting port scanning, probing remote networks, or establishing connections to suspicious command-and-control infrastructure.

## 🚀 Key Architectural Capabilities

- **IOC Normalization & Validation:** Validates formats for IPv4 (RFC 5737), IPv6, FQDNs (RFC 2606), URLs, cryptographic hashes (MD5, SHA-1, SHA-256), and CVE IDs.
- **Decoupled Risk & Confidence Scoring:** Calculates an empirical 0–100 Risk Score (Severity 35%, Confidence 25%, Source Reliability 20%, Telemetry Frequency 20%) while evaluating evidence confidence independently.
- **Adversary Behavior Mapping:** Direct alignment of synthetic threat categories to MITRE ATT&CK enterprise tactics and technique IDs (e.g., Phishing `T1566`, OS Credential Dumping `T1003`).
- **Telemetry Correlation:** Clusters indicators sharing infrastructure patterns, campaign context, or adversary tactics to reduce SOC analyst alert fatigue.
- **Human-Layer Defense:** Modular awareness curriculum (Phishing, MFA, Ransomware containment) paired with an interactive 30+ question scoring evaluation engine.

## 🏗️ System Architecture

```text
Synthetic Defensive Feeds (RFC Compliant)
               ↓
    Ingestion & Data Normalization
               ↓
  IOC Validation (ioc_validator.py)
               ↓
  Context Enrichment & MITRE Mapping (attack_mapper.py)
               ↓
 Risk & Confidence Composite Engine (risk_engine.py)
               ↓
        SQLite Telemetry DB
         ┌─────┴──────────────┐
         ↓                    ↓
  Flask REST API (app.py)    Awareness Module & Quiz
         ↓                    ↓
  SOC Dashboard (Chart.js)   Defensive Recommendations
  ```

## 💻 Tech Stack

Backend: Python 3.11+, Flask (Modular Blueprints)
Data Engineering: Pandas, SQLite3
Frontend: HTML5, Modern CSS3 (Dark-mode SOC Theme), Vanilla JavaScript (ES6+)
Data Visualization: Chart.js
Testing & Verification: Pytest

## 📂 Project Structure

```
Cybersecurity-Threat-Intelligence-Dashboard/
│
├── backend/
│   ├── app.py                     # Main application entry point
│   ├── database.py                # SQLite schema and migration logic
│   ├── models/                    # Data dataclasses and schemas
│   ├── routes/                    # Flask blueprints (threats, awareness)
│   ├── services/                  # Business logic (IOC validation, scoring, correlation)
│   └── utils/                     # Sanitization & helper utilities
│
├── frontend/
│   ├── index.html                 # Main SOC Analytics Dashboard
│   ├── threat-dashboard.html      # Indicator triage stream
│   ├── threat-details.html        # Forensic deep-dive view
│   ├── awareness.html             # Hygiene learning center
│   ├── quiz.html                  # Interactive assessment portal
│   ├── css/style.css              # Custom responsive stylesheet
│   └── js/                        # Client-side renderers & charts
│
├── awareness/
│   ├── modules.json               # Educational training content
│   └── quiz_questions.json        # Assessment dataset
│
├── data/
│   ├── generate_threat_data.py    # 2,200+ record synthetic data generator
│   ├── threat_intelligence_dataset.csv
│   └── vulnerabilities.csv
│
├── tests/
│   └── test_dashboard.py          # Automated verification test suite
│
├── requirements.txt
├── .gitignore
└── README.md
```

## ⚙️ Installation & Local Setup

1. Create and Activate Virtual Environment
python -m venv venv
venv\Scripts\activate

2. Install Dependencies
pip install -r requirements.txt

3. Generate Synthetic Telemetry & Seed Database
python data/generate_threat_data.py
python backend/database.py

4. Run Automated Tests
python -m pytest tests/test_dashboard.py -v

5. Start the Application
python -m backend.app

Open browser and navigate to http://127.0.0.1:5000.

## 🧪 Testing & Validation

The test suite validates:
Syntactic verification for IPv4, IPv6, Domains, URLs, Hashes, and CVE identifiers.
Composite risk scoring algorithms across variable severity levels.
Telemetry clustering and alert fatigue deduplication.
API response contracts, pagination, and database persistence.

## 📊 Security & Ethical Controls

No External Socket Execution: Queries do not trigger HTTP requests or DNS queries to remote infrastructure.
Defensive Documentation Ranges: Utilizes designated documentation address spaces (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and reserved TLDs (.example, .invalid).
Evidence Distinction: Strictly maintains separation between Observation, Indicator, Alert, and Incident to avoid false-positive alert cascades.

## 📜 License
Distributed under the MIT License. See LICENSE for more information.
