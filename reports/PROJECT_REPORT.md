# Project Report: Cybersecurity Awareness & Threat Intelligence Dashboard

## Executive Summary
This project demonstrates an end-to-end defensive security dashboard designed to bridge technical indicators of compromise (IOCs) with operational awareness training. Built with Python, Flask, and vanilla frontend architectures, the system ingests, normalizes, and visualizes defensive security data.

## Defensive Objectives Achieved
1. **Indicator Normalization:** Syntactically validates IPv4, IPv6, URLs, FQDNs, Hashes, and CVE records.
2. **Behavioral Alignment:** Direct correlation to the MITRE ATT&CK framework across high-probability tactics.
3. **Decoupled Scoring:** Independently scores Risk Level (0-100) vs Evidence Confidence (0-100) to minimize false positives.
4. **Human Layer Integration:** Integrates bite-sized security hygiene modules and an interactive quiz evaluation system.

## Ethical & Safety Declaration
The platform does not execute malicious code, perform port scanning, or communicate with external adversarial command-and-control servers. All data is sanitized and synthetic.