import csv
import hashlib
import os
import random
from datetime import datetime, timedelta

def generate_dataset(num_records=2200, output_path="data/threat_intelligence_dataset.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    categories = [
        "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL_THEFT", 
        "WEB_THREATS", "NETWORK_THREATS", "VULNERABILITY_EXPOSURE", 
        "SOCIAL_ENGINEERING", "DATA_EXPOSURE", "ACCOUNT_SECURITY"
    ]
    
    severities = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    statuses = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
    sources = [
        ("Internal SOC", "A"),
        ("Security Vendor", "B"),
        ("Public Threat Feed", "C"),
        ("Research Report", "B"),
        ("Community Submission", "D")
    ]
    
    mitre_map = {
        "PHISHING": ("Initial Access", "Phishing", "T1566"),
        "CREDENTIAL_THEFT": ("Credential Access", "OS Credential Dumping", "T1003"),
        "RANSOMWARE": ("Impact", "Data Encrypted for Impact", "T1486"),
        "MALWARE": ("Execution", "User Execution", "T1204"),
        "WEB_THREATS": ("Initial Access", "Exploit Public-Facing Application", "T1190"),
        "NETWORK_THREATS": ("Command and Control", "Protocol Tunneling", "T1572")
    }

    base_time = datetime.now()
    records = []

    for i in range(1, num_records + 1):
        threat_id = f"THR-2026-{i:05d}"
        category = random.choice(categories)
        indicator_type = random.choice(["IP", "DOMAIN", "URL", "FILE_HASH", "CVE_ID"])
        
        if indicator_type == "IP":
            block = random.choice(["192.0.2", "198.51.100", "203.0.113"])
            indicator_val = f"{block}.{random.randint(1, 254)}"
        elif indicator_type == "DOMAIN":
            sub = f"defense-test-{random.randint(10, 999)}"
            tld = random.choice(["example.com", "example.org", "invalid"])
            indicator_val = f"{sub}.{tld}"
        elif indicator_type == "URL":
            tld = random.choice(["example.com", "example.net"])
            indicator_val = f"https://{tld}/defensive-path/{random.randint(100, 999)}"
        elif indicator_type == "FILE_HASH":
            indicator_val = hashlib.sha256(f"DEFENSIVE_SYNTHETIC_{i}".encode()).hexdigest()
        else:
            indicator_val = f"CVE-2026-{random.randint(1000, 9999)}"

        source, reliability = random.choice(sources)
        severity = random.choice(severities)
        confidence = random.randint(20, 99)
        
        sev_weights = {"INFORMATIONAL": 15, "LOW": 35, "MEDIUM": 55, "HIGH": 75, "CRITICAL": 95}
        risk_score = min(100, int((sev_weights[severity] * 0.6) + (confidence * 0.4)))
        
        status = random.choice(statuses)
        days_ago = random.randint(1, 120)
        first_seen = (base_time - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")
        last_seen = (base_time - timedelta(days=random.randint(0, days_ago))).strftime("%Y-%m-%d %H:%M:%S")
        
        tactic, technique, tid = mitre_map.get(category, ("N/A", "N/A", "N/A"))
        cve = indicator_val if indicator_type == "CVE_ID" else f"CVE-2026-{random.randint(100, 500)}" if random.random() > 0.7 else ""

        records.append({
            "threat_id": threat_id,
            "timestamp": last_seen,
            "threat_name": f"Synthetic {category.replace('_', ' ').title()} Indicator #{i}",
            "threat_category": category,
            "indicator_type": indicator_type,
            "indicator_value": indicator_val,
            "source_name": source,
            "source_reliability": reliability,
            "confidence_score": confidence,
            "severity": severity,
            "risk_score": risk_score,
            "status": status,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "description": f"Synthetic security indicator collected for defensive analytics validation. Label: DEMO_ONLY.",
            "mitre_tactic": tactic,
            "mitre_technique": technique,
            "mitre_technique_id": tid,
            "cve_id": cve
        })

    fields = list(records[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    print(f"Generated {num_records} synthetic threat records in {output_path}")

if __name__ == "__main__":
    generate_dataset()