MITRE_ATTACK_MATRIX = {
    "PHISHING": {"tactic": "Initial Access", "technique": "Phishing", "technique_id": "T1566"},
    "CREDENTIAL_THEFT": {"tactic": "Credential Access", "technique": "OS Credential Dumping", "technique_id": "T1003"},
    "RANSOMWARE": {"tactic": "Impact", "technique": "Data Encrypted for Impact", "technique_id": "T1486"},
    "MALWARE": {"tactic": "Execution", "technique": "User Execution", "technique_id": "T1204"},
    "WEB_THREATS": {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "technique_id": "T1190"},
    "NETWORK_THREATS": {"tactic": "Command and Control", "technique": "Protocol Tunneling", "technique_id": "T1572"},
    "DATA_EXPOSURE": {"tactic": "Exfiltration", "technique": "Exfiltration Over Web Service", "technique_id": "T1567"},
    "ACCOUNT_SECURITY": {"tactic": "Persistence", "technique": "Valid Accounts", "technique_id": "T1078"}
}

def map_threat_to_attack(category: str) -> dict:
    normalized = category.upper().strip()
    return MITRE_ATTACK_MATRIX.get(normalized, {
        "tactic": "Unassigned / General Defense",
        "technique": "Behavioral Context Required",
        "technique_id": "T-NONE"
    })