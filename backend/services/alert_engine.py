from datetime import datetime

def generate_threat_alert(threat_data: dict, observation_count: int = 1) -> dict:
    risk = threat_data.get("risk_score", 0)
    conf = threat_data.get("confidence_score", 0)
    sev = threat_data.get("severity", "LOW")
    
    alert_type = "ANOMALY_DETECTION"
    if risk >= 75 and conf >= 70:
        alert_type = "HIGH_CONFIDENCE_THREAT"
    elif "CVE" in threat_data.get("indicator_type", ""):
        alert_type = "EXPLOITABLE_VULNERABILITY"

    return {
        "threat_id": threat_data.get("threat_id"),
        "alert_type": alert_type,
        "severity": sev,
        "risk_score": risk,
        "confidence_score": conf,
        "description": f"Telemetry correlation triggered for {threat_data.get('indicator_value')}. Sightings: {observation_count}",
        "status": "INVESTIGATING" if risk >= 80 else "MONITORING",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "observation_count": observation_count
    }