def calculate_threat_risk(severity: str, confidence: int, source_reliability: str = "C", frequency: int = 1) -> dict:
    sev_weights = {
        "INFORMATIONAL": 10,
        "LOW": 30,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 95
    }
    rel_weights = {
        "A": 1.0,
        "B": 0.85,
        "C": 0.70,
        "D": 0.50
    }
    
    base_sev = sev_weights.get(severity.upper(), 30)
    rel_factor = rel_weights.get(source_reliability.upper(), 0.70)
    
    # Mathematical composite scoring
    # Severity 35%, Confidence 25%, Source Reliability 20%, Frequency/Context 20%
    freq_score = min(100, frequency * 20)
    composite = (base_sev * 0.35) + (confidence * 0.25) + ((rel_factor * 100) * 0.20) + (freq_score * 0.20)
    final_score = int(round(min(100, max(0, composite))))
    
    if final_score <= 20:
        level = "INFORMATIONAL"
    elif final_score <= 40:
        level = "LOW"
    elif final_score <= 60:
        level = "MEDIUM"
    elif final_score <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"
        
    return {
        "risk_score": final_score,
        "risk_level": level,
        "interpretation": "Calculated risk based on empirical telemetry without confirming compromise."
    }