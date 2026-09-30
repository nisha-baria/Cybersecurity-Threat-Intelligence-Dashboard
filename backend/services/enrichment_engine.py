from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk

def enrich_indicator(indicator_value: str, db_connection):
    val_res = validate_indicator(indicator_value)
    if not val_res["valid"]:
        return {"error": "Invalid indicator syntax", "details": val_res}

    cur = db_connection.cursor()
    cur.execute("SELECT * FROM threats WHERE indicator_value = ?", (val_res["normalized_value"],))
    rows = cur.fetchall()

    if not rows:
        return {
            "indicator": val_res["normalized_value"],
            "indicator_type": val_res["indicator_type"],
            "validation": val_res,
            "known_in_dataset": False,
            "message": "Indicator valid syntactically; no defensive intelligence sightings recorded."
        }

    records = [dict(r) for r in rows]
    base = records[0]
    
    cur.execute("SELECT * FROM analyst_notes WHERE threat_id = ?", (base["threat_id"],))
    notes = [dict(n) for n in cur.fetchall()]

    return {
        "indicator": base["indicator_value"],
        "indicator_type": base["indicator_type"],
        "known_in_dataset": True,
        "first_seen": min(r["first_seen"] for r in records),
        "last_seen": max(r["last_seen"] for r in records),
        "observation_count": len(records),
        "threat_ids": [r["threat_id"] for r in records],
        "category": base["threat_category"],
        "severity": base["severity"],
        "risk_score": base["risk_score"],
        "confidence_score": base["confidence_score"],
        "source": base["source_name"],
        "source_reliability": base["source_reliability"],
        "mitre_mapping": {
            "tactic": base["mitre_tactic"],
            "technique": base["mitre_technique"],
            "technique_id": base["mitre_technique_id"]
        },
        "analyst_notes": notes,
        "defensive_guidance": "Isolate indicator in telemetry, cross-reference mail gateway/DNS sinks, and audit logs without triggering active outbound queries."
    }