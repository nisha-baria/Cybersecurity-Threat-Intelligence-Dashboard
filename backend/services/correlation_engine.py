def correlate_threats(threat_records: list) -> list:
    clusters = {}
    for t in threat_records:
        key = (t["threat_category"], t.get("mitre_technique_id", "N/A"))
        if key not in clusters:
            clusters[key] = {
                "category": t["threat_category"],
                "technique_id": t.get("mitre_technique_id"),
                "technique": t.get("mitre_technique"),
                "indicator_count": 0,
                "indicators": [],
                "avg_risk": 0,
                "threat_ids": []
            }
        clusters[key]["indicator_count"] += 1
        clusters[key]["indicators"].append(t["indicator_value"])
        clusters[key]["threat_ids"].append(t["threat_id"])
        clusters[key]["avg_risk"] += t["risk_score"]

    result = []
    for k, v in clusters.items():
        if v["indicator_count"] > 1:
            v["avg_risk"] = int(v["avg_risk"] / v["indicator_count"])
            v["indicators"] = list(set(v["indicators"]))[:5]
            result.append(v)
            
    return sorted(result, key=lambda x: x["indicator_count"], reverse=True)