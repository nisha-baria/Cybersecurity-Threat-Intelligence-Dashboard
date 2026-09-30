import pytest
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk
from backend.services.correlation_engine import correlate_threats
from backend.app import app
from backend.database import init_db, get_connection

@pytest.fixture
def client():
    app.config["TESTING"] = True
    init_db()
    with app.test_client() as client:
        yield client

# 1. Valid IPv4
def test_valid_ipv4():
    res = validate_indicator("192.0.2.1")
    assert res["valid"] is True
    assert res["indicator_type"] == "IP"

# 2. Invalid IPv4
def test_invalid_ipv4():
    res = validate_indicator("999.999.999.999")
    assert res["valid"] is False

# 3. Valid IPv6
def test_valid_ipv6():
    res = validate_indicator("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res["valid"] is True
    assert res["indicator_type"] == "IP"

# 4. Valid Domain
def test_valid_domain():
    res = validate_indicator("malicious-sub.example.com")
    assert res["valid"] is True
    assert res["indicator_type"] == "DOMAIN"

# 5. Invalid Domain
def test_invalid_domain():
    res = validate_indicator("invalid_domain-.com")
    assert res["valid"] is False

# 6. Valid URL
def test_valid_url():
    res = validate_indicator("https://example.com/phish-path")
    assert res["valid"] is True
    assert res["indicator_type"] == "URL"

# 7. Valid MD5
def test_valid_md5():
    res = validate_indicator("d41d8cd98f00b204e9800998ecf8427e")
    assert res["valid"] is True
    assert res["indicator_type"] == "FILE_HASH"

# 8. Valid SHA1
def test_valid_sha1():
    res = validate_indicator("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    assert res["valid"] is True
    assert res["indicator_type"] == "FILE_HASH"

# 9. Valid SHA256
def test_valid_sha256():
    res = validate_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert res["valid"] is True
    assert res["indicator_type"] == "FILE_HASH"

# 10. Valid CVE
def test_valid_cve():
    res = validate_indicator("CVE-2026-12345")
    assert res["valid"] is True
    assert res["indicator_type"] == "CVE_ID"

# 11. Invalid CVE
def test_invalid_cve():
    res = validate_indicator("CVE-INVALID-2026")
    assert res["valid"] is False

# 12. Risk Calculation - Critical
def test_risk_critical():
    res = calculate_threat_risk("CRITICAL", 95, "A", frequency=5)
    assert res["risk_level"] == "CRITICAL"
    assert res["risk_score"] >= 80

# 13. Risk Calculation - Informational
def test_risk_informational():
    res = calculate_threat_risk("INFORMATIONAL", 10, "D", frequency=1)
    assert res["risk_level"] == "INFORMATIONAL"
    assert res["risk_score"] <= 25

# 14. Correlation Engine
def test_correlation_clustering():
    records = [
        {"threat_id": "T1", "threat_category": "PHISHING", "mitre_technique_id": "T1566", "indicator_value": "test1.example.com", "risk_score": 80},
        {"threat_id": "T2", "threat_category": "PHISHING", "mitre_technique_id": "T1566", "indicator_value": "test2.example.com", "risk_score": 90},
    ]
    clusters = correlate_threats(records)
    assert len(clusters) == 1
    assert clusters[0]["indicator_count"] == 2

# 15. REST API - Stats Endpoint
def test_api_stats(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    assert "total_threats" in res.get_json()

# 16. REST API - Threat Feed Paging
def test_api_threat_pagination(client):
    res = client.get("/api/threats?page=1&limit=5")
    assert res.status_code == 200
    assert len(res.get_json()["data"]) <= 5

# 17. REST API - Valid Search Lookup
def test_api_search_known(client):
    res = client.get("/api/indicators/search?query=192.0.2.1")
    assert res.status_code == 200
    assert "indicator" in res.get_json()

# 18. REST API - Notes Post
def test_api_post_notes(client):
    res = client.post("/api/threats/THR-2026-00001/notes", json={"note": "Verified safe test entry", "author": "Analyst"})
    assert res.status_code == 200
    assert res.get_json()["success"] is True

# 19. REST API - Quiz Submit
def test_api_quiz_submission(client):
    res = client.post("/api/quiz/submit", json={"1": "C", "2": "B"})
    assert res.status_code == 200
    assert "overall_score" in res.get_json()

# 20. Database Persistence Check
def test_db_persistence():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1")
    assert cur.fetchone()[0] == 1
    conn.close()