from flask import Blueprint, request, jsonify
from backend.database import get_connection
from backend.services.enrichment_engine import enrich_indicator

threat_bp = Blueprint("threats", __name__, url_prefix="/api")

@threat_bp.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) FROM threats")
    total_threats = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'")
    critical = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'")
    high = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(DISTINCT indicator_value) FROM threats")
    unique_indicators = cur.fetchone()[0]
    
    cur.execute("SELECT AVG(confidence_score) FROM threats")
    avg_conf = round(cur.fetchone()[0] or 0, 1)

    cur.execute("SELECT severity, COUNT(*) as count FROM threats GROUP BY severity")
    sev_dist = {r["severity"]: r["count"] for r in cur.fetchall()}

    cur.execute("SELECT threat_category, COUNT(*) as count FROM threats GROUP BY threat_category")
    cat_dist = {r["threat_category"]: r["count"] for r in cur.fetchall()}

    cur.execute("SELECT indicator_type, COUNT(*) as count FROM threats GROUP BY indicator_type")
    type_dist = {r["indicator_type"]: r["count"] for r in cur.fetchall()}

    conn.close()
    return jsonify({
        "total_threats": total_threats,
        "critical_threats": critical,
        "high_threats": high,
        "unique_indicators": unique_indicators,
        "avg_confidence": avg_conf,
        "severity_distribution": sev_dist,
        "category_distribution": cat_dist,
        "indicator_type_distribution": type_dist
    })

@threat_bp.route("/threats", methods=["GET"])
def get_threats():
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    severity = request.args.get("severity")
    category = request.args.get("category")
    offset = (page - 1) * limit

    conn = get_connection()
    cur = conn.cursor()
    
    query = "SELECT * FROM threats WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if category:
        query += " AND threat_category = ?"
        params.append(category)
        
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cur.execute(query, params)
    threats = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"page": page, "limit": limit, "data": threats})

@threat_bp.route("/indicators/search", methods=["GET"])
def search_indicator():
    val = request.args.get("query", "").strip()
    if not val:
        return jsonify({"error": "Query parameter is required"}), 400
        
    conn = get_connection()
    result = enrich_indicator(val, conn)
    conn.close()
    return jsonify(result)

@threat_bp.route("/threats/<threat_id>", methods=["GET"])
def get_threat_detail(threat_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    threat = cur.fetchone()
    if not threat:
        conn.close()
        return jsonify({"error": "Threat record not found"}), 404
        
    threat_dict = dict(threat)
    cur.execute("SELECT * FROM analyst_notes WHERE threat_id = ?", (threat_id,))
    threat_dict["notes"] = [dict(n) for n in cur.fetchall()]
    conn.close()
    return jsonify(threat_dict)