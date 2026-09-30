import sqlite3
import csv
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "threat_intel.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        threat_id TEXT PRIMARY KEY,
        timestamp TEXT,
        threat_name TEXT,
        threat_category TEXT,
        indicator_type TEXT,
        indicator_value TEXT,
        source_name TEXT,
        source_reliability TEXT,
        confidence_score INTEGER,
        severity TEXT,
        risk_score INTEGER,
        status TEXT,
        first_seen TEXT,
        last_seen TEXT,
        description TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        mitre_technique_id TEXT,
        cve_id TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        alert_type TEXT,
        severity TEXT,
        risk_score INTEGER,
        confidence_score INTEGER,
        description TEXT,
        status TEXT,
        timestamp TEXT,
        observation_count INTEGER DEFAULT 1
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS analyst_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        note TEXT,
        author TEXT,
        created_at TEXT
    );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threats(indicator_value);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_category ON threats(threat_category);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity);")
    
    conn.commit()
    conn.close()

def seed_database():
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) FROM threats")
    if cur.fetchone()[0] > 0:
        conn.close()
        return

    csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "threat_intelligence_dataset.csv")
    if not os.path.exists(csv_path):
        from data.generate_threat_data import generate_dataset
        generate_dataset(output_path=csv_path)

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            cur.execute("""
            INSERT OR REPLACE INTO threats VALUES (
                :threat_id, :timestamp, :threat_name, :threat_category, :indicator_type,
                :indicator_value, :source_name, :source_reliability, :confidence_score,
                :severity, :risk_score, :status, :first_seen, :last_seen, :description,
                :mitre_tactic, :mitre_technique, :mitre_technique_id, :cve_id
            )
            """, r)
    conn.commit()
    conn.close()
    print("Database schema verified and initial threat data seeded.")

if __name__ == "__main__":
    seed_database()