from backend.database import get_connection
import pandas as pd
import os

def load_vulnerabilities():
    csv_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "vulnerabilities.csv")
    if not os.path.exists(csv_path):
        return []
    df = pd.read_csv(csv_path)
    return df.to_dict(orient="records")

def get_threat_by_id(threat_id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None