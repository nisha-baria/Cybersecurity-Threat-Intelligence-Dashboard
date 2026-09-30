from flask import Flask, send_from_directory
from flask_cors import CORS
from backend.database import seed_database
from backend.routes.threat_routes import threat_bp
from backend.routes.awareness_routes import awareness_bp

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# Initialize database schema & demo records
seed_database()

# Register modular blueprints
app.register_blueprint(threat_bp)
app.register_blueprint(awareness_bp)

@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)