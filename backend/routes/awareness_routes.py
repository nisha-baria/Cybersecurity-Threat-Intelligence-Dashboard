from flask import Blueprint, request, jsonify
import json
import os

awareness_bp = Blueprint("awareness", __name__, url_prefix="/api")

@awareness_bp.route("/awareness/modules", methods=["GET"])
def get_modules():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "awareness", "modules.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)

@awareness_bp.route("/quiz", methods=["GET"])
def get_quiz():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "awareness", "quiz_questions.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)

@awareness_bp.route("/quiz/submit", methods=["POST"])
def submit_quiz():
    submissions = request.get_json() or {}
    path = os.path.join(os.path.dirname(__file__), "..", "..", "awareness", "quiz_questions.json")
    with open(path, "r", encoding="utf-8") as f:
        all_questions = json.load(f)

    score = 0
    total = len(all_questions)
    category_scores = {}

    for q in all_questions:
        cat = q["category"]
        if cat not in category_scores:
            category_scores[cat] = {"correct": 0, "total": 0}
        category_scores[cat]["total"] += 1
        
        user_answer = submissions.get(str(q["id"]))
        if user_answer == q["correct"]:
            score += 1
            category_scores[cat]["correct"] += 1

    pct = int((score / total) * 100) if total > 0 else 0
    
    recommendations = []
    for cat, metrics in category_scores.items():
        cat_pct = (metrics["correct"] / metrics["total"]) * 100
        if cat_pct < 70:
            recommendations.append(f"Review module: {cat.replace('_', ' ').title()} - Focus on practical hygiene.")

    return jsonify({
        "overall_score": pct,
        "correct_answers": score,
        "total_questions": total,
        "category_performance": category_scores,
        "recommendations": recommendations
    })