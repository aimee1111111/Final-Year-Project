import time
import threading
from datetime import datetime, UTC
from flask import request, jsonify

from config import (
    MAX_TEXT_LENGTH,
    RETRAIN_INTERVAL,
    ONLINE_REBUILD_INTERVAL,
)
from heuristics import heuristic_score, verdict, tips
from storage import (
    append_labeled_example,
    load_labeled_examples,
    load_state,
    save_state,
    latest_data_timestamp,
)
from model_utils import build_or_load_model, OnlineModel, ml_probability

"""
This file defines the main Flask routes for the phishing detector.
It handles text analysis, user feedback, manual retraining, system metrics,
and a health check. It also updates the models over time using user-labelled
examples so the detector can improve after deployment.
"""

_mutex = threading.Lock()

_state = load_state()
_feedback_count = int(_state.get("feedback_count", 0))
_online_since_rebuild = int(_state.get("online_since_rebuild", 0))

BATCH_MODEL = None
ONLINE_MODEL = None


def init_route_models(batch_model, online_model):
    # Stores the trained models so the routes can access them
    global BATCH_MODEL, ONLINE_MODEL
    BATCH_MODEL = batch_model
    ONLINE_MODEL = online_model


def register_routes(app):
    @app.route("/chat", methods=["POST"])
    def chat():
        try:
            # Reads the submitted message text from the frontend
            payload = request.get_json(force=True)
            text = (payload.get("message") or "").strip()

            # Validates the input before analysis
            if not text:
                return jsonify(error="Empty message"), 400
            if len(text) > MAX_TEXT_LENGTH:
                return jsonify(error=f"Message too long (max {MAX_TEXT_LENGTH})"), 400

            # Runs heuristic scoring and machine learning prediction
            hs = heuristic_score(text)
            mlp = ml_probability(text, BATCH_MODEL, ONLINE_MODEL)
            v = verdict(hs["score"], mlp)

            # Builds the explanation shown to the user
            lines = [f"{v['label']}  (overall risk ~ {v['risk_pct']})", "", "Why:"]
            lines += [f"• {r}" for r in hs["reasons"]] if hs["reasons"] else ["• No obvious phishing indicators found."]
            lines += ["", "Safety tips:"] + [f"• {t}" for t in tips()]

            return jsonify(
                reply="\n".join(lines),
                summary={
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "risk": v,
                    "heuristic_score": hs["score"],
                    "ml_probability": round(mlp, 3),
                    "reasons": hs["reasons"]
                }
            )
        except Exception:
            return jsonify(error="Analysis failed"), 500

    @app.route("/feedback", methods=["POST"])
    def feedback():
        global _feedback_count, _online_since_rebuild, BATCH_MODEL, ONLINE_MODEL

        try:
            # Reads the user-labelled example from the frontend
            data = request.get_json(force=True)
            text = (data.get("text") or "").strip()
            label = data.get("label")

            # Checks the feedback is valid before saving it
            if not text or len(text) > MAX_TEXT_LENGTH:
                return jsonify(error="Invalid text"), 400
            if label not in (0, 1, True, False):
                return jsonify(error="Label must be 0 or 1"), 400

            label = int(1 if label else 0)

            with _mutex:
                # Saves the new example and updates the online model immediately
                append_labeled_example(text, label, source="feedback")
                ONLINE_MODEL.update([text], [label])

                _feedback_count += 1
                _online_since_rebuild += 1

                rebuilt_online = False
                retrained_batch = False

                # Rebuilds the online model after a set number of feedback updates
                if _online_since_rebuild >= ONLINE_REBUILD_INTERVAL:
                    ONLINE_MODEL.rebuild_from_all_data()
                    _online_since_rebuild = 0
                    rebuilt_online = True

                ONLINE_MODEL.save()

                # Retrains the larger batch model after enough feedback has been collected
                if _feedback_count % RETRAIN_INTERVAL == 0:
                    BATCH_MODEL = build_or_load_model(force=True)
                    ONLINE_MODEL = OnlineModel()
                    ONLINE_MODEL.rebuild_from_all_data()
                    ONLINE_MODEL.save()
                    retrained_batch = True

                # Saves the updated feedback counters and retraining state
                current_state = load_state()
                save_state({
                    "feedback_count": _feedback_count,
                    "online_since_rebuild": _online_since_rebuild,
                    "last_retrain_ts": time.time() if retrained_batch else current_state.get("last_retrain_ts")
                })

            return jsonify(
                ok=True,
                updated_online=True,
                rebuilt_online=rebuilt_online,
                retrained_batch=retrained_batch,
                total_feedbacks=_feedback_count
            )

        except Exception:
            return jsonify(error="Feedback processing failed"), 500

    @app.route("/retrain", methods=["POST"])
    def retrain():
        global BATCH_MODEL, ONLINE_MODEL, _online_since_rebuild

        try:
            with _mutex:
                # Rebuilds both models from the saved training data
                BATCH_MODEL = build_or_load_model(force=True)
                ONLINE_MODEL = OnlineModel()
                ONLINE_MODEL.rebuild_from_all_data()
                ONLINE_MODEL.save()

                _online_since_rebuild = 0

                # Updates the saved state after retraining
                save_state({
                    "feedback_count": _feedback_count,
                    "online_since_rebuild": _online_since_rebuild,
                    "last_retrain_ts": time.time()
                })

            return jsonify(ok=True, retrained=True)
        except Exception:
            return jsonify(error="Retraining failed"), 500

    @app.route("/metrics", methods=["GET"])
    def metrics():
        # Returns model and feedback statistics for monitoring
        X, y = load_labeled_examples()
        return jsonify(
            examples_total=len(X),
            positives=sum(y) if y else 0,
            negatives=(len(X) - sum(y)) if y else 0,
            online_fitted=ONLINE_MODEL._fitted,
            online_sample_count=ONLINE_MODEL._sample_count,
            feedback_count=_feedback_count,
            online_since_rebuild=_online_since_rebuild,
            latest_data_ts=latest_data_timestamp(),
            model_paths={
                "batch": "phish_model.joblib",
                "online": "phish_online_model.joblib",
                "state": "phish_state.json"
            }
        )

    @app.route("/health", methods=["GET"])
    def health():
        # Simple endpoint to confirm the backend is running
        return jsonify(status="ok", service="phishing-detector")