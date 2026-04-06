"""
Phishing detector backend

This file runs the Flask backend for the phishing checker.
It accepts message text from the frontend, analyses it using a mix of
rule-based heuristics and machine learning, returns a phishing risk result,
and can also save user feedback so the model improves over time.
"""

import os
import re
import json
import time
import math
import sys
import random
import threading
from datetime import datetime
from typing import List, Dict, Tuple, Any, Optional

from flask import Flask, request, jsonify
from flask_cors import CORS

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
import joblib

# File paths used to store the trained models, labelled examples, and app state
MODEL_PATH = "phish_model.joblib"
ONLINE_MODEL_PATH = "phish_online_model.joblib"
DATA_FILE = "phish_examples.jsonl"
STATE_FILE = "phish_state.json"

# General settings for limits and retraining behaviour
MAX_TEXT_LENGTH = 50_000
RETRAIN_INTERVAL = 100
ONLINE_REBUILD_INTERVAL = 10
MIN_CONFIDENCE_FLOOR = 0.02
MAX_CONFIDENCE_CEIL = 0.98

app = Flask(__name__)
CORS(app)

# Prevents simultaneous model updates from overlapping
_mutex = threading.Lock()

# Keyword and pattern lists used by the heuristic scorer
PHISH_KEYWORDS = [
    "verify your account", "urgent action required", "limited time",
    "your account will be suspended", "confirm your password", "update billing",
    "unusual activity", "payment failed", "reset your account", "security alert",
    "final notice", "account locked", "unauthorized login", "act now", "suspended",
    "suspicious activity", "customs fee", "package on hold", "tax refund",
    "wire transfer", "bank transfer", "crypto", "bitcoin", "ransomware", "phishing",
    "approve login", "access suspended", "password reset request", "verify card",
    "limited offer", "offer expires", "low balance", "credit limit", "invoice attached"
]

FINANCE_TRIGGERS = [
    "bank", "billing", "paypal", "revolut", "bank of ireland", "tax", "revenue", "irs", "hmrc",
    "post office", "an post", "delivery", "dhl", "ups", "customs", "expenses"
]

UNCLEAR_PATTERNS = [
    r"c\s*1\s*i\s*c\s*k",
    r"c\s*l\s*i\s*c\s*k",
    r"pa\W?ss\W?wo\W?rd",
    r"l0gin",
    r"verif[ y]{1,3}",
    r"pay\s*ment",
    r"up\.?date",
    r"supp0rt",
    r"\$\$"
]

SHORTENERS = r"(bit\.ly|tinyurl|goo\.gl|t\.co)"
RISKY_ATTACH = r"(\.pdf|\.zip|\.docm|\.xlsm|\.exe|macro|attachment|attached)"


# Looks for suspicious wording and patterns in the text and returns a score
def heuristic_score(text: str) -> Dict[str, Any]:
    if not text:
        return {"score": 0, "reasons": []}

    t = text.lower()

    kw = sum(1 for k in PHISH_KEYWORDS if k in t)
    fin = sum(1 for k in FINANCE_TRIGGERS if k in t)
    obf = sum(1 for p in UNCLEAR_PATTERNS if re.search(p, t))
    urg = len(re.findall(r"(urgent|immediately|now|suspend|expired|final notice|act now)", t))
    att = len(re.findall(RISKY_ATTACH, t))
    sho = len(re.findall(SHORTENERS, t))

    raw_score = kw * 3 + fin + obf * 3 + urg * 2 + att + sho * 2
    score = max(0, min(100, int((raw_score / 25) * 100)))

    reasons = []
    if kw:
        reasons.append(f"{kw} phishing-language cue(s)")
    if fin:
        reasons.append(f"{fin} finance/brand term(s)")
    if obf:
        reasons.append(f"{obf} unclear pattern(s)")
    if urg:
        reasons.append(f"{urg} urgency/threat cue(s)")
    if att:
        reasons.append(f"{att} attachment/extension cue(s)")
    if sho:
        reasons.append(f"{sho} URL shortener(s)")

    return {"score": score, "reasons": reasons}


# Creates the labelled data file if it does not already exist
def _ensure_datafile():
    if not os.path.exists(DATA_FILE):
        open(DATA_FILE, "a", encoding="utf-8").close()


# Saves one user-labelled example to the JSONL training file
def append_labeled_example(text: str, label: int, source: str = "user"):
    _ensure_datafile()
    rec = {
        "text": text,
        "label": int(1 if label else 0),
        "ts": time.time(),
        "source": source
    }
    with open(DATA_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# Loads all labelled training examples from disk
def load_labeled_examples() -> Tuple[List[str], List[int]]:
    if not os.path.exists(DATA_FILE):
        return [], []

    X, y = [], []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
                txt = (obj.get("text") or "").strip()
                if txt:
                    X.append(txt)
                    y.append(int(1 if obj.get("label") else 0))
            except Exception:
                continue
    return X, y


# Loads saved counters and retraining state
def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return {"feedback_count": 0, "online_since_rebuild": 0, "last_retrain_ts": None}

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"feedback_count": 0, "online_since_rebuild": 0, "last_retrain_ts": None}


# Saves counters and retraining state back to disk
def save_state(state: Dict[str, Any]):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"State save error: {e}", file=sys.stderr)


# Returns the last modification time of the training data file
def latest_data_timestamp() -> Optional[float]:
    if not os.path.exists(DATA_FILE):
        return None
    try:
        return os.path.getmtime(DATA_FILE)
    except Exception:
        return None


_state = load_state()
_feedback_count = int(_state.get("feedback_count", 0))
_online_since_rebuild = int(_state.get("online_since_rebuild", 0))


# Builds the text feature extractor using both word-level and character-level TF-IDF
def build_features() -> FeatureUnion:
    return FeatureUnion([
        ("word", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            max_features=5000
        )),
        ("char", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=2,
            max_df=0.95,
            max_features=3000
        )),
    ])


# Builds the main batch model using a soft-voting ensemble
def build_ensemble() -> VotingClassifier:
    feats = build_features()

    lr = Pipeline([
        ("features", feats),
        ("clf", CalibratedClassifierCV(
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                solver="liblinear"
            ),
            method="sigmoid",
            cv=3
        ))
    ])

    rf = Pipeline([
        ("features", feats),
        ("clf", CalibratedClassifierCV(
            RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1
            ),
            method="isotonic",
            cv=3
        ))
    ])

    return VotingClassifier(
        estimators=[("lr", lr), ("rf", rf)],
        voting="soft",
        weights=[0.65, 0.35]
    )


# Online model used to absorb feedback incrementally between full retrains
class OnlineModel:
    def __init__(self):
        self.features = build_features()
        self.sgd = SGDClassifier(
            loss="log_loss",
            random_state=42,
            max_iter=1000,
            tol=1e-3,
            class_weight="balanced"
        )
        self._fitted = False
        self._sample_count = 0

    # Trains the online model from scratch
    def fit(self, X: List[str], y: List[int]):
        if not X:
            return
        try:
            self.features = build_features()
            Xf = self.features.fit_transform(X)
            self.sgd = SGDClassifier(
                loss="log_loss",
                random_state=42,
                max_iter=1000,
                tol=1e-3,
                class_weight="balanced"
            )
            self.sgd.partial_fit(Xf, y, classes=[0, 1])
            self._fitted = True
            self._sample_count = len(X)
        except Exception as e:
            print(f"Online.fit error: {e}", file=sys.stderr)

    # Updates the online model with newly labelled examples
    def update(self, X: List[str], y: List[int]):
        if not X:
            return
        if not self._fitted:
            return self.fit(X, y)

        try:
            Xf = self.features.transform(X)
            self.sgd.partial_fit(Xf, y)
            self._sample_count += len(X)
        except Exception as e:
            print(f"Online.update fallback: {e}", file=sys.stderr)
            Xa, ya = load_labeled_examples()
            if Xa:
                self.fit(Xa, ya)

    # Rebuilds the online model using all saved labelled data
    def rebuild_from_all_data(self):
        Xa, ya = load_labeled_examples()
        if Xa:
            self.fit(Xa, ya)

    # Predicts phishing probability for one text item
    def predict_proba_one(self, text: str) -> float:
        if not self._fitted:
            return 0.5
        try:
            Xf = self.features.transform([text])
            if hasattr(self.sgd, "predict_proba"):
                p = self.sgd.predict_proba(Xf)[0][1]
            else:
                d = self.sgd.decision_function(Xf)[0]
                p = 1.0 / (1.0 + math.exp(-d))
            return float(max(MIN_CONFIDENCE_FLOOR, min(MAX_CONFIDENCE_CEIL, p)))
        except Exception as e:
            print(f"Online.predict error: {e}", file=sys.stderr)
            return 0.5

    # Saves the online model to disk
    def save(self, path: str = ONLINE_MODEL_PATH):
        try:
            joblib.dump({
                "features": self.features,
                "sgd": self.sgd,
                "fitted": self._fitted,
                "sample_count": self._sample_count
            }, path)
        except Exception as e:
            print(f"Online.save error: {e}", file=sys.stderr)

    # Loads the online model from disk if it exists
    def load(self, path: str = ONLINE_MODEL_PATH) -> bool:
        if not os.path.exists(path):
            return False
        try:
            obj = joblib.load(path)
            self.features = obj["features"]
            self.sgd = obj["sgd"]
            self._fitted = obj.get("fitted", False)
            self._sample_count = obj.get("sample_count", 0)
            return True
        except Exception as e:
            print(f"Online.load error: {e}", file=sys.stderr)
            return False


# Creates extra synthetic examples to strengthen the training set
def _augment(samples: List[str], brands: List[str], n: int) -> List[str]:
    tlds = ["com", "net", "org", "co", "io", "xyz"]
    out = []
    for _ in range(n):
        base = random.choice(samples)
        b = random.choice(brands)
        s = base.replace("[BRAND]", b).replace("[SERVICE]", b)
        if random.random() < 0.3:
            s = (
                s.replace("verify", "v3rify")
                 .replace("click", "cl1ck")
                 .replace("password", "pa$$word")
                 .replace("login", "l0gin")
            )
        out.append(f"{s} Visit {b}.{random.choice(tlds)} to resolve.")
    return out


# Loads the batch model from disk if still current, otherwise retrains it
def build_or_load_model(force: bool = False) -> VotingClassifier:
    X_user, y_user = load_labeled_examples()

    if not force and os.path.exists(MODEL_PATH):
        try:
            model_time = os.path.getmtime(MODEL_PATH)
            data_time = os.path.getmtime(DATA_FILE) if os.path.exists(DATA_FILE) else 0
            if data_time <= model_time:
                return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"Model load error, retraining: {e}", file=sys.stderr)

    # Built-in starter examples used before much user feedback exists
    phish = [
        "Urgent action required: your [BRAND] account will be suspended. Verify now.",
        "Security alert: unusual activity on your [SERVICE] account. Click to restore.",
        "Payment failed for [BRAND], update billing to avoid interruption.",
        "Your package is on hold. Pay customs fee: http://bit.ly/xyz",
        "Confirm your identity to receive prize. Fill form immediately.",
        "We detected 2FA disabled on [SERVICE]. Re-validate now.",
        "Invoice attached. Please enable macros to view.",
        "Your [BRAND] account is restricted. Login to reactivate.",
        "Final notice: mailbox storage full. Verify to continue.",
        "[SERVICE] withdrawal request. If this wasn't you, cancel here.",
        "Unusual login detected on your [BRAND] account. Verify your password now.",
        "Payment to [SERVICE] could not be processed. Update billing immediately.",
        "Account suspended due to suspicious activity. Click to verify identity.",
        "Your [BRAND] will be locked within 24 hours. Reset password now.",
        "Unrecognized device signed into [SERVICE]. V3rify your account now.",
        "Recent payment declined. Update card details to avoid service interruption.",
        "Delivery failure: parcel being returned. Pay customs here.",
        "You've won a $500 gift card! Claim prize now.",
        "Confirm payment of £129.99 to [BRAND]. Click to dispute.",
        "System upgrade: all users must reset passwords or lose access.",
        "Refund issued. Open attached invoice and enable macros to accept.",
        "Tax authority requires verification for refund. Provide documents here.",
        "Account compromise detected. Provide one-time code to re-enable.",
        "Subscription renewal failed. Update billing or [SERVICE] will be cancelled."
    ]

    legit = [
        "Meeting moved to 2pm tomorrow, see updated agenda.",
        "Thanks for your purchase. Your order has shipped.",
        "Quarterly newsletter: new features and improvements.",
        "Team offsite details and FAQs inside.",
        "Your password was changed successfully.",
        "Project update: sprint review notes and next steps.",
        "Invoice for services rendered in September.",
        "Reminder: appointment on Friday at 9:00 AM.",
        "Welcome to the course! Here are your materials.",
        "Board minutes from last week are available.",
        "Your subscription renewal receipt attached. No action required.",
        "Delivery scheduled: parcel arrives Thursday between 9-5.",
        "Security alert: login from recognized device in Dublin.",
        "Your event registration is confirmed. See you there!",
        "Monthly statement available in your account portal.",
        "Thank you for attending today's webinar."
    ]

    brands = [
        "PayPal", "Bank of Ireland", "AIB", "Revolut", "Stripe", "DHL", "UPS", "An Post",
        "Amazon", "Apple", "Google", "Microsoft", "Facebook", "LinkedIn", "Netflix",
        "Spotify", "eBay", "Twitter", "Instagram", "Zoom"
    ]

    X = phish + legit + _augment(phish, brands, 80) + _augment(legit, brands, 40) + X_user
    y = [1] * (len(phish) + 80) + [0] * (len(legit) + 40) + y_user

    model = build_ensemble()

    try:
        if len(set(y)) > 1 and len(X) >= 10:
            X_tr, _, y_tr, _ = train_test_split(
                X, y, test_size=0.12, random_state=42, stratify=y
            )
            model.fit(X_tr, y_tr)
        else:
            model.fit(X, y)
    except Exception as e:
        print(f"Training fallback: {e}", file=sys.stderr)
        model.fit(X, y)

    try:
        joblib.dump(model, MODEL_PATH)
    except Exception as e:
        print(f"Save model error: {e}", file=sys.stderr)

    return model


print("Initializing models...", file=sys.stderr)
_user_X, _user_y = load_labeled_examples()
BATCH_MODEL = build_or_load_model(force=False)
ONLINE_MODEL = OnlineModel()

# Try loading the saved online model first, otherwise build it from user data
if not ONLINE_MODEL.load() and _user_X:
    ONLINE_MODEL.fit(_user_X, _user_y)
    ONLINE_MODEL.save()

print("Models ready.", file=sys.stderr)


# Combines batch and online model probabilities into one value
def ml_probability(text: str) -> float:
    try:
        pb = float(BATCH_MODEL.predict_proba([text])[0][1])
        pb = max(MIN_CONFIDENCE_FLOOR, min(MAX_CONFIDENCE_CEIL, pb))
    except Exception as e:
        print(f"Batch predict error: {e}", file=sys.stderr)
        pb = 0.5

    po = ONLINE_MODEL.predict_proba_one(text)

    # Increase the online model's influence as it sees more data
    if ONLINE_MODEL._fitted and ONLINE_MODEL._sample_count >= 20:
        batch_weight, online_weight = 0.55, 0.45
    elif ONLINE_MODEL._fitted:
        batch_weight, online_weight = 0.65, 0.35
    else:
        batch_weight, online_weight = 1.0, 0.0

    return float(max(
        MIN_CONFIDENCE_FLOOR,
        min(MAX_CONFIDENCE_CEIL, batch_weight * pb + online_weight * po)
    ))


# Converts the final score into a user-friendly verdict
def verdict(score_0_100: int, ml_p: float) -> Dict[str, str]:
    blended = (score_0_100 / 100.0 * 0.50) + (ml_p * 0.50)

    if blended >= 0.65:
        return {"label": "⚠️ Highly Suspicious", "risk_pct": f"{round(blended * 100)}%", "color": "red"}
    if blended >= 0.40:
        return {"label": "🟠 Suspicious", "risk_pct": f"{round(blended * 100)}%", "color": "orange"}
    return {"label": "🟢 Low Risk", "risk_pct": f"{round(blended * 100)}%", "color": "green"}


# General safety advice returned with each result
def tips() -> List[str]:
    return [
        "Verify via official channels before acting.",
        "Never enable macros in unsolicited attachments.",
        "Avoid clicking shortened links; type the site directly.",
        "Be cautious of urgent language or threats.",
        "Check sender domains for subtle misspellings."
    ]


# Main analysis endpoint used by the frontend checker
@app.route("/chat", methods=["POST"])
def chat():
    try:
        payload = request.get_json(force=True)
        text = (payload.get("message") or "").strip()

        if not text:
            return jsonify(error="Empty message"), 400
        if len(text) > MAX_TEXT_LENGTH:
            return jsonify(error=f"Message too long (max {MAX_TEXT_LENGTH})"), 400

        hs = heuristic_score(text)
        mlp = ml_probability(text)
        v = verdict(hs["score"], mlp)

        # Build the text response shown in the frontend
        lines = [f"{v['label']}  (overall risk ~ {v['risk_pct']})", "", "Why:"]
        lines += [f"• {r}" for r in hs["reasons"]] if hs["reasons"] else ["• No obvious phishing indicators found."]
        lines += ["", "Safety tips:"] + [f"• {t}" for t in tips()]

        return jsonify(
            reply="\n".join(lines),
            summary={
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "risk": v,
                "heuristic_score": hs["score"],
                "ml_probability": round(mlp, 3),
                "reasons": hs["reasons"]
            }
        )
    except Exception as e:
        print(f"/chat error: {e}", file=sys.stderr)
        return jsonify(error="Analysis failed"), 500


# Saves user feedback and updates the models
@app.route("/feedback", methods=["POST"])
def feedback():
    global _feedback_count, _online_since_rebuild, BATCH_MODEL, ONLINE_MODEL

    try:
        data = request.get_json(force=True)
        text = (data.get("text") or "").strip()
        label = data.get("label")

        if not text or len(text) > MAX_TEXT_LENGTH:
            return jsonify(error="Invalid text"), 400
        if label not in (0, 1, True, False):
            return jsonify(error="Label must be 0 or 1"), 400

        label = int(1 if label else 0)

        with _mutex:
            append_labeled_example(text, label, source="feedback")

            # Update the online model immediately with the new example
            ONLINE_MODEL.update([text], [label])

            _feedback_count += 1
            _online_since_rebuild += 1

            rebuilt_online = False
            retrained_batch = False

            # Periodically rebuild the online model so its vocabulary stays fresh
            if _online_since_rebuild >= ONLINE_REBUILD_INTERVAL:
                ONLINE_MODEL.rebuild_from_all_data()
                _online_since_rebuild = 0
                rebuilt_online = True

            ONLINE_MODEL.save()

            # Occasionally retrain the larger batch model from scratch
            if _feedback_count % RETRAIN_INTERVAL == 0:
                print(f"Auto-retraining batch model with {_feedback_count} feedbacks...", file=sys.stderr)
                BATCH_MODEL = build_or_load_model(force=True)

                ONLINE_MODEL = OnlineModel()
                ONLINE_MODEL.rebuild_from_all_data()
                ONLINE_MODEL.save()

                retrained_batch = True

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

    except Exception as e:
        print(f"/feedback error: {e}", file=sys.stderr)
        return jsonify(error="Feedback processing failed"), 500


# Manually retrains the batch and online models
@app.route("/retrain", methods=["POST"])
def retrain():
    global BATCH_MODEL, ONLINE_MODEL, _online_since_rebuild

    try:
        with _mutex:
            BATCH_MODEL = build_or_load_model(force=True)

            ONLINE_MODEL = OnlineModel()
            ONLINE_MODEL.rebuild_from_all_data()
            ONLINE_MODEL.save()

            _online_since_rebuild = 0

            save_state({
                "feedback_count": _feedback_count,
                "online_since_rebuild": _online_since_rebuild,
                "last_retrain_ts": time.time()
            })

        return jsonify(ok=True, retrained=True)
    except Exception as e:
        print(f"/retrain error: {e}", file=sys.stderr)
        return jsonify(error="Retraining failed"), 500


# Returns model and feedback statistics
@app.route("/metrics", methods=["GET"])
def metrics():
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
            "batch": MODEL_PATH,
            "online": ONLINE_MODEL_PATH,
            "state": STATE_FILE
        }
    )


# Simple health check endpoint
@app.route("/health", methods=["GET"])
def health():
    return jsonify(status="ok", service="phishing-detector")


# Starts the Flask app on port 5050
if __name__ == "__main__":
    print("Starting on 0.0.0.0:5050", file=sys.stderr)
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)