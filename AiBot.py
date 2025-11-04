"""
Compact+ Flask phishing detector — accuracy-focused, still lean.

- Word+char TF-IDF with capped vocab
- Calibrated LR + RF (soft-voted), isotonic/sigmoid explicit
- Online SGD with balanced classes + robust recovery
- Freshness check (retrain when data newer than model)
- Clear reasons + tips; slim metrics
"""
import os, re, json, time, math, sys, random, threading
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

#Config
MODEL_PATH = "phish_model.joblib"            # Batch ensemble model path
ONLINE_MODEL_PATH = "phish_online_model.joblib"  # Online learner path
DATA_FILE = "phish_examples.jsonl"           # Feedback datastore (JSONL)

MAX_TEXT_LENGTH = 50_000                     # Input size guard
RETRAIN_INTERVAL = 100                       # Auto-retrain cadence on feedback

app = Flask(__name__)
CORS(app)

_mutex = threading.Lock()                    # Guards model/data updates
_feedback_count = 0                          # Counts accepted feedbacks

# Heuristic signals (slim but stronger than baseline)
PHISH_KEYWORDS = [
    "verify your account","urgent action required","limited time",
    "your account will be suspended","confirm your password","update billing",
    "unusual activity","payment failed","reset your account","security alert",
    "final notice","account locked","unauthorized login","act now","suspended",
    "suspicious activity","customs fee","package on hold","tax refund",
    "wire transfer","bank transfer","crypto","bitcoin","ransomware","phishing",
    "approve login","access suspended","password reset request","verify card",
    "limited offer","offer expires","low balance","credit limit","invoice attached"
]

# Note: values are matched against lowercased text; mixed case here is harmless
FINANCE_TRIGGERS = [
    "bank","billing","paypal","revolut","BanK of Ireland","tax","revenue","irs","hmrc",
    "post office","an Post","delivery","dhl","ups","customs","Expenses"
]

# Obfuscation/spacing patterns commonly used by phishers
UNCLEAR_PATTERNS = [
    r"c\s*1\s*i\s*c\s*k", r"c\s*l\s*i\s*c\s*k", r"pa\W?ss\W?wo\W?rd",
    r"l0gin", r"verif[ y]{1,3}", r"pay\s*ment", r"up\.?date", r"supp0rt", r"\$\$"
]

SHORTENERS = r"(bit\.ly|tinyurl|goo\.gl|t\.co)"  # URL shorteners
RISKY_ATTACH = r"(\.pdf|\.zip|\.docm|\.xlsm|\.exe|macro|attachment|attached)"  # risky file cues

def heuristic_score(text: str) -> Dict[str, Any]:
    # Compute heuristic score and reasons
    if not text:
        return {"score": 0, "reasons": []}
    t = text.lower()

    kw = sum(1 for k in PHISH_KEYWORDS if k in t)                 # keyword cues
    fin = sum(1 for k in FINANCE_TRIGGERS if k in t)              # finance/brand terms
    obf = sum(1 for p in UNCLEAR_PATTERNS if re.search(p, t))     # obfuscation
    urg = len(re.findall(r"(urgent|immediately|now|suspend|expired|final notice|act now)", t))  # urgency
    att = len(re.findall(RISKY_ATTACH, t))                         # attachment hints
    sho = len(re.findall(SHORTENERS, t))                           # short URLs

    # Weighted sum → normalized to 0–100
    score = kw*3 + fin + obf*3 + urg*2 + att + sho*2
    score = max(0, min(100, int((score/25)*100)))

    # Human-readable reasons
    reasons = []
    if kw:  reasons.append(f"{kw} phishing-language cue(s)")
    if fin: reasons.append(f"{fin} finance/brand term(s)")
    if obf: reasons.append(f"{obf} unclear pattern(s)")
    if urg: reasons.append(f"{urg} urgency/threat cue(s)")
    if att: reasons.append(f"{att} attachment/extension cue(s)")
    if sho: reasons.append(f"{sho} URL shortener(s)")

    return {"score": score, "reasons": reasons}

# Data I/O
def _ensure_datafile():
    # Create JSONL file if missing
    if not os.path.exists(DATA_FILE):
        open(DATA_FILE, "a", encoding="utf-8").close()

def append_labeled_example(text: str, label: int, source: str = "user"):
    # Append one labeled line to JSONL
    _ensure_datafile()
    rec = {"text": text, "label": int(1 if label else 0), "ts": time.time(), "source": source}
    with open(DATA_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def load_labeled_examples() -> Tuple[List[str], List[int]]:
    # Load all labeled samples from JSONL
    if not os.path.exists(DATA_FILE): return [], []
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

#Features & Models
def build_features() -> FeatureUnion:
    # Word-level 1–2 grams + char 3–5 grams; capped to avoid vocab blowup
    return FeatureUnion([
        ("word", TfidfVectorizer(
            analyzer="word", ngram_range=(1,2),
            min_df=2, max_df=0.95, max_features=5000
        )),
        ("char", TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3,5),
            min_df=2, max_df=0.95, max_features=3000
        )),
    ])

def build_ensemble() -> VotingClassifier:
    # Calibrated LR (sigmoid) + RF (isotonic), soft-voted with weights
    feats = build_features()
    lr = Pipeline([
        ("features", feats),
        ("clf", CalibratedClassifierCV(
            LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear"),
            method="sigmoid", cv=3
        ))
    ])
    rf = Pipeline([
        ("features", feats),
        ("clf", CalibratedClassifierCV(
            RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1),
            method="isotonic", cv=3
        ))
    ])
    return VotingClassifier([("lr", lr), ("rf", rf)], voting="soft", weights=[0.65, 0.35])

class OnlineModel:
    # Online learner with its own features and SGD
    def __init__(self):
        self.features = build_features()
        self.sgd = SGDClassifier(loss="log_loss", random_state=42, max_iter=5, tol=1e-3, class_weight="balanced")
        self._fitted = False

    def fit(self, X: List[str], y: List[int]):
        # Initial fit; enables incremental partial_fit calls
        if not X: return
        try:
            Xf = self.features.fit_transform(X)
            self.sgd.partial_fit(Xf, y, classes=[0,1])
            self._fitted = True
        except Exception as e:
            print(f"Online.fit error: {e}", file=sys.stderr)

    def update(self, X: List[str], y: List[int]):
        # Incremental update; on failure refit from all JSONL data
        if not X: return
        if not self._fitted: return self.fit(X, y)
        try:
            self.sgd.partial_fit(self.features.transform(X), y)
        except Exception as e:
            print(f"Online.update fallback: {e}", file=sys.stderr)
            Xa, ya = load_labeled_examples()
            if Xa: self.fit(Xa, ya)

    def predict_proba_one(self, text: str) -> float:
        # Predict single-sample probability
        if not self._fitted: return 0.5
        try:
            Xf = self.features.transform([text])
            if hasattr(self.sgd, "predict_proba"):
                p = self.sgd.predict_proba(Xf)[0][1]
            else:
                d = self.sgd.decision_function(Xf)[0]
                p = 1.0 / (1.0 + math.exp(-d))
            return float(max(0.01, min(0.99, p)))
        except Exception as e:
            print(f"Online.predict error: {e}", file=sys.stderr)
            return 0.5

    def save(self, path: str = ONLINE_MODEL_PATH):
        # Persist online model + vectorizer
        try: joblib.dump({"features": self.features, "sgd": self.sgd, "fitted": self._fitted}, path)
        except Exception as e: print(f"Online.save error: {e}", file=sys.stderr)

    def load(self, path: str = ONLINE_MODEL_PATH) -> bool:
        # Load persisted online model
        if not os.path.exists(path): return False
        try:
            obj = joblib.load(path)
            self.features = obj["features"]; self.sgd = obj["sgd"]; self._fitted = obj.get("fitted", False)
            return True
        except Exception as e:
            print(f"Online.load error: {e}", file=sys.stderr); return False

def _augment(samples: List[str], brands: List[str], n: int) -> List[str]:
    # Simple synthetic data: brand injection + light obfuscation + TLD tail
    tlds = ["com","net","org","co","io","xyz"]
    out = []
    for _ in range(n):
        base = random.choice(samples)
        b = random.choice(brands)
        s = base.replace("[BRAND]", b).replace("[SERVICE]", b)
        if random.random() < 0.3:
            s = s.replace("verify","v3rify").replace("click","cl1ck").replace("password","pa$$word").replace("login","l0gin")
        out.append(f"{s} Visit {b}.{random.choice(tlds)} to resolve.")
    return out

def build_or_load_model(force: bool=False) -> VotingClassifier:
    # Train if forced or data is newer than model; include all JSONL feedback
    X_user, y_user = load_labeled_examples()

    if not force and os.path.exists(MODEL_PATH):
        try:
            model_time = os.path.getmtime(MODEL_PATH)
            data_time = os.path.getmtime(DATA_FILE) if os.path.exists(DATA_FILE) else 0
            if data_time <= model_time:
                return joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"Model load error, retraining: {e}", file=sys.stderr)

    #phish vs legit
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
        "Account suspended due to suspicious activity. Click to verify identity",
        "Your [BRAND] will be locked within 24 hours. Reset password now",
        "Unrecognized device signed into [SERVICE]. V3rify your account at",
        "Recent payment declined. Update card details to avoid service interruption.",
        "Delivery failure: parcel being returned. Pay customs here:",
        "You've won a $500 gift card! Claim prize now.",
        "Confirm payment of £129.99 to [BRAND]. Click to dispute.",
        "System upgrade: all users must reset passwords or lose access.",
        "Refund issued. Open attached invoice and enable macros to accept.",
        "Tax authority requires verification for refund. Provide documents here.",
        "Account compromise detected. Provide one-time code to re-enable.",
        "Subscription renewal failed. Update billing or [SERVICE] will be cancelled.",
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
        "Thank you for attending today's webinar.",
    ]

    # Brands used in augmentation
    brands = ["PayPal","Bank of Ireland","AIB","Revolut","Stripe","DHL","UPS","An Post","Amazon","Apple","Google","Microsoft","Facebook","LinkedIn","Netflix","Spotify","eBay","Twitter","Instagram","Zoom"]

    # Build train set = seeds + augmentation + user feedback
    X = phish + legit + _augment(phish, brands, 80) + _augment(legit, brands, 40) + X_user
    y = [1]*(len(phish)+80) + [0]*(len(legit)+40) + y_user

    model = build_ensemble()
    try:
        if len(set(y)) > 1:
            # Hold-out small validation split for stability
            X_tr, _, y_tr, _ = train_test_split(X, y, test_size=0.12, random_state=42, stratify=y)
            model.fit(X_tr, y_tr)
        else:
            model.fit(X, y)
    except Exception as e:
        print(f"Training fallback: {e}", file=sys.stderr)
        model.fit(X, y)

    try: joblib.dump(model, MODEL_PATH)
    except Exception as e: print(f"Save model error: {e}", file=sys.stderr)

    return model

# Bootstrap
print("Initializing models...", file=sys.stderr)
_user_X, _user_y = load_labeled_examples()        # Load any prior feedback
BATCH_MODEL = build_or_load_model(force=False)    # Load or train batch ensemble
ONLINE_MODEL = OnlineModel()                      # Init online learner
if not ONLINE_MODEL.load() and _user_X:
    ONLINE_MODEL.fit(_user_X, _user_y)            # Warm-start online from JSONL
    ONLINE_MODEL.save()
print("Models ready.", file=sys.stderr)

#Scoring helpers
def ml_probability(text: str) -> float:
    # Blend batch (70%) + online (30%); clamp to avoid extremes
    try:
        pb = float(BATCH_MODEL.predict_proba([text])[0][1])
        pb = max(0.01, min(0.99, pb))
    except Exception as e:
        print(f"Batch predict error: {e}", file=sys.stderr)
        pb = 0.5
    po = ONLINE_MODEL.predict_proba_one(text)
    return float(max(0.01, min(0.99, 0.70*pb + 0.30*po)))

def verdict(score_0_100: int, ml_p: float) -> Dict[str, str]:
    # Join heuristics (30%) and ML (70%) into risk label and color
    blended = (score_0_100/100.0 * 0.50) + (ml_p * 0.50)
    if blended >= 0.65: return {"label":"⚠️ Highly Suspicious","risk_pct":f"{round(blended*100)}%","color":"red"}
    if blended >= 0.40: return {"label":"🟠 Suspicious","risk_pct":f"{round(blended*100)}%","color":"orange"}
    return {"label":"🟢 Low Risk","risk_pct":f"{round(blended*100)}%","color":"green"}

def tips() -> List[str]:
    # Short, actionable safety tips
    return [
        "Verify via official channels before acting.",
        "Never enable macros in unsolicited attachments.",
        "Avoid clicking shortened links; type the site directly.",
        "Be cautious of urgent language or threats.",
        "Check sender domains for subtle misspellings."
    ]

# Routes
@app.route("/chat", methods=["POST"])
def chat():
    # Main analysis endpoint
    try:
        payload = request.get_json(force=True)
        text = (payload.get("message") or "").strip()
        if not text: return jsonify(error="Empty message"), 400
        if len(text) > MAX_TEXT_LENGTH: return jsonify(error=f"Message too long (max {MAX_TEXT_LENGTH})"), 400

        hs = heuristic_score(text)
        mlp = ml_probability(text)
        v = verdict(hs["score"], mlp)

        lines = [f"{v['label']}  (overall risk ~ {v['risk_pct']})", "", "Why:"]
        lines += [f"• {r}" for r in hs["reasons"]] if hs["reasons"] else ["• No obvious phishing indicators found."]
        lines += ["", "Safety tips:"] + [f"• {t}" for t in tips()]

        return jsonify(reply="\n".join(lines), summary={
            "timestamp": datetime.utcnow().isoformat()+"Z",
            "risk": v,
            "heuristic_score": hs["score"],
            "ml_probability": round(mlp,3),
            "reasons": hs["reasons"]
        })
    except Exception as e:
        print(f"/chat error: {e}", file=sys.stderr)
        return jsonify(error="Analysis failed"), 500

@app.route("/feedback", methods=["POST"])
def feedback():
    # Accept labeled feedback; update online; optionally auto-retrain batch
    global _feedback_count, BATCH_MODEL, ONLINE_MODEL
    try:
        data = request.get_json(force=True)
        text = (data.get("text") or "").strip()
        label = data.get("label")
        if not text or len(text) > MAX_TEXT_LENGTH: 
            return jsonify(error="Invalid text"), 400
        if label not in (0,1,True,False): 
            return jsonify(error="Label must be 0 or 1"), 400

        label = int(1 if label else 0)
        
        with _mutex:
            # 1) Persist labeled example to JSONL
            append_labeled_example(text, label, source="feedback")
            # 2) Update online model immediately
            ONLINE_MODEL.update([text], [label])
            ONLINE_MODEL.save()
            # 3)trigger batch retrain every N feedbacks
            _feedback_count += 1
            should_retrain = (_feedback_count % RETRAIN_INTERVAL == 0)
            if should_retrain:
                print(f"Auto-retraining with {_feedback_count} feedbacks...", file=sys.stderr)
                BATCH_MODEL = build_or_load_model(force=True)  # full fold-in of JSONL
                X_user, y_user = load_labeled_examples()
                ONLINE_MODEL = OnlineModel()
                if X_user:
                    ONLINE_MODEL.fit(X_user, y_user)
                    ONLINE_MODEL.save()
                print("Auto-retrain complete.", file=sys.stderr)

        return jsonify(
            ok=True, 
            updated_online=True,
            retrained_batch=should_retrain,
            total_feedbacks=_feedback_count
        )
    except Exception as e:
        print(f"/feedback error: {e}", file=sys.stderr)
        return jsonify(error="Feedback processing failed"), 500

@app.route("/retrain", methods=["POST"])
def retrain():
    # Manual full retrain endpoint
    try:
        with _mutex:
            global BATCH_MODEL, ONLINE_MODEL
            BATCH_MODEL = build_or_load_model(force=True)
            X_user, Y_user = load_labeled_examples()
            ONLINE_MODEL = OnlineModel()
            if X_user:
                ONLINE_MODEL.fit(X_user, Y_user)
                ONLINE_MODEL.save()
        return jsonify(ok=True, retrained=True)
    except Exception as e:
        print(f"/retrain error: {e}", file=sys.stderr)
        return jsonify(error="Retraining failed"), 500

@app.route("/metrics", methods=["GET"])
def metrics():
    # Lightweight telemetry for observability
    X, y = load_labeled_examples()
    return jsonify(
        examples_total=len(X),
        positives=sum(y) if y else 0,
        negatives=(len(X)-sum(y)) if y else 0,
        online_fitted=ONLINE_MODEL._fitted,
        feedback_count=_feedback_count,
        model_paths={"batch": MODEL_PATH, "online": ONLINE_MODEL_PATH}
    )

@app.route("/health", methods=["GET"])
def health():
    # Basic liveness
    return jsonify(status="ok", service="phishing-detector")

#Entrypoint
if __name__ == "__main__":
    print("Starting on 0.0.0.0:5050", file=sys.stderr)
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)
