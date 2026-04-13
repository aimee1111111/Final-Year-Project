"""
Machine learning utilities for the phishing detector.

This file contains the core model logic used by the phishing detection system.
It builds the text features, creates the batch and online machine learning models,
loads or retrains models when needed, generates synthetic training examples, and
calculates the final phishing probability score returned by the backend.
"""

import os
import math
import sys
import random
import joblib
from typing import List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split

from config import (
    MODEL_PATH,
    ONLINE_MODEL_PATH,
    MIN_CONFIDENCE_FLOOR,
    MAX_CONFIDENCE_CEIL,
)
from storage import load_labeled_examples


# Builds a combined feature extractor using both word-level and character-level TF-IDF
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


# Builds the main batch model as a soft-voting ensemble
def build_ensemble() -> VotingClassifier:
    feats = build_features()

    # Logistic Regression branch with probability calibration
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

    # Random Forest branch with probability calibration
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

    # Combines both models into one final voting classifier
    return VotingClassifier(
        estimators=[("lr", lr), ("rf", rf)],
        voting="soft",
        weights=[0.65, 0.35]
    )


# Online model used to learn incrementally from user feedback
class OnlineModel:
    def __init__(self):
        # Builds the same feature extractor for online learning
        self.features = build_features()

        # Uses SGDClassifier because it supports partial_fit for incremental updates
        self.sgd = SGDClassifier(
            loss="log_loss",
            random_state=42,
            max_iter=1000,
            tol=1e-3,
            class_weight="balanced"
        )

        # Tracks whether the online model has been fitted and how many samples it has seen
        self._fitted = False
        self._sample_count = 0

    # Trains the online model from scratch using all supplied examples
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

    # Updates the online model with newly labelled feedback examples
    def update(self, X: List[str], y: List[int]):
        if not X:
            return

        # If the model has not been trained yet, train it first
        if not self._fitted:
            return self.fit(X, y)

        try:
            Xf = self.features.transform(X)
            self.sgd.partial_fit(Xf, y)
            self._sample_count += len(X)

        except Exception as e:
            print(f"Online.update fallback: {e}", file=sys.stderr)

            # If update fails, rebuild from all saved labelled examples
            Xa, ya = load_labeled_examples()
            if Xa:
                self.fit(Xa, ya)

    # Rebuilds the online model using all saved feedback data
    def rebuild_from_all_data(self):
        Xa, ya = load_labeled_examples()
        if Xa:
            self.fit(Xa, ya)

    # Predicts the phishing probability for one text input
    def predict_proba_one(self, text: str) -> float:
        if not self._fitted:
            return 0.5

        try:
            Xf = self.features.transform([text])

            # Use predict_proba if available, otherwise calculate probability from decision score
            if hasattr(self.sgd, "predict_proba"):
                p = self.sgd.predict_proba(Xf)[0][1]
            else:
                d = self.sgd.decision_function(Xf)[0]
                p = 1.0 / (1.0 + math.exp(-d))

            # Keeps the probability within predefined confidence limits
            return float(max(MIN_CONFIDENCE_FLOOR, min(MAX_CONFIDENCE_CEIL, p)))

        except Exception as e:
            print(f"Online.predict error: {e}", file=sys.stderr)
            return 0.5

    # Saves the online model and its fitted state to disk
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

    # Loads the saved online model from disk if it exists
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


# Creates extra synthetic examples by inserting brand names and small text variations
def _augment(samples: List[str], brands: List[str], n: int) -> List[str]:
    tlds = ["com", "net", "org", "co", "io", "xyz"]
    out = []

    for _ in range(n):
        base = random.choice(samples)
        b = random.choice(brands)

        # Replaces placeholders like [BRAND] and [SERVICE] with real brand names
        s = base.replace("[BRAND]", b).replace("[SERVICE]", b)

        # Sometimes adds small obfuscations to mimic phishing tricks
        if random.random() < 0.3:
            s = (
                s.replace("verify", "v3rify")
                 .replace("click", "cl1ck")
                 .replace("password", "pa$$word")
                 .replace("login", "l0gin")
            )

        out.append(f"{s} Visit {b}.{random.choice(tlds)} to resolve.")

    return out


# Loads an existing batch model if possible, otherwise retrains it
def build_or_load_model(force: bool = False) -> VotingClassifier:
    X_user, y_user = load_labeled_examples()

    # Reuse saved model if it already exists and the data file has not changed
    if not force and os.path.exists(MODEL_PATH):
        try:
            model_time = os.path.getmtime(MODEL_PATH)
            data_time = os.path.getmtime("phish_examples.jsonl") if os.path.exists("phish_examples.jsonl") else 0

            if data_time <= model_time:
                return joblib.load(MODEL_PATH)

        except Exception as e:
            print(f"Model load error, retraining: {e}", file=sys.stderr)

    # Built-in phishing examples used to bootstrap the model
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

    # Built-in legitimate examples used to balance the dataset
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

    # Brand names used to generate more varied synthetic examples
    brands = [
        "PayPal", "Bank of Ireland", "AIB", "Revolut", "Stripe", "DHL", "UPS", "An Post",
        "Amazon", "Apple", "Google", "Microsoft", "Facebook", "LinkedIn", "Netflix",
        "Spotify", "eBay", "Twitter", "Instagram", "Zoom"
    ]

    # Builds the final training set using built-in, synthetic, and user-labelled examples
    X = phish + legit + _augment(phish, brands, 80) + _augment(legit, brands, 40) + X_user
    y = [1] * (len(phish) + 80) + [0] * (len(legit) + 40) + y_user

    model = build_ensemble()

    try:
        # Uses a train/test split when there is enough varied data
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

    # Saves the trained batch model to disk
    try:
        joblib.dump(model, MODEL_PATH)
    except Exception as e:
        print(f"Save model error: {e}", file=sys.stderr)

    return model


# Initialises both the batch model and the online model when the system starts
def init_models():
    print("Initializing models...", file=sys.stderr)

    user_X, user_y = load_labeled_examples()
    batch_model = build_or_load_model(force=False)
    online_model = OnlineModel()

    # Loads a saved online model if possible, otherwise builds it from user data
    if not online_model.load() and user_X:
        online_model.fit(user_X, user_y)
        online_model.save()

    print("Models ready.", file=sys.stderr)
    return batch_model, online_model


# Combines the batch and online model probabilities into one final phishing score
def ml_probability(text: str, batch_model, online_model) -> float:
    try:
        pb = float(batch_model.predict_proba([text])[0][1])
        pb = max(MIN_CONFIDENCE_FLOOR, min(MAX_CONFIDENCE_CEIL, pb))
    except Exception as e:
        print(f"Batch predict error: {e}", file=sys.stderr)
        pb = 0.5

    po = online_model.predict_proba_one(text)

    # Gives the online model more influence once it has seen enough examples
    if online_model._fitted and online_model._sample_count >= 20:
        batch_weight, online_weight = 0.55, 0.45
    elif online_model._fitted:
        batch_weight, online_weight = 0.65, 0.35
    else:
        batch_weight, online_weight = 1.0, 0.0

    return float(max(
        MIN_CONFIDENCE_FLOOR,
        min(MAX_CONFIDENCE_CEIL, batch_weight * pb + online_weight * po)
    ))