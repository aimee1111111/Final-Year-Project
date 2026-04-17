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
    phish += [
    # more urgency / account threats
    "Immediate verification required or your [BRAND] account will be deleted.",
    "We were unable to verify your details. Confirm now to avoid suspension.",
    "Your session has expired. Login again to continue using [SERVICE].",
    "Too many failed login attempts. Reset your password immediately.",
    "Critical alert: your account is at risk. Secure it now.",

    # more payment / billing
    "Your subscription to [SERVICE] has expired. Renew now to avoid disruption.",
    "Payment declined for your recent order. Update your card details.",
    "Outstanding balance detected. Pay now to avoid penalties.",
    "Auto-payment failed. Re-enter billing information immediately.",
    "Confirm your payment details to avoid late fees.",

    # delivery / logistics scams
    "Your parcel is waiting for collection. Pay small fee to release.",
    "Delivery attempt failed. Reschedule here: http://tinyurl.com/abc",
    "Package held at depot. Confirm address and pay shipping fee.",
    "We could not deliver your item. Update delivery info now.",
    "Shipment requires signature confirmation. Click to proceed.",

    # rewards / bait
    "Congratulations! You’ve been selected for an exclusive reward.",
    "You are eligible for a compensation payment. Claim now.",
    "Limited time reward available. Confirm your details to receive.",
    "You have unclaimed funds waiting. Verify to access.",
    "Exclusive offer just for you. Act now before it expires.",

    # impersonation (more realistic)
    "Your Netflix account has been suspended. Update payment to continue watching.",
    "Apple ID locked due to suspicious activity. Verify immediately.",
    "Your PayPal account is limited. Resolve now to restore access.",
    "Amazon: problem with your recent order. Confirm your details.",
    "Microsoft account security alert. Review activity now.",

    # work / internal phishing (very realistic)
    "HR: Please review updated company policy document attached.",
    "IT Support: Your password expires today. Reset here.",
    "Shared document from [SERVICE]. Click to view securely.",
    "New voicemail received. Listen to message here.",
    "You have a secure message waiting. Access now.",

    # attachments / malware-style
    "Important document attached. Enable editing to view contents.",
    "Scanned invoice attached. Open file to review.",
    "Confidential report. Download and enable macros.",
    "Voicemail attachment received. Open to listen.",
    "Encrypted message. Download attachment to decrypt.",

    # slightly obfuscated / trickier
    "Verify your acc0unt now to avoid suspensi0n.",
    "C0nfirm your det@ils to restore access.",
    "Unusual activity detected. V3rify immediately.",
    "Reset your passw0rd using the secure link.",
    "Click h3re to update your inf0rmation.",

    # social engineering / fear tactics
    "Legal notice: failure to respond may result in account closure.",
    "We have reported suspicious activity linked to your account.",
    "Failure to comply may result in permanent data loss.",
    "Your account is under investigation. Confirm identity now.",
    "Security team requires immediate verification from you.",

    # OTP / MFA abuse
    "Your verification code is required to restore access.",
    "Enter the code sent to your phone to confirm identity.",
    "We sent you a security code. Provide it to continue.",
    "2FA verification failed. Re-enter your code now.",
    "Confirm your login using the one-time passcode."
]

    # Built-in legitimate examples used to balance the dataset
    legit += [
    # general workplace / normal comms
    "Can you review the document and send feedback by EOD?",
    "Here are the notes from today’s meeting.",
    "Please see the attached report for your reference.",
    "Let me know if you have any questions.",
    "Following up on the email I sent earlier this week.",
    "Quick reminder about the deadline tomorrow.",
    "Updated version of the file is now available.",
    "Thanks again for your help on this.",
    "We’ll discuss this further in tomorrow’s call.",
    "Agenda for next week’s meeting attached.",

    # account / service (legit but similar tone to phishing)
    "We noticed a login to your account from a new device. If this was you, no action is needed.",
    "Your password has been updated successfully.",
    "A new device was used to access your account.",
    "You recently signed in on a new browser.",
    "Your account settings were updated.",
    "Security notice: we recommend reviewing your recent activity.",
    "You can manage your account settings anytime in your profile.",

    # payments / receipts (legit)
    "Your payment has been processed successfully.",
    "Receipt for your recent transaction is attached.",
    "Thank you for your payment.",
    "Your order confirmation is included below.",
    "We’ve received your payment and your order is being prepared.",
    "Invoice attached for your records.",
    "Payment confirmation for your subscription renewal.",

    # delivery / logistics (legit)
    "Your package has been dispatched and is on its way.",
    "Tracking information for your delivery is included below.",
    "Your order will arrive within 3–5 business days.",
    "Delivery completed successfully.",
    "Your parcel has been delivered to your address.",
    "Courier has picked up your package.",

    # events / bookings
    "Your booking has been confirmed.",
    "Here are your tickets for the event.",
    "Reminder: your reservation is tomorrow evening.",
    "Your check-in details are included below.",
    "We look forward to seeing you at the event.",
    "Your registration details are attached.",

    # casual / human tone (important for realism)
    "Hey, just checking in about this.",
    "No rush on this, just when you get a chance.",
    "Thanks, that worked perfectly.",
    "Got it, I’ll take a look later today.",
    "Let’s catch up tomorrow.",
    "Sounds good to me.",

    # slightly “trigger-like” but still legit (important for testing false positives)
    "Click here to view your invoice in your account portal.",
    "Download your receipt from the link below.",
    "Please log in to your account to view your statement.",
    "Access your dashboard to see the latest updates.",
    "Follow this link to review your subscription details.",
    "Open the document in your account to view more details.",

    # system / automated but safe
    "System update completed successfully.",
    "Your request has been processed.",
    "No further action is required at this time.",
    "This is an automated message confirming your request.",
    "Backup completed successfully.",
    "Your data has been synced."
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