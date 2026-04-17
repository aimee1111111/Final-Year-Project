"""
Configuration settings for the phishing detector.

This file stores the main constants used across the phishing detection system,
including model file paths, retraining settings, input limits, and the keyword
and pattern lists used by the heuristic scoring logic. Keeping these values in
one file makes the system easier to manage and update.
"""

# File paths used to save the trained models, labelled examples, and app state
MODEL_PATH = "phish_model.joblib"
ONLINE_MODEL_PATH = "phish_online_model.joblib"
DATA_FILE = "phish_examples.jsonl"
STATE_FILE = "phish_state.json"

# General settings for text length, retraining frequency, and confidence limits
MAX_TEXT_LENGTH = 50_000
RETRAIN_INTERVAL = 100
ONLINE_REBUILD_INTERVAL = 10
MIN_CONFIDENCE_FLOOR = 0.02
MAX_CONFIDENCE_CEIL = 0.98

# Common phishing-related phrases used to detect suspicious language
PHISH_KEYWORDS = [
    "verify your account", "urgent action required", "limited time",
    "your account will be suspended", "confirm your password", "update billing",
    "unusual activity", "payment failed", "reset your account", "security alert",
    "final notice", "account locked", "unauthorized login", "act now", "suspended",
    "suspicious activity", "customs fee", "package on hold", "tax refund",
    "wire transfer", "bank transfer", "crypto", "bitcoin", "ransomware", "phishing",
    "approve login", "access suspended", "password reset request", "verify card",
    "limited offer", "offer expires", "low balance", "credit limit", "invoice attached",

    # urgency / pressure
    "immediate action required", "respond immediately", "within 24 hours",
    "within 12 hours", "last warning", "final warning", "act immediately",
    "time sensitive", "do not ignore", "urgent response needed",

    # account / security
    "confirm your identity", "verify your identity", "account verification",
    "security check", "account restriction", "account limitation",
    "login attempt detected", "multiple login attempts",
    "unrecognized device", "new device login", "secure your account",
    "account compromised", "security breach",

    # credentials / sensitive info
    "enter your password", "confirm your details", "update your details",
    "provide your information", "verify your information",
    "confirm billing details", "update payment information",
    "verify payment details", "submit your credentials",

    # financial / threats
    "account will be closed", "account will be terminated",
    "service interruption", "payment declined", "transaction failed",
    "refund available", "claim your refund", "pending payment",
    "outstanding balance", "overdue payment",

    # delivery / scams
    "delivery failed", "missed delivery", "reschedule delivery",
    "track your package", "shipment delayed", "parcel held",
    "customs clearance required",

    # generic bait / rewards
    "you have won", "claim your prize", "exclusive deal",
    "special promotion", "free gift", "reward waiting",
    "loyalty reward", "bonus offer",

    # authority impersonation
    "bank notice", "government notice", "official notice",
    "irs notice", "tax authority", "legal action",
    "compliance required",

    # attachments / links
    "download attachment", "open attachment", "view document",
    "secure link", "click here", "follow the link",
    "access document", "review document"
]

# Brand, finance, and service-related words often seen in phishing messages
FINANCE_TRIGGERS = [
    "bank", "billing", "paypal", "revolut", "bank of ireland", "tax", "revenue", "irs", "hmrc",
    "post office", "an post", "delivery", "dhl", "ups", "customs", "expenses"
]

# Regular expression patterns used to catch obfuscated or suspicious wording
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

# Detects common URL shortening services
SHORTENERS = r"(bit\.ly|tinyurl|goo\.gl|t\.co)"

# Detects risky attachment types or related wording often used in phishing emails
RISKY_ATTACH = r"(\.pdf|\.zip|\.docm|\.xlsm|\.exe|macro|attachment|attached)"