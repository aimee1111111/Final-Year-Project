import re
from typing import Dict, Any
from config import PHISH_KEYWORDS, FINANCE_TRIGGERS, UNCLEAR_PATTERNS, SHORTENERS, RISKY_ATTACH

"""
This file contains the rule-based scoring logic for the phishing detector.
It checks message text for common phishing phrases, urgency cues, suspicious
patterns, risky attachments, and shortened links, then returns a score,
reasons for the result, safety tips, and a final verdict label.
"""


def heuristic_score(text: str) -> Dict[str, Any]:
    # Returns a zero score if no text is provided
    if not text:
        return {"score": 0, "reasons": []}

    # Converts the text to lowercase so pattern matching is easier
    t = text.lower()

    # Counts phishing indicators found in the message
    kw = sum(1 for k in PHISH_KEYWORDS if k in t)
    fin = sum(1 for k in FINANCE_TRIGGERS if k in t)
    obf = sum(1 for p in UNCLEAR_PATTERNS if re.search(p, t))
    urg = len(re.findall(r"(urgent|immediately|now|suspend|expired|final notice|act now)", t))
    att = len(re.findall(RISKY_ATTACH, t))
    sho = len(re.findall(SHORTENERS, t))

    # Combines the indicators into a weighted score out of 100
    raw_score = kw * 3 + fin + obf * 3 + urg * 2 + att + sho * 2
    score = max(0, min(100, int((raw_score / 25) * 100)))

    # Builds short explanation points for the result
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


def tips():
    # Returns general safety advice shown with results
    return [
        "Verify via official channels before acting.",
        "Never enable macros in unsolicited attachments.",
        "Avoid clicking shortened links; type the site directly.",
        "Be cautious of urgent language or threats.",
        "Check sender domains for subtle misspellings."
    ]


def verdict(score_0_100: int, ml_p: float):
    # Gives more weight to machine learning so user feedback can matter more
    blended = (score_0_100 / 100.0 * 0.35) + (ml_p * 0.65)

    # Converts the blended score into a final risk label
    if blended >= 0.65:
        return {"label": "⚠️ Highly Suspicious", "risk_pct": f"{round(blended * 100)}%", "color": "red"}
    if blended >= 0.40:
        return {"label": "🟠 Suspicious", "risk_pct": f"{round(blended * 100)}%", "color": "orange"}
    return {"label": "🟢 Low Risk", "risk_pct": f"{round(blended * 100)}%", "color": "green"}