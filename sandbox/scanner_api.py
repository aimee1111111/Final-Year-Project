"""
This is a Flask-based API that uses YARA rules to scan uploaded files for malware.
It loads a set of detection rules, accepts a file upload, calculates its SHA-256 hash,
and checks the file against the YARA rules to determine if it is safe or malicious.
"""

import os
import hashlib
from flask import Flask, request, jsonify
import yara

# Get path to YARA rules from environment, default to /app/rules.yar
RULES_PATH = os.environ.get("YARA_RULES_PATH", "/app/rules.yar")

app = Flask(__name__)

# Store compiled rules + any error during loading
_rules = None
_rules_err = None

# Load and compile YARA rules
def _load_rules():
    global _rules, _rules_err

    # Check if rules file exists
    if not os.path.exists(RULES_PATH):
        _rules = None
        _rules_err = f"rules not found: {RULES_PATH}"
        return

    try:
        # Compile rules file
        _rules = yara.compile(filepath=RULES_PATH)
        _rules_err = None
    except Exception as e:
        # Store error if compilation fails
        _rules = None
        _rules_err = str(e)

# Load rules when app starts
_load_rules()

# Health check route to verify system status
@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "rules_path": RULES_PATH,
        "rules_loaded": _rules is not None,
        "rules_error": _rules_err,
    })

# Main scan endpoint
@app.post("/scan")
def scan():

    # If rules failed to load, return error
    if _rules is None:
        return jsonify({
            "safe": None,
            "engine": "YARA",
            "error": _rules_err or "rules not loaded"
        }), 503

    # Get uploaded file from request
    up = request.files.get("file")
    if not up:
        return jsonify({
            "safe": None,
            "engine": "YARA",
            "error": "missing form field: file"
        }), 400

    # Read file data
    data = up.read() or b""

    # Generate SHA-256 hash of file
    sha256 = hashlib.sha256(data).hexdigest()

    try:
        # Match file against YARA rules
        matches = _rules.match(data=data)

        # If matches found → file is malicious
        if matches:
            threats = [
                {"rule": m.rule, "tags": m.tags, "meta": m.meta}
                for m in matches
            ]
            return jsonify({
                "safe": False,
                "engine": "YARA",
                "sha256": sha256,
                "threats": threats
            })

        # No matches → file is safe
        return jsonify({
            "safe": True,
            "engine": "YARA",
            "sha256": sha256,
            "threats": []
        })

    except Exception as e:
        # Handle runtime errors during scanning
        return jsonify({
            "safe": None,
            "engine": "YARA",
            "sha256": sha256,
            "error": str(e)
        }), 500


# Run app on port 8000
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)