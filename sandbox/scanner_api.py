# sandbox/scanner_api.py
import os
import hashlib
from flask import Flask, request, jsonify
import yara

RULES_PATH = os.environ.get("YARA_RULES_PATH", "/app/rules.yar")

app = Flask(__name__)

_rules = None
_rules_err = None

def _load_rules():
    global _rules, _rules_err
    if not os.path.exists(RULES_PATH):
        _rules = None
        _rules_err = f"rules not found: {RULES_PATH}"
        return
    try:
        _rules = yara.compile(filepath=RULES_PATH)
        _rules_err = None
    except Exception as e:
        _rules = None
        _rules_err = str(e)

_load_rules()

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "rules_path": RULES_PATH,
        "rules_loaded": _rules is not None,
        "rules_error": _rules_err,
    })

@app.post("/scan")
def scan():
    if _rules is None:
        return jsonify({"safe": None, "engine": "YARA", "error": _rules_err or "rules not loaded"}), 503

    up = request.files.get("file")
    if not up:
        return jsonify({"safe": None, "engine": "YARA", "error": "missing form field: file"}), 400

    data = up.read() or b""
    sha256 = hashlib.sha256(data).hexdigest()

    try:
        matches = _rules.match(data=data)
        if matches:
            threats = [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]
            return jsonify({"safe": False, "engine": "YARA", "sha256": sha256, "threats": threats})
        return jsonify({"safe": True, "engine": "YARA", "sha256": sha256, "threats": []})
    except Exception as e:
        return jsonify({"safe": None, "engine": "YARA", "sha256": sha256, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)