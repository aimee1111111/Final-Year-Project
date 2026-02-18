from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timezone
import traceback

from scanning import scan_single_file
from db import init_db_pool, save_scan_to_db, get_history
from commonvirus_db import (
    init_commonvirus_db_pool,
    get_common_threats,
    get_threat_recent_scans,
)
from forum_routes import forum_bp 

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)
app.register_blueprint(forum_bp)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


@app.route("/")
def root():
    return send_from_directory(".", "files.html")


@app.route("/upload", methods=["POST"])
def upload():
    user_id = request.form.get("user_id")
    if not user_id:
        return jsonify({"safe": False, "message": "Missing user_id"}), 400

    try:
        user_id_int = int(user_id)
    except Exception:
        return jsonify({"safe": False, "message": "user_id must be an integer"}), 400

    files = request.files.getlist("file")
    if not files:
        return jsonify({"safe": False, "message": "No files provided"}), 400

    valid_files = [f for f in files if f.filename and f.filename.strip()]
    if not valid_files:
        return jsonify({"safe": False, "message": "No valid files provided"}), 400

    source_ip = get_client_ip()

    try:
        # Single
        if len(valid_files) == 1:
            scanned_at_dt = datetime.now(timezone.utc)
            result = scan_single_file(valid_files[0])
            scan_id = save_scan_to_db(user_id_int, result, scanned_at_dt, source_ip)

            result["scan_id"] = scan_id
            result["scanned_at"] = scanned_at_dt.isoformat()

            if result.get("error"):
                return jsonify(result), 500
            return jsonify(result)

        # Multiple
        results = []
        for f in valid_files:
            scanned_at_dt = datetime.now(timezone.utc)
            r = scan_single_file(f)
            scan_id = save_scan_to_db(user_id_int, r, scanned_at_dt, source_ip)

            r["scan_id"] = scan_id
            r["scanned_at"] = scanned_at_dt.isoformat()
            results.append(r)

        return jsonify(results)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"safe": False, "message": f"Upload failed: {e}"}), 500


@app.route("/history", methods=["GET"])
def history():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    try:
        user_id_int = int(user_id)
    except Exception:
        return jsonify({"error": "user_id must be an integer"}), 400

    limit = request.args.get("limit", "200")
    try:
        limit = max(1, min(int(limit), 500))
    except Exception:
        limit = 200

    rows = get_history(user_id_int, limit)

    results = []
    for row in rows:
        results.append(
            {
                "scan_id": str(row["id"]),
                "user_id": row["user_id"],
                "filename": row["filename"],
                "size": row["size_bytes"],
                "type": row["mime_type"],
                "sha256": row.get("sha256"),
                "safe": bool(row["safe"]),
                "message": row["message"],
                "threats": row.get("threats") or [],
                "scan_results": row.get("scan_results") or [],
                "source_ip": row.get("source_ip"),
                "created_at": row["scanned_at"].isoformat() if row.get("scanned_at") else None,
            }
        )

    return jsonify({"results": results})


#Common virus APIs

@app.route("/api/common-viruses", methods=["GET"])
def api_common_viruses():
    days = request.args.get("days", "30")
    min_count = request.args.get("min_count", "10")
    limit = request.args.get("limit", "50")
    name = request.args.get("name", "").strip()

    try:
        days_i = max(1, min(int(days), 365))
    except Exception:
        days_i = 30

    try:
        min_count_i = max(1, int(min_count))
    except Exception:
        min_count_i = 10

    try:
        limit_i = max(1, min(int(limit), 200))
    except Exception:
        limit_i = 50

    user_id = request.args.get("user_id")
    user_id_int = None
    if user_id not in (None, "", "null"):
        try:
            user_id_int = int(user_id)
        except Exception:
            return jsonify({"error": "user_id must be an integer"}), 400

    items = get_common_threats(
        days=days_i,
        min_count=min_count_i,
        user_id=user_id_int,
        name=name if name else None,
        limit=limit_i,
    )

    return jsonify({"days": days_i, "min_count": min_count_i, "items": items})


@app.route("/api/virus", methods=["GET"])
def api_virus_info():
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"error": "missing name"}), 400

    return jsonify(
        {
            "name": name,
            "category": "Malware / Threat",
            "summary": "A threat frequently detected in recent scans. Treat detections as potentially malicious until verified.",
            "how_to_avoid": [
                "Keep OS and apps updated",
                "Do not open unexpected attachments/links",
                "Use reputable endpoint protection",
                "Use MFA and strong unique passwords",
            ],
            "how_to_get_rid": [
                "Quarantine/remove detected files",
                "Update scanners and run a full scan",
                "Rotate passwords if compromise is suspected",
            ],
        }
    )


@app.route("/api/virus/scans", methods=["GET"])
def api_virus_scans():
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"error": "missing name"}), 400

    days = request.args.get("days", "30")
    limit = request.args.get("limit", "100")

    try:
        days_i = max(1, min(int(days), 365))
    except Exception:
        days_i = 30

    try:
        limit_i = max(1, min(int(limit), 500))
    except Exception:
        limit_i = 100

    user_id = request.args.get("user_id")
    user_id_int = None
    if user_id not in (None, "", "null"):
        try:
            user_id_int = int(user_id)
        except Exception:
            return jsonify({"error": "user_id must be an integer"}), 400

    items = get_threat_recent_scans(
        threat_name=name,
        days=days_i,
        user_id=user_id_int,
        limit=limit_i,
    )

    return jsonify({"name": name, "days": days_i, "items": items})


if __name__ == "__main__":
    init_db_pool()
    init_commonvirus_db_pool()
    app.run(host="0.0.0.0", port=5000, debug=True)
