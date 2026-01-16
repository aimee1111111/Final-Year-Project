from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from datetime import datetime, timezone
import traceback
import os

from scanning import scan_single_file
from db import init_db_pool, save_scan_to_db, get_history

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)
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
    except:
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
    except:
        return jsonify({"error": "user_id must be an integer"}), 400

    limit = request.args.get("limit", "200")
    try:
        limit = max(1, min(int(limit), 500))
    except:
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


if __name__ == "__main__":
    init_db_pool()
    app.run(host="0.0.0.0", port=5000, debug=True)
