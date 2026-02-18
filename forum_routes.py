# forum_routes.py
from flask import Blueprint, request, jsonify
from forum_db import (
    create_post,
    list_posts,
    list_posts_by_user,
    get_post,
    list_replies,
    create_reply,
)

forum_bp = Blueprint("forum_bp", __name__)


def _get_user_id_from_request() -> int:
    raw = request.headers.get("X-User-Id", "").strip()
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError:
        return 0


@forum_bp.get("/api/posts")
def api_list_posts():
    mine = request.args.get("mine", "0") == "1"
    user_id = _get_user_id_from_request()
    q = (request.args.get("q") or "").strip()

    if mine:
        if user_id <= 0:
            return jsonify({"error": "missing or invalid X-User-Id"}), 401
        rows = list_posts_by_user(user_id=user_id, limit=200, q=q if q else None)
    else:
        rows = list_posts(limit=50, q=q if q else None)

    return jsonify(rows)


@forum_bp.post("/api/posts")
def api_create_post():
    user_id = _get_user_id_from_request()
    if user_id <= 0:
        return jsonify({"error": "missing or invalid X-User-Id"}), 401

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    body = (data.get("body") or "").strip()

    if len(title) < 3:
        return jsonify({"error": "title too short"}), 400
    if len(body) < 10:
        return jsonify({"error": "body too short"}), 400

    row = create_post(user_id=user_id, title=title, body=body)
    return jsonify(row), 201


@forum_bp.get("/api/posts/<int:post_id>")
def api_get_post(post_id: int):
    post = get_post(post_id)
    if not post:
        return jsonify({"error": "not found"}), 404

    replies = list_replies(post_id=post_id, limit=200)
    return jsonify({"post": post, "replies": replies})


@forum_bp.post("/api/posts/<int:post_id>/replies")
def api_create_reply(post_id: int):
    user_id = _get_user_id_from_request()
    if user_id <= 0:
        return jsonify({"error": "missing or invalid X-User-Id"}), 401

    post = get_post(post_id)
    if not post:
        return jsonify({"error": "post not found"}), 404

    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if len(body) < 2:
        return jsonify({"error": "reply too short"}), 400

    row = create_reply(post_id=post_id, user_id=user_id, body=body)
    return jsonify(row), 201