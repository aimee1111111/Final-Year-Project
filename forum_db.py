# forum_db.py
from psycopg2.extras import RealDictCursor
from db import db_get_conn, db_put_conn


def create_post(user_id: int, title: str, body: str) -> dict:
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO posts (user_id, title, body)
                VALUES (%s, %s, %s)
                RETURNING id, user_id, title, body, created_at
                """,
                (user_id, title, body),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        if conn:
            db_put_conn(conn)


def list_posts(limit: int = 50, q: str | None = None) -> list[dict]:
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if q:
                like = f"%{q}%"
                cur.execute(
                    """
                    SELECT p.id, p.user_id, p.title, p.body, p.created_at,
                           (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) AS reply_count
                    FROM posts p
                    WHERE (p.title ILIKE %s OR p.body ILIKE %s)
                    ORDER BY p.created_at DESC
                    LIMIT %s
                    """,
                    (like, like, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT p.id, p.user_id, p.title, p.body, p.created_at,
                           (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) AS reply_count
                    FROM posts p
                    ORDER BY p.created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            return cur.fetchall()
    finally:
        if conn:
            db_put_conn(conn)


def list_posts_by_user(user_id: int, limit: int = 200, q: str | None = None) -> list[dict]:
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if q:
                like = f"%{q}%"
                cur.execute(
                    """
                    SELECT p.id, p.user_id, p.title, p.body, p.created_at,
                           (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) AS reply_count
                    FROM posts p
                    WHERE p.user_id = %s
                      AND (p.title ILIKE %s OR p.body ILIKE %s)
                    ORDER BY p.created_at DESC
                    LIMIT %s
                    """,
                    (user_id, like, like, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT p.id, p.user_id, p.title, p.body, p.created_at,
                           (SELECT COUNT(*) FROM replies r WHERE r.post_id = p.id) AS reply_count
                    FROM posts p
                    WHERE p.user_id = %s
                    ORDER BY p.created_at DESC
                    LIMIT %s
                    """,
                    (user_id, limit),
                )
            return cur.fetchall()
    finally:
        if conn:
            db_put_conn(conn)


def get_post(post_id: int) -> dict | None:
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, user_id, title, body, created_at
                FROM posts
                WHERE id = %s
                """,
                (post_id,),
            )
            return cur.fetchone()
    finally:
        if conn:
            db_put_conn(conn)


def list_replies(post_id: int, limit: int = 200) -> list[dict]:
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, post_id, user_id, body, created_at
                FROM replies
                WHERE post_id = %s
                ORDER BY created_at ASC
                LIMIT %s
                """,
                (post_id, limit),
            )
            return cur.fetchall()
    finally:
        if conn:
            db_put_conn(conn)


def create_reply(post_id: int, user_id: int, body: str) -> dict:
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO replies (post_id, user_id, body)
                VALUES (%s, %s, %s)
                RETURNING id, post_id, user_id, body, created_at
                """,
                (post_id, user_id, body),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    finally:
        if conn:
            db_put_conn(conn)