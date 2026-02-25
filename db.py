import os
from datetime import datetime, timezone

import psycopg2
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import Json, RealDictCursor

DATABASE_URL = os.environ.get("DATABASE_URL")

PG_USER = os.environ.get("PGUSER", "postgres")
PG_PASSWORD = os.environ.get("PGPASSWORD", "1Partner!")
PG_HOST = os.environ.get("PGHOST", "localhost")
PG_PORT = int(os.environ.get("PGPORT", "5432"))
PG_DB = os.environ.get("PGDATABASE", "my_database")

_pool = None


def init_db_pool():
    global _pool
    if _pool is not None:
        return

    if DATABASE_URL:
        _pool = SimpleConnectionPool(minconn=1, maxconn=10, dsn=DATABASE_URL)
    else:
        _pool = SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            user=PG_USER,
            password=PG_PASSWORD,
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DB,
        )


def db_get_conn():
    init_db_pool()
    return _pool.getconn()


def db_put_conn(conn):
    if conn is not None and _pool is not None:
        _pool.putconn(conn)


def save_scan_to_db(user_id: int, result: dict, scanned_at_dt: datetime, source_ip: str) -> str:
    filename = result.get("filename")
    size_bytes = result.get("size_bytes")
    mime_type = result.get("mime_type")
    sha256 = result.get("sha256")

    safe_val = True if result.get("safe") is True else False
    message = result.get("message", "")

    threats = result.get("threats", [])
    scan_results = result.get("scan_results", [])

    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (
                    user_id, filename, size_bytes, mime_type, sha256, scanned_at,
                    safe, message, threats, scan_results, source_ip
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                RETURNING id
                """,
                (
                    user_id,
                    filename,
                    size_bytes,
                    mime_type,
                    sha256,
                    scanned_at_dt,
                    safe_val,
                    message,
                    Json(threats),
                    Json(scan_results),
                    source_ip,
                ),
            )
            scan_id = cur.fetchone()[0]
        conn.commit()
        return str(scan_id)
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            db_put_conn(conn)

def get_history(user_id_int: int, limit: int = 200):
    conn = None
    try:
        conn = db_get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, user_id, filename, size_bytes, mime_type, sha256,
                       scanned_at, safe, message, threats, scan_results, source_ip
                FROM scans
                WHERE user_id = %s
                ORDER BY scanned_at DESC
                LIMIT %s
                """,
                (user_id_int, limit),
            )
            return cur.fetchall()
    finally:
        if conn:
            db_put_conn(conn)
