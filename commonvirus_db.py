# commonvirus_db.py
import os
from typing import Optional, List, Dict, Any

from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor

_pool: Optional[SimpleConnectionPool] = None


def init_commonvirus_db_pool() -> None:
    global _pool
    if _pool is not None:
        return

    database_url = os.environ.get("DATABASE_URL")

    pg_user = os.environ.get("PGUSER", "postgres")
    pg_password = os.environ.get("PGPASSWORD", "1Partner!")
    pg_host = os.environ.get("PGHOST", "localhost")
    pg_port = int(os.environ.get("PGPORT", "5432"))
    pg_db = os.environ.get("PGDATABASE", "my_database")

    if database_url:
        _pool = SimpleConnectionPool(minconn=1, maxconn=10, dsn=database_url)
    else:
        _pool = SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            user=pg_user,
            password=pg_password,
            host=pg_host,
            port=pg_port,
            dbname=pg_db,
        )


def _get_conn():
    init_commonvirus_db_pool()
    assert _pool is not None
    return _pool.getconn()


def _put_conn(conn) -> None:
    if conn is not None and _pool is not None:
        _pool.putconn(conn)


def get_common_threats(
    days: int = 30,
    min_count: int = 10,
    user_id: Optional[int] = None,
    name: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    conn = None
    try:
        conn = _get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            sql = """
            WITH extracted AS (
              SELECT
                s.id,
                s.scanned_at,
                CASE
                  WHEN jsonb_typeof(elem) = 'string'
                    THEN trim(both '"' from elem::text)
                  WHEN jsonb_typeof(elem) = 'object'
                    THEN COALESCE(elem->>'name', elem->>'threat', elem->>'label')
                  ELSE NULL
                END AS threat_name
              FROM scans s
              LEFT JOIN LATERAL jsonb_array_elements(COALESCE(s.threats_json, '[]'::jsonb)) AS elem ON TRUE
              WHERE s.scanned_at >= (now() AT TIME ZONE 'utc') - (%s || ' days')::interval
                AND (%s IS NULL OR s.user_id = %s)
            )
            SELECT
              threat_name,
              COUNT(*)::int AS hits,
              MAX(scanned_at) AS last_seen
            FROM extracted
            WHERE threat_name IS NOT NULL
              AND threat_name <> ''
              AND (%s IS NULL OR threat_name ILIKE ('%%' || %s || '%%'))
            GROUP BY threat_name
            HAVING COUNT(*) >= %s
            ORDER BY hits DESC, last_seen DESC
            LIMIT %s;
            """
            cur.execute(sql, (days, user_id, user_id, name, name, min_count, limit))
            return cur.fetchall()
    finally:
        _put_conn(conn)


def get_threat_recent_scans(
    threat_name: str,
    days: int = 30,
    user_id: Optional[int] = None,  # kept for compatibility; not used in query below
    limit: int = 100,
) -> List[Dict[str, Any]]:
    conn = None
    try:
        conn = _get_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            sql = """
            WITH extracted AS (
              SELECT
                s.id,
                s.filename,
                s.sha256,
                s.mime_type,
                s.safe,
                s.message,
                s.scanned_at,
                CASE
                  WHEN jsonb_typeof(elem) = 'string'
                    THEN trim(both '"' from elem::text)
                  WHEN jsonb_typeof(elem) = 'object'
                    THEN COALESCE(elem->>'name', elem->>'threat', elem->>'label')
                  ELSE NULL
                END AS threat_name
              FROM scans s
              LEFT JOIN LATERAL jsonb_array_elements(COALESCE(s.threats_json, '[]'::jsonb)) AS elem ON TRUE
              WHERE s.scanned_at >= (now() AT TIME ZONE 'utc') - (%s || ' days')::interval
            )
            SELECT
              id,
              filename,
              sha256,
              mime_type,
              safe,
              message,
              scanned_at
            FROM extracted
            WHERE (%s IS NULL OR threat_name ILIKE ('%%' || %s || '%%'))
            ORDER BY scanned_at DESC
            LIMIT %s;
            """
            cur.execute(sql, (days, threat_name, threat_name, limit))
            return cur.fetchall()
    finally:
        _put_conn(conn)
