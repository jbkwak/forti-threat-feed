"""수집한 URL의 중복 제거 및 임시(로컬) 저장소.

SQLite 하나로 '이미 본 URL', 'Forti에 아직 못 밀어넣은 URL', VirusTotal 조회 결과,
웹 대시보드 설정(예: VT API 키)을 함께 추적한다.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_urls (
    url TEXT PRIMARY KEY,
    raw_url TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    pushed INTEGER NOT NULL DEFAULT 0,
    pushed_at TEXT,
    vt_status TEXT,
    vt_malicious INTEGER,
    vt_total INTEGER,
    vt_checked_at TEXT,
    fg_status TEXT,
    fg_category TEXT,
    fg_category_id INTEGER,
    fg_checked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_seen_urls_date ON seen_urls (first_seen);
CREATE INDEX IF NOT EXISTS idx_seen_urls_source ON seen_urls (source);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

# 기존에 만들어진 DB(위 컬럼들이 추가되기 전)를 위한 마이그레이션
_MIGRATION_COLUMNS = {
    "fg_status": "TEXT",
    "fg_category": "TEXT",
    "fg_category_id": "INTEGER",
    "fg_checked_at": "TEXT",
}


def _migrate(conn):
    existing = {row[1] for row in conn.execute("PRAGMA table_info(seen_urls)")}
    for col, coltype in _MIGRATION_COLUMNS.items():
        if col in existing:
            continue
        try:
            conn.execute(f"ALTER TABLE seen_urls ADD COLUMN {col} {coltype}")
        except sqlite3.OperationalError as e:
            # 동시 요청이 먼저 같은 컬럼을 추가한 경우(레이스 컨디션)는 무시
            if "duplicate column name" not in str(e):
                raise


@contextmanager
def connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    _migrate(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def add_new_urls(conn, triples):
    """처음 보는 URL만 삽입. triples: (url, source, raw_url) 이터러블. 반환값: 신규 삽입 개수."""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.executemany(
        "INSERT OR IGNORE INTO seen_urls (url, raw_url, source, first_seen) VALUES (?, ?, ?, ?)",
        [(url, raw_url, source, now) for url, source, raw_url in triples],
    )
    return cur.rowcount


def mark_pushed(conn, urls):
    if not urls:
        return
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "UPDATE seen_urls SET pushed = 1, pushed_at = ? WHERE url = ?",
        [(now, url) for url in urls],
    )


COLUMNS = [
    "url", "raw_url", "source", "first_seen", "pushed", "pushed_at",
    "vt_status", "vt_malicious", "vt_total", "vt_checked_at",
    "fg_status", "fg_category", "fg_category_id", "fg_checked_at",
]


def search_urls(conn, date=None, source=None, q=None, fg_category=None, page=1, page_size=50):
    """날짜(YYYY-MM-DD, KST 기준)/출처/검색어/FortiGuard 카테고리로 필터링.

    fg_category는 실제 카테고리명(예: "Malicious Websites") 외에 특수값을 받는다:
      "__unchecked__" - 아직 FortiGuard 조회를 안 한 URL (fg_status IS NULL)
      "__not_found__" - FortiGuard에 등록되지 않은 URL (fg_status = 'not_found')

    반환값: (row dict 목록, 전체 건수)
    """
    where, params = [], []
    if date:
        # first_seen은 UTC로 저장되어 있으므로 KST(UTC+9) 기준 날짜로 변환해 비교
        where.append("date(datetime(first_seen, '+9 hours')) = ?")
        params.append(date)
    if source:
        where.append("source = ?")
        params.append(source)
    if q:
        where.append("url LIKE ?")
        params.append(f"%{q}%")
    if fg_category == "__unchecked__":
        where.append("fg_status IS NULL")
    elif fg_category == "__not_found__":
        where.append("fg_status = 'not_found'")
    elif fg_category:
        where.append("fg_category = ?")
        params.append(fg_category)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""

    total = conn.execute(f"SELECT COUNT(*) FROM seen_urls {where_sql}", params).fetchone()[0]

    offset = (page - 1) * page_size
    rows = conn.execute(
        f"SELECT {', '.join(COLUMNS)} FROM seen_urls {where_sql} "
        f"ORDER BY first_seen DESC LIMIT ? OFFSET ?",
        params + [page_size, offset],
    ).fetchall()

    return [dict(zip(COLUMNS, row)) for row in rows], total


def list_dates(conn):
    """URL이 수집된 날짜 목록 (KST 기준, 최신순)."""
    rows = conn.execute(
        "SELECT DISTINCT date(datetime(first_seen, '+9 hours')) AS d FROM seen_urls ORDER BY d DESC"
    ).fetchall()
    return [r[0] for r in rows]


def list_fg_categories(conn):
    """FortiGuard 조회 결과로 나온 카테고리 목록 + 건수 (건수 많은 순)."""
    rows = conn.execute(
        "SELECT fg_category, fg_category_id, COUNT(*) FROM seen_urls "
        "WHERE fg_status = 'found' AND fg_category IS NOT NULL "
        "GROUP BY fg_category, fg_category_id ORDER BY COUNT(*) DESC"
    ).fetchall()
    return [{"category": r[0], "category_id": r[1], "count": r[2]} for r in rows]


def get_fg_status_counts(conn):
    """FortiGuard 미확인/미등록 건수 (카테고리 드롭다운의 특수 옵션용)."""
    unchecked = conn.execute("SELECT COUNT(*) FROM seen_urls WHERE fg_status IS NULL").fetchone()[0]
    not_found = conn.execute("SELECT COUNT(*) FROM seen_urls WHERE fg_status = 'not_found'").fetchone()[0]
    return {"unchecked": unchecked, "not_found": not_found}


def raw_urls_for(conn, urls):
    """url(정규화) -> raw_url 매핑."""
    if not urls:
        return {}
    placeholders = ",".join("?" * len(urls))
    rows = conn.execute(
        f"SELECT url, raw_url FROM seen_urls WHERE url IN ({placeholders})", urls
    ).fetchall()
    return dict(rows)


def update_vt_result(conn, url, status, malicious, total):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE seen_urls SET vt_status = ?, vt_malicious = ?, vt_total = ?, vt_checked_at = ? "
        "WHERE url = ?",
        (status, malicious, total, now, url),
    )


def update_fg_result(conn, url, status, category, category_id):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE seen_urls SET fg_status = ?, fg_category = ?, fg_category_id = ?, fg_checked_at = ? "
        "WHERE url = ?",
        (status, category, category_id, now, url),
    )


def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(conn, key, value):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_forti_config(conn) -> dict:
    """웹 설정(DB)이 있으면 우선 사용, 없으면 .env 값으로 대체."""
    return {
        "host": get_setting(conn, "forti_host") or os.environ.get("FORTIPROXY_HOST"),
        "api_key": get_setting(conn, "forti_api_key") or os.environ.get("FORTIPROXY_TOKEN"),
        "resource_name": get_setting(conn, "forti_resource_name")
        or os.environ.get("FORTIPROXY_RESOURCE_NAME"),
        # FortiProxy는 대부분 자체서명 인증서를 쓰므로 기본은 검증 생략(curl -k와 동일)
        "verify_ssl": os.environ.get("VERIFY_SSL", "false").lower() == "true",
    }


def get_vt_api_key(conn) -> str | None:
    return get_setting(conn, "vt_api_key") or os.environ.get("VT_API_KEY")


def get_fortiguard_api_key(conn) -> str | None:
    return get_setting(conn, "fortiguard_api_key") or os.environ.get("FORTIGUARD_API_KEY")
