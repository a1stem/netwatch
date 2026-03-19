"""
data/history.py
---------------
Append-only SQLite log of every connection seen since the app started.
Provides the "what connected while I was away?" audit trail.

Schema is intentionally denormalised for fast single-table queries.
"""

from __future__ import annotations
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from backend.poller import ConnectionRecord

log = logging.getLogger(__name__)

_DEFAULT_DB = os.path.join(os.path.dirname(__file__), "connections.db")

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS connections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    seen_at      TEXT    NOT NULL,
    local_ip     TEXT,
    local_port   INTEGER,
    remote_ip    TEXT,
    remote_port  INTEGER,
    remote_host  TEXT,
    proto        TEXT,
    status       TEXT,
    pid          INTEGER,
    app_name     TEXT,
    app_exe      TEXT,
    iface_name   TEXT,
    iface_type   TEXT,
    is_wifi      INTEGER,
    is_vpn       INTEGER,
    tls_status   TEXT,
    is_plaintext INTEGER,
    geo_country  TEXT,
    geo_flag     TEXT,
    is_trusted   INTEGER,
    is_blocked   INTEGER,
    is_pkg_mgr   INTEGER,
    pkg_risk     TEXT
);
CREATE INDEX IF NOT EXISTS idx_seen_at    ON connections(seen_at);
CREATE INDEX IF NOT EXISTS idx_remote_ip  ON connections(remote_ip);
CREATE INDEX IF NOT EXISTS idx_app_name   ON connections(app_name);
CREATE INDEX IF NOT EXISTS idx_is_blocked ON connections(is_blocked);
"""


class History:
    """
    Thread-safe SQLite history log.

    The poller calls log_batch() from its worker thread.
    The GUI calls query_*() from the main thread.
    A single write lock serialises all writes.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as db:
                db.executescript(_CREATE_SQL)
        log.info("history: database ready at %s", self._db_path)

    # ── Write ─────────────────────────────────────────────────────────────

    def log_batch(self, records: "list[ConnectionRecord]") -> None:
        """Log a full poll snapshot.  Skips duplicates seen in last 30s."""
        if not records:
            return
        rows = [self._to_row(r) for r in records]
        with self._lock:
            try:
                with self._connect() as db:
                    # Deduplicate: skip if identical (pid+remote+port) seen in last 30s
                    cutoff = (datetime.now() - timedelta(seconds=30)).isoformat()
                    for row in rows:
                        exists = db.execute(
                            "SELECT 1 FROM connections "
                            "WHERE pid=? AND remote_ip=? AND remote_port=? "
                            "AND seen_at > ? LIMIT 1",
                            (row["pid"], row["remote_ip"], row["remote_port"], cutoff),
                        ).fetchone()
                        if not exists:
                            db.execute(
                                """INSERT INTO connections
                                   (seen_at, local_ip, local_port, remote_ip, remote_port,
                                    remote_host, proto, status, pid, app_name, app_exe,
                                    iface_name, iface_type, is_wifi, is_vpn,
                                    tls_status, is_plaintext,
                                    geo_country, geo_flag,
                                    is_trusted, is_blocked, is_pkg_mgr, pkg_risk)
                                   VALUES
                                   (:seen_at,:local_ip,:local_port,:remote_ip,:remote_port,
                                    :remote_host,:proto,:status,:pid,:app_name,:app_exe,
                                    :iface_name,:iface_type,:is_wifi,:is_vpn,
                                    :tls_status,:is_plaintext,
                                    :geo_country,:geo_flag,
                                    :is_trusted,:is_blocked,:is_pkg_mgr,:pkg_risk)
                                """,
                                row,
                            )
            except Exception as exc:
                log.error("history: write error: %s", exc)

    @staticmethod
    def _to_row(r: "ConnectionRecord") -> dict:
        return dict(
            seen_at=datetime.now().isoformat(timespec="seconds"),
            local_ip=r.local_ip,
            local_port=r.local_port,
            remote_ip=r.remote_ip,
            remote_port=r.remote_port,
            remote_host=r.hostname or r.remote_ip,
            proto=r.proto,
            status=r.status,
            pid=r.pid,
            app_name=r.app_name,
            app_exe=r.app_exe,
            iface_name=r.iface.name if r.iface else "",
            iface_type=r.iface.iface_type.name if r.iface else "",
            is_wifi=int(r.is_wifi),
            is_vpn=int(r.is_vpn),
            tls_status=r.tls.status.name if r.tls else "",
            is_plaintext=int(r.is_plaintext),
            geo_country=r.geo.country_code if r.geo else "",
            geo_flag=r.geo.flag if r.geo else "",
            is_trusted=int(r.is_trusted),
            is_blocked=int(r.is_blocked),
            is_pkg_mgr=int(r.is_pkg_manager),
            pkg_risk=r.pkg_event.risk.name if r.pkg_event else "",
        )

    # ── Read ──────────────────────────────────────────────────────────────

    def query_recent(self, limit: int = 500) -> list[sqlite3.Row]:
        """Most recent N connections, newest first."""
        with self._connect() as db:
            return db.execute(
                "SELECT * FROM connections ORDER BY seen_at DESC LIMIT ?",
                (limit,)
            ).fetchall()

    def query_by_app(self, app_name: str, limit: int = 200) -> list[sqlite3.Row]:
        with self._connect() as db:
            return db.execute(
                "SELECT * FROM connections WHERE app_name LIKE ? "
                "ORDER BY seen_at DESC LIMIT ?",
                (f"%{app_name}%", limit)
            ).fetchall()

    def query_blocked(self) -> list[sqlite3.Row]:
        with self._connect() as db:
            return db.execute(
                "SELECT * FROM connections WHERE is_blocked=1 "
                "ORDER BY seen_at DESC"
            ).fetchall()

    def query_unknown(self) -> list[sqlite3.Row]:
        with self._connect() as db:
            return db.execute(
                "SELECT * FROM connections "
                "WHERE is_trusted=0 AND is_blocked=0 "
                "ORDER BY seen_at DESC LIMIT 200"
            ).fetchall()

    def query_since(self, since: datetime, limit: int = 1000) -> list[sqlite3.Row]:
        with self._connect() as db:
            return db.execute(
                "SELECT * FROM connections WHERE seen_at >= ? "
                "ORDER BY seen_at DESC LIMIT ?",
                (since.isoformat(timespec="seconds"), limit)
            ).fetchall()

    def stats(self) -> dict:
        with self._connect() as db:
            row = db.execute(
                "SELECT COUNT(*) as total, "
                "SUM(is_trusted) as trusted, "
                "SUM(is_blocked) as blocked, "
                "SUM(CASE WHEN is_trusted=0 AND is_blocked=0 THEN 1 ELSE 0 END) as unknown "
                "FROM connections"
            ).fetchone()
            return dict(row) if row else {}

    def purge_older_than(self, days: int = 30) -> int:
        """Remove records older than N days. Returns number deleted."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._lock:
            with self._connect() as db:
                cur = db.execute(
                    "DELETE FROM connections WHERE seen_at < ?", (cutoff,)
                )
                count = cur.rowcount
        if count:
            log.info("history: purged %d records older than %d days", count, days)
        return count
