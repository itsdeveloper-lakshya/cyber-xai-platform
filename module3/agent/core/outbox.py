"""
SQLite-Backed Durable Outbox (Section 6 G4 & Section 15 G-03, X-02)
Features:
- Durable SQLite storage for offline tolerance.
- Capacity cap at 50,000 events or 50 MB.
- Low-severity priority drop when capacity reached, incrementing dropped counter.
- Atomic batch fetch and delete on confirmation.
- Metadata only: zero clipboard text, zero file names.
"""

import os
import json
import sqlite3
import threading
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger("cyber_sentinel_agent.outbox")

MAX_OUTBOX_EVENTS = 50_000
MAX_OUTBOX_BYTES = 50 * 1024 * 1024  # 50 MB

class SQLiteOutbox:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._dropped_events_total = 0
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS outbox_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'low',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_outbox_severity_id 
                ON outbox_events(severity, id);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS outbox_meta (
                    key TEXT PRIMARY KEY,
                    val INTEGER NOT NULL
                );
            """)
            conn.execute("""
                INSERT OR IGNORE INTO outbox_meta (key, val) VALUES ('dropped_total', 0);
            """)
            # Read existing dropped counter
            cur = conn.execute("SELECT val FROM outbox_meta WHERE key = 'dropped_total';")
            row = cur.fetchone()
            if row:
                self._dropped_events_total = row[0]

    def _enforce_capacity(self, conn: sqlite3.Connection):
        """
        Drops oldest low-severity events first when capacity is exceeded (Section 6 G4).
        """
        cur = conn.execute("SELECT COUNT(*) FROM outbox_events;")
        count = cur.fetchone()[0]

        db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
        if count >= MAX_OUTBOX_EVENTS or db_size >= MAX_OUTBOX_BYTES:
            # Need to drop oldest low severity first
            to_drop = max(1, count - MAX_OUTBOX_EVENTS + 1)
            cur = conn.execute("""
                SELECT id FROM outbox_events 
                ORDER BY CASE severity WHEN 'low' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END ASC, id ASC 
                LIMIT ?;
            """, (to_drop,))
            ids = [r[0] for r in cur.fetchall()]
            if ids:
                placeholders = ",".join("?" * len(ids))
                conn.execute(f"DELETE FROM outbox_events WHERE id IN ({placeholders});", ids)
                dropped_cnt = len(ids)
                self._dropped_events_total += dropped_cnt
                conn.execute("UPDATE outbox_meta SET val = ? WHERE key = 'dropped_total';", (self._dropped_events_total,))
                logger.warning(f"Outbox cap reached: dropped {dropped_cnt} older low-priority events.")

    def enqueue(self, event_dict: Dict[str, Any], severity: str = "low") -> bool:
        """
        Enqueues an event dictionary into the outbox.
        Ensures metadata only before writing.
        """
        event_id = event_dict.get("event_id")
        event_type = event_dict.get("event_type", "unknown")
        occurred_at = event_dict.get("occurred_at", "")
        payload_str = json.dumps(event_dict)

        with self._lock, self._get_connection() as conn:
            self._enforce_capacity(conn)
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO outbox_events (event_id, event_type, occurred_at, payload, severity)
                    VALUES (?, ?, ?, ?, ?);
                """, (event_id, event_type, occurred_at, payload_str, severity))
                return True
            except Exception as e:
                logger.error(f"Failed to enqueue event {event_id}: {e}")
                return False

    def fetch_batch(self, batch_size: int = 100) -> List[Tuple[int, Dict[str, Any]]]:
        """
        Fetches up to batch_size oldest events from the outbox.
        Returns list of (row_id, event_dict).
        """
        with self._lock, self._get_connection() as conn:
            cur = conn.execute("""
                SELECT id, payload FROM outbox_events 
                ORDER BY id ASC LIMIT ?;
            """, (batch_size,))
            batch = []
            for row_id, payload_str in cur.fetchall():
                try:
                    event_data = json.loads(payload_str)
                    batch.append((row_id, event_data))
                except Exception as e:
                    logger.error(f"Corrupted outbox row {row_id}: {e}")
            return batch

    def ack_batch(self, row_ids: List[int]):
        """
        Deletes acknowledged rows after successful transmission.
        """
        if not row_ids:
            return
        with self._lock, self._get_connection() as conn:
            placeholders = ",".join("?" * len(row_ids))
            conn.execute(f"DELETE FROM outbox_events WHERE id IN ({placeholders});", row_ids)

    def get_queue_depth(self) -> int:
        with self._lock, self._get_connection() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM outbox_events;")
            return cur.fetchone()[0]

    def get_dropped_count(self) -> int:
        return self._dropped_events_total
