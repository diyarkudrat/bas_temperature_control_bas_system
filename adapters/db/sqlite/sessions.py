import sqlite3
from typing import List, Optional

from domains.auth.models import Session
from domains.auth.serializers import session_from_dict, session_to_dict


class SessionsTable:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init()

    def _init(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                last_access REAL NOT NULL,
                fingerprint TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                user_id TEXT DEFAULT 'unknown',
                tenant_id TEXT
            )
            '''
        )
        conn.commit(); conn.close()

    def upsert(self, session: Session) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        record = session_to_dict(session)
        cur.execute(
            '''
            INSERT OR REPLACE INTO sessions
            (session_id, username, role, created_at, expires_at, last_access, fingerprint, ip_address, user_agent, user_id, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                record["session_id"],
                record["username"],
                record["role"],
                record["created_at"],
                record["expires_at"],
                record["last_access"],
                record["fingerprint"],
                record["ip_address"],
                record["user_agent"],
                record["user_id"],
                record["tenant_id"],
            ),
        )
        conn.commit(); conn.close()

    def delete(self, session_id: str) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit(); conn.close()

    def get_by_username_active(self, username: str, now: float) -> List[Session]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('SELECT * FROM sessions WHERE username = ? AND expires_at > ?', (username, now))
        rows = cur.fetchall()
        desc = cur.description
        conn.close()
        cols = [d[0] for d in desc]
        out: List[Session] = []
        for row in rows:
            data = dict(zip(cols, row))
            out.append(session_from_dict(data))
        return out
