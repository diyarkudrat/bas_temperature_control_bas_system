import sqlite3
from typing import Optional

from domains.auth.models import User
from domains.auth.serializers import user_from_dict, user_to_dict


class UsersTable:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init()

    def _init(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                created_at REAL NOT NULL,
                last_login REAL DEFAULT 0,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0,
                password_history TEXT DEFAULT '[]'
            )
            '''
        )
        conn.commit(); conn.close()

    def get(self, username: str) -> Optional[User]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        desc = cur.description
        conn.close()
        if not row:
            return None
        cols = [d[0] for d in desc]
        data = dict(zip(cols, row))
        return user_from_dict(data)

    def upsert(self, user: User) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        record = user_to_dict(user)
        cur.execute(
            '''
            INSERT OR REPLACE INTO users 
            (username, password_hash, salt, role, created_at, last_login, failed_attempts, locked_until, password_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                record["username"],
                record["password_hash"],
                record["salt"],
                record["role"],
                record["created_at"],
                record["last_login"],
                record["failed_attempts"],
                record["locked_until"],
                record["password_history"],
            ),
        )
        conn.commit(); conn.close()
