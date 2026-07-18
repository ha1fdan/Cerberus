import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

DB_PATH = os.environ.get("DB_PATH", "app/data/cerberus.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    nickname TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    icon_url TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
"""

INVITE_TTL_SECONDS = 60 * 60  # 1 hour


@contextmanager
def get_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA)


def is_empty() -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return row["n"] == 0


# --- users ---

def create_user(username: str, display_name: str, is_admin: bool = False) -> sqlite3.Row:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, display_name, is_admin, created_at) VALUES (?, ?, ?, ?)",
            (username, display_name, int(is_admin), int(time.time())),
        )
        return conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_users() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()


def delete_user(user_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def bump_token_version(user_id: int):
    with get_db() as conn:
        conn.execute("UPDATE users SET token_version = token_version + 1 WHERE id = ?", (user_id,))


# --- credentials ---

def add_credential(user_id: int, credential_id: bytes, public_key: bytes, sign_count: int,
                    transports: Optional[str], nickname: Optional[str]):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO credentials (user_id, credential_id, public_key, sign_count, transports, nickname, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, credential_id, public_key, sign_count, transports, nickname, int(time.time())),
        )


def get_credential_by_credential_id(credential_id: bytes) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()


def list_credentials_for_user(user_id: int) -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at ASC", (user_id,)
        ).fetchall()


def count_credentials_for_user(user_id: int) -> int:
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM credentials WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row["n"]


def update_credential_sign_count(credential_id: bytes, sign_count: int):
    with get_db() as conn:
        conn.execute(
            "UPDATE credentials SET sign_count = ? WHERE credential_id = ?",
            (sign_count, credential_id),
        )


def delete_credential(credential_db_id: int, user_id: int):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM credentials WHERE id = ? AND user_id = ?", (credential_db_id, user_id)
        )


def delete_all_credentials_for_user(user_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM credentials WHERE user_id = ?", (user_id,))


# --- invites ---

def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def create_invite(user_id: int) -> str:
    raw_token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO invites (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (_hash_token(raw_token), user_id, int(time.time()) + INVITE_TTL_SECONDS, int(time.time())),
        )
    return raw_token


def get_valid_invite(raw_token: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM invites WHERE token_hash = ?", (_hash_token(raw_token),)
        ).fetchone()
        if row is None:
            return None
        if row["used"] or row["expires_at"] < int(time.time()):
            return None
        return row


def mark_invite_used(token_hash: str):
    with get_db() as conn:
        conn.execute("UPDATE invites SET used = 1 WHERE token_hash = ?", (token_hash,))


# --- apps ---

def list_apps() -> list[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute("SELECT * FROM apps ORDER BY sort_order ASC, created_at ASC").fetchall()


def add_app(name: str, url: str, icon_url: Optional[str]):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO apps (name, url, icon_url, sort_order, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, url, icon_url or None, 0, int(time.time())),
        )


def delete_app(app_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM apps WHERE id = ?", (app_id,))
