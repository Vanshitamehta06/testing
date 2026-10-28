"""User accounts stored in a SQLite database (DATABASE_PATH, default
data/app.db): salted PBKDF2 password hashing, sessions and single-use
password-reset codes. Data survives restarts."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
RESET_CODE_TTL_SECONDS = 15 * 60
RESET_MAX_ATTEMPTS = 5
_ITERATIONS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS reset_codes (
    email TEXT PRIMARY KEY REFERENCES users(email) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
);
"""


class AccountExistsError(Exception):
    pass


class InvalidAccountError(ValueError):
    pass


class InvalidResetCodeError(ValueError):
    pass


@dataclass
class User:
    email: str
    salt: bytes
    password_hash: bytes


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        db.execute("PRAGMA journal_mode = WAL")
    db.executescript(SCHEMA)
    return db


class UserStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.environ.get("DATABASE_PATH", "data/app.db")
        self._db = connect(self.path)
        self._lock = threading.Lock()

    @staticmethod
    def normalize(email: str) -> str:
        return email.strip().lower()

    @staticmethod
    def _check_password(password: str) -> None:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise InvalidAccountError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    def register(self, email: str, password: str) -> User:
        email = self.normalize(email)
        if not EMAIL_RE.match(email):
            raise InvalidAccountError("Enter a valid email address.")
        self._check_password(password)
        user = User(email=email, salt=secrets.token_bytes(16), password_hash=b"")
        user.password_hash = _hash(password, user.salt)
        with self._lock:
            try:
                with self._db:
                    self._db.execute(
                        "INSERT INTO users (email, salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
                        (email, user.salt, user.password_hash, time.time()),
                    )
            except sqlite3.IntegrityError as exc:
                raise AccountExistsError("An account with this email already exists.") from exc
        return user

    def _user(self, email: str) -> sqlite3.Row | None:
        return self._db.execute("SELECT * FROM users WHERE email = ?", (self.normalize(email),)).fetchone()

    def authenticate(self, email: str, password: str) -> str | None:
        """Return a new session token, or None if the credentials are wrong."""
        with self._lock:
            row = self._user(email)
        if row is None:
            # Hash anyway so response time does not reveal whether the email exists.
            _hash(password, secrets.token_bytes(16))
            return None
        if not hmac.compare_digest(_hash(password, row["salt"]), row["password_hash"]):
            return None
        token = secrets.token_urlsafe(32)
        with self._lock, self._db:
            # Only a hash of the token is stored: a leaked database can't be used to sign in.
            self._db.execute("INSERT INTO sessions (token_hash, email, created_at) VALUES (?, ?, ?)",
                             (_sha256(token), row["email"], time.time()))
        return token

    def user_for_token(self, token: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT email FROM sessions WHERE token_hash = ?", (_sha256(token),)).fetchone()
        return row["email"] if row else None

    # -- password reset ------------------------------------------------------
    def request_reset(self, email: str, now: float | None = None) -> str | None:
        """A new 6-digit reset code for the account, or None if there is no such
        account. Callers must answer the same way in both cases."""
        email = self.normalize(email)
        with self._lock:
            if self._user(email) is None:
                return None
            code = f"{secrets.randbelow(1_000_000):06d}"
            with self._db:
                self._db.execute(
                    "INSERT OR REPLACE INTO reset_codes (email, code_hash, expires_at, attempts) VALUES (?, ?, ?, 0)",
                    (email, _sha256(code), (now or time.time()) + RESET_CODE_TTL_SECONDS),
                )
        return code

    def reset_password(self, email: str, code: str, new_password: str, now: float | None = None) -> None:
        email = self.normalize(email)
        self._check_password(new_password)
        with self._lock, self._db:
            pending = self._db.execute("SELECT * FROM reset_codes WHERE email = ?", (email,)).fetchone()
            expired = pending is None or (now or time.time()) > pending["expires_at"]
            if expired or pending["attempts"] >= RESET_MAX_ATTEMPTS:
                self._db.execute("DELETE FROM reset_codes WHERE email = ?", (email,))
                raise InvalidResetCodeError("This reset code is invalid or has expired. Request a new one.")
            if not hmac.compare_digest(pending["code_hash"], _sha256(code.strip())):
                self._db.execute("UPDATE reset_codes SET attempts = attempts + 1 WHERE email = ?", (email,))
                self._db.commit()
                raise InvalidResetCodeError("That code is not correct.")
            salt = secrets.token_bytes(16)
            self._db.execute("UPDATE users SET salt = ?, password_hash = ? WHERE email = ?",
                             (salt, _hash(new_password, salt), email))
            self._db.execute("DELETE FROM reset_codes WHERE email = ?", (email,))  # single use
            # Sign out everywhere: a reset usually means the old password is compromised.
            self._db.execute("DELETE FROM sessions WHERE email = ?", (email,))
