"""In-memory user accounts: salted PBKDF2 password hashing, sessions and
single-use password-reset codes."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
RESET_CODE_TTL_SECONDS = 15 * 60
RESET_MAX_ATTEMPTS = 5
_ITERATIONS = 200_000


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


@dataclass
class ResetCode:
    code_hash: str
    expires_at: float
    attempts: int = 0


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


class UserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._sessions: dict[str, str] = {}
        self._resets: dict[str, ResetCode] = {}

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
        if email in self._users:
            raise AccountExistsError("An account with this email already exists.")
        salt = secrets.token_bytes(16)
        user = User(email=email, salt=salt, password_hash=_hash(password, salt))
        self._users[email] = user
        return user

    def authenticate(self, email: str, password: str) -> str | None:
        """Return a new session token, or None if the credentials are wrong."""
        user = self._users.get(self.normalize(email))
        if user is None:
            # Hash anyway so response time does not reveal whether the email exists.
            _hash(password, secrets.token_bytes(16))
            return None
        if not hmac.compare_digest(_hash(password, user.salt), user.password_hash):
            return None
        token = secrets.token_urlsafe(32)
        self._sessions[token] = user.email
        return token

    def user_for_token(self, token: str) -> str | None:
        return self._sessions.get(token)

    # -- password reset ------------------------------------------------------
    def request_reset(self, email: str, now: float | None = None) -> str | None:
        """A new 6-digit reset code for the account, or None if there is no such
        account. Callers must answer the same way in both cases."""
        email = self.normalize(email)
        if email not in self._users:
            return None
        code = f"{secrets.randbelow(1_000_000):06d}"
        self._resets[email] = ResetCode(_code_hash(code), (now or time.time()) + RESET_CODE_TTL_SECONDS)
        return code

    def reset_password(self, email: str, code: str, new_password: str, now: float | None = None) -> None:
        email = self.normalize(email)
        self._check_password(new_password)
        pending = self._resets.get(email)
        if pending is None or (now or time.time()) > pending.expires_at or pending.attempts >= RESET_MAX_ATTEMPTS:
            self._resets.pop(email, None)
            raise InvalidResetCodeError("This reset code is invalid or has expired. Request a new one.")
        if not hmac.compare_digest(pending.code_hash, _code_hash(code.strip())):
            pending.attempts += 1
            raise InvalidResetCodeError("That code is not correct.")
        user = self._users[email]
        user.salt = secrets.token_bytes(16)
        user.password_hash = _hash(new_password, user.salt)
        del self._resets[email]  # single use
        # Sign out everywhere: a reset usually means the old password is compromised.
        self._sessions = {t: e for t, e in self._sessions.items() if e != email}
