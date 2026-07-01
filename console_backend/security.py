from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from .db import Database, utcnow


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2_sha256$310000$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode(),
        base64.urlsafe_b64encode(digest).decode(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt_text, digest_text = encoded.split("$", 3)
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def create_session(db: Database, user_id: int, hours: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    db.execute(
        "INSERT INTO sessions(token_hash,user_id,csrf_hash,expires_at) VALUES(?,?,?,?)",
        (token_hash(token), user_id, token_hash(csrf), expires.isoformat()),
    )
    return token, csrf


def session_user(db: Database, token: str) -> dict | None:
    if not token:
        return None
    row = db.one(
        "SELECT u.*,s.csrf_hash,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND u.active=1",
        (token_hash(token),),
    )
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))
        return None
    return row


def delete_session(db: Database, token: str) -> None:
    if token:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))

