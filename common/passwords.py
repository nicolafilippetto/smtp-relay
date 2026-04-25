"""Bcrypt password hashing helpers.

Used for:
  - SMTP local account passwords
  - UI admin password

The cost factor is set in `common/constants.py`. Bcrypt silently
truncates passwords longer than 72 bytes in versions < 5.0, and raises
in bcrypt 5+. We normalise to a sha256 pre-hash only when the raw
password exceeds the bcrypt limit, then base64-encode to avoid NUL
bytes. This preserves full entropy without tripping bcrypt's length
check, a well-known pattern used by Django and others.
"""

from __future__ import annotations

import base64
import hashlib

import bcrypt

from .constants import BCRYPT_COST_FACTOR

_BCRYPT_MAX_BYTES = 72


def _prepare(password: str) -> bytes:
    """Normalise the password to bcrypt-safe bytes."""
    if password is None:
        raise ValueError("Password is required.")
    raw = password.encode("utf-8")
    if len(raw) <= _BCRYPT_MAX_BYTES:
        return raw
    # Pre-hash long passwords. base64 keeps the result within bcrypt's
    # 72-byte budget and avoids NULs that bcrypt would reject.
    digest = hashlib.sha256(raw).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """Return a bcrypt hash string suitable for storage in the DB."""
    salted = bcrypt.gensalt(rounds=BCRYPT_COST_FACTOR)
    return bcrypt.hashpw(_prepare(password), salted).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time verification of a password against a stored hash."""
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(_prepare(password), hashed.encode("ascii"))
    except (ValueError, TypeError):
        # Malformed hash in DB; treat as failure rather than raising.
        return False
