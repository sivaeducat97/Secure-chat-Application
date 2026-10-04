import hashlib
import hmac
import json
import os
import re
from pathlib import Path

USERS_FILE = Path("users.json")
ITERATIONS = 210_000


def _load_users():
    if not USERS_FILE.exists():
        return {}

    try:
        return json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_users(users):
    USERS_FILE.write_text(
        json.dumps(users, indent=4),
        encoding="utf-8"
    )


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS
    )


def register_user(username, password):
    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
        return False, "Username must be 3-24 characters."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    users = _load_users()

    if username in users:
        return False, "Username already exists."

    salt = os.urandom(16)
    password_hash = _hash_password(password, salt)

    users[username] = {
        "salt": salt.hex(),
        "password_hash": password_hash.hex(),
        "iterations": ITERATIONS
    }

    _save_users(users)

    return True, "Registration successful."


def authenticate_user(username, password):
    users = _load_users()

    record = users.get(username)

    if not record:
        return False

    try:
        salt = bytes.fromhex(record["salt"])
        stored_hash = bytes.fromhex(record["password_hash"])

        iterations = int(
            record.get("iterations", ITERATIONS)
        )

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )

        return hmac.compare_digest(
            candidate,
            stored_hash
        )

    except (KeyError, ValueError, TypeError):
        return False