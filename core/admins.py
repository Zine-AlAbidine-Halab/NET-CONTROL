"""
admins.py — simple admin account management for the control panel.

Accounts are stored in admins.json next to this package. Passwords are
never stored in plain text: each is salted and hashed with PBKDF2.

An initial administrator is created only with an explicit strong password
provided through NETCONTROL_ADMIN_PASSWORD on first run.
"""

import hashlib
import json
import os
import secrets
import threading

from .alerts import log_event

ADMINS_PATH = os.path.join(os.path.dirname(__file__), "..", "admins.json")
_lock = threading.Lock()

_PBKDF2_ROUNDS = 200_000


def _hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), _PBKDF2_ROUNDS
    ).hex()
    return salt, digest


def _load():
    if not os.path.exists(ADMINS_PATH):
        return {}
    with open(ADMINS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save(data):
    with open(ADMINS_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=4)


def ensure_bootstrap_admin():
    """Bootstrap only from environment; never use published credentials."""
    with _lock:
        existing = _load()
        if existing:
            return
        username = os.environ.get("NETCONTROL_ADMIN_USER", "admin").strip()
        password = os.environ.get("NETCONTROL_ADMIN_PASSWORD", "")
        if not username or not password or len(password) < 12:
            raise RuntimeError(
                "First start: set NETCONTROL_ADMIN_PASSWORD to a unique "
                "password of at least 12 characters."
            )
        salt, digest = _hash_password(password)
        _save({username: {"salt": salt, "hash": digest}})
        log_event("ADMIN", f"Initial administrator '{username}' created", "info")


def verify(username, password):
    admins = _load()
    record = admins.get(username)
    if not record:
        return False
    _, digest = _hash_password(password, record["salt"])
    # secrets.compare_digest avoids timing attacks.
    return secrets.compare_digest(digest, record["hash"])


def list_admins():
    return sorted(_load().keys())


def add_admin(username, password):
    if not username or len(password) < 12:
        return False, "Username and password of at least 12 characters required"
    with _lock:
        admins = _load()
        if username in admins:
            return False, "Admin already exists"
        salt, digest = _hash_password(password)
        admins[username] = {"salt": salt, "hash": digest}
        _save(admins)
    log_event("ADMIN", f"Admin account '{username}' added", "info")
    return True, "created"


def remove_admin(username, requested_by):
    with _lock:
        admins = _load()
        if username not in admins:
            return False, "Admin does not exist"
        if len(admins) == 1:
            return False, "Cannot remove the last admin"
        if username == requested_by:
            return False, "You cannot remove your own active account"
        del admins[username]
        _save(admins)
    log_event("ADMIN", f"Admin account '{username}' removed", "warning")
    return True, "removed"
