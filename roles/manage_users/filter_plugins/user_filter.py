from __future__ import annotations

import copy
import crypt
import re
from typing import Any


SENSITIVE_EXACT_KEYS = {
    "password",
    "password_salt",
    "password_rounds",
    "private_key",
}

PASSWORD_KEY_RE = re.compile(r"^(password.*|passwd.*)$", re.IGNORECASE)
VALID_SALT_RE = re.compile(r"[^A-Za-z0-9./]")


def _safe_salt(value: str | None, fallback: str = "localuser") -> str:
    raw = value or fallback
    cleaned = VALID_SALT_RE.sub("", raw)
    return cleaned or fallback


def _sha512_hash_password(password: str, salt: str, rounds: int = 656000) -> str:
    safe = _safe_salt(salt)
    full_salt = f"$6$rounds={int(rounds)}${safe}$"
    return crypt.crypt(password, full_salt)


def normalize_manage_user(user: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(user, dict):
        raise TypeError("normalize_manage_user expects a dict")

    result = copy.deepcopy(user)

    password_hash = result.get("password_hash")
    plaintext = result.get("password")
    salt = result.get("password_salt", result.get("username", "localuser"))
    rounds = int(result.get("password_rounds", 656000))

    if password_hash is not None and plaintext is not None:
        raise ValueError("User cannot define both password_hash and password")

    if password_hash is None and plaintext is not None:
        result["password_hash"] = _sha512_hash_password(
            password=str(plaintext),
            salt=str(salt),
            rounds=rounds,
        )

    for key in ("password", "password_salt", "password_rounds"):
        result.pop(key, None)

    ssh_keypair = result.get("ssh_keypair")
    if isinstance(ssh_keypair, dict):
        cleaned = {}
        for key, value in ssh_keypair.items():
            if key == "private_key" or PASSWORD_KEY_RE.match(str(key)):
                cleaned[key] = "REDACTED"
            else:
                cleaned[key] = value
        result["ssh_keypair"] = cleaned

    return result


def normalize_manage_users(users: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(users, list):
        raise TypeError("normalize_manage_users expects a list")
    return [normalize_manage_user(user) for user in users]


def redact_sensitive(obj: Any) -> Any:
    if isinstance(obj, dict):
        redacted = {}
        for key, value in obj.items():
            key_str = str(key)

            if key_str == "password_hash":
                redacted[key] = value
            elif key_str in SENSITIVE_EXACT_KEYS or PASSWORD_KEY_RE.match(key_str):
                redacted[key] = "REDACTED"
            else:
                redacted[key] = redact_sensitive(value)
        return redacted

    if isinstance(obj, list):
        return [redact_sensitive(item) for item in obj]

    return obj


class FilterModule(object):
    def filters(self) -> dict[str, Any]:
        return {
            "normalize_manage_user": normalize_manage_user,
            "normalize_manage_users": normalize_manage_users,
            "redact_sensitive": redact_sensitive,
        }