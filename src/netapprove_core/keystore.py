"""Pinned public key storage — the root of trust (spec §2, Phase 0 enrollment).

A user's enrolled public key lives in a root-owned file:

    /etc/netapprove/pinned_keys.d/<user>.pub   (base64 of the 32 raw key bytes)

The verifier reads the key from here and nowhere else. If an attacker can write
this file, the whole scheme is moot — Phase 5 makes the directory immutable
(``chattr +i``). On non-Linux dev machines the ownership check is skipped.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from .crypto import PUBLIC_KEY_LEN

DEFAULT_PIN_DIR = Path("/etc/netapprove/pinned_keys.d")


def _assert_root_owned(path: Path) -> None:
    if sys.platform != "linux":
        return  # ownership semantics differ off-Linux; dev machines skip the check.

    stat = path.stat()
    if stat.st_uid != 0:
        raise PinnedKeyError(f"pinned key {str(path)!r} must be owned by root (uid 0), got uid {stat.st_uid}")
    if stat.st_mode & 0o022:
        raise PinnedKeyError(f"pinned key {str(path)!r} is group/world-writable (mode {oct(stat.st_mode)})")


def pin_path_for(user: str, pin_dir: Path = DEFAULT_PIN_DIR) -> Path:
    if not user or "/" in user or user in (".", ".."):
        raise ValueError(f"invalid user name for pin path: {user!r}")
    return Path(pin_dir) / f"{user}.pub"


def load_pinned_key(user: str, pin_dir: Path = DEFAULT_PIN_DIR) -> bytes:
    """Return the raw 32-byte pinned public key for ``user``. Fail closed."""
    path = pin_path_for(user, pin_dir)

    if not path.is_file():
        raise PinnedKeyError(f"no pinned key for user {user!r} at {str(path)!r}")

    _assert_root_owned(path)
    raw = base64.b64decode(path.read_text().strip(), validate=True)

    if len(raw) != PUBLIC_KEY_LEN:
        raise PinnedKeyError(f"pinned key for {user!r} is {len(raw)} bytes, expected {PUBLIC_KEY_LEN}")

    return raw


def write_pinned_key(user: str, public_key: bytes, pin_dir: Path = DEFAULT_PIN_DIR) -> Path:
    """Enroll (or re-enroll) a user's pinned key. Admin/root operation."""
    if len(public_key) != PUBLIC_KEY_LEN:
        raise ValueError(f"public_key must be {PUBLIC_KEY_LEN} bytes, got {len(public_key)}")

    path = pin_path_for(user, pin_dir)
    Path(pin_dir).mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(public_key).decode("ascii") + "\n")
    os.chmod(path, 0o644)
    return path


class PinnedKeyError(Exception):
    """A pinned key is missing, malformed, or not safely owned."""
