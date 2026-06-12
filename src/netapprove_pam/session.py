"""Detect whether the sudo session is remote (SSH) — gates console-only fallback.

Per Phase 0, the local-password fallback is allowed only on a physical console.
A remote session is the main threat, so over SSH an outage hard-fails instead of
downgrading. Detection uses the SSH_* environment markers and the tty name.
"""

from __future__ import annotations


def is_remote_session(env: dict[str, str], tty: str | None) -> bool:
    if env.get("SSH_CONNECTION") or env.get("SSH_CLIENT") or env.get("SSH_TTY"):
        return True
    if tty and tty.startswith("pts/") and not env.get("DISPLAY"):
        # A pseudo-terminal with no local X display is most likely remote.
        return True
    return False
