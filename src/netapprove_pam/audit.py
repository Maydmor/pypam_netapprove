"""Audit logging (spec §8): log every request/approval/denial/fallback.

Uses syslog (auth facility) on Linux; degrades to stderr elsewhere so the module
imports and is testable on non-Linux dev machines. The fallback alert is logged at
ALERT level — it is the downgrade-attack tripwire (spec §3).
"""

from __future__ import annotations

import sys

try:
    import syslog

    _HAVE_SYSLOG = True
except ImportError:  # non-Linux dev/test
    syslog = None
    _HAVE_SYSLOG = False


def _emit(level_name: str, message: str, syslog_level: int | None) -> None:
    if _HAVE_SYSLOG:
        syslog.openlog("pam_netapprove", syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(syslog_level, message)
        return
    print(f"[pam_netapprove/{level_name}] {message}", file=sys.stderr)


def notice(message: str) -> None:
    _emit("notice", message, syslog.LOG_NOTICE if _HAVE_SYSLOG else None)


def warning(message: str) -> None:
    _emit("warning", message, syslog.LOG_WARNING if _HAVE_SYSLOG else None)


def error(message: str) -> None:
    _emit("error", message, syslog.LOG_ERR if _HAVE_SYSLOG else None)


def alert(message: str) -> None:
    _emit("alert", message, syslog.LOG_ALERT if _HAVE_SYSLOG else None)
