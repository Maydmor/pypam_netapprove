"""PAM module entrypoint for libpam-python (spec §4, Phases 2-3).

Installed as the implementation behind a `pam_python.so` line in a PAM service:

    auth [success=done authinfo_unavail=ignore default=die] \\
         pam_python.so /usr/local/lib/netapprove/pam_netapprove.py config=/etc/netapprove/config.toml

It builds a fresh challenge from the PAM context, asks the configured backend for a
signed approval, verifies the signature LOCALLY against the user's pinned key, and
returns exactly one of three PAM codes. See decision.py for the rule.

⚠ Never test against /etc/pam.d/sudo first. Use a throwaway service (sudotest) with
a root shell held open — see docs/PHASE2_TESTING.md.
"""

from __future__ import annotations

import os
import socket
import time

from netapprove_core.challenge import Challenge
from netapprove_core.keystore import PinnedKeyError, load_pinned_key
from netapprove_core.verifier import Verifier

from . import audit
from .backends import MockBackend
from .client import NetworkBackend, RelayClient
from .config import DEFAULT_CONFIG_PATH, Config
from .decision import PamCode, PamDecision, decide
from .session import is_remote_session


def _parse_args(argv: list[str]) -> dict[str, str]:
    # argv[0] is this module's path; remaining are key=value PAM args.
    pairs = (token.split("=", 1) for token in argv[1:] if "=" in token)
    return {key: value for key, value in pairs}


def _log(decision: PamDecision, user: str, challenge: Challenge) -> None:
    nonce_hex = challenge.nonce.hex()[:16]
    line = (
        f"decision={decision.code.value} user={user} host={challenge.host} "
        f"tty={challenge.tty} ts={challenge.timestamp_unix} nonce={nonce_hex} reason={decision.reason}"
    )
    emit = audit.notice if decision.code is PamCode.SUCCESS else audit.warning
    emit(line)

    if decision.fell_back:
        # The downgrade-attack tripwire (spec §3, §8). Alert on every fallback.
        audit.alert(f"FALLBACK to local password for user={user} host={challenge.host} tty={challenge.tty}")


def _build_backend(config: Config):
    if config.backend == "mock":
        return MockBackend(config.mock_mode, config.mock_private_key_path)
    if config.backend == "network":
        client = RelayClient(config.relay_url, config.cert_fingerprint_sha256, config.request_timeout_seconds)
        return NetworkBackend(client, config.approval_timeout_seconds, config.poll_interval_seconds)
    raise ValueError(f"unknown backend {config.backend!r}; expected mock|network")


def _tty_for(pamh) -> str:
    tty = pamh.get_item(pamh.PAM_TTY)
    return tty or os.environ.get("SSH_TTY") or "unknown"


def _resolve_decision(pamh, config: Config) -> tuple[PamDecision, str, Challenge]:
    user = pamh.get_user(None)
    if not user:
        raise PinnedKeyError("PAM did not provide a user name")

    host = socket.gethostname()
    tty = _tty_for(pamh)
    now = int(time.time())

    challenge = Challenge.create(user=user, host=host, tty=tty, timestamp_unix=now)
    pinned_key = load_pinned_key(user, config.pin_dir)
    backend = _build_backend(config)
    verifier = Verifier(validity_window_seconds=config.validity_window_seconds)
    remote = is_remote_session(dict(os.environ), tty)

    if remote and config.allow_ssh_fallback:
        remote = False  # operator explicitly opted out of console-only fallback

    decision = decide(challenge, backend, verifier, pinned_key, now, is_remote=remote)
    return decision, user, challenge


def _notify(pamh, text: str) -> None:
    try:
        pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, text))
    except Exception:
        pass  # conversation is best-effort UX, never block auth on it


_CODE_MAP = {
    PamCode.SUCCESS: "PAM_SUCCESS",
    PamCode.AUTH_ERR: "PAM_AUTH_ERR",
    PamCode.AUTHINFO_UNAVAIL: "PAM_AUTHINFO_UNAVAIL",
}


def pam_sm_authenticate(pamh, flags, argv):
    config = Config.load(_config_path(argv))

    try:
        _notify(pamh, "Approve this sudo request on your phone…")
        decision, user, challenge = _resolve_decision(pamh, config)
    except PinnedKeyError as exc:
        # No enrolled key / unsafe pin file → cannot do strong auth. Fail closed.
        audit.error(f"enrollment/pin error: {exc}")
        return pamh.PAM_AUTH_ERR
    except Exception as exc:  # defensive: any bug fails closed, never silent-success
        audit.error(f"unexpected error, failing closed: {exc!r}")
        return pamh.PAM_AUTH_ERR

    _log(decision, user, challenge)
    return getattr(pamh, _CODE_MAP[decision.code])


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def _config_path(argv):
    args = _parse_args(list(argv))
    raw = args.get("config")
    return type(DEFAULT_CONFIG_PATH)(raw) if raw else DEFAULT_CONFIG_PATH
