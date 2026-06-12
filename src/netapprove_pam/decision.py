"""The three-return-code rule (spec §4) as a pure, testable function.

This is the Phase 2 deliverable. It contains NO PAM/pamh references so it can be
unit-tested directly; pam_netapprove.py maps ``PamCode`` to the libpam constants.

    Approved + signature verifies   -> PAM_SUCCESS          (success=done)
    Denied OR signature invalid     -> PAM_AUTH_ERR         (default=die, no fallback)
    Genuine outage, local console   -> PAM_AUTHINFO_UNAVAIL (fall back to password)
    Genuine outage, remote (SSH)    -> PAM_AUTH_ERR         (console-only fallback)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from netapprove_core.challenge import Challenge
from netapprove_core.verifier import Verifier

from .backends import ApprovalResponse, Decision, RelayOutage


class PamCode(enum.Enum):
    SUCCESS = "success"
    AUTH_ERR = "auth_err"
    AUTHINFO_UNAVAIL = "authinfo_unavail"


@dataclass(frozen=True)
class PamDecision:
    code: PamCode
    reason: str
    fell_back: bool = False  # True when an outage routed to the password fallback (alert!)


class _Backend:
    """Structural type: anything with request_approval(challenge) -> ApprovalResponse."""

    def request_approval(self, challenge: Challenge) -> ApprovalResponse: ...


def decide(
    challenge: Challenge,
    backend: _Backend,
    verifier: Verifier,
    pinned_public_key: bytes,
    now_unix: int,
    *,
    is_remote: bool,
) -> PamDecision:
    """Run one approval attempt and map it to a PAM return code. Fail closed."""
    try:
        response = backend.request_approval(challenge)
    except RelayOutage as outage:
        if is_remote:
            return PamDecision(PamCode.AUTH_ERR, f"outage on remote session, no fallback: {outage}")
        return PamDecision(PamCode.AUTHINFO_UNAVAIL, f"relay outage, falling back to password: {outage}", fell_back=True)

    if response.decision is Decision.DENIED:
        return PamDecision(PamCode.AUTH_ERR, "approval denied on device (final, no fallback)")

    result = verifier.verify_approval(challenge, response.signature or b"", pinned_public_key, now_unix)
    if not result.approved:
        return PamDecision(PamCode.AUTH_ERR, f"signature rejected: {result.detail}")

    return PamDecision(PamCode.SUCCESS, "approved on device; signature verified against pinned key")
