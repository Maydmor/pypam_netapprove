"""Local verification: the security heart (spec §2).

Approval is a signature verified locally against a pinned public key — never the
relay's word. This module ties together canonical serialization, Ed25519 verify,
the timestamp window, and the nonce cache into one decision.

The result distinguishes *why* a verification failed, because the PAM layer maps
"denied / invalid" to PAM_AUTH_ERR (final, no fallback) and only a network outage
to PAM_AUTHINFO_UNAVAIL. Outage is detected at the client layer, not here — this
module only ever produces APPROVED or a hard rejection.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from .challenge import Challenge
from .crypto import verify
from .replay import NonceCache, ReplayError, is_within_window


class VerifyOutcome(enum.Enum):
    APPROVED = "approved"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    REPLAYED = "replayed"


@dataclass(frozen=True)
class VerifyResult:
    outcome: VerifyOutcome
    detail: str

    @property
    def approved(self) -> bool:
        return self.outcome is VerifyOutcome.APPROVED


class Verifier:
    """Verifies signed approvals for one machine against pinned per-user keys."""

    def __init__(self, *, validity_window_seconds: int, nonce_cache: NonceCache | None = None):
        if validity_window_seconds <= 0:
            raise ValueError(f"validity_window_seconds must be positive, got {validity_window_seconds}")

        self._window = validity_window_seconds
        self._nonces = nonce_cache or NonceCache(ttl_seconds=validity_window_seconds)

    def verify_approval(
        self,
        challenge: Challenge,
        signature: bytes,
        pinned_public_key: bytes,
        now_unix: int,
    ) -> VerifyResult:
        """Decide whether a signed response approves this exact challenge.

        Order: cheap freshness check, then crypto, then replay (which mutates the
        cache only once the signature is known good — an attacker must not be able
        to evict/poison nonces with unsigned garbage).
        """
        message = challenge.to_canonical_bytes()
        fresh = is_within_window(challenge.timestamp_unix, now_unix, self._window)
        signature_ok = verify(pinned_public_key, message, signature)

        if not fresh:
            age = now_unix - challenge.timestamp_unix
            return VerifyResult(VerifyOutcome.EXPIRED, f"challenge age {age}s outside ±{self._window}s window")
        if not signature_ok:
            return VerifyResult(VerifyOutcome.BAD_SIGNATURE, "signature does not verify against pinned key")

        try:
            self._nonces.remember(challenge.nonce, now_unix)
        except ReplayError as exc:
            return VerifyResult(VerifyOutcome.REPLAYED, str(exc))

        return VerifyResult(VerifyOutcome.APPROVED, "signature verified against pinned key")
