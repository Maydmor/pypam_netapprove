"""Approval backends: where the signed response comes from.

Both backends return an ``ApprovalResponse`` (APPROVED + signature, or DENIED) or
raise ``RelayOutage`` to signal a genuine network outage. The PAM decision logic
(decision.py) treats these three cases differently — that distinction is the whole
point of the three-return-code design.

- MockBackend (Phase 2): a local root-owned private key auto-signs/denies/outages,
  isolating the return-code logic from networking.
- NetworkBackend (Phase 3): talks to the untrusted relay via the pinned TLS client.
"""

from __future__ import annotations

import base64
import enum
from dataclasses import dataclass
from pathlib import Path

from netapprove_core.challenge import Challenge
from netapprove_core.crypto import sign


class Decision(enum.Enum):
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True)
class ApprovalResponse:
    decision: Decision
    signature: bytes | None  # present iff APPROVED

    @classmethod
    def approved(cls, signature: bytes) -> "ApprovalResponse":
        return cls(Decision.APPROVED, signature)

    @classmethod
    def denied(cls) -> "ApprovalResponse":
        return cls(Decision.DENIED, None)


class RelayOutage(Exception):
    """The relay was unreachable (connect/read failure, timeout, or TLS pin mismatch)."""


def _load_private_key(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"mock private key not found: {str(path)!r}")
    return base64.b64decode(path.read_text().strip(), validate=True)


class MockBackend:
    """Phase 2 stand-in for the phone. Decision is fixed by config, not interactive."""

    def __init__(self, mode: str, private_key_path: Path | None):
        if mode not in ("approve", "deny", "unavail"):
            raise ValueError(f"invalid mock_mode {mode!r}; expected approve|deny|unavail")
        if mode == "approve" and private_key_path is None:
            raise ValueError("mock_mode='approve' requires mock_private_key_path")

        self._mode = mode
        self._private_key_path = private_key_path

    def request_approval(self, challenge: Challenge) -> ApprovalResponse:
        if self._mode == "unavail":
            raise RelayOutage("mock backend simulating outage")
        if self._mode == "deny":
            return ApprovalResponse.denied()

        private_key = _load_private_key(self._private_key_path)
        signature = sign(private_key, challenge.to_canonical_bytes())
        return ApprovalResponse.approved(signature)
