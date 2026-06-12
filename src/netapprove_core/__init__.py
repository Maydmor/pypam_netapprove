"""netapprove_core — the language-agnostic security heart (Phase 1).

No PAM, no network, no phone. Challenge model + canonical serialization,
Ed25519 sign/verify, replay protection, and pinned-key verification.
"""

from .challenge import CHALLENGE_MAGIC, NONCE_LEN, Challenge
from .crypto import (
    PUBLIC_KEY_LEN,
    PRIVATE_KEY_LEN,
    SIGNATURE_LEN,
    Keypair,
    sign,
    verify,
)
from .keystore import PinnedKeyError, load_pinned_key, write_pinned_key
from .replay import NonceCache, ReplayError, is_within_window
from .verifier import VerifyOutcome, VerifyResult, Verifier

__all__ = [
    "CHALLENGE_MAGIC",
    "NONCE_LEN",
    "Challenge",
    "PUBLIC_KEY_LEN",
    "PRIVATE_KEY_LEN",
    "SIGNATURE_LEN",
    "Keypair",
    "sign",
    "verify",
    "PinnedKeyError",
    "load_pinned_key",
    "write_pinned_key",
    "NonceCache",
    "ReplayError",
    "is_within_window",
    "VerifyOutcome",
    "VerifyResult",
    "Verifier",
]
