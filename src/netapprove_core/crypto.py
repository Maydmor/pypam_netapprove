"""Ed25519 sign/verify over raw 32-byte keys (spec §1, Phase 1).

Ed25519 is the chosen primitive: small, fast, no parameters to misconfigure.
Keys and signatures are handled as raw bytes so the wire contract stays trivial
for the phone app to reproduce.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

PUBLIC_KEY_LEN = 32
PRIVATE_KEY_LEN = 32
SIGNATURE_LEN = 64


@dataclass(frozen=True)
class Keypair:
    """A raw Ed25519 keypair. The private half is the phone-secure-enclave stand-in."""

    private_key: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> "Keypair":
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        return cls(
            private_key=private.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ),
            public_key=public.public_bytes(Encoding.Raw, PublicFormat.Raw),
        )


def sign(private_key: bytes, message: bytes) -> bytes:
    if len(private_key) != PRIVATE_KEY_LEN:
        raise ValueError(f"private_key must be {PRIVATE_KEY_LEN} bytes, got {len(private_key)}")

    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return key.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff signature is valid. Never raises on a bad signature — fail closed."""
    if len(public_key) != PUBLIC_KEY_LEN:
        raise ValueError(f"public_key must be {PUBLIC_KEY_LEN} bytes, got {len(public_key)}")
    if len(signature) != SIGNATURE_LEN:
        return False

    key = Ed25519PublicKey.from_public_bytes(public_key)

    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
