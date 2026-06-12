"""Challenge model and the canonical serialization wire contract (spec §7).

The phone (signer) and the PAM module (verifier) MUST hash byte-identical input.
This module is the single source of truth for those bytes. Any reimplementation
(e.g. the phone app) must reproduce ``to_canonical_bytes`` exactly.
"""

from __future__ import annotations

import base64
import secrets
import struct
from dataclasses import dataclass

# Domain separation + version. Bump the trailing digit if the layout ever changes.
CHALLENGE_MAGIC = b"NAPCHAL1"

NONCE_LEN = 32
_U32_MAX = 0xFFFF_FFFF
# i64 range — timestamp is a signed 64-bit big-endian integer.
_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1


def _write_len_prefixed(out: bytearray, field_name: str, value: bytes) -> None:
    length = len(value)

    if length > _U32_MAX:
        raise ValueError(f"{field_name} length {length} exceeds u32 max {_U32_MAX}")

    out.extend(struct.pack(">I", length))
    out.extend(value)


@dataclass(frozen=True)
class Challenge:
    """A fresh approval challenge bound to {user, host, tty, timestamp, nonce}."""

    user: str
    host: str
    tty: str
    timestamp_unix: int
    nonce: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, (bytes, bytearray)):
            raise TypeError(f"nonce must be bytes, got {type(self.nonce).__name__}")
        if len(self.nonce) != NONCE_LEN:
            raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(self.nonce)}")
        if not isinstance(self.timestamp_unix, int) or isinstance(self.timestamp_unix, bool):
            raise TypeError(f"timestamp_unix must be int, got {type(self.timestamp_unix).__name__}")
        if not (_I64_MIN <= self.timestamp_unix <= _I64_MAX):
            raise ValueError(f"timestamp_unix {self.timestamp_unix} out of i64 range")

    @classmethod
    def create(cls, user: str, host: str, tty: str, timestamp_unix: int) -> "Challenge":
        """Build a challenge with a fresh cryptographically-random 256-bit nonce."""
        return cls(
            user=user,
            host=host,
            tty=tty,
            timestamp_unix=timestamp_unix,
            nonce=secrets.token_bytes(NONCE_LEN),
        )

    def to_canonical_bytes(self) -> bytes:
        """Explicit, length-prefixed, big-endian encoding (spec §7).

        Layout: MAGIC(8) | u32 user_len | user | u32 host_len | host |
                u32 tty_len | tty | i64 timestamp | nonce(32)
        """
        user_bytes = self.user.encode("utf-8")
        host_bytes = self.host.encode("utf-8")
        tty_bytes = self.tty.encode("utf-8")

        out = bytearray()
        out.extend(CHALLENGE_MAGIC)
        _write_len_prefixed(out, "user", user_bytes)
        _write_len_prefixed(out, "host", host_bytes)
        _write_len_prefixed(out, "tty", tty_bytes)
        out.extend(struct.pack(">q", self.timestamp_unix))
        out.extend(self.nonce)
        return bytes(out)

    def to_wire(self) -> dict:
        """JSON-friendly representation for the relay (NOT the signed bytes).

        The signature is always computed over ``to_canonical_bytes``; this wire form
        only carries the fields so the approver can display and reconstruct them.
        """
        return {
            "user": self.user,
            "host": self.host,
            "tty": self.tty,
            "timestamp_unix": self.timestamp_unix,
            "nonce_b64": base64.b64encode(self.nonce).decode("ascii"),
        }

    @classmethod
    def from_wire(cls, data: dict) -> "Challenge":
        missing = {"user", "host", "tty", "timestamp_unix", "nonce_b64"} - data.keys()
        if missing:
            raise ValueError(f"challenge wire data missing fields: {sorted(missing)}")

        return cls(
            user=data["user"],
            host=data["host"],
            tty=data["tty"],
            timestamp_unix=int(data["timestamp_unix"]),
            nonce=base64.b64decode(data["nonce_b64"], validate=True),
        )

    def human_summary(self, *, now_unix: int | None = None) -> str:
        """Human-readable line for the phone/CLI to display before approval."""
        if now_unix is None:
            age = ""
        else:
            age = f", {now_unix - self.timestamp_unix}s ago"
        return f"{self.user}@{self.host} wants sudo (tty {self.tty}{age})"
