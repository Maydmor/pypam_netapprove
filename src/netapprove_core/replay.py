"""Replay protection: timestamp window + nonce cache with TTL (spec §1, Phase 1).

A signed response is accepted only if its challenge timestamp is inside the
validity window AND its nonce has not been seen before. The cache TTL equals the
window: once a challenge can no longer be valid, its nonce is free to purge.
"""

from __future__ import annotations


class NonceCache:
    """Remembers seen nonces until they expire. Single-process, in-memory.

    Time is passed in explicitly (``now_unix``) rather than read from the clock so
    the cache is deterministic and testable. The PAM module supplies wall-clock time.
    """

    def __init__(self, ttl_seconds: int):
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds}")

        self._ttl = ttl_seconds
        self._seen: dict[bytes, int] = {}  # nonce -> expiry unix time

    def _purge_expired(self, now_unix: int) -> None:
        expired = [nonce for nonce, expiry in self._seen.items() if expiry <= now_unix]
        for nonce in expired:
            del self._seen[nonce]

    def has_seen(self, nonce: bytes, now_unix: int) -> bool:
        self._purge_expired(now_unix)
        return nonce in self._seen

    def remember(self, nonce: bytes, now_unix: int) -> None:
        """Record a nonce as used. Raises if it was already seen (replay)."""
        if self.has_seen(nonce, now_unix):
            raise ReplayError(f"nonce already seen: {nonce.hex()[:16]}…")

        self._seen[nonce] = now_unix + self._ttl

    def __len__(self) -> int:
        return len(self._seen)


def is_within_window(timestamp_unix: int, now_unix: int, window_seconds: int) -> bool:
    """True iff timestamp is recent enough and not implausibly in the future.

    Allows a small forward skew (one window) to tolerate clock drift between the
    challenge issuer and verifier; rejects anything older than the window.
    """
    if window_seconds <= 0:
        raise ValueError(f"window_seconds must be positive, got {window_seconds}")

    age = now_unix - timestamp_unix
    return -window_seconds <= age <= window_seconds


class ReplayError(Exception):
    """A nonce was presented more than once."""
