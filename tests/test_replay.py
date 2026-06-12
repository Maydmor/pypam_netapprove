"""Replay protection tests: timestamp window + nonce cache TTL."""

import pytest

from netapprove_core.replay import NonceCache, ReplayError, is_within_window

N1 = b"\x01" * 32
N2 = b"\x02" * 32


def test_window_accepts_fresh():
    assert is_within_window(1000, now_unix=1030, window_seconds=90) is True


def test_window_rejects_expired():
    assert is_within_window(1000, now_unix=1100, window_seconds=90) is False


def test_window_tolerates_small_forward_skew():
    assert is_within_window(1000, now_unix=950, window_seconds=90) is True


def test_window_rejects_far_future():
    assert is_within_window(1000, now_unix=800, window_seconds=90) is False


def test_remember_then_seen():
    cache = NonceCache(ttl_seconds=90)
    cache.remember(N1, now_unix=1000)
    assert cache.has_seen(N1, now_unix=1000) is True
    assert cache.has_seen(N2, now_unix=1000) is False


def test_replay_raises():
    cache = NonceCache(ttl_seconds=90)
    cache.remember(N1, now_unix=1000)
    with pytest.raises(ReplayError):
        cache.remember(N1, now_unix=1000)


def test_nonce_purged_after_ttl():
    cache = NonceCache(ttl_seconds=90)
    cache.remember(N1, now_unix=1000)
    assert cache.has_seen(N1, now_unix=1091) is False
    # purged -> can be remembered again without raising
    cache.remember(N1, now_unix=1091)
    assert len(cache) == 1


def test_rejects_nonpositive_ttl():
    with pytest.raises(ValueError):
        NonceCache(ttl_seconds=0)
