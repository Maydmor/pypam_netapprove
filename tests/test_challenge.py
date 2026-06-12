"""Canonical serialization tests (spec §7 required tests)."""

import struct

import pytest
from hypothesis import given, strategies as st

from netapprove_core.challenge import CHALLENGE_MAGIC, NONCE_LEN, Challenge

NONCE = bytes(range(32))


def make(user="alice", host="box", tty="tty1", ts=1_700_000_000, nonce=NONCE):
    return Challenge(user=user, host=host, tty=tty, timestamp_unix=ts, nonce=nonce)


def test_deterministic():
    assert make().to_canonical_bytes() == make().to_canonical_bytes()


def test_starts_with_magic():
    assert make().to_canonical_bytes().startswith(CHALLENGE_MAGIC)


def test_injective_across_field_boundary():
    # ("ab","c") must not collide with ("a","bc").
    a = make(user="ab", host="c").to_canonical_bytes()
    b = make(user="a", host="bc").to_canonical_bytes()
    assert a != b


@pytest.mark.parametrize(
    "field,value",
    [
        ("user", "bob"),
        ("host", "other"),
        ("tty", "pts/3"),
        ("ts", 1_700_000_001),
    ],
)
def test_every_scalar_field_is_bound(field, value):
    base = make().to_canonical_bytes()
    kwargs = {"user": "alice", "host": "box", "tty": "tty1", "ts": 1_700_000_000}
    kwargs[field] = value
    assert make(**kwargs).to_canonical_bytes() != base


def test_every_nonce_byte_is_bound():
    base = make().to_canonical_bytes()
    for i in range(NONCE_LEN):
        mutated = bytearray(NONCE)
        mutated[i] ^= 0xFF
        assert make(nonce=bytes(mutated)).to_canonical_bytes() != base


def test_layout_exact():
    c = make(user="ab", host="c", tty="t", ts=1, nonce=NONCE)
    raw = c.to_canonical_bytes()
    expected = (
        CHALLENGE_MAGIC
        + struct.pack(">I", 2) + b"ab"
        + struct.pack(">I", 1) + b"c"
        + struct.pack(">I", 1) + b"t"
        + struct.pack(">q", 1)
        + NONCE
    )
    assert raw == expected


def test_negative_timestamp_roundtrips_as_signed():
    raw = make(ts=-5).to_canonical_bytes()
    # last 8 bytes before the nonce encode the signed timestamp
    ts_bytes = raw[-(8 + NONCE_LEN):-NONCE_LEN]
    assert struct.unpack(">q", ts_bytes)[0] == -5


def test_utf8_multibyte_length_is_bytes_not_chars():
    c = make(user="é")  # 1 char, 2 UTF-8 bytes
    raw = c.to_canonical_bytes()
    user_len = struct.unpack(">I", raw[8:12])[0]
    assert user_len == 2


def test_rejects_wrong_nonce_length():
    with pytest.raises(ValueError):
        Challenge(user="a", host="b", tty="c", timestamp_unix=0, nonce=b"short")


def test_rejects_bool_timestamp():
    with pytest.raises(TypeError):
        Challenge(user="a", host="b", tty="c", timestamp_unix=True, nonce=NONCE)


def test_create_generates_unique_nonces():
    a = Challenge.create("u", "h", "t", 0)
    b = Challenge.create("u", "h", "t", 0)
    assert a.nonce != b.nonce
    assert len(a.nonce) == NONCE_LEN


@given(
    user=st.text(max_size=20),
    host=st.text(max_size=20),
    tty=st.text(max_size=20),
)
def test_property_injective_user_host(user, host, tty):
    # Splitting the same concatenation differently must change the encoding,
    # unless the split point is identical.
    c1 = make(user=user, host=host, tty=tty)
    combined = user + host
    for split in range(len(combined) + 1):
        c2 = make(user=combined[:split], host=combined[split:], tty=tty)
        if (c2.user, c2.host) != (c1.user, c1.host):
            assert c2.to_canonical_bytes() != c1.to_canonical_bytes()
