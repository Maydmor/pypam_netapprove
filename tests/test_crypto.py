"""Ed25519 sign/verify tests."""

import pytest

from netapprove_core.crypto import (
    PUBLIC_KEY_LEN,
    PRIVATE_KEY_LEN,
    SIGNATURE_LEN,
    Keypair,
    sign,
    verify,
)


def test_keypair_lengths():
    kp = Keypair.generate()
    assert len(kp.private_key) == PRIVATE_KEY_LEN
    assert len(kp.public_key) == PUBLIC_KEY_LEN


def test_sign_then_verify_roundtrip():
    kp = Keypair.generate()
    msg = b"hello challenge bytes"
    sig = sign(kp.private_key, msg)
    assert len(sig) == SIGNATURE_LEN
    assert verify(kp.public_key, msg, sig) is True


def test_tampered_message_fails():
    kp = Keypair.generate()
    sig = sign(kp.private_key, b"original")
    assert verify(kp.public_key, b"tampered", sig) is False


def test_wrong_key_fails():
    signer = Keypair.generate()
    other = Keypair.generate()
    sig = sign(signer.private_key, b"msg")
    assert verify(other.public_key, b"msg", sig) is False


def test_truncated_signature_returns_false_not_raise():
    kp = Keypair.generate()
    sig = sign(kp.private_key, b"msg")
    assert verify(kp.public_key, b"msg", sig[:-1]) is False


def test_bad_key_length_raises():
    with pytest.raises(ValueError):
        verify(b"short", b"msg", b"\x00" * SIGNATURE_LEN)
    with pytest.raises(ValueError):
        sign(b"short", b"msg")
