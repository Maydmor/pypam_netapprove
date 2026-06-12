"""End-to-end Phase 1 verification: tamper/expired/replayed/wrong-key all reject."""

import pytest

from netapprove_core.challenge import Challenge
from netapprove_core.crypto import Keypair, sign
from netapprove_core.verifier import VerifyOutcome, Verifier

WINDOW = 90


@pytest.fixture
def keypair():
    return Keypair.generate()


def signed(challenge, private_key):
    return sign(private_key, challenge.to_canonical_bytes())


def test_valid_approval(keypair):
    v = Verifier(validity_window_seconds=WINDOW)
    c = Challenge.create("alice", "box", "tty1", 1000)
    sig = signed(c, keypair.private_key)
    result = v.verify_approval(c, sig, keypair.public_key, now_unix=1010)
    assert result.approved
    assert result.outcome is VerifyOutcome.APPROVED


def test_tampered_field_rejected(keypair):
    v = Verifier(validity_window_seconds=WINDOW)
    c = Challenge.create("alice", "box", "tty1", 1000)
    sig = signed(c, keypair.private_key)
    # attacker swaps user after signing
    forged = Challenge(user="root", host=c.host, tty=c.tty, timestamp_unix=c.timestamp_unix, nonce=c.nonce)
    result = v.verify_approval(forged, sig, keypair.public_key, now_unix=1010)
    assert result.outcome is VerifyOutcome.BAD_SIGNATURE


def test_expired_rejected(keypair):
    v = Verifier(validity_window_seconds=WINDOW)
    c = Challenge.create("alice", "box", "tty1", 1000)
    sig = signed(c, keypair.private_key)
    result = v.verify_approval(c, sig, keypair.public_key, now_unix=1000 + WINDOW + 5)
    assert result.outcome is VerifyOutcome.EXPIRED


def test_wrong_key_rejected(keypair):
    v = Verifier(validity_window_seconds=WINDOW)
    other = Keypair.generate()
    c = Challenge.create("alice", "box", "tty1", 1000)
    sig = signed(c, keypair.private_key)
    result = v.verify_approval(c, sig, other.public_key, now_unix=1010)
    assert result.outcome is VerifyOutcome.BAD_SIGNATURE


def test_replayed_nonce_rejected(keypair):
    v = Verifier(validity_window_seconds=WINDOW)
    c = Challenge.create("alice", "box", "tty1", 1000)
    sig = signed(c, keypair.private_key)
    first = v.verify_approval(c, sig, keypair.public_key, now_unix=1010)
    second = v.verify_approval(c, sig, keypair.public_key, now_unix=1011)
    assert first.approved
    assert second.outcome is VerifyOutcome.REPLAYED


def test_bad_signature_does_not_consume_nonce(keypair):
    # An attacker must not be able to burn a nonce with an invalid signature,
    # which would block the legitimate approval that follows.
    v = Verifier(validity_window_seconds=WINDOW)
    c = Challenge.create("alice", "box", "tty1", 1000)
    bad = v.verify_approval(c, b"\x00" * 64, keypair.public_key, now_unix=1010)
    assert bad.outcome is VerifyOutcome.BAD_SIGNATURE
    good = v.verify_approval(c, signed(c, keypair.private_key), keypair.public_key, now_unix=1011)
    assert good.approved
