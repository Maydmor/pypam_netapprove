"""Phase 2 deliverable: the three-return-code logic, every branch."""

import pytest

from netapprove_core.challenge import Challenge
from netapprove_core.crypto import Keypair, sign
from netapprove_core.verifier import Verifier
from netapprove_pam.backends import ApprovalResponse, RelayOutage
from netapprove_pam.decision import PamCode, decide

WINDOW = 90


@pytest.fixture
def keypair():
    return Keypair.generate()


@pytest.fixture
def challenge():
    return Challenge.create("alice", "box", "tty1", 1000)


def verifier():
    return Verifier(validity_window_seconds=WINDOW)


class FixedBackend:
    def __init__(self, response=None, outage=False):
        self._response = response
        self._outage = outage

    def request_approval(self, challenge):
        if self._outage:
            raise RelayOutage("simulated")
        return self._response


def test_approved_signature_verifies_returns_success(keypair, challenge):
    sig = sign(keypair.private_key, challenge.to_canonical_bytes())
    backend = FixedBackend(ApprovalResponse.approved(sig))
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1010, is_remote=False)
    assert decision.code is PamCode.SUCCESS


def test_denied_returns_auth_err_no_fallback(keypair, challenge):
    backend = FixedBackend(ApprovalResponse.denied())
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1010, is_remote=False)
    assert decision.code is PamCode.AUTH_ERR
    assert decision.fell_back is False


def test_invalid_signature_returns_auth_err(keypair, challenge):
    backend = FixedBackend(ApprovalResponse.approved(b"\x00" * 64))
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1010, is_remote=False)
    assert decision.code is PamCode.AUTH_ERR


def test_signature_from_wrong_key_returns_auth_err(keypair, challenge):
    attacker = Keypair.generate()
    sig = sign(attacker.private_key, challenge.to_canonical_bytes())
    backend = FixedBackend(ApprovalResponse.approved(sig))
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1010, is_remote=False)
    assert decision.code is PamCode.AUTH_ERR


def test_outage_on_console_falls_back(keypair, challenge):
    backend = FixedBackend(outage=True)
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1010, is_remote=False)
    assert decision.code is PamCode.AUTHINFO_UNAVAIL
    assert decision.fell_back is True


def test_outage_on_remote_session_hard_fails(keypair, challenge):
    # console-only fallback: SSH outage must NOT downgrade to password
    backend = FixedBackend(outage=True)
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1010, is_remote=True)
    assert decision.code is PamCode.AUTH_ERR
    assert decision.fell_back is False


def test_expired_approval_returns_auth_err(keypair, challenge):
    sig = sign(keypair.private_key, challenge.to_canonical_bytes())
    backend = FixedBackend(ApprovalResponse.approved(sig))
    decision = decide(challenge, backend, verifier(), keypair.public_key, 1000 + WINDOW + 5, is_remote=False)
    assert decision.code is PamCode.AUTH_ERR
