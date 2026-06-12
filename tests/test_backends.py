"""MockBackend (Phase 2) and NetworkBackend polling (Phase 3) behavior."""

import base64

import pytest

from netapprove_core.challenge import Challenge
from netapprove_core.crypto import Keypair, verify
from netapprove_pam.backends import Decision, MockBackend, RelayOutage
from netapprove_pam.client import NetworkBackend, PollResult


@pytest.fixture
def challenge():
    return Challenge.create("alice", "box", "tty1", 1000)


def test_mock_approve_signs_canonical_bytes(tmp_path, challenge):
    kp = Keypair.generate()
    key_file = tmp_path / "k"
    key_file.write_text(base64.b64encode(kp.private_key).decode())
    backend = MockBackend("approve", key_file)
    response = backend.request_approval(challenge)
    assert response.decision is Decision.APPROVED
    assert verify(kp.public_key, challenge.to_canonical_bytes(), response.signature)


def test_mock_deny(challenge):
    assert MockBackend("deny", None).request_approval(challenge).decision is Decision.DENIED


def test_mock_unavail_raises_outage(challenge):
    with pytest.raises(RelayOutage):
        MockBackend("unavail", None).request_approval(challenge)


def test_mock_approve_requires_key():
    with pytest.raises(ValueError):
        MockBackend("approve", None)


class FakeClient:
    """Scripted poll results; submit returns a fixed id."""

    def __init__(self, poll_results):
        self._poll_results = list(poll_results)
        self.submitted = None

    def submit_challenge(self, challenge):
        self.submitted = challenge
        return "req-1"

    def poll(self, request_id):
        return self._poll_results.pop(0)


def make_network_backend(client, timeout=10):
    fake_clock = iter([0, 0, 1, 2, 3, 4, 5, 100, 200])
    return NetworkBackend(
        client,
        approval_timeout_seconds=timeout,
        poll_interval_seconds=0,
        clock=lambda: next(fake_clock),
        sleep=lambda _s: None,
    )


def test_network_approved_after_polling(challenge):
    sig_b64 = base64.b64encode(b"\x01" * 64).decode()
    client = FakeClient([PollResult("pending"), PollResult("approved", sig_b64)])
    response = make_network_backend(client).request_approval(challenge)
    assert response.decision is Decision.APPROVED
    assert response.signature == b"\x01" * 64


def test_network_denied(challenge):
    client = FakeClient([PollResult("denied")])
    response = make_network_backend(client).request_approval(challenge)
    assert response.decision is Decision.DENIED


def test_network_timeout_fails_closed_as_denied(challenge):
    # reachable relay, never resolves -> DENIED (no fallback), not an outage
    client = FakeClient([PollResult("pending")] * 10)
    response = make_network_backend(client, timeout=2).request_approval(challenge)
    assert response.decision is Decision.DENIED
