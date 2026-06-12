"""Phase 3 end-to-end through the real relay app (no real sockets, no phone).

Exercises the full byte path: PAM submits a challenge -> relay holds it pending ->
approver fetches it, signs the canonical bytes, posts back -> PAM polls -> verifies
the signature locally against the pinned key. Also proves a denial and the relay's
inability to forge an approval.
"""

import base64

import pytest
from fastapi.testclient import TestClient

from netapprove_core.challenge import Challenge
from netapprove_core.crypto import Keypair, sign
from netapprove_core.verifier import Verifier
from netapprove_relay.app import app, store


@pytest.fixture
def client():
    store.requests.clear()
    return TestClient(app)


@pytest.fixture
def keypair():
    return Keypair.generate()


def submit(client, challenge):
    resp = client.post("/requests", json={"challenge": challenge.to_wire()})
    assert resp.status_code == 200
    return resp.json()["request_id"]


def approver_signs(client, request_id, challenge, private_key):
    # The approver reconstructs the challenge from the relay and signs canonical bytes.
    pending = client.get("/requests/pending").json()["pending"]
    item = next(p for p in pending if p["request_id"] == request_id)
    reconstructed = Challenge.from_wire(item["challenge"])
    sig = sign(private_key, reconstructed.to_canonical_bytes())
    body = {"decision": "approve", "signature_b64": base64.b64encode(sig).decode()}
    assert client.post(f"/requests/{request_id}/respond", json=body).status_code == 200


def test_full_approve_flow(client, keypair):
    challenge = Challenge.create("alice", "box", "tty1", 1000)
    request_id = submit(client, challenge)
    approver_signs(client, request_id, challenge, keypair.private_key)

    result = client.get(f"/requests/{request_id}").json()
    assert result["status"] == "approved"

    sig = base64.b64decode(result["signature_b64"])
    verdict = Verifier(validity_window_seconds=90).verify_approval(challenge, sig, keypair.public_key, 1005)
    assert verdict.approved


def test_deny_flow(client):
    challenge = Challenge.create("alice", "box", "tty1", 1000)
    request_id = submit(client, challenge)
    client.post(f"/requests/{request_id}/respond", json={"decision": "deny"})
    assert client.get(f"/requests/{request_id}").json()["status"] == "denied"


def test_relay_cannot_forge_approval(client, keypair):
    # The relay/attacker marks a request approved with a bogus signature.
    challenge = Challenge.create("alice", "box", "tty1", 1000)
    request_id = submit(client, challenge)
    forged = base64.b64encode(b"\x00" * 64).decode()
    client.post(f"/requests/{request_id}/respond", json={"decision": "approve", "signature_b64": forged})

    result = client.get(f"/requests/{request_id}").json()
    sig = base64.b64decode(result["signature_b64"])
    verdict = Verifier(validity_window_seconds=90).verify_approval(challenge, sig, keypair.public_key, 1005)
    assert not verdict.approved  # local verification rejects the relay's forgery


def test_double_respond_conflicts(client):
    challenge = Challenge.create("alice", "box", "tty1", 1000)
    request_id = submit(client, challenge)
    client.post(f"/requests/{request_id}/respond", json={"decision": "deny"})
    second = client.post(f"/requests/{request_id}/respond", json={"decision": "deny"})
    assert second.status_code == 409


def test_approve_without_signature_rejected(client):
    challenge = Challenge.create("alice", "box", "tty1", 1000)
    request_id = submit(client, challenge)
    resp = client.post(f"/requests/{request_id}/respond", json={"decision": "approve"})
    assert resp.status_code == 400
