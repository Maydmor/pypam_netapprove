"""Drive the real pam_sm_authenticate via a fake pamh + mock backend config.

This is the Phase 2 service-level check: the entrypoint must return the right PAM
constant for approve / deny / unavailable, using a local root-owned mock signer and
no network. We assert against the fake pamh's own constants.
"""

import base64

import pytest

from netapprove_core.crypto import Keypair
from netapprove_core.keystore import write_pinned_key
from netapprove_pam import pam_netapprove
from netapprove_pam.config import Config


class FakePamh:
    """Minimal stand-in for libpam-python's pamh object."""

    PAM_SUCCESS = 0
    PAM_AUTH_ERR = 7
    PAM_AUTHINFO_UNAVAIL = 9
    PAM_TTY = "PAM_TTY"
    PAM_TEXT_INFO = 4

    class Message:
        def __init__(self, style, msg):
            self.style = style
            self.msg = msg

    def __init__(self, user, tty):
        self._user = user
        self._tty = tty
        self.messages = []

    def get_user(self, prompt):
        return self._user

    def get_item(self, item):
        return self._tty if item == self.PAM_TTY else None

    def conversation(self, message):
        self.messages.append(message.msg)


@pytest.fixture
def enrolled(tmp_path, monkeypatch):
    """Enroll alice with a generated keypair; return (pin_dir, private_key_path)."""
    kp = Keypair.generate()
    pin_dir = tmp_path / "pins"
    write_pinned_key("alice", kp.public_key, pin_dir)
    key_path = tmp_path / "mock_priv"
    key_path.write_text(base64.b64encode(kp.private_key).decode())
    # ensure local (non-SSH) session
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    return pin_dir, key_path


def patch_config(monkeypatch, **overrides):
    base = dict(backend="mock", pin_dir=overrides.pop("pin_dir"))
    cfg = Config(**base, **overrides)
    monkeypatch.setattr(Config, "load", classmethod(lambda cls, path=None: cfg))


def test_entrypoint_approve_returns_success(enrolled, monkeypatch):
    pin_dir, key_path = enrolled
    patch_config(monkeypatch, pin_dir=pin_dir, mock_mode="approve", mock_private_key_path=key_path)
    pamh = FakePamh("alice", "tty1")
    assert pam_netapprove.pam_sm_authenticate(pamh, 0, ["mod"]) == pamh.PAM_SUCCESS


def test_entrypoint_deny_returns_auth_err(enrolled, monkeypatch):
    pin_dir, _ = enrolled
    patch_config(monkeypatch, pin_dir=pin_dir, mock_mode="deny")
    pamh = FakePamh("alice", "tty1")
    assert pam_netapprove.pam_sm_authenticate(pamh, 0, ["mod"]) == pamh.PAM_AUTH_ERR


def test_entrypoint_unavail_on_console_returns_authinfo_unavail(enrolled, monkeypatch):
    pin_dir, _ = enrolled
    patch_config(monkeypatch, pin_dir=pin_dir, mock_mode="unavail")
    pamh = FakePamh("alice", "tty1")
    assert pam_netapprove.pam_sm_authenticate(pamh, 0, ["mod"]) == pamh.PAM_AUTHINFO_UNAVAIL


def test_entrypoint_unavail_over_ssh_returns_auth_err(enrolled, monkeypatch):
    pin_dir, _ = enrolled
    monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
    patch_config(monkeypatch, pin_dir=pin_dir, mock_mode="unavail")
    pamh = FakePamh("alice", "pts/0")
    assert pam_netapprove.pam_sm_authenticate(pamh, 0, ["mod"]) == pamh.PAM_AUTH_ERR


def test_entrypoint_no_enrolled_key_fails_closed(tmp_path, monkeypatch):
    patch_config(monkeypatch, pin_dir=tmp_path / "empty", mock_mode="deny")
    pamh = FakePamh("stranger", "tty1")
    assert pam_netapprove.pam_sm_authenticate(pamh, 0, ["mod"]) == pamh.PAM_AUTH_ERR
