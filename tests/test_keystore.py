"""Pinned-key store: enroll/load roundtrip and fail-closed behavior."""

import pytest

from netapprove_core.crypto import Keypair
from netapprove_core.keystore import (
    PinnedKeyError,
    load_pinned_key,
    pin_path_for,
    write_pinned_key,
)


def test_write_then_load_roundtrip(tmp_path):
    kp = Keypair.generate()
    write_pinned_key("alice", kp.public_key, tmp_path)
    assert load_pinned_key("alice", tmp_path) == kp.public_key


def test_missing_key_raises(tmp_path):
    with pytest.raises(PinnedKeyError):
        load_pinned_key("nobody", tmp_path)


def test_rejects_wrong_length_key(tmp_path):
    with pytest.raises(ValueError):
        write_pinned_key("alice", b"too short", tmp_path)


def test_corrupt_key_file_raises(tmp_path):
    path = pin_path_for("alice", tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    path.write_text("bm90LWJhc2U2NA==")  # valid base64, wrong length
    with pytest.raises(PinnedKeyError):
        load_pinned_key("alice", tmp_path)


@pytest.mark.parametrize("bad", ["", "..", "a/b"])
def test_rejects_unsafe_user_names(bad, tmp_path):
    with pytest.raises(ValueError):
        pin_path_for(bad, tmp_path)
