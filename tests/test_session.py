"""Remote-session detection that gates console-only fallback."""

from netapprove_pam.session import is_remote_session


def test_ssh_connection_is_remote():
    assert is_remote_session({"SSH_CONNECTION": "1.2.3.4 ..."}, "pts/0") is True


def test_ssh_client_is_remote():
    assert is_remote_session({"SSH_CLIENT": "1.2.3.4 ..."}, "pts/0") is True


def test_local_console_is_not_remote():
    assert is_remote_session({}, "tty1") is False


def test_local_terminal_with_display_is_not_remote():
    assert is_remote_session({"DISPLAY": ":0"}, "pts/2") is False


def test_pts_without_display_treated_remote():
    assert is_remote_session({}, "pts/2") is True
