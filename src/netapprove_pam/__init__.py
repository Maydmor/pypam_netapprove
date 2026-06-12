"""netapprove_pam — PAM module logic (Phases 2-3).

The libpam-python entrypoint lives in pam_netapprove.py. The return-code logic is
isolated in decision.py (pure, testable). Backends in backends.py / client.py.
"""
