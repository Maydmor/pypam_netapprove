"""Live Phase 3 smoke test over real HTTP (not TestClient).

Starts the relay in a background thread, then runs the PAM client side
(RelayClient + NetworkBackend + decide) against it for approve / deny / outage,
with the CLI-approver logic signing in another thread. Exits non-zero on mismatch.
"""

from __future__ import annotations

import base64
import threading
import time

import requests
import uvicorn

from netapprove_core import Challenge, Keypair, Verifier, write_pinned_key
from netapprove_core.crypto import sign
from netapprove_pam.client import NetworkBackend, RelayClient
from netapprove_pam.decision import PamCode, decide

HOST, PORT = "127.0.0.1", 8137
BASE = f"http://{HOST}:{PORT}"


def start_relay() -> uvicorn.Server:
    from netapprove_relay.app import app

    config = uvicorn.Config(app, host=HOST, port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        try:
            requests.get(f"{BASE}/requests/pending", timeout=0.5)
            return server
        except requests.exceptions.RequestException:
            time.sleep(0.1)
    raise RuntimeError("relay did not start")


def approver_loop(private_key: bytes, approve: bool, stop: threading.Event) -> None:
    while not stop.is_set():
        pending = requests.get(f"{BASE}/requests/pending", timeout=2).json()["pending"]
        for item in pending:
            challenge = Challenge.from_wire(item["challenge"])
            if approve:
                sig = sign(private_key, challenge.to_canonical_bytes())
                body = {"decision": "approve", "signature_b64": base64.b64encode(sig).decode()}
            else:
                body = {"decision": "deny"}
            requests.post(f"{BASE}/requests/{item['request_id']}/respond", json=body, timeout=2)
        time.sleep(0.2)


def run_case(name: str, kp: Keypair, pin_dir, approve: bool, base_url: str, expected: PamCode) -> bool:
    stop = threading.Event()
    if approve is not None and "127.0.0.1" in base_url:
        threading.Thread(target=approver_loop, args=(kp.private_key, approve, stop), daemon=True).start()

    challenge = Challenge.create("alice", "smoke-host", "tty1", int(time.time()))
    client = RelayClient(base_url, cert_fingerprint_sha256=None, timeout_seconds=2)
    backend = NetworkBackend(client, approval_timeout_seconds=8, poll_interval_seconds=0.3)
    from netapprove_core import load_pinned_key

    pinned = load_pinned_key("alice", pin_dir)
    decision = decide(challenge, backend, Verifier(validity_window_seconds=90), pinned, int(time.time()), is_remote=False)
    stop.set()

    ok = decision.code is expected
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: got {decision.code.value} (expected {expected.value}) — {decision.reason}")
    return ok


def main() -> int:
    import tempfile
    from pathlib import Path

    kp = Keypair.generate()
    pin_dir = Path(tempfile.mkdtemp()) / "pins"
    write_pinned_key("alice", kp.public_key, pin_dir)

    start_relay()

    results = [
        run_case("approve -> SUCCESS", kp, pin_dir, True, BASE, PamCode.SUCCESS),
        run_case("deny -> AUTH_ERR", kp, pin_dir, False, BASE, PamCode.AUTH_ERR),
        run_case("outage(console) -> AUTHINFO_UNAVAIL", kp, pin_dir, None, "http://127.0.0.1:1", PamCode.AUTHINFO_UNAVAIL),
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
