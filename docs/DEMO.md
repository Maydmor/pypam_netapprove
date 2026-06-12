# Phase 3 — End-to-end demo (relay + CLI approver, no phone)

Runs the whole flow on one machine: a relay, a CLI approver standing in for the
phone, and a small driver that plays the PAM module's network side. Dev-only:
plain HTTP, software key. (TLS pinning is exercised by `RelayClient`; see DEPLOY.md
for the real cert setup.)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[relay,client,dev]"
```

### 1. Enroll a software keypair

```bash
mkdir -p ./demo/pins
netapprove-enroll "$USER" --generate \
    --private-out ./demo/priv.b64 --pin-dir ./demo/pins
```

### 2. Start the relay (terminal A)

```bash
netapprove-relay     # listens on http://127.0.0.1:8443
```

### 3. Submit a challenge as the PAM module would (terminal B)

```python
# demo_pam_side.py
from netapprove_core import Challenge, Verifier, load_pinned_key
from netapprove_pam.client import RelayClient, NetworkBackend
from netapprove_pam.decision import decide
import time

challenge = Challenge.create("$USER", "demo-host", "tty1", int(time.time()))
client  = RelayClient("http://127.0.0.1:8443", cert_fingerprint_sha256=None, timeout_seconds=4)
backend = NetworkBackend(client, approval_timeout_seconds=60, poll_interval_seconds=1.5)
verifier = Verifier(validity_window_seconds=90)
pinned   = load_pinned_key("$USER", pin_dir="./demo/pins")

print("waiting for approval… run the approver in terminal C")
decision = decide(challenge, backend, verifier, pinned, int(time.time()), is_remote=False)
print("PAM would return:", decision.code.value, "-", decision.reason)
```

```bash
python demo_pam_side.py    # blocks, polling the relay
```

### 4. Approve as the "phone" (terminal C)

```bash
netapprove-approver --relay-url http://127.0.0.1:8443 --key ./demo/priv.b64
# shows: alice@demo-host wants sudo (tty tty1) ; answer y to approve
```

Terminal B then prints `PAM would return: success`. Try again answering **deny** →
`auth_err`. Kill the relay (Ctrl-C in A) and rerun step 3 → `authinfo_unavail`
(falls back) on a console, or `auth_err` if you set `is_remote=True`.

This is exactly the Phase 3 deliverable: request appears in the approver; approve →
auth succeeds; deny → fails; kill API → falls back. The phone (Phase 4) replaces the
approver without changing anything else.
