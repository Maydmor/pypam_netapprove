# pam-netapprove (Python)

Network-approved `sudo`: replace the password prompt with an **out-of-band,
cryptographically-verified approval**. When you run `sudo`, a challenge is pushed to
your phone; you approve with a fingerprint; the phone signs the challenge with a
hardware-backed key; the PAM module **verifies the signature locally** against a
pinned public key. If the relay is genuinely unreachable, it falls back to the local
password — but only on a console, never over SSH.

## The one idea everything rests on

**The relay and the network are untrusted.** Approval is an Ed25519 signature over a
canonical challenge, verified locally against a public key pinned in a root-owned
file. A compromised relay or on-path attacker cannot forge an approval — they don't
hold the private key. The relay is a dumb byte-mover.

## The three-return-code rule (spec §4)

| Situation                        | PAM code               | Stack behavior                        |
|----------------------------------|------------------------|---------------------------------------|
| Approved, signature verifies     | `PAM_SUCCESS`          | `success=done` → skip password        |
| Denied **or** signature invalid  | `PAM_AUTH_ERR`         | `default=die` → fail, **no fallback** |
| Relay genuinely unreachable      | `PAM_AUTHINFO_UNAVAIL` | fall through to `pam_unix` (password)  |

**Denial ≠ outage.** Only a real outage falls back; a denial is final. Over SSH even
an outage hard-fails (console-only fallback). Collapsing these reintroduces the
downgrade attack .

## What's implemented

| Phase | Scope | Status |
|------|-------|--------|
| 0 | Decisions & threat model |
| 1 | Crypto core (challenge, canonical bytes, Ed25519, replay, pinned key) | ✅ `netapprove_core`, fully tested |
| 2 | PAM module + mock signer, three-return-code logic | ✅ `netapprove_pam`, `pam_netapprove.py` |
| 3 | REST relay + CLI approver, TLS pinning, outage mapping | ✅ `netapprove_relay`, `netapprove_approver` |
| 4 | Phone app | ⛔ out of scope here — the CLI approver is the stand-in; it speaks the exact relay protocol the phone must implement |
| 5 | Hardening & ops | 📋 documented in [`docs/DEPLOY.md`](docs/DEPLOY.md) (chattr, rate-limit, alerting, rotation) |
| 6 | Per-command approval (sudo plugin) | 📋 noted, not built |

## Layout

```
src/
  netapprove_core/     Phase 1 — security heart (no PAM, no network)
    challenge.py        Challenge + canonical serialization (§7 wire contract)
    crypto.py           Ed25519 sign/verify
    replay.py           timestamp window + nonce cache
    verifier.py         local verification against a pinned key
    keystore.py         root-owned pinned-key storage
    enroll.py           netapprove-enroll CLI (root of trust)
  netapprove_pam/      Phases 2-3 — the module
    decision.py         the three-return-code rule (pure, testable)
    backends.py         MockBackend (Phase 2) + ApprovalResponse/RelayOutage
    client.py           TLS-pinned RelayClient + polling NetworkBackend (Phase 3)
    session.py          remote-session (SSH) detection for console-only fallback
    config.py           TOML config
    audit.py            syslog logging / fallback alert
    pam_netapprove.py   libpam-python entrypoint (pam_sm_authenticate)
  netapprove_relay/    Phase 3 — untrusted FastAPI relay
  netapprove_approver/ Phase 3 — CLI phone stand-in
tests/                 71 tests across all phases
docs/                  DECISIONS, PHASE2_TESTING, DEPLOY, DEMO
```

## Quick start (dev, on any OS)

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .\.venv\Scripts\activate
pip install -e ".[relay,client,dev]"
pytest -q                                         # 71 passing
```

End-to-end demo (relay + CLI approver, no phone): see [`docs/DEMO.md`](docs/DEMO.md).

## Installing as a real PAM module (Ubuntu)

See [`docs/DEPLOY.md`](docs/DEPLOY.md). **Read [`docs/PHASE2_TESTING.md`](docs/PHASE2_TESTING.md)
first** — wiring this into `/etc/pam.d/sudo` incorrectly will lock you out of sudo.
Always test against a throwaway `sudotest` service with a separate root shell held
open.

## Security must-haves checklist (spec §8)

- [x] Signed challenge–response, verified locally
- [x] Per-request 256-bit nonce; timestamp window + nonce cache (replay protection)
- [x] Canonical, length-prefixed, domain-separated serialization (§7) with full test coverage
- [x] TLS certificate pinning on the client
- [x] Fail closed on anything ambiguous
- [x] Denial ≠ outage; console-only fallback
- [x] Audit log every request/approval/denial/fallback; **alert on fallback**
- [ ] `chattr +i` on pinned keys/config — operational, see DEPLOY.md
- [ ] Rate-limiting on the relay — operational, see DEPLOY.md
```
