# pypam-netapprove

> Approve `sudo` from your phone with a fingerprint — no password typed, and no trust
> placed in the network.

`pypam-netapprove` is a PAM module that replaces the `sudo` password prompt with an
**out-of-band, cryptographically-verified approval**. Run `sudo`, get a push on your
phone, approve with a biometric, and you're root. If the network is down it falls
back to the normal local password — but only on a physical console, never over SSH.

**Status: a working, fully-tested reference / prototype.** Read
[Security model](#security-model) and [Project status](#project-status) before
putting it on a machine you care about.

---

## Table of contents

- [Why](#why)
- [Security model](#security-model)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start (no phone needed)](#quick-start-no-phone-needed)
- [Deploying as a real PAM module](#deploying-as-a-real-pam-module)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Project status](#project-status)
- [Development](#development)
- [Contributing](#contributing)
- [Reporting security issues](#reporting-security-issues)
- [Alternatives worth considering](#alternatives-worth-considering)
- [License](#license)

---

## Why

Passwords on the `sudo` path are phishable, reused, and shoulder-surfable. The nice
UX of "tap your phone to approve" usually comes from a vendor. This project is a
small, auditable, self-hostable version of that flow whose security does **not**
depend on trusting a server: approval is a signature your phone makes and your
machine verifies locally.

It's also a good learning project for PAM, challenge–response auth, and the subtle
ways an availability fallback can become an attacker's downgrade path.

## Security model

**The one idea everything rests on: the relay and the network are untrusted.**

Approval is an **Ed25519 signature over a canonical challenge**, verified **locally**
against a public key **pinned in a root-owned file**. The phone holds the private key
in its secure enclave; a fingerprint unlocks the signing operation. A compromised
relay, a swapped TLS cert, or an on-path attacker still cannot forge an approval —
they don't hold the key. The relay is reduced to a dumb byte-mover.

This is the difference between "trust the network's word that it's `true`" (insecure)
and FIDO2/WebAuthn-style push approval (secure).

### The three-return-code rule

The PAM module returns exactly one of three codes, and the distinction is
load-bearing:

| Situation                       | PAM code               | Stack behavior                         |
|---------------------------------|------------------------|----------------------------------------|
| Approved, signature verifies    | `PAM_SUCCESS`          | skip the password line                 |
| Denied **or** signature invalid | `PAM_AUTH_ERR`         | fail immediately — **no fallback**     |
| Relay genuinely unreachable     | `PAM_AUTHINFO_UNAVAIL` | fall through to the local password     |

**A denial is final; only a real outage falls back.** Otherwise an attacker who got a
denial could just cut the network to downgrade to a password they might already know.
And the password fallback is **console-only** — over SSH an outage hard-fails — because
the remote attacker is the main threat.

## How it works

```
  sudo                PAM module                 relay (untrusted)        phone
   │  authenticate ───────▶│                          │                    │
   │                       │ build challenge          │                    │
   │                       │  {user,host,tty,ts,nonce}│                    │
   │                       │ submit ─────────────────▶│ ── push ──────────▶│
   │                       │                          │      fingerprint ✔ │
   │                       │                          │◀── signature ──────│  (signs the
   │                       │◀── poll: signature ──────│                    │   canonical
   │              verify signature LOCALLY            │                    │   bytes)
   │                against pinned public key         │                    │
   │◀── PAM_SUCCESS ───────│                          │                    │
```

The signed message is a strict, length-prefixed, domain-separated byte encoding
so the signer and verifier hash byte-identical input. The relay only ever
sees opaque bytes and a signature.

## Install

Requires **Python 3.10+**. The crypto core has one dependency (`cryptography`); the
relay and client pull in `fastapi`/`requests` via extras.

```bash
git clone <your-fork-url> pypam-netapprove && cd pypam-netapprove
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\activate
pip install -e ".[relay,client,dev]"
pytest -q                          # 71 tests should pass
```

Extras:

| Extra      | Pulls in                  | Needed for                         |
|------------|---------------------------|------------------------------------|
| (none)     | `cryptography`            | the crypto core + PAM verification |
| `relay`    | `fastapi`, `uvicorn`      | running the relay server           |
| `client`   | `requests`                | the PAM client / CLI approver      |
| `dev`      | `pytest`, `hypothesis`    | the test suite                     |

## Quick start (no phone needed)

A CLI approver stands in for the phone and speaks the exact same protocol. Full
walkthrough in [`docs/DEMO.md`](docs/DEMO.md); the short version:

```bash
# 1. enroll a software keypair (dev stand-in for a secure-enclave key)
netapprove-enroll "$USER" --generate --private-out ./demo/priv.b64 --pin-dir ./demo/pins

# 2. start the relay
netapprove-relay                       # http://127.0.0.1:8443

# 3. in another terminal, approve pending requests
netapprove-approver --relay-url http://127.0.0.1:8443 --key ./demo/priv.b64
```

To see all three outcomes end-to-end over real HTTP in one shot:

```bash
python scripts/smoke_phase3.py         # approve→SUCCESS, deny→AUTH_ERR, outage→AUTHINFO_UNAVAIL
```

## Deploying as a real PAM module

> ⚠️ **Wiring a broken module into `/etc/pam.d/sudo` can lock you out of `sudo`.**
> Always test against a throwaway `sudotest` service with a **separate root shell
> Only edit the real sudo stack on a canary machine, last.

The module runs under [`libpam-python`](https://pam-python.sourceforge.io/). Full
steps — install, TLS cert + pinning, enrollment, hardening (`chattr +i`, fallback
alerting, rate-limiting, clock sync, revocation), and the final `/etc/pam.d/sudo`
line — are in [`docs/DEPLOY.md`](docs/DEPLOY.md). The PAM line looks like:

```
auth [success=done authinfo_unavail=ignore default=die] \
     pam_python.so /usr/local/lib/netapprove/pam_netapprove.py config=/etc/netapprove/config.toml
```

## Configuration

Config lives in a root-owned `/etc/netapprove/config.toml`. Every key is optional and
falls back to a safe default. See [`examples/config.toml`](examples/config.toml) for
the annotated reference; the security-relevant ones:

```toml
relay_url = "https://relay.example.internal:8443"
cert_fingerprint_sha256 = "<sha256 of the relay leaf cert, hex, no colons>"
validity_window_seconds = 90      # challenge freshness
allow_ssh_fallback = false        # keep false: console-only fallback
backend = "network"               # or "mock" for return-code testing
```

## Project layout

```
src/
  netapprove_core/     security heart — no PAM, no network, heavily tested
    challenge.py        Challenge + canonical serialization (the signed wire contract)
    crypto.py           Ed25519 sign/verify
    replay.py           timestamp window + nonce cache
    verifier.py         local verification against a pinned key
    keystore.py         root-owned pinned-key storage
    enroll.py           `netapprove-enroll` — pins a public key (root of trust)
  netapprove_pam/      the PAM module
    decision.py         the three-return-code rule (pure & testable)
    backends.py         mock signer + approval/outage types
    client.py           TLS-pinned relay client + polling backend
    session.py          SSH-vs-console detection (gates fallback)
    config.py / audit.py / pam_netapprove.py
  netapprove_relay/    untrusted FastAPI relay
  netapprove_approver/ CLI phone stand-in
tests/                 71 tests across all phases
docs/                  DECISIONS · PHASE2_TESTING · DEMO · DEPLOY
examples/ · scripts/   sample config, sudotest service, cert-gen, smoke test
```

## Project status

This is a **reference implementation and prototype**, not a hardened product.

- ✅ **Phase 1** crypto core — complete, exhaustively tested.
- ✅ **Phase 2** PAM module + mock signer — complete; three return codes verified.
- ✅ **Phase 3** relay + CLI approver, TLS pinning, outage mapping — complete.
- ⛔ **Phase 4** native phone app — **not included.** The CLI approver is the
  stand-in; a real app must generate its key in the secure enclave / StrongBox /
  Keystore, gate signing on a biometric, and reimplement the §7 byte encoding exactly.
- 📋 **Phase 5/6** hardening and per-command approval — documented, not automated.

Caveats to weigh before production use:

- Implemented in Python, so it drags an interpreter onto the `sudo` auth path (the
  brief recommends Rust for the shipped `.so`). The crypto core and wire contract are
  language-agnostic and a Rust port can reuse them verbatim.
- The relay's request store is in-memory; rate-limiting and persistence are left to
  the deployment.
- No phone app ships here — you supply Phase 4.

## Development

```bash
pip install -e ".[relay,client,dev]"
pytest -q                       # run everything
pytest tests/test_challenge.py  # one module
python scripts/smoke_phase3.py  # live end-to-end over HTTP
```

Conventions:

- The `netapprove_core` package must stay free of PAM and network dependencies — it's
  the auditable security core. Keep it that way.
- The canonical byte encoding in `challenge.py` is a **wire contract**. Any change
  bumps `CHALLENGE_MAGIC` (`NAPCHAL1` → `NAPCHAL2`) and must update every signer.
- Auth code **fails closed**: any unexpected error must resolve to `PAM_AUTH_ERR`,
  never silent success.
- New behavior needs tests. Security-relevant paths (tamper/replay/expiry/downgrade)
  need a test that proves the *rejection*, not just the happy path.

## Contributing

Contributions are welcome — bug reports, tests, docs, and a real phone app especially.

1. Open an issue describing the change before large PRs, so we can agree on approach.
2. Fork, branch from `main`, and keep PRs focused.
3. Run `pytest -q` (all green) and add tests for your change.
4. Match the surrounding style: small functions that validate inputs first and exit
   early, dataclasses over naked dicts, flat control flow.
5. For anything touching the auth path or the byte encoding, explain the security
   reasoning in the PR description and cite the relevant brief section.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the longer version.

## Reporting security issues

**Please do not open public issues for vulnerabilities.** This code runs as root on
the auth path. Report privately to the maintainers (see `CONTRIBUTING.md` for the
contact) and allow time for a fix before disclosure.

## Alternatives worth considering

If you need this in production today and don't need to own the code, these have
already paid for the boring hardening: **Duo Unix (`pam_duo`)**, **Teleport**, and
**Okta / Entra** verify-style push via their PAM integrations. Rolling your own is a
great learning project and gives full control; the gap between "demo" and "auth path
I'd bet root on" is mostly operational hardening.

## License

MIT — see [`LICENSE`](LICENSE).
