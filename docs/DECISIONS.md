# Phase 0 — Decisions & Threat Model

This is the one-page decisions doc required by Phase 0. These choices are baked into
the code; changing them later means touching the verifier, the PAM module, and the
phone/CLI signer in lockstep (the canonical serialization is a wire contract — §7).

## Core security principle (non-negotiable)

The REST relay and the network are **untrusted**. Approval is an **Ed25519 signature
over a canonical challenge**, verified locally against a **pinned public key** in a
root-owned file. The relay only moves bytes. A compromised relay or on-path attacker
cannot forge an approval because they do not hold the private key.

## Fallback scope

- **Console-only.** The local-password fallback (`pam_unix`) is allowed **only on a
  physical console, never over SSH**. Detection: presence of `SSH_CONNECTION` /
  `SSH_CLIENT` in the PAM environment, or a `pts/*` `PAM_TTY` for remote sessions.
  Over SSH, an outage results in `PAM_AUTH_ERR` (hard fail), not a downgrade.
- Rationale: the remote attacker with a stolen shell is the main threat. Denying
  *them* the fallback removes most downgrade risk while a physically-present admin
  can still recover.

## Three-return-code rule (load-bearing)

| Situation                        | PAM code               | Stack behavior                       |
|----------------------------------|------------------------|--------------------------------------|
| Approved, signature verifies     | `PAM_SUCCESS`          | `success=done` → skip password       |
| Denied **or** signature invalid  | `PAM_AUTH_ERR`         | `default=die` → fail, **no fallback** |
| Relay genuinely unreachable      | `PAM_AUTHINFO_UNAVAIL` | `authinfo_unavail=ignore` → password  |

**Denial ≠ outage.** A phone *denial* is final and never falls back. Only a genuine
network *outage* (connect failure / timeout / TLS pin mismatch) returns
`PAM_AUTHINFO_UNAVAIL`. Collapsing these two reintroduces the downgrade attack.

## Timing windows

- **Challenge validity window:** 90 seconds. A signed response whose challenge
  timestamp is older than this is rejected (`PAM_AUTH_ERR`).
- **Approval poll timeout (PAM side):** 60 seconds total, polling the relay. If no
  result by then, treated as a denial-equivalent only if the relay was reachable;
  if the relay was never reachable it is an outage.
- **Per-request connect/read timeout:** 4 seconds. Exceeded → treated as outage.
- **Nonce cache TTL:** equals the validity window (90 s). A nonce is accepted once;
  replays inside the window are rejected, and the entry is purged after it.

## Enrollment trust (root of trust)

The first public key is pinned **out-of-band by an already-root admin**. Enrollment is
`netapprove-enroll` writing the base64 public key into the root-owned pin file
(`/etc/netapprove/pinned_keys.d/<user>.pub`, mode `0644`, owner `root:root`). The
phone generates the keypair in its secure enclave; the private key never leaves
hardware. **If an attacker can write the pin file, the scheme is moot** — hence the
file and its directory are root-owned and made immutable (`chattr +i`) in Phase 5.

## Revocation

Remove the user's pin file (after `chattr -i`) and re-`chattr +i` the directory.
Verification then fails closed for that user. A revocation runbook + a test that a
revoked key is actually rejected is a Phase 5 deliverable.

## Logging & alerting

- Log every request, approval, denial, and **fallback**, with full challenge context
  (`user`, `host`, `tty`, `timestamp`, `nonce` hex prefix) to syslog (`auth` facility).
- **Alert on every fallback firing.** Real outages are rare; an unexplained fallback
  is the downgrade-attack tripwire.

## Rate limiting

Both approval requests and fallback attempts are rate-limited per `{user, host}` so a
stolen session cannot spam approvals hoping for a fat-finger tap (relay-side, Phase 5).

## Language note

The spec recommends Rust for the shipped module (lean `.so`, no embedded runtime on
the auth path). This implementation is **Python via `libpam-python`** at the user's
request: faster to iterate and fully expresses the three-return-code logic, at the
cost of dragging the interpreter onto the auth path. Treat it as a strong
prototype/reference; the crypto core and wire contract are language-agnostic and can
be reused by a Rust port verbatim.
