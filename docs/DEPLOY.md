# Deployment & Phase 5 hardening (Ubuntu)

Go through Phases 0–3 first (DECISIONS, PHASE2_TESTING, DEMO). **Only edit the real
`/etc/pam.d/sudo` on a canary machine, with a root shell held open and console
access confirmed.**

## 1. Install

```bash
sudo apt-get install -y libpam-python
sudo pip install --break-system-packages -e .          # makes netapprove_* importable system-wide
sudo install -d -m 0755 /usr/local/lib/netapprove
sudo install -m 0644 src/netapprove_pam/pam_netapprove.py /usr/local/lib/netapprove/
sudo install -d -m 0755 /etc/netapprove/pinned_keys.d
```

## 2. Relay TLS + certificate pinning

The relay is untrusted, but the client still pins its leaf cert so a swapped cert is
detected. Generate a cert and compute the pin:

```bash
scripts/gen_relay_cert.sh relay.example.internal     # writes relay.crt / relay.key
# SHA-256 fingerprint (hex, no colons) for cert_fingerprint_sha256:
openssl x509 -in relay.crt -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z'
```

Serve the relay over TLS (behind nginx/caddy, or `uvicorn --ssl-keyfile --ssl-certfile`).

## 3. Enroll the phone's public key (root of trust)

The phone generates its keypair in the secure enclave and exports the **public** key.
An already-root admin pins it out-of-band:

```bash
sudo netapprove-enroll alice --public-key "<base64-from-phone>"
```

## 4. Config `/etc/netapprove/config.toml`

```toml
relay_url = "https://relay.example.internal:8443"
cert_fingerprint_sha256 = "<hex pin from step 2>"
pin_dir = "/etc/netapprove/pinned_keys.d"
validity_window_seconds = 90
approval_timeout_seconds = 60
request_timeout_seconds = 4.0
allow_ssh_fallback = false        # console-only fallback (Phase 0)
backend = "network"
```

## 5. Phase 5 hardening (do before going live)

- **Tamper-resistance:** make pinned keys + config immutable.
  ```bash
  sudo chattr +i /etc/netapprove/config.toml /etc/netapprove/pinned_keys.d/*.pub
  # to rotate/revoke: chattr -i, edit, chattr +i again
  ```
- **Alert on fallback.** The module logs `LOG_ALERT` with tag `pam_netapprove` on
  every fallback. Wire it to your alerting:
  ```bash
  # rsyslog example: forward ALERT-level auth messages
  # :programname, isequal, "pam_netapprove"  @siem.example.internal:514
  ```
- **Rate-limit** approval requests per `{user,host}` at the relay (add a limiter /
  put it behind nginx `limit_req`) so a stolen session can't spam approvals.
- **Clock sync.** Timestamp validation depends on it — enforce `systemd-timesyncd`
  or chrony on every machine.
- **Revocation runbook + test:** remove the user's `.pub`, confirm auth now fails
  closed for that user. Test that a revoked key is actually rejected.

## 6. Wire into sudo (canary only, last step)

`/etc/pam.d/sudo` — add **above** the existing `@include common-auth`:

```
auth [success=done authinfo_unavail=ignore default=die] pam_python.so /usr/local/lib/netapprove/pam_netapprove.py config=/etc/netapprove/config.toml
```

With a root shell open: open a new terminal, run `sudo true`, approve on the phone.
Test deny, and test outage (block the relay) on a local console (should prompt for
password) and over SSH (should hard-fail). Roll out only after the canary is solid.

## Phase 6 — per-command approval (optional)

PAM cannot see the command line during auth. To show *which* command is being
approved, add a **sudo approval plugin** (sudo 1.9+) alongside this PAM module: PAM
remains the biometric identity gate; the approval plugin adds command-level
confirmation. Check current sudo plugin docs for the API before building.
