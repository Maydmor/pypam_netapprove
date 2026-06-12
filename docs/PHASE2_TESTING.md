# Phase 2 — Testing the PAM module without locking yourself out

> ⚠️ **The most dangerous operational step in the project.** Wiring a broken module
> into `/etc/pam.d/sudo` can lock you out of `sudo` permanently. Do **not** touch
> `/etc/pam.d/sudo` during development.

## The rules

1. **Keep a separate root shell open the entire time** (`sudo -i` in another
   terminal, before you start). If you break sudo, you recover from there.
2. Test against a **throwaway PAM service**, never the real `sudo` one.
3. Verify all three return codes (approve / deny / unavailable) before going near
   the real stack (that happens in Phase 5, on a canary machine).

## Setup on Ubuntu

```bash
sudo apt-get install -y libpam-python pamtester
# install the package so the system python can import it:
sudo pip install --break-system-packages -e .   # or into a system path on sys.path
sudo mkdir -p /usr/local/lib/netapprove
sudo cp src/netapprove_pam/pam_netapprove.py /usr/local/lib/netapprove/
```

### Mock config (no network, local signer)

```bash
sudo mkdir -p /etc/netapprove/pinned_keys.d
# generate a software keypair, pin the public key, write the mock private key:
sudo netapprove-enroll "$USER" --generate --private-out /etc/netapprove/mock_priv.b64
sudo chmod 600 /etc/netapprove/mock_priv.b64
```

`/etc/netapprove/config.toml`:

```toml
backend = "mock"
mock_mode = "approve"          # flip to "deny" / "unavail" to test each branch
mock_private_key_path = "/etc/netapprove/mock_priv.b64"
pin_dir = "/etc/netapprove/pinned_keys.d"
```

### Throwaway service `/etc/pam.d/sudotest`

```
auth  [success=done authinfo_unavail=ignore default=die]  pam_python.so /usr/local/lib/netapprove/pam_netapprove.py config=/etc/netapprove/config.toml
auth  [success=done default=die]                          pam_unix.so
account  required  pam_permit.so
```

The first line is the **exact** control syntax the real `/etc/pam.d/sudo` will use —
that's the point of `sudotest`: prove the syntax and the three codes here.

## Drive it with `pamtester`

```bash
# mock_mode = "approve"  -> should succeed
pamtester sudotest "$USER" authenticate

# mock_mode = "deny"     -> should fail, NO password prompt (default=die)
sudo sed -i 's/mock_mode = .*/mock_mode = "deny"/' /etc/netapprove/config.toml
pamtester sudotest "$USER" authenticate

# mock_mode = "unavail"  -> on a console, falls through to pam_unix (password prompt)
sudo sed -i 's/mock_mode = .*/mock_mode = "unavail"/' /etc/netapprove/config.toml
pamtester sudotest "$USER" authenticate
```

Expected:
- **approve** → `pamtester: successfully authenticated` with no password.
- **deny** → `pamtester: authentication failed`, immediately, no password prompt.
- **unavail** (local tty) → password prompt from `pam_unix`; correct password succeeds.
- **unavail over SSH** → hard fail, no password prompt (console-only fallback).

Watch the audit trail in another terminal:

```bash
journalctl -t pam_netapprove -f
```

Only once every branch behaves correctly here do you proceed toward Phase 3 / Phase 5.
