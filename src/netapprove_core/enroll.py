"""netapprove-enroll — pin a user's public key (Phase 0 root-of-trust operation).

Run by an already-root admin, out of band. The phone normally generates its
keypair in the secure enclave and exports only the public half; for the software
signer (Phases 2-3) ``--generate`` mints a keypair and writes the private key to a
root-owned file standing in for the enclave.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from .crypto import Keypair
from .keystore import DEFAULT_PIN_DIR, write_pinned_key


def _enroll_public_key_b64(user: str, public_key_b64: str, pin_dir: Path) -> Path:
    raw = base64.b64decode(public_key_b64.strip(), validate=True)
    return write_pinned_key(user, raw, pin_dir)


def _generate_and_enroll(user: str, pin_dir: Path, private_out: Path) -> Path:
    keypair = Keypair.generate()
    private_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_text(base64.b64encode(keypair.private_key).decode("ascii") + "\n")
    os.chmod(private_out, 0o600)
    return write_pinned_key(user, keypair.public_key, pin_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netapprove-enroll", description="Pin a user's approval public key")
    parser.add_argument("user", help="local user name to enroll")
    parser.add_argument("--pin-dir", type=Path, default=DEFAULT_PIN_DIR, help="pinned-keys directory")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--public-key", help="base64 of the 32-byte raw Ed25519 public key (from the phone)")
    source.add_argument("--generate", action="store_true", help="generate a software keypair (dev/test signer)")
    parser.add_argument("--private-out", type=Path, help="where to write the generated private key (with --generate)")
    args = parser.parse_args(argv)

    if args.generate and not args.private_out:
        parser.error("--generate requires --private-out")

    if args.generate:
        pin = _generate_and_enroll(args.user, args.pin_dir, args.private_out)
        print(f"generated keypair; private key -> {args.private_out}, pinned public key -> {pin}")
        return 0

    pin = _enroll_public_key_b64(args.user, args.public_key, args.pin_dir)
    print(f"pinned public key for {args.user!r} -> {pin}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
