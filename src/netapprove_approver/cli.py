"""CLI approver — the phone stand-in (spec §3 Phase 3, §4 Phase 4 swap point).

Lists pending requests from the relay, shows the human-readable challenge, signs the
canonical bytes with the test private key, and posts the signature back. The real
phone app replaces this with a secure-enclave key gated on a biometric, but speaks
the exact same relay protocol — nothing else changes when you swap it in.
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

import requests

from netapprove_core.challenge import Challenge
from netapprove_core.crypto import sign


def _load_private_key(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"private key not found: {str(path)!r}")
    return base64.b64decode(path.read_text().strip(), validate=True)


def _fetch_pending(relay_url: str) -> list[dict]:
    resp = requests.get(f"{relay_url.rstrip('/')}/requests/pending", timeout=5, verify=False)
    resp.raise_for_status()
    return resp.json().get("pending", [])


def _sign_and_respond(relay_url: str, request_id: str, challenge: Challenge, private_key: bytes, approve: bool) -> str:
    if not approve:
        body = {"decision": "deny"}
    else:
        signature = sign(private_key, challenge.to_canonical_bytes())
        body = {"decision": "approve", "signature_b64": base64.b64encode(signature).decode("ascii")}

    resp = requests.post(f"{relay_url.rstrip('/')}/requests/{request_id}/respond", json=body, timeout=5, verify=False)
    resp.raise_for_status()
    return resp.json().get("status", "unknown")


def _approve_one(relay_url: str, item: dict, private_key: bytes, auto_approve: bool) -> None:
    challenge = Challenge.from_wire(item["challenge"])
    print(f"\n  request {item['request_id']}")
    print(f"  {challenge.human_summary()}")

    if auto_approve:
        decision = True
    else:
        answer = input("  approve with biometric? [y/N/deny]: ").strip().lower()
        decision = answer in ("y", "yes")

    status = _sign_and_respond(relay_url, item["request_id"], challenge, private_key, decision)
    print(f"  -> {status}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netapprove-approver", description="Approve pending sudo requests")
    parser.add_argument("--relay-url", default="https://127.0.0.1:8443")
    parser.add_argument("--key", type=Path, required=True, help="path to the base64 test private key")
    parser.add_argument("--yes", action="store_true", help="auto-approve all pending (non-interactive test)")
    args = parser.parse_args(argv)

    requests.packages.urllib3.disable_warnings()  # self-signed relay in dev
    private_key = _load_private_key(args.key)
    pending = _fetch_pending(args.relay_url)

    if not pending:
        print("no pending requests")
        return 0

    for item in pending:
        _approve_one(args.relay_url, item, private_key, args.yes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
