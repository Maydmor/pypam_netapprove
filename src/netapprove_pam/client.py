"""TLS-pinned client for the untrusted relay (spec §8: cert pinning, short timeout).

The relay is untrusted, so transport security here protects only against passive
eavesdropping/tampering of the relay channel — the *approval* security comes from
the locally-verified signature, not from TLS. Still, we pin the relay's leaf
certificate by SHA-256 fingerprint so a swapped relay cert is detected.

Every network failure (connect error, timeout, TLS/pin mismatch) is normalized to
``RelayOutage`` so the decision layer can map it to PAM_AUTHINFO_UNAVAIL. A relay
that answers with a *denial* is NOT an outage.
"""

from __future__ import annotations

import base64
import time
import warnings
from dataclasses import dataclass
from typing import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

from netapprove_core.challenge import Challenge

from .backends import ApprovalResponse, RelayOutage


class _FingerprintAdapter(HTTPAdapter):
    """Pins the server's leaf certificate by SHA-256 fingerprint (hex, no colons)."""

    def __init__(self, fingerprint: str, **kwargs):
        self._fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._fingerprint
        super().init_poolmanager(*args, **kwargs)


@dataclass(frozen=True)
class PollResult:
    status: str  # "pending" | "approved" | "denied"
    signature_b64: str | None = None


class RelayClient:
    """Thin HTTP wrapper. Knows nothing about crypto — it only moves bytes."""

    def __init__(self, base_url: str, cert_fingerprint_sha256: str | None, timeout_seconds: float):
        self._base = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._session = requests.Session()

        if cert_fingerprint_sha256:
            self._session.mount("https://", _FingerprintAdapter(cert_fingerprint_sha256.lower()))
            self._session.verify = False  # leaf is pinned by fingerprint instead of CA chain

    def _post(self, path: str, json: dict) -> dict:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                resp = self._session.post(f"{self._base}{path}", json=json, timeout=self._timeout)
        except requests.exceptions.RequestException as exc:
            raise RelayOutage(f"POST {path} failed: {exc}") from exc

        if resp.status_code >= 500:
            raise RelayOutage(f"POST {path} returned {resp.status_code}")
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str) -> dict:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                resp = self._session.get(f"{self._base}{path}", timeout=self._timeout)
        except requests.exceptions.RequestException as exc:
            raise RelayOutage(f"GET {path} failed: {exc}") from exc

        if resp.status_code >= 500:
            raise RelayOutage(f"GET {path} returned {resp.status_code}")
        resp.raise_for_status()
        return resp.json()

    def submit_challenge(self, challenge: Challenge) -> str:
        data = self._post("/requests", {"challenge": challenge.to_wire()})
        request_id = data.get("request_id")
        if not request_id:
            raise RelayOutage("relay did not return a request_id")
        return request_id

    def poll(self, request_id: str) -> PollResult:
        data = self._get(f"/requests/{request_id}")
        return PollResult(status=data.get("status", "pending"), signature_b64=data.get("signature_b64"))


class NetworkBackend:
    """Phase 3 backend: submit to the relay, then poll until resolved or timeout.

    A *reachable* relay that never resolves within the approval window fails closed
    (returns DENIED → PAM_AUTH_ERR, no fallback): the relay was up, so this is not
    an outage and must not downgrade. Only an actual transport failure raises
    RelayOutage → PAM_AUTHINFO_UNAVAIL.
    """

    def __init__(
        self,
        client: RelayClient,
        approval_timeout_seconds: float,
        poll_interval_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._client = client
        self._timeout = approval_timeout_seconds
        self._interval = poll_interval_seconds
        self._clock = clock
        self._sleep = sleep

    def request_approval(self, challenge: Challenge) -> ApprovalResponse:
        request_id = self._client.submit_challenge(challenge)
        deadline = self._clock() + self._timeout

        while True:
            result = self._client.poll(request_id)
            if result.status == "approved":
                return self._to_approved(result)
            if result.status == "denied":
                return ApprovalResponse.denied()
            if self._clock() >= deadline:
                return ApprovalResponse.denied()  # reachable but timed out → fail closed
            self._sleep(self._interval)

    def _to_approved(self, result: PollResult) -> ApprovalResponse:
        if not result.signature_b64:
            raise RelayOutage("relay reported approved but returned no signature")
        signature = base64.b64decode(result.signature_b64, validate=True)
        return ApprovalResponse.approved(signature)
