"""Untrusted relay (spec §3 Phase 3): moves bytes, holds no trust.

Endpoints:
  POST /requests                 PAM submits a challenge -> {request_id}
  GET  /requests/pending         approver lists unresolved requests
  POST /requests/{id}/respond    approver posts approve+signature or deny
  GET  /requests/{id}            PAM polls for the result

Security note: this service is deliberately dumb. It never decides auth — it only
shuttles a challenge to the approver and a signature back. Even fully compromised it
cannot forge an approval, because it does not hold the signing key and the PAM
module verifies signatures locally. Storage is in-memory; restart clears state.
"""

from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass, field

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


class _Status(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ChallengeWire(BaseModel):
    user: str
    host: str
    tty: str
    timestamp_unix: int
    nonce_b64: str


class SubmitBody(BaseModel):
    challenge: ChallengeWire


class RespondBody(BaseModel):
    decision: str  # "approve" | "deny"
    signature_b64: str | None = None


@dataclass
class _Request:
    request_id: str
    challenge: ChallengeWire
    status: _Status = _Status.PENDING
    signature_b64: str | None = None


@dataclass
class _Store:
    requests: dict[str, _Request] = field(default_factory=dict)


store = _Store()
app = FastAPI(title="netapprove-relay")


@app.post("/requests")
def submit(body: SubmitBody) -> dict:
    request_id = secrets.token_urlsafe(16)
    store.requests[request_id] = _Request(request_id=request_id, challenge=body.challenge)
    return {"request_id": request_id, "status": _Status.PENDING.value}


@app.get("/requests/pending")
def pending() -> dict:
    items = [
        {"request_id": r.request_id, "challenge": r.challenge.model_dump()}
        for r in store.requests.values()
        if r.status is _Status.PENDING
    ]
    return {"pending": items}


@app.post("/requests/{request_id}/respond")
def respond(request_id: str, body: RespondBody) -> dict:
    record = store.requests.get(request_id)

    if record is None:
        raise HTTPException(status_code=404, detail="unknown request_id")
    if record.status is not _Status.PENDING:
        raise HTTPException(status_code=409, detail=f"already {record.status.value}")
    if body.decision == "approve" and not body.signature_b64:
        raise HTTPException(status_code=400, detail="approve requires signature_b64")
    if body.decision not in ("approve", "deny"):
        raise HTTPException(status_code=400, detail="decision must be approve|deny")

    record.status = _Status.APPROVED if body.decision == "approve" else _Status.DENIED
    record.signature_b64 = body.signature_b64 if body.decision == "approve" else None
    return {"status": record.status.value}


@app.get("/requests/{request_id}")
def poll(request_id: str) -> dict:
    record = store.requests.get(request_id)

    if record is None:
        raise HTTPException(status_code=404, detail="unknown request_id")

    return {"status": record.status.value, "signature_b64": record.signature_b64}


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8443)
