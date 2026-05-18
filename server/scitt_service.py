#!/usr/bin/env python3
"""PublicVCons SCITT transparency service (prototype).

A small, faithful SCITT-style transparency service: an append-only log
of signed statements with RFC 9162-style Merkle inclusion proofs and a
service countersignature (the "receipt"). This is the thing that
scitt.publicvcons.org runs.

It is deliberately ed25519 + JSON (not COSE/CBOR) to stay consistent
with the lifecycle statements the pipeline already emits
(pipeline/scitt_sign.py) and to avoid an archived-emulator dependency
tree on the offline Mac mini. The property that matters for a
transparency archive is preserved: every statement is logged into an
append-only Merkle tree and the service issues a verifiable inclusion
proof + countersignature, so "can I trust this vcon" is answerable by
re-deriving the root and checking two signatures.

SCRAPI-shaped endpoints:
  GET  /                                    health + service info
  GET  /.well-known/transparency-configuration   issuer + service pubkey
  POST /entries                             register a signed statement
  GET  /entries                             list entry ids
  GET  /entries/{eid}                       stored signed statement
  GET  /entries/{eid}/receipt               inclusion proof + countersig

Run:
  PVCONS_SCITT_LEDGER=/Volumes/publicvcons/scitt-ledger \
  ~/venvs/tools/bin/uvicorn scitt_service:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

ISSUER = "did:web:scitt.publicvcons.org"
LEDGER_DIR = Path(os.environ.get(
    "PVCONS_SCITT_LEDGER", "/Volumes/publicvcons/scitt-ledger"))
KEY_PATH = Path(os.environ.get(
    "PVCONS_SCITT_KEY",
    str(Path.home() / ".publicvcons" / "scitt_service_ed25519.jwk")))
LOG_PATH = LEDGER_DIR / "log.jsonl"

_LEAF = b"\x00"
_NODE = b"\x01"
_lock = threading.Lock()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load_or_make_key() -> Ed25519PrivateKey:
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        j = json.loads(KEY_PATH.read_text())
        return Ed25519PrivateKey.from_private_bytes(b64u_dec(j["d"]))
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    KEY_PATH.write_text(json.dumps({
        "kty": "OKP", "crv": "Ed25519",
        "d": b64u(sk.private_bytes_raw()),
        "x": b64u(pk.public_bytes_raw()),
        "issuer": ISSUER,
        "use": "scitt-service-receipt-countersignature",
    }))
    os.chmod(KEY_PATH, 0o600)
    return sk


SK = _load_or_make_key()
SVC_PUB = b64u(SK.public_key().public_bytes_raw())


def leaf_hash(statement_bytes: bytes) -> bytes:
    return hashlib.sha256(_LEAF + statement_bytes).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(_NODE + a + b).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    level = leaves[:]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote odd tail
        level = nxt
    return level[0]


def _inclusion_proof(leaves: list[bytes], index: int) -> list[str]:
    """RFC 9162-style audit path (with odd-tail promotion)."""
    proof: list[str] = []
    level = leaves[:]
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                if i == idx or i + 1 == idx:
                    sib = level[i + 1] if i == idx else level[i]
                    proof.append(b64u(sib))
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        idx //= 2
        level = nxt
    return proof


def _read_leaves() -> list[bytes]:
    if not LOG_PATH.exists():
        return []
    out = []
    for line in LOG_PATH.read_text().splitlines():
        if line.strip():
            rec = json.loads(line)
            out.append(b64u_dec(rec["leaf_hash"]))
    return out


def _read_log() -> list[dict]:
    if not LOG_PATH.exists():
        return []
    return [json.loads(x) for x in LOG_PATH.read_text().splitlines()
            if x.strip()]


app = FastAPI(title="PublicVCons SCITT", version="0.1.0")


class StatementIn(BaseModel):
    statement: dict  # a pipeline/scitt_sign.py signed statement


@app.get("/")
def root():
    log = _read_log()
    return {
        "service": "PublicVCons SCITT transparency service",
        "issuer": ISSUER,
        "tree_size": len(log),
        "status": "ok",
    }


@app.get("/.well-known/transparency-configuration")
def config():
    return {
        "issuer": ISSUER,
        "service_public_key": {
            "kty": "OKP", "crv": "Ed25519", "x": SVC_PUB,
            "alg": "Ed25519",
        },
        "receipt": "rfc9162-inclusion-proof+ed25519-countersignature",
    }


@app.post("/entries")
def post_entry(body: StatementIn):
    stmt = body.statement
    if "payload" not in stmt or "signature" not in stmt:
        raise HTTPException(400, "not a signed statement")
    sb = json.dumps(stmt, sort_keys=True,
                     separators=(",", ":")).encode()
    lh = leaf_hash(sb)
    with _lock:
        LEDGER_DIR.mkdir(parents=True, exist_ok=True)
        log = _read_log()
        eid = len(log)
        rec = {
            "entry_id": eid,
            "registered_at": int(time.time()),
            "subject": stmt["payload"].get("subject"),
            "stage": stmt["payload"].get("stage"),
            "leaf_hash": b64u(lh),
            "statement": stmt,
        }
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(rec) + "\n")
    return JSONResponse({"entry_id": eid, "operation_id": str(eid),
                         "status": "succeeded"})


@app.get("/entries")
def list_entries():
    return {"entries": [r["entry_id"] for r in _read_log()]}


@app.get("/entries/{eid}")
def get_entry(eid: int):
    log = _read_log()
    if eid < 0 or eid >= len(log):
        raise HTTPException(404, "no such entry")
    return log[eid]["statement"]


@app.get("/entries/{eid}/receipt")
def get_receipt(eid: int):
    log = _read_log()
    if eid < 0 or eid >= len(log):
        raise HTTPException(404, "no such entry")
    leaves = [b64u_dec(r["leaf_hash"]) for r in log]
    tree_size = len(leaves)
    root = _merkle_root(leaves)
    proof = _inclusion_proof(leaves, eid)
    signed = {
        "issuer": ISSUER,
        "entry_id": eid,
        "leaf_index": eid,
        "tree_size": tree_size,
        "leaf_hash": log[eid]["leaf_hash"],
        "root": b64u(root),
        "subject": log[eid]["subject"],
        "stage": log[eid]["stage"],
        "alg": "Ed25519",
    }
    to_sign = json.dumps(signed, sort_keys=True,
                         separators=(",", ":")).encode()
    sig = SK.sign(to_sign)
    return {
        "receipt": signed,
        "inclusion_proof": proof,
        "service_signature": b64u(sig),
        "service_kid": SVC_PUB,
    }
