#!/usr/bin/env python3
"""PublicVCons SCITT client + verifier.

register : POST a signed lifecycle statement to the transparency
           service, store the returned receipt next to the vcon.
verify   : for a receipts dir, re-derive the Merkle root from each
           inclusion proof and check (a) the service countersignature
           and (b) the original statement signature. Fully offline —
           no network needed to verify.
walk     : print the lifecycle chain for a vcon uuid from a ledger.

The statement signature check reuses the same ed25519 scheme as
pipeline/scitt_sign.py (issuer key), so a receipt binds: vcon hash ->
signed statement -> logged leaf -> Merkle root -> service signature.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

_LEAF = b"\x00"
_NODE = b"\x01"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _recompute_root(leaf: bytes, index: int, tree_size: int,
                    proof: list[str]) -> bytes:
    h = leaf
    idx, size, pi = index, tree_size, 0
    while size > 1:
        last = size - 1
        if idx == last and size % 2 == 1:
            idx //= 2
            size = (size + 1) // 2
            continue
        sib = b64u_dec(proof[pi])
        pi += 1
        if idx % 2 == 0:
            h = hashlib.sha256(_NODE + h + sib).digest()
        else:
            h = hashlib.sha256(_NODE + sib + h).digest()
        idx //= 2
        size = (size + 1) // 2
    return h


def register(args) -> int:
    stmt = json.loads(Path(args.statement).read_text())
    r = httpx.post(f"{args.url}/entries",
                    json={"statement": stmt}, timeout=30)
    r.raise_for_status()
    eid = r.json()["entry_id"]
    rec = httpx.get(f"{args.url}/entries/{eid}/receipt",
                    timeout=30).json()
    out = Path(args.out)
    out.write_text(json.dumps(rec, indent=2))
    print(f"registered entry {eid} -> {out}")
    return 0


def _verify_one(receipt_path: Path, statement_path: Path) -> str:
    rec = json.loads(receipt_path.read_text())
    body = rec["receipt"]
    # 1. service countersignature over the receipt body
    pub = Ed25519PublicKey.from_public_bytes(
        b64u_dec(rec["service_kid"]))
    signed = json.dumps(body, sort_keys=True,
                        separators=(",", ":")).encode()
    pub.verify(b64u_dec(rec["service_signature"]), signed)
    # 2. inclusion proof re-derives the logged root
    leaf = b64u_dec(body["leaf_hash"])
    root = _recompute_root(leaf, body["leaf_index"],
                           body["tree_size"], rec["inclusion_proof"])
    if b64u(root) != body["root"]:
        raise ValueError("inclusion proof does not reproduce root")
    # 3. the leaf actually commits to this statement
    stmt = json.loads(statement_path.read_text())
    sb = json.dumps(stmt, sort_keys=True,
                    separators=(",", ":")).encode()
    if hashlib.sha256(_LEAF + sb).digest() != leaf:
        raise ValueError("statement does not hash to the logged leaf")
    # 4. the original issuer statement signature
    ipub = Ed25519PublicKey.from_public_bytes(
        b64u_dec(stmt["protected"]["kid"]))
    pb = json.dumps(stmt["payload"], sort_keys=True,
                    separators=(",", ":")).encode()
    ipub.verify(b64u_dec(stmt["signature"]), pb)
    return body["stage"]


def verify(args) -> int:
    rdir = Path(args.receipts)
    pairs = sorted(rdir.glob("*.scitt-receipt.json"))
    if not pairs:
        print("no *.scitt-receipt.json found", file=sys.stderr)
        return 1
    ok = True
    for rp in pairs:
        sp = rp.with_name(rp.name.replace(".scitt-receipt.json",
                                          ".scitt.json"))
        try:
            stage = _verify_one(rp, sp)
            print(f"OK  {rp.name}  stage={stage}")
        except Exception as e:
            ok = False
            print(f"BAD {rp.name}: {e}")
    return 0 if ok else 1


def walk(args) -> int:
    r = httpx.get(f"{args.url}/entries", timeout=30).json()
    found = []
    for eid in r["entries"]:
        st = httpx.get(f"{args.url}/entries/{eid}", timeout=30).json()
        if st["payload"].get("subject") == f"urn:vcon:{args.uuid}":
            found.append((eid, st["payload"]["stage"]))
    for eid, stage in found:
        print(f"entry {eid:>4}  {stage}")
    return 0 if found else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("register")
    rp.add_argument("--statement", required=True)
    rp.add_argument("--out", required=True)
    rp.add_argument("--url", default="http://127.0.0.1:8000")
    vp = sub.add_parser("verify")
    vp.add_argument("--receipts", required=True)
    wp = sub.add_parser("walk")
    wp.add_argument("--uuid", required=True)
    wp.add_argument("--url", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    return {"register": register, "verify": verify,
            "walk": walk}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
