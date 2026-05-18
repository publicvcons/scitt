# SCITT service — run & key management

## What this is

A small, faithful SCITT transparency service: an append-only Merkle log
of signed lifecycle statements that issues RFC 9162-style inclusion
proofs countersigned by the service key (the "receipt"). It is the
thing `scitt.publicvcons.org` runs. ed25519 + JSON (not COSE/CBOR) to
match the statements `conserver/pipeline/scitt_sign.py` already emits.

## Keys

Two independent ed25519 keys, both outside any repo (0600):

| key | file | role |
|---|---|---|
| issuer | `~/.publicvcons/scitt_ed25519.jwk` | signs lifecycle *statements* (pipeline) |
| service | `~/.publicvcons/scitt_service_ed25519.jwk` | countersigns *receipts* (this service) |

Both are auto-created on first use with `0600` perms. For production,
hold them in 1Password or a hardware token and inject at runtime
(PROTOTYPE_PLAN.md §10) — never commit them. Publish the **public**
halves: issuer pubkey at `vcons/.well-known/scitt-pubkey.json`, service
pubkey via `GET /.well-known/transparency-configuration`.

## Run (local / prototype)

```
export PVCONS_SCITT_LEDGER=/Volumes/publicvcons/scitt-ledger
cd seed/scitt/server
~/venvs/tools/bin/uvicorn scitt_service:app --host 127.0.0.1 --port 8000
```

launchd (keep it up on the mini):

```
cp seed/scitt/deploy/com.publicvcons.scitt.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.publicvcons.scitt.plist
```

## Ledger

Append-only `log.jsonl` under `$PVCONS_SCITT_LEDGER` (default
`/Volumes/publicvcons/scitt-ledger`). The local drive is canonical
(§6); back it up with the rest of the drive. The tree only grows —
never edit or truncate `log.jsonl`; doing so invalidates every
previously issued inclusion proof.

## Anchor the pipeline at it

```
orchestrate.py ... --scitt --scitt-url http://127.0.0.1:8000
# or
export PVCONS_SCITT_URL=http://127.0.0.1:8000
```

Each statement is POSTed to `/entries`; the inclusion-proof receipt is
stored next to it as `NN_stage.scitt-receipt.json`.

## Verify (fully offline, no service needed)

```
~/venvs/tools/bin/python seed/scitt/cli/pvcons_scitt.py \
    verify --receipts <vcon>/scitt
```

Checks, per receipt: (1) service countersignature, (2) the inclusion
proof re-derives the logged root, (3) the statement hashes to the
logged leaf, (4) the original issuer statement signature. Any tamper
to the statement, the leaf, the proof, or the root fails.

## Swap to production / cloud

`scitt.publicvcons.org` (public DNS + a Digital Ocean droplet + a
Spaces-backed, versioned ledger) is the deployment target and is **not
done** — it is cloud infra, out of scope for the offline mini (§8).
When ready: run this same service behind that hostname, point
`--scitt-url` / `PVCONS_SCITT_URL` and `conserver/config.yml`'s
`scitt` link at it, and migrate the ledger to the durable store. The
upstream vcon-server `scitt` link (COSE/SCRAPI) is the eventual
production client; this service's HTTP shape is intentionally close to
ease that swap.
