# publicvcons/scitt

SCITT transparency service configuration and key management runbooks for PublicVCons.

Part of the PublicVCons project. Reference implementation of the vcon lifecycle SCITT extension.

## What is here

- `server/scitt_service.py`: the SCITT transparency service — an
  append-only Merkle log of signed lifecycle statements that issues
  RFC 9162-style inclusion proofs countersigned by the service key
  (the "receipt"). This is what `scitt.publicvcons.org` runs. ed25519
  + JSON to match the statements the pipeline already emits
  (`conserver/pipeline/scitt_sign.py`); the HTTP shape is kept close
  to SCRAPI so the upstream vcon-server COSE `scitt` link can be
  swapped in for production.
- `cli/pvcons_scitt.py`: client (`register`), offline verifier
  (`verify` — service countersignature + inclusion proof + statement
  signature, no network) and chain `walk` by vcon uuid. Mirrored as an
  MCP tool in publicvcons/mcp.
- `runbooks/`: run & key-management runbook.
- `deploy/`: launchd unit to keep the service up on the mini.

Two ed25519 keys (issuer for statements, service for receipts) live
outside any repo at `~/.publicvcons/` (0600); production holds them in
1Password or a hardware token. Only the public halves are published.

### Status

The service runs and the committed corpus artifact's five lifecycle
statements are anchored in the canonical on-drive ledger with receipts
that verify offline. Public exposure at `scitt.publicvcons.org`
(DNS + a Digital Ocean droplet + a durable versioned ledger) is the
remaining cloud step and is **not** done — the offline mini cannot do
it (§8). See `runbooks/run-and-key-management.md`.

## License

Apache 2.0.
