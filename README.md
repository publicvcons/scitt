# publicvcons/scitt

SCITT transparency service configuration and key management runbooks for PublicVCons.

Part of the PublicVCons project. Reference implementation of the vcon lifecycle SCITT extension.

## What is here

- `server/`: configuration for the SCITT reference server (forked from SteveLasker/vcon-lifecycle conceptually, consumed as a dependency in practice) exposed at scitt.publicvcons.org
- `runbooks/`: key generation, rotation, backup, and incident response runbooks
- `cli/`: a small verifier CLI that takes a vcon UUID and walks the SCITT chain. Mirrored as an MCP tool in publicvcons/mcp.

The signing key never lives in this repo. It is held in a 1Password vault or hardware token and read at runtime by the Mac mini pipeline.

## License

Apache 2.0.
