# AntiFraud HF v1 Runtime Policy

This document describes the currently enforced AntiFraud behavior.

## Scope
- AntiFraud snapshots are used for **connection enforcement only**:
  - deny new connections from banned IP / unified node ID entries
  - terminate active peers that become banned
- AntiFraud snapshots are **not** used to gate:
  - block relay / block acceptance
  - IBD payload flows
  - transaction relay
  - strong-node claim acceptance

## Snapshot Acceptance
A snapshot is accepted only when:
1. Signature over canonical payload/root hash is valid
2. `network` matches local network
3. Schema/sanitization/count checks pass
4. Monotonic sequence rules pass:
   - older `snapshot_seq` is rejected
   - same `snapshot_seq` with different `root_hash` is rejected

Peer fallback selection (when enabled) uses:
1. highest `snapshot_seq`
2. strict majority on `root_hash` at that sequence (`votes > n/2`)

## Source Strategy
- Startup: immediate fetch from the primary AntiFraud seed endpoint when seed sync is enabled
- Periodic refresh: hourly
- If the seed fetch fails/invalid:
  - keep last valid list (fail-open for snapshot freshness, not process crash)
  - automatically request peer snapshots (peer fallback)
- If seed sync is disabled (`--no-banserver` / `--antifraud-no-seed`):
  - run in peer-snapshot mode continuously

## Persistence / Recovery
- Persist `current.snapshot` and `previous.snapshot` atomically
- Corrupt snapshot files are quarantined/ignored
- Node continues operation with the last valid in-memory/on-disk list
