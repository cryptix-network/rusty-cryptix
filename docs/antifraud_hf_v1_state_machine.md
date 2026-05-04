# AntiFraud HF v1 State Machine

This state machine is normative for transport gating after payload hardfork activation.

## Local State
- `last_valid_snapshot` (optional)
- `last_valid_seq` (`u64`, implicit in snapshot)
- `hash_window[3]` newest-first (`[h0, h1, h2]`)
- `mode in { FULL, RESTRICTED_AF }`

## Snapshot Acceptance
A candidate snapshot is accepted only if all checks pass:
1. Signature valid over canonical `root_hash`
2. `network` matches local network
3. Sanitization succeeds
4. Count limits are within maxima
5. Rollback rules:
   - `snapshot_seq < last_valid_seq` => reject
   - `snapshot_seq == last_valid_seq` AND `root_hash != current_root_hash` => reject + conflict log

Selection among multiple valid peer candidates:
1. Keep only candidates with highest `snapshot_seq`
2. Strict majority on `root_hash` within that highest sequence (`votes > n/2`)
3. If no strict majority, do not update
4. If exactly one valid candidate exists at highest sequence, accept

## Hash Window Update
On accepted snapshot:
- If `new_hash == hash_window[0]`: keep current window
- Else: `hash_window = [new_hash, old_h0, old_h1]`, then remove duplicates, then zero-pad to length 3

## Peer Mode Decision
Given local `hash_window` and peer `anti_fraud_hashes[3]`:
- Invalid peer window format => `RESTRICTED_AF`
- At least one non-zero overlap => `FULL`
- No non-zero overlap => `RESTRICTED_AF`

## Allowed Traffic in `RESTRICTED_AF`
- Handshake
- Ping/Pong
- AntiFraud snapshot request/response

Denied in `RESTRICTED_AF`:
- TX relay
- Block relay/IBD payload flows
- Microblock/FastIntent/StrongNode gossip

## Boot/Persistence
- Persist `current.snapshot` and `previous.snapshot` atomically (`temp -> fsync -> rename`)
- Corrupt snapshot files are ignored/quarantined; node continues
- If no valid snapshot is available:
  - `hash_window = [0,0,0]`
  - with peer snapshot fallback enabled, start AntiFraud runtime in `RESTRICTED_AF` and keep requesting peer snapshots
  - with peer snapshot fallback disabled, remain fail-open and keep retrying configured source(s)
