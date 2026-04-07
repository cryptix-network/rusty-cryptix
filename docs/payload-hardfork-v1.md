# Payload & Messenger Hardfork v1 

Developer info:

Paylaods:
## Frozen Constants

- `SUBNETWORK_ID_PAYLOAD = from_byte(3)`
- `PAYLOAD_MAX_LEN_CONSENSUS = 8192`
- `PAYLOAD_MAX_LEN_STANDARD = 2048`
- `PAYLOAD_WEIGHT_MULTIPLIER = 4`
- `PAYLOAD_SOFT_CAP_PER_BLOCK_BYTES = 32768` (policy-only)
- `OVERCAP_FEERATE_MULTIPLIER = 2.0` (policy-only)
- `PAYLOAD_HF_ACTIVATION_DAA_SCORE` is a release-time network parameter.

## Policy 

- Mempool standardness rejects payload txs above `2048` bytes.
- Consensus still uses the hard limit `8192`.
- Mining selector tracks cumulative payload bytes per block.
- Up to `32768` payload bytes: normal selection.
- Above `32768`: payload txs require feerate `>= minimum_relay_feerate * 2.0`.
- Non-payload tx selection remains unaffected by payload soft-cap logic.

## Wallet v1 Product Safety

- Wallet payload default target: `1024` bytes.
- Wallet warning threshold: `1536` bytes.
- Wallet hard send limit: `2048` bytes.
- Payload-bearing wallet sends are internally routed to `SUBNETWORK_ID_PAYLOAD`.

Messenger:
## Messenger Envelope v1

- `magic`: `"CXM"` (3 bytes)
- `version`: `1` (1 byte)
- `msg_type`: 1 byte
- `flags`: 1 byte
- `recipient_tag`: 16 bytes
- `nonce`: 24 bytes
- `sender_kind`: 1 byte (`1=pubkey`, `2=ref`)
- `sender_len`: 1 byte (`32` for pubkey, `16` for ref)
- `sender_data`: 32 bytes
- Header size: fixed `80` bytes
- `body_len = payload_len - 80`

Strict parsing rules:

- Unknown magic: treat as raw payload.
- Known magic + unknown version: do not treat as valid messenger content.
- No best-effort fallback parsing.
- For `sender_kind=2`, bytes `sender_data[16..32]` must be zero.

Dedup/replay helpers:

- Primary identity key: `txid`.
- Secondary key: `SHA256(sender_kind || sender_data(32 bytes canonical) || nonce)`.

