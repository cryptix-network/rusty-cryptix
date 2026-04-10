# AntiFraud HF v1 Binary Schema

This document is normative for Rust/Go implementations.

## Domain Separation
- `domain_sep` MUST be the exact UTF-8 byte sequence: `cryptix-antifraud-snapshot-v1`
- No length prefix is encoded for `domain_sep`

## Canonical Payload Layout (bytes)
1. `domain_sep` (31 bytes)
2. `schema_version` (`u8`)
3. `network` (`u8`)
4. `snapshot_seq` (`u64`, big-endian)
5. `generated_at_ms` (`u64`, big-endian; telemetry only)
6. `signing_key_id` (`u8`)
7. `banned_ips_count` (`u32`, big-endian)
8. `banned_ip_entry[]` (concatenated)
9. `banned_node_ids_count` (`u32`, big-endian)
10. `banned_node_id_entry[]` (concatenated)

## Entry Encoding
- `banned_ip_entry`:
  - IPv4: `0x04 || ipv4_octets[4]` (5 bytes)
  - IPv6: `0x06 || ipv6_octets[16]` (17 bytes)
- `banned_node_id_entry`:
  - Exactly 32 raw bytes

## Sanitization Rules
- Validate all inputs.
- Deduplicate before hashing.
- Sort bytewise lexicographically over full binary entry bytes.
- Limits:
  - `banned_ips_count <= 4096`
  - `banned_node_ids_count <= 4096`

## Hash + Signature
- `root_hash = BLAKE3-256(canonical_payload)` (exactly 32 bytes)
- `signature` MUST be secp256k1 BIP340 Schnorr, exactly 64 bytes `R||s`
- Verification MUST use `root_hash` directly as the 32-byte message (no rehash)

## Network Enum
- `0 = mainnet`
- `1 = testnet`
- `2 = devnet`
- `3 = simnet`

## Zero-Hash
- Zero-Hash is exactly 32 bytes of `0x00`
- Zero-Hash is padding-only in hash windows and never counts as overlap
