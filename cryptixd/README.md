# Cryptix p2p Node

High-performance p2p node library and daemon for high-BPS BlockDAG [Cryptix](https://cryptix.org) network developed in Rust.

For more information please refer to the GitHub repository `README.md` located at https://github.com/cryptix-network/rusty-cryptix

## Auto-Ban Toggle

- CLI: `--autoban` (enable), `--no-autoban` (disable)
- Config file: `autoban = true|false`
- Defaults: 5 strikes, 3h ban duration

## Banserver Sync

- CLI: `--banserver` (primary AntiFraud seed enabled), `--no-banserver` / `--antifraud-no-seed` (peer-majority only)
- Config file: `banserver = true|false`
- Runtime policy: signed ban list is connection-only enforcement (admission/termination), while block relay/acceptance remains independent of ban entries.
- Fallback policy: peer snapshot fallback is automatic (on seed fetch failures and in `--no-banserver` / `--antifraud-no-seed` mode).
