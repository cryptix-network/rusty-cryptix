###
Needs revision, no longer valid since update 1.3

-------

# Cryptix CLI Contract Commands

This document explains how to use the contract-related commands in the Cryptix CLI, focusing on smart contracts, tokens, and mining tokens.

## Units:
- Coin to sompi: 1 Coin = 100,000,000 sompi

## Overview

The CLI provides commands to:
- Deploy contract instances
- Invoke actions (calls), simulate, and inspect state
- Send and check balances for token contracts
- Perform token operations
- Mine tokens using mining contracts

## Basic Contract Commands

### Deploy a Contract

Deploy a contract instance with initial state.

```
cryptix-cli contract deploy --contract <id> --data <file> [--fee <amount>]
```

Parameters:
- --contract <id>: Contract ID
- --data <file>: File containing initial state (binary)
- --fee <amount>: Optional fee (in sompi or configured human unit)

Example:
```
cryptix-cli contract deploy --contract 100 --data init.bin --fee 1000
```

### Call a Contract Method

Invoke an action on an existing instance.

```
cryptix-cli contract call --instance <id> --action <id> [--data <file>]
```

- --instance: Contract instance ID
- --action: Action ID
- --data: Optional binary data file

Examples:
```
cryptix-cli contract call --instance TX:VOUT --action 3
cryptix-cli contract call --instance TX:VOUT --action 3 --data call.bin
```

### Get Contract State

```
cryptix-cli contract state --instance <id>
```

Prints current state bytes (hex), size, and its state outpoint.

### List Contract Instances

```
cryptix-cli contract list
```

Lists all known instances (id, contract id, state size/hash/outpoint).

### Simulate a Contract Call

```
cryptix-cli contract simulate --instance <id> --action <id> [--data <file>]
```

- Executes call without submitting a transaction
- Useful to preview state changes and validate size limits

## Address Conversion for Token Operations

Token contracts require addresses in a different format than the standard wallet addresses. Use the `address token` command to convert wallet addresses to the token address format:

### Convert Wallet Address to Token Address

```
cryptix-cli address token [wallet-address]
```

If no address is provided, it will use your current wallet address.

Example:
```
cryptix-cli address token cryptix:qz5h05asjz8l38y3djy6c26n63m6s9gn0kssemvra2ssw5v7qt9x2eqpwrc7w
```

Output:
```
Wallet Address:
  cryptix:qz5h05asjz8l38y3djy6c26n63m6s9gn0kssemvra2ssw5v7qt9x2eqpwrc7w

Token Address (32-byte hex for contracts):
  a0f4f7a5c8e9d2b1f3a6c7e8d9b0a1f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8

Use this token address for:
  - Deploying token contracts (--admin parameter)
  - Checking token balances (--address parameter)
  - Sending tokens (--from/--to parameters)
```

**Important:** Always use the token address format (32-byte hex) when interacting with token contracts, not the wallet address format.

## Token Operations

For token operations, use the dedicated `token` command:

### Check Token Balance

```
cryptix-cli token balance --instance <id> --address <address> [--contract <id>]
```

### Send Tokens

```
cryptix-cli token send --instance <id> --to <address> --amount <amount> [--from <address>] [--contract <id>]
```

Note: The `--from` parameter is optional. If not provided, the system will use an address from your wallet.

### Deploy a Token Contract

```
cryptix-cli token deploy --contract <id> [--admin <address>] [--initial-supply <amount>] [--max-supply <amount>] [--name <name>] [--ticker <ticker>] [--fee <amount>] [--deflation-ppm <value>]
```

### List Token Contracts

```
cryptix-cli token list
```

### Show Token Information

```
cryptix-cli token info --instance <id> [--contract <id>]
```

## Mining Token Operations (IDs 250/251)

### Mine Tokens

For mining tokens, use the `token mine` command:

```
cryptix-cli token mine --instance <id> [--reward-address <address>] [--threads <count>] [--algo <sha3|blake3>] [--endpoint <url>] [--contract <id>]
```

Alternatively, use the dedicated `token_miner` binary:

```
token_miner --algo <sha3|blake3> --contract-id <250|251> --instance <id> --reward-address <address>
```

## Common Contract IDs

- 1: ECHO Contract (returns input data as state)
- 2: COUNTER Contract (increments a counter on each call)
- 100: CX20 Extended Token
- 101: CX20-MINI Token
- 110: CX-NFT Extended
- 111: CX-NFT-MINI
- 250: CX-MIN-SHA3 Mining Token
- 251: CX-MIN-BLAKE3 Mining Token
- 9999: ERROR Contract (always returns an error)

## Data Payloads (for reference)

### CX20 (ID 100)
- deploy (0): [initial_supply:u64][owner:32][flags:u16]
- mint (1): [to:32][amount:u64]
- burn (2): [amount:u64]
- transfer (3): [to:32][amount:u64]
- approve (4): [spender:32][amount:u64]
- transfer_from (5): [from:32][to:32][amount:u64]
- freeze (6): [account:32]
- unfreeze (7): [account:32]
- pause (8): []
- unpause (9): []
- set_metadata (10): [symbol_hash:32][decimals:u8]
- admin_transfer (11): [from:32][to:32][amount:u64]

### CX20-MINI (ID 101)
- deploy (0): [owner:32][initial_supply:u64]
- transfer (1): [from:32][to:32][amount:u64]
- mint (2): [caller:32][amount:u64]
- burn (3): [from:32][amount:u64]

### CX-NFT (ID 110)
- deploy (0): [name_hash:32][symbol_hash:32]
- mint (1): [token_id:u64][to:32]
- burn (2): [token_id:u64]
- transfer (3): [token_id:u64][to:32]
- set_metadata (4): [token_id:u64][metadata_hash:32]
- approve (5): [spender:32][token_id:u64]
- transfer_from (6): [from:32][to:32][token_id:u64]
- freeze (7): [token_id:u64]
- unfreeze (8): [token_id:u64]

### CX-NFT-MINI (ID 111)
- deploy (0): [name_hash:32][admin:32]
- mint (1): [caller:32][token_id:u64][to:32]
- transfer (2): [token_id:u64][from:32][to:32]
- burn (3): [token_id:u64][owner:32]

### CX-MIN Mining Tokens (ID 250/251)
- deploy (0): [admin:32][initial_reward:u64][max_supply:u64][deflation_ppm:u32][difficulty_bits:u8][name:str][ticker:str][icon:bytes][decimals:u8]
- mine (1): [miner:32][nonce:u64]
- transfer (2): [from:32][to:32][amount:u64]
- admin_set_difficulty (3): [caller:32][difficulty_bits:u8]
- admin_set_reward (4): [caller:32][reward:u64]
- admin_pause (5): [caller:32]
- admin_unpause (6): [caller:32]

## Notes

- Instance IDs are txid:vout
- The `simulate` command helps validate state transitions and size before submit
- For NFTs, use list-style inspection instead of balance
- The `--from` parameter is optional for token operations. If not provided, the system will use an address from your wallet
- The system works at the wallet level, not just at the address level
