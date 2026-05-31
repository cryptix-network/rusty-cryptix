# Cryptix Atomic Developer Notes

Extended Developer Information:

For frontend trade execution, pending mempool rendering, nonce prebuilding, and parent-built swap transactions, see [Atomic Trading Flow Notes](TRADING_FLOW.md).

## Core Model

- Atomic payloads start with `CAT` (`0x43 0x41 0x54`) and version `1`.
- Atomic transactions use the payload subnetwork. A transaction without payload is a normal CPAY transaction.
- `assetId` is the transaction ID of the token create transaction.
- `ownerId` is not the address string. It is the canonical 32-byte owner ID derived from the address/script. Platforms should get it with `GetTokenOwnerIdByAddress`.
- All token amounts are raw integers. Decimals are display metadata. RPC returns large values as decimal strings.
- Most reads accept optional `atBlockHash`. Without it, the node reads the current Atomic read context. With it, the node reads a stable historical context if that context is still available.

## Token Types

**Standard tokens** are created with `CreateAsset` or `CreateAssetWithMint`. They may use `0..18` decimals. `supplyMode=0` means uncapped and requires `maxSupply=0`; `supplyMode=1` means capped and requires `maxSupply>0`. Minting is allowed only for `mintAuthorityOwnerId`. Burn and transfer can only spend the authenticated owner's own balance.

**Liquidity/swap tokens** are created with `CreateLiquidityAsset`. They are always capped, always use `decimals=0`, and their `mintAuthorityOwnerId` is internally zero. Legacy `Mint` and `Burn` are forbidden for liquidity assets; normal transfers are allowed. Buy, sell, and fee-claim operations additionally validate the `poolNonce`, vault UTXO, and payout output.

## CAT Payload Format

All integers are little-endian. Common header:

| Field | Size | Value |
| --- | ---: | --- |
| magic | 3 | `CAT` |
| version | u8 | `1` |
| op | u8 | see table |
| flags | u8 | currently always `0` |
| authInputIndex | u16 | input that proves the owner |
| nonce | u64 | expected next nonce, never `0` |

Nonce scopes:

- Create operations (`0`, `4`, `5`) use the owner nonce: `GetOwnerNonce` or `GetTokenNonce` without `assetId`.
- Asset operations (`1`, `2`, `3`, `6`, `7`, `8`) use the owner+asset nonce: `GetTokenNonce { ownerId, assetId }`.

Operations:

| Op | Name | Body after header |
| ---: | --- | --- |
| 0 | `CreateAsset` | `tokenVersion:u8`, `decimals:u8`, `supplyMode:u8`, `maxSupply:u128`, `mintAuthorityOwnerId:32`, `nameLen:u8`, `symbolLen:u8`, `metadataLen:u16`, bytes, optional `platformTagLen:u8 + UTF-8` |
| 1 | `Transfer` | `assetId:32`, `toOwnerId:32`, `amount:u128` |
| 2 | `Mint` | `assetId:32`, `toOwnerId:32`, `amount:u128` |
| 3 | `Burn` | `assetId:32`, `amount:u128` |
| 4 | `CreateAssetWithMint` | same as `CreateAsset`, then `initialMintAmount:u128`, `initialMintToOwnerId:32`, optional `platformTag` |
| 5 | `CreateLiquidityAsset` | `tokenVersion:u8`, `curveVersion:u8`, `decimals:u8`, `maxSupply:u128`, name/symbol/metadata, `seedReserveSompi:u64`, `feeBps:u16`, fee recipients, launch-buy fields, optional tail |
| 6 | `BuyLiquidityExactIn` | `assetId:32`, `expectedPoolNonce:u64`, `cpayInSompi:u64`, `minTokenOut:u128` |
| 7 | `SellLiquidityExactIn` | `assetId:32`, `expectedPoolNonce:u64`, `tokenIn:u128`, `minCpayOutSompi:u64`, `cpayReceiveOutputIndex:u16` |
| 8 | `ClaimLiquidityFees` | `assetId:32`, `expectedPoolNonce:u64`, `recipientIndex:u8`, `claimAmountSompi:u64`, `claimReceiveOutputIndex:u16` |

Limits:

- `name <= 32` bytes, `symbol <= 10` bytes, `metadata <= 256` bytes, `platformTag <= 50` UTF-8 bytes.
- Standard tokens: `decimals <= 18`.
- Liquidity tokens: `decimals = 0`, `maxSupply` from `100000` to `10000000`, default `1000000`.
- Liquidity seed reserve: exactly `1 CPAY` in sompi.
- Fee: `0` or `10..1000` bps. With fee `0`, recipient count must be `0`; otherwise it must be `1..2`.
- Two fee recipients must be unique and canonically sorted. For an odd fee, recipient 0 receives `fee/2` and recipient 1 receives the remainder. This is deterministic and intentional.

Liquidity optional tail:

```text
platformTagLen:u8 + platformTagBytes
liquidityUnlockTargetSompi:u64
curveMode:u8                     // optional, default 0
individualVirtualCpaySompi:u64   // only with curveMode=2
individualTokenMultiplierBps:u16 // only with curveMode=2
```

Curves:

- `0 = basic`
- `1 = aggressive`
- `2 = individual`

Individual curves are deliberately quantized: `individualVirtualCpaySompi` must be between `100000000000000` and `800000000000000`, in `10000000000000`-sompi steps. `individualTokenMultiplierBps` must be `10100..20000`, in `100` bps steps. Swap math uses integer arithmetic only; no floats are used for consensus-critical amounts.

## Numeric Enums

Useful values when decoding events and statuses:

| Enum | Values |
| --- | --- |
| `SupplyMode` | `0=Uncapped`, `1=Capped` |
| `ApplyStatus` | `0=Applied`, `1=Noop` |
| `EventType` | `0=Applied`, `1=Noop`, `2=Reorged` |

Common `NoopReason` values:

```text
0 None, 1 BadMagic, 2 BadVersion, 3 BadOp, 4 BadFlags, 5 BadLength,
6 BadUtf8, 7 BadAuthInput, 8 BadNonce, 9 AssetNotFound,
10 AssetAlreadyExists, 11 UnauthorizedMint, 12 InvalidAmount,
13 InsufficientBalance, 14 BalanceOverflow, 15 SupplyOverflow,
16 SupplyUnderflow, 17 SupplyCapExceeded, 18 BadSupplyMode,
19 BadDecimals, 20 BadMaxSupply, 21 AlreadyProcessed,
22 InternalMalformedAcceptance, 23 BadLiquidityFeeBps,
24 BadLiquidityRecipientCount, 25 RecipientEncodingInvalid,
26 RecipientDuplicate, 27 RecipientNotCanonical, 28 BadLaunchBuyFields,
29 MinOutViolation, 30 ZeroOutput, 31 LegacyOpForLiquidityAsset,
32 NonceStale, 33 VaultInputCount, 34 VaultOutputCount,
35 VaultOutpointMismatch, 36 PayoutScriptClassInvalid,
37 HistoricalStateUnavailable, 38 BadPlatformTag,
39 BadLiquidityUnlockTarget, 40 LiquiditySellLocked,
41 BadTokenVersion, 42 BadLiquidityCurveVersion, 43 BadLiquidityCurveMode
```

## WASM Payload Helpers

When possible, do not hand-build CAT payload bytes. The wallet WASM layer exposes serializers that already enforce the same client-side limits:

```ts
atomicTokenPayloadConstants()
serializeAtomicTokenCreateAssetPayload(authInputIndex, nonce, decimals, supplyMode, maxSupply, mintAuthorityOwnerId, name, symbol, metadata, platformTag?)
serializeAtomicTokenCreateAssetWithMintPayload(authInputIndex, nonce, decimals, supplyMode, maxSupply, mintAuthorityOwnerId, name, symbol, metadata, initialMintAmount, initialMintToOwnerId, platformTag?)
serializeAtomicTokenTransferPayload(authInputIndex, nonce, assetId, toOwnerId, amount)
serializeAtomicTokenMintPayload(authInputIndex, nonce, assetId, toOwnerId, amount)
serializeAtomicTokenBurnPayload(authInputIndex, nonce, assetId, amount)
serializeAtomicTokenCreateLiquidityAssetPayload(authInputIndex, nonce, decimals, maxSupply, name, symbol, metadata, seedReserveSompi, feeBps, recipientAddresses, launchBuySompi, launchBuyMinTokenOut, platformTag?, liquidityUnlockTargetSompi?, liquidityCurveMode?, individualVirtualCpayReservesSompi?, individualVirtualTokenMultiplierBps?)
serializeAtomicTokenBuyLiquidityExactInPayload(authInputIndex, nonce, assetId, expectedPoolNonce, cpayInSompi, minTokenOut)
serializeAtomicTokenSellLiquidityExactInPayload(authInputIndex, nonce, assetId, expectedPoolNonce, tokenIn, minCpayOutSompi, cpayReceiveOutputIndex)
serializeAtomicTokenClaimLiquidityFeesPayload(authInputIndex, nonce, assetId, expectedPoolNonce, recipientIndex, claimAmountSompi, claimReceiveOutputIndex)
```

## RPC Types

Atomic RPC models are shared in the core RPC layer. The generated wRPC client exposes the full list below; other bindings may lag for very new helper calls. In TS/WASM, fields are camelCase. `HexString` means a hex-encoded 32-byte hash or ID.

```ts
type RpcTokenContext = {
  atBlockHash: HexString;
  atDaaScore: bigint;
  stateHash: string;
  isDegraded: boolean;
};

type RpcTokenAsset = {
  assetId: string;
  creatorOwnerId: string;
  tokenVersion: number;
  mintAuthorityOwnerId: string;
  decimals: number;
  supplyMode: number;
  maxSupply: string;
  totalSupply: string;
  name: string;
  symbol: string;
  metadataHex: string;
  createdBlockHash?: HexString;
  createdDaaScore?: bigint;
  createdAt?: bigint;
  platformTag: string;
};

type RpcTokenEvent = {
  eventId: string;
  sequence: bigint;
  acceptingBlockHash: HexString;
  txid: HexString;
  eventType: number;     // 0 applied, 1 noop, 2 reorged
  applyStatus: number;   // 0 applied, 1 noop
  noopReason: number;    // 0 none, otherwise NoopReason code
  ordinal: number;
  reorgOfEventId?: string;
  opType?: number;
  assetId?: string;
  fromOwnerId?: string;
  toOwnerId?: string;
  amount?: string;
};

type RpcLiquidityPoolState = {
  assetId: string;
  poolNonce: bigint;
  curveVersion: number;
  curveMode: number;
  curveModeLabel: string;
  individualVirtualCpayReservesSompi: string;
  individualVirtualTokenMultiplierBps: number;
  feeBps: number;
  maxSupply: string;
  totalSupply: string;
  circulatingTokenSupply: string;
  realCpayReservesSompi: string;
  realTokenReserves: string;
  virtualCpayReservesSompi: string;
  virtualTokenReserves: string;
  maxBuyInSompi: string;
  maxTokensOut: string;
  unclaimedFeeTotalSompi: string;
  vaultValueSompi: string;
  vaultTxid: HexString;
  vaultOutputIndex: number;
  feeRecipients: { ownerId: string; address: string; unclaimedSompi: string }[];
  liquidityLockEnabled: boolean;
  unlockTargetSompi: string;
  unlocked: boolean;
  sellLocked: boolean;
  liquidityCpaySompi: string;
  currentSpotPriceSompi: string;
  circulatingMcapCpaySompi: string;
  fdvMcapCpaySompi: string;
};
```

## RPC Commands

| RPC | Request | Response |
| --- | --- | --- |
| `SubmitTransaction` | `{ transaction: RpcTransaction, allowOrphan: boolean }` | `{ transactionId }` |
| `SubmitTransactionReplacement` | `{ transaction: RpcTransaction }` | `{ transactionId, replacedTransaction }` |
| `SimulateTokenOp` | `{ payloadHex, ownerId, atBlockHash? }` | `{ result: "ignored" \| "noop" \| "state_only", noopReason?, expectedNextNonce, context }` |
| `GetTokenBalance` | `{ assetId, ownerId, atBlockHash? }` | `{ balance, context }` |
| `GetTokenNonce` | `{ ownerId, assetId?, atBlockHash? }` | `{ expectedNextNonce, context }` |
| `GetOwnerNonce` | `{ ownerId, atBlockHash? }` | `{ expectedNextNonce, context }`; same create-flow nonce can also be read with `GetTokenNonce` and no `assetId` |
| `GetTokenAsset` | `{ assetId, atBlockHash? }` | `{ asset?: RpcTokenAsset, context }` |
| `GetTokenOpStatus` | `{ txid, atBlockHash? }` | `{ acceptingBlockHash?, applyStatus?, noopReason?, context }` |
| `GetTokenStateHash` | `{ atBlockHash? }` | `{ context }` |
| `GetTokenSpendability` | `{ assetId, ownerId, minDaaForSpend?, atBlockHash? }` | `{ canSpend, reason?, balance, expectedNextNonce, minDaaForSpend, context }` |
| `GetTokenEvents` | `{ afterSequence, limit, atBlockHash? }` | `{ events: RpcTokenEvent[], context }` |
| `GetTokenAssets` | `{ offset, limit, query?, atBlockHash? }` | `{ assets: RpcTokenAsset[], total, context }` |
| `GetTokenBalancesByOwner` | `{ ownerId, offset, limit, includeAssets, atBlockHash? }` | `{ balances: { assetId, balance, asset? }[], total, context }` |
| `GetTokenHolders` | `{ assetId, offset, limit, atBlockHash? }` | `{ holders: { ownerId, balance }[], total, context }` |
| `GetTokenOwnerIdByAddress` | `{ address, atBlockHash? }` | `{ ownerId?, reason?, context }` |
| `GetLiquidityPoolState` | `{ assetId, atBlockHash? }` | `{ pool?: RpcLiquidityPoolState, context }` |
| `GetLiquidityQuote` | `{ assetId, side, exactInAmount, atBlockHash? }` | `{ side, exactInAmount, feeAmountSompi, netInAmount, amountOut, context }` |
| `GetLiquidityFeeState` | `{ assetId, atBlockHash? }` | `{ assetId, feeBps, totalUnclaimedSompi, recipients, context }` |
| `GetLiquidityClaimPreview` | `{ assetId, recipientAddress, atBlockHash? }` | `{ recipientAddress, ownerId?, claimableAmountSompi, minPayoutSompi, claimableNow, reason?, context }` |
| `GetLiquidityHolders` | `{ assetId, offset, limit, atBlockHash? }` | `{ holders: { address?, ownerId, balance }[], total, context }` |
| `NotifyTokenEvents` | `{ command: "start" \| "stop" }` | `{}` plus `TokenEventsChangedNotification { fromSequence, toSequence, eventCount }` |
| `GetTokenHealth` | `{ atBlockHash? }` | `{ isDegraded, bootstrapInProgress, liveCorrect, tokenState, lastAppliedBlock?, lastSequence, stateHash, context }` |
| `ExportTokenSnapshot` | `{ path }` | `{ exported, context }` |
| `ImportTokenSnapshot` | `{ path }` | `{ imported, context }` |
| `GetScBootstrapSources` | `{}` | `{ sources: RpcScBootstrapSource[], context }` |
| `GetScSnapshotManifest` | `{ snapshotId }` | `{ snapshotId, manifestHex, manifestSignatures }` |
| `GetScSnapshotChunk` | `{ snapshotId, chunkIndex, chunkSize? }` | `{ snapshotId, chunkIndex, totalChunks, fileSize, chunkHex }` |
| `GetScReplayWindowChunk` | `{ snapshotId, chunkIndex, chunkSize? }` | `{ snapshotId, chunkIndex, totalChunks, fileSize, chunkHex }` |
| `GetScSnapshotHead` | `{}` | `{ head?: RpcScBootstrapSource, context }` |
| `GetConsensusAtomicStateHash` | `{ blockHash }` | `{ stateHash? }` |

`GetLiquidityQuote.side` is `0=buy`, `1=sell`. For `buy`, `exactInAmount` is CPAY sompi. For `sell`, it is token raw amount.

## Recommended Platform Flow

1. Convert address to `ownerId` with `GetTokenOwnerIdByAddress`.
2. Fetch the nonce: create operations use `GetOwnerNonce`; asset operations use `GetTokenNonce { ownerId, assetId }`.
3. For swaps, read `GetLiquidityPoolState` and `GetLiquidityQuote`. Always build the payload with the current `poolNonce` and a slippage guard (`minTokenOut` or `minCpayOutSompi`).
4. Build the transaction with the correct `authInputIndex`, CAT payload, and for liquidity operations the correct vault/payout output.
5. Submit with `SubmitTransaction`.
6. Track the result with `GetTokenOpStatus` or `NotifyTokenEvents` plus `GetTokenEvents`.

During reorgs, do not trust only local UI cache. Store `context.stateHash`, `context.atBlockHash`, and event sequences. A `noop` is an accepted but semantically unapplied Atomic operation; it must not be treated as a successful token state change.
