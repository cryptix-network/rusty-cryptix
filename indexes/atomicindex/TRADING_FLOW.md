# Atomic Trading Flow Notes

This note is for wallets, DEX frontends and market tools that want a fast trading UX.

Atomic swaps support a useful pending layer: transactions can be prevalidated by the mempool, nonces can be planned ahead, and a child transaction may spend outputs created by a mempool parent. This is what lets a frontend show "this trade is already visible" before the block is accepted. It is still pending state, not confirmed token state.

## State Layers

Use three layers in the UI:

1. Confirmed Atomic state from RPC:
   - `GetTokenAsset`
   - `GetTokenBalance`
   - `GetTokenNonce`
   - `GetLiquidityPoolState`
   - `GetLiquidityQuote`
   - `GetTokenEvents`
   - `GetTokenOpStatus`

2. Pending/mempool overlay:
   - `GetMempoolEntriesByAddresses`
   - `GetMempoolEntries`
   - `GetMempoolEntry`
   - locally submitted transaction IDs and decoded CAT payloads

3. Final result:
   - `GetTokenOpStatus { txid }`
   - `NotifyTokenEvents`
   - `GetTokenEvents { afterSequence, limit }`

The pending layer is allowed to change or disappear. Never store it as a confirmed token balance, pool, fee claim, or trade history row.

## Normal Swap Flow

1. Convert the wallet address to an `ownerId` with `GetTokenOwnerIdByAddress`.
2. Read the current pool with `GetLiquidityPoolState { assetId }`.
3. Read the owner's next asset nonce with `GetTokenNonce { ownerId, assetId }`.
4. Quote with `GetLiquidityQuote`.
5. Build the CAT payload:
   - buy: `BuyLiquidityExactIn(assetId, expectedPoolNonce, cpayInSompi, minTokenOut)`
   - sell: `SellLiquidityExactIn(assetId, expectedPoolNonce, tokenIn, minCpayOutSompi, cpayReceiveOutputIndex)`
   - claim: `ClaimLiquidityFees(assetId, expectedPoolNonce, recipientIndex, claimAmountSompi, claimReceiveOutputIndex)`
6. Put the payload into a normal transaction with the correct auth input and, for swaps, the correct vault/payout outputs.
7. Submit with `SubmitTransaction`.
8. Immediately add a pending UI row from the local transaction and verify visibility through the mempool.
9. Mark it final only after `GetTokenOpStatus` or token events confirm the operation as applied.

Use `minTokenOut` / `minCpayOutSompi` as the slippage guard. If another trade wins the same pool nonce first, the later trade must be rebuilt against the newer pool.

## Nonces And Prebuilding

Atomic nonces are scoped:

- create operations use the owner nonce.
- asset operations use the owner+asset nonce.
- liquidity swaps also carry the pool nonce.

A frontend may prepare nonce `N+1` while nonce `N` is still pending, but it must treat that as a chain. If the parent trade fails, expires, or is replaced, the child trade is stale and must be rebuilt.

Do not skip gaps. If confirmed nonce is `10` and pending nonce `11` is visible, the next planned transaction may use `12`. If nonce `11` is not visible or locally guaranteed, do not submit `12` as if it were independent.

Parallelism is safe when scopes differ. For the same owner+asset, keep operations ordered by nonce. For the same liquidity pool, keep swaps ordered by `poolNonce`.

## Spending Mempool Parents

The transaction mempool can hold parent/child chains. A child can spend an output created by a mempool parent, including outputs used by Atomic swap flows. This is useful for fast trading because the next transaction can be built on the expected parent output instead of waiting for block confirmation.

For frontends:

- Show parent-built transactions as "pending on parent".
- Keep the local graph: parent txid, child txid, spent outpoints, owner nonce, pool nonce.
- Recheck the parent with `GetMempoolEntry` or address mempool queries before submitting a child from another browser session.
- If a parent disappears, suppress or rebuild every child that depends on it.

The mempool prevalidation is not a final apply. Consensus still decides in block order.

## Mempool Conflict Rules

The Rust mempool tracks Atomic slots before a transaction enters the pool:

- owner nonce slot: owner-level create operations.
- owner+asset nonce slot: transfer, mint, burn, buy, sell, claim.
- liquidity pool slot: buy, sell, claim with the expected `poolNonce`.

Two visible transactions cannot both own the exact same Atomic slot. For swaps, two transactions against the same pool nonce cannot both become valid state transitions. One wins; the other must be rebuilt with a fresh pool state and nonce.

## UI Rules

Good trading UIs usually do this:

- Render the confirmed pool first.
- Apply visible pending swaps locally in nonce/pool order to show a projected pool.
- Mark projected values clearly as pending.
- Keep a local submitted-tx cache so the UI reacts before the next polling round.
- Back off `GetMempoolEntry` calls after "not found"; repeated misses are noise.
- Prefer `NotifyTokenEvents` for finality and use `GetTokenEvents` as the catch-up stream.
- Keep history scans and header/block probes out of the hot submit path.

Recommended polling shape:

- Active trade panel: pool/nonce/quote refresh around 750-1500 ms, with short bursts only while the user is typing or right after submit.
- Background token dashboard: 5-15 seconds.
- Event history: cursor based, not full reloads.
- Mempool entry lookup: cache misses for at least a few seconds.

## Reorgs

Reorgs are normal. Use `context.atBlockHash`, `context.atDaaScore`, `context.stateHash`, and event `sequence` to know which state you rendered.

If a reorg happens:

- discard confirmed rows/events that are reorged.
- reload confirmed pool/balances/nonces.
- rebuild the pending overlay from local txs plus current mempool.
- treat old pool-nonce projections as stale until verified again.

## Failure States

An Atomic transaction can be accepted by the chain but apply as `noop`. A noop is not a successful token operation. Always check `applyStatus` and `noopReason`.

Common user-facing reasons:

- stale nonce
- stale pool nonce
- slippage/min-out violation
- missing or wrong vault output
- insufficient token balance
- sell lock still active
- parent transaction disappeared

## RPC Quick Reference

```ts
GetTokenOwnerIdByAddress({ address })
GetTokenNonce({ ownerId, assetId })
GetLiquidityPoolState({ assetId })
GetLiquidityQuote({ assetId, side, exactInAmount })
SubmitTransaction({ transaction, allowOrphan })
GetMempoolEntriesByAddresses({ addresses, includeOrphanPool, filterTransactionPool })
GetMempoolEntries({ includeOrphanPool, filterTransactionPool })
GetMempoolEntry({ transactionId, includeOrphanPool, filterTransactionPool })
GetTokenOpStatus({ txid })
GetTokenEvents({ afterSequence, limit })
NotifyTokenEvents({ command: "start" })
```

For buy quotes, `side=0` and `exactInAmount` is CPAY sompi. For sell quotes, `side=1` and `exactInAmount` is the raw token amount.

